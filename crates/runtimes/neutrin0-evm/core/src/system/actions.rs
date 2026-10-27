//! State-changing staking and governance calls: ABI decoding, gas, collateral
//! bounds and dispatch into the shared system layer.

use super::{abi_word, dynamic_bytes, integer, journal::JournalBackend, selector, word};
use crate::{addresses, state::consensus_address};
use alloc::{string::String, vec::Vec};
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::StateBackend;
use neutrin0_runtime_system::system::SystemAction;
use revm::context_interface::{ContextTr, JournalTr};
use revm::primitives::{Address, B256, keccak256};

pub(super) fn dispatch<B: StateBackend>(
    backend: &mut JournalBackend<'_, '_, B>,
    input: &RuntimeBlockInput,
    address: Address,
    data: &[u8],
    is_static: bool,
    policy: &neutrin0_runtime_system::RuntimePolicy,
    proposer_vrf_available: bool,
) -> Result<Vec<u8>, String> {
    if let Some(result) =
        crate::system_views::dispatch(backend, input, address, data, proposer_vrf_available)
    {
        return result;
    }
    if is_static {
        return Err("state-changing system call under STATICCALL".into());
    }
    let action = decode_action(address, data)?;
    let proposal_id = match &action {
        SystemAction::Propose {
            programs,
            artifacts,
            activate_at_chunk,
        } => Some(neutrin0_runtime_system::governance::proposal_id(
            &consensus_address(backend.caller),
            &neutrin0_runtime_system::ProposalAction::Programs {
                programs: *programs,
                artifacts: *artifacts,
                activate_at_chunk: *activate_at_chunk,
            },
        )),
        SystemAction::Policy(policy) => Some(neutrin0_runtime_system::governance::proposal_id(
            &consensus_address(backend.caller),
            &neutrin0_runtime_system::ProposalAction::Policy(*policy),
        )),
        SystemAction::Cancel {
            programs,
            activate_at_chunk,
        } => Some(neutrin0_runtime_system::governance::proposal_id(
            &consensus_address(backend.caller),
            &neutrin0_runtime_system::ProposalAction::Cancel {
                programs: *programs,
                activate_at_chunk: *activate_at_chunk,
            },
        )),
        SystemAction::ProposeFork(fork) => Some(neutrin0_runtime_system::governance::proposal_id(
            &consensus_address(backend.caller),
            &neutrin0_runtime_system::ProposalAction::Fork(*fork),
        )),
        SystemAction::CancelFork(fork) => Some(neutrin0_runtime_system::governance::proposal_id(
            &consensus_address(backend.caller),
            &neutrin0_runtime_system::ProposalAction::CancelFork(*fork),
        )),
        _ => None,
    };
    if !backend.charge(action.gas()) {
        return Err("system gas exhausted".into());
    }
    check_collateral_capacity(backend, &action)?;
    neutrin0_runtime_system::system::dispatch_with_policy(backend, input, &action, policy)
        .map_err(|status| alloc::format!("system operation rejected: {}", status.as_u32()))?;
    let topic = keccak256(b"SystemOperation(address,uint8)");
    let caller = B256::from(consensus_address(backend.caller));
    backend
        .context
        .journal_mut()
        .log(revm::primitives::Log::new_unchecked(
            address,
            alloc::vec![topic, caller],
            abi_word(action_kind(&action)).into(),
        ));
    if let Some(proposal_id) = proposal_id {
        backend
            .context
            .journal_mut()
            .log(revm::primitives::Log::new_unchecked(
                address,
                alloc::vec![
                    keccak256(b"ProposalSubmitted(address,bytes32)"),
                    caller,
                    B256::from(proposal_id),
                ],
                revm::primitives::Bytes::new(),
            ));
        Ok(proposal_id.to_vec())
    } else {
        Ok(Vec::new())
    }
}

fn check_collateral_capacity<B: StateBackend>(
    backend: &mut JournalBackend<'_, '_, B>,
    action: &SystemAction,
) -> Result<(), String> {
    let (credentials, amount) = match action {
        SystemAction::Stake(amount) | SystemAction::Register { amount, .. } => {
            (consensus_address(backend.caller), *amount)
        }
        _ => return Ok(()),
    };
    let validator: Option<neutrin0_runtime_system::Validator> = backend
        .read(&neutrin0_runtime_system::validator_key(&credentials))
        .map(|bytes| borsh::from_slice(&bytes).expect("canonical validator"));
    let withdrawals: neutrin0_runtime_system::WithdrawalQueue = backend
        .read(&neutrin0_runtime_system::withdrawal_key(&credentials))
        .map(|bytes| borsh::from_slice(&bytes).expect("canonical withdrawal queue"))
        .unwrap_or_default();
    // Shared sanctions deduct a u128 amount once per safety identity. Bound the
    // complete slashable account, including funds waiting behind the withdrawal
    // delay, so a U256-funded caller cannot hide a second u128 balance in that queue.
    let collateral = withdrawals.entries.iter().try_fold(
        validator.map_or(0, |record| record.stake),
        |total, entry| total.checked_add(entry.amount),
    );
    if collateral
        .and_then(|total| total.checked_add(amount))
        .is_none()
    {
        return Err("slashable collateral exceeds u128".into());
    }
    Ok(())
}

fn decode_action(address: Address, data: &[u8]) -> Result<SystemAction, String> {
    let action = if address == addresses::STAKING {
        if selector(data, b"stake(uint256)") {
            SystemAction::Stake(integer(data, 0)?)
        } else if selector(data, b"unstake(uint256)") {
            SystemAction::Unstake(integer(data, 0)?)
        } else if selector(data, b"exit()") {
            SystemAction::Exit
        } else if selector(data, b"withdraw()") {
            SystemAction::Withdraw
        } else if selector(data, b"registerValidator(bytes,bytes,uint256)") {
            SystemAction::Register {
                pubkey: dynamic_bytes(data, 0, 3, 48)?
                    .try_into()
                    .map_err(|_| "BLS key length")?,
                pop: dynamic_bytes(data, 1, 3, 96)?
                    .try_into()
                    .map_err(|_| "BLS proof length")?,
                amount: integer(data, 2)?,
            }
        } else if selector(data, b"rotateKey(bytes,bytes)") {
            SystemAction::RotateKey {
                pubkey: dynamic_bytes(data, 0, 2, 48)?
                    .try_into()
                    .map_err(|_| "BLS key length")?,
                pop: dynamic_bytes(data, 1, 2, 96)?
                    .try_into()
                    .map_err(|_| "BLS proof length")?,
            }
        } else {
            return Err("unknown staking method".into());
        }
    } else if address == addresses::GOVERNANCE {
        decode_governance(data)?
    } else {
        return Err("unknown system interface".into());
    };
    Ok(action)
}

fn decode_governance(data: &[u8]) -> Result<SystemAction, String> {
    if selector(data, b"vote(bytes32)") {
        return Ok(SystemAction::Vote(word(data, 0)?));
    }
    if selector(data, b"proposePolicy(bytes)") {
        return Ok(SystemAction::Policy(
            borsh::from_slice(&dynamic_bytes(data, 0, 1, 1024)?)
                .map_err(|_| "malformed economic policy")?,
        ));
    }
    if selector(
        data,
        b"proposePolicy((uint128,uint64,uint32,uint32,uint32,uint128,uint16,uint16,uint16,uint128))",
    ) {
        return Ok(SystemAction::Policy(crate::system_views::decode_policy(
            data,
        )?));
    }
    if selector(
        data,
        b"proposeUpgrade(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64)",
    ) {
        return Ok(SystemAction::Propose {
            programs: neutrin0_consensus_types::history_proof::ProgramSet {
                runtime_code_hash: word(data, 0)?,
                execution: neutrin0_consensus_types::history_proof::ExecutionPrograms {
                    fact: vk_digest(word(data, 1)?),
                    evidence: vk_digest(word(data, 2)?),
                    block: vk_digest(word(data, 3)?),
                },
            },
            artifacts: neutrin0_consensus_types::history_proof::ProgramArtifacts {
                runtime: word(data, 4)?,
                fact: word(data, 5)?,
                evidence: word(data, 6)?,
                block: word(data, 7)?,
            },
            activate_at_chunk: u64::try_from(integer(data, 8)?)
                .map_err(|_| "upgrade chunk overflow")?,
        });
    }
    if selector(
        data,
        b"cancelUpgrade(bytes32,bytes32,bytes32,bytes32,uint64)",
    ) {
        return Ok(SystemAction::Cancel {
            programs: neutrin0_consensus_types::history_proof::ProgramSet {
                runtime_code_hash: word(data, 0)?,
                execution: neutrin0_consensus_types::history_proof::ExecutionPrograms {
                    fact: vk_digest(word(data, 1)?),
                    evidence: vk_digest(word(data, 2)?),
                    block: vk_digest(word(data, 3)?),
                },
            },
            activate_at_chunk: u64::try_from(integer(data, 4)?)
                .map_err(|_| "upgrade chunk overflow")?,
        });
    }
    if selector(data, b"proposeFork(uint64,bytes32)") {
        return Ok(SystemAction::ProposeFork(fork(data)?));
    }
    if selector(data, b"cancelFork(uint64,bytes32)") {
        return Ok(SystemAction::CancelFork(fork(data)?));
    }
    Err("unknown governance method".into())
}

/// `(uint64 count, bytes32 successor)` of a fork call.
fn fork(data: &[u8]) -> Result<neutrin0_primitives::ScheduledFork, String> {
    Ok(neutrin0_primitives::ScheduledFork {
        count: u64::try_from(integer(data, 0)?).map_err(|_| "fork chunk overflow")?,
        successor: word(data, 1)?,
    })
}

fn vk_digest(bytes: [u8; 32]) -> [u32; 8] {
    core::array::from_fn(|index| {
        u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().expect("VK word"))
    })
}

const fn action_kind(action: &SystemAction) -> u64 {
    match action {
        SystemAction::Stake(_) => 0,
        SystemAction::Unstake(_) => 1,
        SystemAction::Exit => 2,
        SystemAction::Withdraw => 3,
        SystemAction::Register { .. } => 4,
        SystemAction::Propose { .. } => 5,
        SystemAction::Policy(_) => 6,
        SystemAction::Vote(_) => 7,
        SystemAction::Cancel { .. } => 8,
        SystemAction::RotateKey { .. } => 9,
        SystemAction::ProposeFork(_) => 10,
        SystemAction::CancelFork(_) => 11,
    }
}
