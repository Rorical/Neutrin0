//! Solidity views over journaled system records. Reads observe earlier calls in the
//! same EVM transaction and disappear with the enclosing transaction's journal.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible entry points of a private module; `pub` would be unreachable."
)]

use crate::{
    addresses,
    state::ethereum_address,
    system::{abi_word, integer, selector, word},
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::StateBackend;
use neutrin0_runtime_system::{ProposalAction, RuntimePolicy};
use revm::primitives::{Address, U256};

pub(crate) fn dispatch<B: StateBackend>(
    state: &mut B,
    input: &RuntimeBlockInput,
    address: Address,
    data: &[u8],
    proposer_vrf_available: bool,
) -> Option<Result<Vec<u8>, String>> {
    if address == addresses::CONSENSUS {
        return Some(consensus(input, data, proposer_vrf_available));
    }
    if address == addresses::RANDOMNESS {
        return Some(randomness(state, data));
    }
    if address == addresses::STAKING && selector(data, b"validator(address)") {
        return Some(validator(state, data));
    }
    if address == addresses::STAKING && selector(data, b"withdrawalStatus(address)") {
        return Some(withdrawal(state, input.block_height, data));
    }
    if address == addresses::GOVERNANCE {
        return governance(state, input, data);
    }
    None
}

fn consensus(
    input: &RuntimeBlockInput,
    data: &[u8],
    proposer_vrf_available: bool,
) -> Result<Vec<u8>, String> {
    let context = input.context;
    if selector(data, b"finalizedSeed()") {
        Ok(context.finalized.seed.to_vec())
    } else if selector(data, b"producerVrf()") {
        if !proposer_vrf_available {
            return Err("pending proposer VRF unavailable".into());
        }
        Ok(context.proposer_vrf_output.to_vec())
    } else if selector(data, b"chunkId()") {
        Ok(abi_word(context.finalized.next_chunk_id))
    } else if selector(data, b"finalizedHeight()") {
        Ok(abi_word(context.finalized.height))
    } else if selector(data, b"validatorsRoot()") {
        Ok(context.finalized.validators_root.to_vec())
    } else if selector(data, b"historyRoot()") {
        Ok(context.finalized.history_root.to_vec())
    } else if selector(data, b"slot()") {
        Ok(abi_word(context.slot))
    } else if selector(data, b"nativeParentHash()") {
        Ok(context.parent_block_hash.to_vec())
    } else {
        Err("unknown consensus method".into())
    }
}

fn randomness<B: StateBackend>(state: &mut B, data: &[u8]) -> Result<Vec<u8>, String> {
    if !selector(data, b"randomness(uint64)") {
        return Err("unknown randomness method".into());
    }
    let source = u64::try_from(integer(data, 0)?).map_err(|_| "randomness chunk overflow")?;
    let seed = crate::randomness::source_seed(state, source)?;
    let mut bytes = seed.to_vec();
    bytes.extend_from_slice(&abi_word(source));
    bytes.extend_from_slice(&abi_word(source.saturating_sub(1)));
    bytes.extend_from_slice(&abi_word(
        source.checked_add(1).ok_or("randomness chunk overflow")?,
    ));
    Ok(bytes)
}

fn credentials(data: &[u8]) -> Result<[u8; 32], String> {
    let credentials = word(data, 0)?;
    ethereum_address(&credentials).map_err(|error| error.to_string())?;
    Ok(credentials)
}

fn validator<B: StateBackend>(state: &mut B, data: &[u8]) -> Result<Vec<u8>, String> {
    let credentials = credentials(data)?;
    let record: neutrin0_runtime_system::Validator = state
        .read(&neutrin0_runtime_system::validator_key(&credentials))
        .map_or(neutrin0_runtime_system::Validator { stake: 0 }, |bytes| {
            borsh::from_slice(&bytes).expect("canonical validator")
        });
    let mut result = U256::from(record.stake).to_be_bytes::<32>().to_vec();
    result.extend_from_slice(&abi_word(u64::from(record.stake > 0)));
    Ok(result)
}

fn withdrawal<B: StateBackend>(state: &mut B, height: u64, data: &[u8]) -> Result<Vec<u8>, String> {
    let credentials = credentials(data)?;
    let queue: neutrin0_runtime_system::WithdrawalQueue = state
        .read(&neutrin0_runtime_system::withdrawal_key(&credentials))
        .map(|bytes| borsh::from_slice(&bytes).expect("canonical withdrawal queue"))
        .unwrap_or_default();
    let sanctions: Vec<neutrin0_runtime_system::accountability::PendingSanction> = state
        .read(neutrin0_runtime_system::accountability::QUEUE_KEY)
        .map(|bytes| borsh::from_slice(&bytes).expect("canonical mandatory queue"))
        .unwrap_or_default();
    let held = sanctions
        .iter()
        .any(|item| item.sanction.offender.withdrawal_credentials == credentials);
    let matured = queue
        .entries
        .iter()
        .filter(|entry| entry.mature_at_height <= height)
        .fold(0_u128, |total, entry| total.saturating_add(entry.amount));
    let next_maturity = queue
        .entries
        .iter()
        .filter(|entry| entry.mature_at_height > height)
        .map(|entry| entry.mature_at_height)
        .min()
        .unwrap_or(0);
    let mut result = U256::from(queue.total()).to_be_bytes::<32>().to_vec();
    result.extend_from_slice(&U256::from(matured).to_be_bytes::<32>());
    result.extend_from_slice(&abi_word(u64::from(held)));
    result.extend_from_slice(&abi_word(next_maturity));
    Ok(result)
}

fn governance<B: StateBackend>(
    state: &mut B,
    input: &RuntimeBlockInput,
    data: &[u8],
) -> Option<Result<Vec<u8>, String>> {
    use neutrin0_runtime_system::governance::{
        load_fork_proposals, load_policy_proposals, load_proposals,
    };
    if selector(data, b"policy()") {
        let policy = neutrin0_runtime_system::load_runtime_policy(state);
        return Some(Ok(encode_policy(&policy)));
    }
    if selector(data, b"proposalCount()") {
        return Some(Ok(count(&live(load_proposals(state), input))));
    }
    if selector(data, b"proposalAt(uint256)") {
        return Some(proposal_at(live(load_proposals(state), input), data));
    }
    if selector(data, b"policyProposalCount()") {
        return Some(Ok(count(&live(load_policy_proposals(state), input))));
    }
    if selector(data, b"policyProposalAt(uint256)") {
        return Some(proposal_at(live(load_policy_proposals(state), input), data));
    }
    if selector(data, b"forkProposalCount()") {
        return Some(Ok(count(&live(load_fork_proposals(state), input))));
    }
    if selector(data, b"forkProposalAt(uint256)") {
        return Some(proposal_at(live(load_fork_proposals(state), input), data));
    }
    if selector(data, b"pendingPolicy()") {
        let pending = neutrin0_runtime_system::load_pending_policy(state);
        let mut result = abi_word(u64::from(pending.is_some()));
        result.extend_from_slice(&abi_word(
            pending.map_or(0, |pending| pending.effective_height),
        ));
        result.extend(encode_policy(
            &pending.map_or_else(RuntimePolicy::default, |pending| pending.policy),
        ));
        return Some(Ok(result));
    }
    if selector(data, b"hasVoted(address)") {
        return Some((|| {
            let credentials = credentials(data)?;
            let mut proposals = load_proposals(state);
            proposals.extend(load_policy_proposals(state));
            proposals.extend(load_fork_proposals(state));
            let voted = live(proposals, input)
                .iter()
                .any(|proposal| proposal.voters.binary_search(&credentials).is_ok());
            Ok(abi_word(u64::from(voted)))
        })());
    }
    if selector(data, b"scheduledFork()") {
        let fork = neutrin0_runtime_system::governance::load_scheduled_fork(state);
        let mut result = abi_word(u64::from(fork.is_some()));
        result.extend_from_slice(&abi_word(fork.map_or(0, |fork| fork.count)));
        result.extend_from_slice(&fork.map_or([0; 32], |fork| fork.successor));
        return Some(Ok(result));
    }
    if selector(data, b"scheduledUpgrade()") {
        let scheduled = neutrin0_runtime_system::governance::load_scheduled(state);
        let mut result = abi_word(u64::from(scheduled.is_some()));
        if let Some(scheduled) = scheduled {
            result.extend_from_slice(&abi_word(scheduled.activate_at_chunk));
            result.extend_from_slice(&scheduled.programs.runtime_code_hash);
            for digest in [
                scheduled.programs.execution.fact,
                scheduled.programs.execution.evidence,
                scheduled.programs.execution.block,
            ] {
                for part in digest {
                    result.extend_from_slice(&part.to_le_bytes());
                }
            }
            for artifact in [
                scheduled.artifacts.runtime,
                scheduled.artifacts.fact,
                scheduled.artifacts.evidence,
                scheduled.artifacts.block,
            ] {
                result.extend_from_slice(&artifact);
            }
            result.extend_from_slice(&abi_word(u64::from(scheduled.available)));
        } else {
            result.resize(11 * 32, 0);
        }
        return Some(Ok(result));
    }
    None
}

/// The proposals still live in the block's chunk.
fn live(
    proposals: Vec<neutrin0_runtime_system::UpgradeProposal>,
    input: &RuntimeBlockInput,
) -> Vec<neutrin0_runtime_system::UpgradeProposal> {
    let anchor = &input.evidence_anchor;
    let min_lead = neutrin0_runtime_system::governance::upgrade_min_lead_chunks(anchor);
    proposals
        .into_iter()
        .filter(|proposal| proposal.is_live(anchor.chunk_id, min_lead))
        .collect()
}

fn count(proposals: &[neutrin0_runtime_system::UpgradeProposal]) -> Vec<u8> {
    abi_word(u64::try_from(proposals.len()).expect("a slot holds at most one proposal per seat"))
}

/// The live proposal at the index the call names, compared as a 256-bit word
/// so WASM and the Block Guest agree for every index.
fn proposal_at(
    proposals: Vec<neutrin0_runtime_system::UpgradeProposal>,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let index = U256::from_be_bytes(word(data, 0)?);
    let proposal = proposals
        .into_iter()
        .enumerate()
        .find(|(position, _)| U256::from(*position) == index)
        .map(|(_, proposal)| proposal);
    Ok(encode_proposal(proposal))
}

/// `(bool open, bytes32 id, bytes32 proposer, uint256 kind, uint256
/// proposedAt, uint256 activation)`; kind 0 is a program switch, 1 a policy,
/// 2 a cancellation, 3 a hard fork and 4 a fork cancellation, whose
/// activation is the fork's count.
fn encode_proposal(proposal: Option<neutrin0_runtime_system::UpgradeProposal>) -> Vec<u8> {
    let mut result = abi_word(u64::from(proposal.is_some()));
    if let Some(proposal) = proposal {
        result.extend_from_slice(&proposal.id());
        result.extend_from_slice(&proposal.proposer);
        let (kind, activation) = match proposal.action {
            ProposalAction::Programs {
                activate_at_chunk, ..
            } => (0, activate_at_chunk),
            ProposalAction::Policy(_) => (1, 0),
            ProposalAction::Cancel {
                activate_at_chunk, ..
            } => (2, activate_at_chunk),
            ProposalAction::Fork(fork) => (3, fork.count),
            ProposalAction::CancelFork(fork) => (4, fork.count),
        };
        result.extend_from_slice(&abi_word(kind));
        result.extend_from_slice(&abi_word(proposal.proposed_at_chunk));
        result.extend_from_slice(&abi_word(activation));
    } else {
        result.resize(6 * 32, 0);
    }
    result
}

fn encode_policy(policy: &RuntimePolicy) -> Vec<u8> {
    [
        policy.min_validator_stake,
        u128::from(policy.evidence_max_age_blocks),
        u128::from(policy.evidence_max_pending),
        u128::from(policy.evidence_admissions_per_block),
        u128::from(policy.evidence_executions_per_block),
        policy.inactivity_leak_amount,
        u128::from(policy.reporter_reward_bps),
        u128::from(policy.chunk_prover_fee_bps),
        u128::from(policy.annual_issuance_bps),
        policy.abandonment_penalty_amount,
    ]
    .into_iter()
    .flat_map(|value| U256::from(value).to_be_bytes::<32>())
    .collect()
}

pub(crate) fn decode_policy(data: &[u8]) -> Result<RuntimePolicy, String> {
    Ok(RuntimePolicy {
        min_validator_stake: integer(data, 0)?,
        evidence_max_age_blocks: u64::try_from(integer(data, 1)?)
            .map_err(|_| "evidence age exceeds uint64")?,
        evidence_max_pending: u32::try_from(integer(data, 2)?)
            .map_err(|_| "pending limit exceeds uint32")?,
        evidence_admissions_per_block: u32::try_from(integer(data, 3)?)
            .map_err(|_| "admission limit exceeds uint32")?,
        evidence_executions_per_block: u32::try_from(integer(data, 4)?)
            .map_err(|_| "execution limit exceeds uint32")?,
        inactivity_leak_amount: integer(data, 5)?,
        reporter_reward_bps: u16::try_from(integer(data, 6)?)
            .map_err(|_| "reporter reward exceeds uint16")?,
        chunk_prover_fee_bps: u16::try_from(integer(data, 7)?)
            .map_err(|_| "chunk prover share exceeds uint16")?,
        annual_issuance_bps: u16::try_from(integer(data, 8)?)
            .map_err(|_| "annual issuance exceeds uint16")?,
        abandonment_penalty_amount: integer(data, 9)?,
    })
}
