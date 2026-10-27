//! Engine-authenticated system calls and the mandatory block-start phase.

use crate::{Receipt, ReceiptStatus, RuntimePolicy};
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::runtime::AccountabilityOutput;
use neutrin0_runtime_abi::{RuntimeBlockInput, RuntimeTransaction};
use neutrin0_runtime_core::StateBackend;

/// Economic action whose caller is authenticated by its enclosing runtime engine.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum SystemAction {
    /// Add collateral to the caller's validator record.
    Stake(u128),
    /// Queue collateral for delayed withdrawal.
    Unstake(u128),
    /// Queue all remaining active collateral.
    Exit,
    /// Claim matured, unheld collateral.
    Withdraw,
    /// Register the caller's BLS identity and initial stake.
    Register {
        /// Consensus BLS identity.
        pubkey: neutrin0_primitives::BlsPublicKey,
        /// Identity proof of possession bound to the account.
        pop: neutrin0_primitives::BlsSignature,
        /// Initial collateral.
        amount: u128,
    },
    /// Replace the caller's BLS identity; consensus seats the new key in the
    /// caller's seat at the next chunk boundary.
    RotateKey {
        /// New consensus BLS identity.
        pubkey: neutrin0_primitives::BlsPublicKey,
        /// Its proof of possession bound to the account.
        pop: neutrin0_primitives::BlsSignature,
    },
    /// Propose replacement execution programs.
    Propose {
        /// Replacement runtime and execution Guest identities.
        programs: neutrin0_consensus_types::history_proof::ProgramSet,
        /// Content hashes of the distributed program artifacts.
        artifacts: neutrin0_consensus_types::history_proof::ProgramArtifacts,
        /// Consensus boundary at which the new programs activate.
        activate_at_chunk: u64,
    },
    /// Propose replacement economic policy.
    Policy(RuntimePolicy),
    /// Propose cancelling the enacted, not yet activated program switch.
    Cancel {
        /// Program set of the scheduled switch.
        programs: neutrin0_consensus_types::history_proof::ProgramSet,
        /// Activation chunk of the scheduled switch.
        activate_at_chunk: u64,
    },
    /// Propose ending this chain at a hard fork (design 20).
    ProposeFork(neutrin0_primitives::ScheduledFork),
    /// Propose cancelling the enacted hard fork.
    CancelFork(neutrin0_primitives::ScheduledFork),
    /// Cast a stake-weighted vote.
    Vote(neutrin0_primitives::Hash),
}

impl SystemAction {
    /// Gas charged by the runtime-owned system interface, excluding EVM call overhead.
    pub const fn gas(&self) -> u64 {
        match self {
            Self::Stake(_) => crate::GAS_STAKE,
            Self::Unstake(_) => crate::GAS_UNSTAKE,
            Self::Exit => crate::GAS_VOLUNTARY_EXIT,
            Self::Withdraw => crate::GAS_WITHDRAW,
            Self::Register { .. } => crate::GAS_REGISTER_VALIDATOR,
            Self::RotateKey { .. } => crate::GAS_ROTATE_KEY,
            Self::Propose { .. }
            | Self::Policy(_)
            | Self::Cancel { .. }
            | Self::ProposeFork(_)
            | Self::CancelFork(_) => crate::governance::GAS_PROPOSE_UPGRADE,
            Self::Vote(_) => crate::governance::GAS_VOTE_UPGRADE,
        }
    }
}

/// Result of the mandatory system phase, preceding every runtime's user operations.
pub struct SystemBlock {
    /// Proven admissions and deductions.
    pub accountability: AccountabilityOutput,
    /// Mandatory execution and admission gas.
    pub gas: u64,
    /// Mandatory and admission receipts.
    pub receipts: Vec<Receipt>,
    /// Commitment to the certified participation input.
    pub participation: neutrin0_primitives::Hash,
    /// Commitment to the certified proving input (design 08).
    pub proving: neutrin0_primitives::Hash,
}

/// Execute framework accountability after the execution shell authenticates receipts.
pub fn begin_block<B: StateBackend>(input: &RuntimeBlockInput, state: &mut B) -> SystemBlock {
    neutrin0_runtime_core::execution::check_runtime_input(input)
        .expect("valid system block bindings");
    // An enacted policy whose delay has passed governs this block.
    crate::state::activate_pending_policy(state, input.block_height);
    let policy = crate::state::load_runtime_policy(state);
    let participation = crate::state::apply_participation(state, input.participation.as_ref());
    let (proving, settlement_gas) = crate::proving::apply_proving(state, input.proving.as_ref());
    let acknowledgement_gas = crate::state::apply_participation_acks(state, input)
        .checked_add(settlement_gas)
        .expect("system gas bound");
    let mandatory = crate::accountability::apply(input, state, &policy);
    crate::governance::expire(state, &input.evidence_anchor);
    crate::governance::record_program_pieces(
        state,
        &input.program_pieces,
        &input.context.finalized.programs,
    );
    let mut receipts = mandatory.receipts;
    let mut gas = mandatory
        .gas
        .checked_add(acknowledgement_gas)
        .expect("system gas bound");
    for tx in &input.transactions {
        if !matches!(tx, RuntimeTransaction::SubmitEvidence(_)) {
            break;
        }
        gas = gas
            .checked_add(crate::accountability::GAS_EVIDENCE_ADMISSION)
            .expect("system gas bound");
        receipts.push(Receipt {
            status_code: 0,
            gas_used: crate::accountability::GAS_EVIDENCE_ADMISSION,
            kind: crate::accountability::EVIDENCE_RECEIPT_KIND,
        });
    }
    assert!(
        gas <= input.block_gas_limit,
        "mandatory gas must fit the block"
    );
    SystemBlock {
        accountability: mandatory.output,
        gas,
        receipts,
        participation,
        proving,
    }
}

/// Dispatch an authenticated call. Its enclosing runtime supplies rollback and charges gas.
pub fn dispatch<B: StateBackend>(
    state: &mut B,
    input: &RuntimeBlockInput,
    action: &SystemAction,
) -> Result<(), ReceiptStatus> {
    let policy = crate::state::load_runtime_policy(state);
    dispatch_with_policy(state, input, action, &policy)
}

/// Dispatch under the policy captured at block start, even after a policy vote enacts.
pub fn dispatch_with_policy<B: StateBackend>(
    state: &mut B,
    input: &RuntimeBlockInput,
    action: &SystemAction,
    policy: &RuntimePolicy,
) -> Result<(), ReceiptStatus> {
    let caller = state
        .authenticated_caller()
        .ok_or(ReceiptStatus::Unauthorized)?;
    let block = crate::governance::BlockContext {
        chunk: input.evidence_anchor.chunk_id,
        height: input.block_height,
        anchor: &input.evidence_anchor,
        seats: &input.active_validators,
        programs: input.context.finalized.programs,
    };
    let staking = crate::staking::StakingContext {
        block_height: input.block_height,
        unbonding_delay: input.evidence_anchor.unbonding_delay_blocks,
        min_validator_stake: policy.min_validator_stake,
        active: &input.active_validators,
    };
    match action {
        SystemAction::Stake(amount) => {
            crate::staking::apply_stake(state, &staking, &caller, *amount)
        }
        SystemAction::Unstake(amount) => {
            crate::staking::apply_unstake(state, &staking, &caller, *amount)
        }
        SystemAction::Exit => crate::staking::apply_voluntary_exit(state, &staking, &caller),
        SystemAction::Withdraw => {
            // Only a withdrawal needs the queue: a pending deduction holds it.
            let backlog =
                crate::accountability::Backlog::of(&crate::accountability::load_queue(state));
            crate::staking::apply_withdraw(state, &staking, &backlog, &caller)
        }
        SystemAction::Register {
            pubkey,
            pop,
            amount,
        } => {
            crate::staking::apply_register_validator(state, &staking, &caller, pubkey, pop, *amount)
        }
        SystemAction::RotateKey { pubkey, pop } => {
            crate::staking::apply_rotate_key(state, &staking, &caller, pubkey, pop)
        }
        SystemAction::Propose {
            programs,
            artifacts,
            activate_at_chunk,
        } => crate::governance::apply_propose(
            state,
            &block,
            &caller,
            programs,
            artifacts,
            *activate_at_chunk,
        ),
        SystemAction::Policy(policy) => {
            crate::governance::apply_propose_policy(state, &block, &caller, policy)
        }
        SystemAction::Cancel {
            programs,
            activate_at_chunk,
        } => crate::governance::apply_cancel(state, &block, &caller, programs, *activate_at_chunk),
        SystemAction::ProposeFork(fork) => {
            crate::governance::apply_propose_fork(state, &block, &caller, *fork)
        }
        SystemAction::CancelFork(fork) => {
            crate::governance::apply_cancel_fork(state, &block, &caller, *fork)
        }
        SystemAction::Vote(proposal_id) => {
            crate::governance::apply_vote(state, &block, &caller, proposal_id)
        }
    }
}

/// Seed consensus-facing stake records and the governed system policy at genesis.
pub fn initialize_genesis<B: StateBackend>(
    state: &mut B,
    validators: &[neutrin0_primitives::Validator],
    policy: &RuntimePolicy,
) {
    let mut candidates = neutrin0_consensus_types::runtime::ConsensusCandidates::default();
    for validator in validators {
        let address = validator.withdrawal_credentials;
        if address == [0; 32] {
            continue;
        }
        assert!(
            !candidates.contains(&address),
            "duplicate genesis withdrawal credentials"
        );
        let collateral = validator.effective_stake;
        crate::state::store_validator(state, &address, &crate::Validator { stake: collateral });
        candidates.upsert(neutrin0_consensus_types::runtime::ConsensusCandidate {
            address,
            stake: collateral,
            identity: None,
        });
    }
    if !candidates.entries.is_empty() {
        crate::state::store_consensus_candidates(state, &candidates);
    }
    crate::state::store_runtime_policy(state, policy);
}

/// Derive a genesis policy that leaves room for mandatory work and signature challenges.
#[must_use]
pub fn genesis_policy(input: &neutrin0_runtime_abi::RuntimeGenesisInput) -> RuntimePolicy {
    let policy = RuntimePolicy::from_params(&input.runtime_params);
    let anchor = neutrin0_consensus_types::evidence::EvidenceAnchor {
        chunk_size: input.chunk_size,
        unbonding_delay_blocks: input.runtime_params.unbonding_delay_blocks,
        max_block_proving_input_bytes: input.max_block_proving_input_bytes,
        block_gas_limit: input.block_gas_limit,
        ..Default::default()
    };
    assert!(
        policy.is_valid_for(&anchor),
        "genesis system resource and challenge policy"
    );
    policy
}
