//! The proposal entry points of the program, fork and policy slots. Each
//! opens a proposal the proposer's own stake already supports and enacts at
//! once when that stake alone reaches quorum.

#![allow(
    clippy::redundant_pub_crate,
    reason = "Transaction handlers stay explicitly crate-scoped inside this private module."
)]

use neutrin0_consensus_types::history_proof::{ProgramArtifacts, ProgramSet, ScheduledFork};
use neutrin0_runtime_core::StateBackend;

use super::pieces::changed_artifacts;
use super::slot::{check_new_proposal, policy_enactable, settle};
use super::{
    BlockContext, ProposalAction, UPGRADE_ACTIVATION_WINDOW_CHUNKS, UpgradeProposal,
    activation_in_time, upgrade_min_lead_chunks,
};
use crate::{Address, ReceiptStatus, RuntimePolicy};

/// Chunk-relative checks of a new proposal: the activation chunk must fall in
/// the [`UPGRADE_ACTIVATION_WINDOW_CHUNKS`] chunks starting `min_lead` chunks
/// after the current one.
fn proposal_shape_ok(activate_at_chunk: u64, current_chunk: u64, min_lead: u64) -> bool {
    activation_in_time(activate_at_chunk, current_chunk, min_lead)
        && current_chunk
            .checked_add(min_lead)
            .and_then(|earliest| earliest.checked_add(UPGRADE_ACTIVATION_WINDOW_CHUNKS - 1))
            .is_some_and(|latest| activate_at_chunk <= latest)
}

/// Propose a program set to activate at a chunk boundary; the proposer's
/// stake votes for it and enacts at once when it alone reaches quorum.
pub(crate) fn apply_propose<B: StateBackend>(
    state: &mut B,
    block: &BlockContext<'_>,
    proposer: &Address,
    programs: &ProgramSet,
    artifacts: &ProgramArtifacts,
    activate_at_chunk: u64,
) -> Result<(), ReceiptStatus> {
    let action = ProposalAction::Programs {
        programs: *programs,
        artifacts: *artifacts,
        activate_at_chunk,
    };
    let (set, mut slot) = check_new_proposal(state, block, proposer, &action)?;
    if !programs.is_complete()
        || !proposal_shape_ok(
            activate_at_chunk,
            block.chunk,
            upgrade_min_lead_chunks(block.anchor),
        )
        || programs.execution.fact != block.anchor.fact_guest_vk_digest
        || !names_changed_artifacts(&block.programs, programs, artifacts)
    {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    slot.push(UpgradeProposal {
        proposer: *proposer,
        action,
        proposed_at_chunk: block.chunk,
        voters: alloc::vec![*proposer],
    });
    let index = slot.len() - 1;
    settle(state, block, slot, index, &set);
    Ok(())
}

/// Every program a switch changes names the content hash of its artifact, so
/// its availability can be checked before activation (design 20).
fn names_changed_artifacts(
    current: &ProgramSet,
    next: &ProgramSet,
    artifacts: &ProgramArtifacts,
) -> bool {
    changed_artifacts(current, next, artifacts).all(|artifact| artifact != [0; 32])
}

/// Propose cancelling the enacted switch to `programs` at
/// `activate_at_chunk`; the proposer's stake votes for it.
pub(crate) fn apply_cancel<B: StateBackend>(
    state: &mut B,
    block: &BlockContext<'_>,
    proposer: &Address,
    programs: &ProgramSet,
    activate_at_chunk: u64,
) -> Result<(), ReceiptStatus> {
    let action = ProposalAction::Cancel {
        programs: *programs,
        activate_at_chunk,
    };
    let (set, mut slot) = check_new_proposal(state, block, proposer, &action)?;
    slot.push(UpgradeProposal {
        proposer: *proposer,
        action,
        proposed_at_chunk: block.chunk,
        voters: alloc::vec![*proposer],
    });
    let index = slot.len() - 1;
    settle(state, block, slot, index, &set);
    Ok(())
}

/// Propose ending this chain at `fork.count` for the successor whose pinned
/// programs `fork.successor` commits; the proposer's stake votes for it.
pub(crate) fn apply_propose_fork<B: StateBackend>(
    state: &mut B,
    block: &BlockContext<'_>,
    proposer: &Address,
    fork: ScheduledFork,
) -> Result<(), ReceiptStatus> {
    let action = ProposalAction::Fork(fork);
    let (set, mut slot) = check_new_proposal(state, block, proposer, &action)?;
    if fork.successor == [0; 32]
        || !proposal_shape_ok(
            fork.count,
            block.chunk,
            upgrade_min_lead_chunks(block.anchor),
        )
    {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    slot.push(UpgradeProposal {
        proposer: *proposer,
        action,
        proposed_at_chunk: block.chunk,
        voters: alloc::vec![*proposer],
    });
    let index = slot.len() - 1;
    settle(state, block, slot, index, &set);
    Ok(())
}

/// Propose cancelling the enacted `fork`; the proposer's stake votes for it.
pub(crate) fn apply_cancel_fork<B: StateBackend>(
    state: &mut B,
    block: &BlockContext<'_>,
    proposer: &Address,
    fork: ScheduledFork,
) -> Result<(), ReceiptStatus> {
    let action = ProposalAction::CancelFork(fork);
    let (set, mut slot) = check_new_proposal(state, block, proposer, &action)?;
    slot.push(UpgradeProposal {
        proposer: *proposer,
        action,
        proposed_at_chunk: block.chunk,
        voters: alloc::vec![*proposer],
    });
    let index = slot.len() - 1;
    settle(state, block, slot, index, &set);
    Ok(())
}

/// Propose a new [`RuntimePolicy`] against the authenticated anchor's fixed
/// facts.
pub(crate) fn apply_propose_policy<B: StateBackend>(
    state: &mut B,
    block: &BlockContext<'_>,
    proposer: &Address,
    policy: &RuntimePolicy,
) -> Result<(), ReceiptStatus> {
    let action = ProposalAction::Policy(*policy);
    let (set, mut slot) = check_new_proposal(state, block, proposer, &action)?;
    if !policy.is_valid_for(block.anchor) || !policy_enactable(state, policy) {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    slot.push(UpgradeProposal {
        proposer: *proposer,
        action,
        proposed_at_chunk: block.chunk,
        voters: alloc::vec![*proposer],
    });
    let index = slot.len() - 1;
    settle(state, block, slot, index, &set);
    Ok(())
}
