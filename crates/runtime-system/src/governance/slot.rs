//! Slot rules shared by every proposal kind: a slot's live proposals, moving
//! a validator's support, making room for a new proposal and enacting the
//! proposal that reaches quorum.

use alloc::vec::Vec;

use neutrin0_consensus_types::history_proof::ScheduledUpgrade;
use neutrin0_consensus_types::runtime::{FORK_KEY, UPGRADE_KEY};
use neutrin0_runtime_core::StateBackend;

use super::eligibility::authorize_caller;
use super::pieces::{forget_uncollected_pieces, load_pieces, published};
use super::{
    BlockContext, FORK_PROPOSALS_KEY, MAX_SLOT_PROPOSALS, POLICY_PROPOSALS_KEY, ProposalAction,
    UPGRADE_PROPOSALS_KEY, UpgradeProposal, load_scheduled, load_scheduled_fork, proposal_id,
    store_scheduled, upgrade_min_lead_chunks,
};
use crate::state::{
    PendingPolicy, load_runtime_policy, policy_delay_blocks, read_record, store_pending_policy,
    write_record,
};
use crate::{Address, ReceiptStatus, RuntimePolicy, ValidatorSet};

/// The slot a proposal of `action` belongs to.
pub(super) const fn slot_key(action: &ProposalAction) -> &'static [u8] {
    match action {
        ProposalAction::Policy(_) => POLICY_PROPOSALS_KEY,
        ProposalAction::Programs { .. } | ProposalAction::Cancel { .. } => UPGRADE_PROPOSALS_KEY,
        ProposalAction::Fork(_) | ProposalAction::CancelFork(_) => FORK_PROPOSALS_KEY,
    }
}

/// The live proposals of the slot under `key` in `block`.
pub(super) fn live_proposals<B: StateBackend>(
    state: &mut B,
    key: &[u8],
    block: &BlockContext<'_>,
) -> Vec<UpgradeProposal> {
    let min_lead = upgrade_min_lead_chunks(block.anchor);
    let mut slot: Vec<UpgradeProposal> = read_record(state, key).unwrap_or_default();
    slot.retain(|proposal| proposal.is_live(block.chunk, min_lead));
    slot
}

/// Withdraw `voter`'s support from every proposal of `slot`.
pub(super) fn withdraw_support(slot: &mut [UpgradeProposal], voter: &Address) {
    for proposal in slot {
        if let Ok(index) = proposal.voters.binary_search(voter) {
            proposal.voters.remove(index);
        }
    }
}

/// A policy may take effect only if the mandatory sanction queue already
/// fits its capacity: the runtime treats a queue longer than
/// `evidence_max_pending` as an invariant violation, so enacting a smaller
/// bound over a longer backlog would stop every block. Only policy decisions
/// read the queue.
pub(super) fn policy_enactable<B: StateBackend>(state: &mut B, policy: &RuntimePolicy) -> bool {
    crate::accountability::load_queue(state).len() <= policy.evidence_max_pending as usize
}

/// Caller authorization plus the slot rules shared by every proposal kind.
/// Returns the governance set and the slot's live proposals, with room made
/// for `proposer`'s new one.
pub(super) fn check_new_proposal<B: StateBackend>(
    state: &mut B,
    block: &BlockContext<'_>,
    proposer: &Address,
    action: &ProposalAction,
) -> Result<(ValidatorSet, Vec<UpgradeProposal>), ReceiptStatus> {
    let set = authorize_caller(state, proposer, block)?;
    // An enacted switch awaiting its boundary admits only its cancellation in
    // the program slot, and an enacted fork only its cancellation in the fork
    // slot; the policy slot is never blocked.
    let current = block.chunk;
    match action {
        ProposalAction::Programs { .. } | ProposalAction::Cancel { .. } => {
            let scheduled =
                load_scheduled(state).filter(|scheduled| scheduled.activate_at_chunk > current);
            match (action, scheduled) {
                (ProposalAction::Programs { .. }, Some(_)) => {
                    return Err(ReceiptStatus::UpgradeConflict);
                }
                (
                    ProposalAction::Cancel {
                        programs,
                        activate_at_chunk,
                    },
                    scheduled,
                ) if scheduled.is_none_or(|scheduled| {
                    scheduled.programs != *programs
                        || scheduled.activate_at_chunk != *activate_at_chunk
                }) =>
                {
                    return Err(ReceiptStatus::InvalidUpgrade);
                }
                _ => {}
            }
        }
        ProposalAction::Fork(_) | ProposalAction::CancelFork(_) => {
            let scheduled = load_scheduled_fork(state).filter(|fork| fork.count > current);
            match (action, scheduled) {
                (ProposalAction::Fork(_), Some(_)) => return Err(ReceiptStatus::UpgradeConflict),
                (ProposalAction::CancelFork(fork), scheduled) if scheduled != Some(*fork) => {
                    return Err(ReceiptStatus::InvalidUpgrade);
                }
                _ => {}
            }
        }
        ProposalAction::Policy(_) => {}
    }
    let mut slot = live_proposals(state, slot_key(action), block);
    let id = proposal_id(proposer, action);
    if slot.iter().any(|proposal| proposal.id() == id) {
        return Err(ReceiptStatus::UpgradeConflict);
    }
    // A proposer holds one proposal per slot, and its support moves to the
    // new one.
    slot.retain(|proposal| proposal.proposer != *proposer);
    withdraw_support(&mut slot, proposer);
    // Every seat has room, so only proposals of departed proposers can fill
    // the slot; then the least supported yields to more support.
    if slot.len() >= MAX_SLOT_PROPOSALS {
        let support = set
            .entries
            .iter()
            .find(|entry| entry.address == *proposer)
            .map_or(0, |entry| entry.stake);
        let (weakest, weakest_support) = slot
            .iter()
            .map(|proposal| proposal.voted_stake(&set))
            .enumerate()
            .min_by_key(|(_, support)| *support)
            .ok_or(ReceiptStatus::UpgradeConflict)?;
        if weakest_support >= support {
            return Err(ReceiptStatus::UpgradeConflict);
        }
        slot.remove(weakest);
    }
    Ok((set, slot))
}

/// Enact `slot[index]` when it reaches quorum, closing its whole slot;
/// otherwise store the slot's live proposals.
pub(super) fn settle<B: StateBackend>(
    state: &mut B,
    block: &BlockContext<'_>,
    mut slot: Vec<UpgradeProposal>,
    index: usize,
    set: &ValidatorSet,
) {
    let key = slot_key(&slot[index].action);
    if !slot[index].quorum_reached(set) {
        write_record(state, key, &slot);
        return;
    }
    // The decision is made: the slot's competing proposals close with it.
    let proposal = slot.swap_remove(index);
    if state.read(key).is_some() {
        state.delete(key);
    }
    match proposal.action {
        ProposalAction::Programs {
            programs,
            artifacts,
            activate_at_chunk,
        } => {
            // Pieces published while the proposal was open already count.
            let available = published(&load_pieces(state), &block.programs, &programs, &artifacts);
            store_scheduled(
                state,
                &ScheduledUpgrade {
                    activate_at_chunk,
                    programs,
                    artifacts,
                    available,
                },
            );
        }
        ProposalAction::Cancel { .. } => {
            state.delete(UPGRADE_KEY);
        }
        ProposalAction::Fork(fork) => write_record(state, FORK_KEY, &fork),
        ProposalAction::CancelFork(_) => state.delete(FORK_KEY),
        ProposalAction::Policy(policy) => {
            let current = load_runtime_policy(state);
            store_pending_policy(
                state,
                &PendingPolicy {
                    policy,
                    effective_height: block.height.saturating_add(policy_delay_blocks(
                        &current,
                        &policy,
                        block.anchor,
                    )),
                },
            );
        }
    }
    forget_uncollected_pieces(state);
}
