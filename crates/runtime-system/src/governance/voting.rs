//! Votes: a validator moves its support to one live proposal of a slot, and
//! the vote that reaches quorum enacts.

#![allow(
    clippy::redundant_pub_crate,
    reason = "The vote handler stays explicitly crate-scoped inside this private module."
)]

use neutrin0_runtime_core::StateBackend;

use super::eligibility::authorize_caller;
use super::slot::{live_proposals, policy_enactable, settle, withdraw_support};
use super::{
    BlockContext, FORK_PROPOSALS_KEY, POLICY_PROPOSALS_KEY, ProposalAction, UPGRADE_PROPOSALS_KEY,
    load_scheduled, load_scheduled_fork,
};
use crate::{Address, ReceiptStatus};

/// Support the live proposal identified by `proposal_id`, moving the voter's
/// support away from any other proposal of its slot, and enact when quorum
/// is reached. Weight is the voter's counted stake at tally time.
pub(crate) fn apply_vote<B: StateBackend>(
    state: &mut B,
    block: &BlockContext<'_>,
    voter: &Address,
    proposal_id: &[u8; 32],
) -> Result<(), ReceiptStatus> {
    let set = authorize_caller(state, voter, block)?;
    let (mut slot, index) = [
        UPGRADE_PROPOSALS_KEY,
        POLICY_PROPOSALS_KEY,
        FORK_PROPOSALS_KEY,
    ]
    .into_iter()
    .find_map(|key| {
        let slot = live_proposals(state, key, block);
        let index = slot
            .iter()
            .position(|proposal| proposal.id() == *proposal_id)?;
        Some((slot, index))
    })
    .ok_or(ReceiptStatus::InvalidUpgrade)?;
    let proposal = &slot[index];
    if let ProposalAction::Programs { programs, .. } = proposal.action
        && programs.execution.fact != block.anchor.fact_guest_vk_digest
    {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    if let ProposalAction::Cancel {
        programs,
        activate_at_chunk,
    } = proposal.action
        && !load_scheduled(state).is_some_and(|scheduled| {
            scheduled.programs == programs && scheduled.activate_at_chunk == activate_at_chunk
        })
    {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    if let ProposalAction::CancelFork(fork) = proposal.action
        && load_scheduled_fork(state) != Some(fork)
    {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    if proposal.voters.binary_search(voter).is_ok() {
        return Err(ReceiptStatus::AlreadyVoted);
    }
    // A validator supports one proposal per slot: the vote moves its support.
    withdraw_support(&mut slot, voter);
    let proposal = &mut slot[index];
    let position = proposal
        .voters
        .binary_search(voter)
        .unwrap_or_else(|position| position);
    proposal.voters.insert(position, *voter);
    // The vote that would enact a policy the live queue no longer fits fails
    // instead; the proposal stays open and the vote can be cast once the
    // mandatory queue has drained.
    if let ProposalAction::Policy(policy) = proposal.action
        && proposal.quorum_reached(&set)
        && !policy_enactable(state, &policy)
    {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    settle(state, block, slot, index, &set);
    Ok(())
}
