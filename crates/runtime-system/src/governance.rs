//! Runtime governance for program upgrades and economic policy (design 20).
//!
//! The rules here are ordinary runtime rules and therefore upgradable with
//! the runtime, exactly as a governance pallet dispatching `set_code` is in
//! Substrate. Consensus only consumes the result: the chunk Guest reads the
//! [`ScheduledUpgrade`] under [`UPGRADE_KEY`] from the authenticated
//! post-state and switches program sets at the boundary entering
//! `activate_at_chunk`. Nothing outside this module writes that record.
//!
//! A hard fork is decided here too: an enacted [`ScheduledFork`] under
//! [`FORK_KEY`] travels in every consensus boundary until its count, where
//! the chain Guest ends this chain and the successor the fork names takes
//! over (design 20).
//!
//! Decision model: program, policy and fork proposals live in separate slots. Each
//! slot holds every live proposal of its kind, at most one per proposer, so
//! no validator can occupy a slot: support decides, never the proposer's own
//! stake. A validator supports at most one proposal per slot, and a vote
//! moves its support. The proposal whose supporters hold at least two thirds
//! of the active stake is enacted at once and closes every other proposal in
//! its slot. The proposer's own stake counts as a vote, so a validator
//! holding the threshold alone enacts at proposal time. An unenacted proposal
//! expires [`UPGRADE_VOTING_PERIOD_CHUNKS`] after it was made. Proposers and
//! voters are the callers the enclosing engine authenticated.
//!
//! An enacted program switch can be cancelled by the same quorum until its
//! activation chunk, and it activates only if every artifact it names was
//! completely published in the program lane by then; otherwise it is void.
//! An enacted fork can be cancelled by the same quorum until its count.
//! An enacted policy takes effect after a delay: one unbonding delay plus two
//! blocks when it changes stake risk, 64 chunks otherwise.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::evidence::EvidenceAnchor;
use neutrin0_runtime_core::StateBackend;

use crate::state::{PendingPolicy, load_pending_policy, read_record, write_record};
use crate::{Address, RuntimePolicy, ValidatorSet};
use neutrin0_consensus_types::history_proof::ProgramArtifacts;
use neutrin0_consensus_types::history_proof::{ProgramSet, ScheduledFork, ScheduledUpgrade};
use neutrin0_consensus_types::runtime::{FORK_KEY, UPGRADE_KEY};

mod eligibility;
mod pieces;
mod proposals;
mod slot;
mod voting;

pub(crate) use eligibility::record_bond;
pub use pieces::load_pieces;
pub(crate) use pieces::record_program_pieces;
pub(crate) use proposals::{
    apply_cancel, apply_cancel_fork, apply_propose, apply_propose_fork, apply_propose_policy,
};
pub(crate) use voting::apply_vote;

use pieces::forget_uncollected_pieces;

/// Gas charged for a proposal, which writes the open-proposal record.
pub const GAS_PROPOSE_UPGRADE: u64 = 100_000;
/// Gas charged for a vote, which rewrites its slot's proposals.
pub const GAS_VOTE_UPGRADE: u64 = 40_000;

/// Domain tag of the proposal identity hash.
pub const DOMAIN_UPGRADE_PROPOSAL_ID: &[u8; 16] = b"NTRO/upg-prop-id";

/// Canonical key of the program slot: the program switch and cancellation
/// [`UpgradeProposal`]s, at most one per proposer.
pub const UPGRADE_PROPOSALS_KEY: &[u8] = b"upgrade:proposals";

/// Canonical key of the policy slot: the policy [`UpgradeProposal`]s, at most
/// one per proposer.
pub const POLICY_PROPOSALS_KEY: &[u8] = b"policy:proposals";

/// Canonical key of the fork slot: the hard fork and fork cancellation
/// [`UpgradeProposal`]s, at most one per proposer.
pub const FORK_PROPOSALS_KEY: &[u8] = b"fork:proposals";

/// Most proposals one slot holds: one per proposer, and no more validators
/// are seated at once, so every eligible proposer has room.
pub const MAX_SLOT_PROPOSALS: usize = neutrin0_primitives::MAX_CONSENSUS_VALIDATORS;

/// Canonical key of the program-lane pieces seen for the artifacts an open
/// program proposal or an unavailable schedule names.
pub const UPGRADE_PIECES_KEY: &[u8] = b"upgrade:pieces";

/// Minimum distance, in chunks, from enactment to activation of a program
/// switch or a hard fork under `anchor`'s genesis-fixed unbonding delay and
/// chunk size.
///
/// A program switch or a fork can rewrite every rule, so whoever disagrees
/// with one must be able to leave first: stake unbonded in the block after
/// enactment matures and is withdrawn under the current programs. The
/// enactment block may be the last of its chunk, so the lead is that chunk
/// plus every chunk the unbonding delay and the withdrawal block span.
#[must_use]
pub const fn upgrade_min_lead_chunks(anchor: &EvidenceAnchor) -> u64 {
    let chunk_size = if anchor.chunk_size == 0 {
        1
    } else {
        anchor.chunk_size
    };
    anchor
        .unbonding_delay_blocks
        .saturating_add(1)
        .div_ceil(chunk_size)
        .saturating_add(1)
}

/// Number of chunks, starting at the earliest permitted one, a proposal may
/// choose as its activation. Bounds how long an enacted switch can occupy the
/// single governance slot beyond its mandatory lead.
pub const UPGRADE_ACTIVATION_WINDOW_CHUNKS: u64 = 1024;

/// Chunks a proposal stays open for votes after the chunk it was made in.
///
/// An unenacted proposal expires afterwards and leaves its slot when the slot
/// is next written; views and votes ignore it at once.
pub const UPGRADE_VOTING_PERIOD_CHUNKS: u64 = 64;

/// Stake fraction of the eligible validator set that must have voted for a
/// proposal before it is enacted, as `(numerator, denominator)`.
pub const UPGRADE_QUORUM: (u128, u128) = (2, 3);

/// Blocks a registration, and any stake added to a validator afterwards,
/// must have aged before it counts in governance, as proposer, voter or
/// quorum denominator.
///
/// Consensus seats a registration only after its activation delay;
/// governance must not let freshly bonded stake decide an upgrade sooner
/// than that. Genesis validators have no registration record and are always
/// eligible; their later additions age like anyone else's.
pub const UPGRADE_VOTER_MIN_AGE_BLOCKS: u64 = 1024;

/// What a proposal enacts when it reaches quorum.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "Borsh wire type held once per proposal; both variants are plain data copied once."
)]
pub enum ProposalAction {
    /// Switch program sets at a chunk boundary (design 20, switching rule).
    Programs {
        /// Program set to activate. The Fact digest must retain the genesis
        /// pin. Governance names the runtime code hash and every other Guest
        /// digest; the pairing is audited off chain through reproducible
        /// builds, the runtime cannot verify it.
        programs: ProgramSet,
        /// Content hashes of the artifacts behind `programs`, so nodes know
        /// which program-lane pieces to assemble and install.
        artifacts: ProgramArtifacts,
        /// First chunk executed under `programs`.
        activate_at_chunk: u64,
    },
    /// Replace the governable runtime policy. Enactment schedules it for the
    /// first block after its delay (design 20).
    Policy(RuntimePolicy),
    /// Cancel the enacted, not yet activated switch to `programs` at
    /// `activate_at_chunk`.
    Cancel {
        /// Program set of the scheduled switch.
        programs: ProgramSet,
        /// Activation chunk of the scheduled switch.
        activate_at_chunk: u64,
    },
    /// End this chain at the fork's count, where the successor pinning the
    /// programs the fork commits takes over (design 20). Governance names the
    /// successor by commitment; the programs behind it are audited off chain
    /// through reproducible builds.
    Fork(ScheduledFork),
    /// Cancel the enacted fork before its count.
    CancelFork(ScheduledFork),
}

/// A proposal in its slot's list, under [`UPGRADE_PROPOSALS_KEY`],
/// [`POLICY_PROPOSALS_KEY`] or [`FORK_PROPOSALS_KEY`].
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposal {
    /// Proposing validator.
    pub proposer: Address,
    /// What quorum enacts.
    pub action: ProposalAction,
    /// Chunk the proposal was made in.
    pub proposed_at_chunk: u64,
    /// Validators supporting it, sorted ascending; each supports at most one
    /// proposal of its slot.
    pub voters: Vec<Address>,
}

impl UpgradeProposal {
    /// Identity bound by every vote; see [`proposal_id`].
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        proposal_id(&self.proposer, &self.action)
    }

    /// Stake of the current active validators that voted.
    #[must_use]
    pub fn voted_stake(&self, set: &ValidatorSet) -> u128 {
        set.entries
            .iter()
            .filter(|entry| self.voters.binary_search(&entry.address).is_ok())
            .fold(0u128, |sum, entry| sum.saturating_add(entry.stake))
    }

    /// `true` once voters hold at least [`UPGRADE_QUORUM`] of the active stake.
    #[must_use]
    pub fn quorum_reached(&self, set: &ValidatorSet) -> bool {
        let total = set.total_stake();
        total > 0 && quorum_reached(self.voted_stake(set), total, UPGRADE_QUORUM)
    }

    /// `true` while the proposal is still open: its voting period has not
    /// ended and, for a program switch, it can still be enacted at least
    /// `min_lead` chunks before its activation chunk.
    #[must_use]
    pub fn is_live(&self, current_chunk: u64, min_lead: u64) -> bool {
        let in_voting_period = self
            .proposed_at_chunk
            .checked_add(UPGRADE_VOTING_PERIOD_CHUNKS)
            .is_some_and(|deadline| current_chunk <= deadline);
        in_voting_period
            && match self.action {
                ProposalAction::Programs {
                    activate_at_chunk, ..
                } => activation_in_time(activate_at_chunk, current_chunk, min_lead),
                ProposalAction::Cancel {
                    activate_at_chunk, ..
                } => activate_at_chunk > current_chunk,
                ProposalAction::Fork(fork) => {
                    activation_in_time(fork.count, current_chunk, min_lead)
                }
                ProposalAction::CancelFork(fork) => fork.count > current_chunk,
                ProposalAction::Policy(_) => true,
            }
    }
}

/// Snapshot returned by the `upgrade_status` query. Stored proposals may have
/// expired since; [`UpgradeProposal::is_live`] tells.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct UpgradeStatus {
    /// Program switch and cancellation proposals.
    pub proposals: Vec<UpgradeProposal>,
    /// Enacted switch not yet consumed by the chunk Guest, if any.
    pub scheduled: Option<ScheduledUpgrade>,
    /// Policy proposals.
    pub policy_proposals: Vec<UpgradeProposal>,
    /// Enacted policy waiting for its effective height, if any.
    pub pending_policy: Option<PendingPolicy>,
    /// Fork and fork cancellation proposals.
    pub fork_proposals: Vec<UpgradeProposal>,
    /// Enacted fork whose count this chain has not reached, if any.
    pub scheduled_fork: Option<ScheduledFork>,
}

/// Program-lane pieces seen for one artifact.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactPieces {
    /// Content hash of the artifact.
    pub artifact: [u8; 32],
    /// Number of pieces of the artifact.
    pub count: u64,
    /// Bit `i` is set once piece `i` was published.
    pub received: u64,
}

impl ArtifactPieces {
    /// `true` once every piece was published.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.count > 0
            && self.count <= 64
            && self.received
                == if self.count == 64 {
                    u64::MAX
                } else {
                    (1 << self.count) - 1
                }
    }
}

/// `BLAKE3(DOMAIN_UPGRADE_PROPOSAL_ID || proposer || borsh(action))`.
#[must_use]
pub fn proposal_id(proposer: &Address, action: &ProposalAction) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_UPGRADE_PROPOSAL_ID);
    hasher.update(proposer);
    hasher.update(&borsh::to_vec(action).expect("borsh encode ProposalAction never fails"));
    *hasher.finalize().as_bytes()
}

/// `stake / total >= numerator / denominator` without overflow for any
/// `stake <= total`: `stake * d >= total * n` is evaluated as
/// `stake >= ceil(total * n / d)` through `total - floor(total * (d - n) / d)`.
fn quorum_reached(stake: u128, total: u128, (numerator, denominator): (u128, u128)) -> bool {
    debug_assert!(numerator <= denominator && denominator > 0);
    // total * (d - n) / d never exceeds total, so the division is exact
    // enough: ceil(total * n / d) == total - floor(total * (d - n) / d).
    stake >= total - crate::mul_div_floor(total, denominator - numerator, denominator)
}

/// Load the program slot's stored proposals, live or expired.
pub fn load_proposals<B: StateBackend>(state: &mut B) -> Vec<UpgradeProposal> {
    read_record(state, UPGRADE_PROPOSALS_KEY).unwrap_or_default()
}

/// Load the policy slot's stored proposals, live or expired.
pub fn load_policy_proposals<B: StateBackend>(state: &mut B) -> Vec<UpgradeProposal> {
    read_record(state, POLICY_PROPOSALS_KEY).unwrap_or_default()
}

/// Load the fork slot's stored proposals, live or expired.
pub fn load_fork_proposals<B: StateBackend>(state: &mut B) -> Vec<UpgradeProposal> {
    read_record(state, FORK_PROPOSALS_KEY).unwrap_or_default()
}

/// Load the enacted, not yet consumed, switch if any.
pub fn load_scheduled<B: StateBackend>(state: &mut B) -> Option<ScheduledUpgrade> {
    read_record(state, UPGRADE_KEY)
}

fn store_scheduled<B: StateBackend>(state: &mut B, scheduled: &ScheduledUpgrade) {
    write_record(state, UPGRADE_KEY, scheduled);
}

/// Load the enacted fork, if any.
pub fn load_scheduled_fork<B: StateBackend>(state: &mut B) -> Option<ScheduledFork> {
    read_record(state, FORK_KEY)
}

/// Block-start housekeeping.
///
/// A schedule whose activation chunk has been reached was consumed by the
/// chunk Guest at the boundary entering it, or was void there because its
/// artifacts were never completely published, so it is deleted. A block at
/// or beyond a fork's count runs under the successor: the fork is done, and
/// a switch scheduled for the predecessor's programs does not carry over.
/// Expired proposals are left to the next write of their slot, so no block
/// reads the slots unless a transaction acts on them.
pub fn expire<B: StateBackend>(state: &mut B, anchor: &EvidenceAnchor) {
    if load_scheduled_fork(state).is_some_and(|fork| fork.count <= anchor.chunk_id) {
        state.delete(FORK_KEY);
        if state.read(UPGRADE_KEY).is_some() {
            state.delete(UPGRADE_KEY);
        }
    }
    if load_scheduled(state).is_some_and(|scheduled| scheduled.activate_at_chunk <= anchor.chunk_id)
    {
        state.delete(UPGRADE_KEY);
    }
    forget_uncollected_pieces(state);
}

/// Read the current status for the `upgrade_status` query.
pub fn status<B: StateBackend>(state: &mut B) -> UpgradeStatus {
    UpgradeStatus {
        proposals: load_proposals(state),
        scheduled: load_scheduled(state),
        policy_proposals: load_policy_proposals(state),
        pending_policy: load_pending_policy(state),
        fork_proposals: load_fork_proposals(state),
        scheduled_fork: load_scheduled_fork(state),
    }
}

/// `true` when `activate_at_chunk` is still at least `min_lead` chunks ahead.
fn activation_in_time(activate_at_chunk: u64, current_chunk: u64, min_lead: u64) -> bool {
    current_chunk
        .checked_add(min_lead)
        .is_some_and(|earliest| activate_at_chunk >= earliest)
}

/// Block facts governance execution checks against.
pub(crate) struct BlockContext<'a> {
    /// Chunk containing the block.
    pub(crate) chunk: u64,
    /// Height of the block.
    pub(crate) height: u64,
    /// Genesis-fixed facts a policy must respect.
    pub(crate) anchor: &'a EvidenceAnchor,
    /// The block's authenticated consensus validator set.
    pub(crate) seats: &'a [neutrin0_primitives::Validator],
    /// Program set the block executes under.
    pub(crate) programs: ProgramSet,
}

#[cfg(test)]
mod tests;
