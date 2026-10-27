//! Validator activation and exit transitions over the runtime's
//! consensus-facing candidate record.
//!
//! Consensus reads exactly three runtime keys: the candidate record under
//! [`CONSENSUS_CANDIDATES_KEY`], the scheduled upgrade under [`UPGRADE_KEY`]
//! and the scheduled hard fork under [`FORK_KEY`]. How the runtime
//! represents accounts, stake or registrations behind that record is its own
//! business, so the staking economics change without this Guest changing.

use alloc::vec::Vec;

use neutrin0_consensus_types::history_proof::{ProgramSet, ScheduledFork};
use neutrin0_consensus_types::runtime::{
    CONSENSUS_CANDIDATES_KEY, ConsensusCandidates, FORK_KEY, UPGRADE_KEY,
};
use neutrin0_primitives::{ConsensusParams, Hash, Validator};
use neutrin0_runtime_abi::StateWitness;
use neutrin0_runtime_core::{StateBackend, WitnessState};

mod transition;

pub use transition::derive_next_validators;

/// The runtime keys the transition reads: the candidate record, the
/// scheduled upgrade and the scheduled hard fork.
#[must_use]
pub fn witness_keys() -> Vec<Vec<u8>> {
    alloc::vec![
        CONSENSUS_CANDIDATES_KEY.to_vec(),
        UPGRADE_KEY.to_vec(),
        FORK_KEY.to_vec(),
    ]
}

/// Read the keys through `state` so a tracing backend records them, and
/// return [`witness_keys`].
pub fn witness_keys_from<B: StateBackend>(state: &mut B) -> Vec<Vec<u8>> {
    let keys = witness_keys();
    for key in &keys {
        let _ = state.read(key);
    }
    keys
}

/// Program set the next chunk runs under, from the authenticated post-state.
///
/// Reads are authenticated against `post_state_root`, which must be the last
/// recursively verified block's post-state root, exactly as in
/// [`rotate_from_witness`]. The record applies by [`programs_entering`]. The
/// key must have been witnessed (see [`witness_keys`]).
///
/// # Errors
/// Returns [`RotationError::StateRoot`] when the witness is not rooted at
/// `post_state_root` and [`RotationError::Witness`] when the key was not
/// witnessed or the witness is malformed.
pub fn next_programs_from_witness(
    current: ProgramSet,
    next_chunk_id: u64,
    post_state_root: Hash,
    witness: &StateWitness,
) -> Result<ProgramSet, RotationError> {
    check_state_root(post_state_root, witness)?;
    if !witnessed(witness, UPGRADE_KEY) {
        return Err(RotationError::Witness);
    }
    let mut state = WitnessState::new(witness).map_err(|_| RotationError::Witness)?;
    Ok(programs_entering(
        current,
        next_chunk_id,
        state.read(UPGRADE_KEY).as_deref(),
    ))
}

/// A witness authenticates reads only against its own claimed root, so every
/// reader first binds that root to the proven chunk-end state.
fn check_state_root(post_state_root: Hash, witness: &StateWitness) -> Result<(), RotationError> {
    if witness.pre_state_root == post_state_root {
        Ok(())
    } else {
        Err(RotationError::StateRoot)
    }
}

fn witnessed(witness: &StateWitness, key: &[u8]) -> bool {
    witness.witnessed_keys.iter().any(|entry| entry == key)
}

/// Program set in force at the boundary entering `next_chunk_id`, given the
/// scheduled-upgrade `record` of the previous chunk's end state. The engine
/// and the chunk Guest share this rule.
///
/// A schedule switches exactly at its activation boundary if its artifacts
/// were completely published in the program lane (design 20). Any other
/// schedule is void and the current set stays in force: one not yet due or
/// already past, one never completely published, one that does not decode,
/// names an incomplete set or replaces the Fact Guest. The record is runtime
/// state the Guests cannot correct, so refusing it would leave every later
/// chunk unprovable; voiding it keeps the chain live under the set it already
/// trusts. The incoming Fact identity is the immutable chain pin, so even an
/// upgraded runtime may not delegate consensus cryptography to new code.
#[must_use]
pub fn programs_entering(
    current: ProgramSet,
    next_chunk_id: u64,
    record: Option<&[u8]>,
) -> ProgramSet {
    let Some(upgrade) = record.and_then(|bytes| {
        borsh::from_slice::<neutrin0_consensus_types::history_proof::ScheduledUpgrade>(bytes).ok()
    }) else {
        return current;
    };
    if upgrade.activate_at_chunk == next_chunk_id
        && upgrade.available
        && upgrade.programs.is_complete()
        && upgrade.programs.execution.fact == current.execution.fact
    {
        upgrade.programs
    } else {
        current
    }
}

/// The hard fork the boundary entering `next_chunk_id` carries.
///
/// `record` is the runtime's [`FORK_KEY`] record in the post-state before
/// that boundary: the scheduled fork applies while its count is not behind
/// the chunk. A record that does not decode schedules nothing.
#[must_use]
pub fn fork_entering(next_chunk_id: u64, record: Option<&[u8]>) -> Option<ScheduledFork> {
    record
        .and_then(|bytes| borsh::from_slice::<ScheduledFork>(bytes).ok())
        .filter(|fork| fork.count >= next_chunk_id)
}

/// The consensus records of one authenticated chunk-end state, read through a
/// single [`WitnessState`].
pub(crate) struct ConsensusRecords {
    /// Trie view of the chunk-end state.
    state: WitnessState,
    /// Decoded candidate record; the default when the key is absent.
    candidates: ConsensusCandidates,
    /// Whether the scheduled-upgrade key was witnessed.
    upgrade_witnessed: bool,
    /// Whether the scheduled-fork key was witnessed.
    fork_witnessed: bool,
}

/// Check the witness root and the candidate key, build the witness state once
/// and decode the candidate record.
///
/// Errors match [`rotate_from_witness`] in order: root, unwitnessed candidate
/// key, malformed witness, then candidate codec. The upgrade and fork records
/// are read only by [`ConsensusRecords::next_programs`] and
/// [`ConsensusRecords::next_fork`].
pub(crate) fn read_consensus_records(
    post_state_root: Hash,
    witness: &StateWitness,
) -> Result<ConsensusRecords, RotationError> {
    check_state_root(post_state_root, witness)?;
    if !witnessed(witness, CONSENSUS_CANDIDATES_KEY) {
        return Err(RotationError::Witness);
    }
    let mut state = WitnessState::new(witness).map_err(|_| RotationError::Witness)?;
    let candidates: ConsensusCandidates = decode_or_default(state.read(CONSENSUS_CANDIDATES_KEY))?;
    if candidates.entries.len() > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS {
        return Err(RotationError::Committee);
    }
    if candidates
        .entries
        .windows(2)
        .any(|entries| entries[0].address >= entries[1].address)
    {
        return Err(RotationError::Codec);
    }
    Ok(ConsensusRecords {
        state,
        candidates,
        upgrade_witnessed: witnessed(witness, UPGRADE_KEY),
        fork_witnessed: witnessed(witness, FORK_KEY),
    })
}

impl ConsensusRecords {
    /// Canonical candidate projection used by the independent sanctions ledger.
    pub(crate) const fn candidates(&self) -> &ConsensusCandidates {
        &self.candidates
    }
    /// [`derive_next_validators`] over the authenticated candidate record.
    pub(crate) fn next_validators(
        &self,
        previous: &[Validator],
        params: &ConsensusParams,
        unbonding_delay_blocks: u64,
        chunk_id: u64,
    ) -> Result<Vec<Validator>, RotationError> {
        derive_next_validators(
            previous,
            &self.candidates,
            params,
            unbonding_delay_blocks,
            chunk_id,
        )
    }

    /// [`next_programs_from_witness`] over the same witness state.
    pub(crate) fn next_programs(
        &mut self,
        current: ProgramSet,
        next_chunk_id: u64,
    ) -> Result<ProgramSet, RotationError> {
        if !self.upgrade_witnessed {
            return Err(RotationError::Witness);
        }
        Ok(programs_entering(
            current,
            next_chunk_id,
            self.state.read(UPGRADE_KEY).as_deref(),
        ))
    }

    /// [`fork_entering`] over the same witness state.
    pub(crate) fn next_fork(
        &mut self,
        next_chunk_id: u64,
    ) -> Result<Option<ScheduledFork>, RotationError> {
        if !self.fork_witnessed {
            return Err(RotationError::Witness);
        }
        Ok(fork_entering(
            next_chunk_id,
            self.state.read(FORK_KEY).as_deref(),
        ))
    }
}

/// Runtime state or epoch configuration is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationError {
    /// No usable successor committee exists, or certificate/history bounds fail.
    Committee,
    /// Witness root does not match the proven final block state.
    StateRoot,
    /// A trie witness is malformed or a required key was not witnessed.
    Witness,
    /// Runtime state does not decode canonically.
    Codec,
    /// Zero epoch duration or overflowing chunk/epoch arithmetic.
    Epoch,
    /// The next set's total weight exceeds `u128`. The chain specification
    /// bounds its total, and the runtime its stakes together with each seat's
    /// weight beyond its stake, by [`neutrin0_primitives::MAX_TOTAL_STAKE`],
    /// so a runtime that keeps its bound never leads here.
    Stake,
}

/// Derive the next consensus set from the trie-authenticated candidate record.
///
/// Reads are authenticated against `post_state_root`, which must itself be
/// the last recursively verified block's post-state root. The incoming set
/// must be authenticated by the preceding consensus checkpoint.
pub fn rotate_from_witness(
    previous: &[Validator],
    params: &ConsensusParams,
    unbonding_delay_blocks: u64,
    chunk_id: u64,
    post_state_root: Hash,
    witness: &StateWitness,
) -> Result<Vec<Validator>, RotationError> {
    let records = read_consensus_records(post_state_root, witness)?;
    records.next_validators(previous, params, unbonding_delay_blocks, chunk_id)
}

fn decode_or_default<T: borsh::BorshDeserialize + Default>(
    bytes: Option<Vec<u8>>,
) -> Result<T, RotationError> {
    bytes.map_or_else(
        || Ok(T::default()),
        |bytes| borsh::from_slice(&bytes).map_err(|_| RotationError::Codec),
    )
}
