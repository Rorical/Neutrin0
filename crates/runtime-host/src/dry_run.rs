//! Native dry-run of the STF against a live trie, recording the witness the
//! SP1 Guest replays.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible helpers of a private module; `pub` would be unreachable."
)]

use neutrin0_consensus_types::evidence::EvidenceArtifact;
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_abi::RuntimeBlockOutput;
use neutrin0_runtime_abi::StateWitness;
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_trie::{Poseidon2Hasher, Trie};

use crate::{Sp1HostError, evidence};

/// Result of a native dry-run.
pub struct DryRun {
    /// Opaque execution artifacts bound by the returned receipt commitment.
    pub artifacts: neutrin0_runtime_abi::ExecutionArtifacts,
    /// Public output the SP1 Guest would commit for this input.
    pub output: RuntimeBlockOutput,
    /// Witness captured during dry-run; pass this to [`prove`](crate::prove).
    pub witness: StateWitness,
    /// Post-execution state trie with every overlay write applied.
    ///
    /// The block producer swaps this back into the engine's
    /// authoritative state trie after a successful dry-run so the
    /// in-memory head advances in lock-step with the witnessed
    /// transition. Read-only blocks return a clone of the live
    /// snapshot so the swap is unconditional.
    pub post_state: Trie<Poseidon2Hasher>,
    /// Final value of every key the block wrote, in strictly increasing
    /// key order (`None` marks a delete). Applied to the pre-state trie
    /// they reproduce `post_state`'s root; proof-following nodes consume
    /// them in place of execution.
    pub writes: Vec<neutrin0_consensus_types::StateWrite>,
}

/// Convert an ordered final-value map into canonical [`StateWrite`]s.
///
/// [`StateWrite`]: neutrin0_consensus_types::StateWrite
pub(super) fn state_writes<I>(writes: I) -> Vec<neutrin0_consensus_types::StateWrite>
where
    I: IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
{
    writes
        .into_iter()
        .map(|(key, value)| neutrin0_consensus_types::StateWrite { key, value })
        .collect()
}

/// Execute the STF natively against `live` and record the witness the
/// SP1 Guest needs to replay the same transition. Pure dry-run — no
/// writes are committed to `live`.
///
/// # Errors
/// Returns [`Sp1HostError::Codec`] when an evidence attachment does not
/// authenticate or `live` does not hold every node on an accessed path.
pub fn dry_run(
    input: &RuntimeBlockInput,
    live: &LiveTrie,
    evidence_proofs: &[EvidenceArtifact],
) -> Result<DryRun, Sp1HostError> {
    evidence::verify_input_receipts(input, evidence_proofs)?;
    let mut tracer = TracingState::new(live);
    let result = neutrin0_evm_runtime_core::execute_block(input, &mut tracer);
    let (post_state, witness, writes) = tracer
        .into_committed_witness_and_writes()
        .map_err(|error| Sp1HostError::Codec(format!("state unavailable: {error}")))?;
    Ok(DryRun {
        output: result.output,
        artifacts: result.artifacts,
        witness,
        post_state,
        writes: state_writes(writes),
    })
}

#[cfg(test)]
mod tests;
