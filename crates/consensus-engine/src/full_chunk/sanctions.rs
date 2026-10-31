//! Identity sanctions and rotation witnesses of a chunk's post-state.

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofError;
use neutrin0_prover_chunk::{
    consensus::ConsensusWitness,
    execution::{ExecutionContext, ProvenBlock},
};
use neutrin0_runtime_abi::{StateWitness, TrieNodeBytes, TrieValueBytes};
use neutrin0_storage::Database;

use crate::{Engine, FinalizeError};

fn sanctions_candidates(
    post_state: &StateWitness,
) -> Result<neutrin0_consensus_types::runtime::ConsensusCandidates, ProofError> {
    use neutrin0_runtime_core::StateBackend;
    let mut state = neutrin0_runtime_core::WitnessState::new(post_state)
        .map_err(|_| ProofError::InvalidWitness)?;
    if !post_state
        .witnessed_keys
        .iter()
        .any(|key| key == neutrin0_consensus_types::runtime::CONSENSUS_CANDIDATES_KEY)
    {
        return Err(ProofError::InvalidWitness);
    }
    let candidates: neutrin0_consensus_types::runtime::ConsensusCandidates = state
        .read(neutrin0_consensus_types::runtime::CONSENSUS_CANDIDATES_KEY)
        .map(|bytes| borsh::from_slice(&bytes))
        .transpose()
        .map_err(|_| ProofError::InvalidWitness)?
        .unwrap_or_default();
    if candidates.entries.len() > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS {
        return Err(ProofError::InvalidWitness);
    }
    Ok(candidates)
}

fn sanction_offenders(blocks: &[ProvenBlock]) -> Vec<neutrin0_primitives::Validator> {
    blocks
        .iter()
        .flat_map(|block| &block.output.accountability.admitted)
        .filter(|sanction| sanction.kind == neutrin0_consensus_types::evidence::SanctionKind::Slash)
        .map(|sanction| sanction.offender.clone())
        .collect()
}

pub(super) fn sanctions_witness<E>(
    trie: &neutrin0_trie::Trie,
    context: &ExecutionContext,
    post_state: &StateWitness,
    blocks: &[ProvenBlock],
) -> Result<StateWitness, FinalizeError<E>> {
    let candidates = sanctions_candidates(post_state)?;
    let offenders = sanction_offenders(blocks);
    let keys = neutrin0_prover_chunk::identity_sanctions::witness_keys(
        &context.active_validators,
        &candidates,
        &offenders,
    );
    // A missing node on any witnessed path fails the witness below.
    neutrin0_runtime_core::host::witness_of(trie, keys)
        .map_err(|_| crate::StoreError::Corrupt("retained state trie is incomplete").into())
}

impl<DB: Database> Engine<DB> {
    pub(super) fn identity_sanctions_transition(
        &self,
        witness: &ConsensusWitness,
        expected: Hash,
    ) -> Result<neutrin0_trie::Trie, FinalizeError<DB::Error>> {
        if self.identity_sanctions.root() != witness.context.identity_sanctions_root {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let live =
            neutrin0_runtime_core::host::LiveTrie::from_trie(self.identity_sanctions.clone());
        let mut state = neutrin0_runtime_core::host::TracingState::new(&live);
        let candidates = sanctions_candidates(&witness.post_state)?;
        let offenders = sanction_offenders(&witness.blocks);
        neutrin0_prover_chunk::identity_sanctions::apply(
            &mut state,
            &witness.context.active_validators,
            &candidates,
            &offenders,
        )
        .map_err(|_| ProofError::InvalidWitness)?;
        let (trie, _) = state
            .into_committed_and_witness()
            .map_err(|_| crate::StoreError::Corrupt("retained state trie is incomplete"))?;
        if trie.root() != expected {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(trie)
    }

    pub(super) fn consensus_rotation_witness(
        &self,
        root: Hash,
    ) -> Result<StateWitness, FinalizeError<DB::Error>> {
        let trie = self.persisted_trie(root)?;
        let keys = neutrin0_prover_chunk::rotation::witness_keys();
        let mut nodes = BTreeMap::new();
        let mut values = BTreeMap::new();
        for key in &keys {
            trie.collect_path_nodes(key, &mut nodes, &mut values)
                .map_err(|_| crate::StoreError::Corrupt("retained state trie is incomplete"))?;
        }
        Ok(StateWitness {
            pre_state_root: root,
            nodes: nodes
                .into_iter()
                .map(|(hash, bytes)| TrieNodeBytes { hash, bytes })
                .collect(),
            values: values
                .into_iter()
                .map(|(hash, bytes)| TrieValueBytes { hash, bytes })
                .collect(),
            witnessed_keys: keys,
        })
    }
}
