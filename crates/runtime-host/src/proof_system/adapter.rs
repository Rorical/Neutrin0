//! The [`ProofSystem`] trait implementation the consensus engine drives.

use std::sync::Arc;

use neutrin0_consensus_types::BlockProofPublicInputs;
use neutrin0_consensus_types::history_proof::{GuestPrograms, VkDigest};
use neutrin0_proof_system::artifacts::{ArtifactIdentity, ProgramArtifactLoader, ProgramRetention};
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_runtime_abi::BlockReceiptStatement;
use sp1_sdk::{HashableKey, blocking::ProverClient};

use super::{Sp1BlockProof, Sp1ChunkProof, Sp1ProofSystem};
use crate::executor::decode_witness_bundle;
use crate::{ProgramProver, guarded, prove_compressed};

impl<P> ProofSystem for Sp1ProofSystem<P>
where
    P: ProgramProver,
{
    fn lease_programs(
        &self,
        guests: &GuestPrograms,
    ) -> Result<neutrin0_proof_system::artifacts::ProgramLease, ProofError> {
        if guests.execution.fact != self.embedded.execution.fact {
            return Err(ProofError::PublicInputMismatch);
        }
        let leases: Result<Vec<_>, _> = [
            guests.execution.fact,
            guests.execution.evidence,
            guests.execution.block,
            guests.chunk,
        ]
        .iter()
        .map(|digest| {
            if let Ok(keys) = self.keys(digest) {
                return Ok(keys);
            }
            // This hook runs before node/device admission. Never add cold
            // setup to keys(): recursive callers may already own the GPU
            // gate and must not wait on a setup flight waiting for that gate.
            let bytes = self.guest_artifact(digest).ok_or(ProofError::Unsupported)?;
            self.install_guest_checked(bytes, *digest)
                .map_err(|_| ProofError::BackendRejected)?;
            self.keys(digest)
        })
        .collect();
        Ok(Arc::new(leases?))
    }

    fn set_artifact_loader(&self, loader: ProgramArtifactLoader) {
        *self
            .artifact_loader
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(loader);
    }

    fn retain_programs(&self, retention: &ProgramRetention) {
        *self
            .retained_sources
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            retention.sources.iter().copied().collect();
        let mut warm: std::collections::BTreeSet<_> = retention
            .warm
            .iter()
            .filter_map(|identity| match identity {
                ArtifactIdentity::Guest(digest) => Some(*digest),
                ArtifactIdentity::Runtime(_) => None,
            })
            .collect();
        // Public embedded-key accessors and immutable recursive programs retain
        // their keys independently of governed historical runtime upgrades.
        warm.extend([
            self.embedded.execution.fact,
            self.embedded.execution.evidence,
            self.embedded.execution.block,
            self.embedded.chunk,
        ]);
        self.programs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(warm);
    }

    fn authenticate_guest(
        &self,
        elf: Vec<u8>,
        expected: &[VkDigest],
    ) -> Result<VkDigest, ProofError> {
        if expected.is_empty()
            || elf.is_empty()
            || elf.len() > neutrin0_consensus_types::MAX_PROGRAM_BYTES as usize
        {
            return Err(ProofError::InvalidWitness);
        }
        // ROM/VK preprocessing remains local CPU work on a CUDA node and
        // creates no GPU session for archived safety-evidence sources.
        let keys = guarded(|| {
            crate::cached_proving_key(
                &ProverClient::builder().light().build(),
                sp1_sdk::Elf::from(elf),
            )
        })?
        .map_err(|_| ProofError::BackendRejected)?;
        let digest = sp1_sdk::ProvingKey::verifying_key(&keys).hash_u32();
        if !expected.contains(&digest) {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(digest)
    }

    fn native_submission_admission(&self) -> bool {
        self.prover.native_submission_admission()
    }

    fn serial_submission(&self) -> bool {
        self.prover.serial_submission()
    }

    fn submission_device(&self) -> Option<u32> {
        self.prover.submission_device()
    }

    type BlockProof = Sp1BlockProof;
    type ChunkProof = Sp1ChunkProof;

    fn history_domain(
        &self,
        spec: &neutrin0_primitives::ChainSpec,
    ) -> Result<neutrin0_consensus_types::history_proof::ProofDomain, ProofError> {
        self.trusted_history_domain(spec)
    }

    fn verify_history(
        &self,
        proof: &neutrin0_consensus_types::history_proof::HistoryProof,
        chunk: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<(), ProofError> {
        self.verify_history_receipt(proof, chunk)
    }

    fn programs(&self) -> Option<GuestPrograms> {
        Some(self.embedded)
    }

    fn can_prove(&self, guests: &GuestPrograms) -> bool {
        self.holds(guests)
    }

    fn install_guest_checked(
        &self,
        elf: Vec<u8>,
        expected: VkDigest,
    ) -> Result<VkDigest, ProofError> {
        Self::install_guest_checked(self, elf, expected).map_err(|_| ProofError::BackendRejected)
    }

    fn guest_artifact(&self, digest: &VkDigest) -> Option<Vec<u8>> {
        Self::guest_artifact(self, digest)
    }

    fn guest_fragment(
        &self,
        digest: &VkDigest,
        offset: u64,
        max_bytes: usize,
    ) -> Option<(u64, Vec<u8>)> {
        Self::guest_fragment(self, digest, offset, max_bytes)
    }

    fn installed_guests(&self) -> Vec<(VkDigest, neutrin0_primitives::Hash)> {
        Self::installed_guests(self)
    }
    fn last_chunk_fact_coverage(&self) -> Option<(u64, u64)> {
        Self::last_chunk_fact_coverage(self)
    }

    fn preprove_facts(
        &self,
        fact_program: &VkDigest,
        requests: &[neutrin0_prover_chunk::facts::FactRequest],
    ) -> Result<(), ProofError> {
        self.compress_facts(fact_program, requests).map(|_| ())
    }

    fn prove_evidence_batch(
        &self,
        witnesses: &[neutrin0_prover_chunk::evidence::EvidenceWitness],
        execution: &neutrin0_consensus_types::history_proof::ExecutionPrograms,
    ) -> Result<Vec<neutrin0_consensus_types::evidence::EvidenceArtifact>, ProofError> {
        self.prove_batch(witnesses, execution)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        expected: &neutrin0_consensus_types::evidence::EvidenceBatch,
        evidence_program: &VkDigest,
    ) -> Result<(), ProofError> {
        // Digest verification needs no installed key, so evidence under any
        // program set the caller trusts can be checked.
        if expected.count == 0
            || expected.count as usize > neutrin0_consensus_types::evidence::MAX_EVIDENCE_BATCH
        {
            return Err(ProofError::PublicInputMismatch);
        }
        guarded(|| {
            neutrin0_prover_chunk::proof_verification::verify_evidence_receipt(
                bytes,
                expected,
                evidence_program,
            )
        })?
        .map_err(|_| ProofError::BackendRejected)
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<BlockReceiptStatement, ProofError> {
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        borsh::from_slice(bundle.public_values.as_slice()).map_err(|_| ProofError::MalformedProof)
    }

    fn prove_consensus_chunk(
        &self,
        proofs: &[Self::BlockProof],
        ratified: &[Self::ChunkProof],
        witness: &neutrin0_prover_chunk::consensus::ConsensusWitness,
        chunk_prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::ChunkProof, ProofError> {
        Self::prove_consensus_chunk(self, proofs, ratified, witness, chunk_prover_address)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        statement: &neutrin0_consensus_types::history_proof::ChunkReceiptStatement,
    ) -> Result<(), ProofError> {
        Self::verify_consensus_chunk(self, proof, statement)
    }

    fn chunk_prover_address(
        &self,
        proof: &Self::ChunkProof,
    ) -> Result<neutrin0_primitives::Hash, ProofError> {
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        borsh::from_slice::<neutrin0_consensus_types::history_proof::ChunkReceiptStatement>(
            bundle.public_values.as_slice(),
        )
        .map(|statement| statement.chunk_prover_address)
        .map_err(|_| ProofError::MalformedProof)
    }

    fn classify_block_rejection(
        &self,
        proof: &neutrin0_consensus_types::BlockProof,
        expected_block_program: &VkDigest,
    ) -> Result<Option<neutrin0_consensus_types::ProofRejectionReason>, ProofError> {
        // The verifier's key is the program the block's boundary names, never
        // the one the artifact declares: a signer naming another program has
        // signed mismatched public inputs.
        if proof.public_inputs.block_program != *expected_block_program {
            return Ok(Some(
                neutrin0_consensus_types::ProofRejectionReason::PublicInputsMismatch,
            ));
        }
        let digest = *expected_block_program;
        // Malformed adversarial internals may cause an upstream verifier to
        // abort instead of returning a verdict. Such failures are not slashable.
        guarded(|| {
            neutrin0_prover_chunk::proof_verification::verify_block_artifact(proof, &digest).err()
        })
    }

    fn prove_block(
        &self,
        witness: &[u8],
        public_inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        // 1. Decode the witness bundle the executor wrote during
        //    block production. The wire format is owned by
        //    `runtime_host::executor`; any decode failure means the
        //    stored bytes are not the canonical
        //    complete `BlockWitness` shape and the
        //    proof system cannot proceed.
        let crate::BlockWitness {
            input,
            state: witness,
            evidence_proofs,
        } = decode_witness_bundle(witness).map_err(|_| ProofError::InvalidWitness)?;

        // 2. Bind the witness's pre-state-root to the consensus
        //    engine's `state_root_before`. The cryptographic check
        //    happens inside the guest (`WitnessState::new` rebuilds
        //    the partial trie and rejects a mismatch), but failing
        //    fast here avoids a wasted proof.
        let block = self.keys(&public_inputs.block_program)?;
        Self::check_block_input(&input, &witness, public_inputs)?;

        // 3. Keep proof witnesses out of normal stdin and supply verified
        //    attachments through the native recursive proof stream.
        //    Attachments verify only under the anchor's installed
        //    evidence program; without it the block cannot be proven.
        let stdin = self.block_proving_stdin(&input, &witness, &evidence_proofs, prover_address)?;

        // 4. Drive the configured prover (mock / cpu / cuda / network)
        //    to produce a Compressed STARK bound to the embedded
        //    guest ELF's verifying key.
        let proof = prove_compressed(&self.prover, &block.pk, stdin)
            .map_err(|_| ProofError::BackendRejected)?;

        // 5. Cross-check the committed RuntimeBlockOutput against the
        //    consensus public inputs before handing the proof back.
        //    `verify_block` re-checks this too, but doing it here as
        //    well surfaces a divergence as a proving failure rather
        //    than a downstream verification failure. Mirrors the
        //    full verifier-side cross-check set so an off-tree
        //    prover that skips the lines above (the
        //    input-vs-public-inputs ones) still produces a proof
        //    that the verifier accepts or rejects on consistent
        //    grounds.
        Self::check_committed_block(&proof, prover_address, public_inputs)?;

        Sp1BlockProof::from_sp1(&proof).map_err(|_| ProofError::MalformedProof)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.verify_block_statement(proof, public_inputs)
            .map(|_| ())
    }

    fn verify_block_statement(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<BlockReceiptStatement, ProofError> {
        self.verified_block(proof, public_inputs)
            .map(|verified| verified.statement)
    }
}
