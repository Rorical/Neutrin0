//! Complete consensus chunk proofs: fact receipt selection, recursive
//! verification of block, fact and ratified chunk receipts, and verification
//! of a chunk receipt against a caller-authenticated statement.

use std::sync::Arc;

use neutrin0_consensus_types::history_proof::{ChunkReceiptStatement, GuestPrograms};
use neutrin0_proof_system::ProofError;
use neutrin0_prover_chunk::consensus::ConsensusWitness;
use neutrin0_prover_chunk::execution::ProvenBlock;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

use super::{
    Sp1BlockProof, Sp1ChunkProof, Sp1ProofSystem, attached_fact_coverage,
    publish_successful_coverage,
};
use crate::fact_cache::FactReceipt;
use crate::programs::ProgramKeys;
use crate::{ProgramProver, guarded, prove_compressed, push_receipt};

/// Host-selected witness, exact attached receipts, unique-request coverage
/// and the statement the chunk Guest must commit for that witness.
struct AttachedFacts {
    witness: ConsensusWitness,
    receipts: Vec<Arc<FactReceipt>>,
    coverage: (u64, u64),
    statement: neutrin0_consensus_types::history_proof::ConsensusStatement,
}

impl<P> Sp1ProofSystem<P>
where
    P: ProgramProver,
{
    /// `(covered, total)` unique requests of the latest successful chunk proof,
    /// where `covered` were answered by early fact receipts instead of
    /// in-circuit BLS. `None` before the first chunk proof.
    #[must_use]
    pub fn last_chunk_fact_coverage(&self) -> Option<(u64, u64)> {
        *self.last_fact_coverage.lock().expect("fact coverage mutex")
    }

    /// Select cached fact receipts covering this chunk's signature checks.
    ///
    /// Runs the consensus checks once with a recording verifier (verifying
    /// natively as it goes), asks the fact cache for receipts covering the
    /// recorded requests, and returns the witness with those statements
    /// attached in receipt order. Missing facts are never proven here: the
    /// guest falls back to in-circuit verification for them, so chunk
    /// proving never waits on the fact worker.
    ///
    /// The returned statement is the one this single consensus pass
    /// derived. The chunk Guest derives the same statement from any subset
    /// of attached facts, provided the attached statements are well formed,
    /// never conflict and never contradict a recorded verdict; all three are
    /// checked here.
    fn attach_fact_receipts(
        &self,
        witness: &ConsensusWitness,
    ) -> Result<AttachedFacts, ProofError> {
        let fact_program = witness.context.programs.execution.fact;
        let known = self.with_fact_cache(&fact_program, |cache| cache.verified())?;
        let mut recorder = neutrin0_prover_chunk::facts::FactRecorder::with_verifier(
            known,
            crate::native_bls::NativeBlstVerifier,
        );
        let validated =
            neutrin0_prover_chunk::consensus::validate_consensus_using(witness, &mut recorder)
                .map_err(|_| ProofError::InvalidWitness)?;
        let requests = recorder.finish().map_err(|_| ProofError::InvalidWitness)?;
        if requests.iter().any(|(_, valid)| !valid) {
            return Err(ProofError::InvalidWitness);
        }
        let mut wanted: std::collections::BTreeSet<_> =
            requests.iter().map(|(request, _)| request.id()).collect();
        let requested = wanted.clone();
        let receipts = self.with_fact_cache(&fact_program, |cache| {
            cache.covering_limited(
                &mut wanted,
                neutrin0_prover_chunk::consensus::MAX_CONSENSUS_FACT_STATEMENTS,
            )
        })?;
        let mut attached = witness.clone();
        attached.facts = receipts
            .iter()
            .map(|receipt| receipt.statement.clone())
            .collect();
        // The Guest's hybrid verifier rejects malformed or conflicting
        // statements, and every recorded verdict was positive.
        neutrin0_prover_chunk::facts::HybridVerifier::new(&attached.facts)
            .map_err(|_| ProofError::InvalidWitness)?;
        if attached
            .facts
            .iter()
            .flat_map(|statement| &statement.facts)
            .any(|fact| !fact.valid && requested.contains(&fact.id))
        {
            return Err(ProofError::InvalidWitness);
        }
        let coverage = attached_fact_coverage(&requested, &attached.facts);
        Ok(AttachedFacts {
            witness: attached,
            receipts,
            coverage,
            statement: validated.statement,
        })
    }

    /// Prove the stronger consensus chunk statement with explicit witnesses.
    ///
    /// The node supplies authenticated history and runtime witnesses and both
    /// finality certificates before proving. Recursive verification stays
    /// enabled; rejected or malformed inner proofs fail closed.
    pub fn prove_consensus_chunk(
        &self,
        block_proofs: &[Sp1BlockProof],
        ratified: &[Sp1ChunkProof],
        witness: &ConsensusWitness,
        chunk_prover_address: neutrin0_primitives::Hash,
    ) -> Result<Sp1ChunkProof, ProofError> {
        let programs = witness.context.programs;
        self.check_chunk_programs(block_proofs, ratified, witness)?;
        let block_keys = self.keys(&programs.execution.block)?;
        let fact_keys = self.keys(&programs.execution.fact)?;
        let chunk_keys = self.keys(&self.embedded.chunk)?;
        if !witness.facts.is_empty() {
            // The host owns receipt selection; callers hand over bare witnesses.
            return Err(ProofError::InvalidWitness);
        }
        // Learn which signature checks this chunk performs, then cover as many
        // as possible with receipts the early fact worker already produced.
        // Anything uncovered is verified in-circuit by the hybrid verifier.
        let AttachedFacts {
            witness,
            receipts: fact_receipts,
            coverage,
            statement: expected,
        } = self.attach_fact_receipts(witness)?;
        let expected = ChunkReceiptStatement {
            statement: expected,
            chunk_prover_address,
        };
        let encoded = borsh::to_vec(&witness).map_err(|_| ProofError::InvalidWitness)?;
        // The Guest refuses a larger input; voters checked it before voting.
        if encoded.len() > neutrin0_prover_chunk::consensus::MAX_CHUNK_WITNESS_BYTES {
            return Err(ProofError::InvalidWitness);
        }
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(encoded);
        stdin.write_vec(chunk_prover_address.to_vec());
        self.queue_block_receipts(&mut stdin, block_proofs, &witness.blocks, &block_keys.vk)?;
        for receipt in &fact_receipts {
            push_receipt(&mut stdin, &receipt.bundle, &fact_keys.vk)?;
        }
        self.queue_ratified_receipts(&mut stdin, ratified, &witness.ratified, &chunk_keys.vk)?;
        let proof = self.prove_chunk_statement(stdin, &chunk_keys, &expected)?;
        let result = Sp1ChunkProof::from_sp1(&proof).map_err(|_| ProofError::MalformedProof);
        publish_successful_coverage(&self.last_fact_coverage, coverage, &result);
        result
    }

    /// The consensus Guests are pinned by the chain specification: this
    /// backend proves only under the pair it embeds, which the witness's
    /// specification must pin, and must hold every program the chunk names.
    fn check_chunk_programs(
        &self,
        block_proofs: &[Sp1BlockProof],
        ratified: &[Sp1ChunkProof],
        witness: &ConsensusWitness,
    ) -> Result<(), ProofError> {
        let programs = witness.context.programs;
        if programs.execution.fact != self.embedded.execution.fact
            || witness.chain_spec.genesis_execution.fact != self.embedded.execution.fact
            || witness.chain_spec.genesis_chunk != self.embedded.chunk
            || block_proofs.len() != witness.blocks.len()
            || ratified.len() != witness.ratified.len()
        {
            return Err(ProofError::PublicInputMismatch);
        }
        let guests = GuestPrograms {
            execution: programs.execution,
            chunk: self.embedded.chunk,
        };
        if !self.holds(&guests) {
            return Err(ProofError::Unsupported);
        }
        Ok(())
    }

    /// Verify each block receipt against its witnessed block and queue it for
    /// recursive verification under the block program.
    fn queue_block_receipts(
        &self,
        stdin: &mut SP1Stdin,
        block_proofs: &[Sp1BlockProof],
        blocks: &[ProvenBlock],
        block_vk: &SP1VerifyingKey,
    ) -> Result<(), ProofError> {
        for (proof, block) in block_proofs.iter().zip(blocks) {
            let verified = self.verified_block(proof, &block.public_inputs)?;
            if verified.statement.output != block.output
                || verified.statement.prover_address != block.prover_address
            {
                return Err(ProofError::PublicInputMismatch);
            }
            push_receipt(stdin, &verified.bundle, block_vk)?;
        }
        Ok(())
    }

    /// Design 08: the ratified chunk proof is verified recursively under
    /// the pinned chunk program, after the facts, as the Guest reads it.
    fn queue_ratified_receipts(
        &self,
        stdin: &mut SP1Stdin,
        ratified: &[Sp1ChunkProof],
        statements: &[ChunkReceiptStatement],
        chunk_vk: &SP1VerifyingKey,
    ) -> Result<(), ProofError> {
        for (proof, statement) in ratified.iter().zip(statements) {
            self.verify_consensus_chunk(proof, statement)?;
            let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
            push_receipt(stdin, &bundle, chunk_vk)?;
        }
        Ok(())
    }

    /// Prove the chunk under the embedded chunk program and accept the
    /// receipt only when it commits exactly `expected` and verifies.
    fn prove_chunk_statement(
        &self,
        stdin: SP1Stdin,
        chunk_keys: &ProgramKeys<P>,
        expected: &ChunkReceiptStatement,
    ) -> Result<SP1ProofWithPublicValues, ProofError> {
        let proof = prove_compressed(&self.prover, &chunk_keys.pk, stdin)
            .map_err(|_| ProofError::BackendRejected)?;
        let committed: ChunkReceiptStatement = borsh::from_slice(proof.public_values.as_slice())
            .map_err(|_| ProofError::MalformedProof)?;
        if committed != *expected {
            return Err(ProofError::PublicInputMismatch);
        }
        self.prover
            .verify(&proof, &chunk_keys.vk, None)
            .map_err(|_| ProofError::BackendRejected)?;
        Ok(proof)
    }

    /// Verify a consensus chunk proof against a caller-authenticated statement.
    ///
    /// The caller must derive the expected context and incoming seed from its
    /// trusted chain specification and previous finalized checkpoint. A peer's
    /// own declared statement is not a trust anchor. The verdict is cached, so
    /// a node that verified the bytes off its engine lock only looks it up
    /// under the lock.
    pub fn verify_consensus_chunk(
        &self,
        proof: &Sp1ChunkProof,
        expected: &ChunkReceiptStatement,
    ) -> Result<(), ProofError> {
        let bytes = neutrin0_primitives::blake3_256(&proof.bytes);
        let identity = (bytes, expected.statement_key());
        if self
            .chunk_verdicts
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .get(&identity)
            .is_some()
        {
            return Ok(());
        }
        let rejected = self
            .chunk_rejections
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .get(&bytes)
            .copied();
        if let Some(rejected) = rejected {
            return Err(rejected);
        }
        match self.verify_chunk_receipt(proof, expected) {
            Ok(()) => {
                self.chunk_verdicts
                    .lock()
                    .map_err(|_| ProofError::BackendRejected)?
                    .insert(identity, 1, ());
                Ok(())
            }
            // Malformed bytes and a failed STARK are properties of the bytes;
            // a public-value mismatch depends on the expected statement.
            Err(error @ (ProofError::MalformedProof | ProofError::BackendRejected)) => {
                self.chunk_rejections
                    .lock()
                    .map_err(|_| ProofError::BackendRejected)?
                    .insert(bytes, 1, error);
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    fn verify_chunk_receipt(
        &self,
        proof: &Sp1ChunkProof,
        expected: &ChunkReceiptStatement,
    ) -> Result<(), ProofError> {
        guarded(|| {
            let statement = &expected.statement;
            let fact = self.embedded.execution.fact;
            if [statement.start.programs, statement.end.programs]
                .iter()
                .any(|programs| !programs.is_complete() || programs.execution.fact != fact)
            {
                return Err(ProofError::PublicInputMismatch);
            }
            let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
            let committed: ChunkReceiptStatement =
                borsh::from_slice(bundle.public_values.as_slice())
                    .map_err(|_| ProofError::MalformedProof)?;
            if committed != *expected || !matches!(bundle.proof, SP1Proof::Compressed(_)) {
                return Err(ProofError::PublicInputMismatch);
            }
            // The receipt is verified under the chunk Guest this backend
            // embeds, which nodes accept only when it is their specification's
            // pin, never one the peer's statement selects. An installed program
            // verifies with the full key; any other identity is checked by
            // digest, which never accepts mock receipts.
            let chunk_program = self.embedded.chunk;
            if let Ok(chunk) = self.keys(&chunk_program) {
                return self
                    .prover
                    .verify(&bundle, &chunk.vk, None)
                    .map_err(|_| ProofError::BackendRejected);
            }
            neutrin0_prover_chunk::proof_verification::verify_typed_receipt(
                &bundle.proof,
                bundle.public_values.as_slice(),
                &bundle.sp1_version,
                expected,
                &chunk_program,
            )
            .map_err(|_| ProofError::BackendRejected)
        })?
    }
}
