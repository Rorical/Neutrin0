//! Explicit test-only full-consensus adapter over mock SP1 block execution.
//!
//! No cryptographic chunk proof is claimed: the outer statement is checked
//! natively. Real recursive verification has its own runtime-host CUDA gate.
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::consensus::{ConsensusWitness, validate_consensus};
use neutrin0_runtime_host::{Sp1HostError, Sp1ProofSystem};
use sp1_sdk::blocking::MockProver;

type Inner = Sp1ProofSystem<MockProver>;

/// Native consensus checker retaining SP1 mock block execution and bindings.
pub struct NativeChunkTestSystem(Inner);

impl NativeChunkTestSystem {
    /// Construct the mock block program and native outer statement checker.
    pub fn mock() -> Result<Self, Sp1HostError> {
        let system = Inner::mock()?;
        assert_eq!(
            system.execution_programs(),
            Self::execution_programs(),
            "adapter embeds the fixture package"
        );
        Ok(Self(system))
    }

    /// Execution programs this adapter reports, for chain specifications that
    /// must name exactly them: the embedded fact, evidence and block Guests,
    /// which block receipts are verified against.
    ///
    /// Deriving them re-hashes every embedded artifact, so it happens once:
    /// nodes query their programs on every vote and status.
    pub fn execution_programs() -> neutrin0_consensus_types::history_proof::ExecutionPrograms {
        static PROGRAMS: std::sync::OnceLock<
            neutrin0_consensus_types::history_proof::ExecutionPrograms,
        > = std::sync::OnceLock::new();
        *PROGRAMS.get_or_init(|| {
            neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
                .expect("authenticated fixture programs")
                .programs
                .execution
        })
    }
}

impl ProofSystem for NativeChunkTestSystem {
    type BlockProof = <Inner as ProofSystem>::BlockProof;
    type ChunkProof = neutrin0_consensus_types::history_proof::ChunkReceiptStatement;

    fn prove_block(
        &self,
        bytes: &[u8],
        pi: &neutrin0_consensus_types::BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        self.0.prove_block(bytes, pi, prover_address)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        pi: &neutrin0_consensus_types::BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.0.verify_block(proof, pi)
    }

    // Embedded execution programs with a placeholder chunk identity: this
    // adapter never sets up the recursive chunk Guest.
    fn programs(&self) -> Option<neutrin0_consensus_types::history_proof::GuestPrograms> {
        Some(neutrin0_consensus_types::history_proof::GuestPrograms {
            execution: self.0.execution_programs(),
            chunk: [7; 8],
        })
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ProofError> {
        self.0.block_statement(proof)
    }

    fn prove_consensus_chunk(
        &self,
        proofs: &[Self::BlockProof],
        ratified: &[Self::ChunkProof],
        witness: &ConsensusWitness,
        chunk_prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::ChunkProof, ProofError> {
        // The Guest verifies the ratified chunk proof recursively (design 08).
        if ratified.len() != witness.ratified.len()
            || ratified
                .iter()
                .zip(&witness.ratified)
                .any(|(proof, statement)| self.verify_consensus_chunk(proof, statement).is_err())
        {
            return Err(ProofError::PublicInputMismatch);
        }
        if proofs.len() != witness.blocks.len()
            || self.programs().map(|guests| guests.execution)
                != Some(witness.context.programs.execution)
            || self.programs().map(|guests| guests.chunk) != Some(witness.chain_spec.genesis_chunk)
        {
            return Err(ProofError::PublicInputMismatch);
        }
        for (proof, block) in proofs.iter().zip(&witness.blocks) {
            self.verify_block(proof, &block.public_inputs)?;
            if self.block_statement(proof)? != block.statement() {
                return Err(ProofError::PublicInputMismatch);
            }
        }
        validate_consensus(witness)
            .map(
                |statement| neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                    statement,
                    chunk_prover_address,
                },
            )
            .map_err(|_| ProofError::InvalidWitness)
    }

    fn chunk_prover_address(
        &self,
        proof: &Self::ChunkProof,
    ) -> Result<neutrin0_primitives::Hash, ProofError> {
        Ok(proof.chunk_prover_address)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &neutrin0_consensus_types::history_proof::ChunkReceiptStatement,
    ) -> Result<(), ProofError> {
        if proof != expected
            || self.programs().map(|programs| programs.execution.block)
                != Some(expected.statement.start.programs.execution.block)
        {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }
}
