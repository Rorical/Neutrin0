//! Deterministic block-proof backend for isolated consensus tests.
//!
//! A mock block proof commits to its public inputs. It ignores the execution
//! witness and never authorizes complete chunk finalization or checkpoints.
//! Integration tests use native consensus validation with SP1 execution.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{Hash, blake3_256};

use crate::error::ProofError;

use crate::system::ProofSystem;
use neutrin0_consensus_types::BlockProofPublicInputs;

/// Domain tag prepended to block-proof commitments.
pub const MOCK_BLOCK_DOMAIN: [u8; 16] = *b"NEUTRIN0_MK_BLK_";

/// Mock block proof. The hash binds the borsh-encoded public inputs
/// under [`MOCK_BLOCK_DOMAIN`].
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MockBlockProof {
    /// `BLAKE3(MOCK_BLOCK_DOMAIN || borsh(BlockProofPublicInputs))`.
    pub commitment: Hash,
    /// Attribution the receipt carries (design 08); any value verifies.
    pub prover_address: Hash,
}

/// Zero-sized placeholder proof backend.
///
/// Implements [`ProofSystem`] by deterministically hashing the public
/// inputs under per-layer domain tags. Production code never depends
/// on this type directly; the consensus engine takes a `ProofSystem`
/// generic and the binary chooses the concrete backend at build time.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct MockProofSystem;

impl MockProofSystem {
    /// Constructs the stateless mock backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofSystem for MockProofSystem {
    type BlockProof = MockBlockProof;
    type ChunkProof = alloc::vec::Vec<u8>;

    fn classify_block_rejection(
        &self,
        proof: &neutrin0_consensus_types::BlockProof,
        _expected_block_program: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<Option<neutrin0_consensus_types::ProofRejectionReason>, ProofError> {
        use neutrin0_consensus_types::ProofRejectionReason;
        let Ok(decoded) = borsh::from_slice::<MockBlockProof>(&proof.proof_bytes) else {
            return Ok(Some(ProofRejectionReason::MalformedProof));
        };
        if proof.height != proof.public_inputs.height
            || proof.block_hash != proof.public_inputs.block_hash
            || self.verify_block(&decoded, &proof.public_inputs).is_err()
        {
            Ok(Some(ProofRejectionReason::PublicInputsMismatch))
        } else {
            Ok(None)
        }
    }

    fn prove_block(
        &self,
        _witness: &[u8],
        public_inputs: &BlockProofPublicInputs,
        prover_address: Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        Ok(MockBlockProof {
            commitment: domain_hash(&MOCK_BLOCK_DOMAIN, public_inputs),
            prover_address,
        })
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        let expected = domain_hash(&MOCK_BLOCK_DOMAIN, public_inputs);
        if proof.commitment == expected {
            Ok(())
        } else {
            Err(ProofError::PublicInputMismatch)
        }
    }

    // A mock proof carries no runtime statement: only its attribution is
    // meaningful, and tests that need an execution statement use a native
    // backend.
    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ProofError> {
        Ok(neutrin0_runtime_abi::BlockReceiptStatement {
            output: neutrin0_runtime_abi::RuntimeBlockOutput::default(),
            prover_address: proof.prover_address,
        })
    }
}

/// Computes `BLAKE3(domain || borsh(value))`.
///
/// The borsh serialization is infallible for every public-input type
/// in this crate, so panicking on serialization failure cannot trigger
/// in correct programs.
fn domain_hash<T>(domain: &[u8; 16], value: &T) -> Hash
where
    T: BorshSerialize,
{
    let payload = borsh::to_vec(value)
        .expect("public-input borsh serialization is infallible for canonical types");
    let mut input = alloc::vec::Vec::with_capacity(domain.len() + payload.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&payload);
    blake3_256(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block_inputs() -> BlockProofPublicInputs {
        BlockProofPublicInputs {
            context: Box::default(),
            chain_id: 7,
            height: 42,
            parent_block_hash: [1; 32],
            block_hash: [2; 32],
            state_root_before: [3; 32],
            state_root_after: [4; 32],
            transactions_root: [5; 32],
            receipt_root: [6; 32],
            da_root: [7; 32],
            vm_code_hash: [8; 32],
            block_program: [8; 8],
            gas_used: 0,
            gas_limit: 1_000_000,
            proposer_address: [0u8; 32],
            runtime_extra: [9; 32],
            inputs_root: [0; 32],
        }
    }

    #[test]
    fn block_proof_round_trips() {
        let backend = MockProofSystem::new();
        let inputs = sample_block_inputs();
        let proof = backend
            .prove_block(&[], &inputs, [7; 32])
            .expect("mock prove");
        backend
            .verify_block(&proof, &inputs)
            .expect("honest verify");
    }

    #[test]
    fn block_verify_rejects_mutated_inputs() {
        let backend = MockProofSystem::new();
        let inputs = sample_block_inputs();
        let proof = backend
            .prove_block(&[], &inputs, [7; 32])
            .expect("mock prove");

        let mut tampered = inputs;
        tampered.state_root_after = [0xFF; 32];

        assert_eq!(
            backend.verify_block(&proof, &tampered),
            Err(ProofError::PublicInputMismatch)
        );
    }

    #[test]
    fn block_proof_is_deterministic_for_same_inputs() {
        let backend = MockProofSystem::new();
        let inputs = sample_block_inputs();
        let p1 = backend.prove_block(&[1, 2, 3], &inputs, [7; 32]).unwrap();
        let p2 = backend.prove_block(&[4, 5, 6], &inputs, [7; 32]).unwrap();
        // Mock proves over public inputs only; witness contents are ignored.
        assert_eq!(p1, p2);
    }

    #[test]
    fn block_proof_changes_with_inputs() {
        let backend = MockProofSystem::new();
        let proof_a = backend
            .prove_block(&[], &sample_block_inputs(), [7; 32])
            .unwrap();
        let mut other = sample_block_inputs();
        other.height = 43;
        let proof_b = backend.prove_block(&[], &other, [7; 32]).unwrap();
        assert_ne!(proof_a, proof_b);
    }
}
