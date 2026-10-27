//! Block receipts: binding the proving input to the consensus public inputs,
//! verifying receipts under the boundary's block program and caching the
//! verified bundles by exact bytes.

use std::sync::Arc;

use borsh::BorshDeserialize;
use neutrin0_consensus_types::BlockProofPublicInputs;
use neutrin0_consensus_types::evidence::EvidenceArtifact;
use neutrin0_proof_system::ProofError;
use neutrin0_runtime_abi::{
    BlockReceiptStatement, RuntimeBlockInput, RuntimeBlockOutput, StateWitness,
};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1Stdin};

use super::{Sp1BlockProof, Sp1ProofSystem};
use crate::{ProgramProver, guarded};

#[derive(Clone)]
pub(super) struct VerifiedBlock {
    pub(super) bundle: Arc<SP1ProofWithPublicValues>,
    pub(super) statement: BlockReceiptStatement,
}

impl<P> Sp1ProofSystem<P>
where
    P: ProgramProver,
{
    /// Bind the proving input and witness to the consensus public inputs.
    /// The cryptographic check happens inside the guest (`WitnessState::new`
    /// rebuilds the partial trie and rejects a mismatch), but failing fast
    /// here avoids a wasted proof.
    pub(super) fn check_block_input(
        input: &RuntimeBlockInput,
        witness: &StateWitness,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if input.context != *public_inputs.context
            || public_inputs.parent_block_hash != public_inputs.context.parent_block_hash
        {
            return Err(ProofError::PublicInputMismatch);
        }
        if witness.pre_state_root != public_inputs.state_root_before {
            return Err(ProofError::PublicInputMismatch);
        }
        if input.chain_id != public_inputs.chain_id {
            return Err(ProofError::PublicInputMismatch);
        }
        // Bind the STF input's gas ceiling to the consensus header.
        // The guest will execute against `input.block_gas_limit`; if
        // it diverged from the header's `gas_limit` the prover could
        // build a proof for a transition the header didn't authorize.
        if input.block_gas_limit != public_inputs.gas_limit {
            return Err(ProofError::PublicInputMismatch);
        }
        // Bind the STF input's block height to the consensus header.
        // Withdrawal maturity is `mature_at_height = block_height +
        // UNBONDING_DELAY_BLOCKS`; a prover that supplied a forged
        // height could otherwise unlock funds earlier than the header
        // permits.
        if input.block_height != public_inputs.height {
            return Err(ProofError::PublicInputMismatch);
        }
        if input.proposer_address != public_inputs.proposer_address {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }

    /// The block Guest's stdin: normal input plus verified attachments on
    /// the native recursive proof stream. Attachments verify only under the
    /// anchor's installed evidence program; without it the block cannot be
    /// proven.
    pub(super) fn block_proving_stdin(
        &self,
        input: &RuntimeBlockInput,
        witness: &StateWitness,
        evidence_proofs: &[EvidenceArtifact],
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<SP1Stdin, ProofError> {
        let evidence = self
            .keys(&input.evidence_anchor.evidence_guest_vk_digest)
            .ok();
        let evidence_vk = evidence.as_deref().map(|keys| &keys.vk);
        crate::block_stdin(input, witness, evidence_proofs, evidence_vk, prover_address)
            .map_err(|_| ProofError::InvalidWitness)
    }

    /// Cross-check the committed statement of a freshly proven block against
    /// the attribution and consensus public inputs it was proven for.
    pub(super) fn check_committed_block(
        proof: &SP1ProofWithPublicValues,
        prover_address: neutrin0_primitives::Hash,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        let committed: BlockReceiptStatement =
            BorshDeserialize::deserialize_reader(&mut proof.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
        if committed.prover_address != prover_address {
            return Err(ProofError::PublicInputMismatch);
        }
        Self::check_block_output(&committed.output, public_inputs)
    }

    pub(super) fn verified_block(
        &self,
        proof: &Sp1BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<VerifiedBlock, ProofError> {
        if inputs.context.finalized.programs.execution.fact != self.embedded.execution.fact {
            return Err(ProofError::PublicInputMismatch);
        }
        if proof.bytes.len() > neutrin0_prover_chunk::proof_verification::MAX_PROOF_BYTES - 4 {
            return Err(ProofError::MalformedProof);
        }
        // A receipt verified under one program says nothing about another.
        let identity = (
            inputs.block_program,
            neutrin0_primitives::blake3_256(&proof.bytes),
        );
        let cached = self
            .blocks
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .get(&identity)
            .cloned();
        if let Some(cached) = cached {
            Self::check_block_output(&cached.statement.output, inputs)?;
            return Ok(cached);
        }
        let rejected = self
            .block_rejections
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .get(&identity)
            .copied();
        if let Some(rejected) = rejected {
            return Err(rejected);
        }
        let verdict = self
            .block_verdicts
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .get(&identity)
            .cloned();
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        // Bytes already verified under this program need only decoding again.
        let statement = if let Some(statement) = verdict {
            Self::check_block_output(&statement.output, inputs)?;
            statement
        } else {
            let statement = match self.verify_block_bundle(&bundle, inputs) {
                Ok(statement) => statement,
                Err(error) => {
                    // A public-value mismatch depends on the header;
                    // anything failing after it does not.
                    if error != ProofError::PublicInputMismatch {
                        self.block_rejections
                            .lock()
                            .map_err(|_| ProofError::BackendRejected)?
                            .insert(identity, 1, error);
                    }
                    return Err(error);
                }
            };
            self.block_verdicts
                .lock()
                .map_err(|_| ProofError::BackendRejected)?
                .insert(
                    identity,
                    borsh::object_length(&statement).unwrap_or(usize::MAX),
                    statement.clone(),
                );
            statement
        };
        let verified = VerifiedBlock {
            bundle: Arc::new(bundle),
            statement,
        };
        self.blocks
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .insert(identity, proof.bytes.len(), verified.clone());
        Ok(verified)
    }

    fn verify_block_bundle(
        &self,
        bundle: &SP1ProofWithPublicValues,
        inputs: &BlockProofPublicInputs,
    ) -> Result<BlockReceiptStatement, ProofError> {
        guarded(|| {
            if !matches!(bundle.proof, SP1Proof::Compressed(_)) {
                return Err(ProofError::MalformedProof);
            }
            // The caller names the block program its chunk boundary expects; the
            // receipt must verify under exactly that key. An installed program
            // uses the full verifier; any other is checked by digest, which never
            // accepts mock receipts.
            let statement: BlockReceiptStatement =
                borsh::from_slice(bundle.public_values.as_slice())
                    .map_err(|_| ProofError::MalformedProof)?;
            // Public values that cannot match the header are refused before
            // the STARK is checked.
            Self::check_block_output(&statement.output, inputs)?;
            match self.keys(&inputs.block_program) {
                Ok(block) => self
                    .prover
                    .verify(bundle, &block.vk, None)
                    .map_err(|_| ProofError::BackendRejected)?,
                Err(_) => neutrin0_prover_chunk::proof_verification::verify_typed_receipt(
                    &bundle.proof,
                    bundle.public_values.as_slice(),
                    &bundle.sp1_version,
                    &statement,
                    &inputs.block_program,
                )
                .map_err(|_| ProofError::BackendRejected)?,
            }
            Ok(statement)
        })?
    }

    /// The Chunk Guest's own binding rule, including the header's
    /// `inputs_root` over every consumed input and report, so a receipt
    /// marks a block proven only if a voter could certify it.
    pub(super) fn check_block_output(
        output: &RuntimeBlockOutput,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if inputs.parent_block_hash != inputs.context.parent_block_hash
            || !neutrin0_prover_chunk::execution::output_binds(output, inputs)
        {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }
}
