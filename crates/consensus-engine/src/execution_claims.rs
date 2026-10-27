//! Invalid execution claims (design 08).
//!
//! An executing node that receives a candidate whose correct execution
//! contradicts its header re-executes it over the parent state and proves the
//! honest execution. Any node, executing or not, that receives a valid
//! receipt of a block whose results contradict the signed header keeps it.
//! The receipt, the header and its parent form an `InvalidExecutionClaim`
//! once the header's chunk is in History.

extern crate alloc;

use alloc::vec::Vec;

use neutrin0_consensus_types::{
    Block, BlockProof, BlockProofPublicInputs, Header, SlashingEvidence,
};
use neutrin0_primitives::StateRoot;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::Database;

use crate::engine::Engine;
use crate::import::ImportError;
use crate::store::StoreError;

/// The parent an execution claim names, with the pre-state root it binds:
/// `None` for the specification's first boundary, which has no header.
pub type ClaimParent = (Option<Header>, StateRoot);

/// The honest execution of a candidate whose header claimed other results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DivergentExecution {
    /// The offending header.
    pub header: Header,
    /// Its parent header; `None` when the parent is the specification's first
    /// boundary, which binds the pre-state itself.
    pub parent: Option<Header>,
    /// Public inputs of the honest execution: the header's inputs with the
    /// correct result fields.
    pub public_inputs: BlockProofPublicInputs,
    /// Proving witness of the honest execution.
    pub witness_bytes: Vec<u8>,
}

impl DivergentExecution {
    /// The claim a valid receipt of this execution supports.
    #[must_use]
    pub fn claim(&self, receipt: BlockProof) -> SlashingEvidence {
        SlashingEvidence::InvalidExecutionClaim {
            proposer_index: self.header.proposer_index,
            header: self.header.clone(),
            parent: self.parent.clone(),
            receipt,
        }
    }
}

impl<DB: Database> Engine<DB> {
    /// Re-execute `block` over its parent state and return the honest
    /// execution when its results contradict the header (design 08). Only a
    /// block on the current head, declaring the inputs it consumes, is
    /// examined; anything else returns `None`.
    ///
    /// # Errors
    /// Returns storage failures and execution errors.
    pub fn divergent_execution(
        &self,
        block: &Block,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<Option<DivergentExecution>, ImportError<DB::Error>> {
        let header = &block.header;
        if header.parent_hash != self.head_hash() {
            return Ok(None);
        }
        let Some((parent, state_root_before)) = self.claim_parent(header)? else {
            return Ok(None);
        };
        let ctx = self
            .execution_context(header, &block.body)
            .map_err(ImportError::DryRunFailed)?;
        if header.inputs_root != ctx.inputs_root() {
            return Ok(None);
        }
        let mut state = self.state().clone();
        let outcome = executor
            .execute_block(&ctx, &block.body, &mut state)
            .map_err(ImportError::DryRunFailed)?;
        let claimed = (
            header.state_root,
            header.receipts_root,
            header.runtime_extra,
            header.gas_used,
        );
        let honest = (
            outcome.state_root_after,
            outcome.receipts_root,
            outcome.runtime_extra,
            outcome.gas_used,
        );
        if honest == claimed {
            return Ok(None);
        }
        let mut public_inputs = self
            .block_public_inputs(header, state_root_before, header.hash())
            .map_err(|_| ImportError::DryRunFailed(crate::import::PROGRAMS_UNAVAILABLE.into()))?;
        public_inputs.state_root_after = outcome.state_root_after;
        public_inputs.receipt_root = outcome.receipts_root;
        public_inputs.runtime_extra = outcome.runtime_extra;
        public_inputs.gas_used = outcome.gas_used;
        Ok(Some(DivergentExecution {
            header: header.clone(),
            parent,
            public_inputs,
            witness_bytes: outcome.witness_bytes,
        }))
    }

    /// Keep the claim a receipt supports when it contradicts its header.
    ///
    /// The receipt must verify under the header's derived public inputs with
    /// the receipt's own result fields. No execution is needed; the receipt
    /// itself is the honest execution.
    pub(crate) fn note_contradicting_receipt<PS: ProofSystem>(
        &mut self,
        header: &Header,
        expected: &BlockProofPublicInputs,
        backend_proof: &PS::BlockProof,
        envelope: &BlockProof,
        proof_system: &PS,
    ) {
        if self.contradicting_receipts.len() >= MAX_CONTRADICTING_RECEIPTS
            || self
                .contradicting_receipts
                .iter()
                .any(|claim| matches!(claim, SlashingEvidence::InvalidExecutionClaim { header: held, .. } if held == header))
        {
            return;
        }
        let Ok(statement) = proof_system.block_statement(backend_proof) else {
            return;
        };
        let output = &statement.output;
        let mut honest = expected.clone();
        honest.state_root_after = output.post_state_root;
        honest.receipt_root = output.receipts_root;
        honest.runtime_extra = output.consensus_candidates_root;
        honest.gas_used = output.gas_used;
        if honest == *expected {
            return;
        }
        let Ok(verified) = proof_system.verify_block_statement(backend_proof, &honest) else {
            return;
        };
        let Ok(Some((parent, _))) = self.claim_parent(header) else {
            return;
        };
        self.contradicting_receipts
            .push(SlashingEvidence::InvalidExecutionClaim {
                proposer_index: header.proposer_index,
                header: header.clone(),
                parent,
                receipt: BlockProof {
                    public_inputs: honest,
                    prover_address: verified.prover_address,
                    statement_key: crate::prove::statement_key(&verified),
                    ..envelope.clone()
                },
            });
    }

    /// The parent a claim against `header` names, with the pre-state root it
    /// binds: nothing for a boundary without a header (genesis, or a hard
    /// fork's start), otherwise the stored parent header. `None` when that
    /// header is not held.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn claim_parent(
        &self,
        header: &Header,
    ) -> Result<Option<ClaimParent>, StoreError<DB::Error>> {
        if let Some(start) = neutrin0_prover_chunk::history::headerless_parent(
            self.chain_spec(),
            &header.parent_hash,
        ) {
            return Ok(Some((None, start.state_root)));
        }
        Ok(self.store().get_header(&header.parent_hash)?.map(|parent| {
            let state_root = parent.state_root;
            (Some(parent), state_root)
        }))
    }

    /// Drain the claims kept from contradicting receipts.
    pub fn take_contradicting_receipts(&mut self) -> Vec<SlashingEvidence> {
        core::mem::take(&mut self.contradicting_receipts)
    }
}

/// Most claims from contradicting receipts held until the node collects them.
const MAX_CONTRADICTING_RECEIPTS: usize = 16;
