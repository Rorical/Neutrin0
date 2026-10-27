//! Admission of peer blocks: slashing observation, consensus-body
//! authorization and the local effects of an import.

use neutrin0_consensus_engine::{Engine, ImportBlockOutcome};
use neutrin0_consensus_types::Block;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::{HeadersImported, SyncBackendError};

use super::{ChainBackend, rejected};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    fn authorize_incoming_consensus_body(&self, block: &Block) -> Result<(), SyncBackendError> {
        if self.block_program().is_none() {
            return Ok(());
        }
        let replaces_attachments =
            self.with_engine(|engine| Self::authorize_unknown_consensus_body(engine, block))?;
        // Initial execution authenticates attachments in its WASM shell. A
        // replay may reuse archived execution; verify replacement witnesses here.
        if self.block_executor_snapshot().is_none() || replaces_attachments {
            self.verify_evidence_attachments(block)?;
        }
        Ok(())
    }

    /// Authenticate and authorize a block this node does not already hold;
    /// returns whether it replaces the archived body's attachments.
    fn authorize_unknown_consensus_body(
        engine: &Engine<DB>,
        block: &Block,
    ) -> Result<bool, SyncBackendError> {
        if block.header.height == 0 {
            return Err(SyncBackendError::Rejected(
                "a proposed block must have positive height".into(),
            ));
        }
        let archived = engine.store().get_body(&block.hash()).map_err(rejected)?;
        let known = engine
            .store()
            .get_header(&block.hash())
            .map_err(rejected)?
            .as_ref()
            == Some(&block.header)
            && archived
                .as_ref()
                .is_some_and(|body| body.same_consensus_content(&block.body));
        let chunk = block
            .header
            .height
            .checked_sub(1)
            .and_then(|h| h.checked_div(engine.chain_spec().consensus.chunk_size));
        if !known && chunk.is_some_and(|chunk| chunk < engine.finalized_next_chunk_id()) {
            return Err(SyncBackendError::NotAvailable(
                "stale block below the finalized boundary".into(),
            ));
        }
        if !known && chunk.is_none_or(|id| engine.execution_boundary(id).is_err()) {
            return Err(SyncBackendError::ChainBehind(
                "waiting for the previous complete chunk proof".to_owned(),
            ));
        }
        if !known {
            let key = engine
                .programs_for_height(block.header.height)
                .map_err(rejected)?
                .execution
                .block;
            engine
                .authenticate_import_header(&block.header)
                .map_err(Self::map_import_err)?;
            engine
                .authorize_consensus_body(
                    block.header.height,
                    block.header.parent_hash,
                    &block.body,
                    block.header.gas_limit,
                    &key,
                )
                .map_err(rejected)?;
        }
        Ok(archived
            .as_ref()
            .is_some_and(|body| body.same_consensus_content(&block.body) && body != &block.body))
    }

    fn verify_evidence_attachments(&self, block: &Block) -> Result<(), SyncBackendError> {
        // Attachments must name the evidence and fact programs of the
        // block's own chunk boundary, never ones the peer declares.
        let programs = self
            .with_engine(|engine| engine.programs_for_height(block.header.height))
            .map_err(rejected)?
            .execution;
        for attachment in &block.body.evidence_proofs {
            if !attachment.binds(&attachment.statement, &programs.evidence, &programs.fact) {
                return Err(SyncBackendError::Rejected(
                    "evidence program identity mismatch".to_owned(),
                ));
            }
            self.proof_system
                .verify_evidence(
                    &attachment.proof_bytes,
                    &attachment.membership.batch,
                    &programs.evidence,
                )
                .map_err(rejected)?;
        }
        Ok(())
    }

    /// Slashing detection runs first: a peer that gossips a validly-signed but
    /// non-extending header (e.g. an equivocating block we already reorg'd
    /// past) must still be surfaced as evidence even if the import later
    /// rejects it on chain continuity grounds. Headers that fail signature
    /// verification are silently dropped — they are not authentic so there is
    /// no slashable signer to attribute. The consensus body is then authorized.
    pub(super) async fn observe_and_authorize(
        &self,
        block: &Block,
    ) -> Result<(), SyncBackendError> {
        if let Ok(Some(evidence)) = self.with_live_engine_mut(|engine| {
            engine
                .observe_header_for_slashing(&block.header)
                .map_err(rejected)
        }) {
            self.pool_and_gossip_slashing(evidence).await;
        }
        self.authorize_incoming_consensus_body(block)
    }

    /// Local effects of an imported block, and the head it produced.
    pub(super) fn after_block_import(
        &self,
        block: &Block,
        outcome: &ImportBlockOutcome,
    ) -> HeadersImported {
        self.queue_header_facts(&block.header);
        self.absorb_programs(&block.body.programs);
        HeadersImported {
            new_head_height: outcome.new_head_height,
            new_head_hash: outcome.new_head_hash,
            new_head_slot: outcome.new_head_slot,
        }
    }
}
