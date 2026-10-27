//! Evidence anchors, openings and body authorization for consensus blocks.

extern crate alloc;

use alloc::vec::Vec;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::evidence::{EvidenceAnchor, EvidenceArtifact};
use neutrin0_consensus_types::history::is_recent_history_index;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofError;
use neutrin0_runtime_abi::RuntimeTransaction;
use neutrin0_storage::{Column, Database};

use crate::{Engine, FinalizeError};

impl<DB: Database> Engine<DB> {
    /// Build the trusted incoming anchor for ordinary or replay execution.
    pub fn evidence_anchor(
        &self,
        height: u64,
    ) -> Result<neutrin0_consensus_types::evidence::EvidenceAnchor, alloc::string::String> {
        if self.programs.is_none() {
            return Ok(neutrin0_consensus_types::evidence::EvidenceAnchor::default());
        }
        let programs = self
            .programs_for_height(height)
            .map_err(|_| alloc::string::String::from(crate::import::PROGRAMS_UNAVAILABLE))?;
        let spec = self.chain_spec();
        let chunk_id = self
            .chunk_of_height(height)
            .ok_or_else(|| alloc::string::String::from("invalid evidence anchor height"))?;
        let history_root = self
            .execution_boundary(chunk_id)
            .map_err(|_| alloc::string::String::from(crate::import::HISTORY_UNAVAILABLE))?
            .history_root;
        Ok(neutrin0_consensus_types::evidence::EvidenceAnchor {
            chain_spec_hash: self.chain_spec_hash(),
            chunk_id,
            history_root,
            block_guest_vk_digest: programs.execution.block,
            evidence_guest_vk_digest: programs.execution.evidence,
            fact_guest_vk_digest: programs.execution.fact,
            unbonding_delay_blocks: spec.runtime.unbonding_delay_blocks,
            chunk_size: spec.consensus.chunk_size,
            max_block_proving_input_bytes: spec.proof.max_block_proving_input_bytes,
            block_gas_limit: spec.genesis_gas_limit,
        })
    }

    /// Preceding finalized chunks whose complete historical records (validator
    /// vector, seed, certificate) this node keeps so safety evidence can still
    /// be constructed and raw reports verified locally: one unbonding delay,
    /// never less than the eight-chunk liveness window.
    #[must_use]
    pub const fn history_record_window_chunks(&self) -> u64 {
        let spec = self.chain_spec();
        neutrin0_consensus_types::history::history_record_window_chunks(
            spec.runtime.unbonding_delay_blocks,
            spec.consensus.chunk_size,
        )
    }

    /// Whether this node still keeps the complete historical record of a
    /// finalized chunk. Receipts about older chunks stay admissible when a
    /// reporter supplies an opening authenticated at a recent boundary.
    #[must_use]
    pub fn in_history_record_window(&self, chunk_id: u64) -> bool {
        neutrin0_consensus_types::history::is_history_index_within(
            chunk_id,
            self.finalized_next_chunk_id(),
            self.history_record_window_chunks(),
        )
    }

    /// Snapshot a self-contained offence for proving outside the engine lock.
    pub fn evidence_witness(
        &self,
        evidence: &neutrin0_consensus_types::SlashingEvidence,
    ) -> Result<neutrin0_prover_chunk::evidence::EvidenceWitness, FinalizeError<DB::Error>> {
        let block_guest_vk_digest = self
            .programs
            .ok_or(ProofError::Unsupported)?
            .execution
            .block;
        let id = neutrin0_prover_chunk::history::evidence_chunk_id(self.chain_spec(), evidence)
            .map_err(|_| ProofError::InvalidWitness)?;
        // Proving needs the complete record; a chunk this node no longer
        // retains can be proven by an archive, never here.
        let source = self
            .store()
            .historical_chunk(id)?
            .ok_or(ProofError::InvalidWitness)?;
        Ok(neutrin0_prover_chunk::evidence::EvidenceWitness {
            chain_spec: self.chain_spec().clone(),
            source,
            claim: neutrin0_prover_chunk::evidence::EvidenceClaim::Slash(evidence.clone()),
            block_guest_vk_digest,
            reporter: None,
        })
    }

    /// Open a locally retained record, or an archived record, for a new report.
    pub fn evidence_submission(
        &self,
        statement: neutrin0_consensus_types::evidence::EvidenceStatement,
    ) -> Result<neutrin0_consensus_types::evidence::EvidenceSubmission, FinalizeError<DB::Error>>
    {
        let count = self.finalized_next_chunk_id();
        let source = statement.context.chunk_id;
        // Safety has no source age limit. Pruned nodes can open only their
        // finite cache; external reporters supply older openings.
        let in_window = if statement.kind.is_safety() {
            source < count
        } else {
            is_recent_history_index(source, count)
        };
        if !in_window {
            return Err(ProofError::InvalidWitness.into());
        }
        // The path is authenticated against the statement's own context, so a
        // statement about a context that never was the canonical record fails
        // here rather than in the block.
        let history = self.store().history_path(
            source,
            count,
            neutrin0_consensus_types::evidence::commitment(&statement.context),
        )?;
        Ok(neutrin0_consensus_types::evidence::EvidenceSubmission { statement, history })
    }

    /// Authenticate a reporter's opening and advance it over a bounded finalized suffix.
    /// Old source chunks remain admissible; only the opening's anchor must be recent.
    /// Unknown old anchors are unavailable, while forged openings at known anchors
    /// are invalid witnesses. This lets callers defer refresh requests without
    /// misclassifying an old safety offence as expired.
    pub fn evidence_submission_with_path(
        &self,
        statement: &neutrin0_consensus_types::evidence::EvidenceStatement,
        path: &neutrin0_consensus_types::history::HistoryPath,
    ) -> Result<neutrin0_consensus_types::evidence::EvidenceSubmission, FinalizeError<DB::Error>>
    {
        let count = self.finalized_next_chunk_id();
        let source = statement.context.chunk_id;
        if path.index != source
            || source >= path.count
            || (!statement.kind.is_safety() && !is_recent_history_index(source, count))
        {
            return Err(ProofError::InvalidWitness.into());
        }
        if path.count > count {
            return Err(crate::StoreError::Corrupt(
                "evidence history anchor is not finalized locally",
            )
            .into());
        }
        if path.count
            < count.saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS)
        {
            return Err(
                crate::StoreError::Corrupt("evidence history anchor requires refresh").into(),
            );
        }
        let mut frontier = self.store().history_frontier(path.count)?;
        let root = frontier.root().ok_or(ProofError::InvalidWitness)?;
        let boundary =
            self.store()
                .consensus_boundary(path.count)?
                .ok_or(crate::StoreError::Corrupt(
                    "evidence history boundary is unavailable",
                ))?;
        if boundary.history_root != root {
            return Err(crate::StoreError::Corrupt(
                "evidence history frontier differs from boundary",
            )
            .into());
        }
        let leaf = neutrin0_consensus_types::evidence::commitment(&statement.context);
        if !path.verify(leaf, root) {
            return Err(ProofError::InvalidWitness.into());
        }
        let mut history = path.clone();
        for index in path.count..count {
            let record =
                self.store()
                    .historical_chunk(index)?
                    .ok_or(crate::StoreError::Corrupt(
                        "evidence history append is unavailable",
                    ))?;
            let appended_leaf = commitment(&record.evidence_context());
            history
                .advance(leaf, &frontier, appended_leaf)
                .ok_or(ProofError::InvalidWitness)?;
            frontier
                .append(appended_leaf)
                .ok_or(ProofError::InvalidWitness)?;
        }
        if frontier != self.store().history_frontier(count)? {
            return Err(ProofError::InvalidWitness.into());
        }
        Ok(neutrin0_consensus_types::evidence::EvidenceSubmission {
            statement: statement.clone(),
            history,
        })
    }

    /// Bind a candidate to its finalized boundary and complete parent ancestry.
    /// The runtime authenticates receipts and protects replay in the branch state.
    ///
    /// Evidence admissions are checked by `admissions_are_well_formed`, which
    /// rejects without unwinding: this runs natively on peer bodies, and the
    /// release profile aborts on panic. The block gas limit does not affect
    /// admission shape; it is accepted so callers pass the header as is.
    pub fn authorize_consensus_body(
        &self,
        height: u64,
        parent_hash: Hash,
        body: &neutrin0_consensus_types::Body,
        _gas_limit: u64,
        block_key: &[u32; 8],
    ) -> Result<(), FinalizeError<DB::Error>> {
        let chunk_id = self
            .chunk_of_height(height)
            .ok_or(ProofError::InvalidWitness)?;
        self.participation_acknowledgements(height, body)?;
        let inherited = self.inherited_vote_lane(height, parent_hash)?;
        let votes = inherited
            .bytes
            .checked_add(neutrin0_consensus_types::participation::vote_lane_bytes(
                &body.participation_acks,
            )?)
            .ok_or(ProofError::InvalidWitness)?;
        if votes > neutrin0_consensus_types::participation::MAX_PARTICIPATION_VOTE_BYTES
            || body
                .participation_acks
                .iter()
                .any(|vote| inherited.seats.contains(&vote.source_seat()))
        {
            return Err(ProofError::InvalidWitness.into());
        }
        let (context, _, _) = self.execution_consensus_boundary(chunk_id)?;
        let boundary_height = chunk_id
            .checked_mul(self.chunk_size())
            .ok_or(ProofError::InvalidWitness)?;
        let mut ancestor = parent_hash;
        for expected_height in (boundary_height + 1..height).rev() {
            let header = self
                .store()
                .get_header(&ancestor)?
                .ok_or(ProofError::InvalidWitness)?;
            if header.height != expected_height
                || header.hash() != ancestor
                || !self.has_body(&ancestor)?
            {
                return Err(ProofError::InvalidWitness.into());
            }
            ancestor = header.parent_hash;
        }
        if ancestor != context.parent_block_hash
            || (self.programs.is_some() && &context.programs.execution.block != block_key)
        {
            return Err(ProofError::InvalidWitness.into());
        }
        let anchor = self
            .evidence_anchor(height)
            .map_err(|_| ProofError::InvalidWitness)?;
        let transactions = body
            .transactions
            .iter()
            .map(|raw| borsh::from_slice(raw))
            .collect::<Result<Vec<RuntimeTransaction>, _>>()?;
        if !admissions_are_well_formed(
            self.chain_spec().chain_id,
            height,
            &anchor,
            &transactions,
            &body.evidence_proofs,
        ) {
            return Err(ProofError::InvalidWitness.into());
        }
        Ok(())
    }

    /// Whether a block body is archived under `hash`, read without decoding it.
    fn has_body(&self, hash: &Hash) -> Result<bool, crate::StoreError<DB::Error>> {
        let body = self
            .store()
            .db()
            .get(Column::Blocks, &crate::store::keys::hash_key(hash))
            .map_err(crate::StoreError::Database)?;
        Ok(body.is_some())
    }
}

/// Whether a body's evidence admissions satisfy the runtime's input rules
/// (`runtime_core::execution::check_evidence_admissions`) and exactly one attachment per
/// submission binds its statement to the anchor's evidence and fact programs,
/// in order. Peer bodies reach this check in native code, where the release
/// profile aborts on panic, so the non-panicking runtime check is used.
fn admissions_are_well_formed(
    chain_id: u64,
    height: u64,
    anchor: &EvidenceAnchor,
    transactions: &[RuntimeTransaction],
    attachments: &[EvidenceArtifact],
) -> bool {
    if neutrin0_runtime_core::execution::check_evidence_admissions(
        chain_id,
        height,
        anchor,
        transactions,
    )
    .is_err()
    {
        return false;
    }
    let admissions = transactions
        .iter()
        .filter_map(|transaction| match transaction {
            RuntimeTransaction::SubmitEvidence(submission) => Some(submission.as_ref()),
            RuntimeTransaction::User(_) => None,
        });
    admissions.clone().count() == attachments.len()
        && admissions.zip(attachments).all(|(submission, attachment)| {
            attachment.binds(
                &submission.statement,
                &anchor.evidence_guest_vk_digest,
                &anchor.fact_guest_vk_digest,
            )
        })
}
