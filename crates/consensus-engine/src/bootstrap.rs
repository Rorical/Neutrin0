//! Install an authenticated execution snapshot at a recursively proven boundary.

use crate::{Engine, FinalizeError, RetentionPolicy, StoreError};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history::HistoryFrontier;
use neutrin0_consensus_types::history_proof::{AnchorOpening, ConsensusBoundary, anchors};
use neutrin0_consensus_types::{Checkpoint, Header};
use neutrin0_primitives::Validator;
use neutrin0_proof_system::{ProofError, VerifiedHistory};
use neutrin0_prover_chunk::history::HistoricalOpening;
use neutrin0_storage::Database;

mod authentication;

use authentication::{
    authenticate_history, bootstrap_chunk_proof, check_recent_indices, covered_reports,
    opening_state,
};

impl<DB: Database> Engine<DB> {
    /// Reject a bootstrap to `count` while a persisted BFT session beyond it
    /// still holds a lock that installation would discard. A session of chunk
    /// `count` itself survives installation and resumes when that chunk opens.
    fn ensure_no_unfinalized_lock(&self, count: u64) -> Result<(), FinalizeError<DB::Error>> {
        for (key, _) in self
            .store()
            .db()
            .iter_column(neutrin0_storage::Column::BftSessions)
            .map_err(StoreError::Database)?
        {
            let id = u64::from_be_bytes(
                key.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("invalid BFT session key"))?,
            );
            if id > count {
                return Err(
                    StoreError::Corrupt("bootstrap would discard an unfinalized lock").into(),
                );
            }
        }
        Ok(())
    }

    /// Install a full-node bootstrap only after receipt and trust-policy verification.
    ///
    /// `history` is the verified receipt of the chunk ending at the endpoint,
    /// which proves the chain from the specification's start. `trusted_start`
    /// comes from local trust configuration, or the existing local finalized
    /// boundary; `anchor` places it under the endpoint's history root (neither
    /// the start nor the endpoint itself needs one). The endpoint's execution
    /// state and sanctions trie must already be installed, in that order, by
    /// [`ChainStore::install_state_slice`](crate::store::ChainStore::install_state_slice).
    /// The caller applies weak-subjectivity and freshness policy before
    /// invoking this method; the receipt alone never authorizes changing that
    /// anchor.
    #[allow(
        clippy::too_many_arguments,
        reason = "Authenticate the entire snapshot before a single durable installation and publication."
    )]
    pub fn install_bootstrap(
        &mut self,
        history: VerifiedHistory,
        anchor: Option<&AnchorOpening>,
        trusted_start: Checkpoint,
        header: &Header,
        validators: &[Validator],
        frontier: &HistoryFrontier,
        recent: &[HistoricalOpening],
        executor: Option<&dyn neutrin0_proof_system::ErasedBlockExecutor>,
    ) -> Result<(), FinalizeError<DB::Error>> {
        let spec = self.chain_spec();
        let verified_chain = history.domain().chain;
        let history = history.into_proof();
        let receipt = &history.statement;
        let statement = &receipt.statement;
        let end = statement.end;
        // The start of the chunk ending here, whose History leaf the last
        // retained record must be.
        let previous = statement.start;
        let count = end.next_chunk_id;
        let local_count = self.finalized_next_chunk_id();
        let first = ConsensusBoundary::first(spec);
        let supersedes = self.certified_dependency_superseded(count, local_count, anchor, recent);
        if !supersedes
            || self.retention_info()?.policy == RetentionPolicy::Archive
            || count == 0
            || count < local_count
            || self.head_height() > end.height
            || statement.chain != verified_chain
            || self.store().history_domain()?.map(|trusted| trusted.chain) != Some(statement.chain)
            || statement.chain != self.chain_binding()
            || !end.is_well_formed(spec)
            || trusted_start.chain != statement.chain
            || !anchors(&first, &trusted_start.boundary, &end, anchor)
            || (local_count != 0
                && trusted_start.boundary != self.canonical_boundary(local_count)?)
            || header.hash() != end.block_hash
            || header.height != end.height
            || header.state_root != end.state_root
            || header.slot != end.slot
            || self.store().state_install()?
                != Some(crate::store::StateInstall {
                    roots: vec![end.state_root, end.identity_sanctions_root],
                    finished: true,
                })
            || commitment(validators) != end.validators_root
            || previous.next_chunk_id.checked_add(1) != Some(count)
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        self.ensure_no_unfinalized_lock(count)?;
        check_recent_indices(count, recent)?;
        authenticate_history(
            self.consensus_domain(),
            &spec.consensus,
            &end,
            header,
            frontier,
            recent,
        )?;
        let proof = bootstrap_chunk_proof(&history, &previous, recent)?;
        let consensus = opening_state(spec, &end, validators, frontier)?;
        let covered = self.covered_bootstrap_reports(executor, recent, &end)?;
        let statement = statement.clone();
        let receipt = crate::store::StoredChunkReceipt::new(proof, &statement, self.local_slot());
        let genesis = ConsensusBoundary::genesis(spec);
        self.store_mut().commit_bootstrap(
            Some((&receipt, &statement)),
            &genesis,
            header,
            &consensus,
            recent,
            &covered,
        )?;
        self.publish_bootstrap_state(&consensus);
        Ok(())
    }

    /// Whether a certified dependency on chunk `local_count` yields to the
    /// endpoint at `count`: a later endpoint whose History holds exactly that
    /// chunk, read from the trusted boundary's opening or a retained recent
    /// record. Otherwise a node offline past the retention window could never
    /// catch up.
    fn certified_dependency_superseded(
        &self,
        count: u64,
        local_count: u64,
        anchor: Option<&AnchorOpening>,
        recent: &[HistoricalOpening],
    ) -> bool {
        self.certified_history_context().is_none_or(|certified| {
            count > local_count
                && (anchor.is_some_and(|opening| opening.context == certified)
                    || recent
                        .iter()
                        .any(|opening| opening.record.evidence_context() == certified))
        })
    }

    /// The pooled reports the runtime which produced the endpoint state at
    /// `end` already covers. Query only that runtime; a missing/malformed
    /// response retains every report for later refresh.
    fn covered_bootstrap_reports(
        &self,
        executor: Option<&dyn neutrin0_proof_system::ErasedBlockExecutor>,
        recent: &[HistoricalOpening],
        end: &ConsensusBoundary,
    ) -> Result<Vec<neutrin0_primitives::Hash>, StoreError<DB::Error>> {
        let reports = self.store().evidence_reports()?;
        let state = self.store().state_at(end.state_root);
        Ok(executor
            .and_then(|executor| {
                covered_reports(
                    executor,
                    recent.last()?.record.runtime_code_hash,
                    &state,
                    &reports,
                )
            })
            .unwrap_or_default())
    }

    /// Start a hard fork's specification from its predecessor's endpoint
    /// (design 20) in a fresh data directory. The boundary the specification
    /// pins is trusted as genesis is, so no History proof of this
    /// specification exists or is needed: the endpoint's header, validators,
    /// History frontier and preceding records are checked against it, the
    /// records' certificates under their predecessor domains. The state and
    /// sanctions tries must already be installed, in that order
    /// ([`ChainStore::install_state_slice`](crate::store::ChainStore::install_state_slice)).
    ///
    /// # Errors
    /// Refuses a specification without a fork, a data directory that has
    /// finalized anything, and data that does not match the pinned start.
    pub fn install_fork_start(
        &mut self,
        header: &Header,
        validators: &[Validator],
        frontier: &HistoryFrontier,
        recent: &[HistoricalOpening],
    ) -> Result<(), FinalizeError<DB::Error>> {
        let spec = self.chain_spec();
        let start = spec
            .fork
            .as_deref()
            .ok_or(ProofError::InvalidWitness)?
            .start;
        let count = start.next_chunk_id;
        if self.finalized_next_chunk_id() != 0
            || self.head_height() != 0
            || header.hash() != start.block_hash
            || header.height != start.height
            || header.state_root != start.state_root
            || header.slot != start.slot
            || self.store().state_install()?
                != Some(crate::store::StateInstall {
                    roots: vec![start.state_root, start.identity_sanctions_root],
                    finished: true,
                })
            || commitment(validators) != start.validators_root
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        check_recent_indices(count, recent)?;
        authenticate_history(
            self.consensus_domain(),
            &spec.consensus,
            &start,
            header,
            frontier,
            recent,
        )?;
        let consensus = opening_state(spec, &start, validators, frontier)?;
        let genesis = ConsensusBoundary::genesis(spec);
        self.store_mut()
            .commit_bootstrap(None, &genesis, header, &consensus, recent, &[])?;
        self.publish_bootstrap_state(&consensus);
        Ok(())
    }

    /// Import what the predecessor's data directory retained beyond the
    /// endpoint from a carry file
    /// ([`ChainStore::export_fork_carry`](crate::store::ChainStore::export_fork_carry)),
    /// once, after [`Self::install_fork_start`]. Returns `None` when this
    /// directory already imported one.
    ///
    /// # Errors
    /// Refuses a specification without a fork and every carry the store's
    /// import refuses.
    pub fn import_fork_carry(
        &mut self,
        input: &mut impl std::io::Read,
    ) -> Result<Option<crate::store::CarrySummary>, StoreError<DB::Error>> {
        let fork = self
            .chain_spec()
            .fork
            .as_deref()
            .ok_or(StoreError::Corrupt("the specification is not a hard fork"))?;
        let (predecessor, count) = (fork.predecessor, fork.count);
        self.store_mut()
            .import_fork_carry(input, predecessor, count)
    }
}
