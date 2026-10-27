//! Atomic checkpoint installation and bounded authenticated historical openings.

use super::{
    ChainStore, StatePin, StoreError, StoredChunkReceipt, chunk_receipt_key, keys, pointers,
};
use crate::{BlockState, RetentionInfo, RetentionPolicy, full_chunk::ConsensusState};
use neutrin0_consensus_types::Header;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history_proof::{ConsensusBoundary, ConsensusStatement};
use neutrin0_primitives::Hash;
use neutrin0_prover_chunk::history::HistoricalOpening;
use neutrin0_storage::{Batch, Column, Database};

const BOOTSTRAP_ANCHOR: &[u8] = b"bootstrap_anchor";
/// Chunk ranges a bootstrapped reporter never observed, oldest first.
pub(super) const REPORTER_GAPS: &[u8] = b"reporter_gaps";

impl<DB: Database> ChainStore<DB> {
    /// Half-open chunk ranges `[from, to)` whose signatures this reporter never
    /// observed because a snapshot bootstrap jumped over them. Offences signed
    /// only there need another reporter or an archive.
    pub fn reporter_gaps(&self) -> Result<Vec<(u64, u64)>, StoreError<DB::Error>> {
        Ok(self
            .get_decoded(Column::Meta, REPORTER_GAPS)?
            .unwrap_or_default())
    }

    /// First chunk for which a checkpoint-bootstrapped node can serve raw sources.
    /// Historical consensus records have their own preceding-eight-chunk window.
    pub fn bootstrap_source_floor(&self) -> Result<u64, StoreError<DB::Error>> {
        let boundary: Option<ConsensusBoundary> =
            self.get_decoded(Column::Meta, BOOTSTRAP_ANCHOR)?;
        Ok(boundary.map_or(0, |boundary| boundary.next_chunk_id))
    }

    /// Replace all canonical execution data in one durable publication. Signing
    /// intents are deliberately preserved across a bootstrap to prevent equivocation.
    ///
    /// The snapshot's state is already stored by a finished installation
    /// (`install_state_slice`); its roots become the endpoint block's
    /// post-state and the live sanctions trie, and every pin of the replaced
    /// chain is released for bounded collection. `genesis` is the chain's
    /// original genesis boundary, which a hard fork keeps at height zero.
    pub(crate) fn commit_bootstrap(
        &mut self,
        receipt: Option<(&StoredChunkReceipt, &ConsensusStatement)>,
        genesis: &ConsensusBoundary,
        header: &Header,
        consensus: &ConsensusState,
        recent: &[HistoricalOpening],
        covered_reports: &[Hash],
    ) -> Result<(), StoreError<DB::Error>> {
        let mut batch = Batch::new();
        self.stage_reporter_bootstrap_batch(&mut batch, consensus, recent)?;
        let end = consensus.boundary;
        let count = end.next_chunk_id;
        self.stage_replaced_chain_deletions(&mut batch, count)?;
        self.stage_pooled_reports_after_bootstrap(&mut batch, recent, covered_reports, &end)?;
        // The installed roots become the endpoint block's post-state and the
        // live sanctions trie; what only the replaced chain's pins kept is
        // collected afterwards, a bounded slice at a time.
        self.release_chain_pins_batch(&mut batch)?;
        self.adopt_state_install_batch(
            &mut batch,
            &[end.state_root, end.identity_sanctions_root],
            &[StatePin::Block(end.block_hash), StatePin::Sanctions],
        )?;
        // Runtime-owned admission markers are queried through the installed
        // historical runtime after installation. Without that response pooled
        // reports remain retained; native account layouts are never guessed here.
        put_endpoint_rows(&mut batch, header, genesis, consensus)?;
        let policy = self.retention_info()?.policy;
        put_bootstrap_anchor_rows(&mut batch, policy, genesis, &end)?;
        put_endpoint_receipt(&mut batch, receipt)?;
        put_recent_history(&mut batch, consensus, recent, policy)?;
        self.retain_reporter_bootstrap_batch(&mut batch, recent, policy)?;
        self.write_observed_batch(batch, true)
    }

    /// Stage a reporter's carry across the jump: refreshed watched paths and
    /// the gap of chunks it never observed.
    fn stage_reporter_bootstrap_batch(
        &self,
        batch: &mut Batch,
        consensus: &ConsensusState,
        recent: &[HistoricalOpening],
    ) -> Result<(), StoreError<DB::Error>> {
        // A reporter keeps everything it retained. Chunks the snapshot covers
        // move to its count; others the jump left unopenable stay dormant
        // until refreshed, and the chunks it jumps over without observing them
        // are recorded as a gap.
        if self.reporter_has_history()? {
            let observed = self.finalized_count()?;
            let resumed = recent
                .iter()
                .map(|opening| opening.record.chunk.chunk_id)
                .min()
                .unwrap_or(consensus.boundary.next_chunk_id);
            if observed < resumed {
                let mut gaps = self.reporter_gaps()?;
                gaps.push((observed, resumed));
                batch.put(Column::Meta, REPORTER_GAPS, borsh::to_vec(&gaps)?);
            }
            self.refresh_reporter_paths_batch(batch, recent, &consensus.frontier)?;
        }
        Ok(())
    }

    /// Stage the deletion of everything the snapshot replaces: pending
    /// bootstrap metadata, staged downloads and leases, every canonical
    /// execution and consensus column, and the BFT sessions below `count`.
    fn stage_replaced_chain_deletions(
        &self,
        batch: &mut Batch,
        count: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        // Deleting an absent fixed key is a no-op; staged downloads and leases
        // are found by prefix without reading the rest of the metadata column
        // or the staged objects' bytes.
        batch.delete(Column::Meta, pointers::BOOTSTRAP_PENDING);
        // The snapshot finalized past any certified chunk (the install checked
        // it holds exactly that chunk), so the dependency is superseded.
        batch.delete(Column::Meta, crate::certified::CERTIFIED_EXECUTION_KEY);
        // `STATE_DOWNLOAD` prefixes every download row.
        for prefix in [pointers::STATE_DOWNLOAD, super::snapshot::SNAPSHOT_PREFIX] {
            let mut from = prefix.to_vec();
            loop {
                let page = self
                    .db()
                    .keys_from(Column::Meta, &from, 4096)
                    .map_err(StoreError::Database)?;
                let full = page.len() == 4096;
                let mut last = None;
                for key in page.into_iter().take_while(|key| key.starts_with(prefix)) {
                    batch.delete(Column::Meta, key.clone());
                    last = Some(key);
                }
                match last.filter(|_| full) {
                    Some(mut key) => {
                        key.push(0);
                        from = key;
                    }
                    None => break,
                }
            }
        }
        for column in [
            Column::Blocks,
            Column::ExecutionTransactions,
            Column::Headers,
            Column::HeaderByHeight,
            Column::HeaderBySlot,
            Column::Chunks,
            Column::BlockProofs,
            Column::BlockStates,
            Column::ChunkProofs,
            Column::ChunkReceipts,
            Column::Witnesses,
            Column::StateDiffs,
            Column::ValidatorSetSnapshots,
            Column::Finalized,
            Column::ChunkStatements,
            Column::ConsensusBoundaries,
            Column::HistoricalChunks,
            Column::HistoryNodes,
            Column::HistoryFrontiers,
            Column::HistoryPaths,
            Column::FinalizedOffences,
        ] {
            for key in self.db().iter_keys(column).map_err(StoreError::Database)? {
                batch.delete(column, key);
            }
        }
        // The installer refused sessions beyond `count`; one of chunk `count`
        // keeps its lock and resumes when that chunk opens.
        for key in self
            .db()
            .keys_below(Column::BftSessions, &count.to_be_bytes())
            .map_err(StoreError::Database)?
        {
            batch.delete(Column::BftSessions, key);
        }
        Ok(())
    }

    /// Drop the pooled reports finalized state already covers, refresh the
    /// paths of those the snapshot's recent openings reveal and keep the rest
    /// dormant.
    fn stage_pooled_reports_after_bootstrap(
        &self,
        batch: &mut Batch,
        recent: &[HistoricalOpening],
        covered_reports: &[Hash],
        end: &ConsensusBoundary,
    ) -> Result<(), StoreError<DB::Error>> {
        let count = end.next_chunk_id;
        for mut report in self.evidence_reports()? {
            let statement = &report.artifact.statement;
            if covered_reports.contains(&report.artifact.statement_id())
                || self.is_identity_slashed(&statement.offender.pubkey)?
            {
                batch.delete(Column::EvidenceProofs, report.artifact.statement_id());
                continue;
            }
            if report.history.count > count {
                return Err(StoreError::Corrupt(
                    "bootstrap precedes pooled evidence anchor",
                ));
            }
            let leaf = commitment(&statement.context);
            if let Some(opening) = recent.iter().find(|opening| {
                opening.record.chunk.chunk_id == statement.context.chunk_id
                    && commitment(&opening.record.evidence_context()) == leaf
            }) {
                if !opening.path.verify(leaf, end.history_root) {
                    return Err(StoreError::Corrupt("bootstrap evidence opening"));
                }
                report.history = opening.path.clone();
                Self::put_evidence_report_batch(batch, &report)?;
            }
            // Reports beyond the supplied snapshot window remain durable and
            // dormant until their holder supplies a fresh authenticated path.
        }
        Ok(())
    }
}

/// Stage the endpoint block's header, indexes and state, the finalized
/// pointers and the consensus state and validator set at `count`.
fn put_endpoint_rows<E>(
    batch: &mut Batch,
    header: &Header,
    genesis: &ConsensusBoundary,
    consensus: &ConsensusState,
) -> Result<(), StoreError<E>> {
    let end = consensus.boundary;
    let count = end.next_chunk_id;
    batch.put(Column::Headers, end.block_hash, borsh::to_vec(header)?);
    batch.put(
        Column::HeaderByHeight,
        keys::height_key(end.height),
        end.block_hash,
    );
    batch.put(
        Column::HeaderByHeight,
        keys::height_key(0),
        genesis.block_hash,
    );
    batch.put(
        Column::HeaderBySlot,
        keys::slot_block_key(end.slot, &end.block_hash),
        Vec::new(),
    );
    batch.put(
        Column::BlockStates,
        end.block_hash,
        borsh::to_vec(&BlockState::Finalized)?,
    );
    for pointer in [pointers::TIP, pointers::FINALIZED_HEAD] {
        batch.put(Column::Finalized, pointer, end.block_hash);
    }
    batch.put(
        Column::Finalized,
        pointers::LATEST_FINALIZED_CHUNK_ID,
        keys::chunk_id_key(count - 1),
    );
    batch.put(Column::Finalized, pointers::FINALIZED_SEED, end.seed);
    batch.put(
        Column::Finalized,
        pointers::CONSENSUS_STATE,
        borsh::to_vec(consensus)?,
    );
    batch.put(
        Column::ValidatorSetSnapshots,
        keys::chunk_id_key(count),
        borsh::to_vec(&consensus.next_context.active_validators)?,
    );
    batch.put(
        Column::Finalized,
        pointers::LATEST_VALIDATOR_SET_INDEX,
        keys::chunk_id_key(count),
    );
    Ok(())
}

/// Stage the retention metadata the bootstrap starts from, the bootstrap
/// anchor and the genesis and endpoint boundaries.
fn put_bootstrap_anchor_rows<E>(
    batch: &mut Batch,
    policy: RetentionPolicy,
    genesis: &ConsensusBoundary,
    end: &ConsensusBoundary,
) -> Result<(), StoreError<E>> {
    let count = end.next_chunk_id;
    let info = RetentionInfo {
        policy,
        pruned_before_chunk: count,
        first_retained_height: end
            .height
            .checked_add(1)
            .ok_or(StoreError::Corrupt("bootstrap height overflow"))?,
    };
    batch.put(
        Column::Meta,
        super::retention::RETENTION_KEY,
        borsh::to_vec(&info)?,
    );
    batch.put(Column::Meta, BOOTSTRAP_ANCHOR, borsh::to_vec(end)?);
    for boundary in [genesis, end] {
        batch.put(
            Column::ConsensusBoundaries,
            keys::chunk_id_key(boundary.next_chunk_id),
            borsh::to_vec(boundary)?,
        );
    }
    Ok(())
}

/// Stage the endpoint's receipt where ratification reads it.
fn put_endpoint_receipt<E>(
    batch: &mut Batch,
    receipt: Option<(&StoredChunkReceipt, &ConsensusStatement)>,
) -> Result<(), StoreError<E>> {
    // The endpoint's receipt is this node's History proof and the proof
    // the next certificate ratifies, retained where ratification reads. A
    // hard fork's start has none: its History begins there.
    if let Some((receipt, statement)) = receipt {
        batch.put(
            Column::ConsensusBoundaries,
            keys::chunk_id_key(statement.start.next_chunk_id),
            borsh::to_vec(&statement.start)?,
        );
        let proof = &receipt.proof;
        let id = keys::chunk_id_key(proof.chunk_id);
        batch.put(Column::ChunkProofs, id, borsh::to_vec(proof)?);
        batch.put(Column::ChunkStatements, id, borsh::to_vec(statement)?);
        batch.put(
            Column::ChunkReceipts,
            chunk_receipt_key(proof.chunk_id, &receipt.statement_key),
            borsh::to_vec(receipt)?,
        );
    }
    Ok(())
}

/// Stage the frontier at the endpoint and the recent openings with their
/// records (and, on an archive, their tree nodes).
fn put_recent_history<E>(
    batch: &mut Batch,
    consensus: &ConsensusState,
    recent: &[HistoricalOpening],
    policy: RetentionPolicy,
) -> Result<(), StoreError<E>> {
    let end = consensus.boundary;
    super::history::put_history_frontier(batch, &consensus.frontier)?;
    for opening in recent {
        let leaf = commitment(&opening.record.evidence_context());
        super::history::put_history_path(batch, &opening.path, leaf, end.history_root)?;
        // An archive bootstraps only at a hard fork's start. The nodes on
        // the recent openings' paths keep them, and every later append,
        // openable from its tree; older nodes come with a fork carry.
        if policy == RetentionPolicy::Archive {
            super::history::put_path_nodes(batch, leaf, &opening.path)?;
        }
        let key = keys::chunk_id_key(opening.record.chunk.chunk_id);
        batch.put(
            Column::HistoricalChunks,
            key,
            borsh::to_vec(&opening.record)?,
        );
    }
    Ok(())
}
