//! The bounded private pool of proven evidence reports with their locally
//! authenticated history openings.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::Hash;
use neutrin0_storage::{Column, Database};

use super::ChainStore;
use crate::store::StoreError;

extern crate alloc;

/// Maximum pooled evidence reports, active and dormant together.
const MAX_POOLED_REPORTS: usize = 256;
/// Maximum stored bytes of pooled evidence reports, active and dormant together.
const MAX_POOLED_REPORT_BYTES: usize = 32 * 1024 * 1024;

/// A locally authenticated anchor remains available for dormant reports after bootstrap.
#[derive(BorshSerialize, BorshDeserialize)]
pub(super) struct StoredEvidenceReport {
    pub(super) report: neutrin0_consensus_types::evidence::EvidenceReport,
    pub(super) history_root: Hash,
}

/// Pooled entries a new report with a current opening may displace, in
/// eviction order. A dormant entry waits for a holder to refresh its path and
/// must not keep a usable report out of the pool: dormant liveness receipts go
/// first, a dormant safety receipt yields only to another safety report, and
/// the longest-dormant entry goes first within each class. A safety report
/// also displaces active liveness receipts last: anyone can prove those, so
/// they must never keep a safety admission out. Without a finalized boundary
/// nothing is dormant.
pub(super) fn displaceable_reports<E>(
    entries: &[(Vec<u8>, Vec<u8>)],
    incoming: neutrin0_consensus_types::evidence::SanctionKind,
    next_chunk: Option<u64>,
) -> Result<Vec<(Vec<u8>, usize)>, StoreError<E>> {
    let Some(next_chunk) = next_chunk else {
        return Ok(Vec::new());
    };
    let mut ranked = Vec::new();
    for (key, bytes) in entries {
        let stored: StoredEvidenceReport = borsh::from_slice(bytes)?;
        let history = &stored.report.history;
        let dormant = history.count != next_chunk;
        let safety = stored.report.artifact.statement.kind.is_safety();
        let class = match (safety, dormant) {
            (false, true) => 0,
            (true, true) if incoming.is_safety() => 1,
            (false, false) if incoming.is_safety() => 2,
            _ => continue,
        };
        ranked.push(((class, history.count), key.clone(), bytes.len()));
    }
    ranked.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(ranked
        .into_iter()
        .map(|(_, key, size)| (key, size))
        .collect())
}

/// Serialize-only borrowed twin of [`StoredEvidenceReport`] with an identical encoding.
#[derive(BorshSerialize)]
struct StoredEvidenceReportRef<'a> {
    report: &'a neutrin0_consensus_types::evidence::EvidenceReport,
    history_root: Hash,
}

fn evidence_report_root(
    report: &neutrin0_consensus_types::evidence::EvidenceReport,
) -> Option<Hash> {
    use neutrin0_consensus_types::history::{
        HISTORY_DEPTH, counted_history_root, history_leaf_hash, history_node_hash,
    };
    let path = &report.history;
    if path.index != report.artifact.statement.context.chunk_id
        || path.index >= path.count
        || path.siblings.len() != HISTORY_DEPTH
    {
        return None;
    }
    let leaf = neutrin0_consensus_types::evidence::commitment(&report.artifact.statement.context);
    let mut root = history_leaf_hash(Some(leaf));
    for (level, sibling) in path.siblings.iter().enumerate() {
        root = if (path.index >> level) & 1 == 0 {
            history_node_hash(level, root, *sibling)
        } else {
            history_node_hash(level, *sibling, root)
        };
    }
    Some(counted_history_root(path.count, root))
}

impl<DB: Database> ChainStore<DB> {
    /// Persist a verified receipt together with its authenticated current history path.
    /// Returns whether the receipt was newly pooled rather than already present.
    pub fn put_evidence_report(
        &mut self,
        report: &neutrin0_consensus_types::evidence::EvidenceReport,
    ) -> Result<bool, StoreError<DB::Error>> {
        use neutrin0_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES;
        let artifact = &report.artifact;
        let invalid = |message| {
            StoreError::Codec(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                message,
            ))
        };
        if artifact.proof_bytes.is_empty() || artifact.proof_bytes.len() > MAX_EVIDENCE_PROOF_BYTES
        {
            return Err(invalid("evidence receipt size"));
        }
        // The root exists exactly when the path has the canonical shape.
        let history_root =
            evidence_report_root(report).ok_or_else(|| invalid("evidence history path shape"))?;
        if let Some(state) = self.get_consensus_state()?
            && (report.history.count != state.boundary.next_chunk_id
                || history_root != state.boundary.history_root)
        {
            return Err(StoreError::Corrupt("evidence history path is not current"));
        }
        let id = artifact.statement_id();
        // Preserve the first verified receipt; a holder may refresh its dormant opening.
        if let Some(bytes) = self.get_raw(Column::EvidenceProofs, &id)? {
            let mut stored: StoredEvidenceReport = borsh::from_slice(&bytes)?;
            if report.history.count > stored.report.history.count {
                stored.report.history = report.history.clone();
                stored.history_root = history_root;
                self.put_raw(Column::EvidenceProofs, &id, &borsh::to_vec(&stored)?)?;
            }
            return Ok(false);
        }
        let bytes = borsh::to_vec(&StoredEvidenceReportRef {
            report,
            history_root,
        })?;
        let entries = self
            .db
            .iter_column(Column::EvidenceProofs)
            .map_err(StoreError::Database)?;
        let mut count = entries.len();
        let mut total: usize = entries.iter().map(|(_, value)| value.len()).sum();
        let fits = |count: usize, total: usize| {
            count < MAX_POOLED_REPORTS && total + bytes.len() <= MAX_POOLED_REPORT_BYTES
        };
        let mut batch = neutrin0_storage::Batch::new();
        if !fits(count, total) {
            let next_chunk = self
                .get_consensus_state()?
                .map(|state| state.boundary.next_chunk_id);
            for (key, size) in displaceable_reports(&entries, artifact.statement.kind, next_chunk)?
            {
                if fits(count, total) {
                    break;
                }
                batch.delete(Column::EvidenceProofs, key);
                count -= 1;
                total -= size;
            }
            if !fits(count, total) {
                return Err(invalid("evidence pool capacity"));
            }
        }
        batch.put(Column::EvidenceProofs, id, bytes);
        self.write_observed_batch(batch, false)?;
        Ok(true)
    }

    /// Stage a path refresh without replacing its already verified proof attachment.
    pub(in crate::store) fn put_evidence_report_batch(
        batch: &mut neutrin0_storage::Batch,
        report: &neutrin0_consensus_types::evidence::EvidenceReport,
    ) -> Result<(), StoreError<DB::Error>> {
        let history_root = evidence_report_root(report)
            .ok_or(StoreError::Corrupt("evidence history path shape"))?;
        batch.put(
            Column::EvidenceProofs,
            report.artifact.statement_id(),
            borsh::to_vec(&StoredEvidenceReportRef {
                report,
                history_root,
            })?,
        );
        Ok(())
    }

    /// Drop expired liveness receipts, receipts whose offence or safety
    /// identity finalized blocks already consumed, and receipts proven under
    /// programs none of `usable` names: no block can admit them any more, and
    /// the node proves the retained raw report again under the current
    /// programs. An empty `usable` drops nothing for its programs.
    /// Unfinalized execution is retained for re-admission after reorg.
    pub fn prune_evidence_artifacts(
        &mut self,
        finalized_height: u64,
        liveness_max_age: u64,
        usable: &[neutrin0_primitives::ExecutionPrograms],
    ) -> Result<(), StoreError<DB::Error>> {
        let mut batch = neutrin0_storage::Batch::new();
        // Liveness receipts expire with their window. Safety receipts have
        // no age window: they leave only when finalized blocks consumed
        // their offence or sanctioned their identity.
        self.drop_stale_evidence_batch(&mut batch, |artifact| {
            let expired = !artifact.statement.kind.is_safety()
                && finalized_height.saturating_sub(artifact.statement.context.end_height)
                    >= liveness_max_age;
            let superseded = !usable.is_empty()
                && !usable.iter().any(|programs| {
                    artifact.evidence_guest_vk_digest == programs.evidence
                        && artifact.membership.batch.fact_guest_vk_digest == programs.fact
                        && artifact.statement.block_guest_vk_digest == programs.block
                });
            expired || superseded
        })?;
        if batch.is_empty() {
            return Ok(());
        }
        self.write_observed_batch(batch, false)
    }

    /// Stage deletion of pooled receipts that are `expired` or whose offence or
    /// safety identity finalized blocks already consumed.
    pub(in crate::store) fn drop_stale_evidence_batch(
        &self,
        batch: &mut neutrin0_storage::Batch,
        expired: impl Fn(&neutrin0_consensus_types::evidence::EvidenceArtifact) -> bool,
    ) -> Result<(), StoreError<DB::Error>> {
        for artifact in self.evidence_artifacts()? {
            if expired(&artifact) || self.is_receipt_finalized(&artifact.statement)? {
                batch.delete(Column::EvidenceProofs, artifact.statement_id());
            }
        }
        Ok(())
    }

    /// Whether finalized blocks already consumed everything this receipt could
    /// admit: its exact offence, or for a safety receipt any safety sanction
    /// against the same identity.
    pub fn is_receipt_finalized(
        &self,
        statement: &neutrin0_consensus_types::evidence::EvidenceStatement,
    ) -> Result<bool, StoreError<DB::Error>> {
        use neutrin0_consensus_types::evidence::SanctionKind;
        Ok(self.is_offence_finalized(&statement.offence_id)?
            || (statement.kind == SanctionKind::Slash
                && self.is_identity_slashed(&statement.offender.pubkey)?))
    }

    /// Load the receipt view of pooled reports for identity and offence selection.
    pub fn evidence_artifacts(
        &self,
    ) -> Result<Vec<neutrin0_consensus_types::evidence::EvidenceArtifact>, StoreError<DB::Error>>
    {
        Ok(self
            .evidence_reports()?
            .into_iter()
            .map(|report| report.artifact)
            .collect())
    }

    /// Load complete reports, including paths, for restart recovery and re-admission.
    pub fn evidence_reports(
        &self,
    ) -> Result<Vec<neutrin0_consensus_types::evidence::EvidenceReport>, StoreError<DB::Error>>
    {
        Ok(self
            .stored_evidence_reports()?
            .into_iter()
            .map(|stored| stored.report)
            .collect())
    }

    /// Logical bytes and records of active and dormant locally authenticated
    /// report openings. Active means the current finalized root, not a promise
    /// that head-state policy or a block's gas budget admits the report now.
    /// This scans only the bounded 256-report, 32 MiB pool.
    ///
    /// # Errors
    /// Reports database failures, malformed reports or an exceeded pool bound.
    pub fn evidence_pool_metrics(
        &self,
    ) -> Result<[crate::store::RetainedInventory; 2], StoreError<DB::Error>> {
        let boundary = self.get_consensus_state()?.map(|state| state.boundary);
        let mut result = [crate::store::RetainedInventory::default(); 2];
        for stored in self.stored_evidence_reports()? {
            let active = boundary.is_some_and(|boundary| {
                stored.report.history.count == boundary.next_chunk_id
                    && stored.history_root == boundary.history_root
            });
            let inventory = &mut result[usize::from(!active)];
            inventory.records += 1;
            inventory.bytes += u64::try_from(borsh::object_length(&stored)? + 32)
                .map_err(|_| StoreError::Corrupt("evidence metric bytes"))?;
        }
        Ok(result)
    }

    fn stored_evidence_reports(&self) -> Result<Vec<StoredEvidenceReport>, StoreError<DB::Error>> {
        let entries = self
            .db
            .iter_column(Column::EvidenceProofs)
            .map_err(StoreError::Database)?;
        let total: usize = entries.iter().map(|(_, value)| value.len()).sum();
        if entries.len() > MAX_POOLED_REPORTS || total > MAX_POOLED_REPORT_BYTES {
            return Err(StoreError::Corrupt("evidence pool capacity"));
        }
        entries
            .into_iter()
            .map(|(key, bytes)| {
                let stored: StoredEvidenceReport = borsh::from_slice(&bytes)?;
                if key.as_slice() != stored.report.artifact.statement_id() {
                    return Err(StoreError::Corrupt("evidence key mismatch"));
                }
                if evidence_report_root(&stored.report) != Some(stored.history_root) {
                    return Err(StoreError::Corrupt("pooled evidence history path mismatch"));
                }
                Ok(stored)
            })
            .collect()
    }

    /// Check active openings against the current boundary and dormant ones against
    /// the locally authenticated root saved before a snapshot jump.
    pub(crate) fn validate_evidence_reports(&self) -> Result<(), StoreError<DB::Error>> {
        let reports = self.stored_evidence_reports()?;
        if reports.is_empty() {
            return Ok(());
        }
        let count = self
            .get_latest_finalized_chunk_id()?
            .and_then(|id| id.checked_add(1))
            .ok_or(StoreError::Corrupt(
                "evidence pool has no finalized boundary",
            ))?;
        let root = self
            .history_frontier(count)?
            .root()
            .ok_or(StoreError::Corrupt("invalid evidence history frontier"))?;
        for stored in reports {
            if stored.report.history.count > count
                || (stored.report.history.count == count && stored.history_root != root)
            {
                return Err(StoreError::Corrupt("pooled evidence history path mismatch"));
            }
        }
        Ok(())
    }

    /// Rebase pooled paths in the same durable batch as the finalized history append.
    pub(in crate::store) fn advance_evidence_reports_batch(
        &self,
        batch: &mut neutrin0_storage::Batch,
        frontier: &neutrin0_consensus_types::history::HistoryFrontier,
        appended_leaf: Hash,
    ) -> Result<(), StoreError<DB::Error>> {
        for mut report in self.evidence_reports()? {
            if report.history.count < frontier.count {
                // A snapshot can skip append material. Keep the verified offence
                // and its old authenticated anchor until its holder refreshes it.
                continue;
            }
            let leaf =
                neutrin0_consensus_types::evidence::commitment(&report.artifact.statement.context);
            report
                .history
                .advance(leaf, frontier, appended_leaf)
                .ok_or(StoreError::Corrupt("pooled evidence history path mismatch"))?;
            Self::put_evidence_report_batch(batch, &report)?;
        }
        Ok(())
    }
}
