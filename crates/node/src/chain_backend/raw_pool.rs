//! Durable raw-report pool (`Column::SlashingPool`): the FIFO key index,
//! admission by accused identity and the locked pool/engine access.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_types::SlashingEvidence;
use neutrin0_primitives::{BlsPublicKey, Hash};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::{Batch, Column, Database};
use tracing::warn;

use super::{ChainBackend, SLASHING_POOL_MAX_ENTRIES, reporter_retention};

/// Raw reports pooled against one accused identity. It is sanctioned once
/// whatever it signed, so a flood of its own offences cannot evict reports
/// against other validators.
pub(super) const MAX_REPORTS_PER_IDENTITY: usize = 4;

/// FIFO key index of the durable raw-report pool in
/// [`Column::SlashingPool`], with dedup-by-content and a hard
/// `SLASHING_POOL_MAX_ENTRIES` cap. Two detectors that observe the same
/// equivocation produce byte-identical evidence, so the BLAKE3 of the
/// borsh encoding is a safe canonical key.
///
/// Report bodies stay on disk: the evidence worker proves them from the
/// column, so memory holds only membership and insertion order. Engine
/// paths such as retention also delete rows, so every access first
/// reconciles the index with the column (see [`Self::reconcile`]).
#[derive(Default)]
pub(super) struct SlashingPool {
    /// Keys in insertion order, oldest first.
    order: VecDeque<Hash>,
    pub(super) seen: BTreeSet<Hash>,
    /// The identity each report this pool admitted accuses, when resolved.
    /// Rows another writer added stay unattributed.
    accused: BTreeMap<Hash, BlsPublicKey>,
    /// Durable `(records, removals)` raw-report counters observed when the
    /// index last mirrored the column. Another writer changes at least one.
    pub(super) synced: Option<(u64, u64)>,
}

impl SlashingPool {
    fn len(&self) -> usize {
        self.order.len()
    }

    /// Oldest key, which a new insertion evicts once the pool is full.
    pub(super) fn eviction_candidate(&self) -> Option<Hash> {
        if self.order.len() < SLASHING_POOL_MAX_ENTRIES {
            return None;
        }
        self.order.front().copied()
    }

    /// Whether `identity` already has its share of pooled reports.
    pub(super) fn identity_full(&self, identity: &BlsPublicKey) -> bool {
        self.accused
            .values()
            .filter(|accused| *accused == identity)
            .count()
            >= MAX_REPORTS_PER_IDENTITY
    }

    /// Append a key just persisted with the identity it accuses, dropping
    /// keys beyond the cap oldest first; an insertion deletes the evicted
    /// row in the same batch.
    pub(super) fn push_accusing(&mut self, key: Hash, accused: Option<BlsPublicKey>) {
        if let Some(accused) = accused {
            self.accused.insert(key, accused);
        }
        self.push(key);
    }

    /// Append a key just persisted, dropping keys beyond the cap oldest
    /// first; an insertion deletes the evicted row in the same batch.
    pub(super) fn push(&mut self, key: Hash) {
        if self.seen.insert(key) {
            self.order.push_back(key);
        }
        while self.order.len() > SLASHING_POOL_MAX_ENTRIES {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            self.seen.remove(&evicted);
            self.accused.remove(&evicted);
        }
    }

    /// Remove up to `max` keys in FIFO order.
    fn drain(&mut self, max: usize) -> Vec<Hash> {
        let take = max.min(self.order.len());
        let drained: Vec<Hash> = self.order.drain(..take).collect();
        for key in &drained {
            self.seen.remove(key);
            self.accused.remove(key);
        }
        drained
    }

    /// Forget keys whose rows another path deleted.
    pub(super) fn forget(&mut self, removed: &[Hash]) {
        for key in removed {
            self.seen.remove(key);
            self.accused.remove(key);
        }
        self.order.retain(|key| !removed.contains(key));
    }

    /// The column's durable `(records, removals)` raw-report counters.
    fn disk_marker<DB: Database>(engine: &mut Engine<DB>) -> Option<(u64, u64)> {
        engine
            .store_mut()
            .reporter_storage_stats()
            .ok()
            .map(|stats| (stats.raw_reports.records, stats.raw_report_removals))
    }

    /// Mirror the column when another writer changed it since the last
    /// sync: keys whose rows are gone are dropped, rows not yet indexed
    /// are appended in key order, and the cap trims memory oldest first.
    /// The counters are maintained atomically with every observed write,
    /// so an unchanged column costs one metadata read.
    fn reconcile<DB: Database>(&mut self, engine: &mut Engine<DB>)
    where
        DB::Error: core::fmt::Display,
    {
        let marker = Self::disk_marker(engine);
        if marker.is_some() && marker == self.synced {
            return;
        }
        let rows = match engine.store().db().iter_column(Column::SlashingPool) {
            Ok(rows) => rows,
            Err(error) => {
                warn!(%error, "raw evidence pool unreadable; keeping the in-memory index");
                self.synced = None;
                return;
            }
        };
        let on_disk: BTreeSet<Hash> = rows
            .into_iter()
            .filter_map(|(key, _)| Hash::try_from(key.as_slice()).ok())
            .collect();
        self.order.retain(|key| on_disk.contains(key));
        self.seen.retain(|key| on_disk.contains(key));
        self.accused.retain(|key, _| on_disk.contains(key));
        for key in on_disk {
            self.push(key);
        }
        self.synced = marker;
    }

    /// Record that the index mirrors the column after this pool's own
    /// writes. An index already out of sync stays marked for reconciliation.
    fn observe<DB: Database>(&mut self, engine: &mut Engine<DB>) {
        if self.synced.is_some() {
            self.synced = Self::disk_marker(engine);
        }
    }
}

/// The identity `evidence` accuses, from its source chunk's committee, or
/// `None` when this node cannot resolve it.
pub(super) fn accused_identity<DB: Database>(
    engine: &Engine<DB>,
    evidence: &SlashingEvidence,
) -> Option<neutrin0_primitives::BlsPublicKey> {
    let source =
        neutrin0_prover_chunk::history::evidence_chunk_id(engine.chain_spec(), evidence).ok()?;
    if source == engine.finalized_next_chunk_id() {
        return engine
            .active_validator_set()
            .get(evidence.offender_index() as usize)
            .map(|validator| validator.pubkey);
    }
    engine
        .store()
        .historical_chunk(source)
        .ok()
        .flatten()
        .and_then(|record| {
            record
                .validators
                .get(evidence.offender_index() as usize)
                .map(|validator| validator.pubkey)
        })
}

/// Whether this node pools a raw report. Under reporter retention its accused
/// identity must be resolved, still tracked and not already sanctioned; other
/// roles refuse only a report against a sanctioned identity.
pub(super) fn raw_report_admissible<DB: Database>(
    engine: &Engine<DB>,
    evidence: &SlashingEvidence,
) -> bool {
    // Reporters must resolve the accused identity; other roles relay a
    // report they cannot resolve, but never one against a tombstoned identity,
    // so reports retention released are not pooled and gossiped again.
    let reporter = reporter_retention(engine);
    let Some(accused) = accused_identity(engine, evidence) else {
        return !reporter;
    };
    // An unreadable tombstone fails closed for reporters and open for relays.
    if engine
        .store()
        .is_identity_slashed(&accused)
        .unwrap_or(reporter)
    {
        return false;
    }
    !reporter
        || engine
            .store()
            .reporter_tracked_validators()
            .is_ok_and(|identities| identities.iter().any(|(pubkey, _)| *pubkey == accused))
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Run `f` on the raw-report index and the engine, holding both locks
    /// in the file-wide `slashing_pool → engine` order. The index first
    /// adopts any change other engine paths (retention, reporter cleanup)
    /// made to [`Column::SlashingPool`], so membership, cap and eviction
    /// decisions follow the durable pool; afterwards it records the
    /// column state its own writes produced.
    pub(super) fn with_raw_pool<R>(
        &self,
        f: impl FnOnce(&mut SlashingPool, &mut Engine<DB>) -> R,
    ) -> R {
        let mut guard = self
            .slashing_pool
            .lock()
            .expect("ChainBackend slashing_pool poisoned");
        let pool: &mut SlashingPool = &mut guard;
        let result = self.with_engine_mut(|engine| {
            pool.reconcile(engine);
            let result = f(pool, engine);
            pool.observe(engine);
            result
        });
        drop(guard);
        result
    }

    /// Number of distinct slashing-evidence items currently pooled.
    #[must_use]
    pub fn slashing_pool_len(&self) -> usize {
        self.with_raw_pool(|pool, _| pool.len())
    }

    /// Drain up to `max` pooled slashing evidence items in FIFO
    /// insertion order, removing them from [`Column::SlashingPool`].
    /// The evidence worker proves raw reports straight from the
    /// column; this explicit drain serves tests.
    ///
    /// Bodies are read from disk; the in-memory index holds only
    /// keys. A failed delete is logged and leaves the index marked
    /// for reconciliation, so rows still on disk are indexed again.
    pub fn drain_slashing_pool(&self, max: usize) -> Vec<SlashingEvidence> {
        self.with_raw_pool(|pool, engine| {
            let keys = pool.drain(max);
            if keys.is_empty() {
                return Vec::new();
            }
            let mut drained = Vec::with_capacity(keys.len());
            let mut batch = Batch::new();
            for key in keys {
                match engine.store().db().get(Column::SlashingPool, &key) {
                    Ok(Some(bytes)) => match borsh::from_slice::<SlashingEvidence>(&bytes) {
                        Ok(evidence) => drained.push(evidence),
                        Err(error) => warn!(%error, ?key, "dropping undecodable raw evidence"),
                    },
                    Ok(None) => {}
                    Err(error) => warn!(%error, ?key, "failed to read drained slashing evidence"),
                }
                batch.delete(Column::SlashingPool, key);
            }
            if let Err(error) = engine.store_mut().write_observed_batch(batch, false) {
                warn!(%error, "failed to delete drained slashing evidence");
                pool.synced = None;
            }
            drained
        })
    }
}
