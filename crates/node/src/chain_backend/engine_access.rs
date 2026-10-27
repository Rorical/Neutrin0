//! Locked access to the wrapped engine and the guards every mutation passes.

use std::sync::Arc;

use neutrin0_consensus_engine::{Engine, ImportError};
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

use super::{ChainBackend, cloned, pool_validation, transactions};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Diagnostic: does the engine's in-memory state trie agree
    /// with the scalar `head_state_root`?
    ///
    /// Producers maintain this invariant by construction. Importers
    /// maintain it only when a block executor is installed
    /// through the dry-run executor: its post-state trie
    /// is committed in lockstep with the head pointer update.
    /// Executor-less imports leave the trie stale relative to the
    /// committed scalar, which the diagnostic surfaces.
    ///
    /// Used by integration tests to assert the invariant after a
    /// gossip-driven import.
    #[must_use]
    pub fn engine_state_invariant_holds(&self) -> bool {
        self.with_engine(|e| e.state().root() == e.head_state_root())
    }

    /// Explicit trigger for reorg materialisation.
    ///
    /// Imports (block + proof) already call
    /// `Engine::materialise_to_fork_choice_head` automatically;
    /// integration tests use this proxy after mutating the fork-choice
    /// DAG outside an import (for example by injecting votes through
    /// [`Engine::fork_choice_mut_for_test`]).
    ///
    /// Returns `true` when the materialised head actually moved.
    /// Returns `false` when the fork-choice head already matches
    /// the materialised head or when no executor is installed.
    ///
    /// # Errors
    ///
    /// Surfaces any [`SyncBackendError`] that the engine's
    /// materialise step produces (executor trap, replay
    /// mismatch, attempt to reorg past finalised history).
    pub fn try_materialise_to_fork_choice_head(&self) -> Result<bool, SyncBackendError> {
        let executor = self.replay_executor_snapshot();
        self.with_live_engine_mut(|e| {
            e.materialise_to_fork_choice_head(executor.as_deref())
                .map_err(Self::map_import_err)
        })
    }

    pub(super) fn block_executor_snapshot(&self) -> Option<Arc<dyn ErasedBlockExecutor>> {
        cloned(&self.block_executor)
    }

    /// Shared snapshot of the engine's live state trie. Readers at an unchanged
    /// root reuse one copy instead of cloning the whole trie per call. The
    /// caller holds the engine lock, which is always taken before this cache.
    pub(super) fn head_state_snapshot(
        &self,
        engine: &Engine<DB>,
    ) -> Arc<neutrin0_trie::Trie<neutrin0_trie::Poseidon2Hasher>> {
        pool_validation::head_state_snapshot(&self.head_state, engine)
    }

    /// Header import is a full-node path: refuse while checkpoint state
    /// downloads, then on proof-only nodes.
    pub(super) fn ensure_full_import(&self) -> Result<(), SyncBackendError> {
        self.reject_bootstrapping()?;
        self.reject_light()
    }

    /// Test-only mutable engine accessor. `#[doc(hidden)]` because
    /// real callers should always go through the typed import /
    /// production paths; this exists only so cross-crate
    /// integration tests can drive low-level fork-choice
    /// scenarios (e.g. inject votes via
    /// [`Engine::fork_choice_mut_for_test`]) without bypassing
    /// the backend's mutex.
    #[doc(hidden)]
    pub fn with_engine_mut_for_test<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut neutrin0_consensus_engine::Engine<DB>) -> R,
    {
        self.with_engine_mut(f)
    }

    pub(super) fn with_engine<R>(&self, f: impl FnOnce(&Engine<DB>) -> R) -> R {
        let guard = self.engine.lock().expect("ChainBackend mutex poisoned");
        f(&guard)
    }

    pub(super) fn with_engine_mut<R>(&self, f: impl FnOnce(&mut Engine<DB>) -> R) -> R {
        let update = self
            .head_updates
            .lock()
            .expect("ChainBackend head update poisoned");
        let mut guard = self.engine.lock().expect("ChainBackend mutex poisoned");
        let previous = guard.head_hash();
        let result = f(&mut guard);
        let changed = guard.head_hash() != previous;
        let branch_changes = changed.then(|| transactions::branch_changes(&guard, previous));
        drop(guard);
        if let Some((orphaned, mined)) = branch_changes {
            {
                let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
                for identifier in mined {
                    let _ = pool.remove(&identifier);
                }
            }
            for bytes in orphaned {
                let _ = self.admit_transaction(bytes, None);
            }
            drop(update);
            // The rest of the pool is revalidated once per head, off the
            // head-update fence; readers see the last validated pool.
            self.schedule_mempool_revalidation();
        }
        result
    }

    /// The engine lock also orders bootstrap admission, so the optimistic checks
    /// at async entry points cannot authorize mutations after fetching begins.
    pub(super) fn with_live_engine_mut<R>(
        &self,
        f: impl FnOnce(&mut Engine<DB>) -> Result<R, SyncBackendError>,
    ) -> Result<R, SyncBackendError> {
        self.with_engine_mut(|engine| {
            self.reject_bootstrapping()?;
            f(engine)
        })
    }

    /// Refuse a mutation while checkpoint state is downloading.
    fn reject_bootstrapping(&self) -> Result<(), SyncBackendError> {
        if self.bootstrap_pending() {
            return Err(SyncBackendError::NotAvailable(
                "checkpoint state is downloading".into(),
            ));
        }
        Ok(())
    }

    /// Refuse an execution-state operation on a proof-only node.
    pub(super) fn reject_light(&self) -> Result<(), SyncBackendError> {
        if self.is_light() {
            return Err(SyncBackendError::NotAvailable("proof-only node".into()));
        }
        Ok(())
    }

    pub(super) fn map_import_err(err: ImportError<DB::Error>) -> SyncBackendError {
        match err {
            ImportError::Store(e) => SyncBackendError::Storage(e.to_string()),
            ImportError::HeightMismatch { .. }
            | ImportError::ParentMismatch { .. }
            | ImportError::MissingParentHeader { .. }
            | ImportError::ReorgPastCertified { .. }
            | ImportError::UnknownBlock(_) => SyncBackendError::ChainBehind(err.to_string()),
            // The block's chunk context (programs, history root or the previous
            // chunk's participation) is not finalized here yet: retry later.
            lagging if lagging.awaits_local_finality() => {
                SyncBackendError::ChainBehind(lagging.to_string())
            }
            // The slot has not started here; a lagging local clock sees honest
            // blocks this way, so the block is unusable now but not invalid.
            early @ ImportError::FutureSlot { .. } => {
                SyncBackendError::NotAvailable(early.to_string())
            }
            // This node can neither execute nor follow: a local
            // configuration fault, not a verdict on the block.
            local @ ImportError::ExecutorRequired => {
                SyncBackendError::NotAvailable(local.to_string())
            }
            // The candidate is further ahead than the bounded pending chain
            // allows while this node's finality lags; not a verdict either.
            bound
            @ (ImportError::PendingChainBound { .. } | ImportError::CandidateBound { .. }) => {
                SyncBackendError::NotAvailable(bound.to_string())
            }
            // The proposer signed both candidates; the double proposal is
            // recorded before import, and the relaying peer may be honest.
            twin @ ImportError::SlotAlreadyProposed { .. } => {
                SyncBackendError::NotAvailable(twin.to_string())
            }
            // The certificate names a receipt this node has not received yet.
            missing @ ImportError::MissingBlockReceipt { .. } => {
                SyncBackendError::NotAvailable(missing.to_string())
            }
            // Judged against a successor context this node only projected,
            // or contradicted by execution while the writes reproduce the
            // root that following nodes check: neither is a verdict that may
            // penalize the honest peer relaying it.
            unconfirmed
            @ (ImportError::ProjectedContext(_) | ImportError::ExecutionDiverges(_)) => {
                SyncBackendError::NotAvailable(unconfirmed.to_string())
            }
            other => SyncBackendError::Rejected(other.to_string()),
        }
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Clone + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Clone the underlying database. Available only for cloneable
    /// backends (such as [`neutrin0_storage::MemoryDatabase`]); the
    /// RocksDB backend deliberately is not `Clone` because file
    /// handles cannot be duplicated.
    ///
    /// Used by restart-recovery integration tests to simulate a
    /// process restart: snapshot the DB, drop the backend, build a
    /// fresh backend on the snapshot, and assert the new backend
    /// observes everything the old one persisted.
    #[must_use]
    pub fn snapshot_database(&self) -> DB {
        self.with_engine(|e| e.store().db().clone())
    }
}
