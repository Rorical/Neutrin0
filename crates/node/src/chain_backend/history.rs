//! History proofs are finalized chunk receipts: every chunk Guest verifies the
//! previous chunk's receipt, so the latest one proves the chain from genesis.
//! Finality therefore needs no further proving; this module only prunes below
//! the finalized window and announces each new endpoint.

use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_types::history_proof::Checkpoint;
use neutrin0_network::{Topic, rpc::CheckpointAnnouncement, service::NetworkCommand};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use super::ChainBackend;

/// Finalized endpoint this node last pruned below and announced.
#[derive(Default)]
pub(super) struct HistoryRuntime {
    announced: AtomicU64,
    /// Finality advances whose pruning failed; each is retried at the next.
    prune_failures: AtomicU64,
}

impl HistoryRuntime {
    pub(super) fn prune_failures(&self) -> u64 {
        self.prune_failures.load(Ordering::Relaxed)
    }
}

/// Trie entries one state-collection slice visits under the engine lock.
const STATE_COLLECTION_SLICE: usize = 16_384;

/// Run the state collection pruning started, releasing the engine lock
/// between bounded slices so imports and voting interleave with it.
fn collect_state<DB: Database>(engine: &Mutex<Engine<DB>>)
where
    DB::Error: core::fmt::Display,
{
    loop {
        let slice = engine
            .lock()
            .expect("engine")
            .collect_state_slice(STATE_COLLECTION_SLICE);
        match slice {
            Ok(true) => return,
            Ok(false) => std::thread::yield_now(),
            Err(error) => {
                tracing::warn!(%error, "state collection deferred");
                return;
            }
        }
    }
}

/// Prune below a newly finalized window and describe its endpoint, once per
/// finalized count.
fn advance<DB: Database>(
    engine_lock: &Mutex<Engine<DB>>,
    history: &HistoryRuntime,
) -> Option<CheckpointAnnouncement>
where
    DB::Error: core::fmt::Display,
{
    let mut engine = engine_lock.lock().expect("engine");
    let count = engine.finalized_next_chunk_id();
    if count == 0 || history.announced.load(Ordering::Acquire) >= count {
        return None;
    }
    if let Err(error) = engine.prune_finalized_sources() {
        history.prune_failures.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%error, "history pruning deferred");
    }
    let chain = engine.store().history_domain().ok().flatten();
    let boundary = engine.canonical_boundary(count).ok();
    drop(engine);
    collect_state(engine_lock);
    let (chain, boundary) = (chain?.chain, boundary?);
    history.announced.fetch_max(count, Ordering::AcqRel);
    Some(CheckpointAnnouncement {
        chunk_count: count,
        checkpoint_hash: Checkpoint { chain, boundary }.hash(),
    })
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Configure source retention before following the chain.
    /// Switching a pruned database to archive requires rebuilding its history.
    pub fn set_retention_policy(
        &self,
        policy: neutrin0_consensus_engine::RetentionPolicy,
    ) -> Result<(), String> {
        self.with_engine_mut(|engine| engine.set_retention_policy(policy))
            .map_err(|error| error.to_string())
    }

    /// Pin the trusted chain binding and genesis programs this backend derives.
    pub fn initialize_history(&self) -> Result<(), String> {
        let (_, domain) = self.history_profile()?;
        self.with_engine_mut(|engine| engine.set_history_domain(domain))
            .map_err(|error| error.to_string())
    }

    /// Load the chain and independently derive the proof program identities.
    pub(crate) fn history_profile(
        &self,
    ) -> Result<
        (
            neutrin0_primitives::ChainSpec,
            neutrin0_consensus_types::history_proof::ProofDomain,
        ),
        String,
    > {
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let domain = self
            .proof_system
            .history_domain(&spec)
            .map_err(|error| error.to_string())?;
        Ok((spec, domain))
    }

    /// After finality advances, prune below the new window off the caller's
    /// path and announce the endpoint whose History proof this node now
    /// serves. A light node or a pending bootstrap does neither.
    pub(super) fn advance_history(&self) {
        if self.is_light()
            || self.bootstrap_pending()
            || tokio::runtime::Handle::try_current().is_err()
        {
            return;
        }
        let engine = Arc::clone(&self.engine);
        let history = Arc::clone(&self.history);
        let publisher = self.publisher_snapshot();
        self.spawn_supervised("history", false, async move {
            let Ok(Some(announcement)) =
                tokio::task::spawn_blocking(move || advance(&engine, &history)).await
            else {
                return;
            };
            if let (Some(publisher), Ok(data)) = (publisher, borsh::to_vec(&announcement)) {
                let _ = publisher
                    .send(NetworkCommand::Publish {
                        topic: Topic::Checkpoints,
                        data,
                    })
                    .await;
            }
        });
    }
}
