//! Keeping the transaction pool valid at the canonical head without stalling
//! anything else.
//!
//! Every admission validates against the current head, so the pool needs a
//! full pass only when the head or the runtime moves. That pass runs once
//! per head and runtime, holding neither the head-update fence nor the pool
//! while transactions execute; its verdicts apply only if the head is still
//! the one validated against, and otherwise the pass repeats at the new
//! head. Readers see the last validated pool.

use neutrin0_consensus_engine::Engine;
use neutrin0_mempool::Mempool;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ErasedBlockExecutor;
use neutrin0_storage::Database;
use neutrin0_trie::Trie;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Passes one run makes while the head keeps moving under it; the next head
/// change schedules another run.
const MAX_PASSES: usize = 3;

/// Shared copy of the engine's live state trie, reused while its root is
/// unchanged. Lock order: `engine`, then this.
#[derive(Default)]
pub(super) struct HeadState(Mutex<Option<Arc<Trie>>>);

/// The head state, one copy per root. The caller holds the engine lock.
pub(super) fn head_state_snapshot<DB: Database>(
    cache: &HeadState,
    engine: &Engine<DB>,
) -> Arc<Trie> {
    let mut cached = cache.0.lock().expect("head state");
    if let Some(state) = cached
        .as_ref()
        .filter(|state| state.root() == engine.state().root())
    {
        return Arc::clone(state);
    }
    let state = Arc::new(engine.state().clone());
    *cached = Some(Arc::clone(&state));
    drop(cached);
    state
}

/// Head and runtime the pool was last fully validated at, and whether a
/// background pass is running.
#[derive(Default)]
pub(super) struct PoolValidation {
    validated: Mutex<Option<(Hash, Hash)>>,
    running: AtomicBool,
}

/// What one pass needs, shareable with a blocking worker.
pub(super) struct PoolContext<DB: Database> {
    pub(super) engine: Arc<Mutex<Engine<DB>>>,
    pub(super) mempool: Arc<Mutex<Mempool>>,
    pub(super) head_updates: Arc<Mutex<()>>,
    pub(super) head_state: Arc<HeadState>,
    pub(super) validation: Arc<PoolValidation>,
    pub(super) executor: Arc<dyn ErasedBlockExecutor>,
}

/// The head and runtime the next block executes under.
fn target<DB: Database>(engine: &Engine<DB>) -> Option<(Hash, Hash)> {
    engine
        .head_height()
        .checked_add(1)
        .and_then(|height| engine.runtime_code_hash_for(height).ok())
        .or_else(|| engine.runtime_code_hash_for(engine.head_height()).ok())
        .map(|runtime| (engine.head_hash(), runtime))
}

impl<DB: Database> PoolContext<DB> {
    /// Bring the pool up to the current head and runtime unless it is
    /// already there, or the head moves under every pass.
    pub(super) fn validate(&self) {
        for _ in 0..MAX_PASSES {
            let snapshot = {
                let engine = self.engine.lock().expect("engine");
                target(&engine).map(|key| {
                    (
                        key,
                        engine.chain_spec().chain_id,
                        engine.chain_spec().genesis_gas_limit,
                        head_state_snapshot(&self.head_state, &engine),
                    )
                })
            };
            let Some((key, chain_id, gas_limit, state)) = snapshot else {
                return;
            };
            if *self.validation.validated.lock().expect("pool validation") == Some(key) {
                return;
            }
            let entries = self.mempool.lock().expect("mempool").validation_snapshot();
            let verdicts: Vec<_> = entries
                .into_iter()
                .filter_map(|(hash, bytes)| {
                    self.executor
                        .validate_tx(&bytes, chain_id, gas_limit, key.1, &state)
                        .ok()
                        .map(|validity| (hash, validity))
                })
                .collect();
            let _update = self.head_updates.lock().expect("head update");
            if target(&self.engine.lock().expect("engine")) != Some(key) {
                continue;
            }
            {
                let mut pool = self.mempool.lock().expect("mempool");
                pool.expire(crate::now_secs(), 15 * 60);
                pool.apply_validation(verdicts);
            }
            *self.validation.validated.lock().expect("pool validation") = Some(key);
            return;
        }
    }

    /// Validate on a blocking worker unless a pass is already running; that
    /// pass covers any head reached meanwhile. Without a runtime, validate
    /// here.
    pub(super) fn schedule(self)
    where
        DB: Send + 'static,
    {
        if self.validation.running.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.run();
            return;
        };
        runtime.spawn_blocking(move || self.run());
    }

    fn run(&self) {
        for _ in 0..MAX_PASSES {
            self.validate();
            self.validation.running.store(false, Ordering::Release);
            // A head published after the pass read its target but before the
            // flag dropped would otherwise wait for the next head change.
            let current = target(&self.engine.lock().expect("engine"));
            if current.is_none()
                || *self.validation.validated.lock().expect("pool validation") == current
                || self.validation.running.swap(true, Ordering::AcqRel)
            {
                return;
            }
        }
        // The head kept moving: release the flag so the next head change
        // schedules another run.
        self.validation.running.store(false, Ordering::Release);
    }
}
