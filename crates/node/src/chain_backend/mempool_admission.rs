//! Transaction admission into the bounded mempool and its revalidation.

use std::sync::{Arc, Mutex};

use neutrin0_consensus_engine::Engine;
use neutrin0_mempool::{InsertError, Mempool};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_runtime_abi::{TxValidationCode, TxValidity};
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;
use tracing::debug;

use super::{ChainBackend, pool_validation};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Submit a peer-supplied transaction into the local mempool.
    ///
    /// Runs the installed dynamic-runtime executor's
    /// [`BlockExecutor::validate_tx`](neutrin0_proof_system::BlockExecutor::validate_tx)
    /// against a snapshot of the engine's current state trie. The
    /// runtime returns a canonical [`TxValidity`] result; on
    /// [`TxValidationCode::Valid`] the bytes enter the mempool with
    /// the runtime-supplied priority, otherwise the call surfaces
    /// [`InsertError::RejectedByValidator`].
    ///
    /// Without an installed executor the call rejects every
    /// submission as `RejectedByValidator`; the node binary installs
    /// one at startup, but tests that exercise gossip without a
    /// running runtime intentionally leave it unset.
    pub fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, InsertError> {
        self.submit_transaction_with_runtime(bytes)
            .map(|(hash, _)| hash)
    }

    pub(super) fn submit_transaction_with_runtime(
        &self,
        bytes: Vec<u8>,
    ) -> Result<(Hash, Hash), InsertError> {
        let result = self
            .admission()
            .admit(bytes, None)
            .map_err(|(error, _)| error);
        self.metrics
            .execution
            .admission(&result.map(|(hash, _)| hash));
        result
    }

    /// Admit on the blocking pool while holding one of the admission slots.
    /// Admission runs WASM, so it never runs on an async worker; a full set
    /// of slots refuses at once rather than queueing behind it.
    pub(super) async fn admit_bounded(
        &self,
        bytes: Vec<u8>,
        expected_runtime: Option<Hash>,
    ) -> AdmissionResult {
        let Ok(slot) = Arc::clone(&self.admission_slots).try_acquire_owned() else {
            return Err((InsertError::CapacityExceeded, None));
        };
        let admission = self.admission();
        let result = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            admission.admit(bytes, expected_runtime)
        })
        .await
        .unwrap_or(Err((InsertError::RejectedByValidator, None)));
        self.metrics
            .execution
            .admission(&result.map(|(hash, _)| hash).map_err(|(error, _)| error));
        result
    }

    pub(super) async fn admit_peer_transaction(
        &self,
        bytes: Vec<u8>,
        runtime: Option<Hash>,
    ) -> Result<(), SyncBackendError> {
        if self.is_light() || self.bootstrap_pending() {
            return Err(SyncBackendError::NotAvailable(
                "transaction admission unavailable".into(),
            ));
        }
        let result = self.admit_bounded(bytes, runtime).await;
        result.map(|_| ()).map_err(|(error, code)| {
            // Bytes this runtime cannot decode or authenticate are the
            // sender's fault only under the runtime the sender named.
            if runtime.is_some()
                && matches!(
                    code,
                    Some(TxValidationCode::Malformed | TxValidationCode::BadSignature)
                )
            {
                SyncBackendError::Rejected(error.to_string())
            } else {
                SyncBackendError::NotAvailable(error.to_string())
            }
        })
    }

    /// Admit `bytes` while the caller already holds `head_updates`.
    pub(super) fn admit_transaction(
        &self,
        bytes: Vec<u8>,
        expected_runtime: Option<Hash>,
    ) -> AdmissionResult {
        self.admission().admit_held(bytes, expected_runtime)
    }

    fn admission(&self) -> Admission<DB> {
        Admission {
            engine: Arc::clone(&self.engine),
            mempool: Arc::clone(&self.mempool),
            head_updates: Arc::clone(&self.head_updates),
            head_state: Arc::clone(&self.head_state),
            executor: self.block_executor_snapshot(),
        }
    }

    fn pool_context(&self) -> Option<pool_validation::PoolContext<DB>> {
        Some(pool_validation::PoolContext {
            engine: Arc::clone(&self.engine),
            mempool: Arc::clone(&self.mempool),
            head_updates: Arc::clone(&self.head_updates),
            head_state: Arc::clone(&self.head_state),
            validation: Arc::clone(&self.pool_validation),
            executor: self.block_executor_snapshot()?,
        })
    }

    /// Bring the pool up to the current head and runtime before selecting
    /// from it. The caller must not hold `head_updates`.
    pub(super) fn revalidate_mempool(&self) {
        if let Some(context) = self.pool_context() {
            context.validate();
        }
    }

    /// Revalidate after a head change or execution-program switch on a
    /// blocking worker. The caller must not hold `head_updates`.
    pub(super) fn schedule_mempool_revalidation(&self) {
        if let Some(context) = self.pool_context() {
            context.schedule();
        }
    }

    /// Local pending sequence from the last validated pool.
    pub fn pending_nonce(&self, account: Hash, state_nonce: u64) -> u64 {
        self.mempool
            .lock()
            .expect("ChainBackend mempool poisoned")
            .pending_nonce(account, state_nonce)
    }

    /// Number of transactions currently buffered, for metrics and RPC.
    pub fn mempool_len(&self) -> usize {
        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        pool.expire(crate::now_secs(), 15 * 60);
        pool.len()
    }
}

type AdmissionResult = Result<(Hash, Hash), (InsertError, Option<TxValidationCode>)>;

/// What one admission needs, shareable with a blocking worker.
pub(super) struct Admission<DB: Database> {
    engine: Arc<Mutex<Engine<DB>>>,
    mempool: Arc<Mutex<Mempool>>,
    head_updates: Arc<Mutex<()>>,
    head_state: Arc<pool_validation::HeadState>,
    executor: Option<Arc<dyn ErasedBlockExecutor>>,
}

impl<DB: Database> Admission<DB> {
    /// Admit `bytes` under the head-update fence, so no head publication
    /// lands between validation and insertion.
    fn admit(&self, bytes: Vec<u8>, expected_runtime: Option<Hash>) -> AdmissionResult {
        let _update = self
            .head_updates
            .lock()
            .expect("ChainBackend head update poisoned");
        self.admit_held(bytes, expected_runtime)
    }

    /// [`Self::admit`] for a caller that holds the fence.
    fn admit_held(&self, bytes: Vec<u8>, expected_runtime: Option<Hash>) -> AdmissionResult {
        // Impossible-to-store bodies and exact admitted duplicates need no
        // state snapshot or WASM work. Expiry is checked without renewing age.
        {
            let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
            pool.expire(crate::now_secs(), 15 * 60);
            if bytes.len() > pool.capacity_bytes() {
                return Err((InsertError::TooLarge, None));
            }
            if pool.contains(&neutrin0_primitives::blake3_256(&bytes)) {
                return Err((InsertError::Duplicate, None));
            }
        }
        // Capture a consistent runtime/state under the engine mutex, then
        // release it before execution or pool locking to preserve the
        // engine/pool lock order.
        let (chain_id, gas_limit, runtime_code_hash, state_snapshot) = {
            let e = self.engine.lock().expect("ChainBackend mutex poisoned");
            (
                e.chain_spec().chain_id,
                e.chain_spec().genesis_gas_limit,
                e.head_height()
                    .checked_add(1)
                    .and_then(|height| e.runtime_code_hash_for(height).ok())
                    .or_else(|| e.runtime_code_hash_for(e.head_height()).ok()),
                pool_validation::head_state_snapshot(&self.head_state, &e),
            )
        };
        let (Some(executor), Some(runtime_code_hash)) = (&self.executor, runtime_code_hash) else {
            debug!("submit_transaction: no executor or runtime resolvable; rejecting");
            return Err((InsertError::RejectedByValidator, None));
        };

        if expected_runtime.is_some_and(|expected| expected != runtime_code_hash) {
            return Err((InsertError::RejectedByValidator, None));
        }

        // Run admission. Host trap / codec failures degrade to
        // `RejectedByValidator` so a misbehaving runtime never poisons
        // the mempool; the runtime owns the soft-reject codes
        // (BadSignature / NonceMismatch / ...).
        let validity = match executor.validate_tx(
            &bytes,
            chain_id,
            gas_limit,
            runtime_code_hash,
            &state_snapshot,
        ) {
            Ok(v) => v,
            Err(err) => {
                debug!(%err, "validate_tx executor trap; rejecting tx");
                TxValidity::invalid(TxValidationCode::StateReadFailed)
            }
        };

        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        pool.expire(crate::now_secs(), 15 * 60);
        if validity.is_valid() {
            pool.insert_admitted(bytes, validity)
                .map(|hash| (hash, runtime_code_hash))
                .map_err(|error| (error, None))
        } else {
            Err((InsertError::RejectedByValidator, Some(validity.code)))
        }
    }
}
