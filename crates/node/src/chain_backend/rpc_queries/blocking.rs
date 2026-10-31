//! Bound synchronous RPC reads and keep lock waits off async workers.

use std::sync::Arc;

use neutrin0_consensus_engine::Engine;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;

use super::ChainBackend;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(in crate::chain_backend) async fn rpc_blocking<R: Send + 'static>(
        &self,
        read: impl FnOnce() -> R + Send + 'static,
    ) -> R {
        let slot = Arc::clone(&self.query_slots)
            .acquire_owned()
            .await
            .expect("RPC query slots remain open while the backend exists");
        tokio::task::spawn_blocking(move || {
            // Cancellation drops the caller, but running work must retain its
            // slot until it returns so repeated deadlines cannot bypass the cap.
            let _slot = slot;
            read()
        })
        .await
        .expect("RPC read worker panicked")
    }

    pub(in crate::chain_backend) async fn rpc_engine<R: Send + 'static>(
        &self,
        read: impl FnOnce(&Engine<DB>) -> R + Send + 'static,
    ) -> R {
        let engine = Arc::clone(&self.engine);
        self.rpc_blocking(move || {
            let engine = engine.lock().expect("ChainBackend mutex poisoned");
            read(&engine)
        })
        .await
    }
}

#[cfg(test)]
mod tests;
