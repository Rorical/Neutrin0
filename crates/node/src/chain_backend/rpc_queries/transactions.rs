//! RPC transaction submission and canonical or pending transaction lookups.

use neutrin0_mempool::InsertError;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_rpc::{QueryError, SubmitError};
use neutrin0_storage::Database;

use super::{ChainBackend, storage_error};
use std::sync::Arc;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) async fn rpc_submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, SubmitError> {
        if self.is_light() {
            return Err(SubmitError::Rejected {
                reason: "proof-only node has no transaction execution state".into(),
            });
        }
        let gossip = bytes.clone();
        let (hash, runtime) = self
            .admit_bounded(bytes, None)
            .await
            .map_err(|(error, _)| match error {
                InsertError::Duplicate => SubmitError::Duplicate,
                InsertError::CapacityExceeded | InsertError::AccountLimit => SubmitError::Full,
                InsertError::ZeroFee => SubmitError::Rejected {
                    reason: "transaction fee cap must be positive".into(),
                },
                InsertError::TooLarge => SubmitError::Rejected {
                    reason: "transaction exceeds mempool entry size limit".to_owned(),
                },
                InsertError::ReplacementUnderpriced => SubmitError::Rejected {
                    reason: "replacement requires a 10% increase in both fee and tip caps".into(),
                },
                InsertError::RejectedByValidator => SubmitError::Rejected {
                    reason: "runtime admission check rejected transaction".to_owned(),
                },
            })?;
        if gossip.len().saturating_add(36)
            <= neutrin0_network::Topic::Transactions.max_transmit_size()
        {
            let announcement = neutrin0_network::rpc::TransactionAnnouncement {
                runtime,
                transaction: neutrin0_primitives::BoundedBytes::new(gossip)
                    .expect("gossip body fits"),
            };
            if let Ok(data) = borsh::to_vec(&announcement) {
                self.publish_encoded(neutrin0_network::Topic::Transactions, data)
                    .await;
            }
        }
        Ok(hash)
    }

    pub(super) async fn rpc_execution_transaction(
        &self,
        identifier: Hash,
    ) -> Result<Option<(Hash, u32)>, QueryError> {
        let found = self
            .rpc_engine(move |engine| {
                let found = engine
                    .store()
                    .execution_transaction(&identifier)
                    .map_err(storage_error)?;
                if found.is_none() {
                    // Deleted locators cannot establish that an identifier never
                    // appeared in canonical history. Report the provider's actual
                    // retention horizon instead of returning authenticated absence.
                    let retention = engine.retention_info().map_err(storage_error)?;
                    if retention.pruned_before_chunk > 0 {
                        return Err(QueryError::Pruned {
                            retained_from_chunk: retention.pruned_before_chunk,
                            retained_from_height: retention.first_retained_height,
                        });
                    }
                }
                Ok(found)
            })
            .await?;
        if let Some((hash, index)) = found {
            let block = self
                .read_block_async(hash)
                .await?
                .ok_or(QueryError::BlockNotFound)?;
            if !block
                .body
                .artifacts
                .transaction_ids
                .contains(&(index, identifier))
            {
                return Err(storage_error(
                    "transaction locator does not match the authenticated execution artifacts",
                ));
            }
        }
        Ok(found)
    }

    pub(super) async fn rpc_pending_sequence(
        &self,
        account: Hash,
        state_nonce: u64,
        at: Hash,
    ) -> Result<u64, QueryError> {
        let updates = Arc::clone(&self.head_updates);
        let engine = Arc::clone(&self.engine);
        let mempool = Arc::clone(&self.mempool);
        self.rpc_blocking(move || {
            let _update = updates.lock().expect("ChainBackend head update poisoned");
            if engine
                .lock()
                .expect("ChainBackend mutex poisoned")
                .head_hash()
                != at
            {
                return Err(storage_error(
                    "canonical head changed during pending nonce query; retry",
                ));
            }
            Ok(mempool
                .lock()
                .expect("ChainBackend mempool poisoned")
                .pending_nonce(account, state_nonce))
        })
        .await
    }
}
