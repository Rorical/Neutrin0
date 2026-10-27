//! Status, metadata and progress advertisements derived from local finality.

use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_types::history_proof::{Checkpoint, ConsensusBoundary};
use neutrin0_network::{
    rpc::{self, Status},
    sync::LocalProgress,
};
use neutrin0_primitives::ZERO_HASH;
use neutrin0_proof_system::ProofSystem;
use neutrin0_rpc::QueryError;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

use super::{ChainBackend, query_error, rpc_queries, storage_error};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(in crate::chain_backend) fn p2p_local_metadata(&self) -> rpc::Metadata {
        if self.is_light() {
            return rpc::Metadata {
                role_flags: rpc::role_flags::LIGHT_CLIENT,
                ..rpc::Metadata::default()
            };
        }
        self.with_engine(|engine| {
            let retention = rpc_queries::retention_info(engine)?;
            Ok::<_, QueryError>(rpc::Metadata {
                role_flags: rpc::role_flags::FULL_NODE
                    | if retention.archive {
                        rpc::role_flags::ARCHIVE
                    } else {
                        0
                    },
                retained_from_chunk: retention.retained_from_chunk,
                retained_from_height: retention.retained_from_height,
            })
        })
        .unwrap_or_default()
    }

    fn p2p_status_snapshot(
        engine: &Engine<DB>,
    ) -> Result<(Status, ConsensusBoundary), SyncBackendError> {
        // The finalized endpoint, whose History proof is this node's latest
        // chunk receipt.
        let boundary = engine
            .canonical_boundary(engine.finalized_next_chunk_id())
            .map_err(storage_error)?;
        let checkpoint_hash = engine
            .store()
            .history_domain()
            .map_err(storage_error)?
            .map_or(ZERO_HASH, |domain| {
                Checkpoint {
                    chain: domain.chain,
                    boundary,
                }
                .hash()
            });
        let finalized = rpc_queries::finalized_info(engine).map_err(query_error)?;
        let chunk_hash = match finalized.chunk_id {
            Some(id) => {
                let chunk = engine
                    .store()
                    .get_chunk(id)
                    .map_err(storage_error)?
                    .ok_or_else(|| storage_error("finalized chunk is missing"))?;
                if chunk.end_block_hash != finalized.block_hash
                    || chunk.end_height != finalized.height
                    || chunk.end_state_root != finalized.state_root
                {
                    return Err(storage_error("finalized chunk boundary is inconsistent"));
                }
                chunk.hash()
            }
            None => ZERO_HASH,
        };
        let head_slot = if engine.head_hash() == engine.chain_spec().genesis_block_hash {
            0
        } else {
            rpc_queries::checked_header(engine, engine.head_hash())
                .map_err(query_error)?
                .ok_or_else(|| storage_error("head header is missing"))?
                .slot
        };
        Ok((
            Status {
                chain_id: engine.chain_spec().chain_id,
                chain_spec_hash: engine.chain_spec_hash(),
                finalized_chunk_id: finalized.chunk_id,
                finalized_chunk_hash: chunk_hash,
                checkpoint_hash,
                head_block_hash: engine.head_hash(),
                head_slot,
                head_height: engine.head_height(),
            },
            boundary,
        ))
    }

    pub(in crate::chain_backend) fn p2p_local_status(&self) -> Result<Status, SyncBackendError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            // A light node advertises its accepted endpoint, never finality it
            // could serve chunks for.
            return Ok(Status {
                chain_id: self.chain_id(),
                chain_spec_hash: checkpoint.chain.chain_spec_hash,
                finalized_chunk_id: None,
                finalized_chunk_hash: ZERO_HASH,
                checkpoint_hash: checkpoint.hash(),
                head_block_hash: checkpoint.boundary.block_hash,
                head_slot: checkpoint.boundary.slot,
                head_height: checkpoint.boundary.height,
            });
        }
        self.with_engine(|engine| Self::p2p_status_snapshot(engine).map(|(status, _)| status))
    }

    pub(in crate::chain_backend) fn p2p_local_progress(
        &self,
    ) -> Result<LocalProgress, SyncBackendError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            let boundary = checkpoint.boundary;
            return Ok(LocalProgress {
                chain_id: self.chain_id(),
                chain_spec_hash: checkpoint.chain.chain_spec_hash,
                finalized_chunk_id: boundary.next_chunk_id.checked_sub(1),
                finalized_chunk_hash: ZERO_HASH,
                checkpoint_hash: checkpoint.hash(),
                finalized_state_root: boundary.state_root,
                finalized_block_hash: boundary.block_hash,
                finalized_height: boundary.height,
                head_height: boundary.height,
                head_block_hash: boundary.block_hash,
                head_slot: boundary.slot,
                proven_height: 0,
            });
        }
        self.with_engine(|engine| {
            let (status, checkpoint) = Self::p2p_status_snapshot(engine)?;
            Ok(LocalProgress {
                chain_id: status.chain_id,
                chain_spec_hash: status.chain_spec_hash,
                finalized_chunk_id: status.finalized_chunk_id,
                finalized_chunk_hash: status.finalized_chunk_hash,
                checkpoint_hash: status.checkpoint_hash,
                finalized_state_root: checkpoint.state_root,
                finalized_block_hash: checkpoint.block_hash,
                finalized_height: checkpoint.height,
                head_height: status.head_height,
                head_block_hash: status.head_block_hash,
                head_slot: status.head_slot,
                proven_height: Self::contiguous_proven_height(engine)?,
            })
        })
    }
}
