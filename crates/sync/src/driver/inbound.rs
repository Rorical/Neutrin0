//! Read-only peer RPC dispatch, history reply bounds and backend error mapping.

use crate::backend::{SyncBackend, SyncBackendError};
use neutrin0_network::rpc::{HistoryProofRequest, RpcProtocol, RpcRequest, RpcResponse};

/// Construct an inbound reply without changing the sync driver's state.
pub(super) async fn response(backend: &dyn SyncBackend, request: RpcRequest) -> RpcResponse {
    match request {
        RpcRequest::Status(_) => rpc_reply(
            RpcProtocol::Status,
            backend.local_status().await,
            RpcResponse::Status,
        ),
        RpcRequest::Metadata(_) => RpcResponse::Metadata(backend.local_metadata().await),
        RpcRequest::Ping(payload) => RpcResponse::Ping(payload),
        RpcRequest::TransactionInventory(req) => {
            RpcResponse::TransactionInventory(neutrin0_network::rpc::TransactionInventoryResponse {
                hashes: backend.transaction_inventory(req.after).await,
            })
        }
        RpcRequest::TransactionsByHash(req) => {
            RpcResponse::TransactionsByHash(neutrin0_network::rpc::TransactionsByHashResponse {
                transactions: backend.pending_transactions(&req.hashes).await,
            })
        }
        RpcRequest::BlocksByRange(req) => rpc_reply(
            RpcProtocol::BlocksByRange,
            backend
                .blocks_by_range(req.start_height, req.count, req.head_block_hash)
                .await,
            RpcResponse::BlocksByRange,
        ),
        RpcRequest::StateByRoot(req) => rpc_reply(
            RpcProtocol::StateByRoot,
            backend.state_nodes(req.state_root, &req.items).await,
            RpcResponse::StateByRoot,
        ),
        RpcRequest::ChunkProofById(req) => rpc_reply(
            RpcProtocol::ChunkProofById,
            chunk_proof_reply(backend, &req).await,
            RpcResponse::ChunkProofById,
        ),
        RpcRequest::HistoryProof(req) => rpc_reply(
            RpcProtocol::HistoryProof,
            history_rpc_reply(backend, req).await,
            |payload| RpcResponse::HistoryProof(Box::new(payload)),
        ),
        RpcRequest::FinalityCertByChunk(req) => rpc_reply(
            RpcProtocol::FinalityCertByChunk,
            backend.finality_certs_by_chunk(&req.chunk_ids).await,
            RpcResponse::FinalityCertByChunk,
        ),
        RpcRequest::CandidateByChunk(req) => rpc_reply(
            RpcProtocol::CandidateByChunk,
            backend.bft_candidate(req.chunk_id, req.chunk_hash).await,
            |payload| RpcResponse::CandidateByChunk(Box::new(payload)),
        ),
        RpcRequest::BftRoundByChunk(req) => rpc_reply(
            RpcProtocol::BftRoundByChunk,
            backend.bft_round_by_chunk(req.chunk_id).await,
            |payload| RpcResponse::BftRoundByChunk(Box::new(payload)),
        ),
        RpcRequest::SignedArtifactById(req) => rpc_reply(
            RpcProtocol::SignedArtifactById,
            backend.signed_artifact_by_id(req.id).await,
            |payload| RpcResponse::SignedArtifactById(Box::new(payload)),
        ),
        RpcRequest::SignedArtifactInventoryByChunk(req) => rpc_reply(
            RpcProtocol::SignedArtifactInventoryByChunk,
            backend
                .signed_artifact_inventory(req.chunk_id, req.after)
                .await,
            |payload| RpcResponse::SignedArtifactInventoryByChunk(Box::new(payload)),
        ),
        RpcRequest::WitnessByBlock(req) => rpc_reply(
            RpcProtocol::WitnessByBlock,
            backend.witnesses_by_block(&req.block_hashes).await,
            RpcResponse::WitnessByBlock,
        ),
        RpcRequest::ReceiptsByHash(req) => rpc_reply(
            RpcProtocol::ReceiptsByHash,
            backend.receipts_by_hash(&req.block_hashes).await,
            RpcResponse::ReceiptsByHash,
        ),
    }
}

/// Canonical proofs by id, or the retained proofs a request names by
/// statement key, one key per id (design 08).
async fn chunk_proof_reply(
    backend: &dyn SyncBackend,
    request: &neutrin0_network::rpc::ChunkProofByIdRequest,
) -> Result<neutrin0_network::rpc::ChunkProofByIdResponse, SyncBackendError> {
    if request.statement_keys.is_empty() {
        return backend.chunk_proofs_by_id(&request.chunk_ids).await;
    }
    if request.statement_keys.len() != request.chunk_ids.len() {
        return Err(SyncBackendError::InvalidRequest(
            "one statement key per requested chunk".to_owned(),
        ));
    }
    let entries: Vec<_> = request
        .chunk_ids
        .iter()
        .copied()
        .zip(request.statement_keys.iter().copied())
        .collect();
    backend.chunk_proofs_by_key(&entries).await
}

async fn history_rpc_reply(
    backend: &dyn SyncBackend,
    request: HistoryProofRequest,
) -> Result<neutrin0_network::rpc::HistoryProofResponse, SyncBackendError> {
    let mut response = backend
        .history_proof(
            request.anchor_chunks,
            request.end_chunks,
            request.checkpoint_hash,
        )
        .await?;
    if request.bootstrap {
        let data = backend.bootstrap_data(request.checkpoint_hash).await?;
        if data.history != response.proof {
            return Err(SyncBackendError::NotAvailable(
                "bootstrap endpoint moved while serving".into(),
            ));
        }
        response.bootstrap = Some(data);
    }
    bounded_history_reply(response)
}

fn bounded_history_reply(
    payload: neutrin0_network::rpc::HistoryProofResponse,
) -> Result<neutrin0_network::rpc::HistoryProofResponse, SyncBackendError> {
    let size = borsh::object_length(&payload)
        .map_err(|error| SyncBackendError::Storage(error.to_string()))?;
    // Reserve the RpcResult discriminant in the framed response.
    if u64::try_from(size).unwrap_or(u64::MAX) >= neutrin0_network::rpc::DEFAULT_MAX_RESPONSE_SIZE {
        return Err(SyncBackendError::NotAvailable(
            "bootstrap manifest exceeds the wire limit".into(),
        ));
    }
    Ok(payload)
}

fn rpc_reply<T>(
    protocol: RpcProtocol,
    result: Result<T, SyncBackendError>,
    wrap: impl FnOnce(T) -> RpcResponse,
) -> RpcResponse {
    use neutrin0_network::rpc::RpcFailure;
    match result {
        Ok(payload) => wrap(payload),
        Err(error) => {
            let error = match error {
                SyncBackendError::Storage(reason) => RpcFailure::Storage(reason),
                SyncBackendError::Pruned {
                    retained_from_chunk,
                    retained_from_height,
                } => RpcFailure::Pruned {
                    retained_from_chunk,
                    retained_from_height,
                },
                SyncBackendError::NotAvailable(reason) | SyncBackendError::ChainBehind(reason) => {
                    RpcFailure::Unavailable(reason)
                }
                SyncBackendError::Rejected(reason) | SyncBackendError::InvalidRequest(reason) => {
                    RpcFailure::InvalidRequest(reason)
                }
            };
            RpcResponse::Error { protocol, error }
        }
    }
}
