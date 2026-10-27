use super::*;
use borsh::{from_slice, to_vec};
use neutrin0_consensus_types::Block;
use neutrin0_consensus_types::{Body, Header};

fn sample_header() -> Header {
    Header {
        height: 7,
        slot: 9,
        parent_hash: [1; 32],
        proposer_index: 2,
        vrf_proof: [3; 96],
        state_root: [4; 32],
        transactions_root: [5; 32],
        votes_root: [6; 32],
        da_root: [9; 32],
        runtime_extra: [10; 32],
        inputs_root: [0; 32],
        receipts_root: [12; 32],
        gas_used: 100,
        gas_limit: 1_000_000,
        timestamp: 1_800_000_000,
        signature: [11; 96],
    }
}

fn sample_block() -> Block {
    Block {
        header: sample_header(),
        body: Body::default(),
    }
}

#[test]
fn protocol_ids_match_doc_06() {
    assert_eq!(RpcProtocol::Status.protocol_id(), "/neutrin0/req/status");
    assert_eq!(
        RpcProtocol::Metadata.protocol_id(),
        "/neutrin0/req/metadata"
    );
    assert_eq!(RpcProtocol::Ping.protocol_id(), "/neutrin0/req/ping");
    assert_eq!(
        RpcProtocol::BlocksByRange.protocol_id(),
        "/neutrin0/req/blocks_by_range"
    );
    assert_eq!(
        RpcProtocol::StateByRoot.protocol_id(),
        "/neutrin0/req/state_by_root"
    );
    assert_eq!(
        RpcProtocol::ChunkProofById.protocol_id(),
        "/neutrin0/req/chunk_proof_by_id"
    );
    assert_eq!(
        RpcProtocol::HistoryProof.protocol_id(),
        "/neutrin0/req/history_proof"
    );
    assert_eq!(
        RpcProtocol::ReceiptsByHash.protocol_id(),
        "/neutrin0/req/receipts_by_hash"
    );
    assert!(RpcProtocol::ReceiptsByHash.is_chain_data());
}

#[test]
fn per_protocol_timeouts_and_size_caps_are_pinned() {
    for (index, protocol) in RpcProtocol::ALL.into_iter().enumerate() {
        assert_eq!(protocol as usize, index);
        let seconds = match protocol {
            RpcProtocol::WitnessByBlock => 60,
            RpcProtocol::BlocksByRange
            | RpcProtocol::StateByRoot
            | RpcProtocol::ChunkProofById
            | RpcProtocol::HistoryProof
            | RpcProtocol::ReceiptsByHash => 30,
            _ => 15,
        };
        assert_eq!(protocol.request_timeout(), Duration::from_secs(seconds));
    }
    assert_eq!(
        RpcProtocol::SignedArtifactById.size_limits(),
        (64, 8_388_624)
    );
    assert_eq!(
        RpcProtocol::SignedArtifactInventoryByChunk.size_limits(),
        (64, 2048)
    );
    assert_eq!(RpcProtocol::BftRoundByChunk.size_limits(), (64, 8_388_608));
    assert_eq!(RpcProtocol::Status.size_limits(), (161, 1024));
    assert_eq!(RpcProtocol::Metadata.size_limits(), (0, 1024));
    assert_eq!(RpcProtocol::Ping.size_limits(), (8, 1024));
    assert_eq!(
        RpcProtocol::CandidateByChunk.size_limits(),
        (DEFAULT_MAX_REQUEST_SIZE, DEFAULT_MAX_RESPONSE_SIZE)
    );
}

#[test]
fn rpc_request_protocol_tagging_is_consistent() {
    let cases = [
        (
            RpcRequest::Status(Status {
                chain_id: 1,
                chain_spec_hash: [0; 32],
                finalized_chunk_id: None,
                finalized_chunk_hash: [0; 32],
                checkpoint_hash: [0; 32],
                head_block_hash: [0; 32],
                head_slot: 0,
                head_height: 0,
            }),
            RpcProtocol::Status,
        ),
        (RpcRequest::Metadata(MetadataRequest), RpcProtocol::Metadata),
        (
            RpcRequest::Ping(PingPayload { nonce: 42 }),
            RpcProtocol::Ping,
        ),
        (
            RpcRequest::BlocksByRange(BlocksByRangeRequest {
                head_block_hash: [0; 32],
                start_height: 0,
                count: 1,
            }),
            RpcProtocol::BlocksByRange,
        ),
        (
            RpcRequest::StateByRoot(StateByRootRequest {
                state_root: [0; 32],
                items: neutrin0_consensus_types::bootstrap::StateItems::default(),
            }),
            RpcProtocol::StateByRoot,
        ),
        (
            RpcRequest::ChunkProofById(ChunkProofByIdRequest {
                chunk_ids: vec![],
                statement_keys: Vec::new(),
            }),
            RpcProtocol::ChunkProofById,
        ),
        (
            RpcRequest::HistoryProof(HistoryProofRequest {
                anchor_chunks: 1,
                end_chunks: 2,
                checkpoint_hash: [2; 32],
                bootstrap: false,
            }),
            RpcProtocol::HistoryProof,
        ),
    ];
    for (req, expected) in cases {
        assert_eq!(req.protocol(), expected);
    }
}

#[test]
fn history_request_binds_its_anchor_and_exact_endpoint() {
    let request = HistoryProofRequest {
        anchor_chunks: 1,
        end_chunks: 2,
        checkpoint_hash: [2; 32],
        bootstrap: false,
    };
    let bytes = to_vec(&request).unwrap();
    assert_eq!(bytes.len(), 49);
    assert!(bytes.len() <= usize::try_from(DEFAULT_MAX_REQUEST_SIZE).unwrap());
    assert_eq!(from_slice::<HistoryProofRequest>(&bytes).unwrap(), request);
    assert!(from_slice::<HistoryProofRequest>(&bytes[..48]).is_err());
}

#[test]
fn history_response_bounds_receipt_before_reading_payload() {
    use neutrin0_consensus_types::history_proof::MAX_HISTORY_RECEIPT_BYTES;
    let statement = vec![0_u8; 32];
    let mut encoded = statement.clone();
    encoded.extend_from_slice(
        &u32::try_from(MAX_HISTORY_RECEIPT_BYTES + 1)
            .unwrap()
            .to_le_bytes(),
    );
    // The receipt length is refused before any statement could matter:
    // decode the bounded receipt alone, framed as the response encodes it.
    assert!(
        from_slice::<neutrin0_primitives::BoundedBytes<MAX_HISTORY_RECEIPT_BYTES>>(
            &encoded[statement.len()..]
        )
        .is_err()
    );
    assert!(from_slice::<HistoryProofResponse>(&encoded).is_err());
}

#[test]
fn status_round_trips_via_borsh() {
    let status = Status {
        chain_id: 7,
        chain_spec_hash: [9; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: [1; 32],
        head_block_hash: [2; 32],
        head_slot: 99,
        head_height: 88,
    };
    let bytes = to_vec(&status).unwrap();
    let decoded: Status = from_slice(&bytes).unwrap();
    assert_eq!(decoded, status);
}

#[test]
fn metadata_round_trips_via_borsh() {
    let meta = Metadata {
        role_flags: role_flags::FULL_NODE | role_flags::ARCHIVE,
        retained_from_chunk: Some(8),
        retained_from_height: Some(16_385),
    };
    let bytes = to_vec(&meta).unwrap();
    let decoded: Metadata = from_slice(&bytes).unwrap();
    assert_eq!(decoded, meta);
}

#[test]
fn pruning_failure_preserves_the_actual_retention_boundary_on_wire() {
    let failure = RpcFailure::Pruned {
        retained_from_chunk: 12,
        retained_from_height: 24_577,
    };
    let encoded = to_vec(&failure).unwrap();
    assert_eq!(from_slice::<RpcFailure>(&encoded).unwrap(), failure);
    assert_ne!(failure, RpcFailure::Unavailable("still proving".to_owned()));
}

#[test]
fn blocks_by_range_request_round_trips() {
    let req = BlocksByRangeRequest {
        head_block_hash: [0; 32],
        start_height: 1000,
        count: 16,
    };
    let bytes = to_vec(&req).unwrap();
    let decoded: BlocksByRangeRequest = from_slice(&bytes).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn blocks_by_range_response_round_trips() {
    let proven = neutrin0_consensus_types::ProvenBlock {
        block: sample_block(),
        proof_bytes: vec![7; 4],
        writes: Vec::new(),
    };
    let resp = BlocksByRangeResponse {
        blocks: vec![proven.clone(), proven],
        candidates: Vec::new(),
    };
    let bytes = to_vec(&resp).unwrap();
    let decoded: BlocksByRangeResponse = from_slice(&bytes).unwrap();
    assert_eq!(decoded, resp);
}
