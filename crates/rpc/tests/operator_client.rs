//! Real HTTP transport tests for parameter encoding and confirmation races.

use jsonrpsee::{
    server::{RpcModule, Server},
    types::ErrorObjectOwned,
};
use neutrin0_rpc::client::{
    ClientError, EthereumReceiptJson, NodeApiClient, NodeClient, PinnedBlock, quantity_u64,
};
use neutrin0_rpc::{
    BlockId, BlockIdJson, BytesHex, FinalizedInfoJson, HashHex, HeadInfoJson, HeaderJson,
    RuntimeCallResultJson,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const HASH: HashHex = HashHex([1; 32]);
const BLOCK: HashHex = HashHex([2; 32]);

async fn start(module: RpcModule<()>) -> (NodeClient, jsonrpsee::server::ServerHandle) {
    let server = Server::builder().build("127.0.0.1:0").await.expect("bind");
    let endpoint = format!("http://{}", server.local_addr().expect("address"));
    let handle = server.start(module);
    (
        NodeClient::connect(&endpoint, Duration::from_secs(1)).expect("client"),
        handle,
    )
}

const fn header(hash: HashHex) -> HeaderJson {
    HeaderJson {
        height: 3,
        slot: 3,
        parent_hash: HashHex([0; 32]),
        block_hash: hash,
        proposer_index: 0,
        state_root: HashHex([3; 32]),
        transactions_root: HashHex([4; 32]),
        votes_root: HashHex([0; 32]),
        da_root: HashHex([0; 32]),
        runtime_extra: HashHex([0; 32]),
        receipts_root: HashHex([0; 32]),
        gas_used: 1,
        gas_limit: 30_000_000,
        timestamp: 1,
    }
}

fn receipt(hash: HashHex) -> EthereumReceiptJson {
    EthereumReceiptJson {
        transaction_hash: hash,
        block_hash: BLOCK,
        block_number: "0x3".into(),
        status: "0x0".into(),
        details: serde_json::Map::new(),
    }
}

fn finality(module: &mut RpcModule<()>) {
    module
        .register_method("chain_finalized", |_params, _context, _extensions| {
            Ok::<_, ErrorObjectOwned>(FinalizedInfoJson {
                chunk_id: Some(0),
                block_hash: BLOCK,
                height: 3,
                state_root: HashHex([3; 32]),
            })
        })
        .expect("register finality");
}

#[tokio::test]
async fn named_parameters_and_runtime_failures_survive_http_transport() {
    let mut module = RpcModule::new(());
    module
        .register_method("runtime_call", |params, _context, _extensions| {
            let value: serde_json::Value = params.parse()?;
            assert_eq!(value["method"], "account_get");
            assert_eq!(value["args"], "0x0708");
            assert_eq!(value["at"], serde_json::json!(BLOCK));
            Ok::<_, ErrorObjectOwned>(RuntimeCallResultJson {
                code: 3,
                payload: BytesHex(vec![9]),
                gas_used: 0,
            })
        })
        .expect("register query");
    module
        .register_method("state_getStorage", |_params, _context, _extensions| {
            Err::<Option<BytesHex>, _>(ErrorObjectOwned::owned(
                -32024,
                "pruned",
                Some(serde_json::json!({"retained_from_height": 80})),
            ))
        })
        .expect("register storage");
    let (client, handle) = start(module).await;
    let error = client
        .query::<u64>(
            "account_get",
            vec![7, 8],
            PinnedBlock {
                hash: BLOCK,
                height: 3,
            },
        )
        .await
        .expect_err("runtime error");
    assert!(
        matches!(error, ClientError::Runtime { code: 3, payload: BytesHex(ref payload), .. } if payload == &[9])
    );
    let error = client
        .rpc()
        .storage(BytesHex(vec![]), BlockIdJson(BlockId::Height(1)))
        .await
        .expect_err("pruned");
    let jsonrpsee::core::client::Error::Call(error) = error else {
        panic!("structured RPC error expected");
    };
    assert_eq!(error.code(), -32024);
    assert!(error.data().expect("data").get().contains("80"));
    handle.stop().expect("stop");
}

#[tokio::test]
async fn finality_wait_rechecks_canonical_inclusion_and_reports_reverted_execution() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut module = RpcModule::new(());
    module
        .register_method(
            "eth_getTransactionReceipt",
            |_params, _context, _extensions| Some(receipt(HASH)),
        )
        .expect("receipt");
    let observed = Arc::clone(&calls);
    module
        .register_method("chain_getHeader", move |params, _context, _extensions| {
            let (at,): (BlockIdJson,) = params.parse()?;
            assert_eq!(at, BlockIdJson(BlockId::Height(3)));
            let hash = if observed.fetch_add(1, Ordering::Relaxed) == 0 {
                HashHex([99; 32])
            } else {
                BLOCK
            };
            Ok::<_, ErrorObjectOwned>(Some(header(hash)))
        })
        .expect("header");
    finality(&mut module);
    let (client, handle) = start(module).await;
    let confirmed = client
        .wait_ethereum(HASH, true, Duration::from_secs(1), Duration::from_millis(1))
        .await
        .expect("confirmed");
    assert!(confirmed.finalized);
    assert!(!confirmed.execution_success);
    assert_eq!(confirmed.block.hash, BLOCK);
    assert!(calls.load(Ordering::Relaxed) >= 2);
    handle.stop().expect("stop");
}

#[tokio::test]
async fn mismatched_receipts_cannot_confirm_the_requested_transaction() {
    let mut module = RpcModule::new(());
    module
        .register_method(
            "eth_getTransactionReceipt",
            |_params, _context, _extensions| Some(receipt(HashHex([7; 32]))),
        )
        .expect("receipt");
    let (client, handle) = start(module).await;
    let error = client
        .wait_ethereum(HASH, true, Duration::from_secs(1), Duration::from_millis(1))
        .await
        .expect_err("mismatch");
    assert!(matches!(error, ClientError::InvalidResponse(_)));
    handle.stop().expect("stop");
}

#[tokio::test]
async fn confirmation_deadline_bounds_outstanding_requests() {
    let mut module = RpcModule::new(());
    module
        .register_async_method(
            "eth_getTransactionReceipt",
            |_params, _context, _extensions| async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                None::<EthereumReceiptJson>
            },
        )
        .expect("receipt");
    let (client, handle) = start(module).await;
    let error = client
        .wait_ethereum(
            HASH,
            true,
            Duration::from_millis(10),
            Duration::from_millis(1),
        )
        .await
        .expect_err("deadline");
    assert!(matches!(error, ClientError::ConfirmationTimeout(_)));
    handle.stop().expect("stop");
}

#[tokio::test]
async fn latest_selection_is_pinned_before_multiple_queries() {
    let mut module = RpcModule::new(());
    module
        .register_method("chain_head", |_params, _context, _extensions| {
            Ok::<_, ErrorObjectOwned>(HeadInfoJson {
                height: 3,
                slot: 3,
                hash: BLOCK,
                state_root: HashHex([3; 32]),
            })
        })
        .expect("head");
    module
        .register_method("runtime_call", |params, _context, _extensions| {
            let value: serde_json::Value = params.parse()?;
            assert_eq!(value["at"], serde_json::json!(BLOCK));
            Ok::<_, ErrorObjectOwned>(RuntimeCallResultJson {
                code: 0,
                payload: BytesHex(borsh::to_vec(&7_u64).expect("encode")),
                gas_used: 0,
            })
        })
        .expect("query");
    let (client, handle) = start(module).await;
    let pinned = client.pin(BlockIdJson(BlockId::Latest)).await.expect("pin");
    for method in ["first", "second"] {
        assert_eq!(
            client
                .query::<u64>(method, vec![], pinned)
                .await
                .expect("query"),
            7
        );
    }
    handle.stop().expect("stop");
}

#[test]
fn ethereum_quantities_reject_ambiguous_encodings_and_overflow() {
    assert_eq!(quantity_u64("0xffffffffffffffff").expect("max"), u64::MAX);
    for value in ["0x", "0x00", "0x01", "1", "0x10000000000000000", "0x-1"] {
        assert!(quantity_u64(value).is_err(), "{value}");
    }
}

#[tokio::test]
async fn explicit_genesis_selectors_do_not_require_a_stored_header() {
    let mut module = RpcModule::new(());
    module
        .register_method("chain_getGenesis", |_params, _context, _extensions| {
            Some(neutrin0_rpc::types::GenesisInfoJson {
                hash: BLOCK,
                state_root: HashHex([3; 32]),
                timestamp: 1,
                gas_limit: 30_000_000,
                seed: HashHex([0; 32]),
            })
        })
        .expect("genesis");
    let (client, handle) = start(module).await;
    for selector in [BlockId::Height(0), BlockId::Hash(BLOCK.0)] {
        assert_eq!(
            client
                .pin(BlockIdJson(selector))
                .await
                .expect("genesis selector"),
            PinnedBlock {
                hash: BLOCK,
                height: 0
            }
        );
    }
    handle.stop().expect("stop");
}
