use super::codec::bytes;
use super::filters::initial_filter_anchor;
use super::logs::{LogBudget, ReadBudget, check_log_budget, check_range_block};
use super::queries::check_artifact_projection;
use super::state::call_request;
use super::subscriptions::subscription_filter;
use super::*;
use neutrin0_runtime_abi::ethereum::EvmArtifacts;

#[test]
fn call_arguments_reject_conflicting_calldata_fees_and_overrides() {
    let address = bytes(&[1; 20]);
    assert!(
        call_request(
            &json!({"to": address, "input": "0x01", "data": "0x02"}),
            100_000
        )
        .is_err()
    );
    assert!(call_request(&json!({"gasPrice": "0x1", "maxFeePerGas": "0x2"}), 100_000).is_err());
    assert!(
        call_request(
            &json!({"maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x2"}),
            100_000
        )
        .is_err()
    );
    assert!(call_request(&json!({"input": "0x01", "data": "0x01"}), 100_000).is_ok());
    // Client gas never exceeds the block gas limit.
    assert_eq!(
        call_request(&json!({"gas": "0xffffffffffffffff"}), 100_000)
            .unwrap()
            .gas_limit,
        100_000
    );
    assert!(check_arguments("eth_call", &[json!({}), json!("latest"), json!({})]).is_err());
    assert!(check_arguments("eth_getBlockByNumber", &[json!("latest"), json!("true")]).is_err());
}

#[test]
fn log_result_budget_also_applies_to_one_selected_block() {
    assert!(check_log_budget(&vec![Value::Null; 10_001]).is_err());
    assert!(check_log_budget(&[json!("x".repeat(2 * 1024 * 1024))]).is_err());
    assert!(check_log_budget(&[json!({"removed": true})]).is_ok());
    // A range accumulates across blocks without re-serializing them.
    let mut budget = LogBudget::default();
    let block = vec![json!("x".repeat(512 * 1024))];
    for _ in 0..3 {
        assert!(budget.add(&block).is_ok());
    }
    assert!(budget.add(&block).is_err());
}

#[test]
fn a_range_query_stops_once_it_has_read_its_block_budget() {
    let body = neutrin0_consensus_types::Body {
        transactions: vec![vec![0; 1024 * 1024]],
        ..neutrin0_consensus_types::Body::default()
    };
    let mut read = ReadBudget::default();
    for _ in 0..63 {
        assert!(read.charge(&body).is_ok());
    }
    assert!(read.charge(&body).is_err());
}

#[test]
fn subscriptions_reject_historical_ranges_and_keep_the_initial_head_anchor() {
    assert!(subscription_filter("logs", &[json!("logs"), json!({"fromBlock": "0x1"})], 4).is_err());
    assert!(subscription_filter("newHeads", &[json!("newHeads"), json!({})], 4).is_err());
    assert!(
        subscription_filter(
            "logs",
            &[json!("logs"), json!({"address": bytes(&[1;20])})],
            4
        )
        .is_ok()
    );
    assert_eq!(
        initial_filter_anchor(4, [2; 32]).get(&4),
        Some(&([2; 32], Vec::new()))
    );
    assert!(initial_filter_anchor(0, [2; 32]).is_empty());
}

#[test]
fn range_projection_rejects_mixed_fork_ancestry() {
    let (block, _) = projection_fixture();
    assert!(check_range_block(&block, Some(block.header.parent_hash)).is_ok());
    assert!(check_range_block(&block, Some([9; 32])).is_err());
}

pub(super) fn projection_fixture() -> (neutrin0_consensus_types::Block, EvmArtifacts) {
    let context = neutrin0_consensus_types::runtime::ConsensusExecutionContext {
        slot: 2,
        timestamp: 12,
        parent_block_hash: [3; 32],
        proposer_vrf_output: neutrin0_crypto::sha256(&[4; 96]),
        ..neutrin0_consensus_types::runtime::ConsensusExecutionContext::default()
    };
    let artifacts = EvmArtifacts {
        metadata: neutrin0_runtime_abi::ethereum::EvmBlockMetadata {
            height: 1,
            base_fee: 10,
            beneficiary: [5; 20],
            system_gas: 100,
            evm_gas: 21_000,
            context,
        },
        receipts: vec![neutrin0_runtime_abi::ethereum::EvmReceipt {
            envelope_index: 1,
            transaction_hash: [6; 32],
            from: [5; 20],
            to: Some([7; 20]),
            contract_address: None,
            transaction_type: 2,
            success: true,
            gas_used: 21_000,
            cumulative_gas_used: 21_000,
            effective_gas_price: 11,
            logs: Vec::new(),
        }],
    };
    let body = neutrin0_consensus_types::Body {
        transactions: vec![Vec::new(), vec![1]],
        artifacts: neutrin0_runtime_abi::ExecutionArtifacts {
            transaction_ids: vec![(1, [6; 32])],
            ..neutrin0_runtime_abi::ExecutionArtifacts::default()
        },
        ..neutrin0_consensus_types::Body::default()
    };
    let header = neutrin0_consensus_types::Header {
        height: 1,
        slot: context.slot,
        parent_hash: context.parent_block_hash,
        proposer_index: 0,
        vrf_proof: [4; 96],
        state_root: [0; 32],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        inputs_root: [0; 32],
        receipts_root: body.artifacts.commitment(),
        gas_used: 21_100,
        gas_limit: 100_000,
        timestamp: context.timestamp,
        signature: [0; 96],
    };
    (neutrin0_consensus_types::Block { header, body }, artifacts)
}

#[test]
fn artifact_projection_rejects_header_context_and_receipt_index_drift() {
    let (block, original) = projection_fixture();
    assert!(check_artifact_projection(&block, &original).is_ok());
    for field in 0..8 {
        let mut changed = original.clone();
        match field {
            0 => changed.metadata.context.slot += 1,
            1 => changed.metadata.context.timestamp += 1,
            2 => changed.metadata.context.parent_block_hash[0] ^= 1,
            3 => changed.metadata.context.proposer_vrf_output[0] ^= 1,
            4 => changed.metadata.system_gas += 1,
            5 => changed.receipts[0].cumulative_gas_used += 1,
            6 => changed.receipts[0].transaction_hash[0] ^= 1,
            _ => changed.receipts[0].envelope_index = 0,
        }
        assert!(check_artifact_projection(&block, &changed).is_err());
    }
}
