//! Runtime-owned Ethereum queries and disposable call simulations.

mod pending;
mod simulation;

use crate::state::{StateDb, read_record};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use alloy_consensus::Transaction;
pub use neutrin0_runtime_abi::ethereum::{CallRequest, CallResult};
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, QueryStatus, RuntimeBlockInput};
use neutrin0_runtime_core::StateBackend;
use pending::pending_query;
use revm::Database;
use revm::primitives::{Address, B256, U256};
pub use simulation::simulate;
use simulation::{estimate_gas, simulate_with_availability};

fn call_query<B: StateBackend>(
    request: &QueryRequest,
    state: &mut B,
    proposer_vrf_available: bool,
) -> Result<Vec<u8>, String> {
    let call = borsh::from_slice::<CallRequest>(&request.args)
        .map_err(|_| String::from("malformed call"))?;
    if request.method == "evm:estimate_gas" {
        Ok(
            borsh::to_vec(&estimate_gas(&call, state, proposer_vrf_available)?)
                .expect("gas estimate and call result"),
        )
    } else {
        Ok(borsh::to_vec(&simulate_with_availability(
            &call,
            state,
            proposer_vrf_available,
        )?)
        .expect("call result"))
    }
}

/// Dispatch Ethereum queries; operational queries fall through to the shared
/// system modules.
pub fn query<B: StateBackend>(request: &QueryRequest, state: &mut B) -> QueryResponse {
    if request.method == "evm:pending" {
        pending_query(request, state)
    } else {
        query_regular(request, state)
    }
}
fn query_regular<B: StateBackend>(request: &QueryRequest, state: &mut B) -> QueryResponse {
    let result: Result<Vec<u8>, String> = match request.method.as_str() {
        "runtime_info" => Ok(borsh::to_vec(&neutrin0_primitives::RuntimeInfo {
            spec_name: *b"NEUTRIN0_EVM\0\0\0\0",
        })
        .expect("EVM runtime info")),
        "evm:transaction" => transaction_projection(&request.args),
        "evm:account" => (|| {
            let address: [u8; 20] = borsh::from_slice(&request.args)
                .map_err(|_| String::from("Ethereum address expected"))?;
            let account = crate::state::load_account(state, Address::from(address))
                .map_err(|error| error.to_string())?
                .unwrap_or_default();
            Ok(borsh::to_vec(&account).expect("account query"))
        })(),
        "evm:code" => (|| {
            let address: [u8; 20] = borsh::from_slice(&request.args)
                .map_err(|_| String::from("Ethereum address expected"))?;
            let account = crate::state::load_account(state, Address::from(address))
                .map_err(|error| error.to_string())?
                .unwrap_or_default();
            let mut db = StateDb::new(state, 0);
            let code = db
                .code_by_hash(B256::from(account.code_hash))
                .map_err(|error| error.to_string())?
                .original_bytes()
                .to_vec();
            Ok(borsh::to_vec(&code).expect("bytecode query"))
        })(),
        "evm:storage" => (|| {
            let (address, slot): ([u8; 20], [u8; 32]) = borsh::from_slice(&request.args)
                .map_err(|_| String::from("address and storage word expected"))?;
            let mut db = StateDb::new(state, 0);
            Ok(db
                .storage(Address::from(address), U256::from_be_bytes(slot))
                .map_err(|error| error.to_string())?
                .to_be_bytes::<32>()
                .to_vec())
        })(),
        "evm:call" | "evm:estimate_gas" => call_query(request, state, true),
        "runtime:select_transactions" => (|| {
            let input = borsh::from_slice::<RuntimeBlockInput>(&request.args)
                .map_err(|_| String::from("malformed selection input"))?;
            Ok(
                borsh::to_vec(&crate::execution::select_transactions(&input, state)?)
                    .expect("selection indexes"),
            )
        })(),
        "evm:artifacts" => (|| {
            let artifacts =
                borsh::from_slice::<neutrin0_runtime_abi::ExecutionArtifacts>(&request.args)
                    .map_err(|_| String::from("malformed artifacts"))?;
            let metadata = borsh::from_slice(&artifacts.metadata)
                .map_err(|_| String::from("malformed EVM metadata"))?;
            let mut receipts = Vec::new();
            for bytes in artifacts.receipts {
                match borsh::from_slice::<crate::execution::ExecutionReceipt>(&bytes)
                    .map_err(|_| String::from("malformed EVM receipt"))?
                {
                    crate::execution::ExecutionReceipt::Ethereum(receipt) => receipts.push(receipt),
                    crate::execution::ExecutionReceipt::System(_) => (),
                }
            }
            Ok(
                borsh::to_vec(&neutrin0_runtime_abi::ethereum::EvmArtifacts { metadata, receipts })
                    .expect("artifact projection"),
            )
        })(),
        "evm:environment" => {
            (|| Ok(borsh::to_vec(&crate::environment::load(state)?).expect("environment query")))()
        }
        "evm:next_base_fee" => (|| {
            Ok(borsh::to_vec(&read_record::<crate::fees::FeeState, _>(
                state,
                crate::fees::FEE_STATE_KEY,
            )?)
            .expect("fee query"))
        })(),
        _ => return neutrin0_runtime_system::query(request, state),
    };
    match result {
        Ok(payload) => QueryResponse::ok(payload),
        Err(error) => QueryResponse::err(QueryStatus::MethodError, error.into_bytes()),
    }
}

fn transaction_projection(args: &[u8]) -> Result<Vec<u8>, String> {
    let (chain_id, bytes): (u64, Vec<u8>) =
        borsh::from_slice(args).map_err(|_| String::from("malformed transaction query"))?;
    let neutrin0_runtime_abi::RuntimeTransaction::User(raw) =
        borsh::from_slice(&bytes).map_err(|_| String::from("malformed transaction envelope"))?
    else {
        return Err("system envelopes have no Ethereum transaction projection".into());
    };
    let decoded = crate::transaction::decode(&raw, chain_id)?;
    let signature = decoded.envelope.signature();
    let access_list = decoded
        .envelope
        .access_list()
        .map_or_else(Vec::new, |list| {
            list.iter()
                .map(|entry| {
                    (
                        entry.address.into_array(),
                        entry.storage_keys.iter().map(|slot| slot.0).collect(),
                    )
                })
                .collect()
        });
    let authorization_list = decoded
        .envelope
        .authorization_list()
        .map_or_else(Vec::new, |list| {
            list.iter()
                .map(
                    |authorization| neutrin0_runtime_abi::ethereum::EvmAuthorization {
                        chain_id: authorization.inner().chain_id().to_be_bytes(),
                        address: authorization.inner().address().into_array(),
                        nonce: authorization.inner().nonce(),
                        y_parity: authorization.y_parity(),
                        r: authorization.r().to_be_bytes(),
                        s: authorization.s().to_be_bytes(),
                    },
                )
                .collect()
        });
    let transaction = neutrin0_runtime_abi::ethereum::EvmTransaction {
        hash: decoded.hash.0,
        from: decoded.sender.into_array(),
        to: decoded.envelope.to().map(Address::into_array),
        nonce: decoded.environment.nonce,
        transaction_type: decoded.environment.tx_type,
        chain_id,
        gas_limit: decoded.environment.gas_limit,
        fee_cap: decoded.environment.gas_price,
        tip_cap: decoded.environment.gas_priority_fee,
        value: decoded.environment.value.to_be_bytes(),
        input: decoded.environment.data.to_vec(),
        access_list,
        authorization_list,
        y_parity: signature.v(),
        r: signature.r().to_be_bytes(),
        s: signature.s().to_be_bytes(),
    };
    Ok(borsh::to_vec(&transaction).expect("transaction projection"))
}
