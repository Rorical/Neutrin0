//! Queries answered over a disposable execution of the pending candidate block.

use super::{call_query, query_regular};
use alloc::{string::String, vec::Vec};
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, QueryStatus};
use neutrin0_runtime_core::{StateBackend, overlay::OverlayState};

pub(super) fn pending_query<B: StateBackend>(
    request: &QueryRequest,
    state: &mut B,
) -> QueryResponse {
    let mut run = || -> Result<Vec<u8>, String> {
        let pending: neutrin0_runtime_abi::ethereum::PendingRequest =
            borsh::from_slice(&request.args)
                .map_err(|_| String::from("malformed internal pending request"))?;
        let mut scratch = OverlayState::new(state);
        let head_local = pending.mode == neutrin0_runtime_abi::ethereum::PendingMode::HeadLocal;
        let (indexes, metadata) = if head_local {
            crate::execution::execute_pending_head(&pending.block, &mut scratch)?
        } else {
            let result = crate::execution::execute_pending(&pending.block, &mut scratch)?;
            let metadata = borsh::from_slice(&result.artifacts.metadata)
                .map_err(|_| String::from("pending metadata"))?;
            (
                result
                    .artifacts
                    .transaction_ids
                    .iter()
                    .map(|(index, _)| *index)
                    .collect(),
                metadata,
            )
        };
        if ["evm:call", "evm:estimate_gas"].contains(&pending.query.method.as_str()) {
            return call_query(&pending.query, &mut scratch, head_local);
        }
        if pending.query.method == "evm:block" {
            let mut transactions = Vec::new();
            for index in indexes {
                let raw = borsh::to_vec(&pending.block.transactions[index as usize])
                    .expect("pending envelope");
                let response = query_regular(
                    &QueryRequest {
                        method: "evm:transaction".into(),
                        args: borsh::to_vec(&(pending.block.chain_id, raw))
                            .expect("pending transaction"),
                    },
                    &mut scratch,
                );
                if !response.is_ok() {
                    return Err("pending transaction projection failed".into());
                }
                transactions.push(
                    borsh::from_slice(&response.payload)
                        .map_err(|_| String::from("pending transaction projection"))?,
                );
            }
            return Ok(
                borsh::to_vec(&neutrin0_runtime_abi::ethereum::PendingBlock {
                    mode: pending.mode,
                    number: pending.block.block_height,
                    parent_hash: pending.block.context.parent_block_hash,
                    gas_limit: pending.block.block_gas_limit,
                    metadata,
                    transactions,
                })
                .expect("pending block"),
            );
        }
        if pending.query.method == "evm:environment" {
            // Pending execution always leaves the authenticated head environment
            // behind, so the simulation reports it bare rather than optional.
            let environment = crate::environment::load(&mut scratch)?
                .ok_or("pending execution environment unavailable")?;
            return Ok(borsh::to_vec(&environment).expect("pending environment"));
        }
        if !["evm:account", "evm:code", "evm:storage"].contains(&pending.query.method.as_str()) {
            return Err("unsupported internal pending operation".into());
        }
        let response = query_regular(&pending.query, &mut scratch);
        if !response.is_ok() {
            return Err("pending query failed".into());
        }
        Ok(response.payload)
    };
    match run() {
        Ok(payload) => QueryResponse::ok(payload),
        Err(error) => QueryResponse::err(QueryStatus::MethodError, error.into_bytes()),
    }
}
