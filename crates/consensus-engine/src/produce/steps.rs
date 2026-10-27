//! The selection, execution and diff steps of block production.

extern crate alloc;

use alloc::vec::Vec;

use neutrin0_consensus_types::Body;
use neutrin0_primitives::{BlockHash, StateRoot};
use neutrin0_proof_system::{ErasedBlockExecutor, ExecutionOutcome};

use super::ProductionError;

/// Ask the runtime which user transactions of `body` to include, keeping the
/// leading evidence submissions, and retain exactly the selection in order.
pub(super) fn select_transactions<E>(
    executor: &dyn ErasedBlockExecutor,
    ctx: &neutrin0_proof_system::BlockExecutionContext,
    body: &mut Body,
    state: &neutrin0_trie::Trie,
) -> Result<(), ProductionError<E>> {
    let selection_input = neutrin0_runtime_abi::RuntimeBlockInput {
        context: ctx.context,
        active_validators: ctx.active_validators.clone(),
        evidence_anchor: ctx.evidence_anchor,
        chain_id: ctx.chain_id,
        block_height: ctx.block_height,
        block_gas_limit: ctx.gas_limit,
        proposer_address: ctx.proposer_address,
        participation: ctx.participation.clone(),
        proving: ctx.proving.clone(),
        participation_acks: ctx.participation_acks.clone(),
        program_pieces: ctx.program_pieces.clone(),
        transactions: body
            .transactions
            .iter()
            .map(|bytes| borsh::from_slice(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ProductionError::Executor(error.to_string()))?,
    };
    let request = neutrin0_runtime_abi::QueryRequest {
        method: "runtime:select_transactions".into(),
        args: borsh::to_vec(&selection_input)
            .map_err(|error| ProductionError::Executor(error.to_string()))?,
    };
    let response = executor
        .query(&request, ctx.runtime_code_hash, state)
        .map_err(ProductionError::Executor)?;
    if !response.is_ok() {
        return Err(ProductionError::Executor(
            "runtime transaction selection failed".into(),
        ));
    }
    let selected: Vec<u32> = borsh::from_slice(&response.payload)
        .map_err(|error| ProductionError::Executor(error.to_string()))?;
    let evidence_count = selection_input
        .transactions
        .iter()
        .take_while(|tx| {
            matches!(
                tx,
                neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(_)
            )
        })
        .count();
    let mut indexes = alloc::collections::BTreeSet::new();
    let mut transactions = body.transactions[..evidence_count].to_vec();
    for index in selected {
        let index = usize::try_from(index)
            .map_err(|_| ProductionError::Executor("selection index overflow".into()))?;
        if index < evidence_count || !indexes.insert(index) {
            return Err(ProductionError::Executor(
                "runtime selected a duplicate or system envelope".into(),
            ));
        }
        transactions.push(
            body.transactions
                .get(index)
                .ok_or_else(|| ProductionError::Executor("runtime selection outside input".into()))?
                .clone(),
        );
    }
    body.transactions = transactions;
    Ok(())
}

/// Execute `body` on `state` and require a proving input within the chain's
/// ceiling and artifacts matching their committed root.
pub(super) fn execute_body<E>(
    executor: &dyn ErasedBlockExecutor,
    ctx: &neutrin0_proof_system::BlockExecutionContext,
    body: &Body,
    state: &mut neutrin0_trie::Trie,
) -> Result<ExecutionOutcome, ProductionError<E>> {
    let outcome = executor
        .execute_block(ctx, body, state)
        .map_err(ProductionError::Executor)?;

    if !ctx
        .evidence_anchor
        .accepts_proving_input_size(u64::try_from(outcome.witness_bytes.len()).unwrap_or(u64::MAX))
    {
        return Err(ProductionError::WitnessTooLarge {
            actual: outcome.witness_bytes.len(),
            limit: ctx.evidence_anchor.max_block_proving_input_bytes,
        });
    }
    if outcome.artifacts.commitment() != outcome.receipts_root {
        return Err(ProductionError::Executor(
            "execution artifact commitment mismatch".into(),
        ));
    }
    Ok(outcome)
}

/// The diff proof-following nodes receive. It is a transport artifact, so
/// honest production keeps it within the ceiling those nodes accept.
pub(super) fn produced_state_diff<E>(
    height: u64,
    block_hash: BlockHash,
    state_root_before: StateRoot,
    state_root_after: StateRoot,
    writes: Vec<neutrin0_consensus_types::StateWrite>,
) -> Result<neutrin0_consensus_types::BlockStateDiff, ProductionError<E>> {
    let state_diff = neutrin0_consensus_types::BlockStateDiff {
        height,
        block_hash,
        state_root_before,
        state_root_after,
        writes,
    };
    let diff_bytes = borsh::object_length(&state_diff)
        .map_err(|error| ProductionError::Executor(error.to_string()))?;
    if diff_bytes > neutrin0_primitives::MAX_STATE_DIFF_BYTES {
        return Err(ProductionError::StateDiffTooLarge {
            actual: diff_bytes,
            limit: neutrin0_primitives::MAX_STATE_DIFF_BYTES,
        });
    }
    Ok(state_diff)
}
