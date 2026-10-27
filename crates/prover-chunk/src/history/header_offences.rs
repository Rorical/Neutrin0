//! Offences a signed header establishes: double proposals, DA commitment
//! fraud and execution claims a valid receipt contradicts (design 08).

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{BlockProof, DaFraudProof, Header};
use neutrin0_primitives::{ChainSpec, Hash, Validator};

use super::HistoryError;
use super::offences::{OffenceContext, active_validator, invalid};
use super::penalties::{
    PENALTY_DA_COMMITMENT_FRAUD, PENALTY_DOUBLE_PROPOSAL, PENALTY_INVALID_EXECUTION, penalty_id,
};
use super::records::HistoricalView;
use crate::slashing;

/// The boundary without a header that `parent_hash` names, if any: the
/// specification's first boundary, or after a fork the original genesis,
/// which a fork keeps (design 20).
#[must_use]
pub fn headerless_parent(
    spec: &ChainSpec,
    parent_hash: &Hash,
) -> Option<neutrin0_primitives::ConsensusBoundary> {
    let first = neutrin0_primitives::ConsensusBoundary::first(spec);
    let genesis = neutrin0_primitives::ConsensusBoundary::genesis(spec);
    [first, genesis]
        .into_iter()
        .find(|boundary| boundary.block_hash == *parent_hash)
}

pub(super) fn authorize_double_proposal<'a>(
    context: &OffenceContext<'a, '_>,
    proposer_index: u32,
    header_a: &Header,
    header_b: &Header,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    let chunk_id = context.chunk_for_height(header_a.height)?;
    let (hash_a, hash_b) = (header_a.hash(), header_b.hash());
    if context.chunk_for_height(header_b.height)? != chunk_id
        || header_a.proposer_index != proposer_index
        || header_b.proposer_index != proposer_index
        || header_a.slot != header_b.slot
        || hash_a == hash_b
    {
        return Err(HistoryError::Evidence);
    }
    let record = context.record_at(chunk_id)?;
    let validator = active_validator(record.validators, proposer_index)?;
    for (header, hash) in [(header_a, &hash_a), (header_b, &hash_b)] {
        crate::proposer::verify_header_signature_with(
            header,
            hash,
            context.domain,
            record.validators,
            verifier,
        )
        .map_err(|_| HistoryError::Evidence)?;
    }
    Ok((
        validator,
        penalty_id(PENALTY_DOUBLE_PROPOSAL, validator, header_a.slot, 0),
    ))
}

pub(super) fn authorize_invalid_execution_claim<'a>(
    context: &OffenceContext<'a, '_>,
    proposer_index: u32,
    header: &Header,
    parent: Option<&Header>,
    receipt: &BlockProof,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    let record = context.record_at(context.chunk_for_height(header.height)?)?;
    let validator = active_validator(record.validators, proposer_index)?;
    let hash = header.hash();
    // The specification's first boundary and, after a fork, the
    // original genesis have no header and bind the pre-state
    // themselves; every other parent is a header. One form each.
    let headerless = headerless_parent(context.spec, &header.parent_hash);
    let (parent_hash, parent_height, state_root_before) = match (parent, headerless) {
        (None, Some(start)) => (start.block_hash, start.height, start.state_root),
        (Some(parent), None) => (parent.hash(), parent.height, parent.state_root),
        _ => return Err(HistoryError::Evidence),
    };
    if header.proposer_index != proposer_index
        || parent_hash != header.parent_hash
        || parent_height.checked_add(1) != Some(header.height)
    {
        return Err(HistoryError::Evidence);
    }
    crate::proposer::verify_header_signature_with(
        header,
        &hash,
        context.domain,
        record.validators,
        verifier,
    )
    .map_err(|_| HistoryError::Evidence)?;
    if !execution_claim_contradicted(
        header,
        state_root_before,
        receipt,
        &record,
        context
            .validators_root
            .unwrap_or_else(|| commitment(record.validators)),
        validator,
        context.domain.chain_id,
        context.block_key,
    ) {
        return Err(HistoryError::Evidence);
    }
    // The receipt must verify: a rejected receipt proves nothing.
    if !verifier.accepts_block(receipt, context.block_key)? {
        return Err(HistoryError::Evidence);
    }
    Ok((
        validator,
        penalty_id(PENALTY_INVALID_EXECUTION, validator, header.height, 0),
    ))
}

pub(super) fn authorize_da_commitment_fraud<'a>(
    context: &OffenceContext<'a, '_>,
    proposer_index: u32,
    header: &Header,
    fraud_proof: &DaFraudProof,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    let record = context.record_at(context.chunk_for_height(header.height)?)?;
    let validator = active_validator(record.validators, proposer_index)?;
    if header.proposer_index != proposer_index {
        return Err(HistoryError::Evidence);
    }
    slashing::verify_da_fraud_using(
        context.domain,
        record.validators,
        header,
        fraud_proof,
        verifier,
    )
    .map_err(invalid)?;
    Ok((
        validator,
        penalty_id(PENALTY_DA_COMMITMENT_FRAUD, validator, header.slot, 0),
    ))
}

/// Whether `receipt` attests the execution `header` declared and contradicts
/// its results (design 08): every input field equals the header-derived value
/// under the record's chunk, committee, seed and programs, and at least one
/// result field differs.
#[allow(clippy::too_many_arguments)] // Each authenticated binding of the claim.
fn execution_claim_contradicted(
    header: &Header,
    state_root_before: Hash,
    receipt: &BlockProof,
    record: &HistoricalView<'_>,
    validators_root: Hash,
    proposer: &Validator,
    chain_id: u64,
    block_key: &[u32; 8],
) -> bool {
    let pi = &receipt.public_inputs;
    let finalized = &pi.context.finalized;
    let hash = header.hash();
    let inputs = receipt.height == header.height
        && receipt.block_hash == hash
        && *pi.context == crate::execution::runtime_context(header, *finalized)
        && finalized.next_chunk_id == record.chunk.chunk_id
        && finalized.validators_root == validators_root
        && finalized.seed == *record.seed
        && finalized.programs.execution.block == *block_key
        && pi.chain_id == chain_id
        && pi.height == header.height
        && pi.parent_block_hash == header.parent_hash
        && pi.block_hash == hash
        && pi.state_root_before == state_root_before
        && pi.transactions_root == header.transactions_root
        && pi.vm_code_hash == finalized.programs.runtime_code_hash
        && pi.block_program == *block_key
        && pi.gas_limit == header.gas_limit
        && pi.proposer_address == proposer.withdrawal_credentials
        && pi.inputs_root == header.inputs_root;
    let results_differ = pi.state_root_after != header.state_root
        || pi.receipt_root != header.receipts_root
        || pi.runtime_extra != header.runtime_extra
        || pi.gas_used != header.gas_used;
    inputs && results_differ
}
