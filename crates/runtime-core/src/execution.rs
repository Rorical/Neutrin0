//! Runtime-independent transaction commitments and evidence input validation.

use neutrin0_consensus_types::evidence::EvidenceAnchor;
use neutrin0_runtime_abi::{RuntimeBlockInput, RuntimeTransaction};

/// Canonical commitment to runtime-specific receipts and block metadata.
pub fn artifacts_commitment(
    artifacts: &neutrin0_runtime_abi::ExecutionArtifacts,
) -> neutrin0_primitives::Hash {
    artifacts.commitment()
}

/// Maximum evidence prefix length, independent of runtime economic policy.
pub use neutrin0_runtime_abi::MAX_EVIDENCE_ADMISSIONS;

/// A malformed common execution input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeInputError {
    /// Committee opening does not match the authenticated boundary.
    Validators,
    /// Positive participation is unsorted, duplicated or outside its challenge window.
    Participation,
    /// Program-lane references exceed the lane bound or name an index
    /// outside their artifact.
    Programs,
    /// Malformed authenticated evidence anchor.
    Anchor,
    /// Evidence appears after a user transaction.
    Order,
    /// Evidence does not bind this chain, height or anchor.
    Binding,
    /// Too many evidence admissions.
    Cap,
}
impl RuntimeInputError {
    /// Fixed diagnostic shared by native, WASM and Guest execution.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Validators => "invalid active committee opening",
            Self::Participation => "invalid participation acknowledgements",
            Self::Programs => "invalid program-lane references",
            Self::Anchor => "invalid accountability anchor",
            Self::Order => "evidence admissions must precede ordinary transactions",
            Self::Binding => "evidence binding",
            Self::Cap => "evidence admission cap",
        }
    }
}

/// Check a common block input before receipt verification or state mutation.
///
/// # Errors
/// Rejects bad anchors, ordering, bindings or an excessive evidence prefix.
pub fn check_runtime_input(input: &RuntimeBlockInput) -> Result<(), RuntimeInputError> {
    use neutrin0_consensus_types::participation::{
        MAX_PARTICIPATION_ACKS, PARTICIPATION_CHALLENGE_CHUNKS,
    };
    if input.active_validators.len() > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS
        || neutrin0_consensus_types::evidence::commitment(&input.active_validators)
            != input.context.finalized.validators_root
    {
        return Err(RuntimeInputError::Validators);
    }
    let incoming = input.context.finalized.next_chunk_id;
    if input.participation.as_ref().is_some_and(|report| {
        report.absent.len() != report.absent_identities.len()
            || report.absent.len() > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS
            || report.present.len() > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS
    }) || input.participation_acks.len() > MAX_PARTICIPATION_ACKS
        // Sorted by chunk, so each source chunk is one run; no committee
        // holds more seats than this.
        || input
            .participation_acks
            .chunk_by(|first, second| first.chunk_id == second.chunk_id)
            .any(|run| run.len() > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS)
        || input.participation_acks.windows(2).any(|pair| {
            pair[0] >= pair[1]
                || (pair[0].chunk_id == pair[1].chunk_id && pair[0].identity == pair[1].identity)
        })
        || input.participation_acks.iter().any(|ack| {
            ack.chunk_id >= incoming
                || ack
                    .chunk_id
                    .checked_add(PARTICIPATION_CHALLENGE_CHUNKS)
                    .is_none_or(|deadline| incoming > deadline)
        })
    {
        return Err(RuntimeInputError::Participation);
    }
    if input.program_pieces.len() > neutrin0_consensus_types::MAX_PROGRAM_PIECES_PER_BLOCK
        || input
            .program_pieces
            .iter()
            .any(|piece| piece.count == 0 || piece.index >= piece.count)
    {
        return Err(RuntimeInputError::Programs);
    }
    // Design 08: the proving report derives from the same carried certificate
    // as the participation report and is bounded by the committee, the chunk
    // length and the ratification cap.
    if input.proving.as_ref().is_some_and(|report| {
        input
            .participation
            .as_ref()
            .is_some_and(|participation| participation.chunk_id != report.chunk_id)
            || report.committee.len() > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS
            || u64::try_from(report.entries.len())
                .is_ok_and(|entries| entries != input.evidence_anchor.chunk_size)
            || u64::try_from(report.entries.len()).is_err()
            || report.chunk_provers.len() > neutrin0_primitives::MAX_CHUNK_RATIFICATIONS as usize
    }) {
        return Err(RuntimeInputError::Participation);
    }
    check_evidence_admissions(
        input.chain_id,
        input.block_height,
        &input.evidence_anchor,
        &input.transactions,
    )
}

/// Check a body's evidence prefix without interpreting user payloads.
///
/// # Errors
/// Rejects bad anchors, ordering, bindings or an excessive evidence prefix.
pub fn check_evidence_admissions(
    chain_id: u64,
    height: u64,
    anchor: &EvidenceAnchor,
    transactions: &[RuntimeTransaction],
) -> Result<(), RuntimeInputError> {
    if !anchor.is_well_formed() {
        return Err(RuntimeInputError::Anchor);
    }
    let mut ordinary = false;
    let mut count = 0_u32;
    for transaction in transactions {
        if let RuntimeTransaction::SubmitEvidence(submission) = transaction {
            if ordinary {
                return Err(RuntimeInputError::Order);
            }
            if !submission.binds(chain_id, height, anchor) {
                return Err(RuntimeInputError::Binding);
            }
            count = count.checked_add(1).ok_or(RuntimeInputError::Cap)?;
        } else {
            ordinary = true;
        }
    }
    if count > MAX_EVIDENCE_ADMISSIONS {
        return Err(RuntimeInputError::Cap);
    }
    Ok(())
}

/// Whether the common public output binds the exact input and actual state roots.
/// Economic results and receipt encoding remain runtime-defined.
#[must_use]
pub fn output_binds_input(
    input: &RuntimeBlockInput,
    output: &neutrin0_runtime_abi::RuntimeBlockOutput,
    pre_state_root: neutrin0_primitives::Hash,
    post_state_root: neutrin0_primitives::Hash,
) -> bool {
    let (transactions_root, summary) = transaction_commitments(&input.transactions);
    // Design 08: a block before its chunk's carrier consumes no new report
    // and commits the start boundary's.
    let boundary = &input.context.finalized;
    let participation = input.participation.as_ref().map_or(
        boundary.participation,
        neutrin0_consensus_types::participation::ParticipationReport::commitment,
    );
    let proving = input.proving.as_ref().map_or(
        boundary.proving,
        neutrin0_consensus_types::proving::ProvingReport::commitment,
    );
    output.context == input.context
        && output.chain_id == input.chain_id
        && output.block_height == input.block_height
        && output.block_gas_limit == input.block_gas_limit
        && output.proposer_address == input.proposer_address
        && output.participation == participation
        && output.proving == proving
        && output.participation_acks
            == neutrin0_consensus_types::participation::acknowledgement_commitment(
                &input.participation_acks,
            )
        && output.program_pieces
            == neutrin0_consensus_types::program_pieces_commitment(&input.program_pieces)
        && output.accountability.anchor == input.evidence_anchor
        && output.pre_state_root == pre_state_root
        && output.post_state_root == post_state_root
        && output.transactions_root == transactions_root
        && output.transaction_summary == summary
        && output.gas_used <= input.block_gas_limit
}

/// Commit every canonical transaction envelope and its exact count.
/// Each leaf includes its Borsh length prefix, matching the block body's root.
///
/// # Panics
/// Panics when a transaction count or byte length exceeds the Borsh u32 bound.
#[must_use]
pub fn transaction_commitments(
    transactions: &[RuntimeTransaction],
) -> (
    neutrin0_primitives::Hash,
    neutrin0_runtime_abi::TransactionSummary,
) {
    let count = u32::try_from(transactions.len()).expect("transaction count fits borsh");
    let mut leaves = alloc::vec::Vec::with_capacity(transactions.len());
    for tx in transactions {
        let length =
            u32::try_from(borsh::object_length(tx).expect("canonical transaction envelope"))
                .expect("transaction length fits borsh");
        // `neutrin0_primitives::transaction_leaf` over the length-prefixed
        // encoding, streamed without materializing it.
        let mut prefix = [0; 20];
        prefix[..16].copy_from_slice(&neutrin0_primitives::DOMAIN_TX_LEAF);
        prefix[16..].copy_from_slice(&length.to_le_bytes());
        leaves.push(neutrin0_consensus_types::hashing::borsh_commitment(
            &prefix, tx,
        ));
    }
    (
        neutrin0_primitives::transactions_root(leaves),
        neutrin0_runtime_abi::TransactionSummary {
            transaction_count: count,
        },
    )
}

#[cfg(test)]
mod tests;
