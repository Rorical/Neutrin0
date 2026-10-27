//! Abandoned heights: a signed block the canonical chain replaced after its
//! exclusive proof window (design 08).
#![allow(clippy::redundant_pub_crate)] // Crate-internal helper re-exported by the parent module.

use neutrin0_consensus_types::Header;
use neutrin0_consensus_types::evidence::MerkleOpening;
use neutrin0_primitives::{ChainSpec, ConsensusDomain, Hash, Validator};

use super::HistoryError;
use super::offences::active_validator;
use super::penalties::{PENALTY_ABANDONMENT, penalty_id};
use super::records::HistoricalChunk;

/// Authorize an abandoned height in `source`.
///
/// `canonical` is the finalized block at its height, opened in the chunk's
/// block hash root. `abandoned` was signed on the same finalized parent and
/// is not that block, and the canonical block's slot comes at least one
/// exclusive proof window after it: for that long the height waited on a
/// block no receipt carried into the chain. A block the canonical chain
/// replaced inside the window, or one built on a parent the chain dropped,
/// establishes nothing.
pub(crate) fn authorize_abandonment<'a>(
    spec: &ChainSpec,
    domain: ConsensusDomain,
    source: &'a HistoricalChunk,
    abandoned: &Header,
    canonical: &Header,
    opening: &MerkleOpening,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    let chunk = &source.chunk;
    let canonical_hash = canonical.hash();
    let abandoned_hash = abandoned.hash();
    let index = canonical
        .height
        .checked_sub(chunk.start_height)
        .filter(|_| canonical.height <= chunk.end_height)
        .ok_or(HistoryError::Evidence)?;
    let leaves = chunk
        .end_height
        .checked_sub(chunk.start_height)
        .and_then(|span| span.checked_add(1))
        .ok_or(HistoryError::Evidence)?;
    let replaced_late = abandoned
        .slot
        .checked_add(spec.consensus.proof_exclusive_slots)
        .is_some_and(|deadline| canonical.slot >= deadline);
    if opening.index != index
        || opening.count != leaves
        || !opening.verify_plain(canonical_hash, chunk.block_hash_root)
        || abandoned.height != canonical.height
        || abandoned.parent_hash != canonical.parent_hash
        || abandoned_hash == canonical_hash
        || !replaced_late
    {
        return Err(HistoryError::Evidence);
    }
    let validator = active_validator(&source.validators, abandoned.proposer_index)?;
    crate::proposer::verify_header_signature_with(
        abandoned,
        &abandoned_hash,
        domain,
        &source.validators,
        verifier,
    )
    .map_err(|_| HistoryError::Evidence)?;
    Ok((
        validator,
        penalty_id(PENALTY_ABANDONMENT, validator, abandoned.slot, 0),
    ))
}
