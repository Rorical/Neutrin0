//! Selective durable accountability storage, independent of ordinary source pruning.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::FinalityVotePhase;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history::HistorySubtree;
use neutrin0_consensus_types::history_proof::ConsensusBoundary;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_primitives::{BlsPublicKey, Hash, Validator};
use neutrin0_prover_chunk::history::{HistoricalChunk, HistoricalOpening};
use neutrin0_storage::{Batch, BatchOp, Column, Database};

use super::{ChainStore, StoreError};

mod eligibility;
mod headers;
mod history;
mod sources;
mod statements;
mod validate;

#[cfg(test)]
mod tests;

/// `ReporterIndex` tag: source identity to its authenticated chunk.
const SOURCE_LOOKUP: u8 = 0;
/// `ReporterIndex` tag: header hash to every chunk retaining it.
const HEADER_LOOKUP: u8 = 1;
/// `ReporterIndex` tag: per-chunk source inventory entry.
const SOURCE_INVENTORY: u8 = 2;
/// `ReporterIndex` tag: watched historical chunk, valued by its leaf commitment.
const CHUNK_LOOKUP: u8 = 3;
/// `ReporterIndex` tag: complete History subtree root that opens a watched chunk.
pub(super) const SUBTREE: u8 = 4;
/// `ReporterIndex` tag: watched chunk a snapshot jump left unopenable.
const DORMANT: u8 = 5;
/// `ReporterIndex` tag: one owner's retained signed statement, keyed by chunk,
/// owner, round (a header's slot), step and content, valued by the identity of
/// the source or header holding it.
const STATEMENT: u8 = 6;

/// Statement step of a signed header, after the BFT vote, proposal and
/// round-change steps.
const HEADER_STEP: u8 = 6;
/// Differing statements one owner keeps per chunk, round and step: two that
/// conflict already prove an equivocation, and re-bundled copies of one
/// statement count once.
const STATEMENTS_PER_STEP: usize = 2;
/// Statements one owner keeps per chunk. Honest rounds are few and low, so the
/// highest-round statement yields to a lower one.
const STATEMENTS_PER_OWNER: usize = 256;
/// Statement key bytes before the round: tag, chunk and owner.
const OWNER_PREFIX: usize = 1 + 8 + 48;
/// Statement key bytes before the content commitment: owner prefix, round and step.
const STEP_PREFIX: usize = OWNER_PREFIX + 8 + 1;

#[derive(BorshSerialize, BorshDeserialize)]
pub(super) struct Owned<T> {
    pub(super) owners: Vec<BlsPublicKey>,
    pub(super) value: T,
}

/// Serialize-only borrowed twin of [`Owned`] with an identical encoding.
#[derive(BorshSerialize)]
struct OwnedRef<'a, T> {
    owners: &'a [BlsPublicKey],
    value: &'a T,
}

struct ReporterContext {
    validators: Vec<Validator>,
    owners: Vec<BlsPublicKey>,
}

fn source_key(chunk: u64, id: Hash) -> [u8; 40] {
    let mut key = [0; 40];
    key[..8].copy_from_slice(&chunk.to_be_bytes());
    key[8..].copy_from_slice(&id);
    key
}

fn lookup_key(kind: u8, hash: &Hash) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = kind;
    key[1..].copy_from_slice(hash);
    key
}

fn inventory_key(chunk: u64, hash: Hash) -> [u8; 41] {
    let mut key = [0; 41];
    key[0] = SOURCE_INVENTORY;
    key[1..].copy_from_slice(&source_key(chunk, hash));
    key
}

fn chunk_lookup_key(chunk: u64) -> [u8; 9] {
    let mut key = [CHUNK_LOOKUP; 9];
    key[1..].copy_from_slice(&chunk.to_be_bytes());
    key
}

fn subtree_key(level: u8, start: u64) -> [u8; 10] {
    let mut key = [SUBTREE; 10];
    key[1] = level;
    key[2..].copy_from_slice(&start.to_be_bytes());
    key
}

fn dormant_key(chunk: u64) -> [u8; 9] {
    let mut key = [DORMANT; 9];
    key[1..].copy_from_slice(&chunk.to_be_bytes());
    key
}

fn statement_key(
    chunk: u64,
    owner: &BlsPublicKey,
    order: u64,
    step: u8,
    statement: &Hash,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(STEP_PREFIX + statement.len());
    key.push(STATEMENT);
    key.extend_from_slice(&chunk.to_be_bytes());
    key.extend_from_slice(owner);
    key.extend_from_slice(&order.to_be_bytes());
    key.push(step);
    key.extend_from_slice(statement);
    key
}

fn put_subtrees(batch: &mut Batch, subtrees: impl IntoIterator<Item = HistorySubtree>) {
    for subtree in subtrees {
        batch.put(
            Column::ReporterIndex,
            subtree_key(subtree.level, subtree.start),
            subtree.root,
        );
    }
}

/// Each signer's own statement in `artifact`: validator index, round, step
/// and content commitment. Re-bundled copies of one statement agree. Steps are
/// value prevote 0 and precommit 1, nil prevote 2 and precommit 3, proposal 4
/// and round change 5, alone or inside a certificate; headers use
/// [`HEADER_STEP`].
fn signed_statements(artifact: &SignedArtifact) -> Vec<(u32, u64, u8, Hash)> {
    let step = |phase: FinalityVotePhase, prevote: u8| match phase {
        FinalityVotePhase::Prevote => prevote,
        FinalityVotePhase::Precommit => prevote + 1,
    };
    match artifact {
        SignedArtifact::Vote(vote) => vote
            .attestations
            .iter()
            .map(|claim| {
                let round = u64::from(claim.vote.round);
                (
                    claim.validator_index,
                    round,
                    step(claim.vote.phase, 0),
                    commitment(claim),
                )
            })
            .collect(),
        SignedArtifact::NilVote(vote) => vote
            .attestations
            .iter()
            .map(|claim| {
                let round = u64::from(claim.vote.round);
                (
                    claim.validator_index,
                    round,
                    step(claim.vote.phase, 2),
                    commitment(claim),
                )
            })
            .collect(),
        SignedArtifact::Proposal(proposal) => vec![(
            proposal.proposer_index,
            u64::from(proposal.round),
            4,
            artifact.id(),
        )],
        SignedArtifact::RoundChange(report) => vec![(
            report.validator_index,
            u64::from(report.round),
            5,
            commitment(report),
        )],
        SignedArtifact::RoundChangeCertificate(certificate) => certificate
            .reports
            .iter()
            .map(|report| {
                (
                    report.validator_index,
                    u64::from(report.round),
                    5,
                    commitment(report),
                )
            })
            .collect(),
        SignedArtifact::Quorum(_) | SignedArtifact::BlockProof(_) => Vec::new(),
    }
}

fn validate_addresses<E>(addresses: &[[u8; 32]]) -> Result<(), StoreError<E>> {
    if addresses.is_empty() || addresses.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(StoreError::Corrupt(
            "reporter withdrawal addresses are not canonical",
        ));
    }
    Ok(())
}

/// Stage one owned entry without cloning its owners or value.
fn put_owned<E, T: BorshSerialize>(
    batch: &mut Batch,
    column: Column,
    key: impl Into<Vec<u8>>,
    owners: &[BlsPublicKey],
    value: &T,
) -> Result<(), StoreError<E>> {
    batch.put(column, key, borsh::to_vec(&OwnedRef { owners, value })?);
    Ok(())
}

/// Stage a watched chunk's leaf, the complete subtrees its current opening
/// reveals and its owned record.
fn put_reporter_opening_batch<E>(
    batch: &mut Batch,
    opening: &HistoricalOpening,
    owners: &[BlsPublicKey],
) -> Result<(), StoreError<E>> {
    let chunk = opening.record.chunk.chunk_id;
    batch.put(
        Column::ReporterIndex,
        chunk_lookup_key(chunk),
        commitment(&opening.record.evidence_context()),
    );
    put_subtrees(batch, opening.path.complete_siblings());
    batch.delete(Column::ReporterIndex, dormant_key(chunk));
    put_owned(
        batch,
        Column::ReporterHistory,
        chunk.to_be_bytes(),
        owners,
        &opening.record,
    )
}

/// Save a historical program boundary needed by retained exact proof envelopes.
fn put_reporter_boundary_batch<E>(
    batch: &mut Batch,
    record: &HistoricalChunk,
    boundary: &ConsensusBoundary,
) -> Result<(), StoreError<E>> {
    let owners: Vec<_> = record
        .validators
        .iter()
        .filter(|v| v.effective_stake > 0)
        .map(|v| v.pubkey)
        .collect();
    put_owned(
        batch,
        Column::ReporterBoundaries,
        boundary.next_chunk_id.to_be_bytes(),
        &owners,
        boundary,
    )
}

impl<DB: Database> ChainStore<DB> {
    /// Decode `(column, key)` as `batch` would leave it: the batch's latest
    /// write to that key overrides the database. A merge staged twice in one
    /// batch therefore keeps the owners its earlier write added.
    fn staged_decoded<T: BorshDeserialize>(
        &self,
        batch: &Batch,
        column: Column,
        key: &[u8],
    ) -> Result<Option<T>, StoreError<DB::Error>> {
        for op in batch.operations().iter().rev() {
            let (written_column, written_key, value) = match op {
                BatchOp::Put { column, key, value } => (*column, key, Some(value)),
                BatchOp::Delete { column, key } => (*column, key, None),
                BatchOp::AddCount { .. } => continue,
            };
            if written_column == column && written_key.as_slice() == key {
                return match value {
                    Some(bytes) => Ok(Some(T::try_from_slice(bytes)?)),
                    None => Ok(None),
                };
            }
        }
        self.get_decoded(column, key)
    }
}

/// The chunk of a raw report's source height under `chunk_size`.
fn reporter_chunk_for_height<E>(height: u64, chunk_size: u64) -> Result<u64, StoreError<E>> {
    height
        .checked_sub(1)
        .and_then(|h| h.checked_div(chunk_size))
        .ok_or(StoreError::Corrupt("reporter raw source height"))
}
