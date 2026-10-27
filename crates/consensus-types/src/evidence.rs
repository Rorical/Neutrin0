//! Compact, recursively authenticated offence statements and historical openings.

mod merkle;
#[cfg(test)]
mod tests;

pub use merkle::{MerkleOpening, counted_merkle_root};

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{Hash, Validator, merkle_root_from_hashes};

/// Maximum encoded SP1 evidence receipt accepted from the network.
pub const MAX_EVIDENCE_PROOF_BYTES: usize = 2 * 1024 * 1024;

/// Finalized historical context, independent of a certificate's signer subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceContext {
    /// Canonical historical chunk index.
    pub chunk_id: u64,
    /// Commitment to the complete canonical chunk.
    pub chunk_hash: Hash,
    /// Last height of the source chunk; used for the evidence admission window.
    pub end_height: u64,
    /// Historical validator identities and weights.
    pub validators_root: Hash,
    /// Randomness effective during the source chunk.
    pub seed: Hash,
    /// Block program authenticated at the source chunk's start boundary.
    pub source_block_guest_vk_digest: [u32; 8],
    /// WASM runtime authenticated at the same historical boundary.
    pub source_runtime_code_hash: Hash,
    /// Commitment of the source chunk's start boundary, which lets a later
    /// boundary's history root authenticate it as an ancestor (design 13).
    pub start_boundary: Hash,
}

/// Proven sanction class. Liveness classes do not imply Byzantine behaviour.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum SanctionKind {
    /// Objective signed misconduct; excludes the identity from future sets.
    Slash,
    /// Non-inclusion in a particular authenticated finality certificate.
    Inactivity,
    /// A signed block the canonical chain replaced after its exclusive
    /// proof window (design 08).
    Abandonment,
}

impl SanctionKind {
    /// Safety offences are admitted once per identity with no age window;
    /// every other class is a liveness offence admitted once per offence
    /// within the governed window.
    #[must_use]
    pub const fn is_safety(self) -> bool {
        matches!(self, Self::Slash)
    }
}

/// Public values committed by the evidence guest, with no raw evidence bytes.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceStatement {
    /// Chain/domain separation.
    pub chain_id: u64,
    /// Full rule configuration used to decide the offence.
    pub chain_spec_hash: Hash,
    /// Current block program required by the consuming admission anchor.
    pub block_guest_vk_digest: [u32; 8],
    /// Historical context whose inclusion the block authenticates.
    pub context: EvidenceContext,
    /// Stable identity, withdrawal account and historical stake.
    pub offender: Validator,
    /// Punishment class.
    pub kind: SanctionKind,
    /// Canonical event ID, independent of the proof or evidence encoding.
    pub offence_id: Hash,
    /// Commitment to the exact signed evidence used by the prover.
    pub facts_commitment: Hash,
    /// Optional reward account, bound by the evidence receipt and its membership.
    pub reporter: Option<[u8; 32]>,
}

/// Consensus evidence claim, including its current history opening.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceSubmission {
    /// Public statement authenticated by the receipt.
    pub statement: EvidenceStatement,
    /// Inclusion in the block's incoming trusted historical root.
    pub history: crate::history::HistoryPath,
}

/// Maximum offence statements committed by one Evidence Guest receipt.
pub const MAX_EVIDENCE_BATCH: usize = 16;

/// Compact public values of the batch Evidence Guest.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceBatch {
    /// Pinned program authenticating all reused cryptographic facts.
    pub fact_guest_vk_digest: [u32; 8],
    /// Exact number of unique statements.
    pub count: u32,
    /// Ordered Merkle commitment to canonical statement hashes.
    pub root: Hash,
}

impl EvidenceBatch {
    /// Construct the committed batch and reject duplicate offence identities.
    pub fn new(statements: &[EvidenceStatement], fact_guest_vk_digest: [u32; 8]) -> Option<Self> {
        if statements.is_empty() || statements.len() > MAX_EVIDENCE_BATCH {
            return None;
        }
        let mut seen = alloc::collections::BTreeSet::new();
        if statements
            .iter()
            .any(|statement| !seen.insert(statement.offence_id))
        {
            return None;
        }
        Some(Self {
            fact_guest_vk_digest,
            count: u32::try_from(statements.len()).ok()?,
            root: merkle_root_from_hashes(statements.iter().map(commitment).collect()),
        })
    }
}

/// Select one offence from a reusable batch without binding its proof to a transaction.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceMembership {
    /// Exact batch public values.
    pub batch: EvidenceBatch,
    /// Counted opening in the batch's ordered statement Merkle tree.
    pub opening: MerkleOpening,
}

impl EvidenceMembership {
    /// Build a canonical opening for an existing statement in a bounded batch.
    pub fn build(
        statements: &[EvidenceStatement],
        index: usize,
        fact_key: [u32; 8],
    ) -> Option<Self> {
        Some(Self {
            batch: EvidenceBatch::new(statements, fact_key)?,
            opening: MerkleOpening::build(
                &statements.iter().map(commitment).collect::<Vec<_>>(),
                index,
            )?,
        })
    }

    /// Authenticate a statement and the fact program used by the batch Guest.
    pub fn binds(&self, statement: &EvidenceStatement, fact_key: &[u32; 8]) -> bool {
        self.batch.fact_guest_vk_digest == *fact_key
            && self.batch.count > 0
            && self.batch.count as usize <= MAX_EVIDENCE_BATCH
            && self.opening.count == u64::from(self.batch.count)
            && self.opening.verify(
                commitment(statement),
                counted_merkle_root(self.opening.count, self.batch.root),
            )
    }
}

/// Reusable proof attachment, independent of today's Merkle opening.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceArtifact {
    /// Membership in the recursively authenticated batch.
    pub membership: EvidenceMembership,
    /// Evidence program identity, checked against the trusted execution anchor.
    pub evidence_guest_vk_digest: [u32; 8],
    /// Public values proved by the independent guest.
    pub statement: EvidenceStatement,
    /// Canonical compressed SP1 receipt bytes.
    pub proof_bytes: Vec<u8>,
}

/// Self-contained offence report for network relay and the durable evidence pool.
///
/// The reporter supplies the historical opening; a receiving node needs only
/// a trusted history root and the bounded append suffix to refresh this path.
/// Blocks keep the receipt as an independent [`EvidenceArtifact`] attachment
/// and commit the refreshed opening in their [`EvidenceSubmission`].
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize)]
pub struct EvidenceReport {
    /// Reusable independently proven offence.
    pub artifact: EvidenceArtifact,
    /// Historical context inclusion under an authenticated finalized root.
    pub history: crate::history::HistoryPath,
}

impl BorshDeserialize for EvidenceReport {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let membership = EvidenceMembership::deserialize_reader(reader)?;
        let evidence_guest_vk_digest = <[u32; 8]>::deserialize_reader(reader)?;
        let statement = EvidenceStatement::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)?;
        if length == 0 || length as usize > MAX_EVIDENCE_PROOF_BYTES {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "evidence report proof length",
            ));
        }
        let mut proof_bytes = alloc::vec![0; length as usize];
        reader.read_exact(&mut proof_bytes)?;
        Ok(Self {
            artifact: EvidenceArtifact {
                membership,
                evidence_guest_vk_digest,
                statement,
                proof_bytes,
            },
            history: crate::history::HistoryPath::deserialize_reader(reader)?,
        })
    }
}

impl EvidenceArtifact {
    /// Stable statement identity independent of the proof's encoding or nonce.
    #[must_use]
    pub fn statement_id(&self) -> Hash {
        crate::tagged_commitment(
            b"neutrin0-evidence-statement",
            &(
                self.evidence_guest_vk_digest,
                self.membership.batch.fact_guest_vk_digest,
                &self.statement,
            ),
        )
    }

    /// Match an attachment to the exact claim and trusted evidence program.
    /// Cryptographic verification remains the execution shell's obligation.
    #[must_use]
    pub fn binds(
        &self,
        statement: &EvidenceStatement,
        key: &[u32; 8],
        fact_key: &[u32; 8],
    ) -> bool {
        self.membership.binds(statement, fact_key)
            && self.evidence_guest_vk_digest == *key
            && self.statement == *statement
            && !self.proof_bytes.is_empty()
            && self.proof_bytes.len() <= MAX_EVIDENCE_PROOF_BYTES
    }
}

/// Incoming block authorization context. The chunk authenticates every field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceAnchor {
    /// Trusted early cryptographic-fact program.
    pub fact_guest_vk_digest: [u32; 8],
    /// Full chain specification commitment.
    pub chain_spec_hash: Hash,
    /// Number of previously finalized historical chunks.
    pub chunk_id: u64,
    /// Counted historical context commitment.
    pub history_root: Hash,
    /// Trusted block program for proof-rejection claims.
    pub block_guest_vk_digest: [u32; 8],
    /// Trusted evidence program for recursive receipt verification.
    pub evidence_guest_vk_digest: [u32; 8],
    /// Genesis-fixed unbonding delay in blocks. Withdrawal maturity, marker
    /// retention and the upper bound of the liveness window derive from it.
    pub unbonding_delay_blocks: u64,
    /// Genesis-fixed blocks per chunk.
    pub chunk_size: u64,
    /// Chain-spec-bound allocation limit for one block proving envelope.
    pub max_block_proving_input_bytes: u64,
    /// Chain-spec block gas ceiling, bounding mandatory work and participation challenges.
    pub block_gas_limit: u64,
}

impl EvidenceAnchor {
    /// Absolute decoder allocation ceiling before an anchor can be decoded.
    pub const MAX_PROVING_INPUT_BYTES: u64 = neutrin0_primitives::MAX_BLOCK_PROVING_INPUT_BYTES;

    /// Whether an encoded block input fits this authenticated allocation limit.
    #[must_use]
    pub const fn accepts_proving_input_size(&self, bytes: u64) -> bool {
        self.is_well_formed() && bytes <= self.max_block_proving_input_bytes
    }

    /// Timeline the anchor must satisfy for any admission to be sound: the
    /// unbonding delay exceeds one chunk, so consensus observes a zero stake
    /// at a boundary before a validator record can be retired.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        self.chunk_size > 0
            && self.unbonding_delay_blocks > self.chunk_size
            && self.block_gas_limit > 0
            && self.max_block_proving_input_bytes > 0
            && self.max_block_proving_input_bytes
                <= neutrin0_primitives::MAX_BLOCK_PROVING_INPUT_BYTES
    }
}

impl Default for EvidenceAnchor {
    /// Zero program and history identities with the canonical consensus
    /// facts, so a default anchor is a usable test input while the STF keeps
    /// asserting the real invariants.
    fn default() -> Self {
        Self {
            fact_guest_vk_digest: [0; 8],
            chain_spec_hash: [0; 32],
            chunk_id: 0,
            history_root: [0; 32],
            block_guest_vk_digest: [0; 8],
            evidence_guest_vk_digest: [0; 8],
            unbonding_delay_blocks: neutrin0_primitives::DEFAULT_UNBONDING_DELAY_BLOCKS,
            chunk_size: neutrin0_primitives::DEFAULT_CHUNK_SIZE,
            max_block_proving_input_bytes:
                neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
            block_gas_limit: 30_000_000,
        }
    }
}

/// Canonical Borsh commitment of a value under its type's own domain tag,
/// so two types with byte-identical encodings never share a commitment.
pub fn commitment<T: crate::hashing::Committed + ?Sized>(value: &T) -> Hash {
    crate::hashing::borsh_commitment(&T::COMMITMENT_TAG, value)
}

impl EvidenceSubmission {
    /// Cheap authenticated-input bindings, shared by the runtime and native
    /// admission. This does not replace verification of the SP1 receipt.
    ///
    /// Liveness claims must reference one of the eight preceding finalized
    /// chunks. Safety claims may reference any finalized chunk: the runtime
    /// admits them while the offender still holds slashable balance, and the
    /// fixed-depth history opening costs the same at any age.
    pub fn binds(&self, chain_id: u64, height: u64, anchor: &EvidenceAnchor) -> bool {
        let statement = &self.statement;
        let source = statement.context.chunk_id;
        // Safety claims cite any finalized chunk: their admissibility is the
        // offender's remaining slashable balance, checked by the runtime, not
        // the age of the signature. Liveness claims keep the eight-chunk rule.
        let in_window = if statement.kind.is_safety() {
            source < anchor.chunk_id
        } else {
            crate::history::is_recent_history_index(source, anchor.chunk_id)
        };
        statement.chain_id == chain_id
            && statement.chain_spec_hash == anchor.chain_spec_hash
            && statement.block_guest_vk_digest == anchor.block_guest_vk_digest
            && self.history.index == source
            && self.history.count == anchor.chunk_id
            && in_window
            && self
                .history
                .verify(commitment(&statement.context), anchor.history_root)
            && statement.context.end_height < height
    }

    /// `true` while a liveness offence is still admissible under
    /// `max_age_blocks` after its source chunk's last block. Safety offences
    /// have no age window and always pass.
    #[must_use]
    pub const fn within_age(&self, height: u64, max_age_blocks: u64) -> bool {
        let end = self.statement.context.end_height;
        if self.statement.kind.is_safety() {
            end < height
        } else {
            end < height && height - end <= max_age_blocks
        }
    }
}
