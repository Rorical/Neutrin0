//! Independent evidence-guest statement construction. No deduction happens here.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::{
    Header, QuorumCertificate, SlashingEvidence,
    evidence::{EvidenceContext, EvidenceStatement, MerkleOpening, SanctionKind},
};
use neutrin0_primitives::{ChainSpec, ConsensusDomain};

use crate::history::{
    HistoricalChunk, HistoryError, PENALTY_INACTIVITY, authorize_evidence_with, penalty_id,
};
use neutrin0_consensus_types::evidence::commitment;

/// Upper bound on authenticated fact statements one evidence batch may carry.
pub const MAX_EVIDENCE_FACT_STATEMENTS: usize = 256;

/// Self-contained witness classes accepted by the evidence program.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[allow(clippy::large_enum_variant)] // One bounded claim per witness; no repeated array of enum slots.
pub enum EvidenceClaim {
    /// Objectively attributable signed misconduct.
    Slash(SlashingEvidence),
    /// Absence from this exact precommit quorum for an already finalized chunk.
    Inactivity {
        /// Historical validator index.
        validator_index: u32,
        /// Authenticated aggregate and vote data, not a host-selected bitmap.
        certificate: QuorumCertificate,
    },
    /// A signed block the canonical chain replaced after its exclusive proof
    /// window (design 08).
    Abandonment {
        /// The signed header no receipt carried into the chain.
        abandoned: Header,
        /// The canonical block at the same height.
        canonical: Header,
        /// Opening of `canonical` in the source chunk's block hash root.
        opening: MerkleOpening,
    },
}

impl neutrin0_consensus_types::hashing::Committed for EvidenceClaim {
    const COMMITMENT_TAG: neutrin0_primitives::DomainTag =
        neutrin0_primitives::DOMAIN_EVIDENCE_CLAIM;
}

/// Inputs to the independent SP1 evidence guest.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceWitness {
    /// Rules whose hash is authenticated by the consuming block.
    pub chain_spec: ChainSpec,
    /// Single historical context; no growing chain-history vector is needed.
    pub source: HistoricalChunk,
    /// Exact signed evidence or inactivity certificate.
    pub claim: EvidenceClaim,
    /// Current block program authenticated by the consuming admission anchor.
    pub block_guest_vk_digest: [u32; 8],
    /// Optional reward account committed into the proven statement.
    pub reporter: Option<[u8; 32]>,
}

/// Derive the public statement or fail closed. A resource failure never
/// substitutes for a verifier rejection verdict.
pub fn validate_evidence(input: &EvidenceWitness) -> Result<EvidenceStatement, HistoryError> {
    validate_evidence_using(input, &mut crate::bls::DirectVerifier::default())
}

/// Derive the same statement from already proven cryptographic facts.
pub fn validate_evidence_using(
    input: &EvidenceWitness,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<EvidenceStatement, HistoryError> {
    EvidenceValidation::default().validate(input, verifier)
}

/// Private checked data, never supplied as a trusted flag in the witness.
struct CheckedSpec<'a> {
    spec: &'a ChainSpec,
    domain: ConsensusDomain,
}

struct CheckedSource<'a> {
    spec: usize,
    source: &'a HistoricalChunk,
    context: EvidenceContext,
}

struct CheckedCertificate<'a> {
    source: usize,
    certificate: &'a QuorumCertificate,
}

/// One invocation's bounded memoization. Entries bind complete typed equality,
/// not merely a chunk id, numeric chain id, root, or signer bitmap. Its lifetime
/// prevents the immutable source/spec/certificate bytes changing after checking.
#[derive(Default)]
struct EvidenceValidation<'a> {
    specs: Vec<CheckedSpec<'a>>,
    sources: Vec<CheckedSource<'a>>,
    certificates: Vec<CheckedCertificate<'a>>,
}

impl<'a> EvidenceValidation<'a> {
    fn source(&mut self, input: &'a EvidenceWitness) -> Result<usize, HistoryError> {
        let spec = if let Some(index) = self
            .specs
            .iter()
            .position(|checked| checked.spec == &input.chain_spec)
        {
            index
        } else {
            input
                .chain_spec
                .validate()
                .map_err(|_| HistoryError::Anchor)?;
            let index = self.specs.len();
            self.specs.push(CheckedSpec {
                spec: &input.chain_spec,
                domain: input.chain_spec.consensus_domain(),
            });
            index
        };
        if let Some(index) = self
            .sources
            .iter()
            .position(|checked| checked.spec == spec && checked.source == &input.source)
        {
            return Ok(index);
        }
        let source = &input.source;
        let context = source.evidence_context();
        if source.chunk.active_validator_set_root != context.validators_root
            || source
                .chunk
                .chunk_id
                .checked_add(1)
                .and_then(|n| n.checked_mul(input.chain_spec.consensus.chunk_size))
                != Some(source.chunk.end_height)
        {
            return Err(HistoryError::Anchor);
        }
        let index = self.sources.len();
        self.sources.push(CheckedSource {
            spec,
            source,
            context,
        });
        Ok(index)
    }

    fn validate(
        &mut self,
        input: &'a EvidenceWitness,
        verifier: &mut impl crate::facts::EvidenceVerifier,
    ) -> Result<EvidenceStatement, HistoryError> {
        // The runtime pays a reporter only at a runtime account.
        if input
            .reporter
            .is_some_and(|reporter| !neutrin0_primitives::is_runtime_account(&reporter))
        {
            return Err(HistoryError::Evidence);
        }
        let source_index = self.source(input)?;
        let checked = &self.sources[source_index];
        let spec = self.specs[checked.spec].spec;
        let domain = self.specs[checked.spec].domain;
        let source = checked.source;
        let context = checked.context;
        let (offender, offence_id, kind) = match &input.claim {
            EvidenceClaim::Slash(evidence) => {
                let (validator, id) = authorize_evidence_with(
                    spec,
                    domain,
                    source,
                    Some(context.validators_root),
                    evidence,
                    &source.block_guest_vk_digest,
                    verifier,
                )?;
                (validator, id, SanctionKind::Slash)
            }
            EvidenceClaim::Inactivity {
                validator_index,
                certificate,
            } => {
                if !self.certificates.iter().any(|checked| {
                    checked.source == source_index && checked.certificate == certificate
                }) {
                    crate::history::verify_participation_using(
                        domain,
                        &spec.consensus,
                        source,
                        certificate,
                        verifier,
                    )?;
                    // Only a successful precommit-quorum verification is cached.
                    self.certificates.push(CheckedCertificate {
                        source: source_index,
                        certificate,
                    });
                }
                let validator = source
                    .validators
                    .get(*validator_index as usize)
                    .filter(|v| crate::finality::is_active(v))
                    .ok_or(HistoryError::Evidence)?;
                if certificate.aggregate.aggregation_bits.get(*validator_index) != Some(false) {
                    return Err(HistoryError::Evidence);
                }
                (
                    validator,
                    penalty_id(PENALTY_INACTIVITY, validator, source.chunk.chunk_id, 0),
                    SanctionKind::Inactivity,
                )
            }
            EvidenceClaim::Abandonment {
                abandoned,
                canonical,
                opening,
            } => {
                let (validator, id) = crate::history::authorize_abandonment(
                    spec, domain, source, abandoned, canonical, opening, verifier,
                )?;
                (validator, id, SanctionKind::Abandonment)
            }
        };
        Ok(EvidenceStatement {
            chain_id: spec.chain_id,
            chain_spec_hash: domain.chain_spec_hash,
            block_guest_vk_digest: input.block_guest_vk_digest,
            context,
            offender: offender.clone(),
            kind,
            offence_id,
            facts_commitment: commitment(&input.claim),
            reporter: input.reporter,
        })
    }
}

/// Validate a bounded set with shared, exactly bound specification/source checks.
///
/// All offence-specific checks and every reporter/statement binding still run.
/// A verifier used here must give immediate or explicitly authenticated answers.
///
/// # Errors
/// Rejects an empty/oversized set or any invalid source, signature or offence.
pub fn validate_evidence_set_using(
    witnesses: &[EvidenceWitness],
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<Vec<EvidenceStatement>, HistoryError> {
    if witnesses.is_empty()
        || witnesses.len() > neutrin0_consensus_types::evidence::MAX_EVIDENCE_BATCH
    {
        return Err(HistoryError::Evidence);
    }
    let mut checked = EvidenceValidation::default();
    witnesses
        .iter()
        .map(|witness| checked.validate(witness, verifier))
        .collect()
}

/// Batch Guest input. Fact statements and accepted receipts are authenticated
/// through the separate recursive proof stream, in that order, before any
/// offence can be committed.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceBatchWitness {
    /// Bounded offences, potentially from different historical chunks.
    pub witnesses: alloc::vec::Vec<EvidenceWitness>,
    /// Authenticated cryptographic facts, shared across all offences.
    pub facts: alloc::vec::Vec<crate::facts::FactStatement>,
    /// Block receipts the offences need valid, at most one per offence.
    pub receipts: alloc::vec::Vec<crate::facts::AcceptedReceipt>,
    /// Program identity pinned by the consuming block anchor.
    pub fact_guest_vk_digest: [u32; 8],
}

/// Derive batch statements without repeating signatures or exact-proof verification.
/// The caller must first authenticate every fact statement and accepted
/// receipt through SP1 recursion.
pub fn validate_evidence_batch(
    input: &EvidenceBatchWitness,
) -> Result<
    (
        neutrin0_consensus_types::evidence::EvidenceBatch,
        alloc::vec::Vec<EvidenceStatement>,
    ),
    HistoryError,
> {
    if input.witnesses.is_empty()
        || input.witnesses.len() > neutrin0_consensus_types::evidence::MAX_EVIDENCE_BATCH
        || input.facts.len() > MAX_EVIDENCE_FACT_STATEMENTS
        || input.receipts.len() > input.witnesses.len()
        || input
            .witnesses
            .iter()
            .any(|witness| witness.chain_spec.genesis_execution.fact != input.fact_guest_vk_digest)
    {
        return Err(HistoryError::Evidence);
    }
    let mut reader = crate::facts::FactReader::new(&input.facts)?.with_receipts(&input.receipts);
    let statements = validate_evidence_set_using(&input.witnesses, &mut reader)?;
    if !reader.complete() {
        return Err(HistoryError::Evidence);
    }
    let batch = neutrin0_consensus_types::evidence::EvidenceBatch::new(
        &statements,
        input.fact_guest_vk_digest,
    )
    .ok_or(HistoryError::Evidence)?;
    Ok((batch, statements))
}
