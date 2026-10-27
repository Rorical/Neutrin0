//! Verifiers that answer from recursively authenticated fact statements.

use alloc::{collections::BTreeMap, vec::Vec};
use neutrin0_consensus_types::BlockProof;
use neutrin0_primitives::Hash;

use super::request::{FactRequestRef, MAX_FACTS};
use super::{AcceptedReceipt, EvidenceVerifier, FactStatement};
use crate::{bls, history::HistoryError};

/// Reads only recursively authenticated fact statements. A missing lookup is
/// sticky, even when a caller branches on a negative signature result.
pub struct FactReader {
    facts: BTreeMap<Hash, bool>,
    accepted: Vec<AcceptedReceipt>,
    missing: bool,
}

impl FactReader {
    /// Construct after verifying each statement against the pinned fact program.
    pub fn new(statements: &[FactStatement]) -> Result<Self, HistoryError> {
        let mut facts = BTreeMap::new();
        for statement in statements {
            if statement.facts.is_empty() || statement.facts.len() > MAX_FACTS {
                return Err(HistoryError::Evidence);
            }
            for fact in &statement.facts {
                if let Some(previous) = facts.insert(fact.id, fact.valid)
                    && previous != fact.valid
                {
                    return Err(HistoryError::Evidence);
                }
            }
        }
        Ok(Self {
            facts,
            accepted: Vec::new(),
            missing: false,
        })
    }

    /// Also answer acceptance from `receipts`, which the caller verifies by
    /// recursion before trusting any result.
    #[must_use]
    pub fn with_receipts(mut self, receipts: &[AcceptedReceipt]) -> Self {
        self.accepted = receipts.to_vec();
        self
    }

    pub(super) fn check_fact(&mut self, request: FactRequestRef<'_>) -> bool {
        self.facts.get(&request.id()).copied().unwrap_or_else(|| {
            self.missing = true;
            false
        })
    }
    /// Must be called before committing any derived offence statement.
    pub const fn complete(&self) -> bool {
        !self.missing
    }
}

/// Answers from recursively authenticated fact statements first and falls
/// back to in-circuit BLS for anything they do not cover.
///
/// This lets a consensus chunk consume signature work that fact proofs
/// already did ahead of time without making chunk proving wait for them:
/// uncovered checks still run through the batched pairing path.
pub struct HybridVerifier {
    facts: BTreeMap<Hash, bool>,
    direct: bls::BatchVerifier,
    /// Distinct requests already counted, so repeated checks of one request
    /// (which the batch verifier dedupes anyway) count once.
    counted: alloc::collections::BTreeSet<Hash>,
    hits: usize,
    misses: usize,
}

impl HybridVerifier {
    /// Construct after every statement's receipt has been verified against
    /// the pinned fact program. Conflicting verdicts for one request are
    /// rejected as in [`FactReader::new`].
    pub fn new(statements: &[FactStatement]) -> Result<Self, HistoryError> {
        let reader = FactReader::new(statements)?;
        Ok(Self {
            facts: reader.facts,
            direct: bls::BatchVerifier::default(),
            counted: alloc::collections::BTreeSet::new(),
            hits: 0,
            misses: 0,
        })
    }

    pub(super) fn check_fact(&mut self, request: FactRequestRef<'_>) -> bool {
        let id = request.id();
        let first = self.counted.insert(id);
        if let Some(valid) = self.facts.get(&id) {
            self.hits += usize::from(first);
            return *valid;
        }
        self.misses += usize::from(first);
        request.verify(&mut self.direct).unwrap_or(false)
    }

    /// Checks answered by fact statements.
    #[must_use]
    pub const fn hits(&self) -> usize {
        self.hits
    }

    /// Checks that fell back to in-circuit verification.
    #[must_use]
    pub const fn misses(&self) -> usize {
        self.misses
    }

    /// Settle the batched fallback equations. Must be called before trusting
    /// any positive answer that came from the fallback path.
    #[must_use]
    pub fn finish(self) -> bool {
        self.direct.finish()
    }
}

impl EvidenceVerifier for FactReader {
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        let valid = self.check_fact(FactRequestRef::Block { key, proof });
        if self.missing {
            Err(HistoryError::Unsupported)
        } else {
            Ok(!valid)
        }
    }

    fn accepts_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        if self
            .accepted
            .iter()
            .any(|receipt| receipt.proves(proof, key))
        {
            Ok(true)
        } else {
            self.missing = true;
            Err(HistoryError::Unsupported)
        }
    }
}
