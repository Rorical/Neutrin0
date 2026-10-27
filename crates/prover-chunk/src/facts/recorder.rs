//! Host-side collection of unique facts while deriving offence statements.

use alloc::{collections::BTreeMap, vec::Vec};
use neutrin0_consensus_types::BlockProof;
use neutrin0_primitives::Hash;

use super::request::{FactRequest, FactRequestRef};
use super::{EvidenceVerifier, block_is_valid};
use crate::{bls, bls::Verifier, history::HistoryError};

/// Collect unique facts while deriving offence statements on the host.
/// Cached verdicts must originate exclusively from already verified fact receipts.
pub struct FactRecorder<V = bls::DirectVerifier> {
    direct: V,
    requests: BTreeMap<Hash, (FactRequest, bool)>,
    known: BTreeMap<Hash, bool>,
    /// Receipts verified valid, by program and statement key, for recursion.
    accepted: BTreeMap<([u32; 8], Hash), BlockProof>,
    failed: bool,
}

impl FactRecorder {
    /// Use authenticated cached verdicts to avoid repeating their cryptography.
    pub fn with_verified(known: BTreeMap<Hash, bool>) -> Self {
        Self::with_verifier(known, bls::DirectVerifier::default())
    }
}

impl Default for FactRecorder {
    fn default() -> Self {
        Self::with_verified(BTreeMap::new())
    }
}

impl<V: Verifier> FactRecorder<V> {
    /// Record exact verdicts using an immediate verifier and authenticated cache.
    /// The supplied verifier must never defer a negative or positive decision.
    pub const fn with_verifier(known: BTreeMap<Hash, bool>, direct: V) -> Self {
        Self {
            direct,
            known,
            requests: BTreeMap::new(),
            accepted: BTreeMap::new(),
            failed: false,
        }
    }
    /// Check or reuse one request and record its explicit verdict.
    pub fn check(&mut self, request: FactRequest) -> bool {
        let id = request.id();
        let valid = self.verdict(&id, request.borrowed());
        self.requests.entry(id).or_insert((request, valid));
        valid
    }

    /// [`Self::check`] for a borrowed request, copied only when its id is new.
    pub(super) fn check_fact(&mut self, request: FactRequestRef<'_>) -> bool {
        let id = request.id();
        let valid = self.verdict(&id, request);
        self.requests
            .entry(id)
            .or_insert_with(|| (request.to_request(), valid));
        valid
    }

    fn verdict(&mut self, id: &Hash, request: FactRequestRef<'_>) -> bool {
        let value = self
            .known
            .get(id)
            .copied()
            .or_else(|| self.requests.get(id).map(|(_, value)| *value));
        if let Some(value) = value {
            value
        } else if let Ok(value) = request.verify(&mut self.direct) {
            value
        } else {
            self.failed = true;
            false
        }
    }
    /// Receipts found valid, each to be attached once for recursive
    /// verification under its program.
    pub fn take_accepted(&mut self) -> Vec<([u32; 8], BlockProof)> {
        core::mem::take(&mut self.accepted)
            .into_iter()
            .map(|((key, _), proof)| (key, proof))
            .collect()
    }

    /// Extract checked assertions. A panic/resource failure never becomes a fact.
    pub fn finish(self) -> Result<Vec<(FactRequest, bool)>, HistoryError> {
        if self.failed {
            Err(HistoryError::Unsupported)
        } else {
            Ok(self.requests.into_values().collect())
        }
    }
}

impl<V: Verifier> EvidenceVerifier for FactRecorder<V> {
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        let request = FactRequestRef::Block { key, proof };
        let id = request.id();
        let valid = self.verdict(&id, request);
        if self.failed {
            return Err(HistoryError::Unsupported);
        }
        // Only a rejection becomes a fact; the Fact Guest proves no acceptance.
        if !valid {
            self.requests
                .entry(id)
                .or_insert_with(|| (request.to_request(), false));
        }
        Ok(!valid)
    }

    fn accepts_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        let valid = block_is_valid(proof, key)?;
        if valid {
            self.accepted
                .entry((*key, proof.statement_key))
                .or_insert_with(|| proof.clone());
        }
        Ok(valid)
    }
}
