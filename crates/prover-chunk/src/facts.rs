//! Reusable cryptographic facts, independent of chain inclusion or guilt.
//!
//! Facts bind exact signed bytes and key/domain inputs. Evidence still checks
//! historical membership, offence logic and policy. Missing facts never mean
//! rejection. Only an authenticated explicit negative verdict can do that.

use crate::{
    bls::{self, Verifier},
    history::HistoryError,
};
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::BlockProof;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_primitives::{BlsPublicKey, BlsSignature, Hash};

mod extraction;
mod reader;
mod recorder;
mod request;
#[cfg(test)]
mod tests;

pub use extraction::{
    header_requests, nil_vote_requests, proposal_requests, round_change_certificate_requests,
    round_change_requests, vote_requests,
};
pub use reader::{FactReader, HybridVerifier};
pub use recorder::FactRecorder;
use request::FactRequestRef;
pub use request::{FactRequest, MAX_FACTS, pack_requests};

/// One explicit positive or negative cryptographic verdict.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProvenFact {
    /// Exact request identity.
    pub id: Hash,
    /// True means cryptographically valid, false means objective rejection.
    pub valid: bool,
}

/// Public values of the fact Guest. No signature or raw proof bytes remain.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct FactStatement {
    /// Ordered unique request identities and their proven verdicts.
    pub facts: Vec<ProvenFact>,
}

impl neutrin0_consensus_types::hashing::Committed for FactStatement {
    const COMMITMENT_TAG: neutrin0_primitives::DomainTag =
        neutrin0_primitives::DOMAIN_FACT_STATEMENT;
}

/// Fact Guest witness with expected verdicts; they are all checked inside it.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct FactWitness {
    /// Bounded unique assertions.
    pub requests: Vec<FactRequest>,
    /// Exact public values expected by the caller.
    pub statement: FactStatement,
}

/// Batch positive equations and individually establish negative verdicts.
///
/// Operational failure cannot be encoded as an invalid cryptographic artifact.
/// Block receipts are asserted only rejected here: their acceptance is SP1
/// recursion in the consuming Guest, never a software verifier.
pub fn validate_facts(input: &FactWitness) -> Result<FactStatement, HistoryError> {
    if input.requests.is_empty()
        || input.requests.len() > MAX_FACTS
        || input.requests.len() != input.statement.facts.len()
    {
        return Err(HistoryError::Evidence);
    }
    let mut seen = alloc::collections::BTreeSet::new();
    let mut batch = bls::BatchVerifier::default();
    let mut direct = bls::DirectVerifier::default();
    for (request, fact) in input.requests.iter().zip(&input.statement.facts) {
        // A valid receipt is proven by recursion where it is consumed
        // (`AcceptedReceipt`); only a rejection needs the software verifier.
        if request.id() != fact.id
            || !seen.insert(fact.id)
            || (fact.valid && matches!(request, FactRequest::Block { .. }))
        {
            return Err(HistoryError::Evidence);
        }
        let actual = if fact.valid {
            request.verify(&mut batch)?
        } else {
            request.verify(&mut direct)?
        };
        if actual != fact.valid {
            return Err(HistoryError::Evidence);
        }
    }
    if !batch.finish() {
        return Err(HistoryError::Evidence);
    }
    Ok(input.statement.clone())
}

/// Evidence's cryptographic interface. Negative decisions require immediate
/// verification or an explicitly proven fact; never a deferred positive batch.
pub trait EvidenceVerifier: Verifier {
    /// Decide exact envelope rejection; errors are not slashable verdicts.
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError>;

    /// Decide that a valid receipt under `key` proves the envelope's
    /// statement; errors are not verdicts.
    fn accepts_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError>;
}

impl EvidenceVerifier for bls::DirectVerifier {
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        block_is_valid(proof, key).map(|valid| !valid)
    }

    fn accepts_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        block_is_valid(proof, key)
    }
}

/// A Block receipt an Evidence batch asserts valid.
///
/// The Evidence Guest verifies it by SP1 recursion under
/// `block_guest_vk_digest` over the exact public values, so no
/// compressed-proof verifier runs in software.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct AcceptedReceipt {
    /// Block Guest the receipt was proven under.
    pub block_guest_vk_digest: [u32; 8],
    /// The receipt's complete public values.
    pub statement: neutrin0_runtime_abi::BlockReceiptStatement,
}

impl AcceptedReceipt {
    /// Whether `proof` is an envelope of this receipt under `key`: the same
    /// program and statement, and public inputs the statement binds.
    pub(super) fn proves(&self, proof: &BlockProof, key: &[u32; 8]) -> bool {
        self.block_guest_vk_digest == *key
            && commitment(&self.statement) == proof.statement_key
            && self.statement.prover_address == proof.prover_address
            && proof.height == proof.public_inputs.height
            && proof.block_hash == proof.public_inputs.block_hash
            && crate::execution::output_binds(&self.statement.output, &proof.public_inputs)
    }
}

// The feature-disabled stub is constant; the real receipt verifier is not.
#[cfg_attr(not(feature = "sp1-verification"), allow(clippy::missing_const_for_fn))]
fn block_is_valid(proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
    #[cfg(feature = "sp1-verification")]
    {
        #[cfg(feature = "std")]
        let result = std::panic::catch_unwind(|| {
            crate::proof_verification::verify_block_artifact(proof, key)
        })
        .map_err(|_| HistoryError::Unsupported)?;
        #[cfg(not(feature = "std"))]
        let result = crate::proof_verification::verify_block_artifact(proof, key);
        Ok(result.is_ok())
    }
    #[cfg(not(feature = "sp1-verification"))]
    {
        let _ = (proof, key);
        Err(HistoryError::Unsupported)
    }
}

macro_rules! signature_verifier {
    ($type:ty) => {
        signature_verifier!(@implementation [] $type);
    };
    (@implementation [$($parameters:tt)*] $type:ty) => {
        impl $($parameters)* Verifier for $type {
            fn verify(
                &mut self,
                key: &BlsPublicKey,
                message: &[u8],
                signature: &BlsSignature,
            ) -> bool {
                self.check_fact(FactRequestRef::Signature {
                    key,
                    message,
                    signature,
                    possession: false,
                })
            }
            fn aggregate(
                &mut self,
                keys: &[BlsPublicKey],
                message: &[u8],
                signature: &BlsSignature,
            ) -> bool {
                self.check_fact(FactRequestRef::Aggregate {
                    keys,
                    message,
                    signature,
                })
            }
            fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
                // A possession proof signs exactly the key bytes.
                self.check_fact(FactRequestRef::Signature {
                    key,
                    message: key,
                    signature,
                    possession: true,
                })
            }
        }
    };
}
signature_verifier!(@implementation [<V: Verifier>] FactRecorder<V>);
signature_verifier!(FactReader);
signature_verifier!(HybridVerifier);
