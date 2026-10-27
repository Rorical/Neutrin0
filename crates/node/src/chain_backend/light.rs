//! Persistent proof-only anchors, independent of the full execution engine's head.
//!
//! A light client keeps only the latest History proof it accepted, for an
//! endpoint the sync driver saw a quorum of sampled peers advertise. Two
//! verified proofs ending at different endpoints with one chunk count halt it
//! durably, and so does a verified opening showing that a new endpoint's
//! chain does not contain the current one: the evidence is kept and nothing
//! is accepted until an operator configures a new trusted checkpoint. A
//! proof past the trusted start without an opening of the current endpoint
//! is rejected as missing its opening, and another provider is asked.
//!
//! The database is trusted local storage: its snapshot records the already
//! checked endpoint and expiry, which the latest proof alone cannot
//! reconstruct after a coherent database replacement.

mod acceptance;
mod initialization;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::history_proof::{AnchorOpening, Checkpoint, HistoryProof};
use neutrin0_light_client::{HistoryVerifier, LightClient, LightClientSnapshot};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ProofSystem, VerifiedHistory};
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{ChainBackend, not_available, rejected, storage_error};

const STATE_KEY: &[u8] = b"light_client_state";
const PROOF_KEY: &[u8] = b"light_client_latest_proof";
const CONFLICT_KEY: &[u8] = b"light_client_conflict";
/// Verified endpoints above the current one kept to detect a conflict.
const CANDIDATE_LIMIT: usize = 8;
/// Two checkpoints (chain binding plus boundary each), two timestamps and an
/// optional proof statement key; anything larger is corrupt.
const MAX_STATE_BYTES: usize = 2048;
/// Bound on a persisted History proof: its receipt plus a statement far below this slack.
const MAX_PROOF_BYTES: usize =
    neutrin0_consensus_types::history_proof::MAX_HISTORY_RECEIPT_BYTES + 4096;
/// Bound on persisted conflict evidence: two proofs, an opening and the
/// trust origin.
const MAX_CONFLICT_BYTES: usize = 2 * MAX_PROOF_BYTES + 2 * MAX_STATE_BYTES + 64 * 32;

/// Durable evidence that two verified History proofs disagree, which halts
/// the light client under the trust origin it was found under: they end at
/// different endpoints with one chunk count, or `opening` authenticates a
/// different boundary at the first side's count on the second side's chain.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub(super) struct LightConflict {
    trust_origin: Checkpoint,
    trusted_at: u64,
    /// The chunk count both endpoints claim.
    chunks: u64,
    /// One side; `None` when it is the configured trust origin itself, which
    /// was trusted without a proof.
    first: Option<HistoryProof>,
    /// The other side.
    second: HistoryProof,
    /// The verified opening under `second`'s endpoint of a leaf that started
    /// from a boundary other than the first side's, when that is the
    /// disagreement.
    opening: Option<AnchorOpening>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct StoredLight {
    snapshot: LightClientSnapshot,
    trust_origin: Checkpoint,
    trusted_at: u64,
    /// Statement key of the stored latest History proof.
    proof_key: Option<Hash>,
}

impl StoredLight {
    fn decode(bytes: &[u8], origin: &Checkpoint, trusted_at: u64) -> Result<Self, String> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err("oversized persisted light state".to_owned());
        }
        let stored: Self = borsh::from_slice(bytes).map_err(|error| error.to_string())?;
        if stored.trust_origin != *origin || stored.trusted_at != trusted_at {
            return Err("persistent light trust origin/time differs from configuration".to_owned());
        }
        Ok(stored)
    }

    // Only storage consistency: the caller must independently verify the receipt.
    fn decode_latest(
        &self,
        bytes: Option<&[u8]>,
        initial_expiry: u64,
    ) -> Result<Option<HistoryProof>, String> {
        match (self.proof_key, bytes) {
            (None, None) => {
                if self.snapshot.checkpoint != self.trust_origin
                    || self.snapshot.anchor_expires_at != initial_expiry
                {
                    return Err(
                        "unproven light state differs from its explicit trust origin".to_owned(),
                    );
                }
                Ok(None)
            }
            (Some(key), Some(bytes)) => {
                if bytes.len() > MAX_PROOF_BYTES {
                    return Err("oversized persisted light proof".to_owned());
                }
                let proof: HistoryProof =
                    borsh::from_slice(bytes).map_err(|error| error.to_string())?;
                if proof.statement.statement_key() != key
                    || proof.end_checkpoint() != self.snapshot.checkpoint
                {
                    return Err("persisted light proof/state mismatch".to_owned());
                }
                Ok(Some(proof))
            }
            _ => Err("incomplete persisted light state/proof pair".to_owned()),
        }
    }
}

pub(super) struct LightRuntime {
    client: LightClient,
    latest: Option<HistoryProof>,
    trust_origin: Checkpoint,
    trusted_at: u64,
    /// Verified proofs above the current endpoint, by chunk count.
    candidates: BTreeMap<u64, HistoryProof>,
    conflict: Option<LightConflict>,
}

/// The verified side a new proof contradicts.
enum Contradicted {
    /// The configured trust origin, trusted without a proof.
    Origin,
    /// A verified proof: the current endpoint's or a remembered candidate.
    Proof(Box<HistoryProof>),
}

impl Contradicted {
    fn into_proof(self) -> Option<HistoryProof> {
        match self {
            Self::Origin => None,
            Self::Proof(proof) => Some(*proof),
        }
    }
}

impl LightRuntime {
    /// The verified side `proof` conflicts with: the current endpoint at its
    /// count, or a verified candidate at its count.
    fn conflicting(&self, proof: &HistoryProof) -> Option<Contradicted> {
        let endpoint = proof.end_checkpoint();
        let current = self.client.checkpoint();
        if endpoint.boundary.next_chunk_id == current.boundary.next_chunk_id && endpoint != *current
        {
            return Some(self.latest.clone().map_or(Contradicted::Origin, |proof| {
                Contradicted::Proof(Box::new(proof))
            }));
        }
        self.candidates
            .get(&endpoint.boundary.next_chunk_id)
            .filter(|candidate| candidate.end_checkpoint() != endpoint)
            .map(|candidate| Contradicted::Proof(Box::new(candidate.clone())))
    }

    /// Keep a verified proof above the current endpoint, bounded to the
    /// highest counts.
    fn remember(&mut self, proof: HistoryProof) {
        let count = proof.end().next_chunk_id;
        if count <= self.client.checkpoint().boundary.next_chunk_id {
            return;
        }
        self.candidates.insert(count, proof);
        while self.candidates.len() > CANDIDATE_LIMIT {
            self.candidates.pop_first();
        }
    }
}

/// Reuse only the exact artifact/domain already authenticated outside the engine lock.
pub(super) struct Authenticated<'a>(pub(super) &'a VerifiedHistory);
impl HistoryVerifier for Authenticated<'_> {
    type Error = ();
    fn verify_history(
        &self,
        proof: &HistoryProof,
        chunk: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<(), ()> {
        if proof == self.0.proof() && *chunk == self.0.domain().chunk {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn timestamp() -> Result<u64, SyncBackendError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(not_available)
}

/// A light client's endpoint and trust state, for health and diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LightHealth {
    /// Latest accepted endpoint.
    pub(super) checkpoint: Checkpoint,
    /// The weak-subjectivity trust window has passed.
    pub(super) expired: bool,
    /// A verified History conflict halted the client.
    pub(super) halted: bool,
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Whether this backend runs as a proof-only light node.
    pub(super) fn is_light(&self) -> bool {
        self.light.lock().expect("light state").is_some()
    }

    pub(super) fn light_checkpoint(&self) -> Option<Checkpoint> {
        self.light
            .lock()
            .expect("light state")
            .as_ref()
            .map(|state| *state.client.checkpoint())
    }

    /// Read the authenticated endpoint, whether its trust expired and whether
    /// a History conflict halted the client. A failed local clock check is
    /// unhealthy; observing health never renews trust.
    pub(super) fn light_health(&self) -> Option<LightHealth> {
        self.light
            .lock()
            .expect("light state")
            .as_ref()
            .map(|state| LightHealth {
                checkpoint: *state.client.checkpoint(),
                expired: timestamp().map_or(true, |now| now >= state.client.anchor_expires_at()),
                halted: state.conflict.is_some(),
            })
    }

    /// Whether a verified History conflict halted this light client.
    pub(super) fn light_halted(&self) -> bool {
        self.light
            .lock()
            .expect("light state")
            .as_ref()
            .is_some_and(|state| state.conflict.is_some())
    }

    pub(super) fn light_latest_proof(&self) -> Result<Option<HistoryProof>, String> {
        let state = self.light.lock().map_err(|error| error.to_string())?;
        Ok(state.as_ref().and_then(|state| state.latest.clone()))
    }
}

#[cfg(test)]
mod tests;
