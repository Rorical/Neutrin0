#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Proof-only light-client trust and freshness policy.
//!
//! A History proof is the latest finalized chunk receipt, which proves its
//! chain from the specification's start (genesis, or a hard fork's pinned
//! start). A light client keeps only the latest one it accepted. Which
//! endpoint to accept is decided by [`sampling`]: a quorum of distinct peers
//! must advertise it identically, and two different endpoints at one chunk
//! count stop the client. Past the trusted start, an update also needs an
//! opening of the client's current endpoint under the new one: it proves the
//! new chain contains the current endpoint, or that it does not, which stops
//! the client too.
//!
//! The supplied verifier must authenticate a real compressed receipt under its
//! independently configured program keys. Native statement checks alone never
//! establish proof validity. Persistent applications atomically store this state
//! and the accepted artifact after a successful update.

extern crate alloc;

pub mod sampling;

use neutrin0_consensus_types::history_proof::{
    AnchorCheck, AnchorOpening, ChainBinding, Checkpoint, ConsensusBoundary, HistoryProof,
    ProofDomain, VkDigest, check_anchor,
};
use neutrin0_primitives::{ChainSpec, Hash};

/// Cryptographic receipt verifier, implemented by the trusted proof backend.
///
/// Implementations must reject non-Compressed, malformed, mock and non-success
/// receipts, bind the exact statement bytes and verify the receipt under the
/// chunk Guest of the trusted chain, never one the statement names. A valid
/// receipt proves the chain from the specification's start to its end.
pub trait HistoryVerifier {
    /// Backend verification failure.
    type Error;
    /// Authenticate the exact chunk receipt under `chunk`, the chunk Guest
    /// the trusted specification pins.
    fn verify_history(&self, proof: &HistoryProof, chunk: &VkDigest) -> Result<(), Self::Error>;
}

/// Result of accepting a valid history artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateOutcome {
    /// Advanced the exact local anchor to the requested endpoint.
    Advanced,
    /// Reverified an identical endpoint without changing trust or freshness state.
    AlreadyCurrent,
}

/// Cryptographic or local trust-policy rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LightClientError {
    /// The supplied anchor/spec/profile is inconsistent.
    InvalidAnchor,
    /// Receipt and trusted chain/program identities differ.
    Domain,
    /// The current weak-subjectivity trust window has expired.
    Expired,
    /// A verified endpoint conflicts with the local endpoint at the same height.
    Conflict,
    /// The endpoint precedes the current one; trust never moves backwards.
    Backwards,
    /// A verified opening places a different boundary at the current
    /// endpoint's count on the new endpoint's chain.
    AnchorConflict,
    /// The supplied opening does not authenticate under the new endpoint: a
    /// provider fault that says nothing about the chain.
    BadOpening,
    /// No opening of the current endpoint came with the update, so nothing
    /// shows the new chain contains it: a provider fault, retried elsewhere.
    MissingOpening,
    /// The endpoint does not match the locally requested endpoint identity.
    UnexpectedTarget,
    /// The endpoint claims a slot too far into the future.
    Future,
    /// The advancing endpoint is too old for the local freshness policy.
    Stale,
    /// Time arithmetic overflowed or a malformed endpoint was supplied.
    Range,
    /// The cryptographic verifier rejected the receipt.
    Verification,
}
impl core::fmt::Display for LightClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "light-client update rejected: {self:?}")
    }
}
impl core::error::Error for LightClientError {}

/// Durable local trust state. Restoring never assigns a new trust timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct LightClientSnapshot {
    /// Exact locally authenticated endpoint.
    pub checkpoint: Checkpoint,
    /// Existing absolute weak-subjectivity expiry, including normal proven advancement.
    pub anchor_expires_at: u64,
}

/// Current proof-only trust state and locally pinned time policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LightClient {
    checkpoint: Checkpoint,
    /// The locally pinned specification: chunk size, Guest keys and the time
    /// policy.
    spec: ChainSpec,
    genesis: ConsensusBoundary,
    max_future_drift_secs: u64,
    anchor_expires_at: u64,
}
/// Absolute weak-subjectivity expiry of an explicitly trusted anchor.
///
/// The period runs from the earlier of `trusted_at` and the anchor block's slot
/// time, as for every endpoint the client later accepts: trusting an old
/// boundary today does not make it recent.
///
/// # Errors
/// Returns [`LightClientError::Range`] on time overflow.
pub fn anchor_expiry(
    spec: &ChainSpec,
    trusted: &Checkpoint,
    trusted_at: u64,
) -> Result<u64, LightClientError> {
    trusted_at
        .min(boundary_time(spec, &trusted.boundary)?)
        .checked_add(spec.light_client.weak_subjectivity_period_secs)
        .ok_or(LightClientError::Range)
}

/// Wall-clock start of the slot that produced `boundary`'s block.
fn boundary_time(spec: &ChainSpec, boundary: &ConsensusBoundary) -> Result<u64, LightClientError> {
    boundary
        .slot
        .checked_mul(spec.consensus.slot_duration_secs)
        .and_then(|elapsed| spec.genesis_time.checked_add(elapsed))
        .ok_or(LightClientError::Range)
}

impl LightClient {
    /// Install an explicit locally trusted anchor. This is an out-of-band trust
    /// operation; an arbitrary peer checkpoint is never suitable input.
    pub fn new(
        spec: &ChainSpec,
        trusted: Checkpoint,
        trusted_at: u64,
        max_future_drift_secs: u64,
    ) -> Result<Self, LightClientError> {
        spec.validate()
            .map_err(|_| LightClientError::InvalidAnchor)?;
        // The specification's own start (genesis, or a hard fork's pinned
        // start) is the only anchor at its count; nothing below it belongs to
        // this chain, and the chunk Guest is the one the specification pins.
        let genesis = ConsensusBoundary::first(spec);
        if trusted.boundary.next_chunk_id < genesis.next_chunk_id
            || (trusted.boundary.next_chunk_id == genesis.next_chunk_id
                && trusted.boundary != genesis)
            || trusted.chain != ChainBinding::new(spec)
            || !trusted.boundary.is_well_formed(spec)
        {
            return Err(LightClientError::InvalidAnchor);
        }
        let anchor_expires_at = anchor_expiry(spec, &trusted, trusted_at)?;
        Ok(Self {
            checkpoint: trusted,
            spec: spec.clone(),
            genesis,
            max_future_drift_secs,
            anchor_expires_at,
        })
    }

    /// Snapshot for atomic persistence with the accepted receipt.
    #[must_use]
    pub const fn snapshot(&self) -> LightClientSnapshot {
        LightClientSnapshot {
            checkpoint: self.checkpoint,
            anchor_expires_at: self.anchor_expires_at,
        }
    }

    /// Restore trusted local storage under independently pinned keys and current
    /// local clock policy. Never pass a peer-supplied snapshot: this operation trusts
    /// the persisted history of anchor advancement, which the latest suffix alone
    /// cannot reconstruct. Expired snapshots remain expired; no wall clock is consulted.
    pub fn restore(
        spec: &ChainSpec,
        trusted_domain: &ProofDomain,
        snapshot: &LightClientSnapshot,
        max_future_drift_secs: u64,
    ) -> Result<Self, LightClientError> {
        if snapshot.checkpoint.chain != trusted_domain.chain {
            return Err(LightClientError::Domain);
        }
        let trusted_at = snapshot
            .anchor_expires_at
            .checked_sub(spec.light_client.weak_subjectivity_period_secs)
            .ok_or(LightClientError::InvalidAnchor)?;
        Self::new(spec, snapshot.checkpoint, trusted_at, max_future_drift_secs)
    }

    /// Current exact authenticated endpoint.
    #[must_use]
    pub const fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Trust profile at the current anchor: the chain plus the program set the
    /// anchor boundary names.
    #[must_use]
    pub const fn trusted_domain(&self) -> ProofDomain {
        ProofDomain {
            chain: self.checkpoint.chain,
            chunk: self.spec.genesis_chunk,
            programs: self.checkpoint.boundary.programs,
        }
    }

    /// Local expiry; receipt replay cannot extend it.
    #[must_use]
    pub const fn anchor_expires_at(&self) -> u64 {
        self.anchor_expires_at
    }

    /// Verify and accept a requested endpoint after the current one, or
    /// reverify an identical endpoint. The receipt proves its chain from the
    /// specification's start; it shows that the current endpoint lies on that
    /// chain only through `opening`, which every update past the trusted
    /// start needs.
    /// The caller selects `expected_endpoint` by [`sampling`]. All checks
    /// complete before any in-memory state is changed.
    pub fn accept<V: HistoryVerifier>(
        &mut self,
        proof: &HistoryProof,
        opening: Option<&AnchorOpening>,
        expected_endpoint: Hash,
        now: u64,
        verifier: &V,
    ) -> Result<UpdateOutcome, LightClientError> {
        if now >= self.anchor_expires_at {
            return Err(LightClientError::Expired);
        }
        if *proof.chain() != self.checkpoint.chain {
            return Err(LightClientError::Domain);
        }
        let endpoint = proof.end_checkpoint();
        if endpoint.boundary.next_chunk_id == 0 || !endpoint.boundary.is_well_formed(&self.spec) {
            return Err(LightClientError::Range);
        }
        if endpoint.hash() != expected_endpoint {
            return Err(LightClientError::UnexpectedTarget);
        }
        verifier
            .verify_history(proof, &self.spec.genesis_chunk)
            .map_err(|_| LightClientError::Verification)?;
        if endpoint == self.checkpoint {
            return Ok(UpdateOutcome::AlreadyCurrent);
        }
        if endpoint.boundary.next_chunk_id == self.checkpoint.boundary.next_chunk_id {
            return Err(LightClientError::Conflict);
        }
        if endpoint.boundary.next_chunk_id < self.checkpoint.boundary.next_chunk_id {
            return Err(LightClientError::Backwards);
        }
        // An opening decides whether the new chain contains the current
        // endpoint; a checkpoint past the trusted start needs one.
        match check_anchor(
            &self.genesis,
            &self.checkpoint.boundary,
            &endpoint.boundary,
            opening,
        ) {
            AnchorCheck::Extends => {}
            // Weak subjectivity bounds the fork point only through the
            // anchor: a chain that does not contain it must never be adopted
            // on sampling alone.
            AnchorCheck::Unopened => return Err(LightClientError::MissingOpening),
            AnchorCheck::Invalid => return Err(LightClientError::BadOpening),
            AnchorCheck::Conflicts => return Err(LightClientError::AnchorConflict),
        }
        let timestamp = boundary_time(&self.spec, &endpoint.boundary)?;
        let latest = now
            .checked_add(self.max_future_drift_secs)
            .ok_or(LightClientError::Range)?;
        if timestamp > latest {
            return Err(LightClientError::Future);
        }
        if now.saturating_sub(timestamp) > self.spec.light_client.stale_threshold_secs {
            return Err(LightClientError::Stale);
        }
        let expiry = timestamp
            .min(now)
            .checked_add(self.spec.light_client.weak_subjectivity_period_secs)
            .ok_or(LightClientError::Range)?;
        if expiry <= now {
            return Err(LightClientError::Expired);
        }
        self.checkpoint = endpoint;
        self.anchor_expires_at = expiry;
        Ok(UpdateOutcome::Advanced)
    }
}

#[cfg(test)]
mod tests;
