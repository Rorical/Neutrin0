//! Per-block body Merkle commitments.
//!
//! Headers bind counted transaction and embedded-vote lanes through their
//! dedicated Merkle roots and the combined DA commitment.

use neutrin0_consensus_types::{Body, Header};
use neutrin0_primitives::{Hash, da_root_from_lane_roots};

use crate::merkle::merkle_root;

/// Header-level Merkle roots committed by the header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyRoots {
    /// Root over `body.transactions`.
    pub transactions_root: Hash,
    /// Root over the tagged finality-vote and participation-acknowledgement lane.
    pub votes_root: Hash,
    /// DA commitment to counted transaction and vote roots.
    pub da_root: Hash,
}

/// Derive counted transaction and vote commitments from a body.
#[must_use]
pub fn compute_body_roots(body: &Body) -> BodyRoots {
    let transactions_root = neutrin0_primitives::transactions_root_of_blobs(&body.transactions);
    let votes_root =
        neutrin0_consensus_types::participation::vote_lane_root(&body.participation_acks);
    // The program lane commits each piece's bytes-free descriptor, which
    // binds the bytes by hash and lets the chunk Guest authenticate pieces
    // without them (design 20).
    let descriptors: Vec<_> = body
        .programs
        .iter()
        .map(neutrin0_consensus_types::ProgramPiece::descriptor)
        .collect();
    let programs_root = merkle_root(&descriptors);
    BodyRoots {
        transactions_root,
        votes_root,
        da_root: da_root_from_lane_roots([
            (
                u32::try_from(body.transactions.len()).expect("borsh count"),
                transactions_root,
            ),
            (
                neutrin0_consensus_types::participation::vote_lane_count(&body.participation_acks),
                votes_root,
            ),
            (
                u32::try_from(body.programs.len()).expect("borsh count"),
                programs_root,
            ),
            (
                u32::from(body.participation.is_some()),
                merkle_root(body.participation.as_slice()),
            ),
        ]),
    }
}

/// Apply the computed body roots to `header`, overwriting any prior
/// values. Useful when building a header before sealing it.
pub const fn apply_body_roots(header: &mut Header, roots: &BodyRoots) {
    header.transactions_root = roots.transactions_root;
    header.votes_root = roots.votes_root;
    header.da_root = roots.da_root;
}

#[cfg(test)]
mod tests;
