//! Replay markers: liveness offence keys, safety tombstones and the expiry
//! buckets that sweep liveness markers one unbonding delay after admission.

use alloc::vec::Vec;

use neutrin0_consensus_types::evidence::{EvidenceStatement, SanctionKind};
use neutrin0_primitives::{BlsPublicKey, Hash};
use neutrin0_runtime_abi::Sanction;
use neutrin0_runtime_core::StateBackend;

use crate::state::{prefixed_key, read_canonical, write_record};

/// Status key rejecting duplicate or re-encoded liveness offences while
/// admissible.
///
/// It is swept through the `expiry_key` bucket of its admitting height
/// once the unbonding delay has passed.
pub fn offence_key(id: &Hash) -> Vec<u8> {
    prefixed_key(b"accountability:event:", id)
}

/// Tombstone of a BLS identity whose safety sanction has been admitted.
///
/// One safety sanction retires an identity for good: consensus marks it
/// `slashed` at the next boundary and never seats it again, so a second
/// safety claim against the same key, from any chunk, is rejected while the
/// tombstone stands. The tombstone therefore replaces per-offence markers for
/// safety evidence, and the number of tombstones is bounded by the identities
/// ever sanctioned rather than by how many offences they signed.
pub fn slashed_key(pubkey: &BlsPublicKey) -> Vec<u8> {
    prefixed_key(b"accountability:slashed:", pubkey)
}

/// Replay marker a statement must not find in state to be admissible.
#[must_use]
pub fn marker_key(statement: &EvidenceStatement) -> Vec<u8> {
    replay_marker(
        statement.kind,
        &statement.offender.pubkey,
        &statement.offence_id,
    )
}

/// Safety offences mark the offender's identity; liveness offences mark the
/// offence itself.
pub(super) fn replay_marker(
    kind: SanctionKind,
    pubkey: &BlsPublicKey,
    offence_id: &Hash,
) -> Vec<u8> {
    match kind {
        SanctionKind::Slash => slashed_key(pubkey),
        SanctionKind::Inactivity | SanctionKind::Abandonment => offence_key(offence_id),
    }
}

/// Bucket listing the liveness offence markers written by admissions at
/// `height`.
///
/// The block at `height + unbonding_delay_blocks + 1` deletes the bucket and
/// every listed marker. The unbonding delay is fixed at genesis and exceeds
/// every liveness window governance may set, so a swept marker can never
/// bind again. Safety tombstones are never listed: a safety claim has no age
/// window and consensus never seats a slashed identity again, so the
/// tombstone is permanent and the live set is bounded by the identities ever
/// sanctioned.
pub(super) fn expiry_key(height: u64) -> Vec<u8> {
    prefixed_key(b"accountability:expiry:", &height.to_be_bytes())
}

/// Delete the markers admitted one unbonding delay before this block.
///
/// Retention never depends on a governable window. The sweep is bounded by
/// that block's admission cap and is mandatory, so it carries no gas.
pub(super) fn sweep_expired_markers<B: StateBackend>(state: &mut B, height: u64, retention: u64) {
    let Some(expired) = height
        .checked_sub(retention)
        .and_then(|height| height.checked_sub(1))
    else {
        return;
    };
    let Some(keys) = read_canonical::<Vec<Vec<u8>>, _>(state, &expiry_key(expired)) else {
        return;
    };
    for key in &keys {
        state.delete(key);
    }
    state.delete(&expiry_key(expired));
}

/// Remember which liveness markers this block created so a later block can
/// sweep them. Safety tombstones are permanent.
pub(super) fn record_expiry_bucket<B: StateBackend>(
    state: &mut B,
    height: u64,
    admitted: &[Sanction],
) {
    let keys: Vec<Vec<u8>> = admitted
        .iter()
        .filter(|sanction| !sanction.kind.is_safety())
        .map(|sanction| {
            replay_marker(
                sanction.kind,
                &sanction.offender.pubkey,
                &sanction.offence_id,
            )
        })
        .collect();
    if keys.is_empty() {
        return;
    }
    write_record(state, &expiry_key(height), &keys);
}
