//! Consensus-owned permanent identity sanctions, independent of execution code.

use alloc::{collections::BTreeSet, vec::Vec};
use neutrin0_consensus_types::runtime::ConsensusCandidates;
use neutrin0_primitives::{BlsPublicKey, Hash, Validator};
use neutrin0_runtime_abi::StateWitness;
use neutrin0_runtime_core::{StateBackend, WitnessState};

use crate::rotation::RotationError;

/// Exact key of a permanent BLS identity ban in the independent trie.
#[must_use]
pub fn identity_key(identity: &BlsPublicKey) -> Vec<u8> {
    let mut key = b"consensus:identity-sanction:".to_vec();
    key.extend_from_slice(identity);
    key
}

/// Keys required by one complete identity-sanction transition, in canonical order.
#[must_use]
pub fn witness_keys(
    previous: &[Validator],
    candidates: &ConsensusCandidates,
    offenders: &[Validator],
) -> BTreeSet<Vec<u8>> {
    previous
        .iter()
        .chain(offenders)
        .map(|validator| identity_key(&validator.pubkey))
        .chain(
            candidates
                .entries
                .iter()
                .filter_map(|candidate| candidate.identity)
                .map(|identity| identity_key(&identity.pubkey)),
        )
        .collect()
}

/// Authenticate every lookup before the transition can use absence or insert.
///
/// # Errors
/// Returns a witness error for a wrong root, missing key/path or forged content.
pub fn authenticate_witness(
    root: Hash,
    witness: &StateWitness,
    required: &BTreeSet<Vec<u8>>,
) -> Result<WitnessState, RotationError> {
    if witness.pre_state_root != root {
        return Err(RotationError::Witness);
    }
    // An authenticated empty trie proves every identity absent without a path.
    // Synthesize only its declared accesses; this cannot bypass a nonempty root.
    if root == neutrin0_runtime_core::EMPTY_STATE_ROOT {
        if !witness.nodes.is_empty() || !witness.values.is_empty() {
            return Err(RotationError::Witness);
        }
        return WitnessState::from_owned(StateWitness {
            pre_state_root: root,
            nodes: Vec::new(),
            values: Vec::new(),
            witnessed_keys: required.iter().cloned().collect(),
        })
        .map_err(|_| RotationError::Witness);
    }
    if required
        .iter()
        .any(|key| !witness.witnessed_keys.contains(key))
    {
        return Err(RotationError::Witness);
    }
    WitnessState::new(witness).map_err(|_| RotationError::Witness)
}

fn banned(state: &mut impl StateBackend, identity: &BlsPublicKey) -> Result<bool, RotationError> {
    match state.read(&identity_key(identity)) {
        None => Ok(false),
        Some(value) if value == [1] => Ok(true),
        Some(_) => Err(RotationError::Codec),
    }
}

/// Append proven bans and remove their identities from both seats and candidates.
///
/// A seat or candidate at an offender's address leaves with the banned
/// identity even when a key rotation moved it to another key after the
/// offence (design 19), so a safety admission ejects the offending seat at
/// once whatever key it holds now.
///
/// The caller authenticates its backend and required lookups first. No operation
/// deletes a ban; a different runtime, account or registration cannot clear it.
///
/// # Errors
/// Returns a codec error for a malformed existing permanent marker.
pub fn apply(
    state: &mut impl StateBackend,
    previous: &[Validator],
    candidates: &ConsensusCandidates,
    offenders: &[Validator],
) -> Result<(Vec<Validator>, ConsensusCandidates), RotationError> {
    for offender in offenders {
        // Read first, including duplicate historical sanctions, so a malformed
        // stored value cannot be silently overwritten with a valid marker.
        let _ = banned(state, &offender.pubkey)?;
        state.write(&identity_key(&offender.pubkey), alloc::vec![1]);
    }
    let offending: BTreeSet<Hash> = offenders
        .iter()
        .map(|offender| offender.withdrawal_credentials)
        .collect();
    let mut remaining = Vec::with_capacity(previous.len());
    for validator in previous {
        if !offending.contains(&validator.withdrawal_credentials)
            && !banned(state, &validator.pubkey)?
        {
            remaining.push(validator.clone());
        }
    }
    let mut eligible = ConsensusCandidates::default();
    for candidate in &candidates.entries {
        let keep = !offending.contains(&candidate.address)
            && match candidate.identity {
                None => true,
                Some(identity) => !banned(state, &identity.pubkey)?,
            };
        if keep {
            eligible.entries.push(candidate.clone());
        }
    }
    Ok((remaining, eligible))
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrin0_consensus_types::runtime::{BlsIdentity, ConsensusCandidate};
    use neutrin0_runtime_core::host::{LiveTrie, TracingState, witness_of};

    fn seat(byte: u8) -> Validator {
        Validator {
            pubkey: [byte; 48],
            withdrawal_credentials: neutrin0_primitives::runtime_account([byte; 20]),
            effective_stake: 100,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        }
    }

    fn candidates(address: u8) -> ConsensusCandidates {
        let mut candidates = ConsensusCandidates::default();
        candidates.upsert(ConsensusCandidate {
            address: [address; 32],
            stake: 100,
            identity: Some(BlsIdentity {
                pubkey: [1; 48],
                pop_signature: [0; 96],
            }),
        });
        candidates
    }

    #[test]
    fn permanent_bans_release_seats_and_follow_identity_across_accounts() {
        let previous = [seat(1), seat(2)];
        let offered = candidates(9);
        let live = LiveTrie::default();
        let mut state = TracingState::new(&live);
        let (remaining, filtered) = apply(&mut state, &previous, &offered, &[seat(1)]).unwrap();
        assert_eq!(remaining, [seat(2)]);
        assert_eq!(filtered.entries, Vec::new());
        let root = state.post_state_root();
        let (post, witness) = state.into_committed_and_witness().unwrap();
        let required = witness_keys(&previous, &offered, &[seat(1)]);
        let mut guest = authenticate_witness(live.state_root(), &witness, &required).unwrap();
        assert_eq!(
            apply(&mut guest, &previous, &offered, &[seat(1)]).unwrap(),
            (remaining.clone(), filtered)
        );
        assert_eq!(guest.post_state_root(), root);

        // A later execution program/account sees the same consensus ledger.
        let offered = candidates(10);
        let required = witness_keys(&remaining, &offered, &[]);
        let witness = witness_of(&post, required.clone()).unwrap();
        let mut guest = authenticate_witness(root, &witness, &required).unwrap();
        let (remaining_again, filtered) = apply(&mut guest, &remaining, &offered, &[]).unwrap();
        assert_eq!(remaining_again, remaining);
        assert_eq!(filtered.entries, Vec::new());
        assert_eq!(guest.post_state_root(), root);
    }

    #[test]
    fn a_ban_ejects_the_offending_address_after_its_key_rotated() {
        // The seat at seat(1)'s address now holds another key; the offence
        // was signed with the key it held before.
        let rotated = Validator {
            pubkey: [7; 48],
            ..seat(1)
        };
        let previous = [rotated, seat(2)];
        let mut candidates = ConsensusCandidates::default();
        candidates.upsert(ConsensusCandidate {
            address: seat(1).withdrawal_credentials,
            stake: 100,
            identity: Some(BlsIdentity {
                pubkey: [7; 48],
                pop_signature: [0; 96],
            }),
        });
        let live = LiveTrie::default();
        let mut state = TracingState::new(&live);
        let (remaining, filtered) = apply(&mut state, &previous, &candidates, &[seat(1)]).unwrap();
        assert_eq!(remaining, [seat(2)]);
        assert_eq!(filtered.entries, Vec::new());
    }

    #[test]
    fn forged_absence_and_malformed_markers_fail_closed() {
        let mut live = LiveTrie::default();
        live.insert(&identity_key(&[1; 48]), alloc::vec![1]);
        let offered = candidates(9);
        let required = witness_keys(&[], &offered, &[]);
        let witness = witness_of(live.trie(), required.clone()).unwrap();
        let mut missing_value = witness.clone();
        missing_value.values.clear();
        assert!(authenticate_witness(live.state_root(), &missing_value, &required).is_err());
        let mut wrong_root = witness;
        wrong_root.pre_state_root = [9; 32];
        assert!(authenticate_witness(live.state_root(), &wrong_root, &required).is_err());
        live.insert(&identity_key(&[1; 48]), alloc::vec![2]);
        let witness = witness_of(live.trie(), required.clone()).unwrap();
        let mut guest = authenticate_witness(live.state_root(), &witness, &required).unwrap();
        assert_eq!(
            apply(&mut guest, &[], &offered, &[]),
            Err(RotationError::Codec)
        );
    }
}
