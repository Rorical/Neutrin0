//! The pure activation, exit and weight transition over the candidate record.

use alloc::{collections::BTreeSet, vec::Vec};

use neutrin0_consensus_types::runtime::{BlsIdentity, ConsensusCandidate, ConsensusCandidates};
use neutrin0_primitives::{ConsensusParams, Hash, Validator};

use super::RotationError;

/// Pure activation and exit transition over the candidate record.
///
/// Candidates carrying a BLS identity that is not yet seated are seated after
/// the activation delay, by stake while the committee has room, and a full
/// committee hands its lowest seat to more stake one seat per chunk (see
/// `rebalance_seats`); invalid possession proofs are ignored, so a
/// registration with a bad proof may have cost gas but never enters
/// consensus. The proof binds the candidate's address, so copying another
/// registration's public key and proof cannot claim its key first. A seated
/// address or BLS key is never seated twice in one committee. The independent
/// identity-sanctions trie removes permanently banned identities before this
/// projection runs.
///
/// A seated validator whose candidate carries another BLS key than its seat,
/// as a key rotation records it, takes that key at this boundary when its
/// proof binds the seat's address and no seat holds it already; stake and
/// position stay.
///
/// A seated validator whose candidate stake is zero exits. Genesis validators
/// the runtime never heard of keep their specification stake until a
/// candidate entry appears for them. A full exit retains its authenticated
/// weight until the exit epoch, when its seat is removed. Collateral remains
/// unwithdrawable beyond that handoff. Slashed identities are removed immediately.
///
/// Every other weighted seat takes its runtime stake, in wei, as its
/// consensus weight unchanged.
///
/// # Errors
/// Returns [`RotationError::Epoch`] on a zero epoch length or overflowing
/// chunk arithmetic and [`RotationError::Stake`] when the next set's total
/// weight exceeds `u128`.
pub fn derive_next_validators(
    previous: &[Validator],
    candidates: &ConsensusCandidates,
    params: &ConsensusParams,
    unbonding_delay_blocks: u64,
    chunk_id: u64,
) -> Result<Vec<Validator>, RotationError> {
    if !neutrin0_primitives::committee_size_valid(previous.len(), params.chunk_size)
        || candidates.entries.len() > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS
    {
        return Err(RotationError::Committee);
    }
    if candidates
        .entries
        .windows(2)
        .any(|entries| entries[0].address >= entries[1].address)
    {
        return Err(RotationError::Codec);
    }
    let identities: BTreeSet<_> = previous.iter().map(|validator| validator.pubkey).collect();
    if identities.len() != previous.len() {
        return Err(RotationError::Committee);
    }
    let next_chunk = chunk_id.checked_add(1).ok_or(RotationError::Epoch)?;
    let epoch = next_chunk
        .checked_div(params.epoch_length_in_chunks)
        .ok_or(RotationError::Epoch)?;
    if params
        .exit_accountability_blocks()
        .is_none_or(|blocks| unbonding_delay_blocks < blocks)
    {
        return Err(RotationError::Epoch);
    }
    let stake_for = |address: &Hash| candidates.get(address).map(|entry| entry.stake);
    // Every seated key, and every key a seat takes at this boundary; an
    // expiring seat's key cannot re-seat at the boundary that expires it.
    let mut keys = identities;
    let mut next = Vec::with_capacity(previous.len() + candidates.entries.len());
    // Runtime stake behind each entry of `next`, projected onto its weight
    // once the whole set is known; `None` keeps the weight already set.
    let mut runtime_stakes = Vec::with_capacity(next.capacity());
    carry_seats(
        previous,
        candidates,
        params,
        epoch,
        &mut keys,
        &mut next,
        &mut runtime_stakes,
    )?;
    let waiting = seat_incoming_candidates(
        previous,
        candidates,
        params,
        epoch,
        &mut keys,
        &mut next,
        &mut runtime_stakes,
    )?;
    rebalance_seats(&mut next, &waiting, params, epoch, &stake_for)?;
    project_weights(&mut next, &runtime_stakes)?;
    if !neutrin0_primitives::committee_size_valid(next.len(), params.chunk_size)
        || !next.iter().any(crate::finality::is_active)
    {
        return Err(RotationError::Committee);
    }
    Ok(next)
}

/// Carry every unexpired seat of `previous` into `next`: schedule the exit of
/// a seat whose stake left, apply its recorded key rotation and record the
/// runtime stake behind it.
fn carry_seats(
    previous: &[Validator],
    candidates: &ConsensusCandidates,
    params: &ConsensusParams,
    epoch: u64,
    keys: &mut BTreeSet<neutrin0_primitives::BlsPublicKey>,
    next: &mut Vec<Validator>,
    runtime_stakes: &mut Vec<Option<u128>>,
) -> Result<(), RotationError> {
    let stake_for = |address: &Hash| candidates.get(address).map(|entry| entry.stake);
    for validator in previous {
        // Identity bans live in the independent trie. Neither a slashed seat
        // nor an expired exit needs to consume a lifetime committee slot.
        if epoch >= validator.exit_epoch {
            continue;
        }
        let mut updated = validator.clone();
        let address = &validator.withdrawal_credentials;
        let runtime_stake = stake_for(address);
        // Genesis validators carry no candidate entry until the runtime learns
        // of them; an entry, even at zero, proves they live in the runtime.
        let registered = validator.activation_epoch > 0
            || runtime_stake.is_some()
            || validator.exit_epoch != u64::MAX;
        if registered && validator.exit_epoch == u64::MAX && runtime_stake.unwrap_or(0) == 0 {
            updated.exit_epoch = epoch
                .checked_add(params.exit_delay_epochs)
                .ok_or(RotationError::Epoch)?;
        }
        // A key rotation the runtime recorded (design 19) gives the seat its
        // address's new key, unless the seat is leaving, the key is already
        // seated or its holder did not register it at this address.
        if let Some(identity) = address_identity(candidates, address)
            && updated.exit_epoch == u64::MAX
            && identity.pubkey != validator.pubkey
            && !keys.contains(&identity.pubkey)
            && crate::bls::verify_registration_pop(
                &identity.pubkey,
                address,
                &identity.pop_signature,
            )
        {
            keys.insert(identity.pubkey);
            updated.pubkey = identity.pubkey;
        }
        let stake = if epoch < validator.activation_epoch {
            updated.effective_stake = 0;
            None
        } else if updated.exit_epoch != u64::MAX && runtime_stake.unwrap_or(0) == 0 {
            // Full exits retain their last authenticated weight until the
            // scheduled handoff. The spec keeps its collateral unwithdrawable.
            None
        } else if registered {
            Some(runtime_stake.unwrap_or(0))
        } else {
            // Unregistered genesis validators keep their specification weight.
            None
        };
        next.push(updated);
        runtime_stakes.push(stake);
    }
    Ok(())
}

/// Seat waiting candidates by stake while the committee has room and return
/// the rest, highest stake first, for `rebalance_seats`.
fn seat_incoming_candidates<'c>(
    previous: &[Validator],
    candidates: &'c ConsensusCandidates,
    params: &ConsensusParams,
    epoch: u64,
    keys: &mut BTreeSet<neutrin0_primitives::BlsPublicKey>,
    next: &mut Vec<Validator>,
    runtime_stakes: &mut Vec<Option<u128>>,
) -> Result<Vec<(&'c ConsensusCandidate, BlsIdentity)>, RotationError> {
    let stake_for = |address: &Hash| candidates.get(address).map(|entry| entry.stake);
    // Incoming addresses and keys cannot re-seat at the same boundary that
    // expires their old seat.
    let mut addresses: BTreeSet<_> = previous
        .iter()
        .map(|validator| validator.withdrawal_credentials)
        .collect();
    // Waiting candidates take free seats by stake, highest first (then lowest
    // address), so arrival order cannot hold seats against more stake; the
    // rest keep waiting. Seats in their exit handoff still occupy room.
    let room = neutrin0_primitives::max_committee_size(params.chunk_size);
    let mut incoming: Vec<_> = candidates
        .entries
        .iter()
        .filter(|candidate| candidate.stake > 0)
        .filter_map(|candidate| candidate.identity.map(|identity| (candidate, identity)))
        .collect();
    incoming.sort_by(|(left, _), (right, _)| {
        right
            .stake
            .cmp(&left.stake)
            .then(left.address.cmp(&right.address))
    });
    let mut waiting = Vec::new();
    for (candidate, identity) in incoming {
        // Neither the address nor the BLS key may already be seated.
        if addresses.contains(&candidate.address) || keys.contains(&identity.pubkey) {
            continue;
        }
        if next.len() >= room {
            waiting.push((candidate, identity));
            continue;
        }
        // The key's holder must have registered it at exactly this address.
        if !crate::bls::verify_registration_pop(
            &identity.pubkey,
            &candidate.address,
            &identity.pop_signature,
        ) {
            continue;
        }
        addresses.insert(candidate.address);
        keys.insert(identity.pubkey);
        let activation_epoch = epoch
            .checked_add(params.activation_delay_epochs)
            .ok_or(RotationError::Epoch)?;
        next.push(Validator {
            pubkey: identity.pubkey,
            withdrawal_credentials: candidate.address,
            effective_stake: 0,
            activation_epoch,
            exit_epoch: u64::MAX,
        });
        let active = epoch >= activation_epoch;
        runtime_stakes.push(active.then(|| stake_for(&candidate.address).unwrap_or(0)));
    }
    Ok(waiting)
}

/// The BLS identity the candidate record carries for `address`, if any.
fn address_identity(candidates: &ConsensusCandidates, address: &Hash) -> Option<BlsIdentity> {
    candidates.get(address).and_then(|entry| entry.identity)
}

/// A full committee yields to more stake, one new handoff per chunk.
///
/// Seats leaving for zero stake free places for the highest waiting
/// candidates first. A seat handed off for stake keeps its handoff only while
/// a further waiting candidate still stakes strictly more than it, checked at
/// every boundary until its exit epoch; otherwise the handoff is cancelled, so
/// a challenger that unstakes again cannot evict anyone. Then, when the
/// highest waiting candidate not yet matched stakes strictly more than the
/// lowest active runtime-backed seat, that seat begins its exit handoff. Its
/// stake stays bonded and it keeps its weight until the exit epoch, then waits
/// like any candidate. At least one other active seat must remain.
fn rebalance_seats(
    next: &mut [Validator],
    waiting: &[(&ConsensusCandidate, BlsIdentity)],
    params: &ConsensusParams,
    epoch: u64,
    stake_for: &dyn Fn(&Hash) -> Option<u128>,
) -> Result<(), RotationError> {
    let leaving = |seat: &Validator| seat.exit_epoch != u64::MAX && epoch < seat.exit_epoch;
    let funded =
        |seat: &Validator| stake_for(&seat.withdrawal_credentials).filter(|stake| *stake > 0);
    let voluntary = next
        .iter()
        .filter(|seat| leaving(seat) && funded(seat).is_none())
        .count();
    // Only a key registered at its own address may claim or hold a seat's
    // place. Verified lazily: just the challengers matched below pay for it.
    let mut challengers = waiting
        .iter()
        .filter(|(candidate, identity)| {
            crate::bls::verify_registration_pop(
                &identity.pubkey,
                &candidate.address,
                &identity.pop_signature,
            )
        })
        .skip(voluntary)
        .peekable();
    let mut handed_off: Vec<(u128, Hash, usize)> = next
        .iter()
        .enumerate()
        .filter(|(_, seat)| leaving(seat))
        .filter_map(|(index, seat)| {
            funded(seat).map(|stake| (stake, seat.withdrawal_credentials, index))
        })
        .collect();
    handed_off.sort_unstable();
    for (stake, _, index) in handed_off {
        if challengers
            .peek()
            .is_some_and(|(challenger, _)| challenger.stake > stake)
        {
            challengers.next();
        } else {
            next[index].exit_epoch = u64::MAX;
        }
    }
    let Some((challenger, _)) = challengers.next() else {
        return Ok(());
    };
    let open = |seat: &Validator| seat.exit_epoch == u64::MAX && epoch >= seat.activation_epoch;
    let Some((index, stake)) = next
        .iter()
        .enumerate()
        .filter(|(_, seat)| open(seat))
        .filter_map(|(index, seat)| {
            stake_for(&seat.withdrawal_credentials).map(|stake| (index, stake))
        })
        .min_by_key(|(index, stake)| (*stake, next[*index].withdrawal_credentials))
    else {
        return Ok(());
    };
    if challenger.stake <= stake || next.iter().filter(|seat| open(seat)).count() < 2 {
        return Ok(());
    }
    next[index].exit_epoch = epoch
        .checked_add(params.exit_delay_epochs)
        .ok_or(RotationError::Epoch)?;
    Ok(())
}

/// Assign every runtime-backed seat its consensus weight: the runtime stake
/// in wei, unchanged.
///
/// `runtime_stakes` is parallel to `next`: `Some(stake)` projects that stake
/// onto the seat; `None` keeps the seat's weight as already set (a genesis
/// validator unknown to the runtime keeps its specification weight, a full
/// exit its last authenticated one). Each seat weighs at most the larger of
/// its runtime stake and its previous weight, which the runtime keeps within
/// [`neutrin0_primitives::MAX_TOTAL_STAKE`] in total; a set over `u128` is
/// refused rather than weighed inexactly.
fn project_weights(
    next: &mut [Validator],
    runtime_stakes: &[Option<u128>],
) -> Result<(), RotationError> {
    let mut total = 0_u128;
    for (validator, stake) in next.iter_mut().zip(runtime_stakes) {
        if let Some(stake) = stake {
            validator.effective_stake = *stake;
        }
        total = total
            .checked_add(validator.effective_stake)
            .ok_or(RotationError::Stake)?;
    }
    Ok(())
}
