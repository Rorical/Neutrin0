//! Stake-weighted round-leader selection without replacement.

use alloc::vec::Vec;

use neutrin0_primitives::{DOMAIN_LEADER_DRAW, Hash, Seed, Validator, blake3_256};

/// Select a stake-weighted leader from positive-stake, unslashed validator
/// indices.
///
/// Leaders of one chunk follow a stake-weighted order without replacement:
/// round 0 picks a validator with probability proportional to its effective
/// stake, each later round picks among the validators not yet picked, and the
/// order repeats once every eligible validator has led. Splitting stake across
/// seats therefore buys no extra leadership, while consecutive rounds never
/// return to an offline leader before every other one had its turn. The draws
/// are bound to the chain, the chunk, the validator set and `seed`, the
/// chunk's incoming seed. The seed folds the previous chunk's block VRF
/// outputs, so a validator able to shape the set's encoding, by a top-up or
/// a fresh registration, cannot also grind which leader it yields; only the
/// proposer-withholding bias of the seed itself remains (design 15). Each
/// draw reduces its whole 256-bit digest, unbiased at any total stake.
#[must_use]
pub fn bft_leader(
    chain_id: u64,
    chunk_id: u64,
    round: u32,
    seed: &Seed,
    validators: &[Validator],
) -> Option<u32> {
    let root = neutrin0_primitives::validators_root(validators);
    bft_leader_with_root(chain_id, chunk_id, round, seed, validators, root)
}

/// [`bft_leader`] for a caller already holding `root`, the BLAKE3 of the
/// Borsh-encoded `validators` (their canonical set commitment).
#[must_use]
pub fn bft_leader_with_root(
    chain_id: u64,
    chunk_id: u64,
    round: u32,
    seed: &Seed,
    validators: &[Validator],
    root: Hash,
) -> Option<u32> {
    let mut remaining: Vec<(u32, u128)> = validators
        .iter()
        .enumerate()
        .filter(|(_, validator)| validator.effective_stake > 0)
        .map(|(index, validator)| {
            u32::try_from(index)
                .ok()
                .map(|index| (index, validator.effective_stake))
        })
        .collect::<Option<_>>()?;
    let count = u64::try_from(remaining.len())
        .ok()
        .filter(|count| *count > 0)?;
    // `DOMAIN_LEADER_DRAW || chain_id LE8 || borsh((chunk_id, root, seed)) || draw LE8`.
    let mut leader_input = [0; 104];
    leader_input[..16].copy_from_slice(&DOMAIN_LEADER_DRAW);
    leader_input[16..24].copy_from_slice(&chain_id.to_le_bytes());
    leader_input[24..32].copy_from_slice(&chunk_id.to_le_bytes());
    leader_input[32..64].copy_from_slice(&root);
    leader_input[64..96].copy_from_slice(seed);
    let position = u64::from(round) % count;
    let mut leader = None;
    for draw in 0..=position {
        leader_input[96..].copy_from_slice(&draw.to_le_bytes());
        let digest = blake3_256(&leader_input);
        let total = remaining
            .iter()
            .try_fold(0_u128, |total, (_, stake)| total.checked_add(*stake))?;
        let mut target = neutrin0_primitives::wide_remainder(&digest, total)?;
        let at = remaining.iter().position(|(_, stake)| {
            if target < *stake {
                true
            } else {
                target -= stake;
                false
            }
        })?;
        leader = Some(remaining.remove(at).0);
    }
    leader
}
