//! Protocol bounds and chain-specification defaults.

use crate::{FIXED_U128_ONE, FixedU128};

/// Default slot duration in seconds.
pub const DEFAULT_SLOT_DURATION_SECS: u64 = 4;
/// Default chunk size in canonical block heights.
pub const DEFAULT_CHUNK_SIZE: u64 = 128;
/// Current block gossip envelope ceiling, also used by pre-signing production policy.
pub const MAX_GOSSIP_BLOCK_BYTES: usize = 8 * 1024 * 1024;
/// Largest serialized per-block state diff served to proof-following nodes.
///
/// Pre-signing production policy enforces the same ceiling. A diff is a
/// transport artifact authenticated by the proven post-state root, never a
/// consensus commitment.
pub const MAX_STATE_DIFF_BYTES: usize = 8 * 1024 * 1024;
/// Largest serialized `ProvenBlock` publication: a block, its receipt and its
/// state diff travel as one unit, so this bounds the gossip envelope.
pub const MAX_PROVEN_BLOCK_BYTES: usize =
    MAX_GOSSIP_BLOCK_BYTES + MAX_STATE_DIFF_BYTES + 2 * 1024 * 1024;
/// Maximum active and activation-pending consensus seats.
pub const MAX_CONSENSUS_VALIDATORS: usize = 256;
/// Maximum committee seats multiplied by blocks in a chunk. This keeps full
/// accountable certificates and eight retained historical records bounded.
pub const MAX_CONSENSUS_COMMITTEE_BLOCKS: u64 = 16_384;
/// Most seats a committee of `chunk_size`-block chunks may hold: the largest
/// count [`committee_size_valid`] accepts, or zero for a zero chunk size.
#[must_use]
pub fn max_committee_size(chunk_size: u64) -> usize {
    MAX_CONSENSUS_COMMITTEE_BLOCKS
        .checked_div(chunk_size)
        .and_then(|count| usize::try_from(count).ok())
        .unwrap_or(0)
        .min(MAX_CONSENSUS_VALIDATORS)
}
/// Whether a committee fits the accountable certificate and history budgets.
#[must_use]
pub fn committee_size_valid(count: usize, chunk_size: u64) -> bool {
    count > 0
        && chunk_size > 0
        && count <= MAX_CONSENSUS_VALIDATORS
        && u64::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(chunk_size))
            .is_some_and(|product| product <= MAX_CONSENSUS_COMMITTEE_BLOCKS)
}
/// Default proposer-only receipt window and stale age in slots: 128 s at the
/// default slot, covering the measured full-block proof with margin.
pub const DEFAULT_PROOF_EXCLUSIVE_SLOTS: u64 = 32;
/// Default retention of receipts for unknown blocks, in slots.
pub const DEFAULT_PROOF_ORPHAN_SLOTS: u64 = 8;
/// Default number of distinct valid receipts a node retains per block.
pub const DEFAULT_MAX_RECEIPTS_PER_BLOCK: u32 = 4;

/// Chunk proofs one BFT proposal ratifies at most: a certificate of chunk
/// `N > 0` ratifies exactly chunk `N - 1`'s proof, which the chunk Guest
/// verifies recursively (design 08).
pub const MAX_CHUNK_RATIFICATIONS: u32 = 1;
/// Default expected proposer count per slot, `1.0` as `Q64.64`.
pub const DEFAULT_EXPECTED_PROPOSERS_PER_SLOT: FixedU128 = FIXED_U128_ONE;
/// Default expected aggregator count per `(chunk, round)`, `4.0`
/// as `Q64.64`. Sized to keep aggregation work distributed across
/// roughly a quarter of a 16-validator set per round.
pub const DEFAULT_EXPECTED_AGGREGATORS_PER_ROUND: FixedU128 = FIXED_U128_ONE * 4;
/// Finality-vote subnet topics every node registers; a specification uses at
/// most this many subnets.
pub const MAX_VOTE_SUBNETS: u8 = 16;
/// Default number of finality-vote subnets, all of [`MAX_VOTE_SUBNETS`].
pub const DEFAULT_VOTE_SUBNETS: u16 = 16;
/// Default BFT round-0 timeout in seconds. Two slot durations
/// (at the default 4s slot) gives comfortable propagation room.
pub const DEFAULT_BFT_ROUND_TIMEOUT_BASE_SECS: u64 = 2 * DEFAULT_SLOT_DURATION_SECS;
/// Default per-round linear backoff added to the BFT round timeout.
/// Round N waits `base + N * step` seconds before timing out.
pub const DEFAULT_BFT_ROUND_TIMEOUT_STEP_SECS: u64 = DEFAULT_SLOT_DURATION_SECS;
/// Default epoch length in chunks.
///
/// With the default `chunk_size = 128` this yields a
/// one-chunk-per-epoch cadence (`epoch_length_blocks = 128`).
/// Single-chunk epochs keep activation / exit latency proportional
/// to chunk timing rather than introducing a separate time horizon
/// for staking economics.
pub const DEFAULT_EPOCH_LENGTH_IN_CHUNKS: u64 = 1;
/// Default activation delay for runtime-registered validators in epochs.
///
/// A new `RegisterValidator` lands in epoch E; the validator becomes
/// consensus-eligible at epoch `E + DEFAULT_ACTIVATION_DELAY_EPOCHS`.
/// Two epochs gives every follower at least one full epoch to
/// observe the registration before it influences vote weights.
pub const DEFAULT_ACTIVATION_DELAY_EPOCHS: u64 = 2;
/// Default exit delay for runtime-registered validators in epochs.
///
/// When a validator's runtime stake drops to zero in epoch E, their
/// `exit_epoch` is set to `E + DEFAULT_EXIT_DELAY_EPOCHS`. From that
/// epoch forward they are filtered out of VRF eligibility and BFT
/// quorum weighting. The delay leaves room for slashing windows to
/// close before stake walks free.
pub const DEFAULT_EXIT_DELAY_EPOCHS: u64 = 2;
/// Default weak-subjectivity period in seconds: one unbonding delay.
///
/// A trust anchor stays sound only while a fork signed by the validators who
/// were accountable at it can still be punished. Safety evidence has no age
/// window and the deduction takes whatever stake remains, so the bound is the
/// unbonding delay itself: once every signer of an old anchor has fully
/// withdrawn, nothing they sign costs them anything.
/// The default equals `DEFAULT_UNBONDING_DELAY_BLOCKS * DEFAULT_SLOT_DURATION_SECS`;
/// specifications wanting a longer trust window lengthen the unbonding delay.
pub const DEFAULT_WEAK_SUBJECTIVITY_PERIOD_SECS: u64 =
    DEFAULT_UNBONDING_DELAY_BLOCKS * DEFAULT_SLOT_DURATION_SECS;
/// Default maximum age of an advancing light-client endpoint in seconds.
pub const DEFAULT_LIGHT_CLIENT_STALE_THRESHOLD_SECS: u64 =
    4 * DEFAULT_CHUNK_SIZE * DEFAULT_SLOT_DURATION_SECS;
/// Maximum canonical chain name length.
pub const MAX_CHAIN_NAME_BYTES: usize = 64;
/// Maximum URL or human label length used in chain-spec metadata.
pub const MAX_METADATA_BYTES: usize = 256;

/// Default serialized block proving allocation envelope, covered by the chain spec.
pub const DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES: u64 = 32 * 1024 * 1024;

/// Absolute allocation ceiling for one serialized block proving envelope.
/// This is not a bound on proving time or sustainable chain throughput.
pub const MAX_BLOCK_PROVING_INPUT_BYTES: u64 = 128 * 1024 * 1024;

/// Default unbonding delay used when a chain spec does not override
/// `runtime.unbonding_delay_blocks`: fourteen days at the default slot duration.
///
/// Unbonded stake stays slashable until it matures, and safety evidence has
/// no age window, so this delay is the chain's economic accountability
/// horizon: it bounds the weak-subjectivity period and must exceed both one
/// chunk and the governable liveness evidence window. Chains with a different slot duration
/// or trust window set the delay accordingly.
pub const DEFAULT_UNBONDING_DELAY_BLOCKS: u64 = 14 * 24 * 60 * 60 / DEFAULT_SLOT_DURATION_SECS;

/// Default certificate-omission leak amount: disabled.
///
/// Non-inclusion cannot prove silence. A governed positive amount explicitly opts into bounded signature challenges
/// and their timely-publication/inclusion assumption.
pub const DEFAULT_INACTIVITY_LEAK_AMOUNT: u128 = 0;

/// Default deduction for an abandoned height: one token.
///
/// A proposer whose signed block the chain had to replace after its exclusive
/// proof window pays for the window it held (design 08). The amount is small
/// against the minimum stake, so an honest prover outage costs little, while
/// repeated abandonment costs stake.
pub const DEFAULT_ABANDONMENT_PENALTY_AMOUNT: u128 = WEI_PER_TOKEN;

/// Default chunk prover share of a block's base fee, in basis points.
///
/// The rest goes to the chunk's participating committee by stake, and the
/// proposer keeps only the tips (design 08).
pub const DEFAULT_CHUNK_PROVER_FEE_BPS: u16 = 5_000;

/// Default annual issuance as basis points of total stake (design 08): two
/// percent a year, half to block provers and half to chunk provers, accrued
/// per block over the time since the previous block.
pub const DEFAULT_ANNUAL_ISSUANCE_BPS: u16 = 200;

/// Seconds in the year issuance rates refer to: 365.25 days.
pub const SECONDS_PER_YEAR: u64 = 31_557_600;

/// Decimals of the native token: one token is `10^18` wei, as on Ethereum.
///
/// Every protocol amount (stake, consensus weight, fee, reward, issuance,
/// deduction, withdrawal and EVM balance) is in wei; nothing converts
/// between units.
pub const NATIVE_TOKEN_DECIMALS: u8 = 18;

/// One whole native token in wei.
pub const WEI_PER_TOKEN: u128 = 1_000_000_000_000_000_000;

/// Default minimum stake of a runtime validator: 32 tokens, in wei.
///
/// Registration and stake must reach it, and a partial unstake may not leave
/// a validator below it, so each consensus candidate entry is backed by
/// real, slashable stake rather than dust.
pub const DEFAULT_MIN_VALIDATOR_STAKE: u128 = 32 * WEI_PER_TOKEN;
