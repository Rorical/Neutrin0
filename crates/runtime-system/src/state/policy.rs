//! The governable runtime policy, its validity bounds and the pending policy
//! an enactment schedules.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_runtime_core::StateBackend;

use super::{GAS_PARTICIPATION_ACK, RUNTIME_POLICY_KEY, read_canonical, write_record};
use crate::accountability;

/// Denominator of every basis-point share.
pub(crate) const BASIS_POINTS: u16 = 10_000;
/// Reporter share of a safety deduction a chain specification starts with.
pub(crate) const DEFAULT_REPORTER_REWARD_BPS: u16 = 1_000;

/// Runtime policy that governance may change: evidence windows and queue
/// bounds, the liveness deductions, the reporter share and the proof-market
/// shares and issuance rate.
///
/// Everything consensus depends on (unbonding delay, chunk size, slot timing)
/// stays in the chain specification and reaches the STF through the evidence
/// anchor. Safety offences always deduct the whole slashable balance, so no
/// safety amount is governable. Fees follow EIP-1559 inside the runtime, so no
/// fee rate is either.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimePolicy {
    /// Minimum stake a validator may hold other than zero.
    pub min_validator_stake: u128,
    /// Evidence admission window after its source chunk ends, in blocks.
    pub evidence_max_age_blocks: u64,
    /// Maximum verified sanctions retained in the mandatory FIFO.
    pub evidence_max_pending: u32,
    /// Maximum proof-carrying evidence admissions per block.
    pub evidence_admissions_per_block: u32,
    /// Mandatory FIFO executions reserved at the start of each block.
    pub evidence_executions_per_block: u32,
    /// Stake deduction for proven precommit certificate non-inclusion.
    pub inactivity_leak_amount: u128,
    /// Reporter share of actual safety deductions, in basis points (0 to 10,000).
    pub reporter_reward_bps: u16,
    /// Share of a block's base fee escrowed for the prover of the block's
    /// chunk, in basis points; the rest goes to the chunk's participating
    /// committee by stake (design 08).
    pub chunk_prover_fee_bps: u16,
    /// Annual issuance as basis points of total stake: half to block provers,
    /// half to chunk provers, accrued per block over the time since the
    /// previous block (design 08).
    pub annual_issuance_bps: u16,
    /// Stake deduction for a proven abandoned height (design 08).
    pub abandonment_penalty_amount: u128,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self::from_params(&neutrin0_primitives::RuntimeParams::default())
    }
}

impl RuntimePolicy {
    /// The genesis policy a chain specification declares.
    #[must_use]
    pub const fn from_params(params: &neutrin0_primitives::RuntimeParams) -> Self {
        Self {
            min_validator_stake: params.min_validator_stake,
            evidence_max_age_blocks: params.evidence_max_age_blocks,
            evidence_max_pending: params.evidence_max_pending,
            evidence_admissions_per_block: params.evidence_admissions_per_block,
            evidence_executions_per_block: params.evidence_executions_per_block,
            inactivity_leak_amount: params.inactivity_leak_amount,
            reporter_reward_bps: DEFAULT_REPORTER_REWARD_BPS,
            chunk_prover_fee_bps: params.chunk_prover_fee_bps,
            annual_issuance_bps: params.annual_issuance_bps,
            abandonment_penalty_amount: params.abandonment_penalty_amount,
        }
    }

    /// Structural bounds that hold for any chain.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        self.min_validator_stake > 0
            && self.evidence_max_age_blocks > 0
            && self.evidence_max_pending > 0
            && self.evidence_max_pending <= accountability::MAX_PENDING
            && self.evidence_admissions_per_block > 0
            && self.evidence_admissions_per_block <= self.evidence_max_pending
            && self.evidence_executions_per_block > 0
            && self.evidence_executions_per_block <= self.evidence_max_pending
            && self.reporter_reward_bps <= BASIS_POINTS
            && self.chunk_prover_fee_bps <= BASIS_POINTS
            && self.annual_issuance_bps <= BASIS_POINTS
    }

    /// Full validity against the genesis-fixed facts carried by the anchor:
    /// the governable liveness window ends strictly before the unbonding
    /// delay, so an admitted liveness obligation always finds bonded stake
    /// and a swept offence marker can never bind again.
    #[must_use]
    #[allow(
        clippy::cast_lossless,
        reason = "Const policy validation widens u32 counters; From is not a const trait call."
    )]
    pub const fn is_valid_for(
        &self,
        anchor: &neutrin0_consensus_types::evidence::EvidenceAnchor,
    ) -> bool {
        let unbonding_delay_blocks = anchor.unbonding_delay_blocks;
        let Some(minimum_age) = anchor.chunk_size.checked_mul(3) else {
            return false;
        };
        // Each counter is u32, so even their maxima times these fixed costs
        // and the bounded challenge reserve cannot overflow u64.
        let required_gas = (self.evidence_executions_per_block as u64) * crate::GAS_SANCTION
            + (self.evidence_admissions_per_block as u64) * accountability::GAS_EVIDENCE_ADMISSION
            + 512 * GAS_PARTICIPATION_ACK
            + crate::proving::settlement_gas_bound(anchor.chunk_size);
        self.is_well_formed()
            && anchor.is_well_formed()
            && self.evidence_max_age_blocks < unbonding_delay_blocks
            && (self.inactivity_leak_amount == 0 || self.evidence_max_age_blocks >= minimum_age)
            && required_gas <= anchor.block_gas_limit
    }

    /// Whether replacing `self` with `next` changes how much stake can be
    /// lost: a liveness deduction, the reporter share of safety deductions or
    /// the liveness evidence window.
    #[must_use]
    pub const fn changes_stake_risk(&self, next: &Self) -> bool {
        self.inactivity_leak_amount != next.inactivity_leak_amount
            || self.abandonment_penalty_amount != next.abandonment_penalty_amount
            || self.reporter_reward_bps != next.reporter_reward_bps
            || self.evidence_max_age_blocks != next.evidence_max_age_blocks
    }
}

/// Chunks an enacted policy that leaves stake risk unchanged waits before it
/// takes effect.
pub const POLICY_DELAY_CHUNKS: u64 = 64;

/// Canonical key of an enacted policy waiting for its effective height.
pub const PENDING_POLICY_KEY: &[u8] = b"runtime:policy:pending";

/// An enacted policy and the first block it governs (design 20).
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingPolicy {
    /// Policy that takes effect.
    pub policy: RuntimePolicy,
    /// First block executed under it.
    pub effective_height: u64,
}

/// Blocks between enacting `next` over `current` and its first block.
///
/// A change of stake risk waits one unbonding delay and two blocks, so stake
/// unbonded in the block after enactment matures and is withdrawn while the
/// old policy still applies: unbonding stake stays slashable, so nothing
/// shorter lets a dissenter leave. Any other change waits
/// [`POLICY_DELAY_CHUNKS`] chunks.
#[must_use]
pub const fn policy_delay_blocks(
    current: &RuntimePolicy,
    next: &RuntimePolicy,
    anchor: &neutrin0_consensus_types::evidence::EvidenceAnchor,
) -> u64 {
    if current.changes_stake_risk(next) {
        anchor.unbonding_delay_blocks.saturating_add(2)
    } else {
        anchor.chunk_size.saturating_mul(POLICY_DELAY_CHUNKS)
    }
}

/// Load the enacted policy waiting for its effective height, if any.
pub fn load_pending_policy<B: StateBackend>(state: &mut B) -> Option<PendingPolicy> {
    read_canonical(state, PENDING_POLICY_KEY)
}

/// Schedule an enacted policy; a newer enactment replaces a pending one.
pub(crate) fn store_pending_policy<B: StateBackend>(state: &mut B, pending: &PendingPolicy) {
    write_record(state, PENDING_POLICY_KEY, pending);
}

/// Make a pending policy current once its effective height is reached and
/// the mandatory sanction queue fits its capacity; otherwise it keeps
/// waiting. Runs at block start, before the block reads its policy.
pub(crate) fn activate_pending_policy<B: StateBackend>(state: &mut B, height: u64) {
    let Some(pending) = load_pending_policy(state) else {
        return;
    };
    if height < pending.effective_height
        || accountability::pending_count(state) > pending.policy.evidence_max_pending as usize
    {
        return;
    }
    store_runtime_policy(state, &pending.policy);
    state.delete(PENDING_POLICY_KEY);
}

/// Read the governable policy; absent state means the canonical defaults.
///
/// Stored bytes that do not decode abort the transition: a layout change
/// must never silently reset every governed value to its default.
pub fn load_runtime_policy<B: StateBackend>(state: &mut B) -> RuntimePolicy {
    read_canonical(state, RUNTIME_POLICY_KEY).unwrap_or_default()
}

/// Write the governable policy.
pub(crate) fn store_runtime_policy<B: StateBackend>(state: &mut B, policy: &RuntimePolicy) {
    write_record(state, RUNTIME_POLICY_KEY, policy);
}
