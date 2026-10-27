//! Parameter groups of the chain specification, each covered by its hash.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    DEFAULT_ABANDONMENT_PENALTY_AMOUNT, DEFAULT_ACTIVATION_DELAY_EPOCHS,
    DEFAULT_ANNUAL_ISSUANCE_BPS, DEFAULT_BFT_ROUND_TIMEOUT_BASE_SECS,
    DEFAULT_BFT_ROUND_TIMEOUT_STEP_SECS, DEFAULT_CHUNK_PROVER_FEE_BPS, DEFAULT_CHUNK_SIZE,
    DEFAULT_EPOCH_LENGTH_IN_CHUNKS, DEFAULT_EXIT_DELAY_EPOCHS,
    DEFAULT_EXPECTED_AGGREGATORS_PER_ROUND, DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
    DEFAULT_INACTIVITY_LEAK_AMOUNT, DEFAULT_LIGHT_CLIENT_STALE_THRESHOLD_SECS,
    DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES, DEFAULT_MAX_RECEIPTS_PER_BLOCK,
    DEFAULT_MIN_VALIDATOR_STAKE, DEFAULT_PROOF_EXCLUSIVE_SLOTS, DEFAULT_PROOF_ORPHAN_SLOTS,
    DEFAULT_SLOT_DURATION_SECS, DEFAULT_UNBONDING_DELAY_BLOCKS, DEFAULT_VOTE_SUBNETS,
    DEFAULT_WEAK_SUBJECTIVITY_PERIOD_SECS, FixedU128,
};

/// Consensus timing and finality constants covered by the chain-spec hash.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConsensusParams {
    /// Slot duration in seconds.
    pub slot_duration_secs: u64,
    /// Chunk size in canonical block heights.
    pub chunk_size: u64,
    /// Retention of receipts for blocks not yet known locally, in slots
    /// (design 08).
    pub proof_orphan_slots: u64,
    /// Proposer-only receipt selection window after a block's slot; also the
    /// age at which an unproven candidate is stale and no longer extended
    /// (design 08).
    pub proof_exclusive_slots: u64,
    /// Distinct valid receipts a node retains per block: the proposer's and
    /// the earliest others to arrive (design 08).
    pub max_receipts_per_block: u32,
    /// Prevote quorum numerator.
    pub bft_prevote_quorum_numerator: u64,
    /// Prevote quorum denominator.
    pub bft_prevote_quorum_denominator: u64,
    /// Precommit quorum numerator.
    pub bft_precommit_quorum_numerator: u64,
    /// Precommit quorum denominator.
    pub bft_precommit_quorum_denominator: u64,
    /// Expected proposer count per slot as `Q64.64`.
    pub expected_proposers_per_slot: FixedU128,
    /// Expected aggregator count per `(chunk, round)` as `Q64.64`.
    pub expected_aggregators_per_round: FixedU128,
    /// Number of finality-vote subnets.
    pub vote_subnets: u16,
    /// Round-zero deadline for each propose, prevote and precommit phase.
    pub bft_round_timeout_base_secs: u64,
    /// Linear per-round backoff added to the round timeout. Round N
    /// waits `base + N * step` seconds before timing out so a
    /// pathologically partitioned network still makes progress
    /// after the partition heals.
    pub bft_round_timeout_step_secs: u64,
    /// Number of consecutive chunks that make up one epoch. Together
    /// with `chunk_size` this defines `epoch_length_blocks =
    /// chunk_size * epoch_length_in_chunks`. Used by the
    /// complete chunk validator transition to compute the current epoch
    /// from the chunk index that just finalised:
    /// `current_epoch = (chunk_id + 1) / epoch_length_in_chunks`.
    pub epoch_length_in_chunks: u64,
    /// Activation delay applied to runtime-registered validators in
    /// epochs. A validator registration accepted in
    /// chunk N causes the chunk transition to seat the new consensus
    /// validator with
    /// `activation_epoch = (N + 1) / epoch_length_in_chunks +
    /// activation_delay_epochs`. The validator stays at
    /// `effective_stake = 0` until that epoch, so every existing
    /// `effective_stake == 0` filter naturally excludes them from
    /// VRF eligibility and BFT quorum weighting.
    pub activation_delay_epochs: u64,
    /// Exit delay applied to runtime-registered validators in
    /// epochs. When a runtime-registered validator's runtime stake
    /// drops to zero, the chunk transition sets `exit_epoch =
    /// current_epoch + exit_delay_epochs`. After that epoch the
    /// validator leaves the committee vector. Until that epoch its last
    /// authenticated weight remains backed by unwithdrawable collateral.
    pub exit_delay_epochs: u64,
}

impl ConsensusParams {
    /// Blocks a withdrawn stake must stay slashable after its full unstake.
    ///
    /// An unstake in the first block of chunk `c` is seen at the boundary
    /// entering `c + 1`. The seat keeps its weight through epoch
    /// `exit_delay_epochs` after that, that is through chunk at most
    /// `c + exit_delay_epochs * epoch_length_in_chunks`; it signs that
    /// chunk's certificate during the next chunk, and evidence of that
    /// signature can be admitted only once it finalizes, in the chunk after.
    /// The unbonding delay must cover all of it; what it adds beyond is the
    /// window for proving and admitting evidence of the last signatures.
    /// `None` on overflow.
    #[must_use]
    pub const fn exit_accountability_blocks(&self) -> Option<u64> {
        match self
            .exit_delay_epochs
            .checked_mul(self.epoch_length_in_chunks)
        {
            Some(chunks) => match chunks.checked_add(2) {
                Some(chunks) => chunks.checked_mul(self.chunk_size),
                None => None,
            },
            None => None,
        }
    }
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            slot_duration_secs: DEFAULT_SLOT_DURATION_SECS,
            chunk_size: DEFAULT_CHUNK_SIZE,
            proof_orphan_slots: DEFAULT_PROOF_ORPHAN_SLOTS,
            proof_exclusive_slots: DEFAULT_PROOF_EXCLUSIVE_SLOTS,
            max_receipts_per_block: DEFAULT_MAX_RECEIPTS_PER_BLOCK,
            bft_prevote_quorum_numerator: 2,
            bft_prevote_quorum_denominator: 3,
            bft_precommit_quorum_numerator: 2,
            bft_precommit_quorum_denominator: 3,
            expected_proposers_per_slot: DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
            expected_aggregators_per_round: DEFAULT_EXPECTED_AGGREGATORS_PER_ROUND,
            vote_subnets: DEFAULT_VOTE_SUBNETS,
            bft_round_timeout_base_secs: DEFAULT_BFT_ROUND_TIMEOUT_BASE_SECS,
            bft_round_timeout_step_secs: DEFAULT_BFT_ROUND_TIMEOUT_STEP_SECS,
            epoch_length_in_chunks: DEFAULT_EPOCH_LENGTH_IN_CHUNKS,
            activation_delay_epochs: DEFAULT_ACTIVATION_DELAY_EPOCHS,
            exit_delay_epochs: DEFAULT_EXIT_DELAY_EPOCHS,
        }
    }
}

/// Proof-market and proving-input limits covered by the chain-spec hash.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProofParams {
    /// Maximum persisted block proving envelope, including evidence attachments.
    pub max_block_proving_input_bytes: u64,
}

impl Default for ProofParams {
    fn default() -> Self {
        Self {
            max_block_proving_input_bytes: DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
        }
    }
}

/// Light-client constants covered by the chain-spec hash.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct LightClientParams {
    /// Weak-subjectivity period in seconds.
    pub weak_subjectivity_period_secs: u64,
    /// Maximum accepted age of an advancing light-client endpoint in seconds.
    pub stale_threshold_secs: u64,
}

impl Default for LightClientParams {
    fn default() -> Self {
        Self {
            weak_subjectivity_period_secs: DEFAULT_WEAK_SUBJECTIVITY_PERIOD_SECS,
            stale_threshold_secs: DEFAULT_LIGHT_CLIENT_STALE_THRESHOLD_SECS,
        }
    }
}

/// Runtime-execution constants covered by the chain-spec hash.
///
/// Captures the chain's fee-market and consensus-economics knobs.
/// Borsh uses one positional wire format; adding or reordering fields is an
/// incompatible protocol change, with no fallback for previous layouts.
/// `Default` returns the canonical configuration:
/// [`DEFAULT_MIN_VALIDATOR_STAKE`], [`DEFAULT_UNBONDING_DELAY_BLOCKS`]
/// (fourteen days), no inactivity leak, [`DEFAULT_ABANDONMENT_PENALTY_AMOUNT`],
/// [`DEFAULT_CHUNK_PROVER_FEE_BPS`] and
/// [`DEFAULT_ANNUAL_ISSUANCE_BPS`]. Safety offences always deduct the whole
/// slashable balance. Chains override individual fields through
/// `chain-spec.toml`:
///
/// ```toml
/// min_validator_stake = "32000000000000000000"   # 32 tokens in wei
/// unbonding_delay_blocks = 302_400   # fourteen days of 4 s slots
/// inactivity_leak_amount = "1000000000000000000" # one token
/// annual_issuance_bps = 200
/// ```
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeParams {
    /// Admission window for liveness evidence (inactivity and abandonment)
    /// after its authenticated source chunk ends. Governable; strictly below
    /// `unbonding_delay_blocks`. Safety evidence has no age window: it is
    /// admitted once per identity whenever it arrives.
    pub evidence_max_age_blocks: u64,
    /// Maximum number of verified sanctions retained in the mandatory FIFO.
    pub evidence_max_pending: u32,
    /// Maximum proof-carrying evidence admissions per block.
    pub evidence_admissions_per_block: u32,
    /// Mandatory FIFO executions reserved at the start of each block.
    pub evidence_executions_per_block: u32,
    /// Minimum stake of a runtime validator; must be positive. Registration
    /// and stake must reach it, and a partial unstake may not leave a
    /// validator below it (a full exit to zero is always allowed).
    /// Governable after genesis.
    pub min_validator_stake: u128,
    /// Number of blocks an unstaked / exited amount waits in the
    /// per-validator withdrawal queue before becoming claimable by
    /// a withdrawal transaction. Surfaced through
    /// `RuntimeBlockInput.block_height` and the queue's `mature_at_height`
    /// arithmetic.
    pub unbonding_delay_blocks: u64,
    /// Stake deduction for proven precommit certificate non-inclusion.
    /// Clamped to current stake. Safety offences always deduct the whole
    /// slashable balance and have no configurable amount.
    pub inactivity_leak_amount: u128,
    /// Stake deduction for a proven abandoned height: a signed block the
    /// canonical chain replaced after its exclusive proof window. Clamped to
    /// current stake; zero disables the offence. Governable after genesis.
    pub abandonment_penalty_amount: u128,
    /// Share of a block's base fee escrowed for the prover of the block's
    /// chunk and paid when that chunk proof is ratified, in basis points; the
    /// rest goes to the chunk's participating committee by stake (design
    /// 08). Governable after genesis.
    pub chunk_prover_fee_bps: u16,
    /// Annual issuance as basis points of total stake: half to block
    /// provers, half to chunk provers (design 08). Governable after genesis.
    pub annual_issuance_bps: u16,
}

impl Default for RuntimeParams {
    fn default() -> Self {
        // Canonical execution and accountability policy for new chain specifications.
        Self {
            evidence_max_age_blocks: 1024,
            evidence_max_pending: 1024,
            evidence_admissions_per_block: 16,
            evidence_executions_per_block: 16,
            min_validator_stake: DEFAULT_MIN_VALIDATOR_STAKE,
            unbonding_delay_blocks: DEFAULT_UNBONDING_DELAY_BLOCKS,
            inactivity_leak_amount: DEFAULT_INACTIVITY_LEAK_AMOUNT,
            abandonment_penalty_amount: DEFAULT_ABANDONMENT_PENALTY_AMOUNT,
            chunk_prover_fee_bps: DEFAULT_CHUNK_PROVER_FEE_BPS,
            annual_issuance_bps: DEFAULT_ANNUAL_ISSUANCE_BPS,
        }
    }
}
