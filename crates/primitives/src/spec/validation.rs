//! Consistency rules of a chain specification.

use super::{ChainSpec, ChainSpecError, ForkAnchor};
use crate::{
    ConsensusParams, LightClientParams, MAX_BLOCK_PROVING_INPUT_BYTES, MAX_PRIOR_DOMAINS,
    MAX_TOTAL_STAKE, MAX_VOTE_SUBNETS, ProofParams, ZERO_HASH, committee_size_valid,
    is_runtime_account, quorum_fraction_valid,
};

impl ChainSpec {
    /// Validates consistency of consensus-critical chain-spec fields.
    pub fn validate(&self) -> Result<(), ChainSpecError> {
        if self.chain_id == 0 {
            return Err(ChainSpecError::ZeroChainId);
        }

        if !self.genesis_execution.is_complete() || self.genesis_chunk == [0; 8] {
            return Err(ChainSpecError::IncompleteGenesisPrograms);
        }
        if let Some(fork) = &self.fork {
            self.validate_fork(fork)?;
        }
        self.consensus.validate()?;
        self.proof.validate()?;
        self.light_client.validate()?;
        self.validate_runtime_policy()?;
        self.validate_weak_subjectivity()?;
        self.validate_committee()?;
        self.validate_genesis_validators()
    }

    /// Evidence windows, proof-market shares and the stake floor must be
    /// usable against the unbonding delay.
    fn validate_runtime_policy(&self) -> Result<(), ChainSpecError> {
        // The liveness window ends strictly before unbonding, so an admitted
        // obligation always finds the stake it holds; the unbonding delay
        // itself exceeds one chunk so consensus observes a zero stake at a
        // boundary before a record can be retired. Safety evidence has no age
        // window: it is admitted once per identity whenever it arrives.
        if self.runtime.evidence_max_age_blocks == 0
            || self.runtime.evidence_max_age_blocks >= self.runtime.unbonding_delay_blocks
            || self.runtime.unbonding_delay_blocks <= self.consensus.chunk_size
            || self.runtime.evidence_max_pending == 0
            || self.runtime.evidence_max_pending > 4096
            || self.runtime.evidence_executions_per_block == 0
            || self.runtime.evidence_executions_per_block > self.runtime.evidence_max_pending
            || self.runtime.evidence_admissions_per_block == 0
            || self.runtime.evidence_admissions_per_block > self.runtime.evidence_max_pending
        {
            return Err(ChainSpecError::InvalidEvidencePolicy);
        }
        if self.runtime.chunk_prover_fee_bps > 10_000 || self.runtime.annual_issuance_bps > 10_000 {
            return Err(ChainSpecError::InvalidProofMarketPolicy);
        }
        if self.runtime.min_validator_stake == 0 {
            return Err(ChainSpecError::ZeroMinValidatorStake);
        }
        Ok(())
    }

    /// The light-client trust window must stay inside the accountability
    /// horizon.
    fn validate_weak_subjectivity(&self) -> Result<(), ChainSpecError> {
        // Weak subjectivity is only sound while a fork signed by the anchor's
        // validators can still be punished. Safety evidence has no age window
        // and deducts whatever stake remains, so the trust window may not
        // outlast the unbonding delay.
        if self
            .runtime
            .unbonding_delay_blocks
            .checked_mul(self.consensus.slot_duration_secs)
            .is_none_or(|secs| self.light_client.weak_subjectivity_period_secs > secs)
        {
            return Err(ChainSpecError::WeakSubjectivityOutlivesAccountability);
        }
        Ok(())
    }

    /// The genesis committee must fit the accountable bounds, and its seats'
    /// exit weight must stay collateralized.
    fn validate_committee(&self) -> Result<(), ChainSpecError> {
        if self.initial_validators.is_empty() {
            return Err(ChainSpecError::EmptyValidatorSet);
        }
        if !committee_size_valid(self.initial_validators.len(), self.consensus.chunk_size) {
            return Err(ChainSpecError::CommitteeBounds);
        }
        if self
            .consensus
            .exit_accountability_blocks()
            .is_none_or(|blocks| self.runtime.unbonding_delay_blocks < blocks)
        {
            return Err(ChainSpecError::ExitDelayOutlivesCollateral);
        }
        Ok(())
    }

    /// The declared validator root must be canonical and every entry a
    /// distinct, funded, runtime-payable genesis seat within the stake bound.
    fn validate_genesis_validators(&self) -> Result<(), ChainSpecError> {
        if self.genesis_validator_set_root != crate::validators_root(&self.initial_validators) {
            return Err(ChainSpecError::InvalidGenesisValidatorRoot);
        }

        let mut total_stake = 0_u128;
        let mut identities = alloc::collections::BTreeSet::new();
        for validator in &self.initial_validators {
            if !identities.insert(validator.pubkey) {
                return Err(ChainSpecError::DuplicateValidatorIdentity);
            }
            if validator.effective_stake == 0 {
                return Err(ChainSpecError::ZeroValidatorStake);
            }
            if !is_runtime_account(&validator.withdrawal_credentials) {
                return Err(ChainSpecError::NonRuntimeWithdrawalAccount);
            }
            // The validator transition uses `activation_epoch > 0` as the
            // discriminator for runtime-registered validators. Chain-spec
            // entries must be born at genesis so it can tell the two
            // populations apart.
            if validator.activation_epoch != 0 || validator.exit_epoch != u64::MAX {
                return Err(ChainSpecError::NonGenesisInitialValidator);
            }
            // The runtime keeps its validator set within the same bound, so
            // every rotated consensus total fits `u128`.
            total_stake = total_stake
                .checked_add(validator.effective_stake)
                .filter(|total| *total <= MAX_TOTAL_STAKE)
                .ok_or(ChainSpecError::ValidatorStakeOverflow)?;
        }

        Ok(())
    }

    /// A fork starts after chunk zero at nonzero commitments, and its domains
    /// are bounded, contiguous and end with the predecessor's at the anchor.
    fn validate_fork(&self, fork: &ForkAnchor) -> Result<(), ChainSpecError> {
        let mut previous_end = 0;
        for prior in &fork.prior_domains {
            if prior.chain_spec_hash == ZERO_HASH
                || prior.end_chunk <= previous_end
                || prior.end_chunk.checked_mul(self.consensus.chunk_size) != Some(prior.end_height)
            {
                return Err(ChainSpecError::InvalidFork);
            }
            previous_end = prior.end_chunk;
        }
        if fork.count == 0
            || fork.predecessor == ZERO_HASH
            || !fork.endpoint_programs.is_complete()
            || !is_runtime_account(&fork.endpoint_prover)
            || fork.start.next_chunk_id != fork.count
            || fork.start.programs != self.genesis_programs()
            || fork.start.fork.is_some()
            || fork
                .start
                .next_chunk_id
                .checked_mul(self.consensus.chunk_size)
                != Some(fork.start.height)
            || fork.prior_domains.len() > MAX_PRIOR_DOMAINS
            || fork.prior_domains.last().is_none_or(|last| {
                last.chain_spec_hash != fork.predecessor || last.end_chunk != fork.count
            })
        {
            return Err(ChainSpecError::InvalidFork);
        }
        Ok(())
    }
}

impl ConsensusParams {
    fn validate(&self) -> Result<(), ChainSpecError> {
        if self.slot_duration_secs == 0
            || self.chunk_size == 0
            || self.proof_orphan_slots == 0
            || self.proof_exclusive_slots == 0
            || self.max_receipts_per_block == 0
            || self.bft_round_timeout_base_secs == 0
            || self.bft_round_timeout_step_secs == 0
        {
            return Err(ChainSpecError::ZeroConsensusParameter);
        }

        validate_quorum(
            self.bft_prevote_quorum_numerator,
            self.bft_prevote_quorum_denominator,
        )?;
        validate_quorum(
            self.bft_precommit_quorum_numerator,
            self.bft_precommit_quorum_denominator,
        )?;

        if self.vote_subnets == 0 {
            return Err(ChainSpecError::ZeroConsensusParameter);
        }
        if self.vote_subnets > u16::from(MAX_VOTE_SUBNETS) {
            return Err(ChainSpecError::TooManyVoteSubnets);
        }

        if self.expected_proposers_per_slot == 0 || self.expected_aggregators_per_round == 0 {
            return Err(ChainSpecError::InvalidFixedPointParameter);
        }

        if self.epoch_length_in_chunks == 0
            || self.activation_delay_epochs == 0
            || self.exit_delay_epochs == 0
        {
            return Err(ChainSpecError::ZeroConsensusParameter);
        }

        Ok(())
    }
}

impl ProofParams {
    const fn validate(&self) -> Result<(), ChainSpecError> {
        if self.max_block_proving_input_bytes == 0
            || self.max_block_proving_input_bytes > MAX_BLOCK_PROVING_INPUT_BYTES
        {
            return Err(ChainSpecError::InvalidBlockProvingInputLimit);
        }
        Ok(())
    }
}

impl LightClientParams {
    fn validate(&self) -> Result<(), ChainSpecError> {
        if self.weak_subjectivity_period_secs == 0 || self.stale_threshold_secs == 0 {
            return Err(ChainSpecError::ZeroLightClientParameter);
        }

        Ok(())
    }
}

fn validate_quorum(numerator: u64, denominator: u64) -> Result<(), ChainSpecError> {
    if !quorum_fraction_valid(numerator, denominator) {
        return Err(ChainSpecError::InvalidQuorum);
    }

    Ok(())
}
