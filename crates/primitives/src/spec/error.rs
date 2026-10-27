//! Why a chain specification is rejected.

use core::fmt;

/// Chain-spec validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainSpecError {
    /// One BLS identity occurs at more than one genesis committee position.
    DuplicateValidatorIdentity,
    /// The block proving allocation limit is zero or exceeds the absolute ceiling.
    InvalidBlockProvingInputLimit,
    /// Committee and chunk product exceeds accountable wire/history bounds.
    CommitteeBounds,
    /// Exit weight could remain usable after its collateral becomes withdrawable.
    ExitDelayOutlivesCollateral,
    /// A genesis execution Guest or the chunk Guest has no pinned identity.
    IncompleteGenesisPrograms,
    /// The hard-fork anchor or its predecessor domains are malformed.
    InvalidFork,
    /// Evidence limits or the relationship to the withdrawal delay are invalid.
    InvalidEvidencePolicy,
    /// A proof-market basis-point share exceeds 10,000 (design 08).
    InvalidProofMarketPolicy,
    /// The minimum validator stake is zero.
    ZeroMinValidatorStake,
    /// Chain ID zero is reserved as invalid.
    ZeroChainId,
    /// The declared genesis validator commitment does not match the ordered set.
    InvalidGenesisValidatorRoot,
    /// At least one consensus parameter was zero.
    ZeroConsensusParameter,
    /// More finality-vote subnets than the network registers.
    TooManyVoteSubnets,
    /// A quorum numerator/denominator pair was invalid.
    InvalidQuorum,
    /// A fixed-point parameter was outside its valid range.
    InvalidFixedPointParameter,
    /// At least one light-client parameter was zero.
    ZeroLightClientParameter,
    /// The weak-subjectivity period exceeds the unbonding delay in seconds,
    /// so a fork signed inside a still-trusted window could be signed by
    /// validators who no longer hold any slashable balance.
    WeakSubjectivityOutlivesAccountability,
    /// The initial validator set must not be empty.
    EmptyValidatorSet,
    /// A genesis withdrawal account is not a runtime account; see
    /// [`is_runtime_account`](crate::is_runtime_account).
    NonRuntimeWithdrawalAccount,
    /// Validators must start with non-zero effective stake.
    ZeroValidatorStake,
    /// Total validator stake exceeds [`MAX_TOTAL_STAKE`](crate::MAX_TOTAL_STAKE).
    ValidatorStakeOverflow,
    /// An initial validator was declared with a non-genesis
    /// `activation_epoch`, `exit_epoch`, or a pre-slashed status. Genesis validators
    /// must always be born at epoch 0 with `exit_epoch = u64::MAX` so the
    /// validator transition can use `activation_epoch > 0` as the
    /// discriminator for runtime-registered validators.
    NonGenesisInitialValidator,
}

impl fmt::Display for ChainSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateValidatorIdentity => f.write_str("duplicate genesis validator BLS identity"),
            Self::NonRuntimeWithdrawalAccount => f.write_str(
                "genesis withdrawal account must be a runtime account: twelve zero bytes, then the 20-byte address",
            ),
            Self::InvalidBlockProvingInputLimit => f.write_str("block proving input limit must be positive and at most 128 MiB"),
            Self::CommitteeBounds => f.write_str("consensus committee exceeds certificate/history bounds"),
            Self::ExitDelayOutlivesCollateral => f.write_str("unbonding delay must cover the consensus exit delay and two more chunks"),
            Self::InvalidEvidencePolicy => f.write_str("invalid evidence queue/window policy"),
            Self::InvalidProofMarketPolicy => {
                f.write_str("proof-market basis-point share exceeds 10000")
            }
            Self::ZeroMinValidatorStake => f.write_str("minimum validator stake must be non-zero"),
            Self::IncompleteGenesisPrograms => f.write_str("genesis program set is incomplete"),
            Self::InvalidFork => f.write_str("hard-fork anchor is malformed"),
            Self::ZeroChainId => f.write_str("chain ID must be non-zero"),
            Self::InvalidGenesisValidatorRoot => {
                f.write_str("genesis validator root is not canonical")
            }
            Self::ZeroConsensusParameter => f.write_str("consensus parameters must be non-zero"),
            Self::TooManyVoteSubnets => f.write_str("vote_subnets exceeds the registered subnet topics"),
            Self::InvalidQuorum => f.write_str("BFT quorum fraction is invalid"),
            Self::InvalidFixedPointParameter => f.write_str("fixed-point parameter is invalid"),
            Self::ZeroLightClientParameter => {
                f.write_str("light-client parameters must be non-zero")
            }
            Self::WeakSubjectivityOutlivesAccountability => write!(
                f,
                "weak-subjectivity period must not exceed unbonding_delay_blocks * slot_duration_secs"
            ),
            Self::EmptyValidatorSet => f.write_str("initial validator set must not be empty"),
            Self::ZeroValidatorStake => f.write_str("validator effective stake must be non-zero"),
            Self::ValidatorStakeOverflow => f.write_str("total validator stake exceeds the protocol bound"),
            Self::NonGenesisInitialValidator => f.write_str(
                "initial validator must be unslashed with activation_epoch = 0 and exit_epoch = u64::MAX",
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChainSpecError {}
