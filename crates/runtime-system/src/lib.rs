#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! System modules the Neutrin0 runtime embeds.
//!
//! Staking and the validator lifecycle, stake-weighted governance,
//! proof-authorized evidence admission and the mandatory sanction FIFO.
//! Every economic action runs on behalf of the caller the enclosing
//! execution engine authenticated
//! ([`StateBackend::authenticated_caller`](neutrin0_runtime_core::StateBackend::authenticated_caller));
//! the engine owns transaction decoding, signatures, nonces, fees and
//! rollback. The same code runs inside the SP1 Guest, the WASM master
//! binary and native dry runs; only the state backend differs.

extern crate alloc;

pub mod accountability;
pub mod governance;
pub mod proving;
mod query;
mod staking;
pub mod system;
pub use staking::prune_consensus_candidates;
mod state;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub use governance::{ArtifactPieces, ProposalAction, UpgradeProposal, UpgradeStatus};

pub use query::{
    MAX_REPORTER_STATUS_IDENTITIES, QUERY_METHOD_ACCOUNTABILITY_METRICS,
    QUERY_METHOD_CONSENSUS_CANDIDATES, QUERY_METHOD_PARTICIPATION,
    QUERY_METHOD_PENDING_WITHDRAWALS, QUERY_METHOD_REPORTER_STATUS, QUERY_METHOD_RUNTIME_INFO,
    QUERY_METHOD_RUNTIME_POLICY, QUERY_METHOD_UPGRADE_STATUS, QUERY_METHOD_VALIDATOR_GET,
    QUERY_METHOD_VALIDATOR_REGISTRATION, QUERY_METHOD_VALIDATOR_SET, ReporterIdentity,
    ReporterStatus, ReporterStatusRequest, query,
};
pub use state::{
    ABSENT_KEY_PREFIX, ACCOUNT_KEY_PREFIX, Account, BONDING_KEY_PREFIX, Bonding, PARTICIPATION_KEY,
    PENDING_POLICY_KEY, POLICY_DELAY_CHUNKS, PendingPolicy, REGISTRATION_KEY_PREFIX,
    RUNTIME_POLICY_KEY, RuntimePolicy, VALIDATOR_KEY_PREFIX, Validator, ValidatorRegistration,
    ValidatorSet, ValidatorSetEntry, WITHDRAWAL_KEY_PREFIX, Withdrawal, WithdrawalQueue,
    absent_key, account_key, bonding_key, decode_account, encode_account, encode_validator,
    load_consensus_candidates, load_participation, load_pending_policy, load_runtime_policy,
    load_validator_registration, policy_delay_blocks, registration_key, validator_key,
    withdrawal_key,
};

use borsh::{BorshDeserialize, BorshSerialize};

/// 32-byte system address: the caller identity an execution engine
/// authenticates. The EVM runtime zero-pads an Ethereum account address.
pub type Address = [u8; 32];

// ---------------------------------------------------------------------------
// System gas schedule
// ---------------------------------------------------------------------------

/// Gas the system interface charges for adding collateral to the caller's
/// own validator record.
pub const GAS_STAKE: u64 = 50_000;
/// Gas for queuing collateral into the delayed withdrawal queue.
pub const GAS_UNSTAKE: u64 = 50_000;
/// Block gas reserved for each mandatory sanction execution.
pub const GAS_SANCTION: u64 = 5_000;
/// Gas for queuing a validator's whole remaining collateral.
pub const GAS_VOLUNTARY_EXIT: u64 = 40_000;
/// Gas for claiming matured, unheld collateral.
pub const GAS_WITHDRAW: u64 = 50_000;
/// Gas for registering a BLS identity with its initial stake. Execution
/// verifies the identity's proof of possession, a pairing the registration
/// pays for; a refused registration still consumed its gas.
pub const GAS_REGISTER_VALIDATOR: u64 = 225_000;
/// Gas for replacing a validator's BLS identity. Execution verifies the new
/// identity's proof of possession, the same pairing a registration pays for.
pub const GAS_ROTATE_KEY: u64 = 225_000;

/// `floor(value * numerator / denominator)` for `numerator <= denominator`,
/// exact over the 256-bit product, so wei amounts may be shared by wei
/// stakes; zero for a zero denominator.
const fn mul_div_floor(value: u128, numerator: u128, denominator: u128) -> u128 {
    match neutrin0_primitives::mul_div_floor(value, numerator, denominator) {
        Some(quotient) => quotient,
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

/// Outcome of one system action or mandatory execution.
///
/// `u32` codes mapped one-way through [`Self::as_u32`], dense in declaration
/// order. Codes are part of the consensus-bound receipts-root commitment.
/// `Success` is always `0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptStatus {
    /// The action's state mutations were committed.
    Success,
    /// The caller lacked the balance or stake the action moves. Also covers
    /// a stake, unstake or registration of zero, which has nothing
    /// to move, an exit from a validator with zero stake and a withdrawal
    /// held behind a pending sanction.
    InsufficientBalance,
    /// Arithmetic overflow while computing a new balance, stake or maturity,
    /// or stake that would lift the stakes, plus the weight consensus seats
    /// keep beyond their stake, above `MAX_TOTAL_STAKE`.
    Overflow,
    /// The engine authenticated no caller or a different one, the caller is
    /// not an eligible validator for a validator-only action, a stake names
    /// an address that is neither a genesis nor a registered validator, or a
    /// registration's identity, proof of possession or seat capacity is
    /// refused.
    Unauthorized,
    /// The slot is occupied by a better-supported live proposal, or a
    /// program switch is proposed while an enacted one awaits its boundary.
    UpgradeConflict,
    /// The proposal is malformed, too close to its activation chunk, or
    /// the vote names no live proposal.
    InvalidUpgrade,
    /// The validator already voted for this proposal.
    AlreadyVoted,
}

impl ReceiptStatus {
    /// Wire encoding. `Success` is always `0`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Success => 0,
            Self::InsufficientBalance => 1,
            Self::Overflow => 2,
            Self::Unauthorized => 3,
            Self::UpgradeConflict => 4,
            Self::InvalidUpgrade => 5,
            Self::AlreadyVoted => 6,
        }
    }
}

/// Receipt of a framework evidence admission or a mandatory sanction
/// execution, emitted by [`system::begin_block`].
///
/// The runtime commits every receipt of a block through its execution
/// artifacts so the SP1 proof and the consensus header agree on what each
/// mandatory step produced.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// [`ReceiptStatus`] encoded as a wire-stable `u32`. `0` means
    /// success; non-zero values identify a specific failure reason.
    pub status_code: u32,
    /// Block gas the step consumed.
    pub gas_used: u64,
    /// [`accountability::EVIDENCE_RECEIPT_KIND`] for an admission or
    /// [`accountability::SANCTION_RECEIPT_KIND`] for a mandatory execution.
    pub kind: u8,
}
