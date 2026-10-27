//! Reserved runtime-owned Ethereum addresses.
use revm::primitives::{Address, address};
/// Validator lifecycle interface.
pub const STAKING: Address = address!("0000000000000000000000000000000000000800");
/// Stake-weighted governance interface.
pub const GOVERNANCE: Address = address!("0000000000000000000000000000000000000801");
/// Authenticated consensus context interface.
pub const CONSENSUS: Address = address!("0000000000000000000000000000000000000802");
/// Finalized source-chunk randomness interface.
pub const RANDOMNESS: Address = address!("0000000000000000000000000000000000000803");
/// Journal projection of native system records; never user-programmable storage.
pub const SYSTEM_STATE: Address = address!("0000000000000000000000000000000000000804");
/// Token escrow backing active and unclaimed unbonding collateral.
pub const ESCROW: Address = address!("0000000000000000000000000000000000000805");
/// Every protected runtime-owned address.
pub const RESERVED: [Address; 6] = [
    STAKING,
    GOVERNANCE,
    CONSENSUS,
    RANDOMNESS,
    SYSTEM_STATE,
    ESCROW,
];
