#![no_std]
#![deny(unsafe_code)]
//! Osaka EVM execution over the Neutrin0 authenticated state backend.
extern crate alloc;
pub mod addresses;
pub mod admission;
pub mod currency;
pub mod environment;
pub mod execution;
pub mod fees;
pub mod genesis;
pub mod query;
pub mod randomness;
#[cfg(all(feature = "sp1-crypto", target_os = "zkvm", target_vendor = "succinct"))]
mod sp1_crypto;
pub mod state;
pub mod system;
mod system_views;
pub mod transaction;
pub use admission::validate_tx;
pub use execution::{
    apply_block, apply_prepared_block, execute_block, execute_prepared_block, prepare_block,
};
pub use genesis::init_genesis;
pub use query::query;
/// Explicit EVM fork. Governance changes the runtime artifact to change its rules.
pub const EVM_SPEC: revm::primitives::hardfork::SpecId = revm::primitives::hardfork::SpecId::OSAKA;

#[cfg(test)]
mod tests;
