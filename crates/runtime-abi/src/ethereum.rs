//! Ethereum compatibility query and artifact wire contracts. All integer words are big endian.
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};

/// Canonical Ethereum account record. Integer byte arrays use big endian.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvmAccount {
    /// Ethereum transaction nonce.
    pub nonce: u64,
    /// Native-token balance in the smallest unit.
    pub balance: [u8; 32],
    /// Keccak hash of the account's bytecode.
    pub code_hash: [u8; 32],
}

impl Default for EvmAccount {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: [0; 32],
            code_hash: [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70,
            ],
        }
    }
}

/// Ethereum event emitted by successful execution.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvmLog {
    /// Contract address.
    pub address: [u8; 20],
    /// Indexed event topics.
    pub topics: Vec<[u8; 32]>,
    /// Event data.
    pub data: Vec<u8>,
}

/// Ethereum receipt data excluding block-local indexing supplied by RPC.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvmReceipt {
    /// Index of the common transaction envelope in the body.
    pub envelope_index: u32,
    /// Exact Ethereum transaction hash.
    pub transaction_hash: [u8; 32],
    /// Recovered sender.
    pub from: [u8; 20],
    /// Destination, absent for creation.
    pub to: Option<[u8; 20]>,
    /// Created contract, only on successful creation.
    pub contract_address: Option<[u8; 20]>,
    /// Ethereum transaction type.
    pub transaction_type: u8,
    /// Whether EVM execution succeeded; revert and halt both yield false.
    pub success: bool,
    /// Gas charged after refunds.
    pub gas_used: u64,
    /// Cumulative EVM gas, excluding mandatory system gas.
    pub cumulative_gas_used: u64,
    /// Effective price paid per gas.
    pub effective_gas_price: u128,
    /// Logs retained after nested rollback.
    pub logs: Vec<EvmLog>,
}

/// Authenticated metadata consumed by the Ethereum facade.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvmBlockMetadata {
    /// Height of this execution.
    pub height: u64,
    /// Base fee paid in this block.
    pub base_fee: u64,
    /// Authenticated fee recipient, also returned by COINBASE.
    pub beneficiary: [u8; 20],
    /// Gas spent on mandatory work.
    pub system_gas: u64,
    /// Gas spent on Ethereum transactions.
    pub evm_gas: u64,
    /// Header and finalized-boundary facts actually consumed.
    pub context: neutrin0_consensus_types::runtime::ConsensusExecutionContext,
}

/// One Ethereum genesis account; all words use big endian.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct GenesisAccount {
    /// Canonical Ethereum address.
    pub address: [u8; 20],
    /// Spendable native-token allocation.
    pub balance: [u8; 32],
    /// Account nonce, zero for ordinary initial EOAs.
    pub nonce: u64,
    /// Optional initial contract bytecode.
    pub code: Vec<u8>,
    /// Initial storage, forbidden for accounts without bytecode.
    pub storage: Vec<([u8; 32], [u8; 32])>,
}

/// Opaque genesis payload interpreted only by the EVM runtime.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvmGenesisConfig {
    /// Positive initial EIP-1559 base fee.
    pub initial_base_fee: u64,
    /// Funded Ethereum accounts and optional contracts.
    pub accounts: Vec<GenesisAccount>,
}

/// Canonical call request, with block facts loaded exclusively from selected state.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct CallRequest {
    /// Simulated caller; signatures are intentionally unnecessary for read-only calls.
    pub from: [u8; 20],
    /// Destination or contract creation.
    pub to: Option<[u8; 20]>,
    /// Simulated value transfer, big endian.
    pub value: [u8; 32],
    /// Input or init code.
    pub data: Vec<u8>,
    /// Gas allowance bounded by the selected block gas limit.
    pub gas_limit: u64,
    /// Optional maximum gas price; absence simulates a fee-free call.
    pub fee_cap: Option<u128>,
    /// Optional priority fee.
    pub tip_cap: Option<u128>,
    /// Ethereum access list.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    /// Explicit envelope type; absent infers legacy/access-list/dynamic/delegation.
    pub transaction_type: Option<u8>,
    /// Signed EIP-7702 authorizations applied only to the disposable journal.
    pub authorization_list: Vec<EvmAuthorization>,
}
/// Simulation output; reverted bytes are returned explicitly for RPC errors.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct CallResult {
    /// Execution succeeded.
    pub success: bool,
    /// Revert or halt consumed execution without success.
    pub reverted: bool,
    /// Gas charged after refunds.
    pub gas_used: u64,
    /// RETURN or REVERT data.
    pub output: Vec<u8>,
}

/// Authenticated per-block fee state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct FeeState {
    /// Height of the last executed block.
    pub height: u64,
    /// Base fee applicable to the next block.
    pub next_base_fee: u64,
}

/// Complete Ethereum projection of already authenticated opaque execution artifacts.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvmArtifacts {
    /// Block metadata, including total and mandatory gas.
    pub metadata: EvmBlockMetadata,
    /// Included Ethereum receipts in transaction order.
    pub receipts: Vec<EvmReceipt>,
}

/// Standard signed authorization exposed by the Ethereum facade.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvmAuthorization {
    /// Authorized chain identifier; zero permits every chain.
    pub chain_id: [u8; 32],
    /// Delegation target.
    pub address: [u8; 20],
    /// Authority nonce.
    pub nonce: u64,
    /// Recovery parity.
    pub y_parity: u8,
    /// Signature scalar r.
    pub r: [u8; 32],
    /// Signature scalar s.
    pub s: [u8; 32],
}
/// Runtime-decoded Ethereum transaction; common hosts never decode user payloads.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvmTransaction {
    /// Ethereum Keccak transaction identifier.
    pub hash: [u8; 32],
    /// Recovered signer.
    pub from: [u8; 20],
    /// Destination, absent for creation.
    pub to: Option<[u8; 20]>,
    /// Transaction nonce.
    pub nonce: u64,
    /// Ethereum envelope type.
    pub transaction_type: u8,
    /// Protected chain identifier.
    pub chain_id: u64,
    /// Transaction gas allowance.
    pub gas_limit: u64,
    /// Maximum gas-unit bid, or gas price for types zero and one.
    pub fee_cap: u128,
    /// Priority bid, absent for types zero and one.
    pub tip_cap: Option<u128>,
    /// Native-token value transfer.
    pub value: [u8; 32],
    /// Calldata or initcode.
    pub input: Vec<u8>,
    /// Access list.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    /// Signed EIP-7702 authorizations.
    pub authorization_list: Vec<EvmAuthorization>,
    /// Recovery parity.
    pub y_parity: bool,
    /// Signature scalar r.
    pub r: [u8; 32],
    /// Signature scalar s.
    pub s: [u8; 32],
}

/// Internal pending operation. Consensus facts are constructed by the node;
/// Ethereum RPC clients supply only the nested Ethereum query arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum PendingMode {
    /// Execute a hypothetical next block under its available authenticated boundary.
    NextBlock,
    /// Apply user candidates at the authenticated head environment while the
    /// next boundary is unavailable. This never runs a block transition.
    HeadLocal,
}

/// Query-only pending request, never an imported or provable block input.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct PendingRequest {
    /// Whether this is a next-block view or an explicitly head-local overlay.
    pub mode: PendingMode,
    /// Available next-block context, or exact selected head context for a user-only view.
    pub block: crate::RuntimeBlockInput,
    /// Operation against the disposable pending journal.
    pub query: crate::QueryRequest,
}
/// Local pending block projection, with no signed block identifier or state commitment.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct PendingBlock {
    /// Explicit simulation semantics; neither mode supplies a signed identifier.
    pub mode: PendingMode,
    /// Simulated height: the next height or the existing head for `HeadLocal`.
    pub number: u64,
    /// Authenticated native parent identifier.
    pub parent_hash: [u8; 32],
    /// Native shared gas ceiling.
    pub gas_limit: u64,
    /// Speculative executed metadata.
    pub metadata: EvmBlockMetadata,
    /// Executable local Ethereum candidates, in simulated execution order.
    pub transactions: Vec<EvmTransaction>,
}
