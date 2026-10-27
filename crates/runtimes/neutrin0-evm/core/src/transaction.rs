//! Exact Ethereum envelope decoding and signer authentication.

use alloc::string::{String, ToString};
use alloy_consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy_eips::eip2718::{Decodable2718, Typed2718};
use revm::context::TxEnv;
use revm::primitives::{Address, B256, keccak256};

/// Authenticated Ethereum transaction and its REVM environment.
#[derive(Clone, Debug)]
pub struct EthereumTransaction {
    /// Keccak hash of the exact signed envelope.
    pub hash: B256,
    /// Recovered account address.
    pub sender: Address,
    /// Original Ethereum envelope.
    pub envelope: TxEnvelope,
    /// Interpreter input.
    pub environment: TxEnv,
}

/// Decode a supported, chain-protected Ethereum transaction without trailing bytes.
pub fn decode(bytes: &[u8], chain_id: u64) -> Result<EthereumTransaction, String> {
    let mut remaining = bytes;
    let envelope = TxEnvelope::decode_2718(&mut remaining).map_err(|error| error.to_string())?;
    if !remaining.is_empty() {
        return Err("trailing Ethereum transaction bytes".into());
    }
    if envelope.chain_id() != Some(chain_id) {
        return Err("Ethereum transaction chain ID mismatch".into());
    }
    let tx_type = envelope.ty();
    if !matches!(tx_type, 0 | 1 | 2 | 4) {
        return Err("unsupported Ethereum transaction type".into());
    }
    if envelope.signature().normalize_s().is_some() {
        return Err("noncanonical high-s signature".into());
    }
    let sender = envelope
        .recover_signer()
        .map_err(|error| error.to_string())?;
    let environment = TxEnv {
        tx_type,
        caller: sender,
        gas_limit: envelope.gas_limit(),
        gas_price: envelope.max_fee_per_gas(),
        gas_priority_fee: envelope.max_priority_fee_per_gas(),
        kind: envelope.kind(),
        value: envelope.value(),
        data: envelope.input().clone(),
        nonce: envelope.nonce(),
        chain_id: Some(chain_id),
        access_list: envelope.access_list().cloned().unwrap_or_default(),
        authorization_list: envelope
            .authorization_list()
            .unwrap_or_default()
            .iter()
            .cloned()
            .map(revm::context_interface::either::Either::Left)
            .collect(),
        ..TxEnv::default()
    };
    Ok(EthereumTransaction {
        hash: keccak256(bytes),
        sender,
        envelope,
        environment,
    })
}
