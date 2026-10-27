//! Ethereum signature, fee and queued-nonce admission.

use neutrin0_runtime_abi::{
    RuntimeTransaction, TransactionDependency, TxValidationCode, TxValidity,
};
use neutrin0_runtime_core::StateBackend;
use revm::primitives::U256;

/// Admit only canonical, chain-protected Ethereum envelopes through ordinary RPC.
pub fn validate_tx<B: StateBackend>(
    bytes: &[u8],
    state: &mut B,
    chain_id: u64,
    block_gas_limit: u64,
) -> TxValidity {
    let Ok(RuntimeTransaction::User(payload)) = borsh::from_slice(bytes) else {
        return TxValidity::invalid(TxValidationCode::Malformed);
    };
    let Ok(transaction) = crate::transaction::decode(&payload, chain_id) else {
        return TxValidity::invalid(TxValidationCode::BadSignature);
    };
    let Ok(record) = crate::state::load_account(state, transaction.sender) else {
        return TxValidity::invalid(TxValidationCode::StateReadFailed);
    };
    let record = record.unwrap_or_default();
    let code_hash = revm::primitives::B256::from(record.code_hash);
    if code_hash != revm::primitives::KECCAK_EMPTY && !code_hash.is_zero() {
        let Some(code) = state.read(&crate::state::code_key(code_hash)) else {
            return TxValidity::invalid(TxValidationCode::StateReadFailed);
        };
        if revm::primitives::keccak256(&code) != code_hash {
            return TxValidity::invalid(TxValidationCode::StateReadFailed);
        }
        if code.len() != 23 || !code.starts_with(&[0xef, 0x01, 0x00]) {
            return TxValidity::invalid(TxValidationCode::Unauthorized);
        }
    }
    let tx = &transaction.environment;
    if tx.nonce < record.nonce || tx.nonce.saturating_sub(record.nonce) > 64 {
        return TxValidity::invalid(TxValidationCode::NonceMismatch);
    }
    if tx.gas_limit > block_gas_limit || tx.gas_limit > 16_777_216 || tx.gas_limit < 21_000 {
        return TxValidity::invalid(TxValidationCode::Malformed);
    }
    if tx.nonce == u64::MAX
        || (tx.kind.is_create() && tx.data.len() > 49_152)
        || (tx.tx_type == 4 && tx.authorization_list.is_empty())
        || revm::handler::validation::validate_initial_tx_gas(
            tx,
            crate::EVM_SPEC,
            false,
            false,
            16_777_216,
            None,
        )
        .is_err()
    {
        return TxValidity::invalid(TxValidationCode::Malformed);
    }
    if tx.gas_priority_fee.is_some_and(|tip| tip > tx.gas_price) {
        return TxValidity::invalid(TxValidationCode::Malformed);
    }
    let Ok(Some(fees)) =
        crate::state::read_record::<crate::fees::FeeState, _>(state, crate::fees::FEE_STATE_KEY)
    else {
        return TxValidity::invalid(TxValidationCode::StateReadFailed);
    };
    // A fee cap below the current base fee can become executable after future blocks.
    // It remains queued and is never included while underpriced.
    let balance = U256::from_be_bytes(record.balance);
    let upfront = U256::from(tx.gas_price) * U256::from(tx.gas_limit);
    if upfront
        .checked_add(tx.value)
        .is_none_or(|required| required > balance)
    {
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }
    let tip = tx.gas_priority_fee.unwrap_or(tx.gas_price);
    let priority = tx
        .gas_price
        .saturating_sub(u128::from(fees.next_base_fee))
        .min(tip);
    TxValidity {
        code: TxValidationCode::Valid,
        priority: u64::try_from(priority).unwrap_or(u64::MAX),
        dependency: Some(TransactionDependency {
            identifier: transaction.hash.0,
            account: crate::state::consensus_address(transaction.sender),
            nonce: tx.nonce,
            state_nonce: record.nonce,
            fee_cap: tx.gas_price,
            tip_cap: tip,
            gas_limit: tx.gas_limit,
        }),
    }
}
