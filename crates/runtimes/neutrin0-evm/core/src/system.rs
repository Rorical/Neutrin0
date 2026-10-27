//! Journaled Solidity system interfaces. Native records are projected into REVM storage
//! for the duration of a transaction, then materialized only after successful execution.

mod actions;
mod journal;

use crate::{addresses, state::StateDb};
use actions::dispatch;
use alloc::{string::String, vec::Vec};
use journal::JournalBackend;
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::StateBackend;
use revm::context::{BlockEnv, CfgEnv, TxEnv};
use revm::handler::{EthPrecompiles, PrecompileProvider};
use revm::interpreter::{CallInputs, CallScheme, Gas, InstructionResult, InterpreterResult};
use revm::precompile::{PrecompileHalt, PrecompileOutput, PrecompileStatus};
use revm::primitives::{AddressSet, U256, keccak256};
use revm::{Context, Journal};

/// Concrete execution context carrying the authenticated block input.
pub type RuntimeContext<'a, B> = Context<
    BlockEnv,
    TxEnv,
    CfgEnv,
    StateDb<'a, B>,
    Journal<StateDb<'a, B>>,
    &'a RuntimeBlockInput,
>;

/// Ethereum precompiles plus protected, runtime-owned system entrypoints.
pub struct SystemPrecompiles {
    ethereum: EthPrecompiles,
    warm: AddressSet,
    policy: neutrin0_runtime_system::RuntimePolicy,
    proposer_vrf_available: bool,
}

impl SystemPrecompiles {
    /// Install Osaka primitives and the block-start system policy.
    pub fn new(policy: neutrin0_runtime_system::RuntimePolicy) -> Self {
        #[cfg(all(feature = "sp1-crypto", target_os = "zkvm", target_vendor = "succinct"))]
        crate::sp1_crypto::install();
        let ethereum = EthPrecompiles::new(crate::EVM_SPEC);
        let mut warm = ethereum.warm_addresses().clone();
        warm.extend([
            addresses::STAKING,
            addresses::GOVERNANCE,
            addresses::CONSENSUS,
            addresses::RANDOMNESS,
        ]);
        Self {
            ethereum,
            warm,
            policy,
            proposer_vrf_available: true,
        }
    }
    /// Configure read-only simulation when the next proposer has not signed a header.
    #[must_use]
    pub const fn with_proposer_vrf(mut self, available: bool) -> Self {
        self.proposer_vrf_available = available;
        self
    }
}

impl<B: StateBackend> PrecompileProvider<RuntimeContext<'_, B>> for SystemPrecompiles {
    type Output = InterpreterResult;
    fn set_spec(&mut self, spec: revm::primitives::hardfork::SpecId) -> bool {
        assert_eq!(spec, crate::EVM_SPEC, "explicit Osaka runtime");
        <EthPrecompiles as PrecompileProvider<RuntimeContext<'_, B>>>::set_spec(
            &mut self.ethereum,
            spec,
        )
    }
    fn warm_addresses(&self) -> &AddressSet {
        &self.warm
    }
    fn run(
        &mut self,
        context: &mut RuntimeContext<'_, B>,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        if ![
            addresses::STAKING,
            addresses::GOVERNANCE,
            addresses::CONSENSUS,
            addresses::RANDOMNESS,
        ]
        .contains(&inputs.bytecode_address)
        {
            return self.ethereum.run(context, inputs);
        }
        let data = inputs.input.as_bytes(context).to_vec();
        let output = if inputs.target_address != inputs.bytecode_address
            || !matches!(inputs.scheme, CallScheme::Call | CallScheme::StaticCall)
            || !inputs.call_value().is_zero()
        {
            PrecompileOutput::revert(
                500,
                abi_error("invalid system call context"),
                inputs.reservoir,
            )
        } else {
            let input = context.chain;
            let mut backend = JournalBackend {
                context,
                caller: inputs.caller,
                gas: 500,
                limit: inputs.gas_limit,
                exhausted: inputs.gas_limit < 500,
            };
            let result = dispatch(
                &mut backend,
                input,
                inputs.bytecode_address,
                &data,
                inputs.is_static,
                &self.policy,
                self.proposer_vrf_available,
            );
            if backend.exhausted {
                PrecompileOutput::halt(PrecompileHalt::OutOfGas, inputs.reservoir)
            } else {
                match result {
                    Ok(bytes) => PrecompileOutput::new(backend.gas, bytes.into(), inputs.reservoir),
                    Err(message) => {
                        PrecompileOutput::revert(backend.gas, abi_error(&message), inputs.reservoir)
                    }
                }
            }
        };
        Ok(Some(interpreter_result(output, inputs.gas_limit)))
    }
}

fn interpreter_result(output: PrecompileOutput, gas_limit: u64) -> InterpreterResult {
    let result = if output.gas_used > gas_limit {
        InstructionResult::PrecompileOOG
    } else {
        match &output.status {
            PrecompileStatus::Success => InstructionResult::Return,
            PrecompileStatus::Revert => InstructionResult::Revert,
            PrecompileStatus::Halt(reason) if reason.is_oog() => InstructionResult::PrecompileOOG,
            PrecompileStatus::Halt(_) => InstructionResult::PrecompileError,
        }
    };
    let mut gas = Gas::new(gas_limit);
    *gas.tracker_mut() = output.to_gas_tracker(gas_limit);
    if result.is_halt() {
        gas.spend_all();
        InterpreterResult::new(result, revm::primitives::Bytes::new(), gas)
    } else {
        InterpreterResult::new(result, output.bytes, gas)
    }
}

pub(super) fn selector(data: &[u8], signature: &[u8]) -> bool {
    data.get(..4) == Some(&keccak256(signature).as_slice()[..4])
}
pub(super) fn word(data: &[u8], index: usize) -> Result<[u8; 32], String> {
    let start = index
        .checked_mul(32)
        .and_then(|offset| offset.checked_add(4))
        .ok_or("ABI offset overflow")?;
    let end = start.checked_add(32).ok_or("ABI offset overflow")?;
    data.get(start..end)
        .ok_or_else(|| String::from("missing ABI word"))?
        .try_into()
        .map_err(|_| "invalid ABI word".into())
}
pub(super) fn integer(data: &[u8], index: usize) -> Result<u128, String> {
    U256::from_be_bytes(word(data, index)?)
        .try_into()
        .map_err(|_| "system amount exceeds u128".into())
}
fn dynamic_bytes(
    data: &[u8],
    index: usize,
    head_words: usize,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    // Offsets and lengths are bounded as 256-bit values before any `usize`
    // conversion: `usize` is 32 bits in WASM and 64 bits in the Block Guest, so
    // a width-dependent failure would make the two executions disagree.
    let offset = U256::from_be_bytes(word(data, index)?);
    if offset < U256::from(head_words * 32)
        || offset % U256::from(32) != U256::ZERO
        || offset > U256::from(data.len())
    {
        return Err("invalid dynamic ABI offset".into());
    }
    let length_start = offset.to::<usize>() + 4;
    let length_end = length_start + 32;
    let length_word: [u8; 32] = data
        .get(length_start..length_end)
        .ok_or("missing ABI length")?
        .try_into()
        .map_err(|_| "ABI length")?;
    let length = U256::from_be_bytes(length_word);
    if length > U256::from(maximum) {
        return Err("system argument length limit".into());
    }
    data.get(length_end..length_end + length.to::<usize>())
        .ok_or_else(|| "truncated ABI bytes".into())
        .map(<[u8]>::to_vec)
}
pub(super) fn abi_word(value: u64) -> Vec<u8> {
    U256::from(value).to_be_bytes::<32>().to_vec()
}
fn abi_error(message: &str) -> revm::primitives::Bytes {
    let mut bytes = keccak256(b"Error(string)").as_slice()[..4].to_vec();
    bytes.extend_from_slice(&U256::from(32).to_be_bytes::<32>());
    bytes.extend_from_slice(&U256::from(message.len()).to_be_bytes::<32>());
    bytes.extend_from_slice(message.as_bytes());
    bytes.resize(4 + 64 + message.len().div_ceil(32) * 32, 0);
    bytes.into()
}
