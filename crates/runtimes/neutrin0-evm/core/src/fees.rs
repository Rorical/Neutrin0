//! EIP-1559 fee progression from authenticated previous execution.

pub use neutrin0_runtime_abi::ethereum::FeeState;

/// Compute the next positive base fee with elasticity two and denominator eight.
pub fn next_base_fee(base_fee: u64, gas_used: u64, gas_limit: u64) -> Result<u64, &'static str> {
    let target = gas_limit / 2;
    if base_fee == 0 || target == 0 || gas_used > gas_limit {
        return Err("invalid fee environment");
    }
    let distance = gas_used.abs_diff(target);
    let change = u128::from(base_fee) * u128::from(distance) / u128::from(target) / 8;
    if gas_used > target {
        base_fee
            .checked_add(u64::try_from(change.max(1)).map_err(|_| "base fee overflow")?)
            .ok_or("base fee overflow")
    } else {
        Ok(base_fee - u64::try_from(change).map_err(|_| "base fee overflow")?)
    }
}

/// Persistent key of the authenticated fee progression.
pub const FEE_STATE_KEY: &[u8] = b"evm:fees";
