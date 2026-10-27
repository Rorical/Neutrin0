//! Ethereum JSON quantity, data and argument codecs.
use crate::server::errors::invalid_params;
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::Value;

pub(super) fn error(message: &str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32000, message, None::<()>)
}
pub(super) fn q(value: u128) -> Value {
    Value::String(format!("0x{value:x}"))
}
pub(super) fn bytes(value: &[u8]) -> Value {
    Value::String(format!("0x{}", hex::encode(value)))
}
pub(super) fn word_quantity(value: &[u8; 32]) -> Value {
    let encoded = hex::encode(value);
    let trimmed = encoded.trim_start_matches('0');
    Value::String(format!(
        "0x{}",
        if trimmed.is_empty() { "0" } else { trimmed }
    ))
}
pub(super) fn argument(args: &[Value], index: usize) -> Result<&Value, ErrorObjectOwned> {
    args.get(index)
        .ok_or_else(|| invalid_params("missing argument"))
}
pub(super) fn data(value: &Value) -> Result<Vec<u8>, ErrorObjectOwned> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid_params("hex data expected"))?;
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid_params("hex data requires 0x prefix"))?;
    hex::decode(value).map_err(invalid_params)
}
pub(super) fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], ErrorObjectOwned> {
    data(value)?
        .try_into()
        .map_err(|_| invalid_params(format!("expected {N} bytes")))
}
pub(super) fn quantity(value: &Value) -> Result<u128, ErrorObjectOwned> {
    let value = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(|| invalid_params("hex quantity expected"))?;
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(invalid_params("noncanonical quantity"));
    }
    u128::from_str_radix(value, 16).map_err(invalid_params)
}
pub(super) fn height(value: &Value) -> Result<u64, ErrorObjectOwned> {
    u64::try_from(quantity(value)?).map_err(invalid_params)
}
pub(super) fn word(value: &Value) -> Result<[u8; 32], ErrorObjectOwned> {
    let value = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(|| invalid_params("hex word expected"))?;
    if value.len() > 64 || value.is_empty() {
        return Err(invalid_params("word exceeds U256"));
    }
    let padded = format!("{value:0>64}");
    let mut result = [0; 32];
    result.copy_from_slice(&hex::decode(padded).map_err(invalid_params)?);
    Ok(result)
}
