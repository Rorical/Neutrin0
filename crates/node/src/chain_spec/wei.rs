use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
#[serde(untagged)]
enum Amount {
    Integer(u64),
    Decimal(String),
}

fn resolve(amount: Amount) -> Result<u128, String> {
    match amount {
        Amount::Integer(value) => Ok(u128::from(value)),
        Amount::Decimal(text) => {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("`{text}` is not a decimal wei amount"));
            }
            text.parse()
                .map_err(|_| format!("`{text}` exceeds the largest wei amount"))
        }
    }
}

/// Deserialize one wei amount.
///
/// # Errors
/// Rejects anything but a non-negative integer or a decimal string that
/// fits `u128`.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    resolve(Amount::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// Deserialize an optional wei amount.
///
/// # Errors
/// As [`deserialize`].
pub fn optional<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u128>, D::Error> {
    Option::<Amount>::deserialize(deserializer)?
        .map(resolve)
        .transpose()
        .map_err(D::Error::custom)
}
