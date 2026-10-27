//! Hex, wei and block-selector wrappers with their serde encodings.

use serde::{Deserialize, Serialize};

use crate::backend::BlockId;

/// Wrapper that serializes a wei amount as a decimal string, which JSON
/// clients read without the precision loss of a number above `2^53`.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Wei(pub u128);

impl Serialize for Wei {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Wei {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(serde::de::Error::custom(
                "wei amount must be decimal digits",
            ));
        }
        raw.parse().map(Self).map_err(serde::de::Error::custom)
    }
}

impl core::fmt::Display for Wei {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<u128> for Wei {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

/// Wrapper that serializes a fixed-size byte array as `"0x.."` hex.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HashHex(pub [u8; 32]);

impl Serialize for HashHex {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; 2 + 64];
        buf[0] = b'0';
        buf[1] = b'x';
        hex::encode_to_slice(self.0, &mut buf[2..]).map_err(serde::ser::Error::custom)?;
        ser.serialize_str(core::str::from_utf8(&buf).map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for HashHex {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        let stripped = raw.strip_prefix("0x").unwrap_or(&raw);
        let mut out = [0u8; 32];
        hex::decode_to_slice(stripped, &mut out).map_err(serde::de::Error::custom)?;
        Ok(Self(out))
    }
}

impl From<[u8; 32]> for HashHex {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<HashHex> for [u8; 32] {
    fn from(value: HashHex) -> Self {
        value.0
    }
}

/// Wrapper that serializes opaque bytes as `"0x.."` hex.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BytesHex(pub Vec<u8>);

impl Serialize for BytesHex {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut buf = vec![0u8; 2 + self.0.len() * 2];
        buf[0] = b'0';
        buf[1] = b'x';
        hex::encode_to_slice(&self.0, &mut buf[2..]).map_err(serde::ser::Error::custom)?;
        ser.serialize_str(core::str::from_utf8(&buf).map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for BytesHex {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        let stripped = raw.strip_prefix("0x").unwrap_or(&raw);
        let bytes = hex::decode(stripped).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

impl From<Vec<u8>> for BytesHex {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<BytesHex> for Vec<u8> {
    fn from(value: BytesHex) -> Self {
        value.0
    }
}

/// JSON representation of [`BlockId`]. Accepts the strings
/// `"latest"` / `"safe"` / `"finalized"`, a hex hash, or a decimal-or-hex
/// height integer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockIdJson(pub BlockId);

impl Serialize for BlockIdJson {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            BlockId::Latest => ser.serialize_str("latest"),
            BlockId::Safe => ser.serialize_str("safe"),
            BlockId::Finalized => ser.serialize_str("finalized"),
            BlockId::Hash(h) => HashHex(*h).serialize(ser),
            BlockId::Height(h) => ser.serialize_u64(*h),
        }
    }
}

impl<'de> Deserialize<'de> for BlockIdJson {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        // Accept string ("latest"/"finalized"/hash), number (height).
        let v = serde_json::Value::deserialize(de)?;
        match v {
            serde_json::Value::Null => Ok(Self(BlockId::Latest)),
            serde_json::Value::String(s) => {
                if s.eq_ignore_ascii_case("latest") {
                    Ok(Self(BlockId::Latest))
                } else if s.eq_ignore_ascii_case("safe") {
                    Ok(Self(BlockId::Safe))
                } else if s.eq_ignore_ascii_case("finalized") {
                    Ok(Self(BlockId::Finalized))
                } else if let Some(stripped) = s.strip_prefix("0x") {
                    // Could be a hex hash (32 bytes => 64 hex chars) or
                    // a hex-encoded height.
                    if stripped.len() == 64 {
                        let mut out = [0u8; 32];
                        hex::decode_to_slice(stripped, &mut out)
                            .map_err(serde::de::Error::custom)?;
                        Ok(Self(BlockId::Hash(out)))
                    } else {
                        let h =
                            u64::from_str_radix(stripped, 16).map_err(serde::de::Error::custom)?;
                        Ok(Self(BlockId::Height(h)))
                    }
                } else {
                    // Decimal height as string.
                    let h: u64 = s.parse().map_err(serde::de::Error::custom)?;
                    Ok(Self(BlockId::Height(h)))
                }
            }
            serde_json::Value::Number(n) => {
                let h = n
                    .as_u64()
                    .ok_or_else(|| serde::de::Error::custom("block height must be a u64"))?;
                Ok(Self(BlockId::Height(h)))
            }
            other => Err(serde::de::Error::custom(format!(
                "unsupported block id encoding: {other}",
            ))),
        }
    }
}
