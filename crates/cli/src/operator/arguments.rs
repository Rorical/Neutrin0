//! The RPC command option parser and the decoders its values pass through.

use neutrin0_rpc::{BlockIdJson, HashHex};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};

use super::Error;

pub(super) struct Arguments {
    values: BTreeMap<String, String>,
}

impl Arguments {
    pub(super) fn parse(args: &[String], allowed: &[&str]) -> Result<Self, Error> {
        let mut values = BTreeMap::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let flag = arg
                .strip_prefix("--")
                .ok_or_else(|| Error::Usage(format!("unexpected argument `{arg}`")))?;
            if !["rpc", "timeout-secs", "json"].contains(&flag) && !allowed.contains(&flag) {
                return Err(Error::Usage(format!("unknown option --{flag}")));
            }
            let value = if matches!(flag, "json" | "submit") {
                String::new()
            } else {
                iter.next()
                    .filter(|value| !value.starts_with("--"))
                    .ok_or_else(|| Error::Usage(format!("--{flag} requires a value")))?
                    .clone()
            };
            if values.insert(flag.into(), value).is_some() {
                return Err(Error::Usage(format!("duplicate option --{flag}")));
            }
        }
        Ok(Self { values })
    }
    pub(super) fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    pub(super) fn required(&self, key: &str) -> Result<&str, Error> {
        self.get(key)
            .ok_or_else(|| Error::Usage(format!("missing --{key}")))
    }
    pub(super) fn flag(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }
    pub(super) fn number(&self, key: &str, default: u64) -> Result<u64, Error> {
        self.get(key).map_or(Ok(default), |value| {
            value
                .parse()
                .map_err(|_| Error::Usage(format!("--{key} must be an unsigned integer")))
        })
    }
    pub(super) fn duration(&self, key: &str, default: u64) -> Result<Duration, Error> {
        let seconds = self.number(key, default)?;
        if seconds == 0 {
            return Err(Error::Usage(format!("--{key} must be positive")));
        }
        Ok(Duration::from_secs(seconds))
    }
    pub(super) fn at(&self) -> Result<BlockIdJson, Error> {
        serde_json::from_value(json!(self.get("at").unwrap_or("finalized")))
            .map_err(|error| Error::Usage(format!("invalid --at: {error}")))
    }
    pub(super) fn hash(&self, key: &str) -> Result<HashHex, Error> {
        decode_hash(self.required(key)?)
    }
    pub(super) fn output(&self, value: &Value, streaming: bool) -> Result<(), Error> {
        if self.flag("json") {
            if streaming {
                println!("{value}");
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(value)
                        .map_err(|error| Error::Local(error.to_string()))?
                );
            }
        } else {
            print_value("", value);
        }
        Ok(())
    }
}

fn print_value(prefix: &str, value: &Value) {
    match value {
        Value::Object(object) if !object.is_empty() => {
            for (key, value) in object {
                let name = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                print_value(&name, value);
            }
        }
        Value::Array(array) if !array.is_empty() => {
            for (index, value) in array.iter().enumerate() {
                print_value(&format!("{prefix}[{index}]"), value);
            }
        }
        Value::String(value) => println!("{prefix}: {value}"),
        _ => println!("{prefix}: {value}"),
    }
}

fn decode_hash(value: &str) -> Result<HashHex, Error> {
    serde_json::from_value(json!(value))
        .map_err(|_| Error::Usage("expected a 32-byte hexadecimal hash".into()))
}

pub(super) fn decode_bytes(value: &str) -> Result<Vec<u8>, Error> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| Error::Usage("expected hexadecimal bytes".into()))
}

pub(super) fn credentials(value: &str) -> Result<[u8; 32], Error> {
    let bytes = decode_bytes(value)?;
    let mut result = [0; 32];
    match bytes.len() {
        20 => result[12..].copy_from_slice(&bytes),
        32 if bytes[..12] == [0; 12] => result.copy_from_slice(&bytes),
        _ => {
            return Err(Error::Usage(
                "address must be a 20-byte Ethereum address or zero-padded 32-byte credentials"
                    .into(),
            ));
        }
    }
    Ok(result)
}
