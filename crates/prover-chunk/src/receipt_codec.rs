//! SP1 receipt serde encoding with fixed-width little-endian integers.
//!
//! Decoding is bounded and consumes the entire envelope. This matches the
//! SDK's receipt encoding, independently of its internal bincode dependency.

use alloc::vec::Vec;
use bincode::error::{DecodeError, EncodeError};
use serde::{Serialize, de::DeserializeOwned};

/// Encode an SP1 receipt or verifying key in its native serde wire format.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    bincode::serde::encode_to_vec(
        value,
        bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding(),
    )
}

/// Decode a bounded envelope, rejecting extra bytes and excessive lengths.
pub fn decode<T: DeserializeOwned, const LIMIT: usize>(bytes: &[u8]) -> Result<T, DecodeError> {
    if bytes.len() > LIMIT {
        return Err(DecodeError::LimitExceeded);
    }
    let (value, consumed) = bincode::serde::decode_from_slice(
        bytes,
        bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding()
            .with_limit::<LIMIT>(),
    )?;
    if consumed != bytes.len() {
        return Err(DecodeError::Other("trailing receipt bytes"));
    }
    Ok(value)
}

/// [`decode`], also rejecting any encoding but the one `value` re-encodes to.
///
/// Release builds decode a field element from any `u32` modulo `P` and maps
/// from unsorted or repeated keys, so one receipt would otherwise have many
/// byte identities, each missing every exact-byte cache and verified again.
pub fn decode_canonical<T: Serialize + DeserializeOwned, const LIMIT: usize>(
    bytes: &[u8],
) -> Result<T, DecodeError> {
    let value = decode::<T, LIMIT>(bytes)?;
    if encode(&value).ok().as_deref() != Some(bytes) {
        return Err(DecodeError::Other("noncanonical receipt encoding"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_fixed_width_little_endian_lengths() {
        let bytes = encode(&alloc::vec![0x1234_u16]).unwrap();
        assert_eq!(bytes, [1, 0, 0, 0, 0, 0, 0, 0, 0x34, 0x12]);
        assert_eq!(decode::<Vec<u16>, 64>(&bytes).unwrap(), [0x1234]);
    }

    #[test]
    fn only_the_canonical_encoding_decodes_canonically() {
        use alloc::collections::BTreeMap;
        let canonical = encode(&BTreeMap::from([(1_u8, 2_u8)])).unwrap();
        // Two entries for one key decode to the same map as the canonical bytes.
        let mut repeated = 2_u64.to_le_bytes().to_vec();
        repeated.extend_from_slice(&[1, 9, 1, 2]);
        assert_eq!(
            decode::<BTreeMap<u8, u8>, 64>(&repeated).unwrap(),
            decode::<BTreeMap<u8, u8>, 64>(&canonical).unwrap()
        );
        assert!(decode_canonical::<BTreeMap<u8, u8>, 64>(&repeated).is_err());
        assert_eq!(
            decode_canonical::<BTreeMap<u8, u8>, 64>(&canonical).unwrap(),
            BTreeMap::from([(1, 2)])
        );
    }

    #[test]
    fn rejects_trailing_bytes_and_oversized_declared_lengths() {
        let mut bytes = encode(&alloc::vec![7_u8]).unwrap();
        bytes.push(0);
        assert!(decode::<Vec<u8>, 64>(&bytes).is_err());
        assert!(decode::<Vec<u8>, 64>(&u64::MAX.to_le_bytes()).is_err());
        assert!(decode::<Vec<u8>, 8>(&[0; 9]).is_err());
    }
}
