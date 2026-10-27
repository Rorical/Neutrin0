//! Compact bit vector for validator aggregation bitmaps.

use alloc::vec::Vec;
use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::BoundsError;

/// Compact bit vector used for validator aggregation bitmaps.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct BitVec {
    bit_len: u32,
    bytes: Vec<u8>,
}

impl BitVec {
    /// Creates a bit vector from raw bytes and validates zero padding bits.
    pub fn from_bytes(bit_len: u32, bytes: Vec<u8>) -> Result<Self, BoundsError> {
        let expected = bytes_for_bits(bit_len);
        if bytes.len() != expected {
            return Err(BoundsError {
                actual: bytes.len(),
                max: expected,
            });
        }

        let bit_vec = Self { bit_len, bytes };
        if bit_vec.has_non_zero_padding() {
            return Err(BoundsError {
                actual: bit_vec.bytes.len(),
                max: expected,
            });
        }

        Ok(bit_vec)
    }

    /// Returns the number of meaningful bits.
    pub const fn bit_len(&self) -> u32 {
        self.bit_len
    }

    /// Returns the number of encoded bytes.
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if no bits are present.
    pub const fn is_empty(&self) -> bool {
        self.bit_len == 0
    }

    /// Borrows the encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reads a bit by index. Bits are encoded least-significant-bit first.
    pub fn get(&self, index: u32) -> Option<bool> {
        if index >= self.bit_len {
            return None;
        }

        let byte = self.bytes[usize::try_from(index / 8).ok()?];
        let mask = 1_u8 << (index % 8);
        Some(byte & mask != 0)
    }

    /// Appends one bit.
    pub fn push(&mut self, value: bool) {
        let index = self.bit_len;
        let next_len = index.saturating_add(1);
        let next_byte_len = bytes_for_bits(next_len);
        if self.bytes.len() < next_byte_len {
            self.bytes.push(0);
        }
        if value {
            let byte_index =
                usize::try_from(index / 8).expect("u32 fits usize on supported targets");
            self.bytes[byte_index] |= 1_u8 << (index % 8);
        }
        self.bit_len = next_len;
    }

    fn has_non_zero_padding(&self) -> bool {
        let unused_bits = self
            .bytes
            .len()
            .saturating_mul(8)
            .saturating_sub(self.bit_len as usize);
        if unused_bits == 0 || self.bytes.is_empty() {
            return false;
        }

        let used_bits_in_last = self.bit_len % 8;
        let mask = if used_bits_in_last == 0 {
            0
        } else {
            !((1_u8 << used_bits_in_last) - 1)
        };

        self.bytes.last().is_some_and(|last| last & mask != 0)
    }
}

impl fmt::Debug for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitVec")
            .field("bit_len", &self.bit_len)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

impl BorshSerialize for BitVec {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.bit_len.serialize(writer)?;
        self.bytes.serialize(writer)
    }
}

impl BorshDeserialize for BitVec {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let bit_len = u32::deserialize_reader(reader)?;
        let bytes = Vec::<u8>::deserialize_reader(reader)?;
        Self::from_bytes(bit_len, bytes).map_err(|_| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid bit-vector encoding",
            )
        })
    }
}

fn bytes_for_bits(bit_len: u32) -> usize {
    (bit_len as usize).div_ceil(8)
}
