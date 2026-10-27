//! Heap bytes with a type-level maximum length.

use alloc::vec::Vec;
use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

/// Error returned when bounded bytes exceed their configured maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundsError {
    /// Observed byte length.
    pub actual: usize,
    /// Maximum permitted byte length.
    pub max: usize,
}

impl fmt::Display for BoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bounded byte length {} exceeds maximum {}",
            self.actual, self.max
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BoundsError {}

/// Heap bytes with a type-level maximum length.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedBytes<const MAX_LEN: usize> {
    inner: Vec<u8>,
}

impl<const MAX_LEN: usize> BoundedBytes<MAX_LEN> {
    /// Creates bounded bytes after checking the maximum length.
    pub fn new(bytes: Vec<u8>) -> Result<Self, BoundsError> {
        if bytes.len() > MAX_LEN {
            return Err(BoundsError {
                actual: bytes.len(),
                max: MAX_LEN,
            });
        }

        Ok(Self { inner: bytes })
    }

    /// Returns the current byte length.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Borrows the contained bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Consumes the wrapper and returns the contained bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }
}

impl<const MAX_LEN: usize> AsRef<[u8]> for BoundedBytes<MAX_LEN> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const MAX_LEN: usize> TryFrom<Vec<u8>> for BoundedBytes<MAX_LEN> {
    type Error = BoundsError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const MAX_LEN: usize> fmt::Debug for BoundedBytes<MAX_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedBytes")
            .field("len", &self.inner.len())
            .field("max", &MAX_LEN)
            .finish()
    }
}

impl<const MAX_LEN: usize> BorshSerialize for BoundedBytes<MAX_LEN> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.inner.serialize(writer)
    }
}

impl<const MAX_LEN: usize> BorshDeserialize for BoundedBytes<MAX_LEN> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let len = u32::deserialize_reader(reader)? as usize;
        if len > MAX_LEN {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "bounded bytes exceed maximum length",
            ));
        }
        let mut inner = alloc::vec![0; len];
        reader.read_exact(&mut inner)?;
        Ok(Self { inner })
    }
}
