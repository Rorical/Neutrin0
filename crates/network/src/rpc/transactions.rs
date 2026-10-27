//! Bounded pending-transaction discovery and retrieval.

use super::{BorshCodec, RpcResult};
use borsh::{BorshDeserialize, BorshSerialize};
use libp2p::request_response;
use neutrin0_primitives::Hash;

/// Hashes advertised in one lexicographically ordered inventory page.
pub const MAX_TRANSACTION_INVENTORY: usize = 128;
/// Bodies requested and returned in one retrieval.
pub const MAX_TRANSACTIONS_PER_REQUEST: usize = 16;
/// Maximum pending transaction body size.
pub const MAX_TRANSACTION_BYTES: usize = 256 * 1024;

/// Gossip transaction interpreted under one exact execution runtime.
///
/// A receiver with another installed program ignores this announcement; an
/// upgrade race cannot turn an honest transaction into a signature penalty.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransactionAnnouncement {
    /// Runtime content hash used for the publisher's successful admission.
    pub runtime: Hash,
    /// Ordinary runtime transaction bytes, independent of the gossip envelope.
    pub transaction: neutrin0_primitives::BoundedBytes<MAX_TRANSACTION_BYTES>,
}

/// Request a pending-pool inventory page after an exclusive hash cursor.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionInventoryRequest {
    /// Exclusive BLAKE3 transaction hash; `None` starts a fresh scan.
    pub after: Option<Hash>,
}

/// Pending transaction hashes, sorted and unique, without execution authority.
#[derive(BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct TransactionInventoryResponse {
    /// At most [`MAX_TRANSACTION_INVENTORY`] hashes.
    pub hashes: Vec<Hash>,
}

/// Fetch exact pending bodies by their BLAKE3 hashes.
#[derive(BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct TransactionsByHashRequest {
    /// At most [`MAX_TRANSACTIONS_PER_REQUEST`] hashes.
    pub hashes: Vec<Hash>,
}

/// Available requested bodies; entries that left the pool may be omitted.
#[derive(BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct TransactionsByHashResponse {
    /// At most [`MAX_TRANSACTIONS_PER_REQUEST`] bounded bodies.
    pub transactions: Vec<Vec<u8>>,
}

fn read_bounded<T: BorshDeserialize, R: borsh::io::Read>(
    reader: &mut R,
    maximum: usize,
) -> borsh::io::Result<Vec<T>> {
    let count = usize::try_from(u32::deserialize_reader(reader)?).map_err(|_| {
        borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, "transaction count")
    })?;
    if count > maximum {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "transaction limit",
        ));
    }
    (0..count).map(|_| T::deserialize_reader(reader)).collect()
}

impl BorshDeserialize for TransactionInventoryResponse {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            hashes: read_bounded(reader, MAX_TRANSACTION_INVENTORY)?,
        })
    }
}

impl BorshDeserialize for TransactionsByHashRequest {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            hashes: read_bounded(reader, MAX_TRANSACTIONS_PER_REQUEST)?,
        })
    }
}

impl BorshDeserialize for TransactionsByHashResponse {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let count = u32::deserialize_reader(reader)?;
        if count > 16 {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "transaction limit",
            ));
        }
        let transactions = (0..count)
            .map(|_| read_bounded(reader, MAX_TRANSACTION_BYTES))
            .collect::<borsh::io::Result<_>>()?;
        Ok(Self { transactions })
    }
}

/// Inventory protocol codec.
pub type TransactionInventoryCodec =
    BorshCodec<TransactionInventoryRequest, RpcResult<TransactionInventoryResponse>>;
/// Inventory request/response behaviour.
pub type TransactionInventoryBehaviour = request_response::Behaviour<TransactionInventoryCodec>;
/// Exact body protocol codec.
pub type TransactionsByHashCodec =
    BorshCodec<TransactionsByHashRequest, RpcResult<TransactionsByHashResponse>>;
/// Exact body request/response behaviour.
pub type TransactionsByHashBehaviour = request_response::Behaviour<TransactionsByHashCodec>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_counts_before_reading_or_allocating_elements() {
        assert!(borsh::from_slice::<TransactionInventoryResponse>(&129u32.to_le_bytes()).is_err());
        assert!(borsh::from_slice::<TransactionsByHashRequest>(&17u32.to_le_bytes()).is_err());
        assert!(borsh::from_slice::<TransactionsByHashResponse>(&17u32.to_le_bytes()).is_err());
        let mut wire = 1u32.to_le_bytes().to_vec();
        wire.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(borsh::from_slice::<TransactionsByHashResponse>(&wire).is_err());
    }

    #[test]
    fn bounded_transaction_payloads_round_trip() {
        let payload = TransactionsByHashResponse {
            transactions: vec![vec![7; MAX_TRANSACTION_BYTES]; MAX_TRANSACTIONS_PER_REQUEST],
        };
        let wire = borsh::to_vec(&payload).unwrap();
        assert!(
            u64::try_from(wire.len()).unwrap()
                < crate::rpc::RpcProtocol::TransactionsByHash.size_limits().1
        );
        assert_eq!(
            borsh::from_slice::<TransactionsByHashResponse>(&wire).unwrap(),
            payload
        );
    }
}
