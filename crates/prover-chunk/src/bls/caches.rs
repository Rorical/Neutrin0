//! Validation-local caches of checked points and prepared messages.
//!
//! Only subgroup-checked nonidentity points enter a cache; eviction changes
//! work, never validity.

use alloc::{
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    vec::Vec,
};
use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective,
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
};
use neutrin0_primitives::{BlsPublicKey, BlsSignature};
use sha2_10::Sha256;

use super::public_key;

pub(super) const MAX_CHECKED_KEYS: usize = 256;
pub(super) const MAX_CHECKED_SIGNATURES: usize = 64;
pub(super) const MAX_AGGREGATE_KEYS: usize = 16;
pub(super) const MAX_AGGREGATE_KEY_BYTES: usize = 64 * 1024;
pub(super) const MAX_PREPARED_MESSAGES: usize = 16;
pub(super) const MAX_PREPARED_MESSAGE_BYTES: usize = 64 * 1024;

/// Per-validation FIFO cache of at most 256 checked public keys. Only
/// subgroup-checked nonidentity points enter it; wire inputs carry no trust flag.
#[derive(Default)]
pub struct CheckedKeys {
    pub(super) points: BTreeMap<BlsPublicKey, G1Affine>,
    pub(super) order: VecDeque<BlsPublicKey>,
    pub(super) aggregates: CheckedAggregates,
}

#[derive(Default)]
pub(super) struct CheckedAggregates {
    pub(super) entries: BTreeMap<neutrin0_primitives::Hash, (Vec<BlsPublicKey>, G1Affine)>,
    order: VecDeque<neutrin0_primitives::Hash>,
    pub(super) bytes: usize,
}

impl CheckedAggregates {
    pub(super) fn get(
        &self,
        id: &neutrin0_primitives::Hash,
        keys: &[BlsPublicKey],
    ) -> Option<G1Affine> {
        self.entries
            .get(id)
            .and_then(|(checked, point)| (checked.as_slice() == keys).then_some(*point))
    }

    fn insert(&mut self, id: neutrin0_primitives::Hash, keys: &[BlsPublicKey], point: G1Affine) {
        let Some(bytes) = keys.len().checked_mul(core::mem::size_of::<BlsPublicKey>()) else {
            return;
        };
        if bytes > MAX_AGGREGATE_KEY_BYTES {
            return;
        }
        // Exact bytes are retained as a second binding, even on a hash collision.
        self.remove(&id);
        while self.entries.len() >= MAX_AGGREGATE_KEYS
            || self.bytes + bytes > MAX_AGGREGATE_KEY_BYTES
        {
            let oldest = self.order.pop_front().expect("aggregate cache order");
            if let Some((keys, _)) = self.entries.remove(&oldest) {
                self.bytes -= keys.len() * core::mem::size_of::<BlsPublicKey>();
            }
        }
        self.entries.insert(id, (keys.to_vec(), point));
        self.order.push_back(id);
        self.bytes += bytes;
    }

    fn remove(&mut self, id: &neutrin0_primitives::Hash) {
        if let Some((keys, _)) = self.entries.remove(id) {
            self.bytes -= keys.len() * core::mem::size_of::<BlsPublicKey>();
            self.order.retain(|entry| entry != id);
        }
    }
}

impl CheckedKeys {
    pub(super) fn get(&mut self, key: &BlsPublicKey) -> Option<G1Affine> {
        if let Some(point) = self.points.get(key) {
            return Some(*point);
        }
        let point = public_key(key)?;
        if self.points.len() == MAX_CHECKED_KEYS {
            let oldest = self.order.pop_front().expect("checked-key cache order");
            self.points.remove(&oldest);
        }
        self.points.insert(*key, point);
        self.order.push_back(*key);
        Some(point)
    }

    pub(super) fn aggregate(&mut self, keys: &[BlsPublicKey]) -> Option<G1Affine> {
        if keys.is_empty() {
            return None;
        }
        let id =
            neutrin0_consensus_types::tagged_commitment(b"neutrin0-checked-bls-aggregate", keys);
        if let Some(point) = self.aggregates.get(&id, keys) {
            return Some(point);
        }
        let mut sum = G1Projective::identity();
        for key in keys {
            sum += self.get(key)?;
        }
        let point = G1Affine::from(sum);
        if bool::from(point.is_identity()) {
            return None;
        }
        self.aggregates.insert(id, keys, point);
        Some(point)
    }
}

#[derive(Default)]
pub(super) struct CheckedSignatures {
    pub(super) points: BTreeMap<BlsSignature, G2Affine>,
    pub(super) order: VecDeque<BlsSignature>,
}

impl CheckedSignatures {
    pub(super) fn get(&mut self, bytes: &BlsSignature) -> Option<G2Affine> {
        if let Some(point) = self.points.get(bytes) {
            return Some(*point);
        }
        let point = Option::<G2Affine>::from(G2Affine::from_compressed(bytes))?;
        if bool::from(point.is_identity()) {
            return None;
        }
        if self.points.len() == MAX_CHECKED_SIGNATURES {
            let oldest = self
                .order
                .pop_front()
                .expect("checked-signature cache order");
            self.points.remove(&oldest);
        }
        self.points.insert(*bytes, point);
        self.order.push_back(*bytes);
        Some(point)
    }
}

pub(super) struct PreparedMessage {
    dst: &'static [u8],
    message: Vec<u8>,
    point: Rc<G2Prepared>,
}

/// Sixteen fixed-size prepared points plus at most 64 KiB of message/DST keys.
/// Live batch terms can retain an evicted point until their Miller loop finishes.
#[derive(Default)]
pub(super) struct PreparedMessages {
    pub(super) entries: BTreeMap<neutrin0_primitives::Hash, PreparedMessage>,
    order: VecDeque<neutrin0_primitives::Hash>,
    pub(super) bytes: usize,
}

impl PreparedMessages {
    pub(super) fn get(&mut self, message: &[u8], dst: &'static [u8]) -> Rc<G2Prepared> {
        let id = neutrin0_consensus_types::tagged_commitment(
            b"neutrin0-prepared-bls-message",
            &(dst, message),
        );
        if let Some(entry) = self.entries.get(&id)
            && entry.dst == dst
            && entry.message == message
        {
            return Rc::clone(&entry.point);
        }
        let point =
            <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([message], dst);
        let point = Rc::new(G2Prepared::from(G2Affine::from(point)));
        let Some(bytes) = message.len().checked_add(dst.len()) else {
            return point;
        };
        if bytes > MAX_PREPARED_MESSAGE_BYTES {
            return point;
        }
        self.remove(&id);
        while self.entries.len() >= MAX_PREPARED_MESSAGES
            || self.bytes + bytes > MAX_PREPARED_MESSAGE_BYTES
        {
            let oldest = self
                .order
                .pop_front()
                .expect("prepared-message cache order");
            if let Some(entry) = self.entries.remove(&oldest) {
                self.bytes -= entry.message.len() + entry.dst.len();
            }
        }
        self.entries.insert(
            id,
            PreparedMessage {
                dst,
                message: message.to_vec(),
                point: Rc::clone(&point),
            },
        );
        self.order.push_back(id);
        self.bytes += bytes;
        point
    }

    fn remove(&mut self, id: &neutrin0_primitives::Hash) {
        if let Some(entry) = self.entries.remove(id) {
            self.bytes -= entry.message.len() + entry.dst.len();
            self.order.retain(|entry| entry != id);
        }
    }
}
