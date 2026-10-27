//! Row layout of staged state downloads.
//!
//! Every row lives under [`STATE_DOWNLOAD_ENTRY_PREFIX`] except the per-root
//! summaries under `STATE_DOWNLOAD/`. Pending and resolved rows belong to one
//! root; objects, fragments and their progress are shared by every root.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::bootstrap::{MAX_STATE_FRAGMENT_BYTES, StateItemKind};
use neutrin0_primitives::Hash;
use neutrin0_storage::{Batch, Column, ColumnSnapshot, Database};
use neutrin0_sync::SyncBackendError;
use neutrin0_trie::{Hasher, Poseidon2Hasher};

use super::super::storage_error;
use neutrin0_consensus_engine::store::pointers::{
    STATE_DOWNLOAD as DOWNLOAD_KEY, STATE_DOWNLOAD_ENTRY_PREFIX,
};

pub(super) const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Fragments of the largest object; every nonfinal fragment is full size.
pub(super) const MAX_FRAGMENTS: usize = 1024;
pub(in crate::chain_backend) const MAX_ENTRY_BYTES: u64 =
    (MAX_FRAGMENTS * MAX_STATE_FRAGMENT_BYTES) as u64;
pub(super) const MAX_ENTRIES: u64 = 2_000_000;
/// Pending rows examined per engine-lock hold while resolving objects an
/// earlier download already staged.
pub(super) const SCAN_LIMIT: usize = 1024;
/// Rows visited per engine-lock hold when clearing or sweeping.
pub(super) const PAGE: usize = 4096;

/// Row tags under [`STATE_DOWNLOAD_ENTRY_PREFIX`]. Pending and resolved rows
/// belong to one root; objects, fragments and their progress are shared.
pub(super) const PENDING: u8 = b'p';
pub(super) const RESOLVED: u8 = b'r';
pub(super) const OBJECT: u8 = b'o';
pub(super) const FRAGMENT: u8 = b'f';
pub(super) const PROGRESS: u8 = b'g';
pub(super) const TOTALS: u8 = b't';

/// Objects discovered for one root, bounding its download.
#[derive(Clone, Copy, Debug, Default, BorshSerialize, BorshDeserialize)]
pub(super) struct Summary {
    pub(super) entries: u64,
}

/// Bytes staged across every download, bounding disk use.
#[derive(Clone, Copy, Debug, Default, BorshSerialize, BorshDeserialize)]
pub(super) struct Totals {
    pub(super) bytes: u64,
}

pub(super) const fn kind_byte(kind: StateItemKind) -> u8 {
    match kind {
        StateItemKind::Node => 0,
        StateItemKind::Value => 1,
        StateItemKind::Runtime => 2,
        StateItemKind::Guest => 3,
    }
}

pub(super) const fn byte_kind(byte: u8) -> Option<StateItemKind> {
    match byte {
        0 => Some(StateItemKind::Node),
        1 => Some(StateItemKind::Value),
        2 => Some(StateItemKind::Runtime),
        3 => Some(StateItemKind::Guest),
        _ => None,
    }
}

pub(super) fn tagged(tag: u8) -> Vec<u8> {
    let mut key = STATE_DOWNLOAD_ENTRY_PREFIX.to_vec();
    key.push(tag);
    key
}

/// A shared row naming one object: its bytes, progress or fragment prefix.
pub(super) fn object_key(tag: u8, kind: StateItemKind, hash: Hash) -> Vec<u8> {
    let mut key = tagged(tag);
    key.push(kind_byte(kind));
    key.extend_from_slice(&hash);
    key
}

pub(super) fn fragment_key(kind: StateItemKind, hash: Hash, offset: u64) -> Vec<u8> {
    let mut key = object_key(FRAGMENT, kind, hash);
    key.extend_from_slice(&offset.to_be_bytes());
    key
}

pub(super) fn root_prefix(tag: u8, root: Hash) -> Vec<u8> {
    let mut key = tagged(tag);
    key.extend_from_slice(&root);
    key
}

pub(super) fn root_key(tag: u8, root: Hash, kind: StateItemKind, hash: Hash) -> Vec<u8> {
    let mut key = root_prefix(tag, root);
    key.push(kind_byte(kind));
    key.extend_from_slice(&hash);
    key
}

/// The object a row key names after `prefix`.
pub(super) fn object_of(
    prefix: &[u8],
    key: &[u8],
) -> Result<(StateItemKind, Hash), SyncBackendError> {
    key.strip_prefix(prefix)
        .filter(|rest| rest.len() >= 33)
        .and_then(|rest| Some((byte_kind(rest[0])?, rest[1..33].try_into().ok()?)))
        .ok_or_else(|| storage_error("malformed state download row"))
}

pub(super) fn summary_prefix() -> Vec<u8> {
    let mut key = DOWNLOAD_KEY.to_vec();
    key.push(b'/');
    key
}

pub(super) fn download_key(root: Hash) -> Vec<u8> {
    let mut key = summary_prefix();
    key.extend_from_slice(&root);
    key
}

pub(super) fn decode<T: BorshDeserialize + Default>(
    bytes: Option<Vec<u8>>,
) -> Result<T, SyncBackendError> {
    bytes.map_or_else(
        || Ok(T::default()),
        |bytes| borsh::from_slice(&bytes).map_err(storage_error),
    )
}

/// Up to `limit` keys under `prefix` from `from`, without reading values.
pub(super) fn keys<DB: Database>(
    db: &DB,
    prefix: &[u8],
    from: &[u8],
    limit: usize,
) -> Result<Vec<Vec<u8>>, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    Ok(db
        .keys_from(Column::Meta, from, limit)
        .map_err(storage_error)?
        .into_iter()
        .take_while(|key| key.starts_with(prefix))
        .collect())
}

pub(super) fn has<DB: Database>(db: &DB, key: &[u8]) -> Result<bool, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    Ok(db.get(Column::Meta, key).map_err(storage_error)?.is_some())
}

/// Bytes already staged for an object arriving in fragments.
pub(super) fn progress<DB: Database>(
    db: &DB,
    kind: StateItemKind,
    hash: Hash,
) -> Result<u64, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    decode(
        db.get(Column::Meta, &object_key(PROGRESS, kind, hash))
            .map_err(storage_error)?,
    )
}

/// An object's staged fragments in offset order.
pub(super) fn fragments<DB: Database>(
    db: &DB,
    kind: StateItemKind,
    hash: Hash,
) -> Result<ColumnSnapshot, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    let prefix = object_key(FRAGMENT, kind, hash);
    Ok(db
        .entries_from(Column::Meta, &prefix, MAX_FRAGMENTS)
        .map_err(storage_error)?
        .into_iter()
        .take_while(|(key, _)| key.starts_with(&prefix))
        .collect())
}

/// Queue deletion of an object's fragments and progress, returning the bytes
/// they held.
pub(super) fn discard_fragments<DB: Database>(
    db: &DB,
    batch: &mut Batch,
    kind: StateItemKind,
    hash: Hash,
) -> Result<u64, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    let mut bytes = 0;
    for (key, fragment) in fragments(db, kind, hash)? {
        bytes += fragment.len() as u64;
        batch.delete(Column::Meta, key);
    }
    batch.delete(Column::Meta, object_key(PROGRESS, kind, hash));
    Ok(bytes)
}

pub(super) fn totals<DB: Database>(db: &DB) -> Result<Totals, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    decode(
        db.get(Column::Meta, &tagged(TOTALS))
            .map_err(storage_error)?,
    )
}

/// Roots with a download in progress.
pub(super) fn live_roots<DB: Database>(db: &DB) -> Result<Vec<Hash>, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    let prefix = summary_prefix();
    keys(db, &prefix, &prefix, PAGE)?
        .iter()
        .map(|key| {
            key[prefix.len()..]
                .try_into()
                .map_err(|_| storage_error("malformed state download summary"))
        })
        .collect()
}

pub(super) fn complete<DB: Database>(db: &DB, root: Hash) -> Result<bool, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    let prefix = root_prefix(PENDING, root);
    Ok(has(db, &download_key(root))? && keys(db, &prefix, &prefix, 1)?.is_empty())
}

pub(super) fn content_hash(kind: StateItemKind, bytes: &[u8]) -> Option<Hash> {
    match kind {
        StateItemKind::Node => Some(Poseidon2Hasher::hash_node(bytes)),
        StateItemKind::Value => Some(Poseidon2Hasher::hash_value(bytes)),
        StateItemKind::Runtime => Some(neutrin0_primitives::blake3_256(bytes)),
        // SP1 setup happens off async workers and outside the engine lock
        // immediately before the authenticated state installation.
        StateItemKind::Guest => None,
    }
}
