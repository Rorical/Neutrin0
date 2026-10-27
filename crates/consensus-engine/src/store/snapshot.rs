//! Bounded execution-state leases for ongoing authenticated snapshot downloads.

use super::{ChainStore, StatePin, StoreError};
use neutrin0_primitives::{Hash, ZERO_HASH};
use neutrin0_storage::{Batch, Column, Database};

pub(super) const SNAPSHOT_PREFIX: &[u8] = b"state_snapshot_lease/";
// Four concurrent manifests, each retaining execution and identity-sanctions roots.
const MAX_SNAPSHOTS: usize = 8;
const IDLE_SECS: u64 = 300;
const MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;
/// A lease is renewed only once less than this much of its idle window
/// remains, so a download's many requests write it a few times an idle window.
const RENEW_WITHIN_SECS: u64 = IDLE_SECS / 2;

fn lease_key(root: Hash) -> Vec<u8> {
    let mut key = SNAPSHOT_PREFIX.to_vec();
    key.extend_from_slice(&root);
    key
}

/// An unexpired lease: its root, creation and expiry.
struct Lease {
    root: Hash,
    created: u64,
    expires: u64,
}

impl<DB: Database> ChainStore<DB> {
    /// Pin only execution state while a manifest's bounded snapshot is downloaded.
    /// A lease expires after five idle minutes and at most 24 hours total. It never
    /// pins transaction bodies or moves the raw-history retention watermark.
    ///
    /// A full table frees its least recently renewed lease rather than refuse
    /// the endpoint a peer just asked for: whoever downloaded under the freed
    /// lease resumes from a newer manifest and keeps what it staged.
    pub fn pin_state_snapshot(
        &mut self,
        root: Hash,
        now: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        if root == ZERO_HASH {
            return Ok(());
        }
        if self
            .db()
            .get(Column::TrieNodes, &root)
            .map_err(StoreError::Database)?
            .is_none()
        {
            return Err(StoreError::Corrupt("snapshot state root is unavailable"));
        }
        let mut batch = Batch::new();
        let active = self.active_leases(&mut batch, now)?;
        let existing = active.iter().find(|lease| lease.root == root);
        if existing.is_none()
            && active.len() >= MAX_SNAPSHOTS
            && let Some(evicted) = active
                .iter()
                .min_by_key(|lease| (lease.expires, lease.root))
        {
            batch.delete(Column::Meta, lease_key(evicted.root));
            self.state_writer(&mut batch)
                .unpin(StatePin::Lease(evicted.root))?;
        }
        // The lease holds its own reference to the root; an expired lease
        // released above is pinned afresh.
        let state = self.state_at(root);
        self.state_writer(&mut batch)
            .pin(StatePin::Lease(root), &state)?;
        // A clock stepped back below the creation time restarts the lifetime
        // there, keeping creation before expiry.
        let created = existing.map_or(now, |lease| lease.created.min(now));
        let expires = now
            .checked_add(IDLE_SECS)
            .zip(created.checked_add(MAX_LIFETIME_SECS))
            .map(|(idle, lifetime)| idle.min(lifetime))
            .filter(|expiry| *expiry > now)
            .ok_or(StoreError::Corrupt("snapshot lease lifetime is exhausted"))?;
        batch.put(
            Column::Meta,
            lease_key(root),
            borsh::to_vec(&(created, expires))?,
        );
        // A lease lost to a crash only ends a transfer early, so its write is
        // never synced under the engine lock.
        self.write_observed_batch(batch, false)
    }

    /// Renew an existing lease once its idle window runs low and return
    /// whether one holds `root`; ordinary reads cannot pin arbitrary roots.
    pub fn refresh_state_snapshot(
        &mut self,
        root: Hash,
        now: u64,
    ) -> Result<bool, StoreError<DB::Error>> {
        let stored: Option<(u64, u64)> = self.get_decoded(Column::Meta, &lease_key(root))?;
        let live =
            stored.filter(|(created, expires)| valid_lease(*created, *expires) && now < *expires);
        let Some((_, expires)) = live else {
            return Ok(false);
        };
        if expires - now < RENEW_WITHIN_SECS {
            self.pin_state_snapshot(root, now)?;
        }
        Ok(true)
    }

    pub(crate) fn snapshot_retention(
        &self,
        batch: &mut Batch,
        now: u64,
    ) -> Result<Vec<Hash>, StoreError<DB::Error>> {
        Ok(self
            .active_leases(batch, now)?
            .into_iter()
            .map(|lease| lease.root)
            .collect())
    }

    /// Unexpired leases; expired ones are released into `batch`, and so is a
    /// malformed one, which must never stop pruning.
    fn active_leases(
        &self,
        batch: &mut Batch,
        now: u64,
    ) -> Result<Vec<Lease>, StoreError<DB::Error>> {
        let mut leases = Vec::new();
        for (key, bytes) in self
            .db()
            .iter_prefix(Column::Meta, SNAPSHOT_PREFIX)
            .map_err(StoreError::Database)?
        {
            let Some(hash) = key.strip_prefix(SNAPSHOT_PREFIX) else {
                continue;
            };
            let root = Hash::try_from(hash)
                .map_err(|_| StoreError::Corrupt("invalid snapshot lease key"))?;
            let times = borsh::from_slice::<(u64, u64)>(&bytes)
                .ok()
                .filter(|(created, expires)| valid_lease(*created, *expires));
            match times {
                Some((created, expires)) if now < expires => leases.push(Lease {
                    root,
                    created,
                    expires,
                }),
                _ => {
                    batch.delete(Column::Meta, key);
                    self.state_writer(batch).unpin(StatePin::Lease(root))?;
                }
            }
        }
        if leases.len() > MAX_SNAPSHOTS {
            return Err(StoreError::Corrupt("snapshot leases exceed capacity"));
        }
        Ok(leases)
    }
}

const fn valid_lease(created: u64, expires: u64) -> bool {
    created < expires && expires <= created.saturating_add(MAX_LIFETIME_SECS)
}
