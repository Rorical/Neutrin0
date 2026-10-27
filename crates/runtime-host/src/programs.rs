//! Guest program registry (design 20, on-chain program distribution).
//!
//! Every SP1 Guest this backend can prove or fully verify under is held
//! here, keyed by verifying-key digest. The four embedded Guests are
//! installed at construction; Guests distributed on chain are installed
//! later from their ELF bytes, which runs SP1 setup once and records the
//! derived digest. Proving paths resolve keys by the digests named in
//! boundaries and anchors, never by assuming the embedded set.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, RwLock, Weak},
};

use neutrin0_consensus_types::history_proof::{GuestPrograms, VkDigest};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofError;
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1VerifyingKey, blocking::Prover};

use crate::{ProgramProver, Sp1HostError};

/// Keys of one installed Guest.
pub struct ProgramKeys<P: Prover> {
    /// Proving key; for CUDA this owns a server session.
    pub pk: P::ProvingKey,
    /// Verifying key.
    pub vk: SP1VerifyingKey,
    /// BLAKE3 hash of the ELF bytes.
    pub elf_hash: Hash,
}

/// Installed Guests by digest and by ELF hash.
pub struct Registry<P: Prover> {
    by_digest: HashMap<VkDigest, Arc<ProgramKeys<P>>>,
    by_elf: HashMap<Hash, VkDigest>,
    retired: Vec<Weak<ProgramKeys<P>>>,
    warm: BTreeSet<VkDigest>,
}

/// Bound on live PKs/CUDA sessions, including sessions leased by evicted jobs.
pub const MAX_RESIDENT_GUESTS: usize = 16;

impl<P: Prover> Default for Registry<P> {
    fn default() -> Self {
        Self {
            by_digest: HashMap::new(),
            by_elf: HashMap::new(),
            retired: Vec::new(),
            warm: BTreeSet::new(),
        }
    }
}

impl<P: Prover> Registry<P> {
    pub(crate) fn retain(&mut self, warm: BTreeSet<VkDigest>) {
        self.warm = warm;
        let resumed: Vec<_> = self
            .retired
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|keys| self.warm.contains(&keys.vk.hash_u32()))
            .collect();
        for keys in resumed {
            let digest = keys.vk.hash_u32();
            self.by_elf.insert(keys.elf_hash, digest);
            self.by_digest.entry(digest).or_insert(keys);
        }
        self.retired.retain(|lease| {
            lease
                .upgrade()
                .is_some_and(|keys| !self.warm.contains(&keys.vk.hash_u32()))
        });
        let evicted: Vec<_> = self
            .by_digest
            .keys()
            .filter(|digest| !self.warm.contains(*digest))
            .copied()
            .collect();
        for digest in evicted {
            self.remove(&digest);
        }
        self.retired.retain(|lease| lease.strong_count() != 0);
    }

    fn remove(&mut self, digest: &VkDigest) {
        if let Some(keys) = self.by_digest.remove(digest) {
            self.by_elf.retain(|_, installed| installed != digest);
            self.retired.push(Arc::downgrade(&keys));
        }
    }

    /// Reserve one setup flight before allocating a server session. The caller
    /// serializes setup independently, without holding this registry lock.
    pub(crate) fn reserve(&mut self) -> Result<(), Sp1HostError> {
        self.retired.retain(|lease| lease.strong_count() != 0);
        while self.by_digest.len() + self.retired.len() >= MAX_RESIDENT_GUESTS {
            let victim = self
                .by_digest
                .iter()
                .filter(|(digest, keys)| {
                    !self.warm.contains(*digest) && Arc::strong_count(keys) == 1
                })
                .map(|(digest, _)| *digest)
                .min();
            let Some(victim) = victim else {
                return Err(Sp1HostError::Sdk(
                    "resident Guest/session capacity is leased or protected; retry later".into(),
                ));
            };
            self.remove(&victim);
            self.retired.retain(|lease| lease.strong_count() != 0);
        }
        Ok(())
    }
    pub(crate) fn get(&self, digest: &VkDigest) -> Option<Arc<ProgramKeys<P>>> {
        self.by_digest.get(digest).cloned().or_else(|| {
            self.retired
                .iter()
                .filter_map(Weak::upgrade)
                .find(|keys| keys.vk.hash_u32() == *digest)
        })
    }

    /// Digest of the Guest already installed from the ELF hashing to
    /// `elf_hash`.
    pub(crate) fn digest_of(&self, elf_hash: &Hash) -> Option<VkDigest> {
        self.by_elf.get(elf_hash).copied().or_else(|| {
            self.retired
                .iter()
                .filter_map(Weak::upgrade)
                .find(|keys| keys.elf_hash == *elf_hash)
                .map(|keys| keys.vk.hash_u32())
        })
    }

    /// Record set-up keys and return their digest. A digest that is already
    /// installed keeps its existing keys.
    pub(crate) fn insert(&mut self, keys: ProgramKeys<P>) -> VkDigest {
        let digest = keys.vk.hash_u32();
        let held = self
            .by_digest
            .entry(digest)
            .or_insert_with(|| Arc::new(keys));
        // ELF packaging may change without changing ROM/key identity. Keep
        // only the actual resident source hash, not an unbounded alias table.
        self.by_elf.insert(held.elf_hash, digest);
        digest
    }

    pub(crate) fn installed(&self) -> Vec<(VkDigest, Hash)> {
        let mut all: Vec<_> = self
            .by_digest
            .iter()
            .map(|(digest, keys)| (*digest, keys.elf_hash))
            .collect();
        all.sort_unstable();
        all
    }
}

impl<P: ProgramProver> Registry<P> {
    /// Set up `elf` if its hash is new and return the Guest's digest.
    pub(crate) fn install(&mut self, prover: &P, elf: Elf) -> Result<VkDigest, Sp1HostError> {
        let elf_hash = neutrin0_primitives::blake3_256(&elf);
        if let Some(digest) = self.digest_of(&elf_hash) {
            return Ok(digest);
        }
        self.reserve()?;
        Ok(self.insert(setup(prover, elf, elf_hash)?))
    }
}

/// Run SP1 setup for `elf`, whose BLAKE3 hash is `elf_hash`. Holds no
/// registry lock, so callers may run it concurrently with proving.
pub(crate) fn setup<P: ProgramProver>(
    prover: &P,
    elf: Elf,
    elf_hash: Hash,
) -> Result<ProgramKeys<P>, Sp1HostError> {
    let pk = prover.setup_program(elf)?;
    let vk = pk.verifying_key().clone();
    Ok(ProgramKeys { pk, vk, elf_hash })
}

/// Shared handle to the registry.
pub type SharedRegistry<P> = RwLock<Registry<P>>;

/// Resolve keys for every digest of a Guest set.
pub(crate) fn can_prove<P: Prover>(registry: &SharedRegistry<P>, guests: &GuestPrograms) -> bool {
    let registry = registry
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    [
        guests.execution.fact,
        guests.execution.evidence,
        guests.execution.block,
        guests.chunk,
    ]
    .iter()
    .all(|digest| registry.get(digest).is_some())
}

/// Keys for `digest`, or `Unsupported` when the Guest is not installed.
pub(crate) fn keys<P: Prover>(
    registry: &SharedRegistry<P>,
    digest: &VkDigest,
) -> Result<Arc<ProgramKeys<P>>, ProofError> {
    registry
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(digest)
        .ok_or(ProofError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_sdk::blocking::ProverClient;

    #[test]
    fn obsolete_guest_keys_live_only_until_the_job_lease_drops() {
        let prover = ProverClient::builder().mock().build();
        let mut registry = Registry::default();
        let digest = registry
            .install(&prover, crate::EVM_GUEST_ELF.clone())
            .unwrap();
        let lease = registry.get(&digest).unwrap();
        registry.retain(BTreeSet::new());
        assert_eq!(registry.installed(), Vec::<([u32; 8], [u8; 32])>::new());
        assert!(registry.get(&digest).is_some());
        assert_eq!(registry.retired.len(), 1);
        drop(lease);
        registry.reserve().unwrap();
        assert!(registry.retired.is_empty());
        assert!(registry.get(&digest).is_none());
    }

    #[test]
    fn renewed_protection_recovers_an_inflight_guest_without_new_setup() {
        let prover = ProverClient::builder().mock().build();
        let mut registry = Registry::default();
        let digest = registry
            .install(&prover, crate::EVM_GUEST_ELF.clone())
            .unwrap();
        let lease = registry.get(&digest).unwrap();
        registry.retain(BTreeSet::new());
        registry.retain(BTreeSet::from([digest]));
        assert!(Arc::ptr_eq(&lease, &registry.get(&digest).unwrap()));
        assert!(registry.retired.is_empty());
        assert_eq!(registry.installed().len(), 1);
    }
}
