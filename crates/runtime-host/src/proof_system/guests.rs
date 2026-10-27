//! Guest installation and lookup: on-chain ELFs set up once under their
//! authenticated identity, and accessors over the embedded program set.

use neutrin0_consensus_types::history_proof::{GuestPrograms, VkDigest};
use neutrin0_proof_system::artifacts::ArtifactIdentity;
use sp1_sdk::{HashableKey, SP1VerifyingKey, blocking::ProverClient};

use super::Sp1ProofSystem;
use crate::{ProgramProver, Sp1HostError, guarded};

impl<P> Sp1ProofSystem<P>
where
    P: ProgramProver,
{
    /// Install a Guest from its ELF bytes, running SP1 setup once, and return
    /// its digest. Installing an already known ELF is free.
    ///
    /// Setup runs without holding the registry lock, so proving and
    /// verification continue while a new Guest is prepared.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] when setup fails.
    pub fn install_guest(&self, elf: Vec<u8>) -> Result<VkDigest, Sp1HostError> {
        self.install_guest_with_expected(elf, None)
    }

    /// Authenticate a governed Guest's key before exposing it to any proof job.
    /// # Errors
    /// Rejects invalid ELFs, setup failures and a mismatched expected identity.
    pub fn install_guest_checked(
        &self,
        elf: Vec<u8>,
        expected: VkDigest,
    ) -> Result<VkDigest, Sp1HostError> {
        self.install_guest_with_expected(elf, Some(expected))
    }

    fn install_guest_with_expected(
        &self,
        elf: Vec<u8>,
        expected: Option<VkDigest>,
    ) -> Result<VkDigest, Sp1HostError> {
        if elf.is_empty() || elf.len() > neutrin0_consensus_types::MAX_PROGRAM_BYTES as usize {
            return Err(Sp1HostError::Sdk(
                "Guest ELF exceeds protocol artifact limit".into(),
            ));
        }
        let elf = sp1_sdk::Elf::from(elf);
        let elf_hash = neutrin0_primitives::blake3_256(&elf);
        let _setup = self
            .program_setup
            .lock()
            .map_err(|_| Sp1HostError::Sdk("program setup lock poisoned".into()))?;
        let installed = self
            .programs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .digest_of(&elf_hash);
        if let Some(digest) = installed {
            if expected.is_some_and(|expected| expected != digest) {
                return Err(Sp1HostError::Sdk("governed Guest key mismatch".into()));
            }
            return Ok(digest);
        }
        // Authenticate ROM locally before allocating a server session. Reuse
        // an existing same-key program even when ELF packaging/debug bytes vary.
        let local = guarded(|| {
            crate::cached_proving_key(&ProverClient::builder().light().build(), elf.clone())
        })
        .map_err(|_| {
            Sp1HostError::Sdk("Guest preprocessing panicked; no key installed".into())
        })??;
        let digest = sp1_sdk::ProvingKey::verifying_key(&local).hash_u32();
        if expected.is_some_and(|expected| expected != digest) {
            return Err(Sp1HostError::Sdk("governed Guest key mismatch".into()));
        }
        if self.keys(&digest).is_ok() {
            return Ok(digest);
        }
        self.programs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reserve()?;
        let keys =
            guarded(|| crate::programs::setup(&self.prover, elf, elf_hash)).map_err(|_| {
                Sp1HostError::Sdk("Guest preprocessing panicked; no key installed".into())
            })??;
        if keys.vk.hash_u32() != digest {
            return Err(Sp1HostError::Sdk("governed Guest key mismatch".into()));
        }
        Ok(self
            .programs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(keys))
    }

    /// Read the exact ELF already held by a locally authenticated registry entry.
    #[must_use]
    pub fn guest_artifact(&self, digest: &VkDigest) -> Option<Vec<u8>> {
        use sp1_sdk::ProvingKey as _;
        let held = self
            .programs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(digest)
            .map(|keys| keys.pk.elf().to_vec());
        held.or_else(|| {
            if !self
                .retained_sources
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&ArtifactIdentity::Guest(*digest))
            {
                return None;
            }
            self.artifact_loader
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .and_then(|reader| reader(ArtifactIdentity::Guest(*digest)))
        })
    }

    /// Read a bounded fragment from an already authenticated ELF registry entry.
    #[must_use]
    pub fn guest_fragment(
        &self,
        digest: &VkDigest,
        offset: u64,
        max_bytes: usize,
    ) -> Option<(u64, Vec<u8>)> {
        use sp1_sdk::ProvingKey as _;
        let registry = self
            .programs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(keys) = registry.get(digest) {
            return neutrin0_proof_system::artifacts::artifact_fragment(
                keys.pk.elf(),
                offset,
                max_bytes,
            );
        }
        drop(registry);
        neutrin0_proof_system::artifacts::artifact_fragment(
            &self.guest_artifact(digest)?,
            offset,
            max_bytes,
        )
    }

    /// `(digest, ELF hash)` of every installed Guest.
    #[must_use]
    pub fn installed_guests(&self) -> Vec<(VkDigest, neutrin0_primitives::Hash)> {
        self.programs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .installed()
    }

    /// `true` when every Guest of `guests` is installed.
    #[must_use]
    pub fn holds(&self, guests: &GuestPrograms) -> bool {
        guests.execution.fact == self.embedded.execution.fact
            && crate::programs::can_prove(&self.programs, guests)
    }

    /// Digests of the four embedded Guests.
    #[must_use]
    pub const fn embedded_guests(&self) -> GuestPrograms {
        self.embedded
    }

    /// Verifying key of the embedded block Guest (`EVM_GUEST_ELF`).
    #[must_use]
    pub fn verifying_key(&self) -> SP1VerifyingKey {
        self.keys(&self.embedded.execution.block)
            .expect("embedded block program is always installed")
            .vk
            .clone()
    }

    /// Digests of the three embedded execution Guests.
    #[must_use]
    pub const fn execution_programs(
        &self,
    ) -> neutrin0_consensus_types::history_proof::ExecutionPrograms {
        self.embedded.execution
    }
}
