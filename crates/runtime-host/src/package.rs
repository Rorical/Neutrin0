//! Content-addressed runtime packages for fresh chains and governed upgrades.
use crate::{ProgramProver, Sp1HostError, Sp1ProofSystem, wasm::WasmRuntime};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::history_proof::{GuestPrograms, ProgramArtifacts, VkDigest};
use neutrin0_primitives::{ProgramSet, blake3_256};

/// Maximum encoded runtime package accepted by operators and nodes.
pub const MAX_RUNTIME_PACKAGE_BYTES: usize = 128 * 1024 * 1024;
/// Maximum bytes of one WASM/ELF artifact, matching the on-chain program lane.
pub const MAX_RUNTIME_ARTIFACT_BYTES: usize = neutrin0_consensus_types::MAX_PROGRAM_BYTES as usize;

/// Complete execution package. Genesis configuration remains opaque to the node.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct RuntimePackage {
    /// Expected runtime content hash and locally derived SP1 identities.
    pub programs: ProgramSet,
    /// Raw BLAKE3 integrity checksums of all four execution artifacts.
    /// Governance uses [`Self::distribution_artifacts`] instead: its hashes bind
    /// the length and authenticated program-lane pieces.
    pub artifacts: ProgramArtifacts,
    /// Runtime WASM with the complete common execution, admission and query ABI.
    pub wasm: Vec<u8>,
    /// Cryptographic Fact Guest ELF.
    pub fact: Vec<u8>,
    /// Evidence admission Guest ELF.
    pub evidence: Vec<u8>,
    /// Matching Block Guest ELF.
    pub block: Vec<u8>,
    /// Runtime-specific Borsh genesis configuration.
    pub genesis: Vec<u8>,
}

impl RuntimePackage {
    /// Bound decoding before validating artifact hashes and the complete WASM ABI.
    /// # Errors
    /// Rejects oversized packages, invalid encodings, content hashes or WASM exports.
    pub fn decode(bytes: &[u8]) -> Result<Self, Sp1HostError> {
        if bytes.len() > MAX_RUNTIME_PACKAGE_BYTES {
            return Err(Sp1HostError::Sdk("runtime package size limit".into()));
        }
        let package: Self =
            borsh::from_slice(bytes).map_err(|error| Sp1HostError::Sdk(error.to_string()))?;
        package.validate_content()?;
        Ok(package)
    }
    /// Validate content identities before setting up any programs.
    /// # Errors
    /// Rejects missing identities or artifacts which do not match their declared hashes.
    pub fn validate_content(&self) -> Result<(), Sp1HostError> {
        self.validate_shape()?;
        let hashes = ProgramArtifacts {
            runtime: blake3_256(&self.wasm),
            fact: blake3_256(&self.fact),
            evidence: blake3_256(&self.evidence),
            block: blake3_256(&self.block),
        };
        if !self.programs.is_complete()
            || hashes != self.artifacts
            || hashes.runtime != self.programs.runtime_code_hash
        {
            return Err(Sp1HostError::Sdk(
                "runtime package content identity mismatch".into(),
            ));
        }
        WasmRuntime::new(&self.wasm).map_err(|error| Sp1HostError::Sdk(error.to_string()))?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), Sp1HostError> {
        let size =
            borsh::object_length(self).map_err(|error| Sp1HostError::Sdk(error.to_string()))?;
        if size > MAX_RUNTIME_PACKAGE_BYTES {
            return Err(Sp1HostError::Sdk("runtime package size limit".into()));
        }
        self.distribution_artifacts()?;
        if !self.wasm.starts_with(b"\0asm")
            || [&self.fact, &self.evidence, &self.block]
                .iter()
                .any(|bytes| !bytes.starts_with(b"\x7fELF"))
        {
            return Err(Sp1HostError::Sdk(
                "runtime package artifact kind mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Content hashes an upgrade proposal must name for on-chain distribution.
    /// These differ from the package's raw integrity checksums and runtime identity.
    /// # Errors
    /// Rejects empty artifacts or artifacts exceeding the program-lane bound.
    pub fn distribution_artifacts(&self) -> Result<ProgramArtifacts, Sp1HostError> {
        Ok(ProgramArtifacts {
            runtime: distribution_hash(&self.wasm)?,
            fact: distribution_hash(&self.fact)?,
            evidence: distribution_hash(&self.evidence)?,
            block: distribution_hash(&self.block)?,
        })
    }

    /// Encode a bounded, content-authenticated package for operator distribution.
    /// # Errors
    /// Rejects invalid package content or an encoding failure.
    pub fn encode(&self) -> Result<Vec<u8>, Sp1HostError> {
        self.validate_content()?;
        borsh::to_vec(self).map_err(|error| Sp1HostError::Sdk(error.to_string()))
    }
    /// Derive all execution keys locally, then authenticate the declared set.
    /// A chain's specification pins its Fact Guest; nodes compare it with the
    /// derived set before use.
    /// # Errors
    /// Rejects invalid Guest ELFs, setup failures or mismatched expected identities.
    pub fn proof_system<P: ProgramProver>(
        &self,
        prover: P,
    ) -> Result<Sp1ProofSystem<P>, Sp1HostError> {
        self.validate_content()?;
        let proof = Sp1ProofSystem::with_execution(
            prover,
            self.fact.clone().into(),
            self.evidence.clone().into(),
            self.block.clone().into(),
            crate::CONSENSUS_CHUNK_GUEST_ELF.clone(),
        )?;
        if proof.execution_programs() != self.programs.execution {
            return Err(Sp1HostError::Sdk("runtime package SP1 key mismatch".into()));
        }
        Ok(proof)
    }

    /// Construct the embedded runtime package (the Osaka EVM runtime and the
    /// embedded Fact, Evidence and Block Guests) with `genesis` as its opaque
    /// configuration, using local verifying-key derivation.
    /// # Errors
    /// Reports local setup failure.
    pub fn embedded(genesis: Vec<u8>) -> Result<Self, Sp1HostError> {
        static EMBEDDED: std::sync::Mutex<Option<RuntimePackage>> = std::sync::Mutex::new(None);
        let mut cached = EMBEDDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cached.is_none() {
            // Only successfully authenticated embedded artifact identities are cached.
            *cached = Some(Self::from_artifacts(
                crate::wasm::EVM_MASTER_WASM.to_vec(),
                crate::FACT_GUEST_ELF.to_vec(),
                crate::EVIDENCE_GUEST_ELF.to_vec(),
                crate::EVM_GUEST_ELF.to_vec(),
                Vec::new(),
            )?);
        }
        let mut package = cached
            .as_ref()
            .expect("authenticated embedded package")
            .clone();
        drop(cached);
        package.genesis = genesis;
        package.validate_shape()?;
        Ok(package)
    }

    /// Package supplied artifacts after deriving their SP1 keys locally.
    /// # Errors
    /// Rejects invalid WASM/ELF artifacts or local setup failures.
    pub fn from_artifacts(
        wasm: Vec<u8>,
        fact: Vec<u8>,
        evidence: Vec<u8>,
        block: Vec<u8>,
        genesis: Vec<u8>,
    ) -> Result<Self, Sp1HostError> {
        // Bound and classify supplied bytes before costly Guest setup.
        let supplied = Self {
            programs: ProgramSet {
                runtime_code_hash: blake3_256(&wasm),
                execution: neutrin0_primitives::ExecutionPrograms {
                    fact: [0; 8],
                    evidence: [0; 8],
                    block: [0; 8],
                },
            },
            artifacts: ProgramArtifacts::default(),
            wasm,
            fact,
            evidence,
            block,
            genesis,
        };
        supplied.validate_shape()?;
        let prover = sp1_sdk::blocking::ProverClient::builder().light().build();
        let backend = Sp1ProofSystem::with_execution(
            prover,
            supplied.fact.clone().into(),
            supplied.evidence.clone().into(),
            supplied.block.clone().into(),
            crate::CONSENSUS_CHUNK_GUEST_ELF.clone(),
        )?;
        let programs = ProgramSet {
            runtime_code_hash: supplied.programs.runtime_code_hash,
            execution: backend.execution_programs(),
        };
        let artifacts = ProgramArtifacts {
            runtime: programs.runtime_code_hash,
            fact: blake3_256(&supplied.fact),
            evidence: blake3_256(&supplied.evidence),
            block: blake3_256(&supplied.block),
        };
        let package = Self {
            programs,
            artifacts,
            ..supplied
        };
        package.validate_content()?;
        Ok(package)
    }
    /// The complete locally pinned identity set after package setup.
    /// # Errors
    /// Rejects a backend initialized from another execution package.
    pub fn guests<P: ProgramProver>(
        &self,
        backend: &Sp1ProofSystem<P>,
    ) -> Result<GuestPrograms, Sp1HostError> {
        if backend.execution_programs() != self.programs.execution {
            return Err(Sp1HostError::Sdk(
                "runtime package backend identity mismatch".into(),
            ));
        }
        Ok(backend.embedded_guests())
    }
}

/// Derive a Guest's verifying-key digest locally from its ELF bytes.
/// # Errors
/// Rejects a non-ELF artifact or a failed SP1 setup.
pub fn guest_key(elf: &[u8]) -> Result<VkDigest, Sp1HostError> {
    if !elf.starts_with(b"\x7fELF") {
        return Err(Sp1HostError::Sdk("Guest artifact is not an ELF".into()));
    }
    let prover = sp1_sdk::blocking::ProverClient::builder().light().build();
    crate::programs::Registry::default().install(&prover, elf.to_vec().into())
}

/// The embedded chunk Guest's locally derived key; derived once per process.
/// # Errors
/// Reports a failed SP1 setup.
pub fn embedded_chunk_program() -> Result<VkDigest, Sp1HostError> {
    static EMBEDDED: std::sync::OnceLock<VkDigest> = std::sync::OnceLock::new();
    if let Some(chunk) = EMBEDDED.get() {
        return Ok(*chunk);
    }
    let chunk = guest_key(&crate::CONSENSUS_CHUNK_GUEST_ELF)?;
    Ok(*EMBEDDED.get_or_init(|| chunk))
}

/// Program-lane content hash of an artifact, the key a node fetches it by.
/// # Errors
/// Rejects empty artifacts or artifacts exceeding the program-lane bound.
pub fn content_hash(bytes: &[u8]) -> Result<neutrin0_primitives::Hash, Sp1HostError> {
    distribution_hash(bytes)
}

fn distribution_hash(bytes: &[u8]) -> Result<neutrin0_primitives::Hash, Sp1HostError> {
    use neutrin0_consensus_types::{
        MAX_PROGRAM_BYTES, MAX_PROGRAM_PIECE_BYTES, program_content_hash,
    };
    let length = u32::try_from(bytes.len())
        .map_err(|_| Sp1HostError::Sdk("runtime artifact size limit".into()))?;
    if length == 0 || length > MAX_PROGRAM_BYTES {
        return Err(Sp1HostError::Sdk("runtime artifact size limit".into()));
    }
    let leaves: Vec<_> = bytes
        .chunks(MAX_PROGRAM_PIECE_BYTES)
        .map(blake3_256)
        .collect();
    Ok(program_content_hash(
        length,
        neutrin0_primitives::merkle_root_of_hashes(&leaves),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_hash_authenticates_length_and_program_pieces() {
        let bytes = vec![7; neutrin0_consensus_types::MAX_PROGRAM_PIECE_BYTES + 1];
        let leaves = bytes
            .chunks(neutrin0_consensus_types::MAX_PROGRAM_PIECE_BYTES)
            .map(blake3_256)
            .collect::<Vec<_>>();
        let expected = neutrin0_consensus_types::program_content_hash(
            u32::try_from(bytes.len()).unwrap(),
            neutrin0_primitives::merkle_root_of_hashes(&leaves),
        );
        assert_eq!(distribution_hash(&bytes).unwrap(), expected);
        assert_ne!(expected, blake3_256(&bytes));
        assert!(distribution_hash(&[]).is_err());
    }
}
