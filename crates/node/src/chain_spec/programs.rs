//! The `[programs]` table: pinned genesis program identities and the bytes
//! a node authenticates against them.

use std::fs;
use std::path::Path;

use neutrin0_primitives::{
    ExecutionPrograms, GenesisArtifacts, Hash, PinnedPrograms, ProgramSet, ZERO_HASH,
};
use serde::Deserialize;

use super::{ChainSpecError, ChainSpecFile, decode_hash_or_zero, decode_hex_exact};

/// Genesis program identities a production chain spec pins (`[programs]`).
///
/// Every identity is required; a node accepts program bytes, embedded or
/// read from its package directory, only when they reproduce them. Verifying
/// keys are 32 bytes: eight little-endian `u32` words.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramPins {
    /// BLAKE3 of the runtime WASM.
    pub runtime_code_hash: String,
    /// Fact Guest verifying key.
    pub fact_vk: String,
    /// Evidence Guest verifying key.
    pub evidence_vk: String,
    /// Block Guest verifying key.
    pub block_vk: String,
    /// Chunk Guest verifying key.
    pub chunk_vk: String,
    /// Program-lane content hashes by which a node fetches the artifacts it
    /// does not embed; zero or absent where not distributed.
    #[serde(default)]
    pub runtime_artifact: Option<String>,
    /// Fact Guest ELF content hash.
    #[serde(default)]
    pub fact_artifact: Option<String>,
    /// Evidence Guest ELF content hash.
    #[serde(default)]
    pub evidence_artifact: Option<String>,
    /// Block Guest ELF content hash.
    #[serde(default)]
    pub block_artifact: Option<String>,
    /// Chunk Guest ELF content hash.
    #[serde(default)]
    pub chunk_artifact: Option<String>,
}

/// Encode a verifying-key digest as the 32-byte hex the spec file uses.
#[must_use]
pub fn vk_hex(digest: &[u32; 8]) -> String {
    hex::encode(
        digest
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}

fn decode_vk(hex: &str, field: &str) -> Result<[u32; 8], ChainSpecError> {
    let bytes = decode_hex_exact::<32>(hex, field)?;
    let mut digest = [0; 8];
    for (word, chunk) in digest.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    Ok(digest)
}

/// The genesis programs a node runs: identities the spec pins and their
/// locally authenticated bytes.
#[derive(Clone, Debug)]
pub struct GenesisPrograms {
    /// Runtime WASM and execution Guests with their locally derived keys.
    pub package: neutrin0_runtime_host::package::RuntimePackage,
    /// Chunk Guest ELF.
    pub chunk_elf: Vec<u8>,
    /// Its locally derived key.
    pub chunk: [u32; 8],
    /// Program-lane content hashes of all five artifacts.
    pub artifacts: GenesisArtifacts,
}

impl GenesisPrograms {
    /// Construct a proof backend from exactly these programs, re-deriving
    /// every key locally.
    /// # Errors
    /// Reports setup failure or a backend whose keys differ from the pins.
    pub fn proof_system<P: neutrin0_runtime_host::ProgramProver>(
        &self,
        prover: P,
    ) -> Result<neutrin0_runtime_host::Sp1ProofSystem<P>, neutrin0_runtime_host::Sp1HostError> {
        let backend = neutrin0_runtime_host::Sp1ProofSystem::with_execution(
            prover,
            self.package.fact.clone().into(),
            self.package.evidence.clone().into(),
            self.package.block.clone().into(),
            self.chunk_elf.clone().into(),
        )?;
        let guests = backend.embedded_guests();
        if guests.execution != self.package.programs.execution || guests.chunk != self.chunk {
            return Err(neutrin0_runtime_host::Sp1HostError::Sdk(
                "proof backend keys differ from the pinned genesis programs".into(),
            ));
        }
        Ok(backend)
    }
}

impl ChainSpecFile {
    /// The embedded runtime package for this file's genesis allocation,
    /// authenticated against the file's program pins.
    /// # Errors
    /// See [`Self::genesis_programs`].
    pub fn runtime_package(
        &self,
    ) -> Result<neutrin0_runtime_host::package::RuntimePackage, ChainSpecError> {
        Ok(self.genesis_programs(None)?.package)
    }

    /// Pin the programs this binary embeds as the `[programs]` table, the
    /// authoring step of a new specification. Their identities do not depend
    /// on the genesis allocation.
    /// # Errors
    /// Reports local key derivation or artifact hashing failure.
    pub fn pin_embedded_programs(&mut self) -> Result<(), ChainSpecError> {
        use neutrin0_runtime_host::package::{
            RuntimePackage, content_hash, embedded_chunk_program,
        };
        let error = |error: neutrin0_runtime_host::Sp1HostError| {
            ChainSpecError::Validation(error.to_string())
        };
        let embedded = RuntimePackage::embedded(Vec::new()).map_err(error)?;
        let chunk = embedded_chunk_program().map_err(error)?;
        let artifact = |bytes: &[u8]| {
            content_hash(bytes)
                .map(|hash| Some(hex::encode(hash)))
                .map_err(error)
        };
        let programs = embedded.programs;
        self.programs = Some(ProgramPins {
            runtime_code_hash: hex::encode(programs.runtime_code_hash),
            fact_vk: vk_hex(&programs.execution.fact),
            evidence_vk: vk_hex(&programs.execution.evidence),
            block_vk: vk_hex(&programs.execution.block),
            chunk_vk: vk_hex(&chunk),
            runtime_artifact: artifact(&embedded.wasm)?,
            fact_artifact: artifact(&embedded.fact)?,
            evidence_artifact: artifact(&embedded.evidence)?,
            block_artifact: artifact(&embedded.block)?,
            chunk_artifact: artifact(&neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF)?,
        });
        Ok(())
    }

    /// The `[programs]` table of this file's pins, as `chain-spec.toml` text.
    #[must_use]
    pub fn programs_toml(&self) -> Option<String> {
        let pins = self.programs.as_ref()?;
        let artifact = |value: &Option<String>| value.clone().unwrap_or_else(|| "00".repeat(32));
        Some(format!(
            "[programs]\nruntime_code_hash = \"{}\"\nfact_vk = \"{}\"\nevidence_vk = \"{}\"\n\
             block_vk = \"{}\"\nchunk_vk = \"{}\"\nruntime_artifact = \"{}\"\n\
             fact_artifact = \"{}\"\nevidence_artifact = \"{}\"\nblock_artifact = \"{}\"\n\
             chunk_artifact = \"{}\"\n",
            pins.runtime_code_hash,
            pins.fact_vk,
            pins.evidence_vk,
            pins.block_vk,
            pins.chunk_vk,
            artifact(&pins.runtime_artifact),
            artifact(&pins.fact_artifact),
            artifact(&pins.evidence_artifact),
            artifact(&pins.block_artifact),
            artifact(&pins.chunk_artifact),
        ))
    }

    /// Resolve the genesis programs: each pinned artifact is the embedded one
    /// when it reproduces the pin, otherwise `<package_dir>/<content hash>.bin`
    /// (the node's program store), accepted only when its runtime hash or
    /// locally derived key equals the pin.
    /// # Errors
    /// Rejects a file without `[programs]`, malformed pins or allocations,
    /// missing artifacts and any artifact whose identity differs from its pin.
    pub fn genesis_programs(
        &self,
        package_dir: Option<&Path>,
    ) -> Result<GenesisPrograms, ChainSpecError> {
        use neutrin0_runtime_host::package::{RuntimePackage, embedded_chunk_program, guest_key};
        let error = |error: neutrin0_runtime_host::Sp1HostError| {
            ChainSpecError::Validation(error.to_string())
        };
        let configuration = self.genesis_configuration()?;
        let embedded = RuntimePackage::embedded(configuration.clone()).map_err(error)?;
        let embedded_chunk = embedded_chunk_program().map_err(error)?;
        let chunk_elf = neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF.to_vec();
        let PinnedPrograms {
            programs:
                ProgramSet {
                    runtime_code_hash,
                    execution:
                        ExecutionPrograms {
                            fact,
                            evidence,
                            block,
                        },
                },
            chunk,
            artifacts,
        } = self.pinned_programs()?;
        let pick = |matches: bool, bytes: &[u8], hash: Hash, name: &str| {
            pinned_artifact_bytes(package_dir, matches, bytes, hash, name)
        };
        let wasm = pick(
            embedded.programs.runtime_code_hash == runtime_code_hash,
            &embedded.wasm,
            artifacts.runtime,
            "runtime",
        )?;
        let package = RuntimePackage::from_artifacts(
            wasm,
            pick(
                embedded.programs.execution.fact == fact,
                &embedded.fact,
                artifacts.fact,
                "Fact Guest",
            )?,
            pick(
                embedded.programs.execution.evidence == evidence,
                &embedded.evidence,
                artifacts.evidence,
                "Evidence Guest",
            )?,
            pick(
                embedded.programs.execution.block == block,
                &embedded.block,
                artifacts.block,
                "Block Guest",
            )?,
            configuration,
        )
        .map_err(error)?;
        let chunk_elf = pick(
            embedded_chunk == chunk,
            &chunk_elf,
            artifacts.chunk,
            "chunk Guest",
        )?;
        let derived_chunk = if embedded_chunk == chunk {
            embedded_chunk
        } else {
            guest_key(&chunk_elf).map_err(error)?
        };
        if package.programs.runtime_code_hash != runtime_code_hash
            || package.programs.execution.fact != fact
            || package.programs.execution.evidence != evidence
            || package.programs.execution.block != block
            || derived_chunk != chunk
        {
            return Err(ChainSpecError::Validation(
                "genesis program bytes do not reproduce the pinned identities".into(),
            ));
        }
        Ok(GenesisPrograms {
            package,
            chunk_elf,
            chunk,
            artifacts,
        })
    }

    /// The programs this file's `[programs]` table pins, decoded but not
    /// reproduced from any bytes.
    ///
    /// # Errors
    /// Returns a file without the table and malformed pins.
    pub fn pinned_programs(&self) -> Result<PinnedPrograms, ChainSpecError> {
        let Some(pins) = &self.programs else {
            return Err(ChainSpecError::Validation(
                "the chain spec has no [programs] table; pin the genesis programs with \
                 `neutrin0-cli genesis --spec <file> --write`"
                    .into(),
            ));
        };
        let optional =
            |value: &Option<String>, field: &str| decode_hash_or_zero(value.as_deref(), field);
        Ok(PinnedPrograms {
            programs: ProgramSet {
                runtime_code_hash: decode_hex_exact::<32>(
                    &pins.runtime_code_hash,
                    "programs.runtime_code_hash",
                )?,
                execution: ExecutionPrograms {
                    fact: decode_vk(&pins.fact_vk, "programs.fact_vk")?,
                    evidence: decode_vk(&pins.evidence_vk, "programs.evidence_vk")?,
                    block: decode_vk(&pins.block_vk, "programs.block_vk")?,
                },
            },
            chunk: decode_vk(&pins.chunk_vk, "programs.chunk_vk")?,
            artifacts: GenesisArtifacts {
                runtime: optional(&pins.runtime_artifact, "programs.runtime_artifact")?,
                fact: optional(&pins.fact_artifact, "programs.fact_artifact")?,
                evidence: optional(&pins.evidence_artifact, "programs.evidence_artifact")?,
                block: optional(&pins.block_artifact, "programs.block_artifact")?,
                chunk: optional(&pins.chunk_artifact, "programs.chunk_artifact")?,
            },
        })
    }
}

/// Embedded bytes when they reproduce the pin, else the package
/// directory's copy under the pinned content hash.
fn pinned_artifact_bytes(
    package_dir: Option<&Path>,
    matches: bool,
    bytes: &[u8],
    hash: Hash,
    name: &str,
) -> Result<Vec<u8>, ChainSpecError> {
    use neutrin0_runtime_host::package::content_hash;
    if matches {
        return Ok(bytes.to_vec());
    }
    let missing = || {
        ChainSpecError::Validation(format!(
            "the pinned {name} is not embedded; place its artifact {} in the \
             node's programs directory",
            hex::encode(hash)
        ))
    };
    let dir = package_dir.ok_or_else(missing)?;
    if hash == ZERO_HASH {
        return Err(missing());
    }
    let bytes = fs::read(dir.join(format!("{}.bin", hex::encode(hash)))).map_err(|_| missing())?;
    if content_hash(&bytes).ok() != Some(hash) {
        return Err(ChainSpecError::Validation(format!(
            "{name} artifact does not match its content hash"
        )));
    }
    Ok(bytes)
}
