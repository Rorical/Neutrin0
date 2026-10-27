//! Atomic, input-addressed checkpoints for expensive real-proof acceptance.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{Hash, blake3_256};
use neutrin0_proof_system::ProofError;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const MAX_ARTIFACT_BYTES: u64 = 10 * 1024 * 1024;
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Exact circuit, program, input and expected statement for one proof stage.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct StageIdentity {
    stage: String,
    circuit: String,
    elf_hash: Hash,
    input_hash: Hash,
    expected_hash: Hash,
}

impl StageIdentity {
    /// Bind a checkpoint to its current program and exact canonical inputs.
    #[must_use]
    pub fn new(stage: &str, elf: &[u8], input: &[u8], expected: &[u8]) -> Self {
        Self {
            stage: stage.to_owned(),
            circuit: sp1_sdk::SP1_CIRCUIT_VERSION.to_owned(),
            elf_hash: blake3_256(elf),
            input_hash: blake3_256(input),
            expected_hash: blake3_256(expected),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
struct Artifact {
    identity: StageIdentity,
    payload_hash: Hash,
    payload: Vec<u8>,
}

/// Retains separately verified `EvidenceProof`, block and chunk checkpoints.
pub struct AcceptanceCache {
    directory: PathBuf,
}

impl AcceptanceCache {
    /// Use the configured gate directory or the workspace acceptance directory.
    ///
    /// # Errors
    /// Returns filesystem errors when the checkpoint directory cannot be opened.
    pub fn from_env() -> io::Result<Self> {
        let directory = std::env::var_os("NEUTRIN0_EVIDENCE_GATE_DIR").map_or_else(
            || {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../target/proof-acceptance/evidence-pipeline")
            },
            PathBuf::from,
        );
        Self::new(directory)
    }

    /// Open a checkpoint directory without changing or deleting existing stages.
    ///
    /// # Errors
    /// Returns filesystem errors when the directory cannot be created.
    pub fn new(directory: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    fn path(&self, identity: &StageIdentity) -> PathBuf {
        let digest = blake3_256(&borsh::to_vec(identity).expect("stage identity encoding"));
        let mut name = String::with_capacity(70);
        for byte in digest {
            write!(&mut name, "{byte:02x}").expect("hash filename formatting");
        }
        name.push_str(".proof");
        self.directory.join(name)
    }

    /// Resume only after verifying the checkpoint and exact current statement.
    ///
    /// Newly generated proofs are verified
    /// before an atomic rename publishes them. A corrupt cache fails the gate.
    ///
    /// # Errors
    /// Returns proof, checkpoint validation or filesystem errors without publishing
    /// an unverified stage.
    pub fn prove_or_resume(
        &self,
        identity: &StageIdentity,
        verify: impl Fn(&[u8]) -> Result<(), ProofError>,
        prove: impl FnOnce() -> Result<Vec<u8>, ProofError>,
    ) -> io::Result<Vec<u8>> {
        let path = self.path(identity);
        let start = Instant::now();
        let file = match File::open(&path) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(file) = file {
            let mut bytes = Vec::new();
            file.take(MAX_ARTIFACT_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
                return Err(io::Error::other("acceptance checkpoint exceeds size limit"));
            }
            let artifact: Artifact =
                borsh::from_slice(&bytes).map_err(|error| io::Error::other(error.to_string()))?;
            if artifact.identity != *identity
                || blake3_256(&artifact.payload) != artifact.payload_hash
            {
                return Err(io::Error::other(
                    "acceptance checkpoint identity or digest mismatch",
                ));
            }
            verify(&artifact.payload).map_err(|error| io::Error::other(error.to_string()))?;
            eprintln!(
                "evidence gate: {} resumed and verified in {:?}: {}",
                identity.stage,
                start.elapsed(),
                path.display()
            );
            return Ok(artifact.payload);
        }
        eprintln!(
            "evidence gate: {} checkpoint missing; proving",
            identity.stage
        );
        let payload = prove().map_err(|error| io::Error::other(error.to_string()))?;
        verify(&payload).map_err(|error| io::Error::other(error.to_string()))?;
        let artifact = Artifact {
            identity: identity.clone(),
            payload_hash: blake3_256(&payload),
            payload,
        };
        let encoded =
            borsh::to_vec(&artifact).map_err(|error| io::Error::other(error.to_string()))?;
        if encoded.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(io::Error::other("acceptance checkpoint exceeds size limit"));
        }
        let temporary = path.with_extension(format!(
            "{}.{}.tmp",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let saved = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)
        })();
        if saved.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        saved?;
        eprintln!(
            "evidence gate: {} proved, verified and saved in {:?}: {}",
            identity.stage,
            start.elapsed(),
            path.display()
        );
        Ok(artifact.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "neutrin0-acceptance-test-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn resume_reverifies_and_program_or_input_changes_require_new_proofs() {
        let directory = Directory::new();
        let cache = AcceptanceCache::new(directory.0.clone()).unwrap();
        let identity = StageIdentity::new("stage", b"program", b"input", b"expected");
        let verify = |bytes: &[u8]| {
            if bytes == b"artifact" {
                Ok(())
            } else {
                Err(ProofError::BackendRejected)
            }
        };
        let expected = cache
            .prove_or_resume(&identity, verify, || Ok(b"artifact".to_vec()))
            .unwrap();
        assert_eq!(
            cache
                .prove_or_resume(&identity, verify, || panic!("must resume existing stage"))
                .unwrap(),
            expected
        );
        assert!(
            cache
                .prove_or_resume(
                    &identity,
                    |_| Err(ProofError::BackendRejected),
                    || panic!("must not trust an invalid cached proof")
                )
                .is_err()
        );
        let mut changed_circuit = identity;
        changed_circuit.circuit.push_str("-changed");
        for changed in [
            StageIdentity::new("stage", b"changed program", b"input", b"expected"),
            StageIdentity::new("stage", b"program", b"changed input", b"expected"),
            StageIdentity::new("stage", b"program", b"input", b"changed expected"),
            StageIdentity::new("changed stage", b"program", b"input", b"expected"),
            changed_circuit,
        ] {
            cache
                .prove_or_resume(&changed, verify, || Ok(b"artifact".to_vec()))
                .unwrap();
        }
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 6);
    }

    #[test]
    fn failed_generation_and_corrupt_checkpoints_cannot_publish_acceptance() {
        let directory = Directory::new();
        let cache = AcceptanceCache::new(directory.0.clone()).unwrap();
        let identity = StageIdentity::new("stage", b"program", b"input", b"expected");
        assert!(
            cache
                .prove_or_resume(&identity, |_| Ok(()), || Err(ProofError::BackendRejected))
                .is_err()
        );
        assert!(!cache.path(&identity).exists());
        assert!(
            cache
                .prove_or_resume(
                    &identity,
                    |_| Err(ProofError::BackendRejected),
                    || Ok(vec![1])
                )
                .is_err()
        );
        assert!(!cache.path(&identity).exists());
        cache
            .prove_or_resume(&identity, |_| Ok(()), || Ok(vec![1]))
            .unwrap();
        let path = cache.path(&identity);
        let mut artifact: Artifact = borsh::from_slice(&fs::read(&path).unwrap()).unwrap();
        artifact.payload.push(2);
        fs::write(path, borsh::to_vec(&artifact).unwrap()).unwrap();
        assert!(
            cache
                .prove_or_resume(
                    &identity,
                    |_| panic!("corrupt bytes must not reach verifier"),
                    || panic!("must not hide corrupt cache")
                )
                .is_err()
        );
    }

    #[test]
    fn interrupted_writes_are_ignored_and_malformed_published_records_fail() {
        let directory = Directory::new();
        let cache = AcceptanceCache::new(directory.0.clone()).unwrap();
        let identity = StageIdentity::new("stage", b"program", b"input", b"expected");
        let path = cache.path(&identity);
        fs::write(path.with_extension("interrupted.tmp"), [0]).unwrap();
        assert_eq!(
            cache
                .prove_or_resume(&identity, |_| Ok(()), || Ok(vec![1]))
                .unwrap(),
            vec![1]
        );
        let mut record: Artifact = borsh::from_slice(&fs::read(&path).unwrap()).unwrap();
        record.identity.input_hash[0] ^= 1;
        for bytes in [borsh::to_vec(&record).unwrap(), vec![0]] {
            fs::write(&path, bytes).unwrap();
            assert!(
                cache
                    .prove_or_resume(
                        &identity,
                        |_| panic!("invalid envelope must not reach verifier"),
                        || panic!("published corruption must not trigger regeneration")
                    )
                    .is_err()
            );
        }
        File::create(&path)
            .unwrap()
            .set_len(MAX_ARTIFACT_BYTES + 1)
            .unwrap();
        assert!(
            cache
                .prove_or_resume(
                    &identity,
                    |_| panic!("oversized envelope must not reach verifier"),
                    || panic!("must not hide oversized cache")
                )
                .is_err()
        );
    }
}
