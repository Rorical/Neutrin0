//! SP1-backed implementation of the [`ProofSystem`] trait used by the
//! consensus engine.
//!
//! [`Sp1ProofSystem::prove_block`] decodes the borsh-encoded
//! persisted input, state witness and evidence attachments the producer hands off,
//! pre-validates every cross-checked field of
//! [`BlockProofPublicInputs`] (`chain_id`, `height`, `block_gas_limit`,
//! `proposer_address`, `pre_state_root`) against the SP1
//! input, drives the configured SP1 CPU/CUDA prover (mock in tests),
//! and cross-checks the committed [`RuntimeBlockOutput`]
//! (`pre_state_root`, `post_state_root`, `gas_used`, `receipts_root`)
//! against the same `BlockProofPublicInputs` before returning the
//! wire proof.
//!
//! [`Sp1ProofSystem::verify_block`] runs the real SP1 verifier
//! against the embedded verifying key and re-runs every output-side
//! cross-check so a malicious prover cannot lie about `gas_used`,
//! `receipts_root`, or either state root and have the engine accept
//! the proof.
//!
//! Complete chunk proving recursively verifies blocks and commits guest-checked
//! execution and consensus transitions. Each chunk receipt recursively
//! verifies the previous one, so the latest is the chain's History proof.
//!
//! [`ProofSystem`]: neutrin0_proof_system::ProofSystem
//! [`Sp1ProofSystem::prove_block`]: neutrin0_proof_system::ProofSystem::prove_block
//! [`Sp1ProofSystem::verify_block`]: neutrin0_proof_system::ProofSystem::verify_block
//! [`BlockProofPublicInputs`]: neutrin0_consensus_types::BlockProofPublicInputs
//! [`RuntimeBlockOutput`]: neutrin0_runtime_abi::RuntimeBlockOutput

use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofError;
use neutrin0_proof_system::artifacts::{ArtifactIdentity, ProgramArtifactLoader};
use sp1_sdk::blocking::{MockProver, Prover, ProverClient};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
};

use neutrin0_consensus_types::history_proof::{GuestPrograms, VkDigest};

use crate::bounded_cache::BoundedCache;
use crate::programs::{ProgramKeys, SharedRegistry};
use crate::{ProgramProver, Sp1HostError};

mod adapter;
mod block;
mod chunk;
mod guests;
mod wire;

pub use wire::{Sp1BlockProof, Sp1ChunkProof};

use block::VerifiedBlock;
use neutrin0_runtime_abi::BlockReceiptStatement;

/// Most verified block receipts kept for exact-byte reuse.
const BLOCK_CACHE_ENTRIES: usize = 64;

/// Encoded-size budget of the verified block receipt cache.
const BLOCK_CACHE_BYTES: usize = 32 * 1024 * 1024;

/// Most block receipt verdicts kept. A verdict holds only the committed
/// statement, so it covers several chunks of receipts where the bundle cache
/// holds part of one: preparing a chunk never repeats a STARK check.
const BLOCK_VERDICT_ENTRIES: usize = 4096;

/// Encoded-size budget of the block receipt verdicts.
const BLOCK_VERDICT_BYTES: usize = 16 * 1024 * 1024;

/// Most chunk proof verdicts kept: accepted (proof bytes, statement) pairs
/// and rejected proof bytes, enough for every alternative proof the
/// retained chunks may receive.
const CHUNK_VERDICT_ENTRIES: usize = 1024;

/// Adapter that drives an SP1 prover (mock, cpu, cuda, ...) through the
/// consensus engine's [`ProofSystem`] trait.
///
/// The verifying key is captured at construction time. Verification
/// uses the trait's `verify` method which honours the SP1 status code
/// (a non-zero exit code from the guest causes `verify_proof` to
/// reject the proof).
///
/// [`ProofSystem`]: neutrin0_proof_system::ProofSystem
pub struct Sp1ProofSystem<P: Prover> {
    /// Underlying prover (mock, cpu, cuda, ...).
    pub(super) prover: P,
    /// Digests of the four Guests compiled into this binary.
    pub(super) embedded: GuestPrograms,
    /// Every Guest this backend holds keys for: the embedded four plus any
    /// installed from on-chain artifacts (design 20).
    pub(super) programs: SharedRegistry<P>,
    /// Verified fact receipts per fact program.
    pub(super) facts: Mutex<BTreeMap<VkDigest, super::fact_cache::FactCache>>,
    /// Coherent unique-request coverage of the latest successful chunk proof.
    pub(super) last_fact_coverage: Mutex<Option<(u64, u64)>>,
    /// Serializes cache misses across early and evidence workers. Never an engine lock.
    pub(super) fact_proving: Mutex<()>,
    /// Single-flight installation; no registry or consensus lock is held at setup.
    program_setup: Mutex<()>,
    artifact_loader: RwLock<Option<ProgramArtifactLoader>>,
    retained_sources: RwLock<std::collections::BTreeSet<ArtifactIdentity>>,
    /// Exact-byte cache of verified block receipts, keyed by the block
    /// program each was verified under and the receipt bytes' hash.
    blocks: Mutex<BoundedCache<(VkDigest, Hash), VerifiedBlock>>,
    /// Statements of receipts verified under the same keys, kept after
    /// their bundles leave `blocks`.
    block_verdicts: Mutex<BoundedCache<(VkDigest, Hash), BlockReceiptStatement>>,
    /// Receipts whose STARK failed under a program. The public values are
    /// checked first, so that failure holds for any header: the same bytes
    /// are refused again without another verification.
    block_rejections: Mutex<BoundedCache<(VkDigest, Hash), ProofError>>,
    /// Chunk proofs verified under the embedded chunk Guest, keyed by the
    /// proof bytes' hash and the statement key they were checked against.
    chunk_verdicts: Mutex<BoundedCache<(Hash, Hash), ()>>,
    /// Chunk proof bytes whose STARK failed after their public values
    /// matched, which holds for any expected statement.
    chunk_rejections: Mutex<BoundedCache<Hash, ProofError>>,
}

impl<P> Sp1ProofSystem<P>
where
    P: ProgramProver,
{
    /// Build with an existing prover handle.  Disk-caches the
    /// block verifying key; also initializes the evidence and fact programs.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if `setup` fails for any ELF.
    pub fn new(prover: P) -> Result<Self, Sp1HostError> {
        Self::with_execution(
            prover,
            crate::FACT_GUEST_ELF.clone(),
            crate::EVIDENCE_GUEST_ELF.clone(),
            crate::EVM_GUEST_ELF.clone(),
            crate::CONSENSUS_CHUNK_GUEST_ELF.clone(),
        )
    }

    /// Construct the backend from a chain's starting programs: the execution
    /// Guests and the chunk Guest, embedded or fetched, whose keys are derived
    /// here locally. The chain specification pins which keys they must be.
    /// # Errors
    /// Reports invalid ELFs or failed local SP1 key derivation.
    pub fn with_execution(
        prover: P,
        fact: sp1_sdk::Elf,
        evidence: sp1_sdk::Elf,
        block: sp1_sdk::Elf,
        chunk: sp1_sdk::Elf,
    ) -> Result<Self, Sp1HostError> {
        let mut registry = crate::programs::Registry::default();
        let block = registry.install(&prover, block)?;
        let evidence = registry.install(&prover, evidence)?;
        let fact = registry.install(&prover, fact)?;
        let chunk = registry.install(&prover, chunk)?;
        Ok(Self {
            prover,
            embedded: GuestPrograms {
                execution: neutrin0_consensus_types::history_proof::ExecutionPrograms {
                    fact,
                    evidence,
                    block,
                },
                chunk,
            },
            programs: SharedRegistry::new(registry),
            facts: Mutex::new(BTreeMap::new()),
            last_fact_coverage: Mutex::new(None),
            fact_proving: Mutex::new(()),
            program_setup: Mutex::new(()),
            artifact_loader: RwLock::new(None),
            retained_sources: RwLock::new(std::collections::BTreeSet::new()),
            blocks: Mutex::new(BoundedCache::new(BLOCK_CACHE_ENTRIES, BLOCK_CACHE_BYTES)),
            block_verdicts: Mutex::new(BoundedCache::new(
                BLOCK_VERDICT_ENTRIES,
                BLOCK_VERDICT_BYTES,
            )),
            block_rejections: Mutex::new(BoundedCache::new(
                BLOCK_VERDICT_ENTRIES,
                BLOCK_VERDICT_ENTRIES,
            )),
            chunk_verdicts: Mutex::new(BoundedCache::new(
                CHUNK_VERDICT_ENTRIES,
                CHUNK_VERDICT_ENTRIES,
            )),
            chunk_rejections: Mutex::new(BoundedCache::new(
                CHUNK_VERDICT_ENTRIES,
                CHUNK_VERDICT_ENTRIES,
            )),
        })
    }

    /// Keys of an installed Guest, or `Unsupported`.
    pub(super) fn keys(&self, digest: &VkDigest) -> Result<Arc<ProgramKeys<P>>, ProofError> {
        crate::programs::keys(&self.programs, digest)
    }

    /// Run `f` against the fact cache of one fact program, loading it first.
    pub(super) fn with_fact_cache<R>(
        &self,
        fact_program: &VkDigest,
        f: impl FnOnce(&mut super::fact_cache::FactCache) -> R,
    ) -> Result<R, ProofError> {
        if *fact_program != self.embedded.execution.fact {
            return Err(ProofError::PublicInputMismatch);
        }
        let keys = self.keys(fact_program)?;
        let mut caches = self.facts.lock().map_err(|_| ProofError::BackendRejected)?;
        let result = f(caches
            .entry(*fact_program)
            .or_insert_with(|| super::fact_cache::FactCache::load(&keys.vk)));
        drop(caches);
        Ok(result)
    }
}

impl Sp1ProofSystem<MockProver> {
    /// Convenience: build with a [`MockProver`] for fast tests where
    /// the cryptographic check is skipped but the public-output
    /// cross-check still runs.
    ///
    /// # Errors
    /// See [`Self::new`].
    pub fn mock() -> Result<Self, Sp1HostError> {
        Self::new(ProverClient::builder().mock().build())
    }
}

fn attached_fact_coverage(
    requested: &std::collections::BTreeSet<neutrin0_primitives::Hash>,
    attached: &[neutrin0_prover_chunk::facts::FactStatement],
) -> (u64, u64) {
    let answered: std::collections::BTreeSet<_> = attached
        .iter()
        .flat_map(|statement| &statement.facts)
        .filter(|fact| fact.valid && requested.contains(&fact.id))
        .map(|fact| fact.id)
        .collect();
    (
        u64::try_from(answered.len()).unwrap_or(u64::MAX),
        u64::try_from(requested.len()).unwrap_or(u64::MAX),
    )
}

fn publish_successful_coverage<T>(
    state: &Mutex<Option<(u64, u64)>>,
    coverage: (u64, u64),
    result: &Result<T, ProofError>,
) {
    if result.is_ok() {
        *state.lock().expect("fact coverage mutex") = Some(coverage);
    }
}

#[cfg(test)]
mod coverage_tests;
