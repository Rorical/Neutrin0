//! `[proving]` section: backend, budgets, scheduling policy and the prover
//! account.

use super::NodeRole;
use serde::Deserialize;

/// Backend used by every proof stage in this node.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProvingBackend {
    /// Local CPU proving, supported on all host platforms.
    #[default]
    Cpu,
    /// Local NVIDIA CUDA proving on Linux x86-64; requires the `cuda` feature.
    Cuda,
}

/// Local proof scheduling; never part of chain identity or execution context.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProvingPolicy {
    /// Seconds from the durable round start before other validators back up its leader.
    pub chunk_fallback_secs: u64,
    /// Let pending block proofs go first: the chunk proof start waits, for at
    /// most one slot after the certificate, while this node still has block
    /// proofs to produce.
    pub block_proof_priority: bool,
}

/// A 32-byte runtime address written as hexadecimal in the configuration.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(try_from = "String")]
pub struct HexAddress(pub [u8; 32]);

impl TryFrom<String> for HexAddress {
    type Error = crate::chain_spec::ChainSpecError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let address = crate::chain_spec::decode_hex_exact::<32>(&value, "proving.prover_address")?;
        // The runtime pays only runtime accounts; a receipt crediting any
        // other value is refused by every verifier.
        if !neutrin0_primitives::is_runtime_account(&address) {
            return Err(crate::chain_spec::ChainSpecError::Validation(
                "proving.prover_address must be a runtime account (twelve zero bytes, then the 20-byte address)"
                    .to_owned(),
            ));
        }
        Ok(Self(address))
    }
}

/// Selects the prover, global concurrency and block queue capacity.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProvingConfig {
    /// Shared backend for fact, evidence, block and chunk proofs.
    pub backend: ProvingBackend,
    /// CUDA device index (default 0). Invalid with the CPU backend.
    pub cuda_device: Option<u32>,
    /// Maximum simultaneous proving calls across all proof stages.
    pub concurrency: usize,
    /// Maximum queued plus running blocks, including restart recovery.
    pub capacity: usize,
    /// Delay Chunk proving from the durable BFT round start on every node
    /// but the next chunk's round-zero leader, which proves at once.
    pub chunk_proof_fallback_secs: u64,
    /// Prove candidates this node did not produce (design 08). Needs
    /// `execution.mode = "execute"` so the node holds every candidate's
    /// witness; a node without a proposer key then runs the proof loop
    /// alone. This also enables proactive Fact caching and fallback
    /// Chunk and Evidence proving on a non-validator.
    pub prove_foreign_blocks: bool,
    /// Prove blocks of the head branch whose proposer has published no
    /// receipt once its lease has passed (design 08), rebuilding their
    /// witness by execution. Unset proves them on a GPU backend only: a CPU
    /// prover cannot finish before the block goes stale.
    pub rescue_unproven_blocks: Option<bool>,
    /// Start a chunk proof only once this node has no block proof pending,
    /// waiting at most one slot after the certificate (default on). A running
    /// chunk proof cannot be preempted and takes minutes, while production
    /// waits on block proofs that take seconds.
    pub prioritize_block_proofs: bool,
    /// Runtime account credited for the block receipts this node proves
    /// (design 08), as 32 bytes of hex. Defaults to the validator's
    /// withdrawal credentials; with neither, a receipt credits its block's
    /// proposer.
    pub prover_address: Option<HexAddress>,
}

impl Default for ProvingConfig {
    fn default() -> Self {
        Self {
            backend: ProvingBackend::Cpu,
            cuda_device: None,
            concurrency: 2,
            capacity: 16,
            chunk_proof_fallback_secs: 180,
            prove_foreign_blocks: false,
            rescue_unproven_blocks: None,
            prioritize_block_proofs: true,
            prover_address: None,
        }
    }
}

impl ProvingConfig {
    /// Whether the role opts into generating proofs rather than only verifying them.
    pub(crate) const fn generates_proofs(self, role: NodeRole) -> bool {
        match role {
            NodeRole::Validator | NodeRole::Reporter => true,
            NodeRole::Full | NodeRole::Archive => self.prove_foreign_blocks,
            NodeRole::LightClient => false,
        }
    }

    /// Local scheduling policy; independent of all chain specification parameters.
    #[must_use]
    pub const fn scheduling_policy(self) -> ProvingPolicy {
        ProvingPolicy {
            chunk_fallback_secs: self.chunk_proof_fallback_secs,
            block_proof_priority: self.prioritize_block_proofs,
        }
    }

    /// Validate budgets and backend support before starting node services.
    ///
    /// # Errors
    /// Rejects invalid budgets, CPU device options and unavailable CUDA builds.
    pub const fn validate(self) -> Result<(), &'static str> {
        if self.chunk_proof_fallback_secs > 3600 {
            return Err("proving scheduling requires a bounded fallback <= 3600s");
        }
        if self.concurrency == 0
            || self.concurrency > 64
            || self.capacity < self.concurrency
            || self.capacity > 1024
        {
            return Err("proving requires 1..=64 workers and workers <= capacity <= 1024");
        }
        match self.backend {
            ProvingBackend::Cpu if self.cuda_device.is_some() => {
                Err("proving.cuda_device requires backend = cuda")
            }
            ProvingBackend::Cpu => Ok(()),
            ProvingBackend::Cuda if !cfg!(feature = "cuda") => {
                Err("CUDA requires building neutrin0-node with --features cuda")
            }
            ProvingBackend::Cuda => neutrin0_runtime_host::backend::ensure_cuda_available(),
        }
    }
}
