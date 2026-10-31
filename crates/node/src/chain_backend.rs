//! Real [`SyncBackend`](neutrin0_sync::SyncBackend) backed by a [`ChainStore`](neutrin0_consensus_engine::ChainStore) + [`ProofSystem`].
//!
//! Read methods serve directly from the chain store; write methods route
//! through the engine's import paths ([`Engine::import_candidate_block`],
//! [`Engine::import_block_receipt`], [`Engine::import_proven_block`]) so
//! every imported artifact is validated before persistence and the engine's
//! in-memory head pointers stay consistent.
//!
//! The backend owns a bounded [`Mempool`] keyed by `Topic::Transactions`
//! gossip. The installed
//! [`BlockExecutor`](neutrin0_proof_system::BlockExecutor) runs each
//! candidate transaction's `validate_tx` against a snapshot of the live
//! state trie before admission; transactions that fail validation are
//! rejected with [`InsertError::RejectedByValidator`](neutrin0_mempool::InsertError::RejectedByValidator).
//!
//! When configured with [`ChainBackend::set_local_voter`] and a network
//! publisher via [`ChainBackend::set_network_publisher`], the backend
//! also drives the multi-validator chunk-BFT loop from
//! [`neutrin0_consensus_engine::bft_loop`]: opens a BFT session for
//! every newly proof-ready chunk, broadcasts the local validator's
//! signed votes, ingests peer votes, and triggers chunk finalization
//! after the configured precommit quorum and complete proof verification.
//! Followers execute imported blocks through the installed executor, verify
//! block proofs, and authenticate the full consensus boundary before proceeding.

mod availability;
mod bft_messages;
mod bft_session;
mod bft_votes;
mod block_admission;
mod block_proving;
mod bootstrap;
mod candidates;
#[cfg(test)]
mod canonical_progress_tests;
mod chunk_finality;
mod consensus_jobs;
mod consensus_queries;
#[cfg(test)]
mod consensus_query_tests;
mod engine_access;
mod engine_views;
mod evidence;
mod execution_claims;
mod facts;
mod follow;
mod fork_handoff;
mod history;
#[cfg(test)]
mod import_verdict_tests;
mod light;
mod local_control;
mod mempool_admission;
mod metrics_source;
mod p2p_queries;
mod pool_validation;
mod production;
mod programs;
mod publication;
mod raw_pool;
#[cfg(test)]
mod raw_pool_tests;
mod reporter;
mod rpc_queries;
mod slashing_intake;
mod snapshot_file;
mod state_sync;
#[cfg(test)]
mod state_sync_tests;
mod sync_backend;
mod transactions;
mod wiring;

pub use snapshot_file::SnapshotSummary;

use std::sync::{Arc, Mutex};

use neutrin0_consensus_engine::{BftQuorumIdentity, Engine, RetentionPolicy};
use neutrin0_consensus_types::{Chunk, FinalityVote};
use neutrin0_mempool::Mempool;
use neutrin0_network::service::NetworkCommand;
use neutrin0_primitives::{ChunkId, Hash, Height};
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::Database;
use neutrin0_sync::{SyncBackendError, SyncStatus};
use tokio::sync::mpsc;
use tracing::warn;

use raw_pool::SlashingPool;

/// Maximum bytes of ordinary transactions retained in the mempool.
const DEFAULT_MEMPOOL_CAPACITY_BYTES: usize = 256 * 1024;

/// Per-block budget for ordinary mempool transactions. Evidence receipts
/// have a separate bounded selection path.
const DEFAULT_BODY_TX_BUDGET_BYTES: usize = 256 * 1024;

/// Maximum number of slashing-evidence items the pool retains at any
/// time. Once exceeded, the oldest entry (FIFO) is evicted from
/// `Column::SlashingPool` and the in-memory key index. Sized to comfortably
/// cover even an adversarial network where every validator
/// equivocates every chunk: 1024 entries at ~16 KiB worst-case
/// gossip size caps durable retention; memory holds only their keys.
/// Verified receipts have a separate byte-bounded cache.
const SLASHING_POOL_MAX_ENTRIES: usize = 1024;

/// Fact pre-proving requests queued for one fact program.
type FactJobSender = mpsc::Sender<facts::FactJob>;

/// Map a local storage or encoding failure onto the sync error surface.
fn storage_error(error: impl core::fmt::Display) -> SyncBackendError {
    SyncBackendError::Storage(error.to_string())
}

/// Map an objectively invalid input onto the sync error surface.
fn rejected(error: impl core::fmt::Display) -> SyncBackendError {
    SyncBackendError::Rejected(error.to_string())
}

/// Map a dependency that is not locally available onto the sync error surface.
fn not_available(error: impl core::fmt::Display) -> SyncBackendError {
    SyncBackendError::NotAvailable(error.to_string())
}

/// Whether `engine` runs the reporter retention policy. An unreadable
/// retention record counts as another policy.
fn reporter_retention<DB: Database>(engine: &Engine<DB>) -> bool {
    engine
        .retention_info()
        .is_ok_and(|info| info.policy == RetentionPolicy::Reporter)
}

/// Inclusive height range covered by `chunk_id`, if representable.
fn chunk_height_range(chunk_id: ChunkId, chunk_size: u64) -> Option<(Height, Height)> {
    let end = chunk_id.checked_add(1)?.checked_mul(chunk_size)?;
    let start = chunk_id.checked_mul(chunk_size)?.checked_add(1)?;
    Some((start, end))
}

/// Whether `chunk` spans exactly its own height range and starts from the
/// authenticated pre-state and validator set of `context`.
fn chunk_matches_context(
    chunk: &Chunk,
    context: &neutrin0_prover_chunk::execution::ExecutionContext,
    chunk_size: u64,
) -> bool {
    chunk_height_range(chunk.chunk_id, chunk_size) == Some((chunk.start_height, chunk.end_height))
        && chunk.start_state_root == context.pre_state_root
        && chunk.active_validator_set_root
            == neutrin0_consensus_engine::validator_set_root(&context.active_validators)
}

/// Snapshot an optional shared slot, releasing its lock immediately.
fn cloned<T: Clone>(slot: &Mutex<Option<T>>) -> Option<T> {
    slot.lock().expect("ChainBackend slot poisoned").clone()
}

/// Transaction admissions that may run at once; each executes WASM
/// `validate_tx` on the blocking pool, and one more is refused as full.
const ADMISSION_SLOTS: usize = 4;

/// `SyncBackend` backed by a [`ChainStore`](neutrin0_consensus_engine::ChainStore) + a [`ProofSystem`].
///
/// Internally wraps an [`Engine`] behind a `std::sync::Mutex`. The mutex
/// is synchronous because all chain-store and proof-system operations are
/// themselves synchronous.
pub struct ChainBackend<DB: Database, P: ProofSystem> {
    engine: Arc<Mutex<Engine<DB>>>,
    /// Reads immutable records, such as block bodies, without the engine lock.
    reads: Arc<dyn neutrin0_storage::ReadHandle>,
    /// Serializes head publication with admission and subsequent pool reconciliation.
    /// Acquired before the engine lock; queries do not hold it across awaits.
    head_updates: Arc<Mutex<()>>,
    /// Shared copy of the engine's live state trie, reused while its root is
    /// unchanged. Lock order: `engine`, then `head_state`.
    head_state: Arc<pool_validation::HeadState>,
    /// Hash of the engine's immutable chain specification.
    chain_spec_hash: Hash,
    fact_jobs: Mutex<Option<FactJobSender>>,
    history: Arc<history::HistoryRuntime>,
    light: Mutex<Option<light::LightRuntime>>,
    /// Peer blocks are imported from receipts and diffs (design 07).
    proof_follow: std::sync::atomic::AtomicBool,
    /// Prove candidates this node did not produce (design 08); the executing
    /// mode retains every candidate's witness for it.
    prove_foreign_blocks: std::sync::atomic::AtomicBool,
    /// Prove head-branch blocks whose proposer has published no receipt.
    rescue_proofs: std::sync::atomic::AtomicBool,
    /// Receipts for blocks not held yet, kept for the orphan window.
    orphan_receipts: Mutex<follow::OrphanReceipts>,
    /// Rejected envelopes no retained vote names yet.
    pending_rejections: Mutex<availability::PendingRejections>,
    bootstrap: Arc<Mutex<Option<bootstrap::BootstrapRuntime>>>,
    reporter: Mutex<Option<reporter::ReporterRuntime>>,
    evidence_job_running: Arc<std::sync::atomic::AtomicBool>,
    evidence_job_cursor: std::sync::atomic::AtomicUsize,
    proof_system: Arc<P>,
    proving_budget: Arc<crate::proving_budget::ProvingBudget>,
    proving_policy: Mutex<crate::config::ProvingPolicy>,
    consensus_proof_task: Mutex<Option<ConsensusProofTask<P>>>,
    /// Serializes native certification preparation, including cancelled callers.
    certification_slot: Arc<tokio::sync::Semaphore>,
    /// Local candidate, signing and projection work cannot queue behind peers.
    consensus_preparation_slot: Arc<tokio::sync::Semaphore>,
    /// Expensive candidate advertisements served to remote callers.
    candidate_slot: Arc<tokio::sync::Semaphore>,
    /// Divergent candidates awaiting a proven claim (design 08).
    execution_claims: Arc<Mutex<Vec<execution_claims::PendingClaim>>>,
    consensus_proof_notify: Arc<tokio::sync::Notify>,
    last_candidate_notice: Mutex<Option<Hash>>,
    availability_verdicts: Mutex<availability::VerdictCache>,
    deferred_bft_votes: Mutex<Vec<FinalityVote>>,
    mempool: Arc<Mutex<Mempool>>,
    pool_validation: Arc<pool_validation::PoolValidation>,
    /// Channel used to publish gossip messages produced by the BFT
    /// loop (prevotes, precommits, chunk proofs, History endpoint announcements).
    /// `None` disables the BFT loop's broadcast side; the backend
    /// still ingests peer votes into the engine but emits no traffic.
    network_publisher: Mutex<Option<mpsc::Sender<NetworkCommand>>>,
    /// Live peer/sync summary published by the running [`neutrin0_sync::SyncDriver`].
    sync_status: Mutex<Option<SyncStatus>>,
    /// Proving counters and latencies exported by the metrics endpoint.
    metrics: Arc<crate::metrics::NodeMetrics>,
    rpc_metrics: Arc<neutrin0_rpc::metrics::RpcMetrics>,
    network_metrics: Mutex<Option<Arc<neutrin0_network::metrics::NetworkMetrics>>>,
    process_metrics: Mutex<crate::process_metrics::ProcessSampler>,
    /// Persistent raw reports awaiting independent EvidenceProof generation.
    slashing_pool: Mutex<SlashingPool>,
    /// Dynamic-runtime executor used by [`Self::try_produce_block`].
    /// `None` leaves the producer disabled (any production attempt
    /// surfaces [`ProductionError::Executor`](neutrin0_consensus_engine::ProductionError::Executor)); the node binary
    /// installs a [`neutrin0_runtime_host::WasmExecutor`] at
    /// startup. Tests that exercise gossip / BFT but not local
    /// production deliberately leave this unset.
    block_executor: Mutex<Option<Arc<dyn ErasedBlockExecutor>>>,
    /// Program-lane reassembly, persistence and publication (design 20).
    programs: Mutex<Arc<crate::programs::ProgramStore>>,
    /// One installation attempt owns target caches; newer manifests may replace
    /// pending authority but cannot start another installer before it finishes.
    bootstrap_install: tokio::sync::Mutex<()>,
    /// Serializes retention decisions with authenticated bootstrap pin changes.
    program_lifecycle: Mutex<()>,
    /// Counted source/warm identities owned by overlapping bootstrap attempts.
    bootstrap_program_pins: Arc<
        Mutex<
            std::collections::BTreeMap<
                neutrin0_proof_system::artifacts::ArtifactIdentity,
                (usize, usize),
            >,
        >,
    >,
    /// Guards concurrent Guest installations, which run SP1 setup.
    installing_programs: Arc<std::sync::atomic::AtomicBool>,
    /// Content hashes governance named at the last program sync; served to
    /// the status RPC so an unauthenticated call never runs a runtime query.
    wanted_programs: Mutex<Vec<Hash>>,
    /// Program set of the enacted, not yet activated switch at the last
    /// program sync, for readiness reporting.
    scheduled_programs: Mutex<Option<neutrin0_primitives::ProgramSet>>,
    /// The data filesystem is below its free-space quota; set by the storage guard.
    storage_pressure: Arc<std::sync::atomic::AtomicBool>,
    /// The doppelganger pause was logged.
    doppelganger_reported: std::sync::atomic::AtomicBool,
    /// This node's libp2p identity, once the network service is built.
    local_peer_id: Mutex<Option<String>>,
    /// Blocking RPC reads and WASM queries (calls, gas estimates, pending views)
    /// running at once: half the available cores, leaving capacity for import
    /// and BFT. A running worker keeps its slot after a caller times out.
    query_slots: Arc<tokio::sync::Semaphore>,
    /// Distinct receipt bytes each block may still have verified.
    receipt_budget:
        Mutex<follow::ReceiptBudget<(neutrin0_network::PeerId, neutrin0_primitives::BlockHash)>>,
    /// Distinct alternative proof bytes each finalized chunk may have verified.
    chunk_proof_budget: Mutex<follow::ReceiptBudget<(neutrin0_network::PeerId, u64)>>,
    /// Transaction admissions (RPC and gossip) running WASM at once.
    admission_slots: Arc<tokio::sync::Semaphore>,
    /// The program artifact being fetched from peers, if any.
    program_fetch: Mutex<Option<programs::ProgramFetch>>,
    /// Runner ownership for workers that would otherwise outlive its task.
    background_tasks: Mutex<Option<crate::supervision::TaskSpawner>>,
}

type ConsensusProofTask<P> = (
    BftQuorumIdentity,
    tokio::sync::oneshot::Receiver<
        Result<
            (
                neutrin0_prover_chunk::consensus::ConsensusWitness,
                <P as ProofSystem>::ChunkProof,
            ),
            neutrin0_proof_system::ProofError,
        >,
    >,
);

/// What remains to do with submitted slashing evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EvidenceDisposition {
    /// The persistent pool holds it.
    Held,
    /// A successful read shows this node can never pool it: its offender is
    /// tombstoned or, on a reporter, untracked or unresolvable because its
    /// chunk's record is pruned for good.
    Unpoolable,
    /// Not yet determined; submit again later.
    Retry,
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Wrap an already-initialised [`Engine`].
    ///
    /// [`Column::SlashingPool`](neutrin0_storage::Column::SlashingPool) rows persisted by a
    /// prior node session stay pooled, so locally-detected
    /// equivocation survives a restart. The in-memory key index is
    /// rebuilt from the column on first use, in key order; the
    /// original FIFO order is not preserved across restart, which
    /// is semantically fine because slashing outcomes do not depend
    /// on the order evidence is observed.
    pub fn new(mut engine: Engine<DB>, proof_system: P) -> Self {
        match proof_system.programs() {
            Some(programs) if engine.set_programs(programs) => {}
            Some(_) => warn!(
                "proof backend chunk Guest differs from the specification's pin; chunk consensus is disabled"
            ),
            None => warn!("proof backend reports no Guest identities; chunk consensus is disabled"),
        }
        let metrics = Arc::new(crate::metrics::NodeMetrics::default());
        // The engine never replaces its chain specification after construction.
        let chain_spec_hash = engine.chain_spec().hash();
        let submission_device = proof_system.submission_device();
        let native_admission = proof_system.native_submission_admission();
        let reads = engine.store().db().read_handle();
        Self {
            reads,
            engine: Arc::new(Mutex::new(engine)),
            head_updates: Arc::new(Mutex::new(())),
            head_state: Arc::default(),
            chain_spec_hash,
            fact_jobs: Mutex::new(None),
            history: Arc::new(history::HistoryRuntime::default()),
            light: Mutex::new(None),
            proof_follow: std::sync::atomic::AtomicBool::new(false),
            prove_foreign_blocks: std::sync::atomic::AtomicBool::new(false),
            rescue_proofs: std::sync::atomic::AtomicBool::new(false),
            orphan_receipts: Mutex::default(),
            pending_rejections: Mutex::default(),
            bootstrap: Arc::new(Mutex::new(None)),
            reporter: Mutex::new(None),
            evidence_job_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            evidence_job_cursor: std::sync::atomic::AtomicUsize::new(0),
            proof_system: Arc::new(proof_system),
            proving_budget: Arc::new(crate::proving_budget::ProvingBudget::with_backend(
                2,
                Arc::clone(&metrics),
                submission_device,
                native_admission,
            )),
            proving_policy: Mutex::new(crate::config::ProvingPolicy::default()),
            consensus_proof_task: Mutex::new(None),
            certification_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            consensus_preparation_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            candidate_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            execution_claims: Arc::new(Mutex::new(Vec::new())),
            consensus_proof_notify: Arc::new(tokio::sync::Notify::new()),
            last_candidate_notice: Mutex::new(None),
            availability_verdicts: Mutex::default(),
            deferred_bft_votes: Mutex::new(Vec::new()),
            mempool: Arc::new(Mutex::new(Mempool::with_account_limits(
                DEFAULT_MEMPOOL_CAPACITY_BYTES,
                DEFAULT_MEMPOOL_CAPACITY_BYTES / 4,
                32,
            ))),
            pool_validation: Arc::default(),
            network_publisher: Mutex::new(None),
            sync_status: Mutex::new(None),
            metrics,
            rpc_metrics: Arc::default(),
            network_metrics: Mutex::new(None),
            process_metrics: Mutex::default(),
            slashing_pool: Mutex::default(),
            block_executor: Mutex::new(None),
            programs: Mutex::new(Arc::new(crate::programs::ProgramStore::in_memory())),
            bootstrap_install: tokio::sync::Mutex::new(()),
            program_lifecycle: Mutex::new(()),
            bootstrap_program_pins: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            installing_programs: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            wanted_programs: Mutex::new(Vec::new()),
            scheduled_programs: Mutex::new(None),
            storage_pressure: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            doppelganger_reported: std::sync::atomic::AtomicBool::new(false),
            local_peer_id: Mutex::new(None),
            query_slots: Arc::new(tokio::sync::Semaphore::new(
                std::thread::available_parallelism().map_or(1, |cores| cores.get().div_ceil(2)),
            )),
            admission_slots: Arc::new(tokio::sync::Semaphore::new(ADMISSION_SLOTS)),
            receipt_budget: Mutex::new(follow::ReceiptBudget::default()),
            chunk_proof_budget: Mutex::new(follow::ReceiptBudget::default()),
            program_fetch: Mutex::new(None),
            background_tasks: Mutex::new(None),
        }
    }
}
