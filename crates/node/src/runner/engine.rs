//! Opening the node database, the consensus engine and the SP1 proof system.

use neutrin0_consensus_engine::Engine;
use neutrin0_primitives::ChainSpec;
use neutrin0_runtime_host::{ProgramProver, Sp1HostError, Sp1ProofSystem};
use neutrin0_storage::Database;
use tracing::info;

use super::NodeError;
use crate::chain_spec::{ChainSpecError, ChainSpecFile, GenesisPrograms};
use crate::config::NodeConfig;
use crate::db::NodeDb;

pub(super) fn open_node_db(config: &NodeConfig) -> Result<NodeDb, NodeError> {
    let Some(path) = &config.data_dir else {
        info!(
            backend = "memory",
            "no data_dir configured; using in-memory backend"
        );
        return Ok(NodeDb::memory());
    };
    std::fs::create_dir_all(path).map_err(|source| NodeError::DataDir {
        path: path.display().to_string(),
        source,
    })?;
    info!(backend = "rocksdb", path = %path.display(), "opened persistent data directory");
    Ok(NodeDb::open_rocks(path)?)
}

/// Open or initialise the engine on a blocking thread.
pub(super) async fn open_engine(
    db: NodeDb,
    chain_spec: ChainSpec,
    spec_file: ChainSpecFile,
    genesis_package: neutrin0_runtime_host::package::RuntimePackage,
) -> Result<Engine<NodeDb>, NodeError> {
    tokio::task::spawn_blocking(move || {
        open_or_initialise_engine(db, chain_spec, &spec_file, &genesis_package)
    })
    .await
    .map_err(|error| NodeError::Engine(format!("engine setup task failed: {error}")))?
}

/// SP1's blocking prover clients drive their own runtime while they
/// initialise, which must not happen on an async worker thread.
pub(super) async fn build_proof_system<P: ProgramProver + Send + Sync + 'static>(
    genesis_programs: GenesisPrograms,
    build_prover: impl FnOnce() -> Result<P, Sp1HostError> + Send + 'static,
) -> Result<Sp1ProofSystem<P>, NodeError> {
    tokio::task::spawn_blocking(move || {
        let prover = build_prover()?;
        genesis_programs.proof_system(prover)
    })
    .await
    .map_err(|error| NodeError::ProofSystem(format!("prover setup task failed: {error}")))?
    .map_err(|error| NodeError::ProofSystem(error.to_string()))
}

/// Decode the light client's locally trusted checkpoint file. Peers never
/// supply this anchor; the read is bounded before any byte is decoded.
pub(super) fn load_trusted_checkpoint(
    path: &std::path::Path,
) -> Result<neutrin0_consensus_types::history_proof::Checkpoint, NodeError> {
    let Some(bytes) = crate::config::read_trusted_checkpoint(path)? else {
        return Err(NodeError::ProofSystem(
            "trusted checkpoint exceeds size limit".into(),
        ));
    };
    borsh::from_slice(&bytes)
        .map_err(|error| NodeError::ProofSystem(format!("trusted checkpoint: {error}")))
}

fn open_or_initialise_engine(
    db: NodeDb,
    chain_spec: ChainSpec,
    spec_file: &ChainSpecFile,
    package: &neutrin0_runtime_host::package::RuntimePackage,
) -> Result<Engine<NodeDb>, NodeError> {
    let already_initialised = db
        .get(
            neutrin0_storage::Column::Meta,
            neutrin0_consensus_engine::pointers::CHAIN_SPEC_HASH,
        )
        .map_err(NodeError::Storage)?
        .is_some();
    if already_initialised {
        let engine =
            Engine::open(chain_spec, db).map_err(|err| NodeError::Engine(err.to_string()))?;
        info!(
            head_height = engine.head_height(),
            finalized_chunks = engine.finalized_next_chunk_id(),
            "engine resumed from persistent state"
        );
        Ok(engine)
    } else if chain_spec.fork.is_some() {
        // A fork's successor starts at its pinned start, installed from the
        // predecessor's endpoint snapshot (`[bootstrap] snapshot_path`) or a
        // peer, never from genesis.
        let engine =
            Engine::genesis(chain_spec, db).map_err(|err| NodeError::Engine(err.to_string()))?;
        info!("engine initialised for a hard fork; awaiting its start state");
        Ok(engine)
    } else {
        let genesis = crate::genesis::build_genesis_state_with(spec_file, package)?;
        let expected_programs = neutrin0_primitives::ProgramSet {
            runtime_code_hash: chain_spec.runtime_code_hash,
            execution: chain_spec.genesis_execution,
        };
        if genesis.programs != expected_programs || genesis.root != chain_spec.genesis_state_root {
            return Err(NodeError::ChainSpec(ChainSpecError::Validation(
                "runtime genesis changed after chain specification derivation".to_owned(),
            )));
        }
        // Every node derives the same allocation from the same spec file;
        // the chain spec hash already binds its root. One durable batch holds
        // it with every genesis pointer, so a failed first start retries.
        let engine = Engine::genesis_with_state(chain_spec, db, &genesis.trie)
            .map_err(|err| NodeError::Engine(err.to_string()))?;
        info!(
            accounts = genesis.accounts,
            staked_validators = genesis.staked_validators,
            "engine initialised at genesis"
        );
        Ok(engine)
    }
}
