//! Finalized chunks, certificates and proof envelopes checked against each other.

use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_types::{Chunk, FinalityCert, evidence::commitment};
use neutrin0_primitives::blake3_256;
use neutrin0_rpc::{
    QueryError,
    types::{ArtifactIdJson, ArtifactInfoJson, BytesHex, HashHex},
};
use neutrin0_storage::Database;

use super::super::rpc_queries::{ensure_payload_height, storage_error};

fn unavailable<DB: Database>(engine: &Engine<DB>, id: u64) -> QueryError
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    match engine.retention_info() {
        Ok(retention) if id < retention.pruned_before_chunk => QueryError::Pruned {
            retained_from_chunk: retention.pruned_before_chunk,
            retained_from_height: retention.first_retained_height,
        },
        Ok(_) => QueryError::ArtifactUnavailable,
        Err(error) => storage_error(error),
    }
}
pub(super) fn chunk<DB: Database>(engine: &Engine<DB>, id: u64) -> Result<Option<Chunk>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    if id >= engine.finalized_next_chunk_id() {
        return Ok(None);
    }
    let store = engine.store();
    let chunk = store
        .get_chunk(id)
        .map_err(storage_error)?
        .or(store
            .historical_chunk(id)
            .map_err(storage_error)?
            .map(|record| record.chunk))
        .ok_or_else(|| unavailable(engine, id))?;
    if chunk.chunk_id != id {
        return Err(storage_error("chunk storage index mismatch"));
    }
    if let Some(statement) = store.chunk_statement(id).map_err(storage_error)?
        && neutrin0_prover_chunk::consensus::as_chunk(&statement.chunk) != chunk
    {
        return Err(storage_error("chunk disagrees with finalized statement"));
    }
    Ok(Some(chunk))
}
pub(super) fn certificate<DB: Database>(
    engine: &Engine<DB>,
    id: u64,
) -> Result<Option<FinalityCert>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let Some(chunk) = chunk(engine, id)? else {
        return Ok(None);
    };
    let store = engine.store();
    let cert = store
        .get_finality_cert(id)
        .map_err(storage_error)?
        .or(store
            .historical_chunk(id)
            .map_err(storage_error)?
            .map(|record| record.finality))
        .ok_or_else(|| unavailable(engine, id))?;
    if cert.chunk_id != id
        || cert.chunk_hash != chunk.hash()
        || cert.proposal.chunk != chunk
        || cert.proposal.round != cert.round
        || cert.active_validator_set_root != chunk.active_validator_set_root
    {
        return Err(storage_error("certificate disagrees with finalized chunk"));
    }
    if store
        .chunk_statement(id)
        .map_err(storage_error)?
        .is_some_and(|statement| statement.finality_cert_hash != commitment(&cert))
    {
        return Err(storage_error(
            "certificate commitment differs from finalized statement",
        ));
    }
    Ok(Some(cert))
}

pub(super) struct Artifact {
    pub(super) bytes: Vec<u8>,
    pub(super) proof_bytes: u64,
    pub(super) public_values: Option<BytesHex>,
}
pub(super) fn artifact<DB: Database>(
    engine: &Engine<DB>,
    id: &ArtifactIdJson,
) -> Result<Option<Artifact>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    match id {
        ArtifactIdJson::Certificate { chunk: id } => certificate_artifact(engine, *id),
        ArtifactIdJson::ChunkProof { chunk: id } => chunk_proof_artifact(engine, *id),
        ArtifactIdJson::BlockProof { block } => block_proof_artifact(engine, block.0),
    }
}
fn certificate_artifact<DB: Database>(
    engine: &Engine<DB>,
    id: u64,
) -> Result<Option<Artifact>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    certificate(engine, id)?
        .map(|cert| {
            Ok(Artifact {
                bytes: borsh::to_vec(&cert).map_err(storage_error)?,
                proof_bytes: 0,
                public_values: None,
            })
        })
        .transpose()
}
fn chunk_proof_artifact<DB: Database>(
    engine: &Engine<DB>,
    id: u64,
) -> Result<Option<Artifact>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let store = engine.store();
    let Some(chunk) = chunk(engine, id)? else {
        return Ok(None);
    };
    let proof = store
        .get_chunk_proof(id)
        .map_err(storage_error)?
        .ok_or_else(|| unavailable(engine, id))?;
    let cert = certificate(engine, id)?.ok_or(QueryError::ArtifactUnavailable)?;
    if proof.chunk_id != id
        || proof.chunk_hash != chunk.hash()
        || proof.finality_cert != cert
        || neutrin0_prover_chunk::consensus::as_chunk(&proof.public_inputs) != chunk
    {
        return Err(storage_error(
            "chunk proof disagrees with finalized objects",
        ));
    }
    let values = store
        .chunk_statement(id)
        .map_err(storage_error)?
        .ok_or(QueryError::ArtifactUnavailable)?;
    Ok(Some(Artifact {
        bytes: borsh::to_vec(&proof).map_err(storage_error)?,
        proof_bytes: proof.proof_bytes.len() as u64,
        public_values: Some(BytesHex(borsh::to_vec(&values).map_err(storage_error)?)),
    }))
}
fn block_proof_artifact<DB: Database>(
    engine: &Engine<DB>,
    block_hash: neutrin0_primitives::BlockHash,
) -> Result<Option<Artifact>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let store = engine.store();
    let Some(header) = store.get_header(&block_hash).map_err(storage_error)? else {
        return Ok(None);
    };
    if header.hash() != block_hash {
        return Err(storage_error("block proof header hash mismatch"));
    }
    ensure_payload_height(engine, header.height)?;
    let proof = store
        .get_block_proof(&block_hash)
        .map_err(storage_error)?
        .ok_or(QueryError::ArtifactUnavailable)?;
    if proof.block_hash != block_hash
        || proof.height != header.height
        || proof.public_inputs.block_hash != block_hash
        || proof.public_inputs.height != header.height
        || proof.public_inputs.state_root_after != header.state_root
        || proof.public_inputs.parent_block_hash != header.parent_hash
        || proof.public_inputs.chain_id != engine.chain_spec().chain_id
        || proof.public_inputs.transactions_root != header.transactions_root
        || proof.public_inputs.receipt_root != header.receipts_root
        || proof.public_inputs.da_root != header.da_root
        || proof.public_inputs.runtime_extra != header.runtime_extra
        || proof.public_inputs.gas_used != header.gas_used
        || proof.public_inputs.gas_limit != header.gas_limit
    {
        return Err(storage_error("block proof disagrees with stored header"));
    }
    Ok(Some(Artifact {
        bytes: borsh::to_vec(&proof).map_err(storage_error)?,
        proof_bytes: proof.proof_bytes.len() as u64,
        public_values: Some(BytesHex(
            borsh::to_vec(&proof.public_inputs).map_err(storage_error)?,
        )),
    }))
}
pub(super) fn info(id: ArtifactIdJson, artifact: &Artifact) -> ArtifactInfoJson {
    ArtifactInfoJson {
        id,
        artifact_hash: HashHex(blake3_256(&artifact.bytes)),
        encoded_bytes: artifact.bytes.len() as u64,
        proof_bytes: artifact.proof_bytes,
        public_values: artifact.public_values.clone(),
    }
}
