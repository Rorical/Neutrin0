//! Retained finalized consensus artifacts and durable local event replay.

mod artifacts;
mod events;

use neutrin0_consensus_engine::Engine;
use neutrin0_primitives::{Hash, blake3_256};
use neutrin0_proof_system::ProofSystem;
use neutrin0_rpc::{
    QueryError,
    types::{
        ArtifactIdJson, ArtifactInfoJson, ArtifactSliceJson, BytesHex, CertificateJson,
        ChainCursorJson, ChainEventPageJson, ChunkJson, HashHex,
    },
};
use neutrin0_storage::Database;

use super::{ChainBackend, rpc_queries::storage_error};
use artifacts::{Artifact, artifact, certificate, chunk, info};
use events::{cursor, cursor_rejection, event_json, status};

const MAX_SLICE_BYTES: u32 = 1024 * 1024;
const MAX_EVENT_PAGE: u32 = 256;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Enable or validate the durable journal before starting full-node workers.
    ///
    /// # Errors
    /// Refuses unsafe saved state, unavailable entropy or a failed durable initialization.
    pub fn initialize_chain_events(&self) -> Result<(), String> {
        self.with_engine_mut(|engine| {
            let mut stream_id = [0; 32];
            if engine
                .store()
                .chain_event_state()
                .map_err(|error| error.to_string())?
                .is_none()
            {
                getrandom::fill(&mut stream_id).map_err(|error| error.to_string())?;
            }
            let hash = engine.chain_spec_hash();
            let genesis = engine.chain_spec().genesis_block_hash;
            engine
                .store_mut()
                .initialize_chain_events(stream_id, hash, genesis)
                .map_err(|error| error.to_string())
        })
    }

    async fn consensus_query<R: Send + 'static>(
        &self,
        f: impl FnOnce(&Engine<DB>) -> Result<R, QueryError> + Send + 'static,
    ) -> Result<R, QueryError> {
        if self.is_light() {
            return Err(QueryError::StateUnavailable);
        }
        self.rpc_engine(f).await
    }
    pub(super) async fn query_chunk(
        &self,
        id: Option<u64>,
    ) -> Result<Option<ChunkJson>, QueryError> {
        self.consensus_query(move |engine| {
            let Some(id) = id.or_else(|| engine.latest_finalized_chunk_id()) else {
                return Ok(None);
            };
            let Some(chunk) = chunk(engine, id)? else {
                return Ok(None);
            };
            Ok(Some(ChunkJson::new(
                &chunk,
                engine
                    .store()
                    .get_chunk_proof(id)
                    .map_err(storage_error)?
                    .is_some(),
                engine
                    .store()
                    .get_finality_cert(id)
                    .map_err(storage_error)?
                    .is_some()
                    || engine
                        .store()
                        .historical_chunk(id)
                        .map_err(storage_error)?
                        .is_some(),
            )))
        })
        .await
    }
    pub(super) async fn query_certificate(
        &self,
        id: u64,
    ) -> Result<Option<CertificateJson>, QueryError> {
        self.consensus_query(move |engine| {
            let Some(cert) = certificate(engine, id)? else {
                return Ok(None);
            };
            let bytes = borsh::to_vec(&cert).map_err(storage_error)?;
            let artifact = info(
                ArtifactIdJson::Certificate { chunk: id },
                &Artifact {
                    bytes,
                    proof_bytes: 0,
                    public_values: None,
                },
            );
            let signers = |bits: &neutrin0_primitives::BitVec| {
                (0..bits.bit_len())
                    .filter(|index| bits.get(*index) == Some(true))
                    .collect()
            };
            Ok(Some(CertificateJson {
                chunk_id: id,
                chunk_hash: HashHex(cert.chunk_hash),
                round: cert.round,
                active_validator_set_root: HashHex(cert.active_validator_set_root),
                leader_index: cert.proposal.proposer_index,
                proposal: BytesHex(borsh::to_vec(&cert.proposal).map_err(storage_error)?),
                prevote_signers: signers(&cert.prevote.aggregation_bits),
                precommit_signers: signers(&cert.precommit.aggregation_bits),
                prevote_signature: BytesHex(cert.prevote.signature.to_vec()),
                precommit_signature: BytesHex(cert.precommit.signature.to_vec()),
                prevote_attestations: u32::try_from(cert.prevote_attestations.len())
                    .map_err(storage_error)?,
                precommit_attestations: u32::try_from(cert.precommit_attestations.len())
                    .map_err(storage_error)?,
                proof_manifests: cert
                    .proof_manifests
                    .iter()
                    .map(|manifest| manifest.proof_hashes.iter().copied().map(HashHex).collect())
                    .collect(),
                artifact,
            }))
        })
        .await
    }
    pub(super) async fn query_artifact(
        &self,
        id: ArtifactIdJson,
    ) -> Result<Option<ArtifactInfoJson>, QueryError> {
        self.consensus_query(move |engine| {
            Ok(artifact(engine, &id)?.map(|artifact| info(id, &artifact)))
        })
        .await
    }
    pub(super) async fn query_artifact_bytes(
        &self,
        id: ArtifactIdJson,
        expected: Hash,
        offset: u64,
        length: u32,
    ) -> Result<ArtifactSliceJson, QueryError> {
        if length == 0 || length > MAX_SLICE_BYTES {
            return Err(QueryError::InvalidRequest(
                "artifact slice length must be between 1 and 1048576".into(),
            ));
        }
        self.consensus_query(move |engine| {
            let artifact = artifact(engine, &id)?.ok_or(QueryError::ArtifactUnavailable)?;
            let hash = blake3_256(&artifact.bytes);
            if expected != hash {
                return Err(QueryError::ArtifactChanged);
            }
            let offset_index = usize::try_from(offset)
                .map_err(|_| QueryError::InvalidRequest("offset out of range".into()))?;
            if offset_index > artifact.bytes.len() {
                return Err(QueryError::InvalidRequest(
                    "offset exceeds envelope length".into(),
                ));
            }
            let end = offset_index
                .saturating_add(length as usize)
                .min(artifact.bytes.len());
            Ok(ArtifactSliceJson {
                artifact_hash: HashHex(hash),
                encoded_bytes: artifact.bytes.len() as u64,
                offset,
                bytes: BytesHex(artifact.bytes[offset_index..end].to_vec()),
            })
        })
        .await
    }
    pub(super) async fn query_chain_events(
        &self,
        after: Option<ChainCursorJson>,
        limit: u32,
    ) -> Result<ChainEventPageJson, QueryError> {
        if limit == 0 || limit > MAX_EVENT_PAGE {
            return Err(QueryError::InvalidRequest(
                "event page limit must be between 1 and 256".into(),
            ));
        }
        self.consensus_query(move |engine| {
            let store = engine.store();
            let state = store
                .chain_event_state()
                .map_err(storage_error)?
                .ok_or(QueryError::StateUnavailable)?;
            let status = status(&state);
            let after = after.unwrap_or_else(|| status.latest.clone());
            let sequence = after.sequence.parse::<u64>();
            if let Some(reason) = cursor_rejection(&after, &sequence, &status, &state) {
                return Err(QueryError::EventCursor {
                    reason: reason.into(),
                    status: Box::new(status),
                });
            }
            let sequence = sequence.expect("validated cursor");
            let end = sequence
                .saturating_add(u64::from(limit))
                .min(state.next - 1);
            let mut events = Vec::new();
            for sequence in sequence + 1..=end {
                let event = store
                    .chain_event(sequence)
                    .map_err(storage_error)?
                    .ok_or_else(|| storage_error("chain event journal has a gap"))?;
                events.push(event_json(&state, sequence, &event));
            }
            Ok(ChainEventPageJson {
                status,
                events,
                next: cursor(&state, end),
                has_more: end < state.next - 1,
            })
        })
        .await
    }
}
