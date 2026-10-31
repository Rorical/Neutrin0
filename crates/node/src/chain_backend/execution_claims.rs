//! Invalid execution claims (design 08): a candidate whose correct execution
//! contradicts its header is re-executed, the honest execution is proven, and
//! the claim is reported once the header's chunk is finalized. A node that
//! cannot execute keeps the claim a received receipt supports when that
//! receipt verifies under the header's inputs but commits other results. An unproven
//! claim lives in memory with its witness. A proven claim is persisted as its
//! evidence in the node-local metadata column, so it survives restart until
//! it is pooled: safety offences have no age limit.

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // Fixture heights are below 256.
mod tests;

use super::{ChainBackend, rejected};
use neutrin0_consensus_engine::execution_claims::DivergentExecution;
use neutrin0_consensus_types::{Block, BlockProof, SlashingEvidence};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::{Batch, Column, Database};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Most unproven divergent candidates held in memory at once.
const MAX_PENDING_CLAIMS: usize = 16;
/// Most proven claims persisted while they wait for their chunk.
const MAX_PERSISTED_CLAIMS: usize = 64;
/// Metadata key prefix of a persisted proven claim, followed by the header hash.
const CLAIM_PREFIX: &[u8] = b"execution-claim:";

fn claim_key(header_hash: &Hash) -> Vec<u8> {
    [CLAIM_PREFIX, header_hash.as_slice()].concat()
}

/// A divergent candidate awaiting its honest execution proof.
pub(super) struct PendingClaim {
    divergent: DivergentExecution,
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Examine a candidate that failed import on its results and, when its
    /// honest execution contradicts the header, prove that execution.
    pub(super) fn record_divergent_candidate(&self, block: &Block) {
        if !self.proves_evidence() {
            return;
        }
        let Some(executor) = self.replay_executor_snapshot() else {
            return;
        };
        let Some(divergent) = self.divergent_execution_of(block, executor.as_ref()) else {
            return;
        };
        let key = claim_key(&divergent.header.hash());
        if self.claim_already_persisted(&key) {
            return;
        }
        if !self.enqueue_pending_claim(&divergent) {
            return;
        }
        let Ok(prover_address) = self.with_engine(|engine| {
            engine
                .prover_address()
                .or(Ok::<_, ()>(divergent.public_inputs.proposer_address))
        }) else {
            return;
        };
        self.spawn_claim_proof(divergent, prover_address);
    }

    /// Re-execute `block` honestly; `None` when it agrees with its header or
    /// cannot be executed here.
    fn divergent_execution_of(
        &self,
        block: &Block,
        executor: &dyn ErasedBlockExecutor,
    ) -> Option<DivergentExecution> {
        match self.with_engine(|engine| {
            engine
                .divergent_execution(block, executor)
                .map_err(rejected)
        }) {
            Ok(Some(divergent)) => Some(divergent),
            Ok(None) => None,
            Err(error) => {
                debug!(%error, "divergent candidate could not be re-executed");
                None
            }
        }
    }

    /// Whether a proven claim is already persisted under `key`; an unreadable
    /// column counts as persisted so nothing is proven twice.
    fn claim_already_persisted(&self, key: &[u8]) -> bool {
        self.with_engine(|engine| {
            engine
                .store()
                .db()
                .get(Column::Meta, key)
                .map_or(true, |persisted| persisted.is_some())
        })
    }

    /// Hold `divergent` while its proof runs, unless the bound is reached or
    /// its header is already pending.
    fn enqueue_pending_claim(&self, divergent: &DivergentExecution) -> bool {
        let mut pending = self.execution_claims.lock().expect("execution claims");
        if pending.len() >= MAX_PENDING_CLAIMS
            || pending
                .iter()
                .any(|claim| claim.divergent.header == divergent.header)
        {
            return false;
        }
        pending.push(PendingClaim {
            divergent: divergent.clone(),
        });
        true
    }

    /// Prove the honest execution on a blocking worker and persist the claim.
    fn spawn_claim_proof(&self, divergent: DivergentExecution, prover_address: Hash) {
        let prover = Arc::clone(&self.proof_system);
        let claims = Arc::clone(&self.execution_claims);
        let engine = Arc::clone(&self.engine);
        self.spawn_supervised("execution-claim-proof", false, async move {
            let header = divergent.header.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                prove_honest_execution(prover.as_ref(), &divergent, prover_address)
            })
            .await;
            let claim = {
                let mut pending = claims.lock().expect("execution claims");
                pending.retain(|claim| claim.divergent.header != header);
                outcome
            };
            match claim {
                Ok(Ok(evidence)) => {
                    let persisted = persist_claim(&engine, &header.hash(), &evidence);
                    match persisted {
                        Ok(()) => info!(
                            height = header.height,
                            "proved and persisted the honest execution of a divergent candidate"
                        ),
                        Err(error) => warn!(%error, "proven execution claim was not persisted"),
                    }
                }
                Ok(Err(error)) => warn!(%error, "honest execution proof failed"),
                Err(error) => warn!(%error, "honest execution prover cancelled"),
            }
        });
    }

    /// Persist the claims the engine kept from contradicting receipts.
    ///
    /// They wait for the header's chunk exactly as this node's own proven
    /// claims do.
    pub(super) fn collect_contradicting_receipts(&self) {
        let claims =
            self.with_engine_mut(neutrin0_consensus_engine::Engine::take_contradicting_receipts);
        for claim in claims {
            let SlashingEvidence::InvalidExecutionClaim { header, .. } = &claim else {
                continue;
            };
            match persist_claim(&self.engine, &header.hash(), &claim) {
                Ok(()) => info!(
                    height = header.height,
                    "kept the execution claim of a receipt contradicting its header"
                ),
                Err(error) => warn!(%error, "contradicting receipt claim was not persisted"),
            }
        }
    }

    /// Pool every persisted claim whose header's chunk is finalized. A claim
    /// is forgotten only on a positive determination: the slashing pool holds
    /// it, which persists it, or a successful read shows this node can never
    /// pool it. Anything else keeps it for the next finalization; safety
    /// offences have no age limit, so a claim does not expire.
    pub(super) async fn submit_execution_claims(&self) {
        let chunk_size = self.chunk_size().max(1);
        let ready: Vec<(Vec<u8>, SlashingEvidence)> = self.with_engine(|engine| {
            let finalized = engine.finalized_next_chunk_id();
            engine
                .store()
                .db()
                .iter_prefix(Column::Meta, CLAIM_PREFIX)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(key, bytes)| {
                    let evidence: SlashingEvidence = borsh::from_slice(&bytes).ok()?;
                    let SlashingEvidence::InvalidExecutionClaim { header, .. } = &evidence else {
                        return None;
                    };
                    (header.height.saturating_sub(1) / chunk_size < finalized)
                        .then_some((key, evidence))
                })
                .collect()
        });
        if ready.is_empty() {
            return;
        }
        let mut batch = Batch::new();
        for (key, evidence) in ready {
            self.pool_and_gossip_slashing(evidence.clone()).await;
            match self.evidence_disposition(&evidence) {
                super::EvidenceDisposition::Held => batch.delete(Column::Meta, key),
                super::EvidenceDisposition::Unpoolable => {
                    info!("execution claim against an offender this node cannot pool dropped");
                    batch.delete(Column::Meta, key);
                }
                super::EvidenceDisposition::Retry => {
                    debug!("execution claim kept for a later submission");
                }
            }
        }
        if batch.is_empty() {
            return;
        }
        if let Err(error) =
            self.with_engine_mut(|engine| engine.store_mut().write_observed_batch(batch, true))
        {
            warn!(%error, "submitted execution claims were not forgotten");
        }
    }
}

/// Prove the honest execution of `divergent` under `prover_address` and wrap
/// the receipt into the claim against its header.
fn prove_honest_execution<P: ProofSystem>(
    prover: &P,
    divergent: &DivergentExecution,
    prover_address: Hash,
) -> Result<SlashingEvidence, neutrin0_proof_system::ProofError> {
    let proof = prover.prove_block(
        &divergent.witness_bytes,
        &divergent.public_inputs,
        prover_address,
    )?;
    let statement = prover.verify_block_statement(&proof, &divergent.public_inputs)?;
    Ok::<_, neutrin0_proof_system::ProofError>(BlockProof {
        height: divergent.header.height,
        block_hash: divergent.header.hash(),
        public_inputs: divergent.public_inputs.clone(),
        proof_bytes: borsh::to_vec(&proof)
            .map_err(|_| neutrin0_proof_system::ProofError::MalformedProof)?,
        prover_address: statement.prover_address,
        statement_key: neutrin0_consensus_engine::statement_key(&statement),
    })
    .map(|receipt| divergent.claim(receipt))
}

/// The offender a claim names: its header's chunk and proposer index.
fn claim_offender(evidence: &SlashingEvidence, chunk_size: u64) -> Option<(u64, u32)> {
    let SlashingEvidence::InvalidExecutionClaim { header, .. } = evidence else {
        return None;
    };
    Some((
        header.height.saturating_sub(1) / chunk_size.max(1),
        header.proposer_index,
    ))
}

/// Persist a proven claim under its header hash. One claim per offender and
/// chunk is enough to slash, so a further claim against the same proposer in
/// the same chunk is not stored, and no proposer can fill the store. Held
/// claims are never evicted for another offender's: at the bound a new
/// claim is refused. Pooled and unpoolable claims leave at every
/// finalization, so the bound is reached only by many distinct offenders at
/// once.
fn persist_claim<DB: Database>(
    engine: &std::sync::Mutex<neutrin0_consensus_engine::Engine<DB>>,
    header_hash: &Hash,
    evidence: &SlashingEvidence,
) -> Result<(), String>
where
    DB::Error: core::fmt::Display,
{
    let bytes = borsh::to_vec(evidence).map_err(|error| error.to_string())?;
    let mut engine = engine
        .lock()
        .map_err(|_| "engine mutex poisoned".to_owned())?;
    let held = engine
        .store()
        .db()
        .iter_prefix(Column::Meta, CLAIM_PREFIX)
        .map_err(|error| error.to_string())?;
    let chunk_size = engine.chain_spec().consensus.chunk_size;
    let offender = claim_offender(evidence, chunk_size);
    if held.iter().any(|(_, bytes)| {
        borsh::from_slice::<SlashingEvidence>(bytes)
            .is_ok_and(|held| claim_offender(&held, chunk_size) == offender)
    }) {
        return Ok(());
    }
    if held.len() >= MAX_PERSISTED_CLAIMS {
        return Err("persisted execution claim bound reached".to_owned());
    }
    let mut batch = Batch::new();
    batch.put(Column::Meta, claim_key(header_hash), bytes);
    engine
        .store_mut()
        .write_observed_batch(batch, true)
        .map_err(|error| error.to_string())
}
