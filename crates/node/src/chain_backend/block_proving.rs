//! Block proving (design 08): which retained blocks this node proves, the
//! proving budget around each job and the prover configuration.

use neutrin0_consensus_engine::{Engine, ProveError, ProveOutcome};
use neutrin0_primitives::{BlockHash, Hash};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;

use super::ChainBackend;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Prove a block that is already stored in the wrapped engine.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError`] when the block is unknown, already advanced in
    /// an incompatible way, or the active proof backend rejects proving.
    pub fn prove_block(
        &self,
        block_hash: &BlockHash,
    ) -> Result<ProveOutcome, ProveError<DB::Error>> {
        let job = self.with_engine_mut(|e| {
            if self.bootstrap_pending() {
                return Err(ProveError::Backend(
                    neutrin0_proof_system::ProofError::BackendRejected,
                ));
            }
            e.prepare_block_proof(block_hash)
        })?;
        let programs = self.with_engine(|engine| {
            let header = engine
                .store()
                .get_header(block_hash)
                .map_err(|_| neutrin0_proof_system::ProofError::InvalidWitness)?
                .ok_or(neutrin0_proof_system::ProofError::InvalidWitness)?;
            let execution = engine
                .programs_at_chunk(
                    header.height.saturating_sub(1) / engine.chain_spec().consensus.chunk_size,
                )
                .map_err(|_| neutrin0_proof_system::ProofError::InvalidWitness)?
                .execution;
            Ok::<_, neutrin0_proof_system::ProofError>(
                neutrin0_consensus_types::history_proof::GuestPrograms {
                    execution,
                    chunk: engine.chain_spec().genesis_chunk,
                },
            )
        })?;
        let _program_lease = self
            .proving_budget
            .setup(|| self.proof_system.lease_programs(&programs))?;
        let stage = crate::proof_metrics::ProofStage::Block;
        let permit = self
            .proving_budget
            .request(stage)
            .wait_if(|| self.needs_block_proof(block_hash))
            .ok_or(ProveError::Backend(
                neutrin0_proof_system::ProofError::InvalidWitness,
            ))?;
        let completed = permit.run(|| {
            self.metrics.proof_stage(stage).time(|| {
                if !self.needs_block_proof(block_hash) {
                    return Err(ProveError::Backend(
                        neutrin0_proof_system::ProofError::InvalidWitness,
                    ));
                }
                job.prove(self.proof_system.as_ref())
                    .map_err(ProveError::Backend)
            })
        })?;
        drop(permit);
        self.with_engine_mut(|e| {
            if self.bootstrap_pending() {
                return Err(ProveError::Backend(
                    neutrin0_proof_system::ProofError::BackendRejected,
                ));
            }
            e.commit_block_proof(completed)
        })
    }

    /// Configure the shared proving limit before starting background workers.
    pub fn set_proving_concurrency(&self, concurrency: usize) {
        self.proving_budget.set_capacity(concurrency);
    }

    /// Publish local demand before dispatch so optional facts cannot enter
    /// between consecutive block jobs merely because no permit is queued yet.
    pub(crate) fn set_block_proof_backlog(&self, jobs: usize) {
        self.proving_budget.set_block_backlog(jobs);
    }

    /// Address credited for the block receipts this node proves (design 08).
    pub fn set_prover_address(&self, address: Hash) {
        self.with_engine_mut(|engine| engine.set_prover_address(address));
    }

    /// Configure host-only preferred proving before workers start.
    pub fn set_proving_policy(&self, mut policy: crate::config::ProvingPolicy) {
        policy.chunk_fallback_secs = policy.chunk_fallback_secs.min(3600);
        *self.proving_policy.lock().expect("proving policy") = policy;
    }

    /// Recover canonical, witnessed jobs after restart or a failed proving attempt.
    ///
    /// Only hashes are queued; witnesses are loaded when a worker starts. This
    /// node's own productions always qualify; other candidates only with
    /// `prove_foreign_blocks`, and at most `foreign_limit` of them, so a
    /// producer keeps capacity for its own blocks.
    pub(crate) fn pending_block_proofs(
        &self,
        limit: usize,
        foreign_limit: usize,
        skip: impl Fn(&BlockHash) -> bool,
    ) -> Vec<BlockHash> {
        let prove_foreign = self.prove_foreign_blocks();
        let rescue = self
            .rescue_proofs
            .load(std::sync::atomic::Ordering::Acquire);
        let mut rescued = None;
        let mut pending =
            self.with_engine(|engine| {
                let mut pending = Vec::new();
                let first = engine.latest_finalized_chunk_id().map_or(1, |id| {
                    id.saturating_add(1)
                        .saturating_mul(engine.chain_spec().consensus.chunk_size)
                        .saturating_add(1)
                });
                let local_key = engine.local_voter().map(|voter| *voter.public_key_bytes());
                let mut foreign = 0;
                for height in first..=engine.head_height() {
                    if pending.len() == limit {
                        break;
                    }
                    let Ok(Some(hash)) = engine.store().get_block_hash_by_height(height) else {
                        continue;
                    };
                    if skip(&hash) {
                        continue;
                    }
                    if !Self::awaits_proof(engine, &hash, local_key) {
                        continue;
                    }
                    let local = Self::is_local_production(engine, &hash, local_key);
                    let witnessed = engine.store().get_witness(&hash).ok().flatten().is_some();
                    // A foreign block overdue for its proposer's receipt may be
                    // rescued; its witness is rebuilt below, one block a pass.
                    let due =
                        rescue
                            && !local
                            && foreign < foreign_limit
                            && engine.store().get_header(&hash).ok().flatten().is_some_and(
                                |header| {
                                    Self::rescue_due(
                                        &header,
                                        &hash,
                                        local_key,
                                        engine.chain_spec().consensus.proof_exclusive_slots,
                                        engine.local_slot(),
                                    )
                                },
                            );
                    if due && !witnessed {
                        rescued.get_or_insert(hash);
                        continue;
                    }
                    if !witnessed {
                        continue;
                    }
                    // Without `prove_foreign_blocks` a node proves only the
                    // candidates its own key produced (design 08, rule P), and
                    // the ones overdue for rescue.
                    if !local {
                        if !(prove_foreign || due) || foreign >= foreign_limit {
                            continue;
                        }
                        foreign += 1;
                    }
                    pending.push(hash);
                }
                pending
            });
        if let (Some(hash), Some(executor)) = (rescued, self.block_executor_snapshot())
            && pending.len() < limit
            && self
                .with_engine_mut(|engine| engine.retain_rescue_witness(&hash, executor.as_ref()))
                .unwrap_or(false)
        {
            tracing::info!(?hash, "proving an unproven block its proposer has not");
            pending.push(hash);
        }
        pending
    }

    /// Whether the proposer of the retained block `hash` is this node's key.
    fn is_local_production(
        engine: &Engine<DB>,
        hash: &BlockHash,
        local_key: Option<[u8; 48]>,
    ) -> bool {
        let Some(local_key) = local_key else {
            return false;
        };
        let Ok(Some(header)) = engine.store().get_header(hash) else {
            return false;
        };
        let Ok((validators, _)) = engine.validator_context_for_height(header.height) else {
            return false;
        };
        usize::try_from(header.proposer_index)
            .ok()
            .and_then(|index| validators.get(index))
            .is_some_and(|validator| validator.pubkey == local_key)
    }

    pub(crate) fn needs_block_proof(&self, hash: &BlockHash) -> bool {
        self.with_engine(|engine| {
            let Ok(Some(header)) = engine.store().get_header(hash) else {
                return false;
            };
            let local_key = engine.local_voter().map(|voter| *voter.public_key_bytes());
            engine
                .store()
                .get_block_hash_by_height(header.height)
                .ok()
                .flatten()
                == Some(*hash)
                && Self::awaits_proof(engine, hash, local_key)
        })
    }

    /// Whether the retained block `hash` still needs this node's proof: it is
    /// unproven, or another receipt proved it while this node, its proposer
    /// proving under the proposer's address, holds no receipt of its own yet.
    /// Rule P (design 08) selects the proposer's receipt whenever held, so a
    /// faster third party cannot cancel it.
    fn awaits_proof(engine: &Engine<DB>, hash: &BlockHash, local_key: Option<[u8; 48]>) -> bool {
        match engine.store().get_block_state(hash) {
            Ok(Some(
                neutrin0_consensus_engine::BlockState::BlockProduced
                | neutrin0_consensus_engine::BlockState::PendingProof,
            )) => true,
            Ok(Some(neutrin0_consensus_engine::BlockState::Proven)) => {
                Self::proves_as_proposer(engine, hash, local_key)
                    && engine.lacks_proposer_receipt(hash).unwrap_or(false)
            }
            _ => false,
        }
    }

    /// Whether this node's key produced `hash` and its proofs name that
    /// seat's address, so its receipt is the proposer's.
    fn proves_as_proposer(
        engine: &Engine<DB>,
        hash: &BlockHash,
        local_key: Option<[u8; 48]>,
    ) -> bool {
        let Some(local_key) = local_key else {
            return false;
        };
        let Ok(Some(header)) = engine.store().get_header(hash) else {
            return false;
        };
        let Ok((validators, _)) = engine.validator_context_for_height(header.height) else {
            return false;
        };
        usize::try_from(header.proposer_index)
            .ok()
            .and_then(|index| validators.get(index))
            .is_some_and(|validator| {
                validator.pubkey == local_key
                    && engine.prover_address().ok() == Some(validator.withdrawal_credentials)
            })
    }

    /// What this node proves and which account its proofs name (design 08).
    pub fn proving_status(&self) -> neutrin0_rpc::ProvingStatusJson {
        let pending = self.pending_block_proofs(64, 64, |_| false);
        let running_chunk_proof = self
            .consensus_proof_task
            .lock()
            .expect("proof task mutex poisoned")
            .as_ref()
            .map(|(identity, _)| identity.chunk_id);
        self.with_engine(|engine| neutrin0_rpc::ProvingStatusJson {
            backend_ready: self.block_program().is_some(),
            prover_address: engine
                .prover_address()
                .ok()
                .map(neutrin0_rpc::HashHex::from),
            prove_foreign_blocks: self.prove_foreign_blocks(),
            pending_block_proofs: u64::try_from(pending.len()).unwrap_or(u64::MAX),
            running_chunk_proof,
            proven_head_height: engine
                .store()
                .get_header(&engine.proven_head())
                .ok()
                .flatten()
                .map_or(0, |header| header.height),
            pending_head_height: engine.head_height(),
        })
    }

    /// Whether this node proves candidates it did not produce.
    pub fn prove_foreign_blocks(&self) -> bool {
        self.prove_foreign_blocks
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Prove candidates this node did not produce (design 08). The caller
    /// guarantees the executing mode, which retains their witnesses.
    pub fn set_prove_foreign_blocks(&self, enabled: bool) {
        self.prove_foreign_blocks
            .store(enabled, std::sync::atomic::Ordering::Release);
    }

    /// Prove head-branch blocks whose proposer published no receipt within
    /// its lease, rebuilding their witness by execution (design 08).
    pub fn set_rescue_proofs(&self, enabled: bool) {
        self.rescue_proofs
            .store(enabled, std::sync::atomic::Ordering::Release);
    }

    /// Whether `header`'s block is due for rescue at `now`: its proposer's
    /// lease has passed, plus a stagger this node draws from the block and
    /// its own key, so the nodes rescuing one block mostly do not all prove
    /// it. Late buckets still land before the stale candidate is deleted,
    /// and a valid receipt restores it.
    fn rescue_due(
        header: &neutrin0_consensus_types::Header,
        hash: &BlockHash,
        local_key: Option<[u8; 48]>,
        exclusive_slots: u64,
        now: u64,
    ) -> bool {
        const STAGGER_SLOTS: u64 = 4;
        let mut seed = hash.to_vec();
        seed.extend_from_slice(&local_key.unwrap_or([0; 48]));
        let bucket = u64::from(neutrin0_primitives::blake3_256(&seed)[0] % 2);
        now >= header
            .slot
            .saturating_add(neutrin0_consensus_engine::receipts::proposer_lease(
                exclusive_slots,
            ))
            .saturating_add(bucket * STAGGER_SLOTS)
    }
}
