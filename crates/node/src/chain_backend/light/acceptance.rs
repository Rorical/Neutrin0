//! Accepting sampled History proofs and halting on verified conflicts.

use neutrin0_consensus_types::history_proof::{AnchorOpening, Checkpoint, HistoryProof};
use neutrin0_light_client::{LightClient, LightClientError, LightClientSnapshot, UpdateOutcome};
use neutrin0_proof_system::{ProofSystem, VerifiedHistory, verify_history_proof};
use neutrin0_storage::{Batch, Column, Database};
use neutrin0_sync::{CheckpointsImported, SyncBackendError};
use std::sync::Arc;

use super::{
    Authenticated, CONFLICT_KEY, ChainBackend, Contradicted, LightConflict, LightRuntime,
    PROOF_KEY, STATE_KEY, StoredLight, rejected, storage_error, timestamp,
};

/// The atomic write persisting an advanced client and its latest proof.
fn light_batch(
    next: &LightClient,
    trust_origin: &Checkpoint,
    trusted_at: u64,
    proof: &HistoryProof,
) -> Result<Batch, SyncBackendError> {
    let stored = StoredLight {
        snapshot: next.snapshot(),
        trust_origin: *trust_origin,
        trusted_at,
        proof_key: Some(proof.statement.statement_key()),
    };
    let mut batch = Batch::new();
    batch.put(
        Column::Meta,
        STATE_KEY,
        borsh::to_vec(&stored).map_err(storage_error)?,
    );
    batch.put(
        Column::Meta,
        PROOF_KEY,
        borsh::to_vec(proof).map_err(storage_error)?,
    );
    Ok(batch)
}

fn policy_error(error: LightClientError) -> SyncBackendError {
    match error {
        LightClientError::Expired | LightClientError::Future | LightClientError::Stale => {
            SyncBackendError::NotAvailable(error.to_string())
        }
        _ => SyncBackendError::Rejected(error.to_string()),
    }
}

fn halted() -> SyncBackendError {
    SyncBackendError::NotAvailable(
        "light client halted on conflicting History proofs; configure a new trusted checkpoint"
            .to_owned(),
    )
}
fn imported(checkpoint: &Checkpoint) -> CheckpointsImported {
    CheckpointsImported {
        new_finalized_index: checkpoint.boundary.next_chunk_id,
        new_finalized_hash: checkpoint.hash(),
        new_finalized_state_root: checkpoint.boundary.state_root,
        new_finalized_height: checkpoint.boundary.height,
        new_finalized_block_hash: checkpoint.boundary.block_hash,
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Verify one side of a sampled conflict without accepting it. Returns
    /// `true` once the client is halted.
    pub(in crate::chain_backend) async fn check_light_conflict(
        &self,
        proof: HistoryProof,
    ) -> Result<bool, SyncBackendError> {
        if self.light_halted() {
            return Ok(true);
        }
        let proof = self.verify_history_off_lock(proof).await?.into_proof();
        self.with_engine_mut(|engine| {
            let mut guard = self.light.lock().expect("light state");
            let state = guard.as_mut().ok_or_else(|| {
                SyncBackendError::NotAvailable("light client is not initialized".to_owned())
            })?;
            if state.conflict.is_some() {
                return Ok(true);
            }
            if let Some(first) = state.conflicting(&proof) {
                Self::halt_light(engine, state, first, proof, None)?;
                return Ok(true);
            }
            state.remember(proof);
            drop(guard);
            Ok(false)
        })
    }

    /// Verify `proof` from genesis on a blocking worker, outside every lock.
    async fn verify_history_off_lock(
        &self,
        proof: HistoryProof,
    ) -> Result<VerifiedHistory, SyncBackendError> {
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let verifier = Arc::clone(&self.proof_system);
        tokio::task::spawn_blocking(move || verify_history_proof(verifier.as_ref(), &spec, proof))
            .await
            .map_err(storage_error)?
            .map_err(rejected)
    }

    /// Halt on a verified proof that contradicts a verified side, unless
    /// already halted, and refuse the update.
    fn halt_on_contradiction(
        &self,
        first: Contradicted,
        second: HistoryProof,
        opening: Option<AnchorOpening>,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        self.with_engine_mut(|engine| {
            let mut guard = self.light.lock().expect("light state");
            let state = guard.as_mut().ok_or_else(|| {
                SyncBackendError::NotAvailable("light state disappeared".to_owned())
            })?;
            if state.conflict.is_none() {
                Self::halt_light(engine, state, first, second, opening)?;
            }
            drop(guard);
            Err(halted())
        })
    }

    /// Durably record conflict evidence, then refuse every further update.
    fn halt_light(
        engine: &mut neutrin0_consensus_engine::Engine<DB>,
        state: &mut LightRuntime,
        first: Contradicted,
        second: HistoryProof,
        opening: Option<AnchorOpening>,
    ) -> Result<(), SyncBackendError> {
        let conflict = LightConflict {
            trust_origin: state.trust_origin,
            trusted_at: state.trusted_at,
            chunks: opening.as_ref().map_or_else(
                || second.end().next_chunk_id,
                |opening| opening.context.chunk_id,
            ),
            first: first.into_proof(),
            second,
            opening,
        };
        let mut batch = Batch::new();
        batch.put(
            Column::Meta,
            CONFLICT_KEY,
            borsh::to_vec(&conflict).map_err(storage_error)?,
        );
        engine
            .store_mut()
            .write_observed_batch(batch, true)
            .map_err(storage_error)?;
        tracing::error!(
            chunks = conflict.chunks,
            first = ?conflict.first.as_ref().map(|proof| proof.end_checkpoint().hash()),
            second = ?conflict.second.end_checkpoint().hash(),
            "two verified History proofs disagree; light client halted until a new trusted checkpoint is configured"
        );
        state.conflict = Some(conflict);
        Ok(())
    }

    /// The client's current endpoint as one side of a contradiction.
    fn current_side(&self) -> Contradicted {
        let guard = self.light.lock().expect("light state");
        guard
            .as_ref()
            .and_then(|state| state.latest.clone())
            .map_or(Contradicted::Origin, |proof| {
                Contradicted::Proof(Box::new(proof))
            })
    }

    pub(in crate::chain_backend) async fn accept_light_history(
        &self,
        proof: HistoryProof,
        anchor: Option<AnchorOpening>,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        let (mut next, origin, trusted_at) = self.light_acceptance_snapshot()?;
        let before = next.snapshot();
        if timestamp()? >= before.anchor_expires_at {
            return Err(policy_error(LightClientError::Expired));
        }
        // The receipt proves the chain from genesis; the driver chose its
        // endpoint because a quorum of sampled peers advertise it.
        let authenticated = self.verify_history_off_lock(proof).await?;
        // A verified endpoint contradicting the current one, or another
        // verified endpoint at its count, halts instead of choosing a side.
        if let Some(first) = self.pending_contradiction(authenticated.proof()) {
            return self.halt_on_contradiction(first, authenticated.into_proof(), None);
        }
        let target = authenticated.proof().end_checkpoint().hash();
        let outcome = match next.accept(
            authenticated.proof(),
            anchor.as_ref(),
            target,
            timestamp()?,
            &Authenticated(&authenticated),
        ) {
            Ok(outcome) => outcome,
            // A verified opening shows the new chain does not contain the
            // current endpoint: halt on that evidence instead of choosing.
            Err(LightClientError::AnchorConflict) => {
                return self.halt_on_contradiction(
                    self.current_side(),
                    authenticated.into_proof(),
                    anchor,
                );
            }
            Err(error) => return Err(policy_error(error)),
        };
        let proof = authenticated.into_proof();
        let batch = if outcome == UpdateOutcome::Advanced {
            light_batch(&next, &origin, trusted_at, &proof)?
        } else {
            Batch::new()
        };
        self.commit_light_advance(&before, next, proof, outcome, batch)
    }

    /// The client to advance and the trust it runs under, unless halted.
    fn light_acceptance_snapshot(
        &self,
    ) -> Result<(LightClient, Checkpoint, u64), SyncBackendError> {
        let guard = self.light.lock().expect("light state");
        let state = guard.as_ref().ok_or_else(|| {
            SyncBackendError::NotAvailable("light client is not initialized".to_owned())
        })?;
        if state.conflict.is_some() {
            return Err(halted());
        }
        let snapshot = (state.client.clone(), state.trust_origin, state.trusted_at);
        drop(guard);
        Ok(snapshot)
    }

    /// The verified side `proof` contradicts, if any.
    fn pending_contradiction(&self, proof: &HistoryProof) -> Option<Contradicted> {
        let guard = self.light.lock().expect("light state");
        guard.as_ref().and_then(|state| state.conflicting(proof))
    }

    /// Publish the verified advance atomically, unless the client moved or
    /// halted while verifying.
    fn commit_light_advance(
        &self,
        before: &LightClientSnapshot,
        next: LightClient,
        proof: HistoryProof,
        outcome: UpdateOutcome,
        batch: Batch,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        self.with_engine_mut(|engine| {
            let mut guard = self.light.lock().expect("light state");
            let state = guard.as_mut().ok_or_else(|| {
                SyncBackendError::NotAvailable("light state disappeared".to_owned())
            })?;
            if state.conflict.is_some() {
                return Err(halted());
            }
            if state.client.snapshot() != *before {
                if *state.client.checkpoint() == proof.end_checkpoint()
                    && timestamp()? < state.client.anchor_expires_at()
                {
                    return Ok(imported(state.client.checkpoint()));
                }
                return Err(SyncBackendError::NotAvailable(
                    "light anchor advanced while verifying; request a new History proof".to_owned(),
                ));
            }
            if timestamp()? >= before.anchor_expires_at {
                return Err(policy_error(LightClientError::Expired));
            }
            if outcome == UpdateOutcome::Advanced {
                engine
                    .store_mut()
                    .write_observed_batch(batch, false)
                    .map_err(storage_error)?;
                state.client = next;
                state.latest = Some(proof);
                let count = state.client.checkpoint().boundary.next_chunk_id;
                state.candidates.retain(|candidate, _| *candidate > count);
            }
            let outcome = imported(state.client.checkpoint());
            drop(guard);
            Ok(outcome)
        })
    }
}
