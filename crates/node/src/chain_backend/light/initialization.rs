//! Installing the configured trust origin or restoring its durable advancement.

use neutrin0_consensus_types::history_proof::{Checkpoint, HistoryProof};
use neutrin0_light_client::LightClient;
use neutrin0_proof_system::{ProofSystem, VerifiedHistory, verify_history_proof};
use neutrin0_storage::{Batch, Column, Database};
use std::collections::BTreeMap;

use super::{
    CONFLICT_KEY, ChainBackend, LightConflict, LightRuntime, MAX_CONFLICT_BYTES, PROOF_KEY,
    STATE_KEY, StoredLight,
};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Install an explicit local trust origin or restore its durable advancement.
    /// Existing origin/time must match configuration: startup never refreshes trust.
    pub fn initialize_light(
        &self,
        trusted: Checkpoint,
        trusted_at: u64,
        max_future_drift_secs: u64,
    ) -> Result<(), String> {
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let domain = self
            .proof_system
            .history_domain(&spec)
            .map_err(|error| error.to_string())?;
        if trusted.chain != domain.chain || !trusted.boundary.programs.is_complete() {
            return Err("light trust origin uses a different chain binding".to_owned());
        }
        let (mut state_bytes, mut proof_bytes) = self.with_engine(|engine| {
            let db = engine.store().db();
            Ok::<_, String>((
                db.get(Column::Meta, STATE_KEY)
                    .map_err(|error| error.to_string())?,
                db.get(Column::Meta, PROOF_KEY)
                    .map_err(|error| error.to_string())?,
            ))
        })?;
        let (conflict, replace) = self.persisted_light_conflict(&trusted, trusted_at)?;
        if replace {
            state_bytes = None;
            proof_bytes = None;
        }
        let runtime = if let Some(bytes) = &state_bytes {
            let stored = StoredLight::decode(bytes, &trusted, trusted_at)?;
            let client =
                LightClient::restore(&spec, &domain, &stored.snapshot, max_future_drift_secs)
                    .map_err(|error| error.to_string())?;
            let latest = self.verified_persisted_proof(
                &spec,
                &stored,
                proof_bytes.as_deref(),
                &trusted,
                trusted_at,
            )?;
            LightRuntime {
                client,
                latest,
                trust_origin: stored.trust_origin,
                trusted_at: stored.trusted_at,
                candidates: BTreeMap::new(),
                conflict,
            }
        } else {
            if proof_bytes.is_some() {
                return Err("light proof exists without trust state".to_owned());
            }
            let client = LightClient::new(&spec, trusted, trusted_at, max_future_drift_secs)
                .map_err(|error| error.to_string())?;
            LightRuntime {
                client,
                latest: None,
                trust_origin: trusted,
                trusted_at,
                candidates: BTreeMap::new(),
                conflict,
            }
        };
        // All combined locking uses engine -> light; cryptographic work is complete.
        self.with_engine_mut(|engine| {
            let mut state = self.light.lock().expect("light state");
            if state.is_some() {
                return Err("light client is already initialized".to_owned());
            }
            if state_bytes.is_none() {
                Self::persist_initial_light_state(engine, &runtime, &trusted, trusted_at, replace)?;
            }
            *state = Some(runtime);
            drop(state);
            Ok(())
        })
    }

    /// The stored latest proof, checked against the durable snapshot and
    /// verified from genesis again.
    fn verified_persisted_proof(
        &self,
        spec: &neutrin0_primitives::ChainSpec,
        stored: &StoredLight,
        proof_bytes: Option<&[u8]>,
        trusted: &Checkpoint,
        trusted_at: u64,
    ) -> Result<Option<HistoryProof>, String> {
        let expiry = neutrin0_light_client::anchor_expiry(spec, trusted, trusted_at)
            .map_err(|error| error.to_string())?;
        stored
            .decode_latest(proof_bytes, expiry)?
            .map(|proof| {
                // `decode_latest` bound the statement to the durable
                // snapshot's endpoint; the receipt proves it from genesis.
                verify_history_proof(self.proof_system.as_ref(), spec, proof)
                    .map(VerifiedHistory::into_proof)
                    .map_err(|error| error.to_string())
            })
            .transpose()
    }

    /// Write the fresh trust origin, discarding a halted state it replaces.
    fn persist_initial_light_state(
        engine: &mut neutrin0_consensus_engine::Engine<DB>,
        runtime: &LightRuntime,
        trusted: &Checkpoint,
        trusted_at: u64,
        replace: bool,
    ) -> Result<(), String> {
        let stored = StoredLight {
            snapshot: runtime.client.snapshot(),
            trust_origin: *trusted,
            trusted_at,
            proof_key: None,
        };
        let mut batch = Batch::new();
        if replace {
            batch.delete(Column::Meta, PROOF_KEY);
            batch.delete(Column::Meta, CONFLICT_KEY);
        }
        batch.put(
            Column::Meta,
            STATE_KEY,
            borsh::to_vec(&stored).map_err(|error| error.to_string())?,
        );
        engine
            .store_mut()
            .write_observed_batch(batch, replace)
            .map_err(|error| error.to_string())
    }

    /// The persisted conflict halt, if it still applies, and whether a newly
    /// configured trust origin replaces the halted state: the operator's way
    /// to clear the halt.
    fn persisted_light_conflict(
        &self,
        trusted: &Checkpoint,
        trusted_at: u64,
    ) -> Result<(Option<LightConflict>, bool), String> {
        let conflict = self
            .with_engine(|engine| engine.store().db().get(Column::Meta, CONFLICT_KEY))
            .map_err(|error| error.to_string())?
            .map(|bytes| {
                if bytes.len() > MAX_CONFLICT_BYTES {
                    return Err("oversized persisted light conflict".to_owned());
                }
                borsh::from_slice::<LightConflict>(&bytes).map_err(|error| error.to_string())
            })
            .transpose()?;
        let Some(halt) = conflict else {
            return Ok((None, false));
        };
        if halt.trust_origin != *trusted || halt.trusted_at != trusted_at {
            tracing::warn!(
                chunks = halt.chunks,
                "new light trust origin configured; discarding the halted state and its conflict evidence"
            );
            return Ok((None, true));
        }
        tracing::error!(
            chunks = halt.chunks,
            "light client is halted on conflicting History proofs; configure a new trusted checkpoint"
        );
        Ok((Some(halt), false))
    }
}
