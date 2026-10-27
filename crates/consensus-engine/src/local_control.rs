//! Node-local signing policy, independent of consensus state and wire formats.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_storage::{Batch, Column, Database};

use crate::{Engine, EngineError, StoreError};

pub(crate) const POLICY_KEY: &[u8] = b"local:signing-policy";

/// Operator policy retained across restarts without changing signing journals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct LocalSigningPolicy {
    /// Suppress every new local consensus signature, including VRF evaluation.
    pub signing_paused: bool,
    /// Suppress block production while permitting consensus votes.
    pub production_paused: bool,
}

impl LocalSigningPolicy {
    pub(crate) fn load<DB: Database>(db: &DB) -> Result<Self, EngineError<DB::Error>> {
        db.get(Column::Meta, POLICY_KEY)
            .map_err(StoreError::Database)?
            .map_or(Ok(Self::default()), |bytes| {
                borsh::from_slice(&bytes).map_err(EngineError::from)
            })
    }
}

impl<DB: Database> Engine<DB> {
    /// Read the effective local policy. A failed durable write closes both gates.
    #[must_use]
    pub const fn local_signing_policy(&self) -> LocalSigningPolicy {
        self.local_signing_policy
    }

    /// Whether a policy write failed and the local gates were closed in memory.
    #[must_use]
    pub const fn local_control_faulted(&self) -> bool {
        self.local_control_faulted
    }

    /// Whether shutdown has permanently closed this engine's local signer.
    #[must_use]
    pub const fn local_signer_stopping(&self) -> bool {
        self.local_signer_stopping
    }

    /// Stop signing for shutdown without changing the policy saved for restart.
    pub const fn stop_local_signer(&mut self) {
        self.local_signer_stopping = true;
    }

    /// Persist an operator policy before opening either signing gate.
    ///
    /// The caller must serialize this with all engine operations. On return,
    /// earlier signatures have finished; existing keys, reservations and BFT
    /// locks remain intact. Storage failure closes both gates until a successful
    /// policy write. Shutdown cannot be reversed on a running engine.
    ///
    /// # Errors
    /// Returns a storage/codec error or refuses changes after shutdown starts.
    pub fn set_local_signing_policy(
        &mut self,
        policy: LocalSigningPolicy,
    ) -> Result<(), EngineError<DB::Error>> {
        if self.local_signer_stopping {
            return Err(EngineError::Signing(
                crate::signing::SigningViolation::Paused,
            ));
        }
        let mut batch = Batch::new();
        batch.put(Column::Meta, POLICY_KEY.to_vec(), borsh::to_vec(&policy)?);
        if let Err(error) = self.store_mut().db_mut().write_batch_durable(batch) {
            self.local_signing_policy = LocalSigningPolicy {
                signing_paused: true,
                production_paused: true,
            };
            self.local_control_faulted = true;
            return Err(StoreError::Database(error).into());
        }
        self.local_signing_policy = policy;
        self.local_control_faulted = false;
        // Resuming signing answers a doppelganger pause; detection then
        // watches again, so a later foreign message pauses once more.
        if !policy.signing_paused {
            self.doppelganger = None;
        }
        Ok(())
    }

    pub(crate) fn local_signing_enabled(&self) -> bool {
        !self.local_signer_stopping
            && !self.local_signing_policy.signing_paused
            && !self.signing_quiet()
    }

    /// Whether the doppelganger quiet period still forbids signing.
    pub(crate) fn signing_quiet(&self) -> bool {
        self.local_slot() < self.signing_quiet_until
    }

    /// Whether local policy permits production; eligibility and bootstrap still apply.
    #[must_use]
    pub fn local_production_enabled(&self) -> bool {
        self.local_signing_enabled() && !self.local_signing_policy.production_paused
    }
}
