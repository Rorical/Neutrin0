//! The trust origin a snapshot must extend, and re-authentication of an
//! admitted manifest under it.

use neutrin0_consensus_types::history_proof::{ChainBinding, Checkpoint};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

use super::{AuthenticatedBootstrap, ChainBackend, Check, Pending, authenticate};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// The trust origin a new manifest must extend and when it was trusted:
    /// a configured checkpoint until local finality passes it, otherwise the
    /// local finalized boundary at its own block time. Derived whenever
    /// bootstrap is considered, so a running node that falls behind the
    /// retained window can bootstrap again. A fresh node of a forked
    /// specification trusts the fork's pinned start exactly as another trusts
    /// genesis.
    pub(super) fn local_trust_origin(
        &self,
        chain: ChainBinding,
        configured: Option<&(Checkpoint, u64)>,
    ) -> Result<(Checkpoint, u64), String> {
        let (boundary, genesis_time, slot_duration) = self
            .with_engine(|engine| {
                let spec = engine.chain_spec();
                engine
                    .canonical_boundary(engine.finalized_next_chunk_id().max(spec.first_chunk()))
                    .map(|boundary| {
                        (
                            boundary,
                            spec.genesis_time,
                            spec.consensus.slot_duration_secs,
                        )
                    })
            })
            .map_err(|error| error.to_string())?;
        if let Some(&(checkpoint, trusted_at)) = configured
            && checkpoint.boundary.next_chunk_id >= boundary.next_chunk_id
        {
            return Ok((checkpoint, trusted_at));
        }
        let time = boundary
            .slot
            .checked_mul(slot_duration)
            .and_then(|time| genesis_time.checked_add(time))
            .ok_or("bootstrap trust timestamp overflow")?;
        Ok((Checkpoint { chain, boundary }, time))
    }

    /// The origin bootstrap currently trusts; a download keeps the one it was
    /// admitted under.
    pub(super) fn trust_origin(&self) -> Result<Option<(Checkpoint, u64)>, String> {
        // The engine lock is never taken while the bootstrap lock is held.
        let state = self
            .bootstrap
            .lock()
            .expect("bootstrap runtime")
            .as_ref()
            .map(|runtime| {
                (
                    runtime.chain,
                    runtime.configured,
                    runtime
                        .pending
                        .as_ref()
                        .map(|pending| (pending.origin, pending.trusted_at)),
                )
            });
        let Some((chain, configured, admitted)) = state else {
            return Ok(None);
        };
        if admitted.is_some() {
            return Ok(admitted);
        }
        self.local_trust_origin(chain, configured.as_ref())
            .map(Some)
    }

    pub(super) fn authenticate_pending(
        &self,
        pending: &Pending,
        future: u64,
    ) -> Result<AuthenticatedBootstrap, SyncBackendError> {
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        authenticate(
            self.proof_system.as_ref(),
            &spec,
            pending,
            future,
            Check::Installation,
        )
    }

    pub(in crate::chain_backend) fn bootstrap_origin(&self) -> Option<Checkpoint> {
        self.trust_origin()
            .inspect_err(|error| tracing::warn!(%error, "bootstrap trust origin unavailable"))
            .ok()
            .flatten()
            .map(|(origin, _)| origin)
    }
}
