//! Refreshing the tracked identity set from finalized economic eligibility.

use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_runtime_abi::QueryRequest;
use neutrin0_runtime_abi::operational::{
    MAX_REPORTER_STATUS_IDENTITIES, QUERY_METHOD_REPORTER_STATUS, ReporterIdentity, ReporterStatus,
    ReporterStatusRequest,
};
use neutrin0_storage::Database;
use std::sync::atomic::Ordering;

use super::{
    Address, ChainBackend, ReporterTrackingSnapshot, eligible_identities, finalized_query_state,
    tracked_revision,
};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(in crate::chain_backend) fn refresh_reporter_tracking(&self) {
        if let Err(error) = self.update_reporter_tracking() {
            self.metrics
                .reporter
                .query_failures
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .reporter
                .eligibility_available
                .store(0, Ordering::Relaxed);
            // Failure never implies withdrawal: retaining sources is safe, while
            // deleting on a failed query would lose a slashable identity's proof.
            tracing::warn!(%error, "reporter retains sources until finalized economic query succeeds");
        }
    }

    pub(super) fn reporter_tracking_snapshot(
        &self,
        last_finalized: Option<Hash>,
        last_tracked_revision: Option<u64>,
    ) -> Result<Option<ReporterTrackingSnapshot>, String> {
        self.with_engine_mut(|engine| {
            let boundary = engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?;
            let revision = tracked_revision(engine)?;
            if last_finalized == Some(boundary.block_hash)
                && last_tracked_revision == Some(revision)
                && revision != u64::MAX
            {
                self.metrics
                    .reporter
                    .eligibility_available
                    .store(1, Ordering::Relaxed);
                return Ok(None);
            }
            // New authenticated memberships get source ownership before the
            // query runs; failure can only retain extra data, never lose inputs.
            engine
                .seed_reporter_tracking()
                .map_err(|error| error.to_string())?;
            let revision = tracked_revision(engine)?;
            let (state, runtime) = finalized_query_state(engine, &boundary)?;
            let identities = engine
                .reporter_tracked_validators()
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|(pubkey, withdrawal_credentials)| ReporterIdentity {
                    pubkey,
                    withdrawal_credentials,
                })
                .collect::<Vec<_>>();
            Ok(Some(ReporterTrackingSnapshot {
                boundary,
                state,
                runtime,
                identities,
                revision,
            }))
        })
    }

    fn update_reporter_tracking(&self) -> Result<(), String> {
        let Some((last_finalized, last_tracked_revision)) = self
            .reporter
            .lock()
            .expect("reporter runtime")
            .as_ref()
            .map(|runtime| (runtime.last_finalized, runtime.last_tracked_revision))
        else {
            return Ok(());
        };
        let executor = self
            .block_executor_snapshot()
            .ok_or("reporter requires an installed runtime executor")?;
        let Some(snapshot) =
            self.reporter_tracking_snapshot(last_finalized, last_tracked_revision)?
        else {
            return Ok(());
        };
        let timer = self.metrics.reporter.eligibility_queries.timer();
        let mut eligible = Vec::new();
        for group in snapshot.identities.chunks(MAX_REPORTER_STATUS_IDENTITIES) {
            let request = QueryRequest {
                method: QUERY_METHOD_REPORTER_STATUS.to_owned(),
                args: borsh::to_vec(&ReporterStatusRequest {
                    identities: group.to_vec(),
                })
                .map_err(|error| error.to_string())?,
            };
            let response = executor.query(&request, snapshot.runtime, &snapshot.state)?;
            if !response.is_ok() {
                return Err("reporter status query did not succeed".into());
            }
            let statuses: Vec<ReporterStatus> =
                borsh::from_slice(&response.payload).map_err(|error| error.to_string())?;
            eligible.extend(eligible_identities(group, &statuses)?);
        }
        self.commit_reporter_eligibility(&snapshot, &eligible)?;
        timer.finish(true);
        Ok(())
    }

    pub(super) fn commit_reporter_eligibility(
        &self,
        snapshot: &ReporterTrackingSnapshot,
        eligible: &[(neutrin0_primitives::BlsPublicKey, Address)],
    ) -> Result<(), String> {
        self.with_raw_pool(|raw_pool, engine| {
            if engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?
                != snapshot.boundary
            {
                // Another finalization won the race; its callback will query the
                // new state. Never apply deletion using an older snapshot.
                return Err("finalized boundary changed during reporter economic query".into());
            }
            let current_revision = tracked_revision(engine)?;
            if current_revision != snapshot.revision
                || (snapshot.revision == u64::MAX
                    && engine
                        .reporter_tracked_validators()
                        .map_err(|error| error.to_string())?
                        != snapshot
                            .identities
                            .iter()
                            .map(|identity| (identity.pubkey, identity.withdrawal_credentials))
                            .collect::<Vec<_>>())
            {
                return Err(
                    "reporter tracked identities changed during economic query; retaining sources"
                        .into(),
                );
            }
            let removed = engine
                .set_reporter_eligible(eligible)
                .map_err(|error| error.to_string())?;
            raw_pool.forget(&removed);
            let after_revision = tracked_revision(engine)?;
            self.metrics.reporter.cleaned.fetch_add(
                u64::try_from(removed.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            if let Some(reporter) = self.reporter.lock().expect("reporter runtime").as_mut() {
                reporter.last_finalized = Some(snapshot.boundary.block_hash);
                reporter.last_tracked_revision = Some(after_revision);
            }
            self.metrics
                .reporter
                .last_success_height
                .store(snapshot.boundary.height, Ordering::Relaxed);
            self.metrics
                .reporter
                .eligibility_available
                .store(1, Ordering::Relaxed);
            Ok::<(), String>(())
        })
    }
}
