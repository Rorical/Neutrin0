//! Authenticated full-node snapshot installation from a History proof and
//! resumable state download.

mod download;
mod install;
mod programs;
mod serve;
mod trust;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{
    bootstrap::{BootstrapData, StateItem, StateItemKind},
    history::HISTORY_RETENTION_CHUNKS,
    history_proof::{AnchorOpening, ChainBinding, Checkpoint, ConsensusBoundary},
};
use neutrin0_light_client::LightClient;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ProofSystem, VerifiedHistory, verify_history_proof};
use neutrin0_prover_chunk::history::HistoricalOpening;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{ChainBackend, light::Authenticated, not_available, rejected, storage_error};

use neutrin0_consensus_engine::store::pointers::BOOTSTRAP_PENDING as PENDING_KEY;

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct Pending {
    origin: Checkpoint,
    trusted_at: u64,
    local: ConsensusBoundary,
    local_head: Hash,
    local_height: u64,
    /// Opening of `origin` under the endpoint's history root, unless the
    /// origin is genesis or the endpoint itself.
    anchor: Option<AnchorOpening>,
    data: BootstrapData,
}

pub(super) struct BootstrapRuntime {
    /// Chain of the local trust origin.
    chain: ChainBinding,
    /// An explicitly configured checkpoint and when it was trusted, used
    /// until local finality passes it.
    configured: Option<(Checkpoint, u64)>,
    max_future_drift_secs: u64,
    pending: Option<Pending>,
    fetching: bool,
}

/// RAII authority for an authenticated in-flight snapshot, independent of the
/// replaceable pending manifest. Dropping one attempt cannot release another.
struct BootstrapProgramPins {
    pins: std::sync::Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<
                neutrin0_proof_system::artifacts::ArtifactIdentity,
                (usize, usize),
            >,
        >,
    >,
    retention: neutrin0_proof_system::artifacts::ProgramRetention,
}

impl Drop for BootstrapProgramPins {
    fn drop(&mut self) {
        let mut pins = self
            .pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for identity in &self.retention.sources {
            if let Some((sources, warm)) = pins.get_mut(identity) {
                *sources -= 1;
                if self.retention.warm.contains(identity) {
                    *warm -= 1;
                }
            }
        }
        pins.retain(|_, (sources, warm)| *sources != 0 || *warm != 0);
    }
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|error| error.to_string())
}

pub(super) fn validate_data(
    data: &BootstrapData,
) -> Result<Vec<HistoricalOpening>, SyncBackendError> {
    let end = *data.history.end();
    if data.anchor_header.hash() != end.block_hash
        || data.anchor_header.height != end.height
        || data.anchor_header.slot != end.slot
        || data.anchor_header.state_root != end.state_root
        || commitment(&data.validators[..]) != end.validators_root
        || data.frontier.count != end.next_chunk_id
        || data.frontier.root() != Some(end.history_root)
    {
        return Err(rejected(
            "bootstrap context differs from authenticated boundary",
        ));
    }
    let first = end.next_chunk_id.saturating_sub(HISTORY_RETENTION_CHUNKS);
    if data.recent.len() != usize::try_from(end.next_chunk_id - first).map_err(rejected)? {
        return Err(rejected("bootstrap lacks recent consensus history"));
    }
    data.recent
        .iter()
        .enumerate()
        .map(|(offset, bytes)| {
            let opening: HistoricalOpening =
                borsh::from_slice(bytes.as_slice()).map_err(rejected)?;
            let index = first + u64::try_from(offset).map_err(rejected)?;
            if opening.record.chunk.chunk_id != index
                || opening.path.index != index
                || opening.path.count != end.next_chunk_id
                || !opening.path.verify(
                    commitment(&opening.record.evidence_context()),
                    end.history_root,
                )
            {
                return Err(rejected("bootstrap history membership mismatch"));
            }
            Ok(opening)
        })
        .collect()
}

pub(super) fn bootstrap_program_items(
    data: &BootstrapData,
) -> Result<Vec<StateItem>, SyncBackendError> {
    use std::collections::BTreeSet;
    let programs = data.history.end().programs;
    if !programs.is_complete() {
        return Err(rejected(
            "bootstrap endpoint has incomplete execution programs",
        ));
    }
    let mut items = BTreeSet::from([
        StateItem::runtime(programs.runtime_code_hash),
        StateItem::guest(programs.execution.fact),
        StateItem::guest(programs.execution.evidence),
        StateItem::guest(programs.execution.block),
    ]);
    // The endpoint's next programs can differ from those that produced its
    // state. Authenticated recent records also name old runtime/Block programs
    // needed by retained historical queries and source receipt authentication.
    for opening in validate_data(data)? {
        if opening.record.runtime_code_hash == [0; 32]
            || opening.record.block_guest_vk_digest == [0; 8]
        {
            return Err(rejected(
                "bootstrap history has incomplete execution programs",
            ));
        }
        items.insert(StateItem::runtime(opening.record.runtime_code_hash));
        items.insert(StateItem::guest(opening.record.block_guest_vk_digest));
    }
    Ok(items.into_iter().collect())
}

fn snapshot_program_retention(
    data: &BootstrapData,
) -> Result<neutrin0_proof_system::artifacts::ProgramRetention, SyncBackendError> {
    use neutrin0_proof_system::artifacts::{ArtifactIdentity, ProgramRetention};
    let mut sources: Vec<_> = bootstrap_program_items(data)?
        .into_iter()
        .filter_map(|item| match item.kind {
            StateItemKind::Runtime => Some(ArtifactIdentity::Runtime(item.hash)),
            StateItemKind::Guest => item.guest_digest().map(ArtifactIdentity::Guest),
            StateItemKind::Node | StateItemKind::Value => None,
        })
        .collect();
    sources.sort_unstable();
    sources.dedup();
    let programs = data.history.end().programs;
    let mut warm = std::collections::BTreeSet::from([
        ArtifactIdentity::Runtime(programs.runtime_code_hash),
        ArtifactIdentity::Guest(programs.execution.fact),
        ArtifactIdentity::Guest(programs.execution.evidence),
        ArtifactIdentity::Guest(programs.execution.block),
    ]);
    // The state was produced before the boundary's governed program switch.
    // Only its source runtime needs a compiled module for operational queries;
    // older recent keys/runtimes retain cold authenticated source authority.
    if let Some(bytes) = data.recent.last() {
        let opening: HistoricalOpening = borsh::from_slice(bytes.as_slice()).map_err(rejected)?;
        warm.insert(ArtifactIdentity::Runtime(opening.record.runtime_code_hash));
    }
    Ok(ProgramRetention {
        sources,
        warm: warm.into_iter().collect(),
    })
}

type AuthenticatedBootstrap = (VerifiedHistory, Vec<HistoricalOpening>);

/// When a manifest is authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    /// Accepting a new manifest: every light-client rule applies.
    Admission,
    /// Installing or resuming an admitted manifest. Its proof and opening are
    /// verified again and its trust anchor must not have expired, but it is
    /// not judged stale: freshness selects which endpoint to download, and a
    /// download may outlast the window without weakening what was verified.
    Installation,
    /// Accepting an operator-supplied snapshot file. Every rule applies but
    /// staleness: the operator chose the endpoint, and the node syncs forward
    /// from it. The trust anchor must still not have expired.
    Offline,
}

fn authenticate<P: ProofSystem>(
    verifier: &P,
    spec: &neutrin0_primitives::ChainSpec,
    pending: &Pending,
    future: u64,
    check: Check,
) -> Result<AuthenticatedBootstrap, SyncBackendError> {
    authenticate_at(
        verifier,
        spec,
        pending,
        future,
        check,
        now().map_err(rejected)?,
    )
}

fn authenticate_at<P: ProofSystem>(
    verifier: &P,
    spec: &neutrin0_primitives::ChainSpec,
    pending: &Pending,
    future: u64,
    check: Check,
    clock: u64,
) -> Result<AuthenticatedBootstrap, SyncBackendError> {
    // The receipt proves the chain from this node's own genesis; the light
    // client policy places the explicitly trusted origin on it.
    let history =
        verify_history_proof(verifier, spec, pending.data.history.clone()).map_err(rejected)?;
    let endpoint = history.proof().end_checkpoint();
    let mut policy =
        LightClient::new(spec, pending.origin, pending.trusted_at, future).map_err(rejected)?;
    if clock >= policy.anchor_expires_at() {
        return Err(rejected(
            "bootstrap trust anchor has expired; configure a newer trusted checkpoint",
        ));
    }
    let timestamp = endpoint
        .boundary
        .slot
        .checked_mul(spec.consensus.slot_duration_secs)
        .and_then(|time| spec.genesis_time.checked_add(time))
        .ok_or_else(|| rejected("bootstrap endpoint time overflow"))?;
    // Installation judges the endpoint as of the end of its freshness window
    // at the latest; every other check sees the real clock.
    let clock = match check {
        Check::Admission => clock,
        Check::Installation | Check::Offline => {
            clock.min(timestamp.saturating_add(spec.light_client.stale_threshold_secs))
        }
    };
    if pending.origin == endpoint {
        if pending.anchor.is_some() {
            return Err(rejected("bootstrap exact anchor carries an opening"));
        }
        if timestamp > clock.saturating_add(future)
            || clock.saturating_sub(timestamp) > spec.light_client.stale_threshold_secs
        {
            return Err(rejected("bootstrap exact anchor is stale or in the future"));
        }
    } else {
        // A full node never jumps off its own finalized history: the opening
        // places its trusted boundary on the proven chain. The light-client
        // policy then applies the same time checks.
        let genesis = neutrin0_consensus_types::history_proof::ConsensusBoundary::first(spec);
        if !neutrin0_consensus_types::history_proof::anchors(
            &genesis,
            &pending.origin.boundary,
            &endpoint.boundary,
            pending.anchor.as_ref(),
        ) {
            return Err(rejected(
                "bootstrap endpoint does not extend the trusted boundary",
            ));
        }
        policy
            .accept(
                history.proof(),
                pending.anchor.as_ref(),
                endpoint.hash(),
                clock,
                &Authenticated(&history),
            )
            .map_err(rejected)?;
    }
    let recent = validate_data(&pending.data)?;
    Ok((history, recent))
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) fn bootstrap_pending(&self) -> bool {
        self.bootstrap
            .lock()
            .expect("bootstrap runtime")
            .as_ref()
            .is_some_and(|runtime| runtime.fetching || runtime.pending.is_some())
    }
    pub(super) fn bootstrap_fetch(&self, active: bool) {
        // Serialize admission with every chain mutation. A caller that passed an
        // earlier optimistic check must recheck after acquiring this same lock.
        self.with_engine_mut(|_| {
            let mut guard = self.bootstrap.lock().expect("bootstrap runtime");
            if let Some(runtime) = guard.as_mut() {
                runtime.fetching = active || runtime.pending.is_some();
            }
        });
    }

    pub(super) fn bootstrap_state(
        &self,
    ) -> Result<Option<(Hash, Vec<StateItem>)>, SyncBackendError> {
        let end = self
            .bootstrap
            .lock()
            .expect("bootstrap runtime")
            .as_ref()
            .and_then(|runtime| {
                runtime
                    .pending
                    .as_ref()
                    .map(|pending| *pending.data.history.end())
            });
        end.map(|end| {
            // Seed on resume too, including a crash after persisting the verified
            // manifest but before initially recording its program requirements.
            let programs = self.missing_bootstrap_programs()?;
            self.require_bootstrap_programs(end.state_root, &programs)?;
            for root in [end.state_root, end.identity_sanctions_root] {
                let items = self.state_download_items(root)?;
                if !items.is_empty() {
                    return Ok((root, items));
                }
            }
            Ok((end.state_root, Vec::new()))
        })
        .transpose()
    }

    pub(super) fn bootstrap_downloads_complete(&self) -> Result<bool, SyncBackendError> {
        Ok(self
            .bootstrap_state()?
            .is_some_and(|(_, items)| items.is_empty()))
    }

    pub(super) fn authorize_state_download(&self, root: Hash) -> Result<(), SyncBackendError> {
        let guard = self.bootstrap.lock().expect("bootstrap runtime");
        if let Some(runtime) = &*guard {
            if let Some(pending) = &runtime.pending {
                let end = *pending.data.history.end();
                if end.state_root != root && end.identity_sanctions_root != root {
                    return Err(rejected("state response targets another bootstrap"));
                }
            } else if runtime.fetching {
                return Err(SyncBackendError::NotAvailable(
                    "checkpoint manifest is downloading".into(),
                ));
            }
        }
        drop(guard);
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod barrier_tests;
