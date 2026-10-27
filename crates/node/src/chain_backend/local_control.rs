//! Serialize operator controls with production and all consensus signatures.

use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_primitives::Validator;
use neutrin0_proof_system::ProofSystem;
use neutrin0_rpc::management::{LocalVotesJson, ManagementRequest, ManagementStatus};
use neutrin0_rpc::{BytesHex, HashHex};
use neutrin0_storage::Database;

use super::ChainBackend;

fn committee_seat<'a, DB: Database>(
    engine: &'a Engine<DB>,
    key: Option<&ProposerKey>,
) -> Option<(usize, &'a Validator)> {
    key.and_then(|key| {
        engine
            .active_validator_set()
            .iter()
            .enumerate()
            .find(|(_, validator)| &validator.pubkey == key.public_key_bytes())
    })
}

fn membership_label(
    has_key: bool,
    unavailable: bool,
    member: Option<(usize, &Validator)>,
) -> &'static str {
    if !has_key {
        "no_key"
    } else if unavailable {
        "unavailable"
    } else {
        member.map_or("not_in_committee", |(_, validator)| {
            if validator.effective_stake == 0 {
                "zero_stake"
            } else {
                "member"
            }
        })
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Read local controls and identity under the signing/production mutex.
    #[must_use]
    pub fn management_status(&self) -> ManagementStatus {
        let status = self.with_engine(|engine| self.control_status(engine));
        self.with_publish_queue(status)
    }

    /// The program publish queue is read outside the engine lock.
    fn with_publish_queue(&self, mut status: ManagementStatus) -> ManagementStatus {
        status.publish_queue = self.program_store().status().publish_queue;
        status
    }

    fn control_status(&self, engine: &Engine<DB>) -> ManagementStatus {
        let policy = engine.local_signing_policy();
        let key = engine.local_voter();
        let unavailable = self.is_light() || self.bootstrap_pending();
        let member = committee_seat(engine, key);
        ManagementStatus {
            chain_id: engine.chain_spec().chain_id,
            chain_spec_hash: HashHex(engine.chain_spec_hash()),
            validator_public_key: key.map(|key| BytesHex(key.public_key_bytes().to_vec())),
            validator_index: member
                .filter(|_| !unavailable)
                .and_then(|(index, _)| u32::try_from(index).ok()),
            membership: membership_label(key.is_some(), unavailable, member).into(),
            local_peer_id: self.local_peer_id.lock().expect("local peer id").clone(),
            local_votes: if unavailable {
                Vec::new()
            } else {
                engine
                    .bft_session_overview()
                    .into_iter()
                    .map(|session| LocalVotesJson {
                        chunk_id: session.chunk_id,
                        round: session.round,
                        prevoted: session.local_prevoted,
                        precommitted: session.local_precommitted,
                    })
                    .collect()
            },
            publish_queue: Vec::new(),
            signing_paused: policy.signing_paused,
            production_paused: policy.production_paused,
            persistence_fault: engine.local_control_faulted(),
            stopping: engine.local_signer_stopping(),
            bootstrap_pending: self.bootstrap_pending(),
            validator_active: !self.is_light()
                && !self.bootstrap_pending()
                && key.is_some_and(|key| {
                    engine.active_validator_set().iter().any(|validator| {
                        validator.pubkey == *key.public_key_bytes() && validator.effective_stake > 0
                    })
                }),
            signing_quiet_until_slot: engine.signing_quiet_until(),
            doppelganger: engine
                .doppelganger()
                .map(|seen| format!("{} signed by 0x{}", seen.seen, hex::encode(seen.identity))),
            head_height: self.light_checkpoint().map_or_else(
                || engine.head_height(),
                |checkpoint| checkpoint.boundary.height,
            ),
        }
    }

    /// Apply a local control at a barrier after all prior engine signatures.
    ///
    /// # Errors
    /// Refuses policy changes during shutdown or failed durable storage writes.
    pub fn apply_management(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementStatus, String> {
        if matches!(request, ManagementRequest::ExportSnapshot { .. }) {
            return Err("a snapshot export is not a policy control".into());
        }
        self.with_engine_mut(|engine| {
            if *request == ManagementRequest::Shutdown {
                engine.stop_local_signer();
            } else if *request != ManagementRequest::Status {
                let mut policy = engine.local_signing_policy();
                match request {
                    ManagementRequest::PauseSigning => policy.signing_paused = true,
                    ManagementRequest::ResumeSigning => policy.signing_paused = false,
                    ManagementRequest::PauseProduction => policy.production_paused = true,
                    ManagementRequest::ResumeProduction => policy.production_paused = false,
                    ManagementRequest::Status
                    | ManagementRequest::Shutdown
                    | ManagementRequest::ExportSnapshot { .. } => unreachable!(),
                }
                engine
                    .set_local_signing_policy(policy)
                    .map_err(|error| error.to_string())?;
            }
            Ok(self.control_status(engine))
        })
        .map(|status| self.with_publish_queue(status))
    }
}

#[cfg(all(test, unix))]
mod tests;
