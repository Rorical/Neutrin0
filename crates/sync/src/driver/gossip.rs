//! Gossip topic handlers and the acceptance verdicts they return to
//! peer scoring.

use alloc::vec::Vec;

use neutrin0_network::libp2p::gossipsub::MessageAcceptance;
use neutrin0_network::sync::{SyncCommand, SyncEvent};
use neutrin0_network::topic::Topic;
use tracing::{debug, info, warn};

use crate::backend::{HeadersImported, SyncBackendError};

use super::{SyncDriver, availability, bft, candidates};

impl SyncDriver {
    /// Refresh only the hint's provider within a bounded cooldown. A peer's
    /// assertion cannot cancel History, bootstrap, candidate or BFT recovery.
    async fn refresh_ahead_provider(&mut self, source: neutrin0_network::PeerId) {
        if self.connected_peers.contains(&source)
            && self.ahead_hints.allow(source, tokio::time::Instant::now())
        {
            self.dispatch_one(SyncCommand::RequestStatus(source)).await;
        }
    }

    async fn handle_checkpoint_announcement(
        &mut self,
        data: &[u8],
        source: neutrin0_network::PeerId,
    ) -> MessageAcceptance {
        let Ok(announcement) =
            borsh::from_slice::<neutrin0_network::rpc::CheckpointAnnouncement>(data)
        else {
            return MessageAcceptance::Reject;
        };
        // A notice of nothing beyond local finality is neither news nor
        // worth a hint; it is not relayed and costs no budget.
        let local = self
            .backend
            .local_status()
            .await
            .map_or(0, |status| status.finalized_chunks());
        if announcement.chunk_count <= local
            || !self.connected_peers.contains(&source)
            || !self.ahead_hints.allow(source, tokio::time::Instant::now())
        {
            return MessageAcceptance::Ignore;
        }
        // Relay the notice and refresh its source's status; the FSM decides
        // whether an anchored fetch is still needed. The announcement itself
        // never advances trust, and it never clears a provider's backoff.
        let generation = self
            .history_announcement
            .map_or(1, |(generation, _)| generation.wrapping_add(1));
        self.history_announcement = Some((generation, source));
        self.history_attempts.clear();
        debug!(
            chunks = announcement.chunk_count,
            "History proof endpoint became available"
        );
        self.dispatch_one(SyncCommand::RequestStatus(source)).await;
        MessageAcceptance::Accept
    }

    /// Dispatch one gossip message to the matching topic handler and
    /// translate the outcome into a [`MessageAcceptance`] so
    /// scoring can react to application-level adversaries.
    ///
    /// Verdicts: `Reject` for un-decodable or semantically-wrong
    /// content (the peer sent garbage); `Ignore` for content the local
    /// node simply does not need right now (e.g., a duplicate
    /// gossipped block, or a block we are too behind to import);
    /// `Accept` for content that was useful.
    pub(super) async fn handle_gossip(
        &mut self,
        topic: Topic,
        data: Vec<u8>,
        source: neutrin0_network::PeerId,
    ) -> MessageAcceptance {
        if topic == Topic::Blocks || topic == Topic::Receipts {
            return self.handle_block_topic_gossip(topic, data, source).await;
        }
        if topic == Topic::ChunkProofs {
            let Ok(proof) = borsh::from_slice::<neutrin0_consensus_types::ChunkProof>(&data) else {
                return MessageAcceptance::Reject;
            };
            return verdict(
                &self
                    .backend
                    .verify_and_import_chunk_proof(proof, source)
                    .await,
            );
        }
        if topic == Topic::BftCandidates {
            let Ok(candidate) = borsh::from_slice::<neutrin0_consensus_types::BftCandidate>(&data)
            else {
                return MessageAcceptance::Reject;
            };
            return if candidates::on_hint(self, source, candidate).await {
                MessageAcceptance::Accept
            } else {
                MessageAcceptance::Ignore
            };
        }
        if topic == Topic::BftMessages {
            if data.len() > topic.max_transmit_size() {
                return MessageAcceptance::Reject;
            }
            let Ok(message) = borsh::from_slice::<neutrin0_consensus_types::BftMessage>(&data)
            else {
                return MessageAcceptance::Reject;
            };
            return verdict(&bft::on_message(self, source, message).await);
        }
        if topic == Topic::SignedArtifacts {
            if data.len() > topic.max_transmit_size() {
                return MessageAcceptance::Reject;
            }
            let Ok(inventory) = borsh::from_slice::<
                neutrin0_consensus_types::signed_artifacts::SignedArtifactInventory,
            >(&data) else {
                return MessageAcceptance::Reject;
            };
            return if availability::on_notice(self, source, inventory).await {
                MessageAcceptance::Accept
            } else {
                MessageAcceptance::Ignore
            };
        }
        if topic == Topic::Checkpoints {
            return self.handle_checkpoint_announcement(&data, source).await;
        }
        if topic == Topic::Transactions {
            return self.handle_transaction_gossip(data).await;
        }
        if topic == Topic::FinalityVotesPrevote || topic == Topic::FinalityVotesPrecommit {
            return self.handle_finality_vote_gossip(None, data, source).await;
        }
        if let Topic::AggregateFinalityVotes(subnet) = topic {
            return self
                .handle_finality_vote_gossip(Some(subnet), data, source)
                .await;
        }
        if topic == Topic::EvidenceProofs {
            if data.len() > topic.max_transmit_size() {
                return MessageAcceptance::Reject;
            }
            let Ok(report) =
                borsh::from_slice::<neutrin0_consensus_types::evidence::EvidenceReport>(&data)
            else {
                return MessageAcceptance::Reject;
            };
            return match self.backend.ingest_evidence_proof(report).await {
                crate::EvidenceProofAcceptance::Accepted => MessageAcceptance::Accept,
                crate::EvidenceProofAcceptance::Deferred => MessageAcceptance::Ignore,
                crate::EvidenceProofAcceptance::Rejected => MessageAcceptance::Reject,
            };
        }
        if topic == Topic::SlashingEvidence {
            return self.handle_slashing_evidence_gossip(data).await;
        }
        // Every registered topic has a handler; an unknown topic is ignored
        // so honest peers are not penalised for a subscription this node
        // does not follow.
        debug!(
            ?topic,
            len = data.len(),
            "ignoring gossip for unhandled topic"
        );
        MessageAcceptance::Ignore
    }

    async fn handle_transaction_gossip(&self, data: Vec<u8>) -> MessageAcceptance {
        if data.len() > Topic::Transactions.max_transmit_size() {
            return MessageAcceptance::Reject;
        }
        let Ok(message) =
            borsh::from_slice::<neutrin0_network::rpc::TransactionAnnouncement>(&data)
        else {
            return MessageAcceptance::Reject;
        };
        verdict(
            &self
                .backend
                .submit_transaction_in_runtime(message.runtime, message.transaction.into_vec())
                .await,
        )
    }

    /// Decode and route the two block-market topics (design 08): candidates
    /// on `blocks`, receipts on `receipts`. Oversized or undecodable payloads
    /// are rejected before reaching the backend.
    async fn handle_block_topic_gossip(
        &mut self,
        topic: Topic,
        data: Vec<u8>,
        source: neutrin0_network::PeerId,
    ) -> MessageAcceptance {
        if data.len() > topic.max_transmit_size() {
            return MessageAcceptance::Reject;
        }
        if topic == Topic::Blocks {
            let Ok(candidate) =
                borsh::from_slice::<neutrin0_consensus_types::CandidateBlock>(&data)
            else {
                return MessageAcceptance::Reject;
            };
            return self.handle_candidate_gossip(candidate, source).await;
        }
        let Ok(receipt) = borsh::from_slice::<neutrin0_consensus_types::BlockReceipt>(&data) else {
            return MessageAcceptance::Reject;
        };
        self.handle_receipt_gossip(receipt, source).await
    }

    /// A proposer's candidate publication (design 08). Block and write set
    /// are accepted or rejected together; a failing candidate is attributable
    /// to its gossip source.
    async fn handle_candidate_gossip(
        &mut self,
        candidate: neutrin0_consensus_types::CandidateBlock,
        source: neutrin0_network::PeerId,
    ) -> MessageAcceptance {
        if !candidate.writes_well_formed() {
            warn!(%source, "rejecting candidate with a non-canonical write set");
            return MessageAcceptance::Reject;
        }
        let height = candidate.block.header.height;
        match self
            .backend
            .verify_and_import_candidates(vec![candidate])
            .await
        {
            Ok(HeadersImported {
                new_head_height,
                new_head_hash,
                new_head_slot,
            }) => {
                info!(
                    height,
                    new_head_height,
                    head_hash = %hex_short(&new_head_hash),
                    "imported gossipped candidate"
                );
                let cmds = self.fsm.on_event(SyncEvent::HeadersAdvanced {
                    new_head_height,
                    new_head_hash,
                    new_head_slot,
                });
                self.dispatch_sync_commands(cmds).await;
                MessageAcceptance::Accept
            }
            Err(SyncBackendError::ChainBehind(reason)) => {
                debug!(%reason, %source, "candidate awaits local dependencies");
                self.refresh_ahead_provider(source).await;
                MessageAcceptance::Ignore
            }
            Err(SyncBackendError::NotAvailable(reason)) => {
                debug!(%reason, %source, "ignoring gossipped candidate for now");
                MessageAcceptance::Ignore
            }
            Err(err) => {
                warn!(?err, %source, "rejecting gossipped candidate");
                MessageAcceptance::Reject
            }
        }
    }

    /// A receipt for a block this node may not hold yet (design 08). The
    /// backend verifies it against the retained header, or keeps it for the
    /// orphan window when the block has not arrived. A receipt that proved a
    /// block is relayed, and so is the proposer's own receipt of a block
    /// another receipt proved first, since selection prefers it.
    async fn handle_receipt_gossip(
        &self,
        receipt: neutrin0_consensus_types::BlockReceipt,
        source: neutrin0_network::PeerId,
    ) -> MessageAcceptance {
        let block_hash = hex_short(&receipt.block_hash);
        match self
            .backend
            .verify_and_import_receipts(vec![receipt], source)
            .await
        {
            Ok(imported) if !imported.proven.is_empty() || imported.relayed > 0 => {
                debug!(%block_hash, heights = ?imported.proven, "imported gossipped receipt");
                MessageAcceptance::Accept
            }
            Ok(imported) => {
                debug!(%block_hash, buffered = imported.buffered, "receipt not applied yet");
                MessageAcceptance::Ignore
            }
            Err(SyncBackendError::Rejected(reason)) => {
                warn!(%block_hash, %reason, %source, "rejecting gossipped receipt");
                MessageAcceptance::Reject
            }
            Err(err) => {
                debug!(%block_hash, ?err, %source, "ignoring gossipped receipt");
                MessageAcceptance::Ignore
            }
        }
    }

    /// Route a finality vote from the direct topics (`subnet == None`) or an
    /// aggregate subnet topic.
    async fn handle_finality_vote_gossip(
        &mut self,
        subnet: Option<u8>,
        data: Vec<u8>,
        source: neutrin0_network::PeerId,
    ) -> MessageAcceptance {
        let vote = match borsh::from_slice::<neutrin0_consensus_types::BftVote>(&data) {
            Ok(v) => v,
            Err(err) => {
                warn!(
                    ?err,
                    ?subnet,
                    "failed to decode gossipped finality vote; rejecting"
                );
                return MessageAcceptance::Reject;
            }
        };
        let neutrin0_consensus_types::BftVote::Value(vote) = vote else {
            let message = neutrin0_consensus_types::BftMessage::Vote(vote);
            return verdict(&bft::on_message(self, source, message).await);
        };
        let result = if let Some(subnet) = subnet {
            self.backend
                .ingest_aggregate_finality_vote(subnet, vote.clone())
                .await
        } else {
            self.backend.ingest_finality_vote(vote.clone()).await
        };
        if result.is_ok() {
            candidates::on_vote(self, source, subnet, &vote).await;
            availability::on_vote(self, source, &vote).await;
        }
        verdict(&result)
    }

    async fn handle_slashing_evidence_gossip(&self, data: Vec<u8>) -> MessageAcceptance {
        let evidence = match borsh::from_slice::<neutrin0_consensus_types::SlashingEvidence>(&data)
        {
            Ok(e) => e,
            Err(err) => {
                warn!(
                    ?err,
                    "failed to decode gossipped slashing evidence; rejecting"
                );
                return MessageAcceptance::Reject;
            }
        };
        // Authenticated evidence enters the durable pool and mandatory sanction
        // path; the gossip envelope itself never authorizes a deduction.
        verdict(&self.backend.ingest_slashing_evidence(evidence).await)
    }
}

// Compact hex helper for debug logs; the full chain primitives use lowercase
// hex without a `0x` prefix, but our log lines are short so we truncate.
fn hex_short(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        use core::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Gossip verdict for a backend outcome: verified-invalid data is rejected,
/// data the node merely cannot use now is ignored.
const fn verdict<T>(result: &Result<T, SyncBackendError>) -> MessageAcceptance {
    match result {
        Ok(_) => MessageAcceptance::Accept,
        Err(SyncBackendError::Rejected(_)) => MessageAcceptance::Reject,
        Err(_) => MessageAcceptance::Ignore,
    }
}
