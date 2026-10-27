//! Gossip publication and the retained artifacts a node publishes or serves.

use borsh::BorshSerialize;
use neutrin0_consensus_types::{Block, BlockReceipt, CandidateBlock, ProvenBlock};
use neutrin0_network::Topic;
use neutrin0_network::service::NetworkCommand;
use neutrin0_primitives::BlockHash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::{ChainBackend, cloned};

/// Hand one encoded gossip message to the network task.
async fn send_publication(
    publisher: &mpsc::Sender<NetworkCommand>,
    topic: Topic,
    data: Vec<u8>,
) -> bool {
    match publisher
        .send(NetworkCommand::Publish { topic, data })
        .await
    {
        Ok(()) => true,
        Err(error) => {
            debug!(?error, ?topic, "gossip publish channel closed");
            false
        }
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Enable the multi-validator chunk-BFT loop by installing the
    /// network publisher used to gossip prevotes, precommits, chunk
    /// proofs, and History endpoint announcements.
    ///
    /// Without a publisher the engine still ingests peer votes into
    /// [`Engine::observe_finality_vote`](neutrin0_consensus_engine::Engine::observe_finality_vote) but emits no broadcast
    /// traffic. Isolated tests can leave this unset.
    pub fn set_network_publisher(&self, publisher: mpsc::Sender<NetworkCommand>) {
        *self
            .network_publisher
            .lock()
            .expect("ChainBackend network_publisher poisoned") = Some(publisher);
        if !self.is_light() {
            self.start_evidence_jobs();
        }
    }

    pub(super) fn publisher_snapshot(&self) -> Option<mpsc::Sender<NetworkCommand>> {
        cloned(&self.network_publisher)
    }

    /// Encode and gossip `message` on `topic`. Returns whether it reached the
    /// network command channel; without a publisher nothing is encoded.
    pub(super) async fn publish<T: BorshSerialize + Sync>(
        &self,
        topic: Topic,
        message: &T,
    ) -> bool {
        let Some(publisher) = self.publisher_snapshot() else {
            return false;
        };
        match borsh::to_vec(message) {
            Ok(data) => send_publication(&publisher, topic, data).await,
            Err(error) => {
                warn!(?error, ?topic, "failed to encode gossip message");
                false
            }
        }
    }

    /// Gossip an already encoded message on `topic`; see [`Self::publish`].
    pub(super) async fn publish_encoded(&self, topic: Topic, data: Vec<u8>) -> bool {
        let Some(publisher) = self.publisher_snapshot() else {
            return false;
        };
        send_publication(&publisher, topic, data).await
    }

    /// The single unit a node publishes or serves for the canonical block
    /// `hash`: body, receipt bytes and write set, once all three are retained.
    pub fn proven_block_for_publication(&self, hash: &BlockHash) -> Option<ProvenBlock> {
        self.block_for_publication(hash)?;
        self.with_engine(|engine| engine.proven_block(hash).ok().flatten())
    }

    /// The candidate publication of the canonical block `hash`: body and
    /// write set, with or without a receipt (design 08).
    pub fn candidate_for_publication(&self, hash: &BlockHash) -> Option<CandidateBlock> {
        self.block_for_publication(hash)?;
        self.with_engine(|engine| engine.candidate_block(hash).ok().flatten())
    }

    /// The receipt of the canonical block `hash` as the network carries it.
    pub fn receipt_for_publication(&self, hash: &BlockHash) -> Option<BlockReceipt> {
        self.block_for_publication(hash)?;
        self.with_engine(|engine| engine.block_receipt(hash).ok().flatten())
    }

    pub(crate) fn block_for_publication(&self, hash: &BlockHash) -> Option<Block> {
        self.with_engine(|engine| {
            let header = engine.store().get_header(hash).ok()??;
            if engine
                .store()
                .get_block_hash_by_height(header.height)
                .ok()
                .flatten()
                != Some(*hash)
            {
                return None;
            }
            Some(Block {
                header,
                body: engine.store().get_body(hash).ok()??,
            })
        })
    }
}
