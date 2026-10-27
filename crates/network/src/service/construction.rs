//! Private protocol construction for the networking service.

use super::NetworkError;
use crate::behaviour::{GossipBehaviour, Neutrin0Behaviour};
use crate::rpc::{BorshCodec, RpcProtocol};
use crate::topic::Topic;
use borsh::{BorshDeserialize, BorshSerialize};
use libp2p::{
    PeerId, StreamProtocol, connection_limits, gossipsub, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    ping,
    request_response::{self, ProtocolSupport},
};
use neutrin0_primitives::blake3_256;
use std::{collections::HashMap, time::Duration};

/// Build the composed Neutrin0 behaviour.
pub(super) fn build_behaviour(
    local_key: &Keypair,
    local_peer_id: PeerId,
) -> Result<Neutrin0Behaviour, NetworkError> {
    let connection_limits = connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(16))
            .with_max_pending_outgoing(Some(16))
            .with_max_established_incoming(Some(32))
            .with_max_established_outgoing(Some(32))
            .with_max_established(Some(64))
            .with_max_established_per_peer(Some(2)),
    );

    // Identify keeps no address cache: a peer's claimed listen addresses must
    // not become dial targets outside the filtered Kademlia and the learned
    // book, which keep local targets off a public node.
    let identify = identify::Behaviour::new(
        identify::Config::new("/neutrin0/identify".to_owned(), local_key.public())
            .with_cache_size(0),
    );

    let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(15)));

    let gossipsub = build_gossipsub(local_key)?;
    let kademlia = crate::kademlia::FilteredKademlia::new(build_kademlia(local_peer_id));

    let bulk = read_budgets(3);
    let auxiliary = read_budgets(2);
    let control = read_budgets(64);
    Ok(Neutrin0Behaviour {
        connection_limits,
        identify,
        ping,
        gossipsub,
        kademlia,
        rpc_status: build_rpc(RpcProtocol::Status, control.clone()),
        rpc_metadata: build_rpc(RpcProtocol::Metadata, control.clone()),
        rpc_ping: build_rpc(RpcProtocol::Ping, control),
        rpc_blocks_by_range: build_rpc(RpcProtocol::BlocksByRange, bulk.clone()),
        rpc_state_by_root: build_rpc(RpcProtocol::StateByRoot, bulk.clone()),
        rpc_chunk_proof_by_id: build_rpc(RpcProtocol::ChunkProofById, bulk.clone()),
        rpc_history_proof: build_rpc(RpcProtocol::HistoryProof, bulk.clone()),
        rpc_finality_cert_by_chunk: build_rpc(RpcProtocol::FinalityCertByChunk, bulk.clone()),
        rpc_witness_by_block: build_rpc(RpcProtocol::WitnessByBlock, bulk.clone()),
        rpc_receipts_by_hash: build_rpc(RpcProtocol::ReceiptsByHash, bulk),
        rpc_candidate_by_chunk: build_rpc(RpcProtocol::CandidateByChunk, auxiliary.clone()),
        rpc_signed_artifact_by_id: build_rpc(RpcProtocol::SignedArtifactById, auxiliary.clone()),
        rpc_signed_artifact_inventory_by_chunk: build_rpc(
            RpcProtocol::SignedArtifactInventoryByChunk,
            auxiliary.clone(),
        ),
        rpc_bft_round_by_chunk: build_rpc(RpcProtocol::BftRoundByChunk, auxiliary.clone()),
        rpc_transaction_inventory: build_rpc(RpcProtocol::TransactionInventory, auxiliary.clone()),
        rpc_transactions_by_hash: build_rpc(RpcProtocol::TransactionsByHash, auxiliary),
    })
}

fn gossip_message_id(message: &gossipsub::Message) -> gossipsub::MessageId {
    // Gossipsub shares one duplicate cache across all subscribed topics.
    // Bind the topic before hashing so bytes delivered on an unrelated topic
    // cannot suppress their subsequent delivery on the correct topic.
    let topic = message.topic.as_str().as_bytes();
    let mut input = Vec::with_capacity(8 + topic.len() + message.data.len());
    input.extend_from_slice(&(topic.len() as u64).to_le_bytes());
    input.extend_from_slice(topic);
    input.extend_from_slice(&message.data);
    let digest = blake3_256(&input);
    gossipsub::MessageId::from(digest.to_vec())
}

/// Build the gossipsub behaviour with design 21 settings.
fn build_gossipsub(local_key: &Keypair) -> Result<GossipBehaviour, NetworkError> {
    // Global ceiling matches the largest per-topic limit (the blocks topic).
    // Per-topic caps tighten this further below.
    let global_max = Topic::all_default()
        .map(Topic::max_transmit_size)
        .max()
        .unwrap_or(1024 * 1024);

    let mut builder = gossipsub::ConfigBuilder::default();
    builder
        .heartbeat_interval(Duration::from_millis(700))
        .mesh_n(8)
        .mesh_n_low(6)
        .mesh_n_high(12)
        .history_gossip(6)
        .history_length(10)
        .max_publish_messages(32)
        .max_ihave_messages_heartbeat(8)
        .max_control_messages_sent(256)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(gossip_message_id)
        .max_transmit_size(global_max)
        .duplicate_cache_time(Duration::from_secs(60))
        // Manual validation lets us forward an application-level
        // verdict (`ReportGossipValidation`) back into peer scoring;
        // without it, scoring only reacts to gossipsub-protocol-level
        // misbehaviour and an application-level adversarial flooder
        // never gets graylisted.
        .validate_messages();

    for topic in Topic::all_default() {
        builder.max_transmit_size_for_topic(topic.max_transmit_size(), topic.to_ident().hash());
    }

    let config = builder
        .build()
        .map_err(|e| NetworkError::GossipsubConfig(e.to_string()))?;

    let filter = gossipsub::MaxCountSubscriptionFilter {
        filter: gossipsub::WhitelistSubscriptionFilter(
            Topic::all_default()
                .map(|topic| topic.to_ident().hash())
                .collect(),
        ),
        max_subscribed_topics: Topic::all_default().count(),
        max_subscriptions_per_request: 64,
    };
    let mut behaviour = GossipBehaviour::new_with_subscription_filter(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        config,
        filter,
    )
    .map_err(|e| NetworkError::GossipsubBehaviour(e.to_string()))?;

    let (params, thresholds) = build_peer_score_config();
    behaviour
        .with_peer_score(params, thresholds)
        .map_err(NetworkError::GossipsubBehaviour)?;

    Ok(behaviour)
}

/// Peer-score parameters used in gossipsub v1.1 strict scoring mode.
///
/// Design 21 calls for strict scoring. Application-level invalid messages
/// (decoded payload rejected by the host) carry a heavy per-topic
/// penalty so a flooding adversary drops below `graylist_threshold`
/// within a small number of `Reject` verdicts.
fn build_peer_score_config() -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut topics: HashMap<libp2p::gossipsub::TopicHash, gossipsub::TopicScoreParams> =
        HashMap::new();
    for topic in Topic::all_default() {
        topics.insert(topic.to_ident().hash(), build_topic_score_params());
    }

    let params = gossipsub::PeerScoreParams {
        topics,
        topic_score_cap: 32.0,
        ip_colocation_factor_whitelist: [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]
        .into_iter()
        .collect(),
        behaviour_penalty_weight: -10.0,
        behaviour_penalty_threshold: 6.0,
        behaviour_penalty_decay: 0.5,
        // Independent one-second decay cadence keeps score reactive
        // without thrashing.
        decay_interval: Duration::from_secs(1),
        decay_to_zero: 0.01,
        retain_score: Duration::from_secs(300),
        ..gossipsub::PeerScoreParams::default()
    };

    let thresholds = gossipsub::PeerScoreThresholds {
        gossip_threshold: -10.0,
        publish_threshold: -50.0,
        graylist_threshold: -80.0,
        accept_px_threshold: 10.0,
        opportunistic_graft_threshold: 1.0,
    };

    (params, thresholds)
}

/// Reward validated first deliveries with a small bounded score. Sparse proof
/// topics have no fixed delivery-rate floor: silence alone is not misconduct.
/// Invalid-message penalties exceed the sum of all positive topic rewards.
const fn build_topic_score_params() -> gossipsub::TopicScoreParams {
    gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        // Only application-validated deliveries earn this bounded reward.
        time_in_mesh_weight: 0.0,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 0.0,
        first_message_deliveries_weight: 0.5,
        first_message_deliveries_decay: 0.99,
        first_message_deliveries_cap: 4.0,
        mesh_message_deliveries_weight: 0.0,
        mesh_message_deliveries_decay: 0.5,
        mesh_message_deliveries_cap: 0.0,
        mesh_message_deliveries_threshold: 0.0,
        mesh_message_deliveries_activation: Duration::from_secs(5),
        mesh_message_deliveries_window: Duration::from_millis(10),
        mesh_failure_penalty_weight: 0.0,
        mesh_failure_penalty_decay: 0.5,
        // Each rejected delivery contributes ~160 negative score under
        // P_4. With the graylist threshold at -80, even one confirmed
        // application-level reject pushes the source below it.
        invalid_message_deliveries_weight: -160.0,
        invalid_message_deliveries_decay: 0.99,
    }
}

/// Build the Kademlia behaviour with the Neutrin0 DHT protocol name.
fn build_kademlia(local_peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
    let store = MemoryStore::new(local_peer_id);
    let mut config = kad::Config::new(StreamProtocol::new("/neutrin0/kad"));
    config
        .disjoint_query_paths(true)
        .set_kbucket_inserts(kad::BucketInserts::Manual)
        .set_record_filtering(kad::StoreInserts::FilterBoth);
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, config);
    kademlia.set_mode(Some(kad::Mode::Server));
    kademlia
}

type ReadBudgets = (
    std::sync::Arc<tokio::sync::Semaphore>,
    std::sync::Arc<tokio::sync::Semaphore>,
);

fn read_budgets(readers: usize) -> ReadBudgets {
    (
        std::sync::Arc::new(tokio::sync::Semaphore::new(readers)),
        std::sync::Arc::new(tokio::sync::Semaphore::new(readers)),
    )
}

/// Concurrent request/response streams per protocol and connection, inbound
/// and outbound together. libp2p drops an inbound stream beyond this count
/// without telling either side, so the cap must exceed the sync drivers'
/// per-protocol parallelism (four requests per poller, in each direction);
/// the read budgets below remain the real resource bound.
const MAX_CONCURRENT_RPC_STREAMS: usize = 16;

/// Build one request/response behaviour with its protocol's size caps and timeout.
fn build_rpc<Req, Resp>(
    protocol: RpcProtocol,
    budget: ReadBudgets,
) -> request_response::Behaviour<BorshCodec<Req, Resp>>
where
    Req: BorshSerialize + BorshDeserialize + Send + 'static,
    Resp: BorshSerialize + BorshDeserialize + Send + 'static,
{
    let (request_size, response_size) = protocol.size_limits();
    request_response::Behaviour::with_codec(
        BorshCodec::default()
            .with_read_budgets(budget.0, budget.1)
            .with_request_size_maximum(request_size)
            .with_response_size_maximum(response_size),
        [(protocol.stream_protocol(), ProtocolSupport::Full)],
        request_response::Config::default()
            .with_request_timeout(protocol.request_timeout())
            .with_max_concurrent_streams(MAX_CONCURRENT_RPC_STREAMS),
    )
}

/// Wire topic hashes of every default topic. Gossipsub only delivers messages
/// on subscribed topics, and subscriptions use these canonical strings.
pub(super) fn topic_index() -> HashMap<gossipsub::TopicHash, Topic> {
    Topic::all_default()
        .map(|topic| (topic.to_ident().hash(), topic))
        .collect()
}

#[cfg(test)]
mod tests;
