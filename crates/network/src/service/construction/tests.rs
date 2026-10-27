use super::*;
use crate::rpc;

#[test]
fn unrelated_topic_cannot_poison_the_duplicate_cache() {
    let mut message = gossipsub::Message {
        source: None,
        data: vec![42; 128],
        sequence_number: None,
        topic: Topic::Transactions.to_ident().hash(),
    };
    let transaction_id = gossip_message_id(&message);
    message.topic = Topic::Blocks.to_ident().hash();
    assert_ne!(transaction_id, gossip_message_id(&message));
    message.topic = Topic::Transactions.to_ident().hash();
    assert_eq!(transaction_id, gossip_message_id(&message));
}

#[test]
fn every_finalizer_of_one_endpoint_shares_one_announcement_id() {
    let endpoint = rpc::CheckpointAnnouncement {
        chunk_count: 5,
        checkpoint_hash: [5; 32],
    };
    let next = rpc::CheckpointAnnouncement {
        chunk_count: 6,
        checkpoint_hash: [6; 32],
    };
    let message = |announcement| gossipsub::Message {
        source: None,
        data: borsh::to_vec(&announcement).unwrap(),
        sequence_number: None,
        topic: Topic::Checkpoints.to_ident().hash(),
    };
    let first = message(endpoint);
    assert_eq!(first.data.len(), 40);
    assert_eq!(
        borsh::from_slice::<rpc::CheckpointAnnouncement>(&first.data).unwrap(),
        endpoint
    );
    // Every node announces the endpoint it finalizes; the copies collapse.
    assert_eq!(
        gossip_message_id(&first),
        gossip_message_id(&message(endpoint))
    );
    assert_ne!(gossip_message_id(&first), gossip_message_id(&message(next)));
}

#[test]
fn topic_index_resolves_exactly_the_default_topics() {
    let topics = topic_index();
    let lookup = |name: &str| topics.get(&gossipsub::TopicHash::from_raw(name)).copied();
    for topic in Topic::STATIC {
        assert_eq!(lookup(&topic.protocol_string()), Some(topic));
    }
    for subnet in 0..=15u8 {
        let topic = Topic::AggregateFinalityVotes(subnet);
        assert_eq!(lookup(&topic.protocol_string()), Some(topic));
    }
    assert_eq!(
        lookup(&Topic::AggregateFinalityVotes(16).protocol_string()),
        None
    );
    assert_eq!(lookup("/neutrin0/garbage/borsh"), None);
    assert_eq!(
        lookup("/neutrin0/aggregate_finality_votes_0/borsh/extra"),
        None
    );
    assert_eq!(topics.len(), Topic::all_default().count());
}
