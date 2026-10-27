use super::*;

#[test]
fn protocol_strings_match_doc_06() {
    assert_eq!(Topic::Blocks.protocol_string(), "/neutrin0/blocks/borsh");
    assert_eq!(Topic::Transactions.protocol_string(), "/neutrin0/txs/borsh");
    assert_eq!(
        Topic::SlashingEvidence.protocol_string(),
        "/neutrin0/slashing_evidence/borsh"
    );
    assert_eq!(
        Topic::ChunkProofs.protocol_string(),
        "/neutrin0/chunk_proofs/borsh"
    );
    assert_eq!(
        Topic::Checkpoints.protocol_string(),
        "/neutrin0/checkpoints/borsh"
    );
    assert_eq!(
        Topic::Receipts.protocol_string(),
        "/neutrin0/receipts/borsh"
    );
    assert_eq!(
        Topic::FinalityVotesPrevote.protocol_string(),
        "/neutrin0/finality_votes_prevote/borsh"
    );
    assert_eq!(
        Topic::FinalityVotesPrecommit.protocol_string(),
        "/neutrin0/finality_votes_precommit/borsh"
    );
    assert_eq!(
        Topic::AggregateFinalityVotes(0).protocol_string(),
        "/neutrin0/aggregate_finality_votes_0/borsh"
    );
    assert_eq!(
        Topic::AggregateFinalityVotes(15).protocol_string(),
        "/neutrin0/aggregate_finality_votes_15/borsh"
    );
}

#[test]
fn static_topics_are_unique() {
    let strings: Vec<_> = Topic::all_default().map(Topic::protocol_string).collect();
    let mut sorted = strings.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), strings.len());
}

#[test]
fn max_transmit_sizes_match_doc_06() {
    assert_eq!(Topic::Blocks.max_transmit_size(), 18 * 1024 * 1024);
    assert_eq!(Topic::Receipts.max_transmit_size(), 2 * 1024 * 1024);
    assert_eq!(Topic::ChunkProofs.max_transmit_size(), 8 * 1024 * 1024);
    assert_eq!(Topic::Checkpoints.max_transmit_size(), 1024);
    assert_eq!(
        Topic::FinalityVotesPrevote.max_transmit_size(),
        8 * 1024 * 1024
    );
    assert_eq!(
        Topic::FinalityVotesPrecommit.max_transmit_size(),
        8 * 1024 * 1024
    );
    assert_eq!(
        Topic::AggregateFinalityVotes(0).max_transmit_size(),
        8 * 1024 * 1024
    );
    assert_eq!(Topic::Transactions.max_transmit_size(), 128 * 1024);
    assert_eq!(Topic::SlashingEvidence.max_transmit_size(), 8 * 1024 * 1024);
}

#[test]
fn default_topic_set_includes_all_aggregate_subnets() {
    let topics: Vec<_> = Topic::all_default().collect();
    assert!(topics.contains(&Topic::AggregateFinalityVotes(0)));
    assert!(topics.contains(&Topic::AggregateFinalityVotes(15)));
    assert!(!topics.contains(&Topic::AggregateFinalityVotes(16)));
    assert_eq!(
        topics.len(),
        Topic::STATIC.len() + usize::from(VOTE_SUBNETS)
    );
}
