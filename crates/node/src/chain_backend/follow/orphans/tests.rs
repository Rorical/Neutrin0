use super::*;
use neutrin0_consensus_types::BlockReceipt;

fn source() -> Source {
    neutrin0_network::libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
}

fn receipt(block: u8, bytes: u8) -> BlockReceipt {
    BlockReceipt {
        block_hash: [block; 32],
        proof_bytes: vec![bytes; 8],
    }
}

#[test]
fn orphans_are_attributed_bounded_per_source_and_never_replaced() {
    let (honest, attacker) = (source(), source());
    let now = std::time::Instant::now();
    let ttl = std::time::Duration::from_secs(60);
    let mut orphans = OrphanReceipts::default();
    assert!(orphans.push(receipt(1, 1), honest, now, ttl, 4));
    // Another receipt of the same block joins it instead of replacing it,
    // and one source holds one slot of a block.
    assert!(orphans.push(receipt(1, 2), attacker, now, ttl, 4));
    assert!(!orphans.push(receipt(1, 3), attacker, now, ttl, 4));
    // One source cannot flush the others.
    for block in 2..=u8::try_from(MAX_ORPHANS_PER_SOURCE).unwrap() {
        assert!(orphans.push(receipt(block, 9), attacker, now, ttl, 4));
    }
    assert!(!orphans.push(receipt(200, 9), attacker, now, ttl, 4));
    let kept = orphans.take(&[1; 32]);
    assert_eq!(kept.len(), 2);
    assert!(kept.contains(&(honest, receipt(1, 1))));
    // A source whose receipt failed has its orphans refused.
    orphans.distrust(attacker, now);
    assert!(!orphans.push(receipt(201, 9), attacker, now, ttl, 4));
    assert!(orphans.push(receipt(201, 9), honest, now, ttl, 4));
}
