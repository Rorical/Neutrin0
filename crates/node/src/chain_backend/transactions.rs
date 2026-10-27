//! Canonical mempool maintenance after a durable head change.
use neutrin0_consensus_engine::Engine;
use neutrin0_primitives::{Hash, blake3_256};
use neutrin0_runtime_abi::RuntimeTransaction;
use neutrin0_storage::Database;

/// Recover bounded user payloads from the orphan branch and identifiers mined
/// on the replacement branch. The caller holds the engine lock; pool mutation
/// happens only after releasing it.
pub(super) fn branch_changes<DB: Database>(
    engine: &Engine<DB>,
    previous: Hash,
) -> (Vec<Vec<u8>>, Vec<Hash>) {
    let mut old = previous;
    let mut orphaned = Vec::new();
    let mut retained_bytes = 0_usize;
    while old != engine.chain_spec().genesis_block_hash {
        let Ok(Some(header)) = engine.store().get_header(&old) else {
            break;
        };
        if engine
            .store()
            .get_block_hash_by_height(header.height)
            .ok()
            .flatten()
            == Some(old)
        {
            break;
        }
        if let Ok(Some(body)) = engine.store().get_body(&old) {
            let mut users = Vec::new();
            for bytes in body.transactions {
                if retained_bytes.saturating_add(bytes.len()) <= 32 * 1024 * 1024
                    && matches!(
                        borsh::from_slice::<RuntimeTransaction>(&bytes),
                        Ok(RuntimeTransaction::User(_))
                    )
                {
                    retained_bytes += bytes.len();
                    users.push(bytes);
                }
            }
            orphaned.push(users);
        }
        old = header.parent_hash;
    }
    let mut head = engine.head_hash();
    let mut mined = Vec::new();
    while head != old && head != engine.chain_spec().genesis_block_hash {
        let Ok(Some(header)) = engine.store().get_header(&head) else {
            break;
        };
        if let Ok(Some(body)) = engine.store().get_body(&head) {
            mined.extend(body.transactions.iter().map(|bytes| blake3_256(bytes)));
        }
        head = header.parent_hash;
    }
    // Restore oldest first, so each sender's transactions return in nonce
    // order.
    (orphaned.into_iter().rev().flatten().collect(), mined)
}
