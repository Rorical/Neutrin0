use super::*;
use neutrin0_primitives::blake3_256;
use neutrin0_runtime_abi::TxValidity;

#[test]
fn a_head_rollback_cannot_erase_the_executable_reserve() {
    let mut pool = Mempool::with_account_limits(100, 50, 32);
    for account in 1..=2_u8 {
        let mut validity = admitted(1, 1000, 100);
        let dependency = validity.dependency.as_mut().unwrap();
        dependency.account = [account; 32];
        dependency.state_nonce = 1;
        pool.insert_admitted(tx(account, 50), validity).unwrap();
    }
    assert_eq!(pool.total_bytes(), 100);
    revalidate(&mut pool, |bytes| {
        let mut validity = admitted(1, 1000, 100);
        validity.dependency.as_mut().unwrap().account = [bytes[0]; 32];
        Some(validity)
    });
    assert_eq!(pool.total_bytes(), 50);
    let mut ready = admitted(0, 1, 0);
    ready.dependency.as_mut().unwrap().account = [3; 32];
    pool.insert_admitted(tx(3, 50), ready).unwrap();
    assert_eq!(pool.total_bytes(), 100);
}

#[test]
fn high_bid_future_nonces_cannot_consume_the_executable_reserve() {
    let mut pool = Mempool::with_account_limits(100, 50, 32);
    let future = pool
        .insert_admitted(tx(1, 50), admitted(1, 1000, 100))
        .unwrap();
    let mut other = admitted(1, 1000, 100);
    other.dependency.as_mut().unwrap().account = [2; 32];
    assert_eq!(
        pool.insert_admitted(tx(2, 1), other),
        Err(InsertError::CapacityExceeded)
    );
    other.dependency.as_mut().unwrap().nonce = 0;
    other.dependency.as_mut().unwrap().fee_cap = 1;
    other.priority = 0;
    pool.insert_admitted(tx(3, 50), other).unwrap();
    assert!(pool.contains(&future));
    assert_eq!(pool.total_bytes(), 100);
}

#[test]
fn queued_bids_never_evict_executable_entries() {
    let mut pool = Mempool::with_account_limits(100, 60, 32);
    let mut ready = admitted(0, 1, 0);
    ready.dependency.as_mut().unwrap().account = [2; 32];
    let executable = pool.insert_admitted(tx(2, 60), ready).unwrap();
    let held = pool
        .insert_admitted(tx(1, 40), admitted(1, 1000, 100))
        .unwrap();
    let mut gap = admitted(1, 1000, 50);
    gap.dependency.as_mut().unwrap().account = [3; 32];
    assert_eq!(
        pool.insert_admitted(tx(3, 10), gap),
        Err(InsertError::CapacityExceeded)
    );
    assert!(pool.contains(&executable));
    // An executable bid evicts queued work before a cheaper executable entry.
    let mut better = admitted(0, 2000, 300);
    better.dependency.as_mut().unwrap().account = [4; 32];
    pool.insert_admitted(tx(4, 30), better).unwrap();
    assert!(!pool.contains(&held));
    assert!(pool.contains(&executable));
}

#[test]
fn zero_fee_sequence_spam_cannot_pin_the_pool() {
    let mut pool = Mempool::with_account_limits(256 * 1024, 64 * 1024, 32);
    for nonce in 1..=64 {
        assert_eq!(
            pool.insert_admitted(
                vec![u8::try_from(nonce).unwrap(); 4200],
                admitted(nonce, 0, 0)
            ),
            Err(InsertError::ZeroFee)
        );
    }
    assert!(pool.is_empty());
    assert!(
        pool.insert_admitted(vec![99; 32 * 1024], admitted(0, 100, 0))
            .is_ok()
    );
}

#[test]
fn account_quotas_bound_future_sequences_without_blocking_other_accounts() {
    let mut pool = Mempool::with_account_limits(100, 40, 2);
    let first = pool.insert_admitted(tx(1, 20), admitted(1, 10, 1)).unwrap();
    pool.insert_admitted(tx(2, 20), admitted(2, 10, 1)).unwrap();
    assert_eq!(
        pool.insert_admitted(tx(3, 1), admitted(3, 10, 1)),
        Err(InsertError::AccountLimit)
    );
    let mut other = admitted(0, 10, 1);
    other.dependency.as_mut().unwrap().account = [2; 32];
    assert!(pool.insert_admitted(tx(4, 40), other).is_ok());
    assert!(pool.contains(&first));
    assert_eq!(pool.total_bytes(), 80);
}

#[test]
fn pressure_evicts_worse_bids_and_failed_admission_is_atomic() {
    let mut pool = Mempool::new(100);
    let low = pool.insert_with_priority(tx(1, 60), 1).unwrap();
    let high = pool.insert_with_priority(tx(2, 40), 10).unwrap();
    assert_eq!(
        pool.insert_with_priority(tx(3, 80), 5),
        Err(InsertError::CapacityExceeded)
    );
    assert!(pool.contains(&low));
    assert!(pool.contains(&high));
    let better = pool.insert_with_priority(tx(4, 50), 5).unwrap();
    assert!(!pool.contains(&low));
    assert!(pool.contains(&high));
    assert!(pool.contains(&better));
    assert_eq!(pool.total_bytes(), 90);
}

#[test]
fn zero_tip_higher_fee_cap_can_displace_underpriced_future_work() {
    let mut pool = Mempool::new(100);
    let mut cheap = admitted(1, 1, 0);
    let mut expensive = admitted(0, 100, 0);
    cheap.dependency.as_mut().unwrap().account = [2; 32];
    expensive.dependency.as_mut().unwrap().account = [3; 32];
    let old = pool.insert_admitted(tx(1, 100), cheap).unwrap();
    pool.insert_admitted(tx(2, 100), expensive).unwrap();
    assert!(!pool.contains(&old));
}

#[test]
fn duplicates_and_revalidation_do_not_extend_expiry() {
    let mut pool = Mempool::new(100);
    pool.expire(10, 30);
    let hash = pool.insert_admitted(tx(1, 20), admitted(0, 10, 1)).unwrap();
    pool.expire(20, 30);
    assert_eq!(
        pool.insert_admitted(tx(1, 20), admitted(0, 10, 1)),
        Err(InsertError::Duplicate)
    );
    revalidate(&mut pool, |_| Some(admitted(0, 10, 1)));
    pool.expire(39, 30);
    assert!(pool.contains(&hash));
    pool.expire(40, 30);
    assert!(pool.is_empty());
    assert_eq!(pool.total_bytes(), 0);
}

#[test]
fn verdicts_reached_outside_the_pool_spare_entries_admitted_meanwhile() {
    let mut pool = Mempool::new(100);
    let mut rejected = admitted(0, 10, 1);
    rejected.code = neutrin0_runtime_abi::TxValidationCode::NonceMismatch;
    let stale = pool.insert_admitted(tx(1, 20), admitted(0, 10, 1)).unwrap();
    let snapshot = pool.validation_snapshot();
    let mut later = admitted(0, 10, 1);
    later.dependency.as_mut().unwrap().account = [2; 32];
    let fresh = pool.insert_admitted(tx(2, 20), later).unwrap();
    pool.apply_validation(snapshot.into_iter().map(|(hash, _)| (hash, rejected)));
    assert!(!pool.contains(&stale));
    assert!(pool.contains(&fresh));
    assert_eq!(pool.total_bytes(), 20);
}

/// Validate every entry against one head and apply the verdicts.
fn revalidate(pool: &mut Mempool, mut validate: impl FnMut(&[u8]) -> Option<TxValidity>) {
    let verdicts: Vec<_> = pool
        .validation_snapshot()
        .into_iter()
        .filter_map(|(hash, bytes)| validate(&bytes).map(|validity| (hash, validity)))
        .collect();
    pool.apply_validation(verdicts);
}

fn tx(byte: u8, len: usize) -> Vec<u8> {
    vec![byte; len]
}

fn admitted(nonce: u64, fee: u128, tip: u128) -> TxValidity {
    TxValidity {
        code: neutrin0_runtime_abi::TxValidationCode::Valid,
        priority: u64::try_from(tip).unwrap(),
        dependency: Some(TransactionDependency {
            identifier: [0; 32],
            account: [1; 32],
            nonce,
            state_nonce: 0,
            fee_cap: fee,
            tip_cap: tip,
            gas_limit: 21_000,
        }),
    }
}

#[test]
fn nonce_dependencies_override_priority_without_drain() {
    let mut pool = Mempool::new(100);
    let second = pool.insert_admitted(vec![2], admitted(1, 100, 50)).unwrap();
    assert_eq!(pool.candidates(100), [] as [MempoolEntry; 0]);
    let first = pool.insert_admitted(vec![1], admitted(0, 100, 10)).unwrap();
    assert_eq!(
        pool.candidates(100)
            .iter()
            .map(|entry| entry.hash)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert_eq!(pool.pending_nonce([1; 32], 0), 2);
    assert_eq!(pool.len(), 2);
    revalidate(&mut pool, |bytes| {
        let mut validity = admitted(u64::from(bytes[0] - 1), 100, 10);
        validity.dependency.as_mut().unwrap().state_nonce = 1;
        if bytes[0] == 1 {
            validity.code = neutrin0_runtime_abi::TxValidationCode::NonceMismatch;
        }
        Some(validity)
    });
    assert_eq!(
        pool.candidates(100)
            .iter()
            .map(|entry| entry.hash)
            .collect::<Vec<_>>(),
        vec![second]
    );
}

#[test]
fn replacement_checks_both_caps_and_preserves_old_on_failure() {
    let mut pool = Mempool::new(1);
    let old = pool.insert_admitted(vec![1], admitted(0, 100, 10)).unwrap();
    assert_eq!(
        pool.insert_admitted(vec![2], admitted(0, 110, 10)),
        Err(InsertError::ReplacementUnderpriced)
    );
    assert_eq!(
        pool.insert_admitted(vec![2], admitted(0, 109, 11)),
        Err(InsertError::ReplacementUnderpriced)
    );
    assert!(pool.contains(&old));
    let new = pool.insert_admitted(vec![2], admitted(0, 110, 11)).unwrap();
    assert!(!pool.contains(&old));
    assert!(pool.contains(&new));
    assert_eq!(pool.total_bytes(), 1);
}

#[test]
fn new_mempool_is_empty() {
    let pool = Mempool::new(1024);
    assert_eq!(pool.len(), 0);
    assert!(pool.is_empty());
    assert_eq!(pool.total_bytes(), 0);
    assert_eq!(pool.capacity_bytes(), 1024);
}

#[test]
fn insert_returns_blake3_hash() {
    let mut pool = Mempool::new(1024);
    let bytes = tx(0xAB, 32);
    let expected = blake3_256(&bytes);
    let got = pool.insert(bytes).expect("insert");
    assert_eq!(got, expected);
    assert!(pool.contains(&expected));
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.total_bytes(), 32);
    assert_eq!(pool.iter().next().expect("entry").priority, 0);
}

#[test]
fn explicit_priority_orders_highest_first_with_fifo_ties() {
    let mut pool = Mempool::new(1024);
    let low = pool.insert_with_priority(tx(1, 8), 1).unwrap();
    let high_a = pool.insert_with_priority(tx(2, 8), 9).unwrap();
    let mid = pool.insert_with_priority(tx(3, 8), 5).unwrap();
    let high_b = pool.insert_with_priority(tx(4, 8), 9).unwrap();

    let order: Vec<_> = pool.iter().map(|entry| entry.hash).collect();
    assert_eq!(order, vec![high_a, high_b, mid, low]);
}

#[test]
fn duplicate_insert_is_rejected() {
    let mut pool = Mempool::new(1024);
    let bytes = tx(1, 16);
    pool.insert(bytes.clone()).expect("first insert");
    assert_eq!(pool.insert(bytes), Err(InsertError::Duplicate));
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.total_bytes(), 16);
}

#[test]
fn insert_larger_than_capacity_is_rejected() {
    let mut pool = Mempool::new(32);
    assert_eq!(pool.insert(tx(2, 33)), Err(InsertError::TooLarge));
    assert!(pool.is_empty());
    assert_eq!(pool.total_bytes(), 0);
}

#[test]
fn insert_zero_capacity_rejects_any_nonempty_tx() {
    let mut pool = Mempool::new(0);
    assert_eq!(pool.insert(tx(0, 1)), Err(InsertError::TooLarge));
}

#[test]
fn insert_that_overflows_pool_is_rejected_without_eviction() {
    let mut pool = Mempool::new(48);
    pool.insert(tx(1, 32)).expect("first fits");
    assert_eq!(pool.insert(tx(2, 17)), Err(InsertError::CapacityExceeded));
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.total_bytes(), 32);
}

#[test]
fn insert_that_exactly_fills_pool_is_accepted() {
    let mut pool = Mempool::new(64);
    pool.insert(tx(1, 32)).unwrap();
    pool.insert(tx(2, 32)).unwrap();
    assert_eq!(pool.total_bytes(), 64);
    assert_eq!(pool.len(), 2);
}

#[test]
fn iter_yields_insertion_order() {
    let mut pool = Mempool::new(1024);
    let a = pool.insert(tx(1, 8)).unwrap();
    let b = pool.insert(tx(2, 8)).unwrap();
    let c = pool.insert(tx(3, 8)).unwrap();
    let hashes: Vec<_> = pool.iter().map(|e| e.hash).collect();
    assert_eq!(hashes, vec![a, b, c]);
}

#[test]
fn remove_known_hash_returns_entry_and_updates_size() {
    let mut pool = Mempool::new(1024);
    let bytes_a = tx(1, 16);
    let bytes_b = tx(2, 24);
    let a = pool.insert(bytes_a.clone()).unwrap();
    let b = pool.insert(bytes_b).unwrap();
    let removed = pool.remove(&a).expect("present");
    assert_eq!(removed.hash, a);
    assert_eq!(removed.bytes, bytes_a);
    assert_eq!(pool.total_bytes(), 24);
    assert_eq!(pool.len(), 1);
    assert!(!pool.contains(&a));
    assert!(pool.contains(&b));
}

#[test]
fn remove_unknown_hash_returns_none() {
    let mut pool = Mempool::new(1024);
    pool.insert(tx(1, 16)).unwrap();
    let unknown = [0xFFu8; 32];
    assert!(pool.remove(&unknown).is_none());
    assert_eq!(pool.len(), 1);
}

#[test]
fn remove_preserves_fifo_order_for_remaining() {
    let mut pool = Mempool::new(1024);
    let a = pool.insert(tx(1, 8)).unwrap();
    let b = pool.insert(tx(2, 8)).unwrap();
    let c = pool.insert(tx(3, 8)).unwrap();
    pool.remove(&b).unwrap();
    let order: Vec<_> = pool.iter().map(|e| e.hash).collect();
    assert_eq!(order, vec![a, c]);
}

#[test]
fn reinsert_after_remove_succeeds() {
    let mut pool = Mempool::new(1024);
    let bytes = tx(1, 16);
    let h = pool.insert(bytes.clone()).unwrap();
    pool.remove(&h).unwrap();
    let h2 = pool.insert(bytes).unwrap();
    assert_eq!(h, h2);
    assert_eq!(pool.len(), 1);
}

#[test]
fn same_insert_sequence_yields_identical_order() {
    let inserts: Vec<Vec<u8>> = (0..16u8).map(|i| tx(i, 8 + usize::from(i % 3))).collect();

    let mut pool_a = Mempool::new(4096);
    let mut pool_b = Mempool::new(4096);
    for bytes in &inserts {
        pool_a.insert(bytes.clone()).unwrap();
        pool_b.insert(bytes.clone()).unwrap();
    }
    assert!(pool_a.iter().eq(pool_b.iter()));
}

#[test]
fn pool_invariants_hold_under_mixed_operations() {
    let mut pool = Mempool::new(256);
    let mut hashes = Vec::new();
    for i in 0..8u8 {
        let h = pool.insert(tx(i, 16)).unwrap();
        hashes.push(h);
    }
    // Three of the eight match: 4, 5, 6.
    for h in &hashes[4..7] {
        pool.remove(h).unwrap();
    }
    // Insert another transaction that fits in the freed budget.
    let new_h = pool.insert(tx(99, 32)).unwrap();

    // Invariants:
    // - total_bytes equals sum of entry sizes
    // - by_hash matches the queue contents exactly
    // - len matches by_hash size
    let queued: Vec<_> = pool.iter().map(|e| (e.hash, e.bytes.len())).collect();
    let sum: usize = queued.iter().map(|(_, len)| *len).sum();
    assert_eq!(pool.total_bytes(), sum);
    assert_eq!(pool.len(), queued.len());
    for (h, _) in &queued {
        assert!(pool.contains(h));
    }
    assert!(pool.contains(&new_h));
}
