use super::*;
use neutrin0_storage::MemoryDatabase;

fn signed_source() -> MemoryDatabase {
    let mut db = MemoryDatabase::new();
    db.put(Column::Meta, CHAIN_SPEC_HASH, &[7; 32]).unwrap();
    db.put(Column::SigningJournal, b"vote", b"intent").unwrap();
    db.put(Column::BftSessions, b"session", b"lock").unwrap();
    db.put(Column::Meta, POLICY_KEY, b"paused").unwrap();
    db
}

#[test]
fn transfer_reproduces_protection_and_never_merges() {
    let transfer = SigningTransfer::export(&signed_source()).unwrap();
    let mut target = MemoryDatabase::new();
    transfer.import(&mut target).unwrap();
    assert_eq!(
        target.get(Column::SigningJournal, b"vote").unwrap(),
        Some(b"intent".to_vec())
    );
    assert_eq!(
        target.get(Column::Meta, POLICY_KEY).unwrap(),
        Some(b"paused".to_vec())
    );
    // A second import would merge two histories of the same key.
    assert!(transfer.import(&mut target).is_err());
    assert_eq!(
        SigningTransfer::recorded_chain(&target).unwrap(),
        Some([7; 32])
    );
    assert_eq!(
        SigningTransfer::recorded_chain(&MemoryDatabase::new()).unwrap(),
        None
    );
}

#[test]
fn transfer_refuses_another_chain() {
    let transfer = SigningTransfer::export(&signed_source()).unwrap();
    let mut other = MemoryDatabase::new();
    other.put(Column::Meta, CHAIN_SPEC_HASH, &[8; 32]).unwrap();
    assert!(transfer.import(&mut other).is_err());
    assert!(SigningTransfer::export(&MemoryDatabase::new()).is_err());
}
