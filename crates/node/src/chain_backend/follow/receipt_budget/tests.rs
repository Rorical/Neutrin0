use super::*;

#[test]
fn a_block_verifies_a_bounded_number_of_distinct_receipts() {
    let mut budget = ReceiptBudget::default();
    let block = [1; 32];
    for byte in 0..u8::try_from(RECEIPTS_PER_BLOCK).unwrap() {
        assert!(budget.admit(block, [byte; 32]));
    }
    assert!(!budget.admit(block, [0xFF; 32]));
    // Bytes already counted, and other blocks, are unaffected.
    assert!(budget.admit(block, [0; 32]));
    assert!(budget.admit([2; 32], [0xFF; 32]));
}
