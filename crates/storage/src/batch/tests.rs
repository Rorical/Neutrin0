use super::*;

#[test]
fn batch_records_operations_in_order() {
    let mut batch = Batch::with_capacity(2);
    assert!(batch.is_empty());
    batch.put(Column::Meta, b"a".to_vec(), b"1".to_vec());
    batch.delete(Column::Meta, b"b".to_vec());
    assert_eq!(batch.len(), 2);
    assert!(matches!(batch.operations()[0], BatchOp::Put { .. }));
    assert!(matches!(batch.operations()[1], BatchOp::Delete { .. }));
}

#[test]
fn into_operations_preserves_exact_payloads() {
    let mut batch = Batch::new();
    batch.put(Column::TrieNodes, vec![0, 1, 2], vec![3, 4, 5]);
    batch.delete(Column::TrieNodes, vec![9, 8, 7]);

    let ops = batch.into_operations();
    assert_eq!(
        ops,
        vec![
            BatchOp::Put {
                column: Column::TrieNodes,
                key: vec![0, 1, 2],
                value: vec![3, 4, 5],
            },
            BatchOp::Delete {
                column: Column::TrieNodes,
                key: vec![9, 8, 7],
            },
        ]
    );
}

#[test]
fn cloned_batch_is_equal_to_original() {
    let mut batch = Batch::new();
    batch.put(
        Column::StateValues,
        b"value-hash".to_vec(),
        b"value".to_vec(),
    );
    assert_eq!(batch.clone(), batch);
}
