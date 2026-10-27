use super::*;

#[test]
fn all_columns_has_every_variant_once() {
    assert_eq!(ALL_COLUMNS.len(), 42);
    for (index, left) in ALL_COLUMNS.iter().enumerate() {
        for right in &ALL_COLUMNS[index + 1..] {
            assert_ne!(left, right, "duplicate column {left:?}");
        }
    }
}

#[test]
fn column_names_match_design_doc() {
    let names: [&str; 42] = [
        "trie_nodes",
        "state_values",
        "blocks",
        "execution_transactions",
        "headers",
        "header_by_height",
        "header_by_slot",
        "chunks",
        "block_proofs",
        "block_receipts",
        "block_states",
        "chunk_proofs",
        "chunk_receipts",
        "witnesses",
        "state_diffs",
        "validator_set_snap",
        "finalized",
        "slashing_pool",
        "meta",
        "chunk_statements",
        "consensus_boundaries",
        "historical_chunks",
        "history_nodes",
        "history_frontiers",
        "history_paths",
        "finalized_offences",
        "finalized_slashes",
        "evidence_proofs",
        "signing_journal",
        "bft_sessions",
        "signed_artifacts",
        "signed_artifact_index",
        "reporter_history",
        "reporter_sources",
        "reporter_headers",
        "reporter_boundaries",
        "reporter_validators",
        "reporter_index",
        "state_refs",
        "state_pins",
        "state_releases",
        "abandoned_headers",
    ];
    for (column, expected) in ALL_COLUMNS.iter().zip(names) {
        assert_eq!(column.name(), expected);
    }
}
