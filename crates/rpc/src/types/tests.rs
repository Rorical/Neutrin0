use super::*;
use crate::backend::BlockId;

#[test]
fn hash_hex_round_trips_through_json() {
    let h = HashHex([0x12; 32]);
    let s = serde_json::to_string(&h).unwrap();
    assert!(s.starts_with("\"0x"));
    let back: HashHex = serde_json::from_str(&s).unwrap();
    assert_eq!(back, h);
}

#[test]
fn bytes_hex_round_trips_through_json() {
    let b = BytesHex(vec![1, 2, 3, 4]);
    let s = serde_json::to_string(&b).unwrap();
    assert_eq!(s, "\"0x01020304\"");
    let back: BytesHex = serde_json::from_str(&s).unwrap();
    assert_eq!(back, b);
}

#[test]
fn bytes_hex_keeps_lowercase_and_empty_forms() {
    let b = BytesHex(vec![0xAB, 0x00, 0xFF]);
    assert_eq!(serde_json::to_string(&b).unwrap(), "\"0xab00ff\"");
    let empty = serde_json::to_string(&BytesHex::default()).unwrap();
    assert_eq!(empty, "\"0x\"");
    for json in ["\"0x\"", "\"\""] {
        let back: BytesHex = serde_json::from_str(json).unwrap();
        assert_eq!(back, BytesHex::default());
    }
    let back: BytesHex = serde_json::from_str("\"AB00ff\"").unwrap();
    assert_eq!(back, b);
    assert!(serde_json::from_str::<BytesHex>("\"0xabc\"").is_err());
}

#[test]
fn block_id_deserialises_latest() {
    let bid: BlockIdJson = serde_json::from_str("\"latest\"").unwrap();
    assert_eq!(bid.0, BlockId::Latest);
}

#[test]
fn block_id_deserialises_safe_and_refuses_pending() {
    let bid: BlockIdJson = serde_json::from_str("\"safe\"").unwrap();
    assert_eq!(bid.0, BlockId::Safe);
    assert_eq!(serde_json::to_string(&bid).unwrap(), "\"safe\"");
    // Native queries read executed blocks only; "pending" is Ethereum's
    // simulated next block and has no native meaning.
    assert!(serde_json::from_str::<BlockIdJson>("\"pending\"").is_err());
}

#[test]
fn block_id_deserialises_finalized() {
    let bid: BlockIdJson = serde_json::from_str("\"finalized\"").unwrap();
    assert_eq!(bid.0, BlockId::Finalized);
}

#[test]
fn block_id_deserialises_height_number() {
    let bid: BlockIdJson = serde_json::from_str("42").unwrap();
    assert_eq!(bid.0, BlockId::Height(42));
}

#[test]
fn block_id_deserialises_height_decimal_string() {
    let bid: BlockIdJson = serde_json::from_str("\"100\"").unwrap();
    assert_eq!(bid.0, BlockId::Height(100));
}

#[test]
fn block_id_deserialises_hex_hash() {
    let hex_hash = format!("\"0x{}\"", hex::encode([0xAB; 32]));
    let bid: BlockIdJson = serde_json::from_str(&hex_hash).unwrap();
    assert_eq!(bid.0, BlockId::Hash([0xAB; 32]));
}

#[test]
fn block_id_defaults_to_latest_on_null() {
    let bid: BlockIdJson = serde_json::from_str("null").unwrap();
    assert_eq!(bid.0, BlockId::Latest);
}
