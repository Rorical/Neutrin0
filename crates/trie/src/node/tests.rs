use super::*;
use neutrin0_primitives::ZERO_HASH;

fn sample_hash(byte: u8) -> Hash {
    [byte; 32]
}

#[test]
fn leaf_encode_decode_roundtrip() {
    let node = Node::Leaf {
        key_suffix: BitPath::from_key(&[0xAB, 0xCD]),
        value_hash: sample_hash(0x42),
    };
    let encoded = node.encode();
    let decoded = Node::decode(&encoded).expect("decode leaf");
    assert_eq!(decoded, node);
}

#[test]
fn branch_encode_decode_roundtrip() {
    let node = Node::Branch {
        left: sample_hash(0x11),
        right: ZERO_HASH,
    };
    let encoded = node.encode();
    assert_eq!(encoded.len(), 1 + 32 + 32);
    let decoded = Node::decode(&encoded).expect("decode branch");
    assert_eq!(decoded, node);
}

#[test]
fn extension_encode_decode_roundtrip() {
    let node = Node::Extension {
        prefix: BitPath::from_key(&[0xF0]).prefix(4),
        child: sample_hash(0x99),
    };
    let encoded = node.encode();
    let decoded = Node::decode(&encoded).expect("decode extension");
    assert_eq!(decoded, node);
}

#[test]
fn decode_rejects_unknown_tag() {
    assert_eq!(
        Node::decode(&[0x7F, 0, 0]),
        Err(TrieError::InvalidNodeTag(0x7F))
    );
}

#[test]
fn decode_rejects_empty_input() {
    assert_eq!(Node::decode(&[]), Err(TrieError::TruncatedNode));
}

#[test]
fn decode_rejects_truncated_branch() {
    let bytes = [NODE_TAG_BRANCH; 32];
    assert_eq!(Node::decode(&bytes), Err(TrieError::TruncatedNode));
}

#[test]
fn decode_rejects_trailing_branch_bytes() {
    let mut bytes = vec![NODE_TAG_BRANCH];
    bytes.extend_from_slice(&[0_u8; 64]);
    bytes.push(0); // one extra byte
    assert_eq!(Node::decode(&bytes), Err(TrieError::TrailingNodeBytes));
}

#[test]
fn decode_rejects_trailing_leaf_bytes() {
    let node = Node::Leaf {
        key_suffix: BitPath::from_key(&[0xAB]),
        value_hash: sample_hash(0x01),
    };
    let mut encoded = node.encode();
    encoded.push(0xCC);
    assert_eq!(Node::decode(&encoded), Err(TrieError::TrailingNodeBytes));
}

#[test]
fn distinct_tags_yield_distinct_encodings() {
    let leaf = Node::Leaf {
        key_suffix: BitPath::empty(),
        value_hash: ZERO_HASH,
    };
    let branch = Node::Branch {
        left: ZERO_HASH,
        right: ZERO_HASH,
    };
    let ext = Node::Extension {
        prefix: BitPath::from_key(&[0]).prefix(1),
        child: ZERO_HASH,
    };
    assert_ne!(leaf.encode()[0], branch.encode()[0]);
    assert_ne!(leaf.encode()[0], ext.encode()[0]);
    assert_ne!(branch.encode()[0], ext.encode()[0]);
}
