use super::*;

#[test]
fn from_key_lays_out_bits_msb_first() {
    let path = BitPath::from_key(&[0xC0]);
    assert_eq!(path.bit_len(), 8);
    assert!(path.bit(0));
    assert!(path.bit(1));
    assert!(!path.bit(2));
    assert!(!path.bit(7));
}

#[test]
fn empty_path_is_empty() {
    let p = BitPath::empty();
    assert!(p.is_empty());
    assert_eq!(p.bit_len(), 0);
    assert_eq!(p.as_bytes(), [] as [u8; 0]);
}

#[test]
fn prefix_truncates_and_clears_padding() {
    let path = BitPath::from_key(&[0xFF, 0xFF]);
    let p = path.prefix(3);
    assert_eq!(p.bit_len(), 3);
    assert_eq!(p.as_bytes(), &[0b1110_0000]);
}

#[test]
fn suffix_aligns_remaining_bits_to_msb() {
    let path = BitPath::from_key(&[0b1010_1100, 0b1100_0011]);
    let s = path.suffix(3);
    assert_eq!(s.bit_len(), 13);
    // Original bits 3..16 are 01100110_00011, MSB-aligned that becomes
    // 0110 0110 0001 1, packed as 0b0110_0110, 0b0001_1000.
    assert_eq!(s.as_bytes(), &[0b0110_0110, 0b0001_1000]);
    for i in 0..13 {
        assert_eq!(s.bit(i), path.bit(i + 3), "bit {i}");
    }
}

#[test]
fn suffix_full_length_is_empty() {
    let path = BitPath::from_key(&[0xAB, 0xCD]);
    assert!(path.suffix(16).is_empty());
}

#[test]
fn common_prefix_handles_byte_aligned_match() {
    let a = BitPath::from_key(&[0x12, 0x34, 0x56]);
    let b = BitPath::from_key(&[0x12, 0x34, 0xFF]);
    assert_eq!(a.common_prefix_len(&b), 16);
}

#[test]
fn common_prefix_handles_intra_byte_divergence() {
    let a = BitPath::from_key(&[0b1011_0000]);
    let b = BitPath::from_key(&[0b1010_0000]);
    // Disagree at bit 3.
    assert_eq!(a.common_prefix_len(&b), 3);
}

#[test]
fn common_prefix_handles_unequal_lengths() {
    let a = BitPath::from_key(&[0xAB]);
    let b = BitPath::from_key(&[0xAB, 0xCD]);
    assert_eq!(a.common_prefix_len(&b), 8);
}

#[test]
fn common_prefix_with_empty_is_zero() {
    let a = BitPath::empty();
    let b = BitPath::from_key(&[0xFF]);
    assert_eq!(a.common_prefix_len(&b), 0);
}

#[test]
fn encode_decode_roundtrip() {
    let path = BitPath::from_key(&[0xAA, 0xBB, 0xCC]).prefix(20);
    let mut buf = Vec::new();
    path.encode_into(&mut buf);
    let (decoded, consumed) = BitPath::decode(&buf).expect("decode");
    assert_eq!(consumed, buf.len());
    assert_eq!(decoded, path);
}

#[test]
fn decode_rejects_short_header() {
    assert_eq!(BitPath::decode(&[0, 0, 0]), Err(TrieError::TruncatedNode));
}

#[test]
fn decode_rejects_truncated_body() {
    // bit_len = 16 needs 2 body bytes; provide only 1.
    let bytes = [16, 0, 0, 0, 0xAA];
    assert_eq!(BitPath::decode(&bytes), Err(TrieError::TruncatedNode));
}

#[test]
fn decode_rejects_nonzero_padding() {
    // bit_len = 3 must have low five bits zero in the trailing byte.
    let bytes = [3, 0, 0, 0, 0b1110_0001];
    assert_eq!(BitPath::decode(&bytes), Err(TrieError::NonCanonicalBitPath));
}

/// Canonical paths of many lengths, taken at aligned and unaligned offsets.
fn sample_paths() -> Vec<BitPath> {
    let source = BitPath::from_key(&[0xA5, 0x3C, 0xFF, 0x00, 0x96, 0x71, 0x0E, 0xD2]);
    let mut paths = Vec::new();
    for start in [0, 1, 3, 7, 8, 9, 13] {
        for len in 0..=24 {
            paths.push(source.suffix(start).prefix(len));
        }
    }
    paths
}

#[test]
fn concat_preserves_the_ordered_bit_sequence() {
    let paths = sample_paths();
    for head in &paths {
        for tail in &paths {
            let joined = head.concat(tail);
            let expected: Vec<_> = (0..head.bit_len())
                .map(|i| head.bit(i))
                .chain((0..tail.bit_len()).map(|i| tail.bit(i)))
                .collect();
            let actual: Vec<_> = (0..joined.bit_len()).map(|i| joined.bit(i)).collect();
            assert_eq!(actual, expected, "{head:?} ++ {tail:?}");
            assert_eq!(joined.bit_len(), head.bit_len() + tail.bit_len());
            let mut bytes = Vec::new();
            joined.encode_into(&mut bytes);
            assert_eq!(BitPath::decode(&bytes).unwrap(), (joined, bytes.len()));
        }
    }
    for bit in [false, true] {
        let path = BitPath::single(bit);
        assert_eq!(path.bit_len(), 1);
        assert_eq!(path.as_bytes(), &[if bit { 0x80 } else { 0 }]);
    }
}

#[test]
fn matches_at_and_offset_suffixes_agree_with_allocating_slices() {
    let paths = sample_paths();
    let long = BitPath::from_key(&[0xA5, 0x3C, 0xFF, 0x00, 0x96]);
    for path in paths.iter().chain([&long]) {
        for offset in 0..=path.bit_len() {
            let rest = path.suffix(offset);
            for first in 0..=rest.bit_len() {
                assert_eq!(rest.suffix(first), path.suffix(offset + first));
            }
            for other in &paths {
                let expected = offset + other.bit_len() <= path.bit_len()
                    && rest.prefix(other.bit_len()) == *other;
                assert_eq!(path.matches_at(offset, other), expected);
            }
        }
        for other in &paths {
            assert!(!path.matches_at(path.bit_len() + 1, other));
            assert!(!path.matches_at(u32::MAX, other));
        }
    }
}

#[test]
fn for_key_prefixes_the_little_endian_key_length() {
    assert_eq!(
        BitPath::for_key(b"abc"),
        BitPath::from_key(&[3, 0, 0, 0, b'a', b'b', b'c'])
    );
    assert_eq!(BitPath::for_key(&[]), BitPath::from_key(&[0; 4]));
}

#[test]
fn debug_renders_bit_string() {
    let path = BitPath::from_key(&[0b1010_0000]).prefix(4);
    let s = alloc::format!("{path:?}");
    assert!(s.contains("1010"), "debug string was {s}");
}

#[test]
fn borsh_decoding_refuses_non_canonical_paths() {
    let path = BitPath::from_key(&[0xC0]).prefix(3);
    let encoded = borsh::to_vec(&path).unwrap();
    assert_eq!(borsh::from_slice::<BitPath>(&encoded).unwrap(), path);
    // More bits than bytes would let `bit` index past the buffer.
    let long = borsh::to_vec(&(9_u32, alloc::vec![0xC0_u8])).unwrap();
    assert!(borsh::from_slice::<BitPath>(&long).is_err());
    // Nonzero padding gives one path two encodings.
    let padded = borsh::to_vec(&(3_u32, alloc::vec![0xC1_u8])).unwrap();
    assert!(borsh::from_slice::<BitPath>(&padded).is_err());
}
