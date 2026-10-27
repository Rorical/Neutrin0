use super::*;
fn log(signature: &str, topics: Vec<String>, data: &[u8]) -> IndexedLog {
    IndexedLog {
        transaction_position: 0,
        transaction_hash: hex(&[1; 32]),
        index: 7,
        address: hex(&[3; 20]),
        topics: std::iter::once(hex(&neutrin0_crypto::keccak256(signature.as_bytes())))
            .chain(topics)
            .collect(),
        data: hex(data),
    }
}
fn address(byte: u8) -> String {
    let mut word = [0; 32];
    word[12..].fill(byte);
    hex(&word)
}
#[test]
fn lossless_maximum_fungible_amount_and_mint_address() {
    let decoded = decode(&log(
        "Transfer(address,address,uint256)",
        vec![address(0), address(2)],
        &[255; 32],
    ))
    .unwrap();
    assert_eq!(decoded[0].amount, U256::MAX.to_string());
    assert_eq!(decoded[0].from, hex(&[0; 20]));
    assert_eq!(decoded[0].standard, "ERC20");
    assert!(decoded[0].token_id.is_none());
}
#[test]
fn nft_maximum_id_and_burn_address() {
    let decoded = decode(&log(
        "Transfer(address,address,uint256)",
        vec![address(2), address(0), hex(&[255; 32])],
        &[],
    ))
    .unwrap();
    assert_eq!(
        decoded[0].token_id.as_deref(),
        Some(U256::MAX.to_string().as_str())
    );
    assert_eq!(decoded[0].amount, "1");
    assert_eq!(decoded[0].to, hex(&[0; 20]));
    assert_eq!(decoded[0].standard, "ERC721");
}
#[test]
fn multi_token_single_decodes_distinct_identity_and_quantity() {
    let mut data = U256::from(13).to_be_bytes::<32>().to_vec();
    data.extend([255; 32]);
    let decoded = decode(&log(
        "TransferSingle(address,address,address,uint256,uint256)",
        vec![address(1), address(2), address(3)],
        &data,
    ))
    .unwrap();
    assert_eq!(decoded[0].token_id.as_deref(), Some("13"));
    assert_eq!(decoded[0].amount, U256::MAX.to_string());
}
#[test]
fn batch_offsets_lengths_and_positions_are_checked() {
    let mut data = vec![];
    for value in [64, 160, 2, 7, 8, 2, 9, 10] {
        data.extend(U256::from(value).to_be_bytes::<32>());
    }
    let mut event = log(
        "TransferBatch(address,address,address,uint256[],uint256[])",
        vec![address(1), address(2), address(3)],
        &data,
    );
    let rows = decode(&event).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].item_index, 1);
    assert_eq!(rows[1].token_id.as_deref(), Some("8"));
    assert_eq!(rows[1].amount, "10");
    data[63] = 128;
    event.data = hex(&data);
    assert!(decode(&event).unwrap().is_empty());
    data[63] = 160;
    data.extend([0; 32]);
    event.data = hex(&data);
    assert!(decode(&event).unwrap().is_empty());
    data[..32].fill(255);
    event.data = hex(&data);
    assert!(decode(&event).unwrap().is_empty());
}
#[test]
fn malformed_or_ambiguous_shapes_remain_plain_logs() {
    let event = log(
        "Transfer(address,address,uint256)",
        vec![address(1), address(2), hex(&[0; 32])],
        &[0; 32],
    );
    assert!(decode(&event).unwrap().is_empty());
    let event = log(
        "Transfer(address,address,uint256)",
        vec![hex(&[255; 32]), address(2)],
        &[0; 32],
    );
    assert!(decode(&event).unwrap().is_empty());
}
