use super::*;

#[test]
fn transaction_validity_round_trips_fixed_encoding() {
    let validity = TxValidity::valid(42);
    let encoded = validity.encode();
    assert_eq!(encoded.len(), TX_VALIDITY_ENCODED_LEN);
    assert_eq!(TxValidity::decode(&encoded).unwrap(), validity);
}

#[test]
fn transaction_validity_rejects_unknown_code() {
    let mut encoded = TxValidity::invalid(TxValidationCode::BadSignature).encode();
    encoded[..4].copy_from_slice(&99u32.to_le_bytes());
    assert_eq!(
        TxValidity::decode(&encoded),
        Err(TxValidityDecodeError::UnknownCode { code: 99 })
    );
}

#[test]
fn query_request_round_trips_through_borsh() {
    let req = QueryRequest {
        method: "account_get".into(),
        args: vec![1, 2, 3, 4],
    };
    let bytes = borsh::to_vec(&req).expect("encode");
    let decoded: QueryRequest = borsh::from_slice(&bytes).expect("decode");
    assert_eq!(decoded, req);
}

#[test]
fn query_response_round_trips_through_borsh() {
    let resp = QueryResponse::ok(vec![9, 8, 7]);
    let bytes = borsh::to_vec(&resp).expect("encode");
    let decoded: QueryResponse = borsh::from_slice(&bytes).expect("decode");
    assert_eq!(decoded, resp);
    assert!(decoded.is_ok());
}

#[test]
fn query_status_codes_are_stable() {
    assert_eq!(QueryStatus::Ok.as_u32(), 0);
    assert_eq!(QueryStatus::UnknownMethod.as_u32(), 1);
    assert_eq!(QueryStatus::InvalidArguments.as_u32(), 2);
    assert_eq!(QueryStatus::MethodError.as_u32(), 3);
    assert_eq!(QueryStatus::PermissionDenied.as_u32(), 4);
}

#[test]
fn query_response_err_carries_message_payload() {
    let resp = QueryResponse::err(QueryStatus::UnknownMethod, b"no such method".to_vec());
    assert_eq!(resp.code, QueryStatus::UnknownMethod.as_u32());
    assert_eq!(resp.payload, b"no such method".to_vec());
    assert!(!resp.is_ok());
}

#[test]
fn state_witness_round_trips_through_borsh() {
    let witness = StateWitness {
        pre_state_root: [7; 32],
        nodes: vec![TrieNodeBytes {
            hash: [1; 32],
            bytes: b"node-bytes".to_vec(),
        }],
        values: vec![TrieValueBytes {
            hash: [2; 32],
            bytes: b"value-bytes".to_vec(),
        }],
        witnessed_keys: vec![b"k".to_vec()],
    };
    let bytes = borsh::to_vec(&witness).expect("encode");
    let decoded: StateWitness = borsh::from_slice(&bytes).expect("decode");
    assert_eq!(decoded, witness);
}
