use super::*;
use crate::ProposerKey;
use neutrin0_primitives::Validator;

const fn test_domain(chain_id: u64) -> ConsensusDomain {
    ConsensusDomain::new(chain_id, [9; 32])
}

fn validator_with_pubkey(pubkey: BlsPublicKey, stake: u128) -> Validator {
    Validator {
        pubkey,
        withdrawal_credentials: [0; 32],
        effective_stake: stake,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

fn sample_header(proposer_index: u32, signature: [u8; 96]) -> Header {
    Header {
        height: 1,
        slot: 1,
        parent_hash: [0; 32],
        proposer_index,
        vrf_proof: [0; 96],
        state_root: [0; 32],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        inputs_root: [0; 32],
        receipts_root: [0; 32],
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: 0,
        signature,
    }
}

#[test]
fn round_trip_signed_header_verifies() {
    let proposer = ProposerKey::from_ikm(&[0xAA; 32], 0).expect("derive");
    let active_set = [validator_with_pubkey(*proposer.public_key_bytes(), 100)];

    // Build a header, hash it without the signature, sign, write back.
    let mut header = sample_header(0, [0; 96]);
    let header_hash = header.hash();
    header.signature = proposer.sign_proposer_message(test_domain(7), &header_hash);

    let validator =
        verify_header_signature(&header, &active_set, test_domain(7)).expect("verifies");
    assert_eq!(validator.pubkey, *proposer.public_key_bytes());
}

#[test]
fn rejects_out_of_range_proposer_index() {
    let active_set = [validator_with_pubkey([0; 48], 100)];
    let header = sample_header(7, [0; 96]);
    assert_eq!(
        verify_header_signature(&header, &active_set, test_domain(1)),
        Err(SignatureError::ValidatorIndexOutOfBounds { index: 7, len: 1 })
    );
}

#[test]
fn rejects_signature_under_wrong_chain_id() {
    let proposer = ProposerKey::from_ikm(&[0xBB; 32], 0).expect("derive");
    let active_set = [validator_with_pubkey(*proposer.public_key_bytes(), 100)];
    let mut header = sample_header(0, [0; 96]);
    let header_hash = header.hash();
    header.signature = proposer.sign_proposer_message(test_domain(7), &header_hash);

    assert_eq!(
        verify_header_signature(&header, &active_set, test_domain(99)),
        Err(SignatureError::BadSignature)
    );
}

#[test]
fn rejects_signature_under_another_spec_with_the_same_chain_id() {
    let proposer = ProposerKey::from_ikm(&[0xBB; 32], 0).expect("derive");
    let active_set = [validator_with_pubkey(*proposer.public_key_bytes(), 100)];
    let mut header = sample_header(0, [0; 96]);
    let domain = test_domain(7);
    header.signature = proposer.sign_proposer_message(domain, &header.hash());
    verify_header_signature(&header, &active_set, domain).unwrap();
    let other_domain = ConsensusDomain {
        chain_spec_hash: [10; 32],
        ..domain
    };
    assert_eq!(
        verify_header_signature(&header, &active_set, other_domain),
        Err(SignatureError::BadSignature)
    );
}

#[test]
fn rejects_tampered_signature_bytes() {
    let proposer = ProposerKey::from_ikm(&[0xCC; 32], 0).expect("derive");
    let active_set = [validator_with_pubkey(*proposer.public_key_bytes(), 100)];
    let mut header = sample_header(0, [0; 96]);
    let header_hash = header.hash();
    header.signature = proposer.sign_proposer_message(test_domain(7), &header_hash);
    // Flip a bit in the signature.
    header.signature[0] ^= 0x80;

    match verify_header_signature(&header, &active_set, test_domain(7)) {
        // blst typically reports "BadSignature" for tampered
        // signatures; bytes that fail group-membership decoding
        // become InvalidSignatureBytes. Both indicate the same
        // forgery, so accept either failure mode.
        Err(SignatureError::BadSignature | SignatureError::InvalidSignatureBytes) => {}
        other => panic!("expected signature failure, got {other:?}"),
    }
}

#[test]
fn rejects_invalid_validator_pubkey_bytes() {
    let proposer = ProposerKey::from_ikm(&[0xDD; 32], 0).expect("derive");
    let active_set = [validator_with_pubkey([0xFF; 48], 100)];
    let mut header = sample_header(0, [0; 96]);
    let header_hash = header.hash();
    header.signature = proposer.sign_proposer_message(test_domain(7), &header_hash);

    match verify_header_signature(&header, &active_set, test_domain(7)) {
        Err(SignatureError::InvalidPublicKey { index: 0 }) => {}
        other => panic!("expected InvalidPublicKey, got {other:?}"),
    }
}
