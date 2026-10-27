use super::*;
use sp1_sdk::SP1ProofWithPublicValues;

#[test]
fn malformed_upstream_receipts_cannot_unwind_out_of_host_decode() {
    let mut bytes = 1_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xFF; 128]);
    // The pinned field decoder asserts on a noncanonical u32. Prove that
    // this fixture reaches the assertion, then check both public wrappers.
    assert!(
        guarded(|| {
            neutrin0_prover_chunk::receipt_codec::decode::<SP1ProofWithPublicValues, 256>(&bytes)
        })
        .is_err()
    );
    assert!(
        Sp1BlockProof {
            bytes: bytes.clone()
        }
        .to_sp1()
        .is_err()
    );
    assert!(proof_system::Sp1ChunkProof { bytes }.to_sp1().is_err());
}

#[test]
fn a_receipt_has_one_accepted_encoding() {
    let mut bundle = SP1ProofWithPublicValues {
        proof: sp1_sdk::SP1Proof::Core(Vec::new()),
        public_values: sp1_sdk::SP1PublicValues::new(),
        sp1_version: String::new(),
        tee_proof: None,
    };
    let canonical = Sp1BlockProof::from_sp1(&bundle).unwrap();
    assert!(canonical.to_sp1().is_ok());
    // Verification ignores the attestation, so it must not mint new
    // byte identities for one proof.
    bundle.tee_proof = Some(vec![1]);
    let attested = Sp1BlockProof::from_sp1(&bundle).unwrap();
    assert_ne!(attested, canonical);
    assert!(attested.to_sp1().is_err());
}

#[test]
fn errors_implement_std_error() {
    let err = Sp1HostError::Codec("nope".into());
    let _: &dyn std::error::Error = &err;
}
