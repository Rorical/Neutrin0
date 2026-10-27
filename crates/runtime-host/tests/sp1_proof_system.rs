//! `Sp1ProofSystem` accepts a valid block proof produced by the EVM runtime
//! and rejects every kind of tampering the consensus engine cares about.
//!
//! Uses `MockProver` so the cryptographic step is skipped; the public-
//! output cross-check the adapter performs is what the consensus
//! engine relies on for the `Proven` gate.

#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use std::sync::OnceLock;

use neutrin0_consensus_types::BlockProofPublicInputs;

use neutrin0_primitives::ZERO_HASH;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_host::{ProverCtx, Sp1BlockProof, Sp1ProofSystem, dry_run, prove_with};
use sp1_sdk::blocking::{MockProver, ProverClient};

/// Attribution every receipt in this test names (design 08).
const PROVER_ADDRESS: [u8; 32] = [0x50; 32];

const CHAIN_ID: u64 = 7;

#[test]
fn receipt_codec_matches_sdk_wire_encoding() {
    let (wire, _) = build_block_proof(99);
    let mut proof = wire.to_sp1().unwrap();
    let path = std::env::temp_dir().join(format!("neutrin0-sdk-wire-{}.bin", std::process::id()));
    proof.save(&path).unwrap();
    let sdk_bytes = std::fs::read(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let wire = Sp1BlockProof::from_sp1(&proof).unwrap();
    assert_eq!(wire.bytes, sdk_bytes);
    let decoded = wire.to_sp1().unwrap();
    assert!(matches!(decoded.proof, sp1_sdk::SP1Proof::Compressed(_)));
    assert_eq!(
        decoded.public_values.as_slice(),
        proof.public_values.as_slice()
    );
    assert_eq!(decoded.sp1_version, sp1_sdk::SP1_CIRCUIT_VERSION);
    assert_eq!(
        neutrin0_prover_chunk::proof_verification::CIRCUIT_VERSION,
        sp1_sdk::SP1_CIRCUIT_VERSION
    );
    // Verification ignores a TEE attestation, so a receipt carrying one
    // would give one proof unboundedly many byte identities: it does not
    // decode.
    proof.tee_proof = Some(vec![4, 5]);
    assert!(Sp1BlockProof::from_sp1(&proof).unwrap().to_sp1().is_err());
}

static MOCK_CTX: OnceLock<ProverCtx<MockProver>> = OnceLock::new();

fn mock_ctx() -> &'static ProverCtx<MockProver> {
    MOCK_CTX.get_or_init(|| {
        let prover = ProverClient::builder().mock().build();
        ProverCtx::new(prover).expect("mock setup")
    })
}

/// Build a `BlockProofPublicInputs` whose Q2-bound fields match the
/// `RuntimeBlockOutput` the guest just committed.  Tests that intend the
/// happy path call this; tests that exercise individual cross-check
/// rejections mutate one field after constructing it.
fn matching_public_inputs(
    input: &RuntimeBlockInput,
    output: &neutrin0_runtime_abi::RuntimeBlockOutput,
) -> BlockProofPublicInputs {
    use sp1_sdk::HashableKey;
    BlockProofPublicInputs {
        context: Box::new(output.context),
        chain_id: input.chain_id,
        height: input.block_height,
        parent_block_hash: output.context.parent_block_hash,
        block_hash: ZERO_HASH,
        state_root_before: output.pre_state_root,
        state_root_after: output.post_state_root,
        transactions_root: output.transactions_root,
        receipt_root: output.receipts_root,
        da_root: ZERO_HASH,
        vm_code_hash: ZERO_HASH,
        block_program: mock_ctx().vk.hash_u32(),
        gas_used: output.gas_used,
        gas_limit: input.block_gas_limit,
        proposer_address: input.proposer_address,
        runtime_extra: output.consensus_candidates_root,
        inputs_root: neutrin0_prover_chunk::execution::output_inputs_root(output),
    }
}

fn build_block_proof(seed: u64) -> (Sp1BlockProof, BlockProofPublicInputs) {
    // Distinct seeds produce distinct blocks: the transfer's nonce selects
    // the transaction and therefore every commitment the proof carries.
    let live = support::fixture_genesis_live([1; 8], [4; 32], 30_000_000);
    let (_, mut input, _) = support::fixture([1; 8], [4; 32]);
    assert_eq!(input.chain_id, CHAIN_ID);
    input.context.finalized.programs.execution = Sp1ProofSystem::mock()
        .expect("mock program identities")
        .execution_programs();
    input.transactions = (0..=seed % 3).map(support::transfer).collect();
    let dry = dry_run(&input, &live, &[]).expect("native dry run");
    let bundle = prove_with(&mock_ctx().prover, &input, dry.witness, &[], PROVER_ADDRESS)
        .expect("mock prove succeeds")
        .proof;
    let sp1_bp = Sp1BlockProof::from_sp1(&bundle).expect("encode");
    let pi = matching_public_inputs(&input, &dry.output);
    (sp1_bp, pi)
}

/// A fresh SP1 proof with matching state
/// roots is accepted by `Sp1ProofSystem::verify_block`.
#[test]
fn sp1_proof_system_accepts_consistent_block_proof() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, pi) = build_block_proof(11);
    proof_system
        .verify_block(&proof, &pi)
        .expect("matching public inputs accepted");
}

/// A proof whose committed `pre_state_root`
/// differs from `public_inputs.state_root_before` is rejected with
/// `ProofError::PublicInputMismatch`.
#[test]
fn sp1_proof_system_rejects_pre_root_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(12);
    pi.state_root_before[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered pre_state_root must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// The same for the post-state root.
#[test]
fn sp1_proof_system_rejects_post_root_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(13);
    pi.state_root_after[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered post_state_root must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// A proof whose committed `gas_used` diverges from the consensus
/// public input is rejected with `PublicInputMismatch`. The fee
/// commit added the cross-check; this pins it.
#[test]
fn sp1_proof_system_rejects_gas_used_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(14);
    pi.gas_used = pi.gas_used.wrapping_add(1);
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered gas_used must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// Receipts-root tamper at the public-inputs side. The runtime
/// commits a specific receipts root inside the proof; flipping the
/// public-input field must reject.
#[test]
fn sp1_proof_system_rejects_receipt_root_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(15);
    pi.receipt_root[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered receipt_root must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn cached_block_verification_rejects_every_authenticated_context_field() {
    type Forgery = fn(&mut neutrin0_consensus_types::runtime::ConsensusExecutionContext);
    let forgeries: &[Forgery] = &[
        |context| context.slot += 1,
        |context| context.timestamp += 1,
        |context| context.parent_block_hash[0] ^= 1,
        |context| context.proposer_vrf_output[0] ^= 1,
        |context| context.finalized.seed[0] ^= 1,
        |context| context.finalized.next_chunk_id += 1,
        |context| context.finalized.height += 1,
        |context| context.finalized.slot += 1,
        |context| context.finalized.block_hash[0] ^= 1,
        |context| context.finalized.state_root[0] ^= 1,
        |context| context.finalized.validators_root[0] ^= 1,
        |context| context.finalized.history_root[0] ^= 1,
        |context| context.finalized.participation[0] ^= 1,
        |context| context.finalized.programs.runtime_code_hash[0] ^= 1,
        |context| context.finalized.programs.execution.fact[0] ^= 1,
        |context| context.finalized.programs.execution.evidence[0] ^= 1,
        |context| context.finalized.programs.execution.block[0] ^= 1,
    ];
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, original) = build_block_proof(151);
    proof_system.verify_block(&proof, &original).unwrap();
    for (index, forge) in forgeries.iter().enumerate() {
        let mut changed = original.clone();
        forge(&mut changed.context);
        assert_eq!(
            proof_system.verify_block(&proof, &changed),
            Err(ProofError::PublicInputMismatch),
            "context forgery {index}",
        );
    }
}

/// Q2 closure: each new input-binding field is independently
/// cross-checked.  Mutating any one of them on the verifier side
/// (after the proof is built against the legitimate values) must
/// fail with `PublicInputMismatch`.

#[test]
fn sp1_proof_system_rejects_chain_id_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(16);
    pi.chain_id ^= 0xFFFF_FFFF_FFFF_FFFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered chain_id must reject (cross-chain replay defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_height_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(17);
    pi.height = pi.height.wrapping_add(1);
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered height must reject (withdrawal-maturity acceleration defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_gas_limit_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(18);
    pi.gas_limit = pi.gas_limit.wrapping_add(1);
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered gas_limit must reject (block-gas-ceiling defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_proposer_address_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(20);
    pi.proposer_address[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered proposer_address must reject (fee-redirect defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_transactions_root_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(21);
    pi.transactions_root[0] ^= 0xFF;
    let err = proof_system.verify_block(&proof, &pi).expect_err(
        "tampered transactions_root must reject (forged-state-root-via-fake-txns defence)",
    );
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_runtime_extra_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(22);
    pi.runtime_extra[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered runtime_extra must reject (validator-set-divergence defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// Corrupted proof bytes are rejected with
/// `ProofError::MalformedProof` before any cryptographic work.
#[test]
fn sp1_proof_system_rejects_malformed_proof_bytes() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let bad_proof = Sp1BlockProof {
        bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let (_, pi) = build_block_proof(23);
    let err = proof_system
        .verify_block(&bad_proof, &pi)
        .expect_err("malformed bytes must reject");
    assert_eq!(err, ProofError::MalformedProof);
}

#[test]
fn startup_requires_the_exact_embedded_runtime_hash() {
    use neutrin0_runtime_host::{embedded_runtime_code_hash, expect_runtime_code_hash};
    let hash = embedded_runtime_code_hash();
    assert_eq!(expect_runtime_code_hash(hash), Ok(()));
    assert!(expect_runtime_code_hash(ZERO_HASH).is_err());
    let mut other = hash;
    other[0] ^= 1;
    assert!(expect_runtime_code_hash(other).is_err());
}

#[test]
fn governed_guest_install_rejects_unnamed_keys_without_mutating_registry() {
    let system = Sp1ProofSystem::mock().unwrap();
    let before = system.installed_guests();
    let block = system.programs().unwrap().execution.block;
    let mut wrong = block;
    wrong[0] ^= 1;
    let known_elf = system.guest_artifact(&block).unwrap();
    assert!(
        system
            .install_guest_checked(known_elf.clone(), wrong)
            .is_err()
    );
    // A locally derived key must be checked against the claimed identity
    // before a new entry becomes visible, even for the embedded Guest.
    assert!(
        system
            .install_guest_checked(neutrin0_runtime_host::EVM_GUEST_ELF.to_vec(), wrong)
            .is_err()
    );
    assert_eq!(system.installed_guests(), before);
    assert_eq!(
        system
            .install_guest_checked(known_elf.clone(), block)
            .unwrap(),
        block
    );
    let (total, fragment) = system.guest_fragment(&block, 3, 17).unwrap();
    assert_eq!(total, u64::try_from(known_elf.len()).unwrap());
    assert_eq!(fragment, known_elf[3..20]);
    assert!(system.guest_fragment(&block, total, 17).is_none());
}

#[test]
fn cached_verified_block_still_binds_exact_bytes_and_public_inputs() {
    let system = Sp1ProofSystem::mock().unwrap();
    let (mut proof, mut inputs) = build_block_proof(91);
    let expected = system.verify_block_statement(&proof, &inputs).unwrap();
    assert_eq!(
        system.verify_block_statement(&proof, &inputs).unwrap(),
        expected
    );
    inputs.gas_used += 1;
    assert!(system.verify_block_statement(&proof, &inputs).is_err());
    inputs.gas_used -= 1;
    proof.bytes.push(0);
    assert!(system.verify_block_statement(&proof, &inputs).is_err());
}
