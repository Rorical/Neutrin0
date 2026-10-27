//! Block proving and verification through [`ProverCtx`]. All mock proof
//! tests share one context, so the SP1 preprocessing pass runs once per
//! process.

#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use std::sync::OnceLock;

use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_abi::RuntimeBlockOutput;
use neutrin0_runtime_abi::{RuntimeTransaction, StateWitness, TrieNodeBytes};
use neutrin0_runtime_core::{empty_state_root, host::LiveTrie};
use neutrin0_runtime_host::{ProverCtx, Sp1HostError, dry_run};
use sp1_sdk::blocking::{MockProver, ProverClient};

/// Attribution every receipt in this test names (design 08).
const PROVER_ADDRESS: [u8; 32] = [0x50; 32];

const CHAIN_ID: u64 = 7;

static MOCK_CTX: OnceLock<ProverCtx<MockProver>> = OnceLock::new();

fn mock_ctx() -> &'static ProverCtx<MockProver> {
    MOCK_CTX.get_or_init(|| {
        let prover = ProverClient::builder().mock().build();
        ProverCtx::new(prover).expect("mock setup")
    })
}

/// The fixture chain's genesis state and the authenticated input of its
/// first block, carrying `txs`.
fn genesis_and_block(txs: Vec<RuntimeTransaction>) -> (LiveTrie, RuntimeBlockInput) {
    let (_, mut input, _) = support::fixture([1; 8], [4; 32]);
    assert_eq!(input.chain_id, CHAIN_ID);
    input.transactions = txs;
    (
        support::fixture_genesis_live([1; 8], [4; 32], 30_000_000),
        input,
    )
}

/// Dry-run a block containing one signed transfer, prove it via SP1,
/// verify the committed `RuntimeBlockOutput`.
#[test]
fn full_pipeline_signed_transfer_mock() {
    let ctx = mock_ctx();
    let (live, input) = genesis_and_block(vec![support::transfer(0)]);

    let dry = dry_run(&input, &live, &[]).expect("native dry run");
    assert_eq!(dry.output.applied, 1);
    assert_eq!(dry.output.failed, 0);

    let proof = ctx
        .prove(&input, dry.witness.clone(), &[], PROVER_ADDRESS)
        .unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}

/// A tampered `post_state_root` is rejected by
/// the host-side public-output check.
#[test]
fn tampered_post_state_root_is_rejected() {
    let ctx = mock_ctx();
    let (live, input) = genesis_and_block(vec![]);
    let dry = dry_run(&input, &live, &[]).expect("native dry run");
    let proof = ctx
        .prove(&input, dry.witness.clone(), &[], PROVER_ADDRESS)
        .unwrap();

    let mut tampered = dry.output.clone();
    tampered.post_state_root[0] ^= 0xFF;

    let err = ctx
        .verify(&proof.proof, &tampered)
        .expect_err("verify must reject tampered post_state_root");
    match err {
        Sp1HostError::PublicOutputMismatch { expected, actual } => {
            assert_eq!(expected.post_state_root, tampered.post_state_root);
            assert_eq!(actual.post_state_root, dry.output.post_state_root);
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

/// A witness whose `witnessed_keys` set excludes a key the STF reads
/// causes the guest to panic on the unwitnessed read.
#[test]
fn missing_witness_entry_makes_guest_abort() {
    let ctx = mock_ctx();

    // Empty live state + empty witness. The STF reads its genesis records
    // first, none of which is in `witnessed_keys` → panic.
    let witness = StateWitness {
        pre_state_root: empty_state_root(),
        nodes: vec![],
        values: vec![],
        witnessed_keys: vec![],
    };
    let (_, input) = genesis_and_block(vec![support::transfer(0)]);
    let (_pv, report) = ctx
        .execute(&input, &witness, &[], PROVER_ADDRESS)
        .expect("executor runs");
    assert_ne!(
        report.exit_code, 0,
        "guest must abort with non-zero exit when an unwitnessed account is read"
    );
}

/// A Merkle witness whose
/// `pre_state_root` cannot be reconstructed from the supplied trie
/// nodes makes the guest's `WitnessState::new` reject and abort.
#[test]
fn tampered_witness_value_makes_guest_abort() {
    let ctx = mock_ctx();

    // Claim a non-empty pre_state_root but supply node bytes that
    // hash to a *different* root. The host's verification
    // (`Poseidon2Hasher::hash_node(bytes) == hash`) passes for each
    // supplied node, but the *root* the witness claims is not among
    // them, so `WitnessState::new` returns `PreRootMissing`.
    let bogus_bytes = b"definitely-not-a-canonical-trie-node".to_vec();
    let bogus_hash =
        <neutrin0_trie::Poseidon2Hasher as neutrin0_trie::Hasher>::hash_node(&bogus_bytes);
    let witness = StateWitness {
        pre_state_root: [0xAA; 32],
        nodes: vec![TrieNodeBytes {
            hash: bogus_hash,
            bytes: bogus_bytes,
        }],
        values: vec![],
        witnessed_keys: vec![],
    };
    let (_, input) = genesis_and_block(vec![]);
    let (_pv, report) = ctx
        .execute(&input, &witness, &[], PROVER_ADDRESS)
        .expect("executor runs");
    assert_ne!(
        report.exit_code, 0,
        "guest must abort when the witness contradicts pre_state_root"
    );
}

/// Sanity: the master crate's native rlib `apply_block_with_witness`
/// produces the same public output as the dry-run path. No SP1 work.
#[test]
fn master_apply_block_with_witness_matches_dry_run() {
    let (live, input) = genesis_and_block(vec![support::transfer(0)]);
    let dry = dry_run(&input, &live, &[]).expect("native dry run");
    let bytes = borsh::to_vec(&(input, dry.witness.clone())).unwrap();
    let out_bytes = neutrin0_evm_runtime_master::apply_block_with_witness(&bytes);
    let out: RuntimeBlockOutput = borsh::from_slice(&out_bytes).unwrap();

    assert_eq!(out, dry.output);
}

/// Opt-in real Compressed STARK pipeline. The prover is selected
/// by `SP1_PROVER` (`cpu`, `network`, …); run with `--ignored`.
#[test]
#[ignore = "runs real Compressed STARK proving (multi-minute on CPU)"]
fn real_prover_full_pipeline() {
    let prover = ProverClient::from_env();
    let ctx = ProverCtx::new(prover).unwrap();

    let (live, input) = genesis_and_block(vec![support::transfer(0)]);
    let dry = dry_run(&input, &live, &[]).expect("native dry run");
    let proof = ctx
        .prove(&input, dry.witness.clone(), &[], PROVER_ADDRESS)
        .unwrap();
    ctx.verify(&proof.proof, &dry.output).unwrap();
}

/// Opt-in demonstration: print every artifact of one full block
/// transition under the real env-driven Compressed STARK prover.
///
/// Run with:
/// `SP1_PROVER=cpu cargo test -p neutrin0-runtime-host --test prove_verify \
///    real_prover_demonstration -- --ignored --nocapture --test-threads=1`
///
/// Set `SP1_PROVER=network` (with a Succinct prover key configured)
/// to offload generation to the prover network instead of the local
/// CPU. `SP1_PROVER=mock` short-circuits proving for sanity checks.
///
/// Saves the bincode-encoded `SP1ProofWithPublicValues` to
/// `neutrin0_block_proof.bin` in the system temporary directory so the wire
/// artifact can be inspected directly.
#[test]
#[ignore = "runs real Compressed STARK proving (multi-minute on CPU)"]
#[allow(clippy::too_many_lines)] // demonstration test, intentionally linear
fn real_prover_demonstration() {
    use std::fmt::Write as _;
    use std::time::Instant;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            // `write!` to a `String` is infallible (only Err on alloc
            // OOM, which would have panicked at `with_capacity` or
            // earlier). Avoids the extra `format!` allocation flagged
            // by `clippy::format_push_string`.
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    println!();
    println!("=== Neutrin0 block proof demonstration ============================");
    println!("    real Compressed STARK prover (env-selected), one signed EVM transfer");
    println!();

    // -------------------------------------------------------------
    // 1. Pre-state
    // -------------------------------------------------------------
    let (live, input) = genesis_and_block(vec![support::transfer(0)]);
    let sender = support::sender();

    println!("[1] Pre-state");
    println!("    sender address    {sender:#x}");
    println!(
        "    sender balance    {}",
        support::balance_of(&live, sender)
    );
    println!("    pre_state_root    0x{}", hex(&live.state_root()));
    println!();

    // -------------------------------------------------------------
    // 2. Block (single EIP-1559 transfer)
    // -------------------------------------------------------------
    let RuntimeTransaction::User(raw) = &input.transactions[0] else {
        unreachable!("fixture transfers are user envelopes")
    };
    println!("[2] Block body");
    println!("    chain_id          {CHAIN_ID}");
    println!(
        "    tx[0] = EIP-1559 transfer of 1 wei to 0x{}",
        hex(&[4; 20])
    );
    println!("       raw[..16]      0x{}", hex(&raw[..16]));
    println!("       raw length     {}", raw.len());
    println!();

    // -------------------------------------------------------------
    // 3. Host dry-run (no SP1) -> StateWitness
    // -------------------------------------------------------------
    println!("[3] Host dry-run (TracingState, no SP1)");
    let started = Instant::now();
    let dry = dry_run(&input, &live, &[]).expect("native dry run");
    let elapsed = started.elapsed();
    println!("    elapsed                 {elapsed:.2?}");
    println!("    applied                 {}", dry.output.applied);
    println!("    failed                  {}", dry.output.failed);
    println!(
        "    pre_state_root          0x{}",
        hex(&dry.output.pre_state_root)
    );
    println!(
        "    post_state_root         0x{}",
        hex(&dry.output.post_state_root)
    );
    println!(
        "    consensus_candidates_root 0x{}",
        hex(&dry.output.consensus_candidates_root)
    );
    println!(
        "    witness pre_state_root  0x{}",
        hex(&dry.witness.pre_state_root)
    );
    println!("    witness nodes           {}", dry.witness.nodes.len());
    println!("    witness values          {}", dry.witness.values.len());
    println!(
        "    witness witnessed_keys  {} key(s):",
        dry.witness.witnessed_keys.len()
    );
    for key in &dry.witness.witnessed_keys {
        println!("       0x{}", hex(key));
    }
    println!();

    // -------------------------------------------------------------
    // 4. SP1 prover setup (one-time preprocessing of guest ELF)
    // -------------------------------------------------------------
    println!("[4] SP1 prover setup (program ROM preprocessing)");
    let started = Instant::now();
    let prover = ProverClient::from_env();
    let ctx = ProverCtx::new(prover).unwrap();
    let elapsed = started.elapsed();
    println!("    elapsed                 {elapsed:.2?}");
    println!(
        "    vk fingerprint (bn254)  {}",
        neutrin0_runtime_host::vk_fingerprint(&ctx.vk)
    );
    println!(
        "    sp1 circuit version     {}",
        sp1_sdk::SP1_CIRCUIT_VERSION
    );
    println!();

    // -------------------------------------------------------------
    // 5. Compressed STARK proof generation
    // -------------------------------------------------------------
    println!("[5] SP1 Compressed STARK proof generation (env-selected backend)");
    let started = Instant::now();
    let proof_bundle = ctx
        .prove(&input, dry.witness.clone(), &[], PROVER_ADDRESS)
        .unwrap();
    let elapsed = started.elapsed();
    println!("    elapsed                 {elapsed:.2?}");

    let wire_bytes = neutrin0_prover_chunk::receipt_codec::encode(&proof_bundle.proof)
        .expect("bincode encode proof");
    // `wire_bytes.len()` is the size of a Compressed STARK proof —
    // single-digit MiB in practice, well within f64's 2^52 mantissa.
    // The `as f64` cast can lose precision past 2^52, which can't
    // happen here, hence the explicit allow.
    #[allow(clippy::cast_precision_loss)]
    let kib = wire_bytes.len() as f64 / 1024.0;
    println!(
        "    wire size (bincode)     {} bytes ({kib:.1} KiB)",
        wire_bytes.len()
    );
    println!("    first 32 bytes          0x{}", hex(&wire_bytes[..32]));
    let tail_start = wire_bytes.len().saturating_sub(32);
    println!(
        "    last 32 bytes           0x{}",
        hex(&wire_bytes[tail_start..])
    );

    let pv = proof_bundle.proof.public_values.as_slice();
    println!("    public values           {} bytes", pv.len());
    println!("    public values hex       0x{}", hex(pv));
    let decoded = borsh::from_slice::<neutrin0_runtime_abi::BlockReceiptStatement>(pv)
        .expect("decode BlockReceiptStatement")
        .output;
    println!(
        "       decoded pre          0x{}",
        hex(&decoded.pre_state_root)
    );
    println!(
        "       decoded post         0x{}",
        hex(&decoded.post_state_root)
    );
    println!("       decoded applied      {}", decoded.applied);
    println!("       decoded failed       {}", decoded.failed);
    println!(
        "       decoded vs_root      0x{}",
        hex(&decoded.consensus_candidates_root)
    );

    let out_path = std::env::temp_dir().join("neutrin0_block_proof.bin");
    std::fs::write(&out_path, &wire_bytes).expect("write proof bytes");
    println!("    saved to                {}", out_path.display());
    println!();

    // -------------------------------------------------------------
    // 6. Verify the proof
    // -------------------------------------------------------------
    println!("[6] SP1 verifier");
    let started = Instant::now();
    ctx.verify(&proof_bundle.proof, &dry.output).unwrap();
    let elapsed = started.elapsed();
    println!("    elapsed                 {elapsed:.2?}");
    println!("    result                  ACCEPTED");
    println!();

    // -------------------------------------------------------------
    // 7. Tampered-output sanity check: same proof, different
    //    expected `RuntimeBlockOutput` → verifier rejects.
    // -------------------------------------------------------------
    println!("[7] Tampered-output negative check");
    let mut tampered = dry.output;
    tampered.post_state_root[0] ^= 0xFF;
    let err = ctx
        .verify(&proof_bundle.proof, &tampered)
        .expect_err("verifier must reject tampered post_state_root");
    println!("    flipped post[0] bit     ");
    println!("    verifier returned       {err}");
    println!();
    println!("=== Done ============================================================");
}
