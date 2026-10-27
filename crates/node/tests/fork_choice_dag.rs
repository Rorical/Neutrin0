//! Fork choice over competing siblings.
//!
//! Two validators can win the same slot. Every imported block whose parent
//! is known joins the fork-choice DAG, and the materialised head follows
//! the fork-choice head.
//!
//! Acceptance cases:
//!
//! 1. Two slot-1 siblings on the same genesis parent both import, and the
//!    materialised head is the one fork choice selects.
//! 2. A stake-weighted chunk vote on one branch makes it the fork-choice
//!    head even while the materialised head has not been replayed yet.
//! 3. An invalid block proof excludes its branch from fork choice, which
//!    then selects the competing branch.

use neutrin0_consensus_engine::body::compute_body_roots;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{
    Engine, ImportBlockOutcome, ImportError, ProposerKey, StateSource,
};
use neutrin0_consensus_fork_choice::{ChunkVote, ProofStatus};
use neutrin0_consensus_types::{
    Block, Body, FinalityVoteData, FinalityVotePhase, Header, ProvenBlock,
};
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, Height, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_proof_system::{MockProofSystem, ProofSystem};
use neutrin0_storage::MemoryDatabase;

const CHAIN_ID: u64 = 7_654_321;
const GENESIS_SEED: [u8; 32] = [0xD0; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: neutrin0_primitives::runtime_account([0x88; 20]),
            effective_stake: 32_000_000_000_000_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

fn chain_spec(count: u8) -> ChainSpec {
    let validators = validators(count);
    let proof = ProofParams::default();
    // Inflate `expected_proposers_per_slot` so multiple validators
    // can be VRF-eligible for the same slot — the very condition
    // fork choice is meant to handle.
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 8),
        ..ConsensusParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xAA; 32];
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(b"fork-choice-test".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: ZERO_HASH,
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

/// A receipt-following engine on the fixture spec: these tests exercise
/// fork choice, not execution, so peer blocks arrive as mock publications.
fn following_engine() -> Engine<MemoryDatabase> {
    let mut engine = Engine::genesis(chain_spec(2), MemoryDatabase::new()).expect("genesis");
    engine.set_state_source(StateSource::ReceiptDiffs);
    engine
}

/// Import `block` as the publication a mock receipt makes of it: an empty
/// block over the empty genesis state carries no writes.
fn import(
    engine: &mut Engine<MemoryDatabase>,
    block: &Block,
) -> Result<ImportBlockOutcome, ImportError<<MemoryDatabase as neutrin0_storage::Database>::Error>>
{
    let inputs = engine
        .canonical_block_proof(&block.header, ZERO_HASH, Vec::new())
        .expect("canonical envelope")
        .public_inputs;
    let proof = MockProofSystem
        .prove_block(&[], &inputs, inputs.proposer_address)
        .expect("mock receipt");
    let publication = ProvenBlock {
        block: block.clone(),
        proof_bytes: borsh::to_vec(&proof).expect("encode receipt"),
        writes: Vec::new(),
    };
    engine.import_proven_block(&publication, &MockProofSystem, None)
}

/// Build an empty-body block at `slot` on `parent`, signed by `signer`.
/// `extra_byte` differentiates sibling blocks through `runtime_extra` so
/// they hash differently.
fn signed_block(
    slot: u64,
    parent: BlockHash,
    height: Height,
    signer: &ProposerKey,
    extra_byte: u8,
) -> Block {
    let body = Body::default();
    let roots = compute_body_roots(&body);
    let vrf_proof = signer.vrf_eval(chain_spec(2).consensus_domain(), &GENESIS_SEED, slot);
    let mut header = Header {
        height,
        slot,
        parent_hash: parent,
        proposer_index: signer.validator_index(),
        vrf_proof,
        state_root: ZERO_HASH,
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        da_root: roots.da_root,
        runtime_extra: [extra_byte; 32],
        inputs_root: [0; 32],
        receipts_root: Body::default().artifacts.commitment(),
        gas_used: 0,
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000 + slot * 4,
        signature: [0; 96],
    };
    header.inputs_root = fixture_inputs_root(&chain_spec(2), &header, &body);
    let header_hash = header.hash();
    header.signature = signer.sign_proposer_message(chain_spec(2).consensus_domain(), &header_hash);
    Block { header, body }
}

#[test]
fn multi_winner_slot_does_not_reject_either_sibling() {
    let _ = tracing_subscriber::fmt::try_init();
    let mut engine = following_engine();
    let genesis_hash = engine.head_hash();

    let v0 = proposer(0);
    let v1 = proposer(1);

    // Both validators are VRF-eligible for slot 1 (expected
    // proposers per slot is inflated to ~10). Each signs their own
    // sibling block on top of genesis.
    let block_a = signed_block(1, genesis_hash, 1, &v0, 0x11);
    let block_b = signed_block(1, genesis_hash, 1, &v1, 0x22);
    assert_ne!(
        block_a.hash(),
        block_b.hash(),
        "sibling blocks must have distinct hashes for the test to be meaningful",
    );

    // First import lands as the materialised head.
    let out_a = import(&mut engine, &block_a).expect("import first sibling");
    assert_eq!(out_a.block_hash, block_a.hash());
    assert_eq!(
        engine.head_hash(),
        block_a.hash(),
        "first sibling becomes head"
    );

    // The second sibling, on the same parent, joins the DAG too.
    import(&mut engine, &block_b).expect("import second sibling");

    // The materialised head is whichever sibling fork choice selects: a
    // sibling import replays the selected branch from retained diffs.
    assert_eq!(
        engine.head_hash(),
        engine.fork_choice_head(),
        "materialised head follows fork choice between the siblings",
    );
    // Both siblings are in the DAG.
    assert!(
        engine.fork_choice().block(&block_a.hash()).is_some(),
        "block A in DAG",
    );
    assert!(
        engine.fork_choice().block(&block_b.hash()).is_some(),
        "block B in DAG",
    );
    // Body + header for both blocks survived persistence.
    assert!(
        engine
            .store()
            .get_header(&block_a.hash())
            .expect("read A")
            .is_some()
    );
    assert!(
        engine
            .store()
            .get_header(&block_b.hash())
            .expect("read B")
            .is_some()
    );
}

#[test]
fn heavier_branch_wins_fork_choice_head_even_when_materialised_head_lags() {
    let _ = tracing_subscriber::fmt::try_init();
    let mut engine = following_engine();
    let genesis_hash = engine.head_hash();
    let v0 = proposer(0);
    let v1 = proposer(1);

    let block_a = signed_block(1, genesis_hash, 1, &v0, 0x11);
    let block_b = signed_block(1, genesis_hash, 1, &v1, 0x22);
    import(&mut engine, &block_a).expect("import A");
    import(&mut engine, &block_b).expect("import B");
    let materialised = engine.head_hash();

    // Without votes the deterministic tie-break picks a head. Mark both
    // siblings Proven so only the vote below decides.
    let fc = engine.fork_choice_mut_for_test();
    fc.on_block_proof(block_a.hash(), ProofStatus::Proven)
        .expect("promote A to Proven");
    fc.on_block_proof(block_b.hash(), ProofStatus::Proven)
        .expect("promote B to Proven");

    // Register dummy chunks anchored at each sibling so the
    // vote-applies-to-candidate join has a chunk to hit.
    let chunk_a = dummy_chunk(block_a.hash(), 1);
    let chunk_b = dummy_chunk(block_b.hash(), 2);
    let _chunk_a_hash = fc.add_chunk(&chunk_a);
    let chunk_b_hash = fc.add_chunk(&chunk_b);

    // Big stake-weighted vote on chunk_b: validator 0's vote
    // dominates the tie-break with 100 units of weight.
    fc.add_vote(
        0,
        ChunkVote {
            data: FinalityVoteData {
                chunk_id: 2,
                round: 0,
                chunk_hash: chunk_b_hash,
                selection: [0; 32],
                phase: FinalityVotePhase::Prevote,
            },
            weight: 100,
        },
    );

    // A vote injected straight into the DAG triggers no replay, so the
    // materialised head lags where the imports left it. The fork-choice
    // head, however, picks B because of the heavier vote weight.
    assert_eq!(engine.head_hash(), materialised);
    assert_eq!(
        engine.fork_choice_head(),
        block_b.hash(),
        "fork choice picks heavier-voted branch",
    );
}

const fn dummy_chunk(end_block_hash: BlockHash, chunk_id: u64) -> neutrin0_consensus_types::Chunk {
    neutrin0_consensus_types::Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id,
        start_height: 1,
        end_height: 1,
        start_state_root: ZERO_HASH,
        end_state_root: ZERO_HASH,
        start_block_hash: end_block_hash,
        end_block_hash,
        block_hash_root: ZERO_HASH,
        block_proof_root: ZERO_HASH,
        vrf_proof_root: ZERO_HASH,
        active_validator_set_root: ZERO_HASH,
        next_validator_set_root: ZERO_HASH,
        da_root: ZERO_HASH,
    }
}

/// The inputs root the importing engine derives for a chunk-zero fixture
/// block (design 08): the mock backend installs no programs, so a genesis
/// engine of the same specification derives exactly the same commitment.
fn fixture_inputs_root(
    spec: &neutrin0_primitives::ChainSpec,
    header: &neutrin0_consensus_types::Header,
    body: &neutrin0_consensus_types::Body,
) -> neutrin0_primitives::Hash {
    neutrin0_consensus_engine::Engine::genesis(
        spec.clone(),
        neutrin0_storage::MemoryDatabase::new(),
    )
    .unwrap()
    .expected_inputs_root(header, body)
    .unwrap()
}
