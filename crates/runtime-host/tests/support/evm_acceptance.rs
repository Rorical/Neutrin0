//! Shared real-proof EVM acceptance fixtures for host and node lifecycle gates.
#[path = "acceptance.rs"]
pub mod acceptance;
#[path = "../../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use acceptance::{AcceptanceCache, StageIdentity};
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Signature, TxKind, U256, keccak256};
use neutrin0_consensus_types::{
    BlockProof, Body, FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
    evidence::{EvidenceArtifact, commitment},
    history_proof::{ConsensusStatement, ProgramSet},
};
use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::{DOMAIN_PROPOSER_SIG, Validator, blake3_256};
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::{
    body::ConsensusBody,
    consensus::{ConsensusWitness, as_chunk, validate_consensus, validate_consensus_with_context},
    evidence::{EvidenceClaim, EvidenceWitness},
    history::HistoricalChunk,
};
use neutrin0_runtime_abi::{
    RuntimeBlockInput, RuntimeGenesisInput, RuntimeTransaction, StateWitness,
    ethereum::{EvmGenesisConfig, GenesisAccount},
};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_runtime_host::{
    ProgramProver, Sp1BlockProof, Sp1ProofSystem,
    proof_system::Sp1ChunkProof,
    wasm::{EVM_MASTER_WASM, WasmRuntime},
};

/// Open a gate-specific receipt namespace inside the configured remote result directory.
pub fn acceptance_cache(namespace: &str) -> AcceptanceCache {
    let directory = std::env::var_os("NEUTRIN0_EVM_GATE_DIR").map_or_else(
        || std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/proof-acceptance"),
        std::path::PathBuf::from,
    );
    AcceptanceCache::new(directory.join(namespace)).unwrap()
}

/// Development Ethereum account shared by the real-proof acceptance chains.
pub fn sender() -> Address {
    account_address(7)
}

/// Development Ethereum account for a selected deterministic signing key.
pub fn account_address(byte: u8) -> Address {
    let key = k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap();
    Address::from_slice(&keccak256(&key.verifying_key().to_sec1_point(false).as_bytes()[1..])[12..])
}
/// Sign a protected type-2 transaction against the development chain.
pub fn transaction(nonce: u64, to: Address, data: Vec<u8>) -> RuntimeTransaction {
    transaction_with_key(7, nonce, to, data, 900_000)
}

/// Sign a transaction from another independently funded genesis participant.
pub fn transaction_with_key(
    byte: u8,
    nonce: u64,
    to: Address,
    data: Vec<u8>,
    gas_limit: u64,
) -> RuntimeTransaction {
    let tx = TxEip1559 {
        chain_id: 7,
        nonce,
        gas_limit,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 3,
        to: TxKind::Call(to),
        input: data.into(),
        ..Default::default()
    };
    let key = k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap();
    let (sig, recovery) = key.sign_prehash_recoverable(tx.signature_hash().as_slice());
    let bytes = sig.to_bytes();
    let sig = Signature::from_scalars_and_parity(
        B256::from_slice(&bytes[..32]),
        B256::from_slice(&bytes[32..]),
        recovery.is_y_odd(),
    );
    RuntimeTransaction::User(TxEnvelope::from(tx.into_signed(sig)).encoded_2718())
}
/// Compatible upgraded WASM whose custom section changes its exact identity.
pub fn upgrade_wasm() -> Vec<u8> {
    // A valid custom section changes the governed artifact identity without changing ABI/state semantics.
    let mut wasm = EVM_MASTER_WASM.to_vec();
    wasm.extend_from_slice(&[0, 8, 7]);
    wasm.extend_from_slice(b"upgrade");
    wasm
}
/// Content hash used by the authenticated program distribution lane.
pub fn distribution_hash(bytes: &[u8]) -> [u8; 32] {
    assert!(
        !bytes.is_empty() && bytes.len() <= neutrin0_consensus_types::MAX_PROGRAM_BYTES as usize
    );
    let leaves: Vec<_> = bytes
        .chunks(neutrin0_consensus_types::MAX_PROGRAM_PIECE_BYTES)
        .map(blake3_256)
        .collect();
    neutrin0_consensus_types::program_content_hash(
        u32::try_from(bytes.len()).unwrap(),
        neutrin0_primitives::merkle_root_of_hashes(&leaves),
    )
}
/// Program-lane pieces of an artifact, as a producer publishes them.
pub fn artifact_pieces(bytes: &[u8]) -> Vec<neutrin0_consensus_types::ProgramPiece> {
    let piece = neutrin0_consensus_types::MAX_PROGRAM_PIECE_BYTES;
    let leaves: Vec<_> = bytes.chunks(piece).map(blake3_256).collect();
    let root = neutrin0_primitives::merkle_root_of_hashes(&leaves);
    bytes
        .chunks(piece)
        .enumerate()
        .map(|(index, chunk)| neutrin0_consensus_types::ProgramPiece {
            root,
            total_len: u32::try_from(bytes.len()).unwrap(),
            offset: u32::try_from(index * piece).unwrap(),
            bytes: chunk.to_vec(),
            opening: neutrin0_consensus_types::evidence::MerkleOpening::build(&leaves, index)
                .unwrap(),
        })
        .collect()
}
/// The program-lane batches publishing every artifact of a program switch,
/// at most the per-block bound each, in publication order.
pub fn publication_batches(
    artifacts: &[&[u8]],
) -> Vec<Vec<neutrin0_consensus_types::ProgramPiece>> {
    artifacts
        .iter()
        .flat_map(|artifact| artifact_pieces(artifact))
        .collect::<Vec<_>>()
        .chunks(neutrin0_consensus_types::MAX_PROGRAM_PIECES_PER_BLOCK)
        .map(<[_]>::to_vec)
        .collect()
}
/// Solidity calldata scheduling complete execution programs at chunk one.
pub fn upgrade_call(
    programs: ProgramSet,
    wasm: &[u8],
    elf: &[u8],
    activate_at_chunk: u64,
) -> Vec<u8> {
    let mut data = keccak256(
        b"proposeUpgrade(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64)",
    )[..4]
        .to_vec();
    data.extend(programs.runtime_code_hash);
    for digest in [
        programs.execution.fact,
        programs.execution.evidence,
        programs.execution.block,
    ] {
        for word in digest {
            data.extend(word.to_le_bytes());
        }
    }
    for hash in [
        distribution_hash(wasm),
        distribution_hash(&neutrin0_runtime_host::FACT_GUEST_ELF),
        distribution_hash(&neutrin0_runtime_host::EVIDENCE_GUEST_ELF),
        distribution_hash(elf),
    ] {
        data.extend(hash);
    }
    data.extend(U256::from(activate_at_chunk).to_be_bytes::<32>());
    data
}
/// Construct the deterministic time-zero EVM genesis used by existing gates.
pub fn genesis(programs: ProgramSet) -> LiveTrie {
    genesis_at_time(programs, 0)
}

/// Exact opaque EVM initialization input shared with node bootstrap acceptance.
pub fn genesis_input(programs: ProgramSet, timestamp: u64) -> RuntimeGenesisInput {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    RuntimeGenesisInput {
        max_block_proving_input_bytes: neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
        chain_id: 7,
        timestamp,
        seed: [0; 32],
        genesis_block_hash: [2; 32],
        chunk_size: 1,
        programs,
        block_gas_limit: 1_000_000,
        runtime_params: neutrin0_primitives::RuntimeParams::default(),
        validators: vec![Validator {
            pubkey: key.public_key().to_bytes(),
            withdrawal_credentials: neutrin0_evm_runtime_core::state::consensus_address(sender()),
            effective_stake: 100,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        }],
        configuration: borsh::to_vec(&EvmGenesisConfig {
            initial_base_fee: 10,
            accounts: vec![GenesisAccount {
                address: sender().into_array(),
                balance: U256::from(1_000_000_000_000_000_000_u64).to_be_bytes(),
                nonce: 0,
                code: vec![],
                storage: vec![],
            }],
        })
        .unwrap(),
    }
}

/// Two funded validator identities let a safety sanction eject one without halting the chain.
pub fn genesis_input_with_survivor(programs: ProgramSet, timestamp: u64) -> RuntimeGenesisInput {
    let mut input = genesis_input(programs, timestamp);
    let key = SecretKey::key_gen(&[43; 32], &[]).unwrap();
    let mut validator = input.validators[0].clone();
    validator.pubkey = key.public_key().to_bytes();
    validator.withdrawal_credentials =
        neutrin0_evm_runtime_core::state::consensus_address(account_address(8));
    input.validators.push(validator);
    let mut configuration: EvmGenesisConfig = borsh::from_slice(&input.configuration).unwrap();
    configuration.accounts.push(GenesisAccount {
        address: account_address(8).into_array(),
        balance: U256::from(1_000_000_000_000_000_000_u64).to_be_bytes(),
        nonce: 0,
        code: Vec::new(),
        storage: Vec::new(),
    });
    input.configuration = borsh::to_vec(&configuration).unwrap();
    input
}

/// Short, independently authenticated test-chain delay; production defaults are unchanged.
pub const UPGRADE_UNBONDING_BLOCKS: u64 = 16;
/// Slot duration leaves enough real time for proof generation and snapshot trust checks.
///
/// The bootstrap gate proves about 38 receipts between fixing its clock and checking
/// an endpoint whose freshness window is sixteen slots.
pub const UPGRADE_SLOT_SECONDS: u64 = 600;
/// Required lead for a one-block chunk, checked against the runtime rule before proving.
pub const UPGRADE_ACTIVATION_CHUNK: u64 = UPGRADE_UNBONDING_BLOCKS + 2;

/// Initialize the exact runtime policy used by the governed upgrade test specification.
pub fn upgrade_genesis_input(
    programs: ProgramSet,
    timestamp: u64,
    survivor: bool,
) -> RuntimeGenesisInput {
    let mut input = if survivor {
        genesis_input_with_survivor(programs, timestamp)
    } else {
        genesis_input(programs, timestamp)
    };
    input.runtime_params.unbonding_delay_blocks = UPGRADE_UNBONDING_BLOCKS;
    input.runtime_params.evidence_max_age_blocks = 1;
    input
}

/// Execute the governance block under a validated chain specification before any proving.
pub fn upgrade_fixture(
    programs: ProgramSet,
    chunk_program: neutrin0_consensus_types::history_proof::VkDigest,
    genesis: &RuntimeGenesisInput,
    transactions: Vec<RuntimeTransaction>,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness, LiveTrie) {
    let live = LiveTrie::from_trie(
        WasmRuntime::new(EVM_MASTER_WASM)
            .unwrap()
            .init_genesis(genesis)
            .unwrap()
            .1,
    );
    let keys = committee_keys(&genesis.validators);
    let (witness, input, state) = support::fixture_with_execution_configuration(
        programs,
        chunk_program,
        &genesis.validators,
        &keys,
        transactions,
        1_000_000,
        1_000_000,
        &live,
        neutrin0_evm_runtime_core::execute_block,
        genesis.timestamp,
        |spec| {
            spec.runtime = genesis.runtime_params;
            spec.consensus.slot_duration_secs = UPGRADE_SLOT_SECONDS;
            spec.consensus.epoch_length_in_chunks = 1;
            spec.consensus.exit_delay_epochs = 1;
            spec.light_client.weak_subjectivity_period_secs =
                UPGRADE_UNBONDING_BLOCKS * UPGRADE_SLOT_SECONDS;
            spec.light_client.stale_threshold_secs =
                spec.light_client.weak_subjectivity_period_secs;
            spec.validate().unwrap();
        },
    );
    assert_eq!(
        neutrin0_runtime_system::governance::upgrade_min_lead_chunks(&input.evidence_anchor),
        UPGRADE_ACTIVATION_CHUNK
    );
    (witness, input, state, live)
}

/// One independently verified chunk of the full pre-upgrade prefix.
pub struct UpgradeStep {
    /// Exact signed consensus witness.
    pub witness: ConsensusWitness,
    /// Execution input authenticated by the Block receipt.
    pub input: RuntimeBlockInput,
    /// State before this block.
    pub pre: LiveTrie,
    /// State after this block.
    pub post: LiveTrie,
    /// Exact complete consensus statement.
    pub statement: ConsensusStatement,
    /// Verified Block wire envelope.
    pub block: BlockProof,
    /// Independently verified compressed Chunk receipt.
    pub proof: Sp1ChunkProof,
    /// Program-lane pieces the block's body published; its signed DA root
    /// commits them.
    pub programs: Vec<neutrin0_consensus_types::ProgramPiece>,
}

/// Prove every intervening chunk; no skipped heights or fabricated finality authorize the switch.
///
/// The chunks after the governance block publish `artifacts`, the bytes of every
/// changed program, in their program lanes, so the switch is available at its boundary.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn prove_upgrade_prefix<P: ProgramProver, V: ProgramProver>(
    system: &Sp1ProofSystem<P>,
    verifier: &Sp1ProofSystem<V>,
    cache: &AcceptanceCache,
    mut witness: ConsensusWitness,
    mut input: RuntimeBlockInput,
    mut state: StateWitness,
    mut pre: LiveTrie,
    upgraded: ProgramSet,
    artifacts: &[&[u8]],
) -> Vec<UpgradeStep> {
    let original = witness.context.programs;
    let mut batches = publication_batches(artifacts).into_iter();
    let mut steps = Vec::new();
    let mut programs = Vec::new();
    for chunk_id in 0..UPGRADE_ACTIVATION_CHUNK {
        let dry = WasmRuntime::new(EVM_MASTER_WASM)
            .unwrap()
            .dry_run(&input, pre.trie(), &[])
            .unwrap();
        assert_eq!(dry.output, witness.blocks[0].output);
        let post = LiveTrie::from_trie(dry.post_state);
        let schedule =
            neutrin0_runtime_system::governance::load_scheduled(&mut TracingState::new(&post))
                .unwrap();
        assert_eq!(schedule.activate_at_chunk, UPGRADE_ACTIVATION_CHUNK);
        assert_eq!(schedule.programs, upgraded);
        let expected = if chunk_id + 1 == UPGRADE_ACTIVATION_CHUNK {
            upgraded
        } else {
            original
        };
        // Catch rejected proposals and premature switches before paying for proofs.
        assert_eq!(validate_consensus(&witness).unwrap().end.programs, expected);
        let ratified: Vec<_> = steps
            .last()
            .map(|step: &UpgradeStep| step.proof.clone())
            .into_iter()
            .collect();
        let (statement, proof) = prove_chunk(
            system,
            verifier,
            cache,
            &mut witness,
            &input,
            &state,
            &[],
            &ratified,
            &neutrin0_runtime_host::EVM_GUEST_ELF,
        );
        assert_eq!(statement.end.programs, expected);
        let block = cached_block_proof(
            verifier,
            cache,
            &witness,
            &input,
            &state,
            &[],
            &neutrin0_runtime_host::EVM_GUEST_ELF,
        );
        let next_programs = batches.next().unwrap_or_default();
        let next = if chunk_id + 1 < UPGRADE_ACTIVATION_CHUNK {
            let mut next_input = input.clone();
            next_input.transactions.clear();
            Some(successor_publishing(
                &witness,
                next_input,
                &post,
                vec![],
                EVM_MASTER_WASM,
                next_programs.clone(),
            ))
        } else {
            None
        };
        steps.push(UpgradeStep {
            witness,
            input,
            pre,
            post,
            statement,
            block,
            proof,
            programs: core::mem::replace(&mut programs, next_programs),
        });
        if let Some((next_witness, next_input, next_state, next_post)) = next {
            witness = next_witness;
            input = next_input;
            state = next_state;
            pre = LiveTrie::from_trie(steps.last().unwrap().post.trie().clone());
            // The next post-state is reconstructed by the same installed WASM on the next iteration.
            drop(next_post);
        } else {
            break;
        }
    }
    steps
}

/// Resolve fixture keys in the exact authenticated committee order.
pub fn committee_keys(validators: &[Validator]) -> Vec<SecretKey> {
    validators
        .iter()
        .map(|validator| {
            [42, 43]
                .into_iter()
                .map(|byte| SecretKey::key_gen(&[byte; 32], &[]).unwrap())
                .find(|key| key.public_key().to_bytes() == validator.pubkey)
                .expect("known acceptance committee identity")
        })
        .collect()
}

/// The second validator independently enacts the same exact upgrade proposal.
pub fn upgrade_vote_call(
    programs: ProgramSet,
    wasm: &[u8],
    elf: &[u8],
    activate_at_chunk: u64,
) -> Vec<u8> {
    let action = neutrin0_runtime_system::governance::ProposalAction::Programs {
        programs,
        artifacts: neutrin0_consensus_types::history_proof::ProgramArtifacts {
            runtime: distribution_hash(wasm),
            fact: distribution_hash(&neutrin0_runtime_host::FACT_GUEST_ELF),
            evidence: distribution_hash(&neutrin0_runtime_host::EVIDENCE_GUEST_ELF),
            block: distribution_hash(elf),
        },
        activate_at_chunk,
    };
    let proposer = neutrin0_evm_runtime_core::state::consensus_address(sender());
    let mut call = keccak256(b"vote(bytes32)")[..4].to_vec();
    call.extend(neutrin0_runtime_system::governance::proposal_id(
        &proposer, &action,
    ));
    call
}

/// Initialize the selected EVM WASM at an authenticated fresh genesis time.
pub fn genesis_at_time(programs: ProgramSet, timestamp: u64) -> LiveTrie {
    let input = genesis_input(programs, timestamp);
    LiveTrie::from_trie(
        WasmRuntime::new(EVM_MASTER_WASM)
            .unwrap()
            .init_genesis(&input)
            .unwrap()
            .1,
    )
}
/// Exact authenticated source record for a fully validated consensus witness.
pub fn historical(witness: &ConsensusWitness) -> HistoricalChunk {
    HistoricalChunk {
        runtime_code_hash: witness.context.programs.runtime_code_hash,
        block_guest_vk_digest: witness.context.programs.execution.block,
        start_boundary: validate_consensus(witness).unwrap().start.commitment(),
        chunk: as_chunk(&validate_consensus(witness).unwrap().chunk),
        validators: witness.context.active_validators.clone(),
        seed: witness.seed,
        finality: witness.finality_cert.clone(),
    }
}
/// Objective double-precommit evidence against the old execution program.
pub fn evidence(first: &ConsensusWitness, admission: ProgramSet) -> EvidenceWitness {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let vote = |hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash: [hash; 32],
            selection: [0; 32],
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: key
                .sign(&data.signing_message(first.chain_spec.consensus_domain()))
                .to_bytes(),
            data,
        }
    };
    EvidenceWitness {
        reporter: Some(neutrin0_evm_runtime_core::state::consensus_address(
            Address::from([55; 20]),
        )),
        chain_spec: first.chain_spec.clone(),
        source: historical(first),
        claim: EvidenceClaim::Slash(SlashingEvidence::DoublePrecommit {
            validator_index: 0,
            vote_a: vote(1),
            vote_b: vote(2),
        }),
        block_guest_vk_digest: admission.execution.block,
    }
}
/// Sign every mandatory proposal, vote and attestation for the witness.
pub fn sign_certificate(witness: &mut ConsensusWitness) {
    let keys = committee_keys(&witness.context.active_validators);
    let signers: Vec<_> = (0..keys.len()).collect();
    witness.finality_cert = support::certificate_with_precommitters(witness, &keys, &signers);
}
/// Execute and sign the next EVM block under its authenticated incoming boundary.
pub fn successor(
    first: &ConsensusWitness,
    input: RuntimeBlockInput,
    pre: &LiveTrie,
    attachments: Vec<EvidenceArtifact>,
    wasm: &[u8],
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness, LiveTrie) {
    successor_publishing(first, input, pre, attachments, wasm, Vec::new())
}

/// [`successor`] whose block publishes `programs` in its program lane.
#[allow(
    clippy::too_many_lines,
    reason = "Executes, proves and signs one successor chunk under the EVM runtime."
)]
pub fn successor_publishing(
    first: &ConsensusWitness,
    mut input: RuntimeBlockInput,
    pre: &LiveTrie,
    attachments: Vec<EvidenceArtifact>,
    wasm: &[u8],
    programs: Vec<neutrin0_consensus_types::ProgramPiece>,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness, LiveTrie) {
    let prior = validate_consensus_with_context(first).unwrap();
    let mut next = first.clone();
    next.context = prior.next_context;
    next.seed = prior.statement.end.seed;
    let source = historical(first);
    let leaf = neutrin0_consensus_types::evidence::commitment(&source.evidence_context());
    let path = next.history.frontier.append_path(leaf).unwrap();
    next.history.frontier.append(leaf).unwrap();
    next.history.records = vec![neutrin0_prover_chunk::history::HistoricalContextOpening {
        record: (&source).into(),
        path,
    }];
    input
        .active_validators
        .clone_from(&next.context.active_validators);
    input.proposer_address = next.context.active_validators[0].withdrawal_credentials;
    input.block_height += 1;
    input.evidence_anchor.chunk_id = next.context.chunk_id;
    input.evidence_anchor.history_root = next.context.history_root;
    input.evidence_anchor.block_guest_vk_digest = next.context.programs.execution.block;
    input.evidence_anchor.fact_guest_vk_digest = next.context.programs.execution.fact;
    input.evidence_anchor.evidence_guest_vk_digest = next.context.programs.execution.evidence;
    input.participation =
        neutrin0_consensus_types::participation::ParticipationReport::from_certificate(
            first.context.chunk_id,
            &first.context.active_validators,
            &first.finality_cert.precommit.aggregation_bits,
        );
    // Design 08: the carrier consumes the proving report of the same carried
    // certificate.
    input.proving = neutrin0_consensus_types::proving::ProvingReport::from_certificate(
        &source.chunk,
        &first.context.active_validators,
        &first.finality_cert.carried_certificate(),
    );
    let keys = committee_keys(&next.context.active_validators);
    let key = &keys[0];
    let block = &mut next.blocks[0];
    let header = &mut block.header;
    header.proposer_index = 0;
    header.height = input.block_height;
    header.slot += 1;
    header.timestamp = first
        .chain_spec
        .genesis_time
        .checked_add(
            header
                .slot
                .checked_mul(first.chain_spec.consensus.slot_duration_secs)
                .unwrap(),
        )
        .unwrap();
    header.parent_hash = prior.statement.end.block_hash;
    header.vrf_proof = key
        .sign(&neutrin0_vrf::vrf_message(
            first.chain_spec.consensus_domain(),
            &next.seed,
            header.slot,
        ))
        .to_bytes();
    input.context = neutrin0_prover_chunk::execution::runtime_context(header, prior.statement.end);
    input.program_pieces = neutrin0_consensus_types::program_piece_refs(&programs);
    let dry = WasmRuntime::new(wasm)
        .unwrap()
        .dry_run(&input, pre.trie(), &attachments)
        .unwrap();
    let output = dry.output;
    let body = Body {
        participation: Some(first.finality_cert.carried_certificate()),
        artifacts: dry.artifacts,
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        evidence_proofs: attachments,
        programs,
        ..Body::default()
    };
    next.bodies = vec![ConsensusBody::from_body(&body).unwrap()];
    header.state_root = output.post_state_root;
    header.transactions_root = output.transactions_root;
    header.receipts_root = output.receipts_root;
    header.gas_used = output.gas_used;
    header.runtime_extra = output.consensus_candidates_root;
    header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    header.da_root = neutrin0_prover_chunk::consensus::body_da_root(&body);
    header.signature = key
        .sign(
            &first
                .chain_spec
                .consensus_domain()
                .signing_message(DOMAIN_PROPOSER_SIG, &header.hash()),
        )
        .to_bytes();
    let pi = &mut block.public_inputs;
    pi.context = output.context.into();
    pi.height = header.height;
    pi.block_hash = header.hash();
    pi.parent_block_hash = header.parent_hash;
    pi.state_root_before = output.pre_state_root;
    pi.state_root_after = output.post_state_root;
    pi.transactions_root = output.transactions_root;
    pi.receipt_root = output.receipts_root;
    pi.da_root = header.da_root;
    pi.gas_used = output.gas_used;
    pi.runtime_extra = output.consensus_candidates_root;
    pi.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    pi.vm_code_hash = next.context.programs.runtime_code_hash;
    pi.block_program = next.context.programs.execution.block;
    block.output = output;
    let post = LiveTrie::from_trie(dry.post_state);
    let mut trace = TracingState::new(&post);
    neutrin0_prover_chunk::rotation::witness_keys_from(&mut trace);
    next.post_state = trace.into_witness().unwrap();
    // Design 08: the certificate ratifies the previous chunk's proof, which
    // the gates prove crediting the zero account.
    next.ratified = vec![
        neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
            statement: prior.statement,
            chunk_prover_address: [0; 32],
        },
    ];
    sign_certificate(&mut next);
    (next, input, dry.witness, post)
}
/// Prove or resume exact real compressed Block and Chunk receipts, then verify independently.
#[allow(
    clippy::too_many_arguments,
    reason = "Every authenticated stage needs its exact runtime, statement, witness and attachments."
)]
pub fn prove_chunk<P: ProgramProver, V: ProgramProver>(
    system: &Sp1ProofSystem<P>,
    verifier: &Sp1ProofSystem<V>,
    cache: &AcceptanceCache,
    witness: &mut ConsensusWitness,
    input: &RuntimeBlockInput,
    state: &StateWitness,
    attachments: &[EvidenceArtifact],
    ratified: &[Sp1ChunkProof],
    elf: &[u8],
) -> (ConsensusStatement, Sp1ChunkProof) {
    let bundle = neutrin0_runtime_host::encode_witness_bundle(input, state, attachments).unwrap();
    let pi = &witness.blocks[0].public_inputs;
    let identity = StageIdentity::new(
        "evm-block",
        elf,
        &bundle,
        &borsh::to_vec(&(pi, &witness.blocks[0].output)).unwrap(),
    );
    let bytes = cache
        .prove_or_resume(
            &identity,
            |bytes| {
                let proof: Sp1BlockProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_block(&proof, pi)?;
                if verifier.block_statement(&proof)? != witness.blocks[0].statement() {
                    return Err(ProofError::PublicInputMismatch);
                }
                Ok(())
            },
            || {
                borsh::to_vec(&system.prove_block(&bundle, pi, pi.proposer_address)?)
                    .map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap();
    let block: Sp1BlockProof = borsh::from_slice(&bytes).unwrap();
    assert_receipt_public_values_bindings(verifier, &block, &witness.blocks[0]);
    // A certificate authenticates the exact compressed proof served by the node.
    let keys = committee_keys(&witness.context.active_validators);
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![commitment(&BlockProof {
            prover_address: pi.proposer_address,
            statement_key: [0; 32],
            height: input.block_height,
            block_hash: pi.block_hash,
            public_inputs: pi.clone(),
            proof_bytes: bytes.clone(),
        })],
    };
    witness.finality_cert.proof_manifests = vec![manifest.clone()];
    for claim in &mut witness.finality_cert.precommit_attestations {
        claim.proof_acceptance = Some(manifest.commitment());
        claim.signature = keys[usize::try_from(claim.validator_index).unwrap()]
            .sign(&claim.signing_message(witness.chain_spec.consensus_domain()))
            .to_bytes();
    }
    let expected = validate_consensus(witness).unwrap();
    let identity = StageIdentity::new(
        "evm-chunk-facts",
        &neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF,
        &borsh::to_vec(&(witness.clone(), &bytes)).unwrap(),
        &borsh::to_vec(&expected).unwrap(),
    );
    let bytes = cache
        .prove_or_resume(
            &identity,
            |bytes| {
                let proof: Sp1ChunkProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_consensus_chunk(
                    &proof,
                    &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                        statement: expected.clone(),
                        chunk_prover_address: [0; 32],
                    },
                )
            },
            || {
                let mut recorder = neutrin0_prover_chunk::facts::FactRecorder::default();
                neutrin0_prover_chunk::consensus::validate_consensus_using(witness, &mut recorder)
                    .map_err(|_| ProofError::InvalidWitness)?;
                let requests: Vec<_> = recorder
                    .finish()
                    .map_err(|_| ProofError::InvalidWitness)?
                    .into_iter()
                    .map(|(request, _)| request)
                    .collect();
                system.preprove_facts(&witness.context.programs.execution.fact, &requests)?;
                let proof = system.prove_consensus_chunk(&[block], ratified, witness, [0; 32])?;
                let (covered, total) = system.last_chunk_fact_coverage().unwrap();
                if covered != total || total == 0 {
                    return Err(ProofError::InvalidWitness);
                }
                borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap();
    (expected, borsh::from_slice(&bytes).unwrap())
}

/// Recover and independently verify the exact Block envelope created by `prove_chunk`.
/// A missing checkpoint is an error and never starts a second proving job here.
pub fn cached_block_proof<V: ProgramProver>(
    verifier: &Sp1ProofSystem<V>,
    cache: &AcceptanceCache,
    witness: &ConsensusWitness,
    input: &RuntimeBlockInput,
    state: &StateWitness,
    attachments: &[EvidenceArtifact],
    elf: &[u8],
) -> BlockProof {
    let bundle = neutrin0_runtime_host::encode_witness_bundle(input, state, attachments).unwrap();
    let pi = &witness.blocks[0].public_inputs;
    let identity = StageIdentity::new(
        "evm-block",
        elf,
        &bundle,
        &borsh::to_vec(&(pi, &witness.blocks[0].output)).unwrap(),
    );
    let proof_bytes = cache
        .prove_or_resume(
            &identity,
            |bytes| {
                let proof: Sp1BlockProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_block(&proof, pi)?;
                if verifier.block_statement(&proof)? != witness.blocks[0].statement() {
                    return Err(ProofError::PublicInputMismatch);
                }
                Ok(())
            },
            || Err(ProofError::Unsupported),
        )
        .unwrap();
    BlockProof {
        prover_address: pi.proposer_address,
        statement_key: [0; 32],
        height: input.block_height,
        block_hash: pi.block_hash,
        public_inputs: pi.clone(),
        proof_bytes,
    }
}

/// Reuse the actual compressed receipt; adversarial verification needs no
/// additional proving and runs only in the ignored real-proof tests.
fn assert_receipt_public_values_bindings<V: ProgramProver>(
    verifier: &Sp1ProofSystem<V>,
    receipt: &Sp1BlockProof,
    block: &neutrin0_prover_chunk::execution::ProvenBlock,
) {
    type Forgery = fn(&mut neutrin0_runtime_abi::RuntimeBlockOutput);
    let forgeries: &[Forgery] = &[
        |output| output.context.slot += 1,
        |output| output.context.timestamp += 1,
        |output| output.context.parent_block_hash[0] ^= 1,
        |output| output.context.finalized.seed[0] ^= 1,
        |output| output.context.proposer_vrf_output[0] ^= 1,
        |output| output.context.finalized.programs.runtime_code_hash[0] ^= 1,
        |output| output.context.finalized.programs.execution.block[0] ^= 1,
        |output| output.post_state_root[0] ^= 1,
        |output| output.receipts_root[0] ^= 1,
    ];
    for (index, forge) in forgeries.iter().enumerate() {
        let mut output = block.output.clone();
        forge(&mut output);
        let mut public_inputs = block.public_inputs.clone();
        *public_inputs.context = output.context;
        public_inputs.parent_block_hash = output.context.parent_block_hash;
        public_inputs.state_root_after = output.post_state_root;
        public_inputs.receipt_root = output.receipts_root;
        // The context feeds the declared execution inputs commitment.
        public_inputs.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
        assert!(neutrin0_prover_chunk::execution::output_binds(
            &output,
            &public_inputs
        ));
        assert!(
            verifier.verify_block(receipt, &public_inputs).is_err(),
            "unchanged receipt forgery {index}"
        );

        // Make the public values agree with all supplied metadata again,
        // retaining the original compressed proof. Only verification of the
        // actual receipt can reject the altered committed values now.
        let mut bundle = receipt.to_sp1().unwrap();
        let statement = neutrin0_runtime_abi::BlockReceiptStatement {
            output: output.clone(),
            prover_address: block.prover_address,
        };
        bundle.public_values = sp1_sdk::SP1PublicValues::from(&borsh::to_vec(&statement).unwrap());
        let forged = Sp1BlockProof::from_sp1(&bundle).unwrap();
        assert!(
            verifier.verify_block(&forged, &public_inputs).is_err(),
            "rewritten public-values forgery {index}"
        );
    }
    let mut untrusted_program = block.public_inputs.clone();
    untrusted_program.block_program[0] ^= 1;
    assert!(verifier.verify_block(receipt, &untrusted_program).is_err());
}
