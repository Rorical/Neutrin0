//! A genesis-anchored, genuinely executed one-block consensus fixture.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Signature, TxKind, U256, keccak256};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{
    AggregatedVote, BlockProofPublicInputs, Body, FinalityCert, FinalityVoteData,
    FinalityVotePhase, Header,
};
use neutrin0_crypto::bls::{SecretKey, aggregate_signatures};
use neutrin0_evm_runtime_core::execute_block;
use neutrin0_primitives::{
    BitVec, BoundedBytes, ChainSpec, ConsensusParams, DOMAIN_PROPOSER_SIG, Hash, LightClientParams,
    ProofParams, RuntimeInfo, RuntimeParams, Validator, fixed_u128_from_integer,
    merkle_root_of_hashes,
};
use neutrin0_prover_chunk::{
    consensus::{ConsensusWitness, as_chunk},
    execution::{ExecutionContext, ProvenBlock, validate_execution},
    rotation::rotate_from_witness,
};
use neutrin0_runtime_abi::{
    RuntimeBlockInput, RuntimeGenesisInput, RuntimeTransaction, StateWitness,
    ethereum::{EvmGenesisConfig, GenesisAccount},
};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};

/// The program set every fixture context carries for the given block key and runtime.
pub const fn programs(
    key_digest: [u32; 8],
    runtime_hash: Hash,
) -> neutrin0_consensus_types::history_proof::ProgramSet {
    neutrin0_consensus_types::history_proof::ProgramSet {
        runtime_code_hash: runtime_hash,
        execution: neutrin0_consensus_types::history_proof::ExecutionPrograms {
            fact: [3; 8],
            evidence: [2; 8],
            block: key_digest,
        },
    }
}

/// Zero-padded system address of the 20-byte Ethereum account `[byte; 20]`,
/// the only validator credential shape the EVM runtime seats.
#[allow(dead_code)]
pub fn credentials(byte: u8) -> Hash {
    let mut address = [0; 32];
    address[12..].copy_from_slice(&[byte; 20]);
    address
}

/// Development secp256k1 key whose account every fixture genesis funds.
#[allow(dead_code)]
pub fn sender_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap()
}

/// Ethereum address of [`sender_key`].
#[allow(dead_code)]
pub fn sender() -> Address {
    let point = sender_key().verifying_key().to_sec1_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}

/// The single-key fixture committee: BLS key `[42; 32]`, accountable at
/// [`credentials`] of byte 8.
#[allow(dead_code)]
pub fn fixture_committee() -> (Vec<Validator>, Vec<SecretKey>) {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let validators = vec![Validator {
        pubkey: key.public_key().to_bytes(),
        withdrawal_credentials: credentials(8),
        effective_stake: 100,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }];
    (validators, vec![key])
}

/// EVM genesis input consistent with the chain specification the fixtures
/// derive: chain 7, seed zero, genesis block hash `[2; 32]`, one funded
/// development account.
#[allow(dead_code)]
pub fn evm_genesis_input(
    programs: neutrin0_consensus_types::history_proof::ProgramSet,
    gas_limit: u64,
    genesis_time: u64,
    validators: &[Validator],
    chunk_size: u64,
    runtime_params: RuntimeParams,
) -> RuntimeGenesisInput {
    RuntimeGenesisInput {
        max_block_proving_input_bytes: neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
        chain_id: 7,
        timestamp: genesis_time,
        seed: [0; 32],
        genesis_block_hash: [2; 32],
        chunk_size,
        programs,
        block_gas_limit: gas_limit,
        runtime_params,
        validators: validators.to_vec(),
        configuration: borsh::to_vec(&EvmGenesisConfig {
            initial_base_fee: 10,
            accounts: vec![GenesisAccount {
                address: sender().into_array(),
                balance: U256::from(1_000_000_000_000_000_000_u64).to_be_bytes(),
                nonce: 0,
                code: Vec::new(),
                storage: Vec::new(),
            }],
        })
        .unwrap(),
    }
}

/// Initialize `genesis` natively into a live trie.
#[allow(dead_code)]
pub fn evm_genesis_live(genesis: &RuntimeGenesisInput) -> LiveTrie {
    let empty = LiveTrie::default();
    let mut state = TracingState::new(&empty);
    neutrin0_evm_runtime_core::init_genesis(genesis, &mut state);
    let (trie, _) = state.into_committed_and_witness().unwrap();
    LiveTrie::from_trie(trie)
}

/// Genesis state of [`fixture_with_transactions`] for the given programs
/// and gas limit: the exact pre-state of the fixture's first block.
#[allow(dead_code)]
pub fn fixture_genesis_live(key_digest: [u32; 8], runtime_hash: Hash, gas_limit: u64) -> LiveTrie {
    let (validators, _) = fixture_committee();
    evm_genesis_live(&evm_genesis_input(
        programs(key_digest, runtime_hash),
        gas_limit,
        0,
        &validators,
        1,
        RuntimeParams::default(),
    ))
}

/// The runtime genesis state of `witness`'s chain specification: the exact
/// pre-state its first block executes over.
#[allow(dead_code)]
pub fn spec_genesis_live(witness: &ConsensusWitness) -> LiveTrie {
    let spec = &witness.chain_spec;
    let live = evm_genesis_live(&evm_genesis_input(
        witness.context.programs,
        spec.genesis_gas_limit,
        spec.genesis_time,
        &spec.initial_validators,
        spec.consensus.chunk_size,
        spec.runtime,
    ));
    assert_eq!(
        live.trie().root(),
        spec.genesis_state_root,
        "fixture chain spec is sealed to its runtime genesis"
    );
    live
}

/// Genesis state for `programs` under the single-key fixture committee and
/// `gas_limit`, with the fixture chain's other constants.
#[allow(dead_code)]
pub fn genesis_for(
    programs: neutrin0_consensus_types::history_proof::ProgramSet,
    gas_limit: u64,
) -> LiveTrie {
    let (validators, _) = fixture_committee();
    evm_genesis_live(&evm_genesis_input(
        programs,
        gas_limit,
        0,
        &validators,
        1,
        RuntimeParams::default(),
    ))
}

/// Four-byte Solidity selector of `signature`.
#[allow(dead_code)]
pub fn selector(signature: &[u8]) -> [u8; 4] {
    keccak256(signature)[..4].try_into().unwrap()
}

/// Calldata of a system method taking the given 32-byte words.
#[allow(dead_code)]
pub fn system_call(signature: &[u8], words: &[[u8; 32]]) -> Vec<u8> {
    let mut data = selector(signature).to_vec();
    for word in words {
        data.extend_from_slice(word);
    }
    data
}

/// Signed call from the funded development account at `nonce`.
#[allow(dead_code)]
pub fn call(nonce: u64, to: Address, data: Vec<u8>, gas_limit: u64) -> RuntimeTransaction {
    sign_transaction(TxEip1559 {
        chain_id: 7,
        nonce,
        gas_limit,
        max_fee_per_gas: 1_000,
        max_priority_fee_per_gas: 1,
        to: TxKind::Call(to),
        value: U256::ZERO,
        input: data.into(),
        ..Default::default()
    })
}

/// Sign `tx` with [`sender_key`] into the runtime's user envelope.
#[allow(dead_code)]
pub fn sign_transaction(tx: TxEip1559) -> RuntimeTransaction {
    let (signature, recovery) =
        sender_key().sign_prehash_recoverable(tx.signature_hash().as_slice());
    let bytes = signature.to_bytes();
    let signature = Signature::from_scalars_and_parity(
        B256::from_slice(&bytes[..32]),
        B256::from_slice(&bytes[32..]),
        recovery.is_y_odd(),
    );
    RuntimeTransaction::User(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
}

/// Wei balance of `address` in `live`.
#[allow(dead_code)]
pub fn balance_of(live: &LiveTrie, address: Address) -> U256 {
    let mut state = TracingState::new(live);
    neutrin0_evm_runtime_core::state::load_account(&mut state, address)
        .unwrap()
        .map_or(U256::ZERO, |account| U256::from_be_bytes(account.balance))
}

/// Executed bodies by header hash. The shared constructors bind a header to
/// the body they executed; tests that import such a block need the body's
/// artifacts, which the compact consensus body does not carry.
static EXECUTED_BODIES: std::sync::Mutex<std::collections::BTreeMap<Hash, Body>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Remember `body` as the executed body of `header`.
#[allow(dead_code)]
pub fn register_executed_body(header: &neutrin0_consensus_types::Header, body: &Body) {
    EXECUTED_BODIES
        .lock()
        .unwrap()
        .insert(header.hash(), body.clone());
}

/// The body the shared constructors executed for `header`.
#[allow(dead_code)]
pub fn executed_body_of(header: &neutrin0_consensus_types::Header) -> Body {
    EXECUTED_BODIES
        .lock()
        .unwrap()
        .get(&header.hash())
        .cloned()
        .expect("body of a fixture-bound block")
}

/// The runtime genesis state of `spec` under `programs`, with the fixture
/// chain's other constants; the caller pins `spec.genesis_state_root` to it.
#[allow(dead_code)]
pub fn genesis_live_for_spec(
    spec: &ChainSpec,
    programs: neutrin0_consensus_types::history_proof::ProgramSet,
) -> LiveTrie {
    evm_genesis_live(&evm_genesis_input(
        programs,
        spec.genesis_gas_limit,
        spec.genesis_time,
        &spec.initial_validators,
        spec.consensus.chunk_size,
        spec.runtime,
    ))
}

/// The body a block executing `input` over `live` carries.
///
/// It holds the execution's artifacts and the encoded transactions, with no
/// vote or participation lane. Block import requires the body's artifact
/// commitment to be the header's receipts root.
#[allow(dead_code)]
pub fn executed_body(live: &LiveTrie, input: &RuntimeBlockInput) -> Body {
    let mut state = TracingState::new(live);
    let result = execute_block(input, &mut state);
    Body {
        artifacts: result.artifacts,
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    }
}

/// Post-state of executing `input` over `live` natively.
#[allow(dead_code)]
pub fn executed(live: &LiveTrie, input: &RuntimeBlockInput) -> LiveTrie {
    let mut state = TracingState::new(live);
    execute_block(input, &mut state);
    let (trie, _) = state.into_committed_and_witness().unwrap();
    LiveTrie::from_trie(trie)
}

/// Signed 21,000-gas transfer of one wei from the funded development
/// account at `nonce`.
#[allow(dead_code)]
pub fn transfer(nonce: u64) -> RuntimeTransaction {
    sign_transaction(TxEip1559 {
        chain_id: 7,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 1_000,
        max_priority_fee_per_gas: 1,
        to: TxKind::Call(Address::from([4; 20])),
        value: U256::from(1),
        ..Default::default()
    })
}

/// Account credited by the chunk proofs successor fixtures ratify.
#[allow(dead_code)]
pub const RATIFIED_CHUNK_PROVER: Hash = neutrin0_primitives::runtime_account([0x7c; 20]);

/// Assemble genuine signatures for one candidate, with every prevoter and a
/// caller-selected precommit quorum.
///
/// The individual claims are identical when
/// reused in alternative subsets; no recursive proof is synthesized here.
#[allow(dead_code, clippy::too_many_lines)]
pub fn certificate_with_precommitters(
    witness: &ConsensusWitness,
    keys: &[SecretKey],
    precommitters: &[usize],
) -> FinalityCert {
    let chunk = as_chunk(
        &neutrin0_prover_chunk::consensus::validate_candidate(witness)
            .unwrap()
            .execution
            .chunk,
    );
    certificate_for_chunk(witness, &chunk, keys, precommitters)
}

/// [`certificate_with_precommitters`] for a caller-supplied chunk, so a
/// deliberately invalid candidate can still carry genuine signatures.
#[allow(dead_code, clippy::too_many_lines)]
pub fn certificate_for_chunk(
    witness: &ConsensusWitness,
    chunk: &neutrin0_consensus_types::Chunk,
    keys: &[SecretKey],
    precommitters: &[usize],
) -> FinalityCert {
    let domain = witness.chain_spec.consensus_domain();
    assert_eq!(keys.len(), witness.context.active_validators.len());
    let leader = neutrin0_consensus_types::bft_leader(
        witness.chain_spec.chain_id,
        chunk.chunk_id,
        0,
        &witness.seed,
        &witness.context.active_validators,
    )
    .unwrap();
    let mut proposal = neutrin0_consensus_types::BftProposal {
        chunk: chunk.clone(),
        round: 0,
        proposer_index: leader,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: witness.blocks.last().map_or(0, |block| block.header.slot),
        receipts: witness
            .blocks
            .iter()
            .map(|block| neutrin0_consensus_types::bft::ReceiptChoice {
                prover_address: block.prover_address,
                statement_key: commitment(&block.statement()),
            })
            .collect(),
        // The certificate ratifies the chunk proof the witness carries, which
        // the Guest verifies (design 08).
        ratified_chunk_proofs: witness
            .ratified
            .iter()
            .map(
                |ratified| neutrin0_consensus_types::bft::ChunkRatification {
                    chunk_id: ratified.statement.chunk.chunk_id,
                    prover_address: ratified.chunk_prover_address,
                    finality_cert_hash: ratified.statement.finality_cert_hash,
                    statement_key: ratified.statement_key(),
                },
            )
            .collect(),
        signature: [0; 96],
    };
    proposal.signature = keys[usize::try_from(leader).unwrap()]
        .sign(&proposal.signing_message(domain))
        .to_bytes();
    // Every value vote signs the proposal's payment selection (design 08).
    let selection = proposal.selection();
    let vote_data = |phase| FinalityVoteData {
        chunk_id: chunk.chunk_id,
        round: 0,
        chunk_hash: chunk.hash(),
        selection,
        phase,
    };
    let aggregate = |phase, indices: &[usize]| {
        let message = vote_data(phase).signing_message(domain);
        let signatures: Vec<_> = indices
            .iter()
            .map(|index| keys[*index].sign(&message))
            .collect();
        let mut bits = BitVec::from_bytes(0, Vec::new()).unwrap();
        for index in 0..keys.len() {
            bits.push(indices.contains(&index));
        }
        AggregatedVote {
            aggregation_bits: bits,
            signature: aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
                .unwrap()
                .to_bytes(),
        }
    };
    let prevoters: Vec<_> = (0..keys.len()).collect();
    let prevote = aggregate(FinalityVotePhase::Prevote, &prevoters);
    let locking = neutrin0_consensus_types::QuorumCertificate {
        data: vote_data(FinalityVotePhase::Prevote),
        aggregate: prevote.clone(),
    };
    let claims = |phase, indices: &[usize]| {
        let data = vote_data(phase);
        indices
            .iter()
            .map(|index| {
                let mut claim = neutrin0_consensus_types::VoteAttestation {
                    validator_index: u32::try_from(*index).unwrap(),
                    vote: data.clone(),
                    vote_signature: keys[*index].sign(&data.signing_message(domain)).to_bytes(),
                    proof_acceptance: (phase == FinalityVotePhase::Precommit).then(|| {
                        neutrin0_consensus_types::ProofManifest {
                            proof_hashes: vec![[1; 32]; witness.blocks.len()],
                        }
                        .commitment()
                    }),
                    unlock_quorum: (phase == FinalityVotePhase::Precommit).then(|| locking.clone()),
                    signature: [0; 96],
                };
                claim.signature = keys[*index].sign(&claim.signing_message(domain)).to_bytes();
                claim
            })
            .collect()
    };
    FinalityCert {
        proof_manifests: vec![neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![[1; 32]; witness.blocks.len()],
        }],
        proposal,
        prevote_attestations: claims(FinalityVotePhase::Prevote, &prevoters),
        precommit_attestations: claims(FinalityVotePhase::Precommit, precommitters),
        chunk_id: chunk.chunk_id,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote,
        precommit: aggregate(FinalityVotePhase::Precommit, precommitters),
        active_validator_set_root: chunk.active_validator_set_root,
    }
}

/// Re-execute genesis under a complete validator set for certificate-selection
/// regressions. Every validator is eligible, and all cryptographic signatures
/// use the resulting exact chain-spec domain.
#[allow(dead_code)]
pub fn fixture_with_validator_keys(
    key_digest: [u32; 8],
    runtime_hash: Hash,
    keys: &[SecretKey],
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness, LiveTrie) {
    fixture_with_validator_keys_and_chunk_size(key_digest, runtime_hash, keys, 1)
}

/// Native fixture retaining the first execution input/witness and the complete
/// post-chunk state, with one or two genuinely executed blocks.
#[allow(dead_code, clippy::too_many_lines)]
pub fn fixture_with_validator_keys_and_chunk_size(
    key_digest: [u32; 8],
    runtime_hash: Hash,
    keys: &[SecretKey],
    chunk_size: u64,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness, LiveTrie) {
    assert!(!keys.is_empty());
    assert!((1..=2).contains(&chunk_size));
    let (mut witness, mut input, _) = fixture(key_digest, runtime_hash);
    let prototype = witness.context.active_validators[0].clone();
    let validators: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| Validator {
            pubkey: key.public_key().to_bytes(),
            withdrawal_credentials: credentials(u8::try_from(index + 8).unwrap()),
            ..prototype.clone()
        })
        .collect();
    witness
        .chain_spec
        .initial_validators
        .clone_from(&validators);
    witness.chain_spec.genesis_validator_set_root = commitment(&validators);
    witness.chain_spec.consensus.expected_proposers_per_slot =
        fixed_u128_from_integer(u64::try_from(keys.len()).unwrap());
    witness.chain_spec.consensus.chunk_size = chunk_size;
    // The committee changed, so genesis state (and its root in the
    // specification) is re-derived for the new validators.
    let live = evm_genesis_live(&evm_genesis_input(
        witness.context.programs,
        witness.chain_spec.genesis_gas_limit,
        witness.chain_spec.genesis_time,
        &validators,
        chunk_size,
        witness.chain_spec.runtime,
    ));
    witness.chain_spec.genesis_state_root = live.trie().root();
    witness.context = neutrin0_prover_chunk::consensus::genesis_context(
        &witness.chain_spec,
        witness.context.programs,
    );
    input.evidence_anchor.chain_spec_hash = witness.chain_spec.hash();
    input.evidence_anchor.chunk_size = chunk_size;
    input.proposer_address = validators[0].withdrawal_credentials;
    input.active_validators = validators;
    let block = &mut witness.blocks[0];
    block.header.vrf_proof = keys[0]
        .sign(&neutrin0_vrf::vrf_message(
            witness.chain_spec.consensus_domain(),
            &witness.seed,
            block.header.slot,
        ))
        .to_bytes();
    input.context = neutrin0_prover_chunk::execution::runtime_context(
        &block.header,
        neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(&witness.chain_spec),
    );
    let mut state = TracingState::new(&live);
    let result = execute_block(&input, &mut state);
    let (committed, execution_witness) = state.into_committed_and_witness().unwrap();
    let mut post = LiveTrie::from_trie(committed);
    let body = Body {
        artifacts: result.artifacts,
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    };
    bind_executed_block(
        block,
        &input,
        result.output,
        &body,
        &keys[0],
        &witness.chain_spec,
    );
    witness.bodies = vec![neutrin0_prover_chunk::body::ConsensusBody::from_body(&body).unwrap()];
    if chunk_size == 2 {
        append_executed_block(&mut witness, &input, &mut post, &keys[0]);
    }
    let mut trace = TracingState::new(&post);
    neutrin0_prover_chunk::rotation::witness_keys_from(&mut trace);
    witness.post_state = trace.into_witness().unwrap();
    let signers: Vec<_> = (0..keys.len()).collect();
    witness.finality_cert = certificate_with_precommitters(&witness, keys, &signers);
    (witness, input, execution_witness, post)
}

/// Execute a successor whose first block chooses the exact previous certificate.
#[allow(clippy::too_many_arguments, clippy::too_many_lines, dead_code)]
pub fn successor_with_participation(
    first: &ConsensusWitness,
    prior_input: &RuntimeBlockInput,
    pre: &LiveTrie,
    keys: &[SecretKey],
    selected: neutrin0_consensus_types::proving::CarriedCertificate,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness, LiveTrie) {
    successor_with_participation_and_votes(first, prior_input, pre, keys, selected, &[])
}

/// Execute positive participation with genuine signed historical vote envelopes.
#[allow(clippy::too_many_arguments, clippy::too_many_lines, dead_code)]
pub fn successor_with_participation_and_votes(
    first: &ConsensusWitness,
    prior_input: &RuntimeBlockInput,
    pre: &LiveTrie,
    keys: &[SecretKey],
    selected: neutrin0_consensus_types::proving::CarriedCertificate,
    votes: &[neutrin0_consensus_types::FinalityVote],
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness, LiveTrie) {
    use neutrin0_prover_chunk::history::{HistoricalChunk, HistoricalContextOpening};
    let validated =
        neutrin0_prover_chunk::consensus::validate_consensus_with_context(first).unwrap();
    assert!((1..=2).contains(&first.context.chunk_size));
    let source = HistoricalChunk {
        runtime_code_hash: first.context.programs.runtime_code_hash,
        block_guest_vk_digest: first.context.programs.execution.block,
        start_boundary: validated.statement.start.commitment(),
        chunk: as_chunk(&validated.statement.chunk),
        validators: first.context.active_validators.clone(),
        seed: first.seed,
        finality: first.finality_cert.clone(),
    };
    let leaf = commitment(&source.evidence_context());
    let mut next = first.clone();
    next.context = validated.next_context;
    next.seed = validated.statement.end.seed;
    // The successor's certificate ratifies the previous chunk's proof, whose
    // public values the Guest verifies (design 08).
    next.ratified = vec![neutrin0_prover_chunk::consensus::ChunkReceiptStatement {
        statement: validated.statement.clone(),
        chunk_prover_address: RATIFIED_CHUNK_PROVER,
    }];
    let path = next.history.frontier.append_path(leaf).unwrap();
    next.history.frontier.append(leaf).unwrap();
    next.history.records = vec![HistoricalContextOpening {
        record: (&source).into(),
        path,
    }];
    let mut input = prior_input.clone();
    input.block_height = validated.statement.end.height + 1;
    input.evidence_anchor.chunk_id = next.context.chunk_id;
    input
        .active_validators
        .clone_from(&next.context.active_validators);
    input.evidence_anchor.history_root = next.context.history_root;
    input.participation =
        neutrin0_consensus_types::participation::ParticipationReport::from_certificate(
            first.context.chunk_id,
            &first.context.active_validators,
            &selected.quorum.aggregate.aggregation_bits,
        );
    // Design 08: the same carried certificate yields the proving report.
    input.proving = neutrin0_consensus_types::proving::ProvingReport::from_certificate(
        &source.chunk,
        &first.context.active_validators,
        &selected,
    );
    next.blocks.truncate(1);
    let block = &mut next.blocks[0];
    block.header.height = input.block_height;
    block.header.slot = first.blocks.last().unwrap().header.slot + 1;
    block.header.timestamp = next.chain_spec.genesis_time
        + next.chain_spec.consensus.slot_duration_secs * block.header.slot;
    block.header.parent_hash = validated.statement.end.block_hash;
    block.header.vrf_proof = keys[0]
        .sign(&neutrin0_vrf::vrf_message(
            next.chain_spec.consensus_domain(),
            &next.seed,
            block.header.slot,
        ))
        .to_bytes();
    input.context =
        neutrin0_prover_chunk::execution::runtime_context(&block.header, validated.statement.end);
    let source_hash = as_chunk(&validated.statement.chunk).hash();
    let participation_votes = votes
        .iter()
        .flat_map(|vote| {
            vote.attestations.iter().map(|claim| {
                neutrin0_consensus_types::participation::ParticipationVote {
                    data: claim.vote.clone(),
                    validator_index: claim.validator_index,
                    vote_signature: claim.vote_signature,
                }
            })
        })
        .collect::<Vec<_>>();
    input.participation_acks = participation_votes
        .iter()
        .filter_map(|vote| {
            neutrin0_consensus_types::participation::acknowledgement_from_participation_vote(
                next.context.chunk_id,
                source_hash,
                &first.context.active_validators,
                vote,
            )
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut trace = TracingState::new(pre);
    let result = execute_block(&input, &mut trace);
    let (committed, execution_witness) = trace.into_committed_and_witness().unwrap();
    let mut post = LiveTrie::from_trie(committed);
    let body = Body {
        participation: Some(selected),
        participation_acks: participation_votes,
        artifacts: result.artifacts,
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    };
    bind_executed_block(
        block,
        &input,
        result.output,
        &body,
        &keys[0],
        &next.chain_spec,
    );
    next.bodies = vec![neutrin0_prover_chunk::body::ConsensusBody::from_body(&body).unwrap()];
    if next.context.chunk_size == 2 {
        append_executed_block(&mut next, &input, &mut post, &keys[0]);
    }
    let mut trace = TracingState::new(&post);
    neutrin0_prover_chunk::rotation::witness_keys_from(&mut trace);
    next.post_state = trace.into_witness().unwrap();
    let signers: Vec<_> = (0..keys.len()).collect();
    next.finality_cert = certificate_with_precommitters(&next, keys, &signers);
    (next, input, execution_witness, post)
}

fn append_executed_block(
    witness: &mut ConsensusWitness,
    first_input: &RuntimeBlockInput,
    post: &mut LiveTrie,
    key: &SecretKey,
) {
    let parent = witness.blocks.last().unwrap();
    let mut block = parent.clone();
    let mut input = first_input.clone();
    input.participation_acks.clear();
    input.block_height = parent.header.height + 1;
    block.header.height = input.block_height;
    block.header.slot += 1;
    block.header.timestamp = witness.chain_spec.genesis_time
        + witness.chain_spec.consensus.slot_duration_secs * block.header.slot;
    block.header.parent_hash = parent.header.hash();
    block.header.vrf_proof = key
        .sign(&neutrin0_vrf::vrf_message(
            witness.chain_spec.consensus_domain(),
            &witness.seed,
            block.header.slot,
        ))
        .to_bytes();
    input.context = neutrin0_prover_chunk::execution::runtime_context(
        &block.header,
        first_input.context.finalized,
    );
    let mut trace = TracingState::new(post);
    let result = execute_block(&input, &mut trace);
    let (committed, _) = trace.into_committed_and_witness().unwrap();
    let body = Body {
        artifacts: result.artifacts,
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    };
    bind_executed_block(
        &mut block,
        &input,
        result.output,
        &body,
        key,
        &witness.chain_spec,
    );
    *post = LiveTrie::from_trie(committed);
    witness.blocks.push(block);
    witness
        .bodies
        .push(neutrin0_prover_chunk::body::ConsensusBody::from_body(&body).unwrap());
}

/// Commit `output` into `block`'s header and public inputs and sign the
/// header with `key` under `spec`'s domain.
#[allow(dead_code)]
pub fn bind_executed_block(
    block: &mut ProvenBlock,
    input: &RuntimeBlockInput,
    output: neutrin0_runtime_abi::RuntimeBlockOutput,
    body: &Body,
    key: &SecretKey,
    spec: &ChainSpec,
) {
    let header = &mut block.header;
    header.state_root = output.post_state_root;
    header.transactions_root = output.transactions_root;
    header.votes_root =
        neutrin0_consensus_types::participation::vote_lane_root(&body.participation_acks);
    header.receipts_root = output.receipts_root;
    header.runtime_extra = output.consensus_candidates_root;
    header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    header.gas_used = output.gas_used;
    header.da_root = neutrin0_prover_chunk::consensus::body_da_root(body);
    header.signature = key
        .sign(
            &spec
                .consensus_domain()
                .signing_message(DOMAIN_PROPOSER_SIG, &header.hash()),
        )
        .to_bytes();
    let pi = &mut block.public_inputs;
    pi.context = input.context.into();
    pi.height = input.block_height;
    pi.block_hash = header.hash();
    pi.parent_block_hash = header.parent_hash;
    pi.state_root_before = output.pre_state_root;
    pi.state_root_after = output.post_state_root;
    pi.transactions_root = output.transactions_root;
    pi.receipt_root = output.receipts_root;
    pi.da_root = header.da_root;
    pi.runtime_extra = output.consensus_candidates_root;
    pi.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    pi.proposer_address = input.proposer_address;
    pi.gas_used = output.gas_used;
    block.output = output;
    register_executed_body(&block.header, body);
}

/// The embedded Guest set a fixture backend reports: the execution Guests of
/// [`programs`] plus the pinned consensus Guests.
#[allow(dead_code)] // Used by the engine and node suites that share this module.
pub const fn guests(
    key_digest: [u32; 8],
    runtime_hash: Hash,
) -> neutrin0_consensus_types::history_proof::GuestPrograms {
    neutrin0_consensus_types::history_proof::GuestPrograms {
        execution: programs(key_digest, runtime_hash).execution,
        chunk: chunk_program(),
    }
}

/// The chunk identity every fixture pins.
pub const fn chunk_program() -> neutrin0_consensus_types::history_proof::VkDigest {
    [7; 8]
}

#[allow(clippy::too_many_lines)] // The complete signed protocol fixture is intentionally explicit.
/// Construct matching execution and consensus inputs.
pub fn fixture(
    key_digest: [u32; 8],
    runtime_hash: Hash,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness) {
    fixture_with_transactions(key_digest, runtime_hash, vec![], 30_000_000)
}

/// Executed fixture with caller-selected transactions and gas limit.
#[allow(clippy::too_many_lines)]
pub fn fixture_with_transactions(
    key_digest: [u32; 8],
    runtime_hash: Hash,
    transactions: Vec<RuntimeTransaction>,
    gas_limit: u64,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness) {
    fixture_with_live(
        key_digest,
        runtime_hash,
        transactions,
        gas_limit,
        &fixture_genesis_live(key_digest, runtime_hash, gas_limit),
    )
}

/// Fixture anchored in caller-supplied genesis state (see
/// [`fixture_genesis_live`]), with traced witnesses.
pub fn fixture_with_live(
    key_digest: [u32; 8],
    runtime_hash: Hash,
    transactions: Vec<RuntimeTransaction>,
    gas_limit: u64,
    live: &LiveTrie,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness) {
    fixture_with_block_gas_limit(
        key_digest,
        runtime_hash,
        transactions,
        gas_limit,
        gas_limit,
        live,
    )
}

/// [`fixture_with_live`] whose block executes, is proven and is signed under
/// `block_gas_limit` while the chain specification names `gas_limit`.
#[allow(clippy::too_many_lines)]
pub fn fixture_with_block_gas_limit(
    key_digest: [u32; 8],
    runtime_hash: Hash,
    transactions: Vec<RuntimeTransaction>,
    gas_limit: u64,
    block_gas_limit: u64,
    live: &LiveTrie,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness) {
    fixture_with_execution(
        programs(key_digest, runtime_hash),
        chunk_program(),
        credentials(8),
        transactions,
        gas_limit,
        block_gas_limit,
        live,
        execute_block,
    )
}

/// Complete fixture executed by an independently supplied runtime core.
#[allow(clippy::too_many_arguments, clippy::too_many_lines, dead_code)]
pub fn fixture_with_execution<'a>(
    active: neutrin0_primitives::ProgramSet,
    chunk_program: neutrin0_consensus_types::history_proof::VkDigest,
    credentials: Hash,
    transactions: Vec<neutrin0_runtime_abi::RuntimeTransaction>,
    gas_limit: u64,
    block_gas_limit: u64,
    live: &'a LiveTrie,
    execute: impl Fn(
        &RuntimeBlockInput,
        &mut TracingState<'a>,
    ) -> neutrin0_runtime_abi::RuntimeBlockResult,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness) {
    fixture_with_execution_at_time(
        active,
        chunk_program,
        credentials,
        transactions,
        gas_limit,
        block_gas_limit,
        live,
        execute,
        0,
    )
}

/// Complete signed fixture using a fresh authenticated genesis timestamp.
#[allow(clippy::too_many_arguments, clippy::too_many_lines, dead_code)]
pub fn fixture_with_execution_at_time<'a>(
    active: neutrin0_primitives::ProgramSet,
    chunk_program: neutrin0_consensus_types::history_proof::VkDigest,
    credentials: Hash,
    transactions: Vec<neutrin0_runtime_abi::RuntimeTransaction>,
    gas_limit: u64,
    block_gas_limit: u64,
    live: &'a LiveTrie,
    execute: impl Fn(
        &RuntimeBlockInput,
        &mut TracingState<'a>,
    ) -> neutrin0_runtime_abi::RuntimeBlockResult,
    genesis_time: u64,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness) {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let validators = vec![Validator {
        pubkey: key.public_key().to_bytes(),
        withdrawal_credentials: credentials,
        effective_stake: 100,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }];
    fixture_with_execution_and_validators(
        active,
        chunk_program,
        &validators,
        &[key],
        transactions,
        gas_limit,
        block_gas_limit,
        live,
        execute,
        genesis_time,
    )
}

/// Execute and sign genesis under an explicit committee and its exact keys.
#[allow(clippy::too_many_arguments, clippy::too_many_lines, dead_code)]
pub fn fixture_with_execution_and_validators<'a>(
    active: neutrin0_primitives::ProgramSet,
    chunk_program: neutrin0_consensus_types::history_proof::VkDigest,
    validators: &[Validator],
    keys: &[SecretKey],
    transactions: Vec<neutrin0_runtime_abi::RuntimeTransaction>,
    gas_limit: u64,
    block_gas_limit: u64,
    live: &'a LiveTrie,
    execute: impl Fn(
        &RuntimeBlockInput,
        &mut TracingState<'a>,
    ) -> neutrin0_runtime_abi::RuntimeBlockResult,
    genesis_time: u64,
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness) {
    fixture_with_execution_configuration(
        active,
        chunk_program,
        validators,
        keys,
        transactions,
        gas_limit,
        block_gas_limit,
        live,
        execute,
        genesis_time,
        |_| {},
    )
}

/// Configure a test chain before deriving its domain, execution anchor and signatures.
#[allow(clippy::too_many_arguments, clippy::too_many_lines, dead_code)]
pub fn fixture_with_execution_configuration<'a>(
    active: neutrin0_primitives::ProgramSet,
    chunk_program: neutrin0_consensus_types::history_proof::VkDigest,
    validators: &[Validator],
    keys: &[SecretKey],
    transactions: Vec<neutrin0_runtime_abi::RuntimeTransaction>,
    gas_limit: u64,
    block_gas_limit: u64,
    live: &'a LiveTrie,
    execute: impl Fn(
        &RuntimeBlockInput,
        &mut TracingState<'a>,
    ) -> neutrin0_runtime_abi::RuntimeBlockResult,
    genesis_time: u64,
    configure: impl FnOnce(&mut ChainSpec),
) -> (ConsensusWitness, RuntimeBlockInput, StateWitness) {
    assert!(!keys.is_empty());
    assert_eq!(validators.len(), keys.len());
    assert!(
        validators
            .iter()
            .zip(keys)
            .all(|(validator, key)| validator.pubkey == key.public_key().to_bytes())
    );
    let key_digest = active.execution.block;
    let runtime_hash = active.runtime_code_hash;
    let key = &keys[0];
    let root = commitment(&validators);
    let mut spec = ChainSpec {
        genesis_execution: active.execution,
        name: BoundedBytes::new(b"consensus-test".to_vec()).unwrap(),
        chain_id: 7,
        genesis_time,
        genesis_gas_limit: gas_limit,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: runtime_hash,
        genesis_chunk: chunk_program,
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [0; 32],
        genesis_state_root: live.trie().root(),
        genesis_block_hash: [2; 32],
        genesis_validator_set_root: root,
        consensus: ConsensusParams {
            chunk_size: 1,
            expected_proposers_per_slot: fixed_u128_from_integer(
                u64::try_from(keys.len()).unwrap(),
            ),
            ..ConsensusParams::default()
        },
        proof: ProofParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators.to_vec(),
        metadata: BoundedBytes::new(vec![]).unwrap(),
    };
    configure(&mut spec);
    let input = RuntimeBlockInput {
        active_validators: spec.initial_validators.clone(),
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),

        context: neutrin0_consensus_types::runtime::ConsensusExecutionContext {
            slot: 1,
            timestamp: genesis_time
                .checked_add(spec.consensus.slot_duration_secs)
                .unwrap(),
            parent_block_hash: spec.genesis_block_hash,
            proposer_vrf_output: neutrin0_vrf::proof_output(
                &key.sign(&neutrin0_vrf::vrf_message(
                    spec.consensus_domain(),
                    &spec.genesis_seed,
                    1,
                ))
                .to_bytes(),
            ),
            finalized: neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(&spec),
        },
        evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor {
            fact_guest_vk_digest: active.execution.fact,
            chain_spec_hash: spec.hash(),
            chunk_id: 0,
            history_root: neutrin0_prover_chunk::history::history_commitment(&[]),
            block_guest_vk_digest: key_digest,
            evidence_guest_vk_digest: active.execution.evidence,
            unbonding_delay_blocks: spec.runtime.unbonding_delay_blocks,
            chunk_size: spec.consensus.chunk_size,

            max_block_proving_input_bytes:
                neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
            block_gas_limit: spec.genesis_gas_limit,
        },
        chain_id: 7,
        block_height: 1,
        block_gas_limit,
        proposer_address: validators[0].withdrawal_credentials,
        participation: None,
        proving: None,
        transactions,
    };
    // Execution witness over the pre-state, then the chunk's rotation witness
    // over the committed post-state, exactly as the engine builds them.
    let mut state = TracingState::new(live);
    let result = execute(&input, &mut state);
    let output = result.output;
    let (committed, execution_witness) = state.into_committed_and_witness().unwrap();
    let post_live = LiveTrie::from_trie(committed);
    assert_eq!(output.post_state_root, post_live.state_root());
    let mut post_state = TracingState::new(&post_live);
    neutrin0_prover_chunk::rotation::witness_keys_from(&mut post_state);
    let witness = post_state.into_witness().unwrap();
    let body = Body {
        artifacts: result.artifacts,
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    };
    let mut header = Header {
        height: 1,
        slot: 1,
        parent_hash: spec.genesis_block_hash,
        proposer_index: 0,
        vrf_proof: key
            .sign(&neutrin0_vrf::vrf_message(
                spec.consensus_domain(),
                &spec.genesis_seed,
                1,
            ))
            .to_bytes(),
        state_root: output.post_state_root,
        transactions_root: output.transactions_root,
        votes_root: merkle_root_of_hashes(&[]),
        da_root: neutrin0_prover_chunk::consensus::body_da_root(&body),
        runtime_extra: output.consensus_candidates_root,
        inputs_root: neutrin0_prover_chunk::execution::output_inputs_root(&output),
        receipts_root: output.receipts_root,
        gas_used: output.gas_used,
        gas_limit: input.block_gas_limit,
        timestamp: genesis_time
            .checked_add(spec.consensus.slot_duration_secs)
            .unwrap(),
        signature: [0; 96],
    };
    let message = spec
        .consensus_domain()
        .signing_message(DOMAIN_PROPOSER_SIG, &header.hash());
    header.signature = key.sign(&message).to_bytes();
    let pi = BlockProofPublicInputs {
        context: (input.context).into(),
        chain_id: 7,
        height: 1,
        parent_block_hash: header.parent_hash,
        block_hash: header.hash(),
        state_root_before: output.pre_state_root,
        state_root_after: output.post_state_root,
        transactions_root: output.transactions_root,
        receipt_root: output.receipts_root,
        da_root: header.da_root,
        vm_code_hash: runtime_hash,
        block_program: key_digest,
        gas_used: output.gas_used,
        gas_limit: input.block_gas_limit,
        proposer_address: input.proposer_address,
        runtime_extra: output.consensus_candidates_root,
        inputs_root: neutrin0_prover_chunk::execution::output_inputs_root(&output),
    };
    let context = ExecutionContext {
        identity_sanctions_root: [0; 32],

        seed: [0; 32],
        chain_id: 7,
        chain_spec_hash: spec.hash(),
        chunk_id: 0,
        chunk_size: 1,
        parent_block_hash: header.parent_hash,
        pre_state_root: output.pre_state_root,
        parent_slot: 0,
        vm_code_hash: runtime_hash,
        programs: active,
        participation: neutrin0_consensus_types::participation::NO_PARTICIPATION,
        proving: neutrin0_consensus_types::proving::NO_PROVING,
        active_validators: validators.to_vec(),
        history_root: neutrin0_prover_chunk::history::history_commitment(&[]),
        fork: None,
    };
    let blocks = vec![ProvenBlock {
        header,
        prover_address: pi.proposer_address,
        public_inputs: pi,
        output,
    }];
    let mut statement = validate_execution(&context, &blocks).unwrap();
    statement.chunk.next_validator_set_root = commitment(
        &rotate_from_witness(
            validators,
            &spec.consensus,
            spec.runtime.unbonding_delay_blocks,
            0,
            statement.chunk.end_state_root,
            &witness,
        )
        .unwrap(),
    );
    let chunk = as_chunk(&statement.chunk);
    let mut proposal = neutrin0_consensus_types::BftProposal {
        chunk: chunk.clone(),
        round: 0,
        proposer_index: 0,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: blocks.last().map_or(0, |block| block.header.slot),
        receipts: blocks
            .iter()
            .map(|block| neutrin0_consensus_types::bft::ReceiptChoice {
                prover_address: block.prover_address,
                statement_key: commitment(&block.statement()),
            })
            .collect(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    };
    proposal.signature = key
        .sign(&proposal.signing_message(spec.consensus_domain()))
        .to_bytes();
    let selection = proposal.selection();
    let aggregate = |phase| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: chunk.hash(),
            selection,
            phase,
        };
        let msg = data.signing_message(spec.consensus_domain());
        AggregatedVote {
            aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: key.sign(&msg).to_bytes(),
        }
    };
    let mut cert = FinalityCert {
        proof_manifests: vec![neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![[1; 32]],
        }],
        proposal,
        prevote_attestations: Vec::new(),
        precommit_attestations: Vec::new(),
        chunk_id: 0,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote: aggregate(FinalityVotePhase::Prevote),
        precommit: aggregate(FinalityVotePhase::Precommit),
        active_validator_set_root: root,
    };
    let mut claim = neutrin0_consensus_types::VoteAttestation {
        validator_index: 0,
        vote: cert.precommit_vote().data,
        vote_signature: cert.precommit.signature,
        proof_acceptance: Some(
            neutrin0_consensus_types::ProofManifest {
                proof_hashes: vec![[1; 32]],
            }
            .commitment(),
        ),
        unlock_quorum: None,
        signature: [0; 96],
    };
    claim.signature = key
        .sign(&claim.signing_message(spec.consensus_domain()))
        .to_bytes();
    cert.precommit_attestations.push(claim);
    let mut claim = neutrin0_consensus_types::VoteAttestation {
        validator_index: 0,
        vote: cert.prevote_vote().data,
        vote_signature: cert.prevote.signature,
        proof_acceptance: None,
        unlock_quorum: None,
        signature: [0; 96],
    };
    claim.signature = key
        .sign(&claim.signing_message(spec.consensus_domain()))
        .to_bytes();
    cert.prevote_attestations.push(claim);
    register_executed_body(&blocks[0].header, &body);
    let mut result = (
        ConsensusWitness {
            identity_sanctions: neutrin0_runtime_abi::StateWitness {
                pre_state_root: [0; 32],
                nodes: Vec::new(),
                values: Vec::new(),
                witnessed_keys: Vec::new(),
            },

            chain_spec: spec,
            context,
            seed: [0; 32],
            blocks,
            bodies: vec![neutrin0_prover_chunk::body::ConsensusBody::from_body(&body).unwrap()],
            post_state: witness,
            history: neutrin0_prover_chunk::history::HistoryWitness::default(),
            finality_cert: cert,
            facts: Vec::new(),
            ratified: Vec::new(),
        },
        input,
        execution_witness,
    );
    let signers: Vec<_> = (0..keys.len()).collect();
    // A fixture the chain refuses (for example an over-limit header) still
    // carries genuine signatures over the chunk its execution produced.
    let candidate = neutrin0_prover_chunk::consensus::validate_candidate(&result.0).map_or_else(
        |_| chunk.clone(),
        |candidate| as_chunk(&candidate.execution.chunk),
    );
    result.0.finality_cert = certificate_for_chunk(&result.0, &candidate, keys, &signers);
    result
}
