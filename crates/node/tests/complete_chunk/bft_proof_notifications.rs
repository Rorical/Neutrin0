//! Exact certificate fencing and event-driven follow-up using native consensus.

use super::*;
use neutrin0_consensus_types::{FinalityCert, FinalityVote, FinalityVoteData, FinalityVotePhase};
use neutrin0_primitives::{BitVec, ConsensusDomain, Hash, Validator, fixed_u128_from_integer};
use neutrin0_prover_chunk::consensus::{as_chunk, genesis_context, validate_candidate};
use neutrin0_runtime_core::{
    StateBackend,
    host::{LiveTrie, TracingState},
};
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

struct NotifyingNativeConsensusBackend {
    inner: NativeConsensusBackend,
    started: UnboundedSender<FinalityCert>,
    verified: UnboundedSender<Hash>,
}

impl ProofSystem for NotifyingNativeConsensusBackend {
    type BlockProof = BlockReceiptStatement;
    type ChunkProof = neutrin0_consensus_types::history_proof::ChunkReceiptStatement;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        self.inner.prove_block(witness, inputs, prover_address)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.inner.verify_block(proof, inputs)
    }

    fn programs(&self) -> Option<neutrin0_consensus_types::history_proof::GuestPrograms> {
        self.inner.programs()
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<BlockReceiptStatement, ProofError> {
        self.inner.block_statement(proof)
    }

    fn prove_consensus_chunk(
        &self,
        proofs: &[Self::BlockProof],
        ratified: &[Self::ChunkProof],
        witness: &ConsensusWitness,
        chunk_prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::ChunkProof, ProofError> {
        self.started.send(witness.finality_cert.clone()).unwrap();
        self.inner
            .prove_consensus_chunk(proofs, ratified, witness, chunk_prover_address)
    }

    fn chunk_prover_address(
        &self,
        proof: &Self::ChunkProof,
    ) -> Result<neutrin0_primitives::Hash, ProofError> {
        Ok(proof.chunk_prover_address)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &neutrin0_consensus_types::history_proof::ChunkReceiptStatement,
    ) -> Result<(), ProofError> {
        self.inner.verify_consensus_chunk(proof, expected)?;
        self.verified
            .send(expected.statement.finality_cert_hash)
            .unwrap();
        Ok(())
    }
}

fn voter(index: u32) -> ProposerKey {
    let seed = u8::try_from(42 + index).unwrap();
    ProposerKey::from_ikm(&[seed; 32], index).unwrap()
}

#[allow(
    clippy::too_many_lines,
    reason = "Changing the genesis committee rebuilds execution context, public values and signed headers together."
)]
/// Four equal seats: any three hold strictly more than two thirds, any two
/// do not.
fn four_validator_fixture() -> (Engine<MemoryDatabase>, ConsensusWitness) {
    let (mut witness, mut input, _) = support::fixture([1; 8], [4; 32]);
    let validators = (0..4)
        .map(|index| Validator {
            pubkey: *voter(index).public_key_bytes(),
            withdrawal_credentials: support::credentials(u8::try_from(8 + index).unwrap()),
            effective_stake: 100,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect::<Vec<_>>();
    witness
        .chain_spec
        .initial_validators
        .clone_from(&validators);
    witness.chain_spec.genesis_validator_set_root =
        neutrin0_consensus_types::evidence::commitment(&validators);
    witness.chain_spec.consensus.expected_proposers_per_slot = fixed_u128_from_integer(4);
    witness.chain_spec.consensus.bft_round_timeout_base_secs = 1;
    witness.chain_spec.consensus.bft_round_timeout_step_secs = 1;
    // The committee changed, so the runtime genesis (and its root in the
    // specification) is re-derived for the four validators.
    let live = support::evm_genesis_live(&support::evm_genesis_input(
        witness.context.programs,
        witness.chain_spec.genesis_gas_limit,
        witness.chain_spec.genesis_time,
        &validators,
        witness.chain_spec.consensus.chunk_size,
        witness.chain_spec.runtime,
    ));
    witness.chain_spec.genesis_state_root = live.trie().root();
    witness.chain_spec.validate().unwrap();
    input.evidence_anchor.chain_spec_hash = witness.chain_spec.hash();
    witness.context = genesis_context(&witness.chain_spec, witness.context.programs);
    let domain = witness.chain_spec.consensus_domain();
    let header = &mut witness.blocks[0].header;
    header.vrf_proof = voter(0).vrf_eval(domain, &witness.seed, header.slot);
    input.proposer_address = validators[0].withdrawal_credentials;
    input.active_validators = validators;
    input.context = neutrin0_prover_chunk::execution::runtime_context(
        header,
        neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(&witness.chain_spec),
    );
    let mut traced = TracingState::new(&live);
    for key in neutrin0_prover_chunk::rotation::witness_keys_from(&mut traced) {
        let _ = traced.read(&key);
    }
    let output = neutrin0_evm_runtime_core::execute_block(&input, &mut traced).output;
    header.state_root = output.post_state_root;
    header.transactions_root = output.transactions_root;
    header.receipts_root = output.receipts_root;
    header.runtime_extra = output.consensus_candidates_root;
    header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    header.gas_used = output.gas_used;
    header.signature = voter(0).sign_proposer_message(domain, &header.hash());
    let hash = header.hash();
    witness.blocks[0].output = output.clone();
    // The candidate's post-state witness opens the rotation records of the
    // executed state.
    let (committed, _) = traced.into_committed_and_witness().unwrap();
    let post = LiveTrie::from_trie(committed);
    let mut rotation = TracingState::new(&post);
    neutrin0_prover_chunk::rotation::witness_keys_from(&mut rotation);
    witness.post_state = rotation.into_witness().unwrap();
    let inputs = &mut witness.blocks[0].public_inputs;
    *inputs.context = input.context;
    inputs.block_hash = hash;
    inputs.state_root_before = output.pre_state_root;
    inputs.state_root_after = output.post_state_root;
    inputs.transactions_root = output.transactions_root;
    inputs.receipt_root = output.receipts_root;
    inputs.runtime_extra = output.consensus_candidates_root;
    inputs.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    inputs.gas_used = output.gas_used;
    let mut engine = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    engine.install_genesis_state(live.trie().clone()).unwrap();
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    engine
        .import_block(
            &neutrin0_consensus_types::Block {
                header: block.header.clone(),
                body: support::executed_body(&live, &input),
            },
            &super::native_executor::NativeExecutor,
        )
        .unwrap();
    engine
        .store_mut()
        .put_proven_block(
            &hash,
            &BlockProof {
                prover_address: block.public_inputs.proposer_address,
                statement_key: neutrin0_consensus_types::evidence::commitment(&block.statement()),
                height: 1,
                block_hash: hash,
                public_inputs: block.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&block.statement()).unwrap(),
            },
        )
        .unwrap();
    validate_candidate(&witness).unwrap();
    (engine, witness)
}

fn signed_vote(
    domain: ConsensusDomain,
    chunk_hash: Hash,
    phase: FinalityVotePhase,
    index: u32,
    proof_hash: Hash,
    selection: Hash,
) -> FinalityVote {
    signed_chunk_vote(domain, 0, chunk_hash, phase, index, proof_hash, selection)
}

/// The payment selection the session's accepted proposal fixed, which value
/// votes sign (design 08).
fn session_selection(engine: &Engine<MemoryDatabase>, chunk_id: u64) -> Hash {
    engine
        .bft_session(chunk_id)
        .and_then(neutrin0_consensus_engine::BftSession::selection)
        .expect("accepted leader proposal")
}

fn signed_chunk_vote(
    domain: ConsensusDomain,
    chunk_id: u64,
    chunk_hash: Hash,
    phase: FinalityVotePhase,
    index: u32,
    proof_hash: Hash,
    selection: Hash,
) -> FinalityVote {
    let voter = voter(index);
    let data = FinalityVoteData {
        chunk_id,
        round: 0,
        chunk_hash,
        selection,
        phase,
    };
    let signature = voter.sign_finality_vote(domain, &data);
    let hashes = if phase == FinalityVotePhase::Precommit {
        vec![proof_hash]
    } else {
        Vec::new()
    };
    FinalityVote {
        proof_manifests: if phase == FinalityVotePhase::Precommit {
            vec![neutrin0_consensus_types::ProofManifest {
                proof_hashes: hashes.clone(),
            }]
        } else {
            Vec::new()
        },
        data: data.clone(),
        signature,
        aggregation_bits: BitVec::from_bytes(4, vec![1 << index]).unwrap(),
        attestations: vec![voter.attest_vote(domain, data, hashes, None)],
    }
}

fn native_peer_receipt(
    witness: &ConsensusWitness,
    certificate: FinalityCert,
) -> neutrin0_consensus_types::ChunkProof {
    let mut witness = witness.clone();
    witness.finality_cert = certificate;
    let statement = validate_consensus(&witness).unwrap();
    let chunk = as_chunk(&statement.chunk);
    neutrin0_consensus_types::ChunkProof {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        public_inputs: statement.chunk.clone(),
        prover_address: [0; 32],
        finality_cert: witness.finality_cert,
        proof_bytes: borsh::to_vec(
            &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                statement,
                chunk_prover_address: [0; 32],
            },
        )
        .unwrap(),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "The following native block binds its selected participation certificate, authenticated environment and receipt."
)]
fn import_executed_successor(
    engine: &mut Engine<MemoryDatabase>,
    first: &ConsensusWitness,
) -> neutrin0_consensus_types::Chunk {
    let spec = engine.chain_spec().clone();
    let (context, seed, _) = engine.consensus_boundary(1).unwrap();
    let live = LiveTrie::from_trie(engine.state().clone());
    assert_eq!(context.pre_state_root, live.trie().root());
    let mut body = neutrin0_consensus_types::Body {
        participation: Some(
            engine
                .store()
                .historical_chunk(0)
                .unwrap()
                .unwrap()
                .finality
                .carried_certificate(),
        ),
        ..neutrin0_consensus_types::Body::default()
    };
    let proposer = voter(0);
    let mut header = first.blocks[0].header.clone();
    header.height = 2;
    header.slot = 2;
    header.parent_hash = context.parent_block_hash;
    header.timestamp = spec.genesis_time + spec.consensus.slot_duration_secs * header.slot;
    header.vrf_proof = proposer.vrf_eval(spec.consensus_domain(), &seed, header.slot);
    let reports = engine.reports_for_block(&header, &body).unwrap();
    let input = neutrin0_runtime_abi::RuntimeBlockInput {
        program_pieces: Vec::new(),
        active_validators: engine.validator_context_for_height(2).unwrap().0,
        participation_acks: engine.participation_acknowledgements(2, &body).unwrap(),
        context: neutrin0_prover_chunk::execution::runtime_context(
            &header,
            engine.canonical_boundary(1).unwrap(),
        ),
        evidence_anchor: engine.evidence_anchor(2).unwrap(),
        chain_id: spec.chain_id,
        block_height: 2,
        block_gas_limit: spec.genesis_gas_limit,
        proposer_address: context.active_validators[0].withdrawal_credentials,
        // Chunk one's carrier consumes chunk zero's certified reports.
        participation: reports
            .as_ref()
            .map(|(participation, _)| participation.clone()),
        proving: reports.map(|(_, proving)| proving),
        transactions: Vec::new(),
    };
    let mut traced = TracingState::new(&live);
    let result = neutrin0_evm_runtime_core::execute_block(&input, &mut traced);
    body.artifacts = result.artifacts;
    let output = result.output;
    // The body's artifact and vote lanes are committed once execution fixed
    // the artifacts.
    let roots = neutrin0_consensus_engine::compute_body_roots(&body);
    header.votes_root = roots.votes_root;
    header.da_root = roots.da_root;
    header.state_root = output.post_state_root;
    header.transactions_root = output.transactions_root;
    header.receipts_root = output.receipts_root;
    header.runtime_extra = output.consensus_candidates_root;
    header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    header.gas_used = output.gas_used;
    header.signature = proposer.sign_proposer_message(spec.consensus_domain(), &header.hash());
    let hash = header.hash();
    // Executing the block writes the participation record; persist its
    // post-state so the chunk witness can be built from the store.
    engine
        .import_block(
            &neutrin0_consensus_types::Block {
                header: header.clone(),
                body,
            },
            &super::native_executor::NativeExecutor,
        )
        .unwrap();
    engine.flush_trie_to_store().unwrap();
    let mut inputs = first.blocks[0].public_inputs.clone();
    *inputs.context = input.context;
    inputs.height = 2;
    inputs.parent_block_hash = header.parent_hash;
    inputs.block_hash = hash;
    inputs.state_root_before = output.pre_state_root;
    inputs.state_root_after = output.post_state_root;
    inputs.transactions_root = output.transactions_root;
    inputs.receipt_root = output.receipts_root;
    inputs.da_root = header.da_root;
    inputs.proposer_address = input.proposer_address;
    inputs.vm_code_hash = engine.runtime_code_hash_for(2).unwrap();
    inputs.block_program = input.evidence_anchor.block_guest_vk_digest;
    inputs.runtime_extra = output.consensus_candidates_root;
    inputs.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    inputs.gas_used = output.gas_used;
    let statement = neutrin0_runtime_abi::BlockReceiptStatement {
        output,
        prover_address: inputs.proposer_address,
    };
    engine
        .store_mut()
        .put_proven_block(
            &hash,
            &BlockProof {
                prover_address: statement.prover_address,
                statement_key: neutrin0_consensus_types::evidence::commitment(&statement),
                height: 2,
                block_hash: hash,
                public_inputs: inputs,
                proof_bytes: borsh::to_vec(&statement).unwrap(),
            },
        )
        .unwrap();
    let prepared = engine.prepare_consensus_chunk(1, &ready_prover()).unwrap();
    as_chunk(
        &validate_candidate(&prepared.witness)
            .unwrap()
            .execution
            .chunk,
    )
}

struct ProofNotifications {
    backend: Arc<ChainBackend<MemoryDatabase, NotifyingNativeConsensusBackend>>,
    decisions: mpsc::Sender<bool>,
    started: tokio::sync::mpsc::UnboundedReceiver<FinalityCert>,
    verified: tokio::sync::mpsc::UnboundedReceiver<Hash>,
    attempts: Arc<AtomicUsize>,
}

impl ProofNotifications {
    fn new(engine: Engine<MemoryDatabase>) -> Self {
        let (decisions, receiver) = mpsc::channel();
        let (started_tx, started) = unbounded_channel();
        let (verified_tx, verified) = unbounded_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(ChainBackend::new(
            engine,
            NotifyingNativeConsensusBackend {
                inner: NativeConsensusBackend {
                    decisions: Mutex::new(receiver),
                    attempts: Arc::clone(&attempts),
                },
                started: started_tx,
                verified: verified_tx,
            },
        ));
        backend.set_local_voter(voter(0));
        Self {
            backend,
            decisions,
            started,
            verified,
            attempts,
        }
    }

    fn prepare_successor_prevotes(
        &self,
        first: &ConsensusWitness,
    ) -> (neutrin0_consensus_types::Chunk, Hash, Hash) {
        let domain = first.chain_spec.consensus_domain();
        self.backend.with_engine_mut_for_test(|engine| {
            let next = import_executed_successor(engine, first);
            open_authorized_session(engine, &next, 101);
            let proof_hash = receipt_hash(engine, &next);
            let selection = session_selection(engine, 1);
            for peer in [1, 2] {
                engine
                    .observe_finality_vote_at(
                        signed_chunk_vote(
                            domain,
                            1,
                            next.hash(),
                            FinalityVotePhase::Prevote,
                            peer,
                            proof_hash,
                            selection,
                        ),
                        101,
                    )
                    .unwrap();
            }
            (next, proof_hash, selection)
        })
    }
}

fn leader_proposal(
    engine: &Engine<MemoryDatabase>,
    chunk: &neutrin0_consensus_types::Chunk,
) -> neutrin0_consensus_types::BftProposal {
    let leader = neutrin0_consensus_types::bft_leader(
        7,
        chunk.chunk_id,
        0,
        &engine.finalized_seed(),
        engine.active_validator_set(),
    )
    .unwrap();
    let (proposal_slot, receipts, ratified_chunk_proofs) =
        engine.proposal_selection(chunk).unwrap();
    let mut proposal = neutrin0_consensus_types::BftProposal {
        chunk: chunk.clone(),
        round: 0,
        proposer_index: leader,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot,
        receipts,
        ratified_chunk_proofs,
        signature: [0; 96],
    };
    proposal.signature = voter(leader)
        .sign_raw(&proposal.signing_message(engine.chain_spec().consensus_domain()))
        .to_bytes();
    proposal
}

fn open_authorized_session(
    engine: &mut Engine<MemoryDatabase>,
    chunk: &neutrin0_consensus_types::Chunk,
    now: u64,
) {
    engine.open_bft_session_at(chunk.clone(), now).unwrap();
    let proposal = leader_proposal(engine, chunk);
    engine
        .observe_bft_proposal(proposal, now, &ready_prover())
        .unwrap();
}

fn receipt_hash(engine: &Engine<MemoryDatabase>, chunk: &neutrin0_consensus_types::Chunk) -> Hash {
    neutrin0_consensus_types::evidence::commitment(
        &engine
            .store()
            .get_block_proof(&chunk.end_block_hash)
            .unwrap()
            .unwrap(),
    )
}

fn missing_next_leader_fixture() -> (
    Engine<MemoryDatabase>,
    ProposerKey,
    neutrin0_consensus_types::QuorumCertificate,
) {
    let (mut engine, witness) = four_validator_fixture();
    let domain = witness.chain_spec.consensus_domain();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let next_leader = neutrin0_consensus_types::bft_leader(
        7,
        0,
        1,
        &engine.finalized_seed(),
        engine.active_validator_set(),
    )
    .unwrap();
    let follower = (next_leader + 1) % 4;
    engine.set_local_voter(voter(follower));
    let entered_at = now.saturating_sub(2);
    open_authorized_session(&mut engine, &chunk, entered_at);
    let selection = session_selection(&engine, 0);
    let proof_hash = receipt_hash(&engine, &chunk);
    // The follower and the two seats after it, never the next leader.
    for peer in [(follower + 1) % 4, (follower + 2) % 4] {
        engine
            .observe_finality_vote_at(
                signed_vote(
                    domain,
                    chunk.hash(),
                    FinalityVotePhase::Prevote,
                    peer,
                    proof_hash,
                    selection,
                ),
                entered_at,
            )
            .unwrap();
    }
    let old_lock = engine
        .bft_session(0)
        .unwrap()
        .highest_lock_quorum()
        .unwrap()
        .clone();
    let reports = (0..3)
        .map(|index| {
            let mut report = neutrin0_consensus_types::RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: index,
                highest_quorum: Some(old_lock.clone()),
                signature: [0; 96],
            };
            report.signature = voter(index)
                .sign_raw(&report.signing_message(domain))
                .to_bytes();
            report
        })
        .collect();
    engine
        .observe_round_change_certificate(
            neutrin0_consensus_types::RoundChangeCertificate {
                chunk_id: 0,
                round: 1,
                reports,
            },
            entered_at,
        )
        .unwrap();
    (engine, voter(follower), old_lock)
}

#[tokio::test(flavor = "current_thread")]
async fn independent_bft_clock_emits_nil_without_a_leader_or_producer_and_preserves_the_lock() {
    let (engine, follower, old_lock) = missing_next_leader_fixture();
    let (_, receiver) = mpsc::channel();
    let backend = Arc::new(ChainBackend::new(
        engine,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::new(AtomicUsize::new(0)),
        },
    ));
    backend.set_local_voter(follower);
    let (commands, mut published) = tokio::sync::mpsc::channel(16);
    backend.set_network_publisher(commands);
    let clock = tokio::spawn(Arc::clone(&backend).run_bft_round_timeouts());
    let phases = tokio::time::timeout(Duration::from_secs(5), async {
        let mut phases = std::collections::BTreeSet::new();
        loop {
            if let Some(neutrin0_network::service::NetworkCommand::Publish {
                topic: neutrin0_network::Topic::BftMessages,
                data,
            }) = published.recv().await
                && let neutrin0_consensus_types::BftMessage::Vote(
                    neutrin0_consensus_types::BftVote::Nil(vote),
                ) = borsh::from_slice(&data).unwrap()
            {
                assert_eq!(vote.data.round, 1);
                assert_eq!(vote.data.chunk_id, 0);
                phases.insert(vote.data.phase);
                if phases.len() == 2 {
                    return phases;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        phases,
        std::collections::BTreeSet::from([
            FinalityVotePhase::Prevote,
            FinalityVotePhase::Precommit
        ])
    );
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine.bft_session(0).unwrap().round()),
        1
    );
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine
            .bft_session(0)
            .unwrap()
            .highest_lock_quorum()
            .cloned()),
        Some(old_lock)
    );
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    clock.abort();
    assert!(clock.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn current_target_quorum_hint_preserves_precommits_and_finalizes_without_a_tick() {
    let (mut engine, witness) = four_validator_fixture();
    let domain = witness.chain_spec.consensus_domain();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    engine.set_local_voter(voter(0));
    open_authorized_session(&mut engine, &chunk, now);
    let selection = session_selection(&engine, 0);
    let proof_hash = receipt_hash(&engine, &chunk);
    for peer in [1, 2] {
        engine
            .observe_finality_vote_at(
                signed_vote(
                    domain,
                    chunk.hash(),
                    FinalityVotePhase::Prevote,
                    peer,
                    proof_hash,
                    selection,
                ),
                now,
            )
            .unwrap();
    }
    let candidate = engine.bft_candidate(0).unwrap();
    assert_eq!(candidate.round, 1);
    assert_eq!(candidate.justification.as_ref().unwrap().data.round, 0);
    let (decisions, receiver) = mpsc::channel();
    let (started_tx, mut started) = unbounded_channel();
    let (verified_tx, mut verified) = unbounded_channel();
    let backend = Arc::new(ChainBackend::new(
        engine,
        NotifyingNativeConsensusBackend {
            inner: NativeConsensusBackend {
                decisions: Mutex::new(receiver),
                attempts: Arc::new(AtomicUsize::new(0)),
            },
            started: started_tx,
            verified: verified_tx,
        },
    ));
    backend.set_local_voter(voter(0));
    let actor = tokio::spawn(Arc::clone(&backend).run_consensus_proof_notifications());
    backend.consider_bft_candidate(candidate).await.unwrap();
    backend.with_engine_mut_for_test(|engine| {
        let session = engine.bft_session(0).unwrap();
        assert_eq!(session.round(), 0);
        assert_eq!(session.chunk_hash(), chunk.hash());
        assert!(!session.precommit_quorum_observed());
    });
    decisions.send(true).unwrap();
    for peer in [1, 2] {
        let _ = backend
            .ingest_finality_vote(signed_vote(
                domain,
                chunk.hash(),
                FinalityVotePhase::Precommit,
                peer,
                proof_hash,
                selection,
            ))
            .await;
    }
    let certificate = tokio::time::timeout(Duration::from_secs(5), started.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(certificate.round, 0);
    tokio::time::timeout(Duration::from_secs(5), verified.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    actor.abort();
    assert!(actor.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)] // Keep late-vote fencing and proof completion in one sequential lifecycle.
async fn late_overlapping_votes_keep_the_first_certificate_and_complete_without_a_tick() {
    let (mut engine, witness) = four_validator_fixture();
    let domain = witness.chain_spec.consensus_domain();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    engine.set_local_voter(voter(0));
    open_authorized_session(&mut engine, &chunk, 100);
    let selection = session_selection(&engine, 0);
    let proof_hash = receipt_hash(&engine, &chunk);
    for peer in [1, 2] {
        engine
            .observe_finality_vote_at(
                signed_vote(
                    domain,
                    chunk.hash(),
                    FinalityVotePhase::Prevote,
                    peer,
                    proof_hash,
                    selection,
                ),
                100,
            )
            .unwrap();
    }
    for peer in [1, 2] {
        engine
            .observe_finality_vote_at(
                signed_vote(
                    domain,
                    chunk.hash(),
                    FinalityVotePhase::Precommit,
                    peer,
                    proof_hash,
                    selection,
                ),
                100,
            )
            .unwrap();
    }
    let first_identity = engine.bft_quorum_identity(0).unwrap();
    let (decisions, receiver) = mpsc::channel();
    let (started_tx, mut started) = unbounded_channel();
    let (verified_tx, mut verified) = unbounded_channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(ChainBackend::new(
        engine,
        NotifyingNativeConsensusBackend {
            inner: NativeConsensusBackend {
                decisions: Mutex::new(receiver),
                attempts: Arc::clone(&attempts),
            },
            started: started_tx,
            verified: verified_tx,
        },
    ));
    backend.set_local_voter(voter(0));
    let actor = tokio::spawn(Arc::clone(&backend).run_consensus_proof_notifications());
    backend.tick_bft_round_timeouts(100).await;
    let first = tokio::time::timeout(Duration::from_secs(5), started.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        neutrin0_consensus_types::evidence::commitment(&first),
        first_identity.certificate_hash
    );

    // A late fourth seat overlaps the already complete certificate.
    let _ = backend
        .ingest_finality_vote(signed_vote(
            domain,
            chunk.hash(),
            FinalityVotePhase::Prevote,
            3,
            proof_hash,
            selection,
        ))
        .await;
    // A late fourth seat overlaps the already complete certificate.
    let _ = backend
        .ingest_finality_vote(signed_vote(
            domain,
            chunk.hash(),
            FinalityVotePhase::Precommit,
            3,
            proof_hash,
            selection,
        ))
        .await;
    let latest_identity =
        backend.with_engine_mut_for_test(|engine| engine.bft_quorum_identity(0).unwrap());
    assert_eq!(latest_identity, first_identity);
    decisions.send(true).unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(5), verified.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted, first_identity.certificate_hash);
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine.store().get_finality_cert(0).unwrap()),
        Some(first)
    );
    assert!(matches!(
        started.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        verified.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    actor.abort();
    assert!(actor.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)] // Keep both chunks' quorum, proof and notification order in one lifecycle.
async fn peer_finality_makes_local_completion_stale_and_notifies_the_next_quorum() {
    let (mut engine, witness) = four_validator_fixture();
    let domain = witness.chain_spec.consensus_domain();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    engine.set_local_voter(voter(0));
    open_authorized_session(&mut engine, &chunk, 100);
    let selection = session_selection(&engine, 0);
    let proof_hash = receipt_hash(&engine, &chunk);
    for peer in [1, 2] {
        engine
            .observe_finality_vote_at(
                signed_vote(
                    domain,
                    chunk.hash(),
                    FinalityVotePhase::Prevote,
                    peer,
                    proof_hash,
                    selection,
                ),
                100,
            )
            .unwrap();
    }
    let mut notifications = ProofNotifications::new(engine);
    let backend = Arc::clone(&notifications.backend);
    let actor = tokio::spawn(Arc::clone(&backend).run_consensus_proof_notifications());
    for peer in [1, 2] {
        let _ = backend
            .ingest_finality_vote(signed_vote(
                domain,
                chunk.hash(),
                FinalityVotePhase::Precommit,
                peer,
                proof_hash,
                selection,
            ))
            .await;
    }
    let first = tokio::time::timeout(Duration::from_secs(5), notifications.started.recv())
        .await
        .unwrap()
        .unwrap();
    let first_hash = neutrin0_consensus_types::evidence::commitment(&first);
    let imported = backend
        .verify_and_import_chunk_proof(
            native_peer_receipt(&witness, first.clone()),
            neutrin0_network::PeerId::random(),
        )
        .await
        .unwrap();
    assert_eq!(imported.chunk_id, 0);
    assert_eq!(notifications.verified.recv().await.unwrap(), first_hash);
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );

    let (next, next_proof_hash, next_selection) =
        notifications.prepare_successor_prevotes(&witness);
    for peer in [1, 2] {
        let _ = backend
            .ingest_finality_vote(signed_chunk_vote(
                domain,
                1,
                next.hash(),
                FinalityVotePhase::Precommit,
                peer,
                next_proof_hash,
                next_selection,
            ))
            .await;
    }
    assert!(matches!(
        notifications.started.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(notifications.attempts.load(Ordering::SeqCst), 1);

    notifications.decisions.send(true).unwrap();
    // Starting the next worker is a strict barrier: the old worker's Notify
    // must have drained and rejected its now-stale certificate first.
    let second = tokio::time::timeout(Duration::from_secs(5), notifications.started.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.chunk_id, 1);
    assert_eq!(second.chunk_hash, next.hash());
    // The stale local completion lost the race to finality. It is verified
    // once as an alternative chunk proof that still competes for
    // ratification (design 08) and leaves finality unchanged.
    assert_eq!(notifications.verified.try_recv(), Ok(first_hash));
    assert!(matches!(
        notifications.verified.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine.store().get_finality_cert(0).unwrap()),
        Some(first)
    );

    notifications.decisions.send(true).unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(5), notifications.verified.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        accepted,
        neutrin0_consensus_types::evidence::commitment(&second)
    );
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(1)
    );
    assert_eq!(notifications.attempts.load(Ordering::SeqCst), 2);
    assert!(matches!(
        notifications.verified.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    actor.abort();
    assert!(actor.await.unwrap_err().is_cancelled());
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Two independent validator engines with an explicitly held proof job.
async fn two_validators_exchange_successor_while_chunk_proof_is_held() {
    use neutrin0_node::metrics::MetricsSource;
    use neutrin0_runtime_host::WasmExecutor;
    let keys: Vec<_> = [42, 43]
        .map(|n| neutrin0_crypto::bls::SecretKey::key_gen(&[n; 32], &[]).unwrap())
        .into();
    let (witness, input, _, post) = support::fixture_with_validator_keys_and_chunk_size(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
        &keys,
        1,
    );
    let genesis = support::spec_genesis_live(&witness);
    let mut engine = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_programs(support::guests(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
    ));
    engine
        .install_genesis_state(genesis.trie().clone())
        .unwrap();
    let first = &witness.blocks[0];
    engine
        .import_block(
            &neutrin0_consensus_types::Block {
                header: first.header.clone(),
                body: support::executed_body(&genesis, &input),
            },
            &super::native_executor::NativeExecutor,
        )
        .unwrap();
    engine
        .store_mut()
        .put_proven_block(
            &first.header.hash(),
            &BlockProof {
                prover_address: first.public_inputs.proposer_address,
                statement_key: neutrin0_consensus_types::evidence::commitment(&first.statement()),
                height: 1,
                block_hash: first.header.hash(),
                public_inputs: first.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&first.statement()).unwrap(),
            },
        )
        .unwrap();
    // Executing the first block materialized the fixture's post-chunk state.
    assert_eq!(engine.state().root(), post.trie().root());
    engine.flush_trie_to_store().unwrap();
    let peer_engine =
        Engine::open(witness.chain_spec.clone(), engine.store().db().clone()).unwrap();
    let preferred = neutrin0_consensus_types::bft_leader(
        witness.chain_spec.chain_id,
        0,
        0,
        &witness.seed,
        &witness.context.active_validators,
    )
    .unwrap();
    let mut notifications = ProofNotifications::new(engine);
    notifications.backend.set_local_voter(voter(preferred));
    notifications
        .backend
        .set_block_executor(WasmExecutor::embedded().unwrap());
    let backup = ChainBackend::new(
        peer_engine,
        super::certified_execution::NativePipelineProofs,
    );
    backup.set_local_voter(voter(1 - preferred));
    backup.set_block_executor(WasmExecutor::embedded().unwrap());
    backup.set_proving_policy(neutrin0_node::config::ProvingPolicy {
        chunk_fallback_secs: 3600,
        ..Default::default()
    });
    let actor =
        tokio::spawn(Arc::clone(&notifications.backend).run_consensus_proof_notifications());
    for backend in [notifications.backend.as_ref() as &dyn SyncBackend, &backup] {
        backend
            .verify_and_import_execution_certificate(witness.finality_cert.clone())
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), notifications.started.recv())
        .await
        .unwrap()
        .unwrap();
    let executor = WasmExecutor::embedded().unwrap();
    let next_voter = voter(1 - preferred);
    let successor = backup.with_engine_mut_for_test(|engine| {
        engine
            .try_produce_block(
                2,
                neutrin0_consensus_engine::ProductionConfig {
                    proposer: &next_voter,
                },
                neutrin0_consensus_types::Body::default(),
                &executor,
            )
            .unwrap()
            .unwrap()
            .block
    });
    backup.prove_block(&successor.hash()).unwrap();
    backup.with_engine_mut_for_test(|engine| assert!(engine.bft_session(1).is_none()));
    let publication = backup
        .proven_block_for_publication(&successor.hash())
        .unwrap();
    notifications
        .backend
        .verify_and_import_proven_blocks(vec![publication])
        .await
        .unwrap();
    notifications
        .backend
        .with_engine_mut_for_test(|engine| assert!(engine.bft_session(1).is_none()));
    for backend in [notifications.backend.as_ref() as &dyn SyncBackend, &backup] {
        let status = backend.local_status().await.unwrap();
        assert_eq!(status.head_height, 2);
        assert_eq!(status.finalized_chunk_id, None);
    }
    let snapshot = notifications.backend.snapshot();
    assert_eq!(snapshot.certified_execution_height, 1);
    assert_eq!(snapshot.execution_ahead_blocks, 2);
    assert!(snapshot.execution_backpressure);
    notifications.decisions.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while notifications
            .backend
            .local_status()
            .await
            .unwrap()
            .finalized_chunk_id
            != Some(0)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let proof = notifications
        .backend
        .with_engine_mut_for_test(|engine| engine.store().get_chunk_proof(0).unwrap().unwrap());
    backup
        .verify_and_import_chunk_proof(proof, neutrin0_network::PeerId::random())
        .await
        .unwrap();
    for backend in [notifications.backend.as_ref() as &dyn SyncBackend, &backup] {
        let status = backend.local_status().await.unwrap();
        assert_eq!(status.head_block_hash, successor.hash());
        assert_eq!(status.head_height, 2);
        assert_eq!(status.finalized_chunk_id, Some(0));
    }
    for opened in [
        notifications
            .backend
            .with_engine_mut_for_test(|engine| engine.bft_session(1).is_some()),
        backup.with_engine_mut_for_test(|engine| engine.bft_session(1).is_some()),
    ] {
        assert!(
            opened,
            "both local and imported finality must resume a proven successor"
        );
    }
    let snapshot = notifications.backend.snapshot();
    assert_eq!(snapshot.certified_execution_height, 0);
    assert_eq!(snapshot.execution_ahead_blocks, 1);
    actor.abort();
}
