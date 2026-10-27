//! Full-node bootstrap integration with real BLS and native consensus validation.
//! The explicit test-only receipt verifier checks a marker, not a compressed
//! STARK. Real recursive proving runs in ignored tests.

#[path = "../../../../prover-chunk/tests/support/mod.rs"]
#[allow(
    unreachable_pub,
    reason = "The shared integration fixture is compiled inside a private unit-test module."
)]
mod support;

use super::{ChainBackend, PENDING_KEY};
use crate::config::BootstrapConfig;
use neutrin0_consensus_engine::{Engine, RetentionPolicy};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{
    AggregatedVote, Block, BlockProofPublicInputs, Body, FinalityCert, FinalityVoteData,
    FinalityVotePhase, Header, ProvenBlock, VoteAttestation,
    history::{HistoryFrontier, HistoryPath},
    history_proof::{
        AnchorOpening, ChainBinding, Checkpoint, ChunkReceiptStatement, HistoryProof, ProofDomain,
    },
};
use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::{
    BitVec, BoundedBytes, ChainSpec, ConsensusDomain, DOMAIN_PROPOSER_SIG, Hash, Validator,
};
use neutrin0_proof_system::{ProofError, ProofSystem, verify_history_proof};
use neutrin0_prover_chunk::{
    consensus::{as_chunk, validate_candidate, validate_consensus_with_context},
    history::{HistoricalChunk, HistoricalOpening},
};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_storage::{Batch, BatchOp, Column, ColumnSnapshot, Database, MemoryDatabase};
use neutrin0_sync::{StateProgress, SyncBackend};
use neutrin0_trie::Trie;

/// Only this test module can accept the fixture's receipt marker. Block
/// receipts carry the fixture statement itself: the roots the header commits
/// and the bindings the engine checks.
struct NativeHistory;
impl ProofSystem for NativeHistory {
    type BlockProof = neutrin0_runtime_abi::BlockReceiptStatement;
    type ChunkProof = Vec<u8>;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        let output = borsh::from_slice::<neutrin0_runtime_abi::RuntimeBlockOutput>(witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        let statement = neutrin0_runtime_abi::BlockReceiptStatement {
            output,
            prover_address,
        };
        self.verify_block(&statement, inputs)?;
        Ok(statement)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if proof.output.post_state_root == inputs.state_root_after
            && proof.output.consensus_candidates_root == inputs.runtime_extra
        {
            Ok(())
        } else {
            Err(ProofError::PublicInputMismatch)
        }
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ProofError> {
        Ok(proof.clone())
    }

    fn history_domain(&self, spec: &ChainSpec) -> Result<ProofDomain, ProofError> {
        Ok(ProofDomain {
            chain: ChainBinding::new(spec),
            chunk: spec.genesis_chunk,
            programs: support::programs([1; 8], [4; 32]),
        })
    }

    fn programs(&self) -> Option<neutrin0_consensus_types::history_proof::GuestPrograms> {
        Some(support::guests([1; 8], [4; 32]))
    }

    fn installed_guests(&self) -> Vec<([u32; 8], Hash)> {
        let execution = support::programs([1; 8], [4; 32]).execution;
        [execution.fact, execution.evidence, execution.block]
            .into_iter()
            .map(|digest| (digest, [0; 32]))
            .collect()
    }

    fn verify_history(
        &self,
        proof: &HistoryProof,
        chunk: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<(), ProofError> {
        if *chunk != support::chunk_program() || proof.receipt.as_slice() != [7] {
            return Err(ProofError::BackendRejected);
        }
        Ok(())
    }
}

type Backend<DB = MemoryDatabase> = ChainBackend<DB, NativeHistory>;

/// The statement the fixture's receipts carry for a block: the bindings the
/// engine checks (anchor, participation, acknowledgements) and the roots the
/// header commits. The fixture never changes application state.
fn fixture_statement(
    anchor: neutrin0_consensus_types::evidence::EvidenceAnchor,
    participation: Option<&neutrin0_consensus_types::participation::ParticipationReport>,
    acknowledgements: &[neutrin0_consensus_types::participation::ParticipationAcknowledgement],
    state_root: Hash,
    runtime_extra: Hash,
) -> neutrin0_runtime_abi::RuntimeBlockOutput {
    neutrin0_runtime_abi::RuntimeBlockOutput {
        accountability: neutrin0_runtime_abi::AccountabilityOutput {
            anchor,
            ..Default::default()
        },
        participation: neutrin0_consensus_types::participation::participation_commitment(
            participation,
        ),
        participation_acks: neutrin0_consensus_types::participation::acknowledgement_commitment(
            acknowledgements,
        ),
        pre_state_root: state_root,
        post_state_root: state_root,
        consensus_candidates_root: runtime_extra,
        ..Default::default()
    }
}

/// Executor of the fixture's empty blocks: its synthetic programs are already
/// installed, application transactions and queries are refused, and the
/// header commits the fixture's candidate root.
struct FixtureExecutor {
    runtime_extra: Hash,
    /// The fixture block's executed artifacts, which every header commits.
    artifacts: neutrin0_runtime_abi::ExecutionArtifacts,
    /// The genesis root the fixture block executes over.
    genesis_root: Hash,
    /// The fixture block's writes; later blocks keep the state as it is.
    writes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}
impl neutrin0_proof_system::BlockExecutor for FixtureExecutor {
    type Error = String;
    fn execute_block(
        &self,
        context: &neutrin0_proof_system::BlockExecutionContext,
        body: &Body,
        state: &mut Trie,
    ) -> Result<neutrin0_proof_system::ExecutionOutcome, String> {
        if !body.transactions.is_empty() {
            return Err("fixture does not execute application transactions".into());
        }
        let artifacts = self.artifacts.clone();
        // The fixture block moves genesis to its post-state; every later
        // fixture block is a fixed point of that state.
        let state_writes = if state.root() == self.genesis_root {
            for (key, value) in &self.writes {
                match value {
                    Some(value) => state
                        .insert(key, value.clone())
                        .map_err(|error| format!("{error:?}"))?,
                    None => {
                        state.remove(key).map_err(|error| format!("{error:?}"))?;
                    }
                }
            }
            self.writes
                .iter()
                .map(|(key, value)| neutrin0_consensus_types::StateWrite {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };
        let statement = fixture_statement(
            context.evidence_anchor,
            context.participation.as_ref(),
            &context.participation_acks,
            state.root(),
            self.runtime_extra,
        );
        Ok(neutrin0_proof_system::ExecutionOutcome {
            receipts_root: artifacts.commitment(),
            artifacts,
            state_root_after: state.root(),
            runtime_extra: self.runtime_extra,
            gas_used: 0,
            witness_bytes: borsh::to_vec(&statement).map_err(|error| error.to_string())?,
            state_writes,
        })
    }
    fn query(
        &self,
        _: &neutrin0_runtime_abi::QueryRequest,
        _: Hash,
        _: &Trie,
    ) -> Result<neutrin0_runtime_abi::QueryResponse, String> {
        Err("fixture has no application queries".into())
    }
    fn validate_tx(
        &self,
        _: &[u8],
        _: u64,
        _: u64,
        _: Hash,
        _: &Trie,
    ) -> Result<neutrin0_runtime_abi::TxValidity, String> {
        Err("fixture does not admit application transactions".into())
    }
    fn install_runtime(&self, _: &[u8]) -> Result<Hash, String> {
        Err("fixture programs are already installed".into())
    }
    fn installed_runtimes(&self) -> Vec<Hash> {
        vec![[4; 32]]
    }
}

fn fixture_backend<DB>(fixture: &Fixture, engine: Engine<DB>, proof: NativeHistory) -> Backend<DB>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    let backend = ChainBackend::new(engine, proof);
    backend.set_block_executor(FixtureExecutor {
        runtime_extra: fixture.header.runtime_extra,
        artifacts: fixture.body.artifacts.clone(),
        genesis_root: fixture.genesis.root(),
        writes: fixture.writes.clone(),
    });
    backend
}

struct Fixture {
    spec: ChainSpec,
    proof: HistoryProof,
    header: Header,
    validators: Vec<Validator>,
    frontier: HistoryFrontier,
    recent: Vec<HistoricalOpening>,
    /// The specification's genesis allocation.
    genesis: Trie,
    /// Application state at the fixture's finalized head.
    state: Trie,
    /// The executed body of the fixture block.
    body: Body,
    /// The fixture block's state writes over the genesis allocation.
    writes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl Fixture {
    fn new(value: Option<Vec<u8>>) -> Self {
        Self::build(value, None)
    }

    /// The fixture with governance's hard fork at its endpoint, chunk 1, to
    /// a successor pinning the fixture specification's own programs.
    fn forking() -> Self {
        let successor = support::fixture([1; 8], [4; 32])
            .0
            .chain_spec
            .pinned_programs()
            .commitment();
        Self::build(
            None,
            Some(neutrin0_primitives::ScheduledFork {
                count: 1,
                successor,
            }),
        )
    }

    #[allow(clippy::too_many_lines)] // Construct and authenticate the complete signed fixture.
    fn build(value: Option<Vec<u8>>, fork: Option<neutrin0_primitives::ScheduledFork>) -> Self {
        // The runtime's genesis records, plus an oversized value when the
        // scenario downloads state in fragments.
        let mut live = support::fixture_genesis_live([1; 8], [4; 32], 30_000_000);
        if let Some(value) = value {
            live.insert(b"bootstrap-large", value);
        }
        if let Some(fork) = fork {
            live.insert(
                neutrin0_consensus_types::runtime::FORK_KEY,
                borsh::to_vec(&fork).unwrap(),
            );
        }
        let (mut witness, mut input, _) =
            support::fixture_with_live([1; 8], [4; 32], vec![], 30_000_000, &live);
        let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
        // Keep locally configured trust fresh without accepting a peer's clock.
        witness.chain_spec.genesis_time = super::now()
            .unwrap()
            .saturating_sub(witness.chain_spec.consensus.slot_duration_secs);
        let spec_hash = witness.chain_spec.hash();
        witness.context.chain_spec_hash = spec_hash;
        input.evidence_anchor.chain_spec_hash = spec_hash;
        // The changed specification changes the VRF domain and timestamp;
        // execution, header and public inputs must all commit the same values.
        witness.blocks[0].header.timestamp =
            witness.chain_spec.genesis_time + witness.chain_spec.consensus.slot_duration_secs;
        witness.blocks[0].header.vrf_proof = key
            .sign(&neutrin0_vrf::vrf_message(
                witness.chain_spec.consensus_domain(),
                &witness.seed,
                witness.blocks[0].header.slot,
            ))
            .to_bytes();
        input.context.timestamp = witness.blocks[0].header.timestamp;
        input.context.proposer_vrf_output =
            neutrin0_vrf::proof_output(&witness.blocks[0].header.vrf_proof);
        let mut traced = TracingState::new(&live);
        let result = neutrin0_evm_runtime_core::execute_block(&input, &mut traced);
        witness.blocks[0].output = result.output;
        let body = Body {
            artifacts: result.artifacts,
            ..Body::default()
        };
        let (mut post_state, _, writes) = traced.into_committed_witness_and_writes().unwrap();
        // A bootstrap snapshot carries only the nodes its root reaches.
        post_state.retain_roots(&[]).unwrap();
        // The candidate's post-state witness opens the rotation records of
        // the executed state.
        let post_live = LiveTrie::from_trie(post_state.clone());
        let mut rotation = TracingState::new(&post_live);
        neutrin0_prover_chunk::rotation::witness_keys_from(&mut rotation);
        witness.post_state = rotation.into_witness().unwrap();
        let output = witness.blocks[0].output.clone();
        let header = &mut witness.blocks[0].header;
        header.state_root = output.post_state_root;
        header.transactions_root = output.transactions_root;
        header.receipts_root = output.receipts_root;
        header.da_root = neutrin0_prover_chunk::consensus::body_da_root(&body);
        header.runtime_extra = output.consensus_candidates_root;
        header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
        header.gas_used = output.gas_used;
        sign_header(&key, witness.chain_spec.consensus_domain(), header);
        let hash = header.hash();
        let da_root = header.da_root;
        let inputs = &mut witness.blocks[0].public_inputs;
        *inputs.context = input.context;
        inputs.block_hash = hash;
        inputs.state_root_after = output.post_state_root;
        inputs.transactions_root = output.transactions_root;
        inputs.receipt_root = output.receipts_root;
        inputs.da_root = da_root;
        inputs.runtime_extra = output.consensus_candidates_root;
        inputs.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
        inputs.gas_used = output.gas_used;
        let candidate = validate_candidate(&witness).unwrap();
        let chunk = as_chunk(&candidate.execution.chunk);
        let mut proposal = neutrin0_consensus_types::BftProposal {
            chunk: chunk.clone(),
            round: 0,
            proposer_index: 0,
            valid_quorum: None,
            round_change_certificate: None,
            proposal_slot: witness.blocks.last().map_or(0, |block| block.header.slot),
            receipts: witness
                .blocks
                .iter()
                .map(|block| neutrin0_consensus_types::bft::ReceiptChoice {
                    prover_address: block.prover_address,
                    statement_key: neutrin0_consensus_types::evidence::commitment(
                        &block.statement(),
                    ),
                })
                .collect(),
            ratified_chunk_proofs: Vec::new(),
            signature: [0; 96],
        };
        proposal.signature = key
            .sign(&proposal.signing_message(witness.chain_spec.consensus_domain()))
            .to_bytes();
        // Votes sign the chunk with the proposal's payment selection.
        let selection = proposal.selection();
        let aggregate = |phase| {
            let data = FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash: chunk.hash(),
                selection,
                phase,
            };
            AggregatedVote {
                aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
                signature: key
                    .sign(&data.signing_message(witness.chain_spec.consensus_domain()))
                    .to_bytes(),
            }
        };
        let manifest = neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![[1; 32]],
        };
        let mut cert = FinalityCert {
            proof_manifests: vec![manifest.clone()],
            proposal,
            chunk_id: 0,
            round: 0,
            chunk_hash: chunk.hash(),
            active_validator_set_root: chunk.active_validator_set_root,
            prevote: aggregate(FinalityVotePhase::Prevote),
            precommit: aggregate(FinalityVotePhase::Precommit),
            prevote_attestations: vec![],
            precommit_attestations: vec![],
        };
        let mut claim = VoteAttestation {
            validator_index: 0,
            vote: cert.precommit_vote().data,
            vote_signature: cert.precommit.signature,
            proof_acceptance: Some(manifest.commitment()),
            unlock_quorum: None,
            signature: [0; 96],
        };
        claim.signature = key
            .sign(&claim.signing_message(witness.chain_spec.consensus_domain()))
            .to_bytes();
        cert.precommit_attestations.push(claim);
        let mut prevote_claim = cert.precommit_attestations[0].clone();
        prevote_claim.vote = cert.prevote_vote().data;
        prevote_claim.vote_signature = cert.prevote.signature;
        prevote_claim.proof_acceptance = None;
        prevote_claim.signature = key
            .sign(&prevote_claim.signing_message(witness.chain_spec.consensus_domain()))
            .to_bytes();
        cert.prevote_attestations.push(prevote_claim);
        witness.finality_cert = cert;
        let validated = validate_consensus_with_context(&witness).unwrap();
        let statement = validated.statement;
        let record = HistoricalChunk {
            chunk: as_chunk(&statement.chunk),
            validators: witness.context.active_validators,
            seed: witness.seed,
            finality: witness.finality_cert,
            block_guest_vk_digest: statement.start.programs.execution.block,
            runtime_code_hash: statement.start.programs.runtime_code_hash,
            start_boundary: statement.start.commitment(),
        };
        let leaf = commitment(&record.evidence_context());
        let frontier = HistoryFrontier::from_leaves(&[leaf]).unwrap();
        assert_eq!(frontier.root(), Some(statement.end.history_root));
        assert_eq!(
            statement.chain,
            NativeHistory
                .history_domain(&witness.chain_spec)
                .unwrap()
                .chain
        );
        Self {
            // The single chunk's receipt is the History proof from genesis.
            proof: HistoryProof {
                statement: ChunkReceiptStatement {
                    statement,
                    chunk_prover_address: [0; 32],
                },
                receipt: BoundedBytes::new(vec![7]).unwrap(),
            },
            header: witness.blocks[0].header.clone(),
            validators: validated.next_context.active_validators,
            frontier,
            recent: vec![HistoricalOpening {
                record,
                path: HistoryPath::build(&[leaf], 0).unwrap(),
            }],
            genesis: live.trie().clone(),
            state: post_state,
            body,
            writes,
            spec: witness.chain_spec,
        }
    }

    fn backend<DB>(&self, db: DB) -> Backend<DB>
    where
        DB: Database + Send + 'static,
        DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    {
        let mut engine = Engine::genesis(self.spec.clone(), db).unwrap();
        // A fresh node materialises the specification's genesis allocation
        // before any executor-equipped import.
        engine.install_genesis_state(self.genesis.clone()).unwrap();
        let backend = fixture_backend(self, engine, NativeHistory);
        backend.initialize_history().unwrap();
        backend
    }

    /// The genesis checkpoint the fixture's single chunk starts from.
    fn genesis(&self) -> Checkpoint {
        Checkpoint {
            chain: *self.proof.chain(),
            boundary: self.proof.statement.statement.start,
        }
    }

    fn end(&self) -> Hash {
        self.proof.end_checkpoint().hash()
    }

    fn source(&self) -> Backend {
        let mut engine = Engine::genesis(self.spec.clone(), MemoryDatabase::new()).unwrap();
        engine
            .set_history_domain(NativeHistory.history_domain(&self.spec).unwrap())
            .unwrap();
        engine
            .store_mut()
            .install_state_slice(
                &[self.state.root(), neutrin0_trie::EMPTY_TRIE_ROOT],
                &self.state,
                usize::MAX,
            )
            .unwrap();
        engine
            .install_bootstrap(
                verify_history_proof(&NativeHistory, &self.spec, self.proof.clone()).unwrap(),
                None,
                self.genesis(),
                &self.header,
                &self.validators,
                &self.frontier,
                &self.recent,
                None,
            )
            .unwrap();
        let backend = fixture_backend(self, engine, NativeHistory);
        backend.initialize_history().unwrap();
        // The serving peer is itself pruned: there is no archive fallback.
        for column in [
            Column::Blocks,
            Column::BlockProofs,
            Column::Witnesses,
            Column::StateDiffs,
        ] {
            assert_eq!(
                backend
                    .with_engine(|engine| engine.store().db().iter_column(column))
                    .unwrap(),
                ColumnSnapshot::new()
            );
        }
        // It keeps only the endpoint's receipt, which is its History proof.
        assert_eq!(
            backend
                .with_engine(|engine| engine.store().db().iter_column(Column::ChunkProofs))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            backend.with_engine(Engine::latest_history_proof).unwrap(),
            Some(self.proof.clone())
        );
        backend
    }

    /// The publication of `block` that `backend` accepts: the fixture
    /// statement for the block's bindings on that node, with the fixture
    /// block's writes and none for its fixed-point successors.
    fn publication<DB>(&self, backend: &Backend<DB>, block: Block) -> ProvenBlock
    where
        DB: Database + Send + 'static,
        DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    {
        let statement = backend.with_engine(|engine| {
            let height = block.header.height;
            let participation = engine
                .participation_for_block(&block.header, &block.body)
                .unwrap();
            let acknowledgements = engine
                .participation_acknowledgements(height, &block.body)
                .unwrap();
            // The publication carries the proposer's own receipt (design 08).
            neutrin0_runtime_abi::BlockReceiptStatement {
                output: fixture_statement(
                    engine.evidence_anchor(height).unwrap(),
                    participation.as_ref(),
                    &acknowledgements,
                    block.header.state_root,
                    block.header.runtime_extra,
                ),
                prover_address: engine
                    .active_validator_set()
                    .get(block.header.proposer_index as usize)
                    .map_or([0; 32], |validator| validator.withdrawal_credentials),
            }
        });
        // The fixture block moves genesis to its post-state; every later
        // fixture block leaves the state as it is.
        let writes = if block.header.height == 1 {
            self.writes
                .iter()
                .map(|(key, value)| neutrin0_consensus_types::StateWrite {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };
        ProvenBlock {
            block,
            proof_bytes: borsh::to_vec(&statement).unwrap(),
            writes,
        }
    }

    fn next_block(&self) -> Block {
        let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
        let mut header = self.header.clone();
        header.parent_hash = self.header.hash();
        header.height += 1;
        header.slot += 1;
        header.timestamp =
            self.spec.genesis_time + header.slot * self.spec.consensus.slot_duration_secs;
        header.vrf_proof = key
            .sign(&neutrin0_vrf::vrf_message(
                self.spec.consensus_domain(),
                &self.proof.end().seed,
                header.slot,
            ))
            .to_bytes();
        // Each block closes a chunk, so the next one selects the finalized
        // chunk's certificate and commits that body in its header.
        let body = Body {
            participation: Some(self.recent[0].record.finality.carried_certificate()),
            artifacts: self.body.artifacts.clone(),
            ..Body::default()
        };
        let roots = neutrin0_consensus_engine::body::compute_body_roots(&body);
        header.transactions_root = roots.transactions_root;
        header.votes_root = roots.votes_root;
        header.da_root = roots.da_root;
        sign_header(&key, self.spec.consensus_domain(), &mut header);
        Block { header, body }
    }
}

fn sign_header(key: &SecretKey, domain: ConsensusDomain, header: &mut Header) {
    let message = domain.signing_message(DOMAIN_PROPOSER_SIG, &header.hash());
    header.signature = key.sign(&message).to_bytes();
}

async fn receive<DB>(source: &Backend, target: &Backend<DB>, root: Hash) -> StateProgress
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    let items = target.state_download_items(root).unwrap();
    assert_ne!(
        items,
        Vec::<neutrin0_consensus_types::bootstrap::StateItem>::new()
    );
    let entries = source
        .p2p_state_nodes(root, &items)
        .unwrap()
        .entries
        .to_vec();
    target
        .import_state_nodes(root, items, entries)
        .await
        .unwrap()
}

/// One fragment exchange whose import result is returned instead of unwrapped.
async fn try_receive<DB>(
    source: &Backend,
    target: &Backend<DB>,
    root: Hash,
) -> Result<StateProgress, neutrin0_sync::SyncBackendError>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    let items = target.state_download_items(root).unwrap();
    let entries = source
        .p2p_state_nodes(root, &items)
        .unwrap()
        .entries
        .to_vec();
    target.import_state_nodes(root, items, entries).await
}

/// Download every fragment of `root`; the last import installs the bootstrap,
/// so its result is the installation's.
async fn drain<DB>(
    source: &Backend,
    target: &Backend<DB>,
    root: Hash,
) -> Result<StateProgress, neutrin0_sync::SyncBackendError>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    loop {
        let progress = try_receive(source, target, root).await?;
        if progress.root_complete {
            return Ok(progress);
        }
    }
}

/// Exchange fragments until the oversized value's second fragment is the
/// next request; the genesis records before it take a few rounds.
async fn receive_until_large_fragment<DB>(
    source: &Backend,
    target: &Backend<DB>,
    root: Hash,
) -> StateProgress
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    for _ in 0..256 {
        let progress = receive(source, target, root).await;
        assert!(!progress.root_complete);
        if progress.next_items.iter().any(|item| item.offset == 65_536) {
            return progress;
        }
    }
    panic!("the oversized value's second fragment was never requested");
}

/// A bootstrap that must not install: refused at its start, or at the
/// installation its last fragment triggers.
async fn assert_bootstrap_rejected<DB>(
    source: &Backend,
    target: &Backend<DB>,
    fixture: &Fixture,
    anchor: Option<AnchorOpening>,
    manifest: neutrin0_consensus_types::bootstrap::BootstrapData,
) where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    match target.begin_bootstrap(anchor, manifest).await {
        Err(_) => {}
        Ok(progress) => {
            assert!(
                !progress.root_complete,
                "a rejected bootstrap never installs"
            );
            assert!(drain(source, target, fixture.state.root()).await.is_err());
        }
    }
}

fn assert_installed<DB>(fixture: &Fixture, target: &Backend<DB>)
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    target.with_engine(|engine| {
        assert_eq!(engine.head_hash(), fixture.header.hash());
        assert_eq!(engine.finalized_next_chunk_id(), 1);
        assert_eq!(
            engine.latest_history_proof().unwrap(),
            Some(fixture.proof.clone())
        );
        assert_eq!(engine.state().root(), fixture.state.root());
        assert_eq!(engine.active_validator_set(), fixture.validators);
        assert_eq!(
            engine.store().historical_opening(0, 1).unwrap(),
            fixture.recent[0]
        );
        assert_eq!(engine.store().bootstrap_source_floor().unwrap(), 1);
        assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 1);
        assert!(
            engine
                .store()
                .db()
                .get(Column::Meta, PENDING_KEY)
                .unwrap()
                .is_none()
        );
        assert!(
            engine
                .store()
                .db()
                .iter_column(Column::Meta)
                .unwrap()
                .iter()
                .all(|(key, _)| !key.starts_with(b"state_download"))
        );
    });
    assert!(!target.bootstrap_pending());
    // Bootstrap stays available, now trusting the installed endpoint, for a
    // node that later falls behind the window peers retain.
    assert_eq!(
        target.bootstrap_origin().map(|origin| origin.hash()),
        Some(fixture.end())
    );
    assert!(target.engine_state_invariant_holds());
}

#[tokio::test]
async fn pruned_peer_bootstrap_resumes_fragments_and_then_imports_normal_blocks() {
    let fixture = Fixture::new(Some(vec![6; 150_000]));
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    let config = BootstrapConfig::default();
    target.initialize_bootstrap(&config).unwrap();
    let manifest = source.serve_bootstrap(fixture.end()).unwrap();
    let root = fixture.state.root();
    assert!(
        !target
            .begin_bootstrap(None, manifest)
            .await
            .unwrap()
            .root_complete
    );
    let progress = receive_until_large_fragment(&source, &target, root).await;
    assert_eq!(target.with_engine(Engine::head_height), 0);
    assert!(
        target
            .verify_and_import_proven_blocks(vec![ProvenBlock {
                block: fixture.next_block(),
                proof_bytes: Vec::new(),
                writes: Vec::new(),
            }])
            .await
            .is_err()
    );
    let db = target.with_engine(|engine| engine.store().db().clone());
    let resumed = fixture_backend(
        &fixture,
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    resumed.initialize_history().unwrap();
    resumed.initialize_bootstrap(&config).unwrap();
    assert_eq!(
        resumed.bootstrap_state().unwrap().unwrap().1,
        progress.next_items
    );
    while !receive(&source, &resumed, root).await.root_complete {}
    assert_installed(&fixture, &resumed);
    assert_eq!(
        resumed.with_engine(|engine| engine.state().get(b"bootstrap-large").unwrap()),
        Some(vec![6; 150_000])
    );
    let db = resumed.with_engine(|engine| engine.store().db().clone());
    let restarted = fixture_backend(
        &fixture,
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    restarted.initialize_history().unwrap();
    restarted.initialize_bootstrap(&config).unwrap();
    assert_installed(&fixture, &restarted);
    let mut next = fixture.next_block();
    next.header.inputs_root = restarted
        .with_engine(|engine| engine.expected_inputs_root(&next.header, &next.body))
        .unwrap();
    sign_header(
        &SecretKey::key_gen(&[42; 32], &[]).unwrap(),
        fixture.spec.consensus_domain(),
        &mut next.header,
    );
    let imported = restarted
        .verify_and_import_proven_blocks(vec![fixture.publication(&restarted, next.clone())])
        .await
        .unwrap();
    assert_eq!(imported.new_head_height, 2);
    assert_eq!(imported.new_head_hash, next.hash());
    assert!(restarted.engine_state_invariant_holds());
}

/// A snapshot file carries everything a peer would serve, so a fresh node
/// bootstraps from it without any exchange; tampered objects are refused.
#[tokio::test]
async fn a_snapshot_file_bootstraps_a_fresh_node_without_peers() {
    let fixture = Fixture::new(Some(vec![6; 150_000]));
    let source = fixture.source();
    let path = std::env::temp_dir().join(format!(
        "neutrin0-snapshot-{}-{:?}.snap",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    let summary = source.export_snapshot(&path, None).unwrap();
    assert_eq!(summary.endpoint, fixture.end());
    assert!(summary.objects > 0);
    // A file is never overwritten.
    assert!(source.export_snapshot(&path, None).is_err());

    let target = fixture.backend(MemoryDatabase::new());
    target
        .initialize_bootstrap(&BootstrapConfig::default())
        .unwrap();
    assert!(target.import_snapshot(&path).await.unwrap());
    assert_installed(&fixture, &target);
    assert_eq!(
        target.with_engine(|engine| engine.state().get(b"bootstrap-large").unwrap()),
        Some(vec![6; 150_000])
    );
    // An endpoint local finality already reached is skipped.
    assert!(!target.import_snapshot(&path).await.unwrap());

    // The last object is a state node; changing its bytes breaks its key.
    let mut bytes = std::fs::read(&path).unwrap();
    let inside = bytes.len() - 2;
    bytes[inside] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let tampered = fixture.backend(MemoryDatabase::new());
    tampered
        .initialize_bootstrap(&BootstrapConfig::default())
        .unwrap();
    assert!(
        tampered
            .import_snapshot(&path)
            .await
            .unwrap_err()
            .ends_with("snapshot object does not match its key")
    );
    std::fs::remove_file(&path).unwrap();
}

/// `fixture`'s successor at its endpoint, pinning the same programs.
fn successor_of(fixture: &Fixture) -> ChainSpec {
    let end = fixture.proof.statement.statement.end;
    let mut successor = fixture.spec.clone();
    let start = neutrin0_primitives::ConsensusBoundary::fork_start(&end, &successor);
    successor.fork = Some(Box::new(neutrin0_primitives::ForkAnchor {
        predecessor: fixture.spec.hash(),
        count: end.next_chunk_id,
        endpoint_programs: end.programs,
        start,
        endpoint_prover: neutrin0_primitives::runtime_account([5; 20]),
        prior_domains: vec![neutrin0_primitives::PriorDomain {
            chain_spec_hash: fixture.spec.hash(),
            end_chunk: end.next_chunk_id,
            end_height: end.height,
        }],
    }));
    successor.validate().unwrap();
    assert_eq!(successor.fork_endpoint(), Some(end));
    successor
}

/// Under a hard fork's successor, a snapshot file of exactly the endpoint its
/// specification pins starts the successor there: the start is trusted as
/// genesis is, so no History proof of the successor exists or is verified.
#[tokio::test]
async fn a_snapshot_file_of_the_fork_endpoint_starts_the_successor() {
    let fixture = Fixture::forking();
    let path = std::env::temp_dir().join(format!(
        "neutrin0-fork-{}-{:?}.snap",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    fixture.source().export_snapshot(&path, None).unwrap();
    let end = fixture.proof.statement.statement.end;
    let successor = successor_of(&fixture);
    // A forked node never materialises the original genesis state. An
    // archive, which bootstraps from nothing else, starts there as well.
    for archive in [false, true] {
        let mut engine = Engine::genesis(successor.clone(), MemoryDatabase::new()).unwrap();
        if archive {
            engine
                .set_retention_policy(RetentionPolicy::Archive)
                .unwrap();
        }
        let target = fixture_backend(&fixture, engine, NativeHistory);
        target.initialize_history().unwrap();
        if !archive {
            target
                .initialize_bootstrap(&BootstrapConfig::default())
                .unwrap();
        }
        assert!(target.import_snapshot(&path).await.unwrap());
        target.with_engine(|engine| {
            assert_eq!(engine.head_hash(), fixture.header.hash());
            assert_eq!(engine.finalized_next_chunk_id(), end.next_chunk_id);
            assert_eq!(engine.latest_history_proof().unwrap(), None);
            assert_eq!(engine.state().root(), fixture.state.root());
            assert_eq!(engine.active_validator_set(), fixture.validators);
        });
        assert!(!target.bootstrap_pending());
        assert!(!target.import_snapshot(&path).await.unwrap());
    }
    std::fs::remove_file(&path).unwrap();
}

/// A chain that finalized up to governance's fork notices its end and writes
/// the endpoint bundle; a successor starts from it with the predecessor's
/// signing protection, its start and its carry, each once, and needs the
/// bundle no more afterwards. A chain without a scheduled fork never ends.
#[tokio::test]
async fn the_fork_endpoint_bundle_hands_the_chain_to_its_successor() {
    assert_eq!(Fixture::new(None).source().reached_fork(), None);
    let fixture = Fixture::forking();
    let source = fixture.source();
    let fork = source.reached_fork().unwrap();
    assert_eq!(fork.count, 1);
    let directory = std::env::temp_dir().join(format!(
        "neutrin0-fork-bundle-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let bundle = source
        .export_fork_endpoint("name = \"fixture\"\n", &directory)
        .unwrap();
    let template = std::fs::read_to_string(bundle.join("successor.toml")).unwrap();
    assert!(template.contains(&format!(
        "predecessor_hex = \"{}\"",
        hex::encode(fixture.spec.hash())
    )));
    assert!(!template.contains("[programs]"));
    // A written bundle is kept as it is.
    assert_eq!(
        source
            .export_fork_endpoint("name = \"other\"\n", &directory)
            .unwrap(),
        bundle
    );
    assert_eq!(
        std::fs::read_to_string(bundle.join("successor.toml")).unwrap(),
        template
    );

    let successor = successor_of(&fixture);
    let handoff = crate::fork::Handoff {
        bundle: bundle.clone(),
        spec_path: directory.join("chain-spec.toml"),
    };
    let mut db = MemoryDatabase::new();
    handoff.import_signing(&mut db, &successor).unwrap();
    // A database that records its chain is never imported into again.
    handoff.import_signing(&mut db, &successor).unwrap();
    let engine = Engine::genesis(successor, db).unwrap();
    let target = fixture_backend(&fixture, engine, NativeHistory);
    target.initialize_history().unwrap();
    target
        .initialize_bootstrap(&BootstrapConfig::default())
        .unwrap();
    target.complete_fork_handoff(&handoff).await.unwrap();
    target.with_engine(|engine| {
        assert_eq!(engine.finalized_next_chunk_id(), fork.count);
        assert_eq!(engine.state().root(), fixture.state.root());
        assert!(engine.store().fork_carry_imported().unwrap());
    });
    // The predecessor's directory may go once the handoff is complete.
    std::fs::remove_dir_all(&directory).unwrap();
    target.complete_fork_handoff(&handoff).await.unwrap();
}

struct TrustedFile(std::path::PathBuf);
impl TrustedFile {
    fn new(checkpoint: &Checkpoint) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "neutrin0-bootstrap-{}-{}.borsh",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, borsh::to_vec(checkpoint).unwrap()).unwrap();
        Self(path)
    }
    fn config(&self) -> BootstrapConfig {
        BootstrapConfig {
            trusted_checkpoint_path: Some(self.0.clone()),
            trusted_at: Some(super::now().unwrap()),
            ..BootstrapConfig::default()
        }
    }
}
impl Drop for TrustedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// An unbounded trusted checkpoint source is refused once it passes the size
/// limit, without reading it whole.
#[cfg(unix)]
#[test]
fn unbounded_trusted_checkpoint_file_is_refused_within_its_limit() {
    let fixture = Fixture::new(None);
    let target = fixture.backend(MemoryDatabase::new());
    let config = BootstrapConfig {
        trusted_checkpoint_path: Some("/dev/zero".into()),
        trusted_at: Some(super::now().unwrap()),
        ..BootstrapConfig::default()
    };
    assert_eq!(
        target.initialize_bootstrap(&config),
        Err("bootstrap trusted checkpoint exceeds size limit".to_owned())
    );
    assert!(!target.bootstrap_pending());
}

#[tokio::test]
async fn explicit_latest_anchor_bootstraps_without_an_empty_bridge_receipt() {
    let fixture = Fixture::new(None);
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    let trust = TrustedFile::new(&fixture.proof.end_checkpoint());
    target.initialize_bootstrap(&trust.config()).unwrap();
    assert!(target.bootstrap_pending()); // An ahead local trust anchor gates signing immediately.
    let manifest = source.serve_bootstrap(fixture.end()).unwrap();
    if !target
        .begin_bootstrap(None, manifest)
        .await
        .unwrap()
        .root_complete
    {
        assert!(
            drain(&source, &target, fixture.state.root())
                .await
                .unwrap()
                .root_complete
        );
    }
    assert_installed(&fixture, &target);
}

#[tokio::test]
async fn invalid_receipt_context_history_or_certificate_never_publishes_bootstrap() {
    let fixture = Fixture::new(None);
    let source = fixture.source();
    for mutation in 0..7 {
        let target = fixture.backend(MemoryDatabase::new());
        target
            .initialize_bootstrap(&BootstrapConfig::default())
            .unwrap();
        let mut manifest = source.serve_bootstrap(fixture.end()).unwrap();
        let mut anchor = None;
        match mutation {
            0 => manifest.history.receipt = BoundedBytes::new(vec![9]).unwrap(),
            1 => {
                let mut validators = manifest.validators.to_vec();
                validators[0].effective_stake += 1;
                manifest.validators =
                    neutrin0_consensus_types::bootstrap::BootstrapValidators::new(validators)
                        .unwrap();
            }
            2 => manifest.anchor_header.signature[0] ^= 1,
            3 => manifest.frontier.peaks[0][0] ^= 1,
            // A genesis origin is authenticated by the receipt alone; an
            // opening offered for it is not accepted in its place.
            6 => {
                anchor = Some(AnchorOpening {
                    context: fixture.recent[0].record.evidence_context(),
                    path: fixture.recent[0].path.clone(),
                });
            }
            _ => {
                let mut opening: HistoricalOpening =
                    borsh::from_slice(manifest.recent[0].as_slice()).unwrap();
                if mutation == 4 {
                    opening.path.siblings[63][0] ^= 1;
                } else {
                    opening.record.finality.precommit_attestations[0].signature[0] ^= 1;
                }
                manifest.recent = neutrin0_consensus_types::bootstrap::BootstrapHistory::new(vec![
                    BoundedBytes::new(borsh::to_vec(&opening).unwrap()).unwrap(),
                ])
                .unwrap();
            }
        }
        Box::pin(assert_bootstrap_rejected(
            &source, &target, &fixture, anchor, manifest,
        ))
        .await;
        target.with_engine(|engine| {
            assert_eq!(engine.head_hash(), fixture.spec.genesis_block_hash);
            assert_eq!(engine.finalized_next_chunk_id(), 0);
            assert_eq!(engine.latest_history_proof().unwrap(), None);
            assert_eq!(engine.store().bootstrap_source_floor().unwrap(), 0);
        });
    }
}

#[derive(Clone, Default)]
struct FaultDb {
    inner: MemoryDatabase,
    fail_install: bool,
}
impl Database for FaultDb {
    type Error = String;
    fn read_handle(&self) -> std::sync::Arc<dyn neutrin0_storage::ReadHandle> {
        self.inner.read_handle()
    }
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        Ok(self.inner.get(column, key).unwrap())
    }
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.inner.put(column, key, value).unwrap();
        Ok(())
    }
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), String> {
        self.inner.delete(column, key).unwrap();
        Ok(())
    }
    fn write_batch(&mut self, batch: Batch) -> Result<(), String> {
        self.inner.write_batch(batch).unwrap();
        Ok(())
    }
    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), String> {
        if self.fail_install
            && batch.operations().iter().any(|operation| {
                matches!(
                    operation,
                    BatchOp::Put {
                        column: Column::HistoricalChunks,
                        ..
                    }
                )
            })
        {
            return Err("injected bootstrap durable batch failure".into());
        }
        self.inner.write_batch_durable(batch).unwrap();
        Ok(())
    }
    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, String> {
        Ok(self.inner.iter_column(column).unwrap())
    }
}

#[tokio::test]
async fn failed_install_retains_durable_download_for_retry_and_restart() {
    let fixture = Fixture::new(None);
    let source = fixture.source();
    let target = fixture.backend(FaultDb::default());
    let config = BootstrapConfig::default();
    target.initialize_bootstrap(&config).unwrap();
    target.with_engine_mut(|engine| engine.store_mut().db_mut().fail_install = true);
    let manifest = source.serve_bootstrap(fixture.end()).unwrap();
    Box::pin(assert_bootstrap_rejected(
        &source, &target, &fixture, None, manifest,
    ))
    .await;
    assert_eq!(target.with_engine(Engine::head_height), 0);
    assert!(target.bootstrap_pending());
    let mut db = target.with_engine(|engine| engine.store().db().clone());
    assert!(db.get(Column::Meta, PENDING_KEY).unwrap().is_some());
    assert_eq!(
        db.iter_column(Column::HistoricalChunks).unwrap(),
        ColumnSnapshot::new()
    );
    db.fail_install = false;
    let resumed = fixture_backend(
        &fixture,
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    resumed.initialize_history().unwrap();
    resumed.initialize_bootstrap(&config).unwrap();
    resumed.finish_bootstrap().await.unwrap();
    assert_installed(&fixture, &resumed);
    let persisted = resumed.with_engine(|engine| engine.store().db().clone());
    let restarted = fixture_backend(
        &fixture,
        Engine::open(fixture.spec.clone(), persisted).unwrap(),
        NativeHistory,
    );
    restarted.initialize_history().unwrap();
    restarted.initialize_bootstrap(&config).unwrap();
    assert_installed(&fixture, &restarted);
}

#[tokio::test]
async fn an_admitted_download_still_installs_after_its_endpoint_goes_stale() {
    let fixture = Fixture::new(None);
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    let config = BootstrapConfig::default();
    target.initialize_bootstrap(&config).unwrap();
    let manifest = source.serve_bootstrap(fixture.end()).unwrap();
    target.begin_bootstrap(None, manifest).await.unwrap();
    let pending = target
        .bootstrap
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|runtime| runtime.pending.clone())
        .unwrap();
    let spec = &fixture.spec;
    let endpoint_time =
        spec.genesis_time + pending.data.history.end().slot * spec.consensus.slot_duration_secs;
    let stale = endpoint_time + spec.light_client.stale_threshold_secs + 1;
    let check = |check, clock| {
        super::authenticate_at(
            &NativeHistory,
            spec,
            &pending,
            config.max_future_drift_secs,
            check,
            clock,
        )
    };
    // A download slower than the freshness window is not refused at
    // installation or restart; a new manifest still must be fresh.
    assert!(check(super::Check::Admission, stale).is_err());
    assert!(check(super::Check::Installation, stale).is_ok());
    // The trust anchor's expiry still binds.
    let expires = neutrin0_light_client::LightClient::new(
        spec,
        pending.origin,
        pending.trusted_at,
        config.max_future_drift_secs,
    )
    .unwrap()
    .anchor_expires_at();
    assert!(check(super::Check::Installation, expires).is_err());
    assert!(check(super::Check::Installation, expires - 1).is_ok());
}

#[tokio::test]
async fn archive_role_cannot_replace_source_history_with_a_snapshot() {
    let fixture = Fixture::new(None);
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    target.with_engine_mut(|engine| {
        engine
            .set_retention_policy(RetentionPolicy::Archive)
            .unwrap();
    });
    target
        .initialize_bootstrap(&BootstrapConfig::default())
        .unwrap();
    let manifest = source.serve_bootstrap(fixture.end()).unwrap();
    Box::pin(assert_bootstrap_rejected(
        &source, &target, &fixture, None, manifest,
    ))
    .await;
    assert_eq!(target.with_engine(Engine::head_height), 0);
    assert_eq!(
        target.with_engine(Engine::latest_history_proof).unwrap(),
        None
    );
}

fn assert_download_discarded(target: &Backend) {
    use neutrin0_consensus_engine::store::pointers::{STATE_DOWNLOAD, STATE_DOWNLOAD_ENTRY_PREFIX};
    target.with_engine(|engine| {
        let metadata = engine.store().db().iter_column(Column::Meta).unwrap();
        assert!(metadata.iter().all(|(key, _)| {
            key != PENDING_KEY
                && !key.starts_with(STATE_DOWNLOAD)
                && !key.starts_with(STATE_DOWNLOAD_ENTRY_PREFIX)
        }));
    });
    assert!(!target.bootstrap_pending());
    assert_eq!(target.bootstrap_origin(), None);
}

#[tokio::test]
async fn disabled_restart_discards_partial_download_and_can_restart_from_local_origin() {
    let fixture = Fixture::new(Some(vec![8; 150_000]));
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    let enabled = BootstrapConfig::default();
    target.initialize_bootstrap(&enabled).unwrap();
    target.with_engine_mut(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::SigningJournal, b"preserve", b"local-intent")
            .unwrap();
        engine
            .store_mut()
            .db_mut()
            .put(Column::Meta, b"application", b"live-metadata")
            .unwrap();
    });
    let before = target.with_engine(|engine| engine.store().db().clone());
    let root = fixture.state.root();
    let end = fixture.end();
    let manifest = source.serve_bootstrap(end).unwrap();
    target.begin_bootstrap(None, manifest).await.unwrap();
    receive_until_large_fragment(&source, &target, root).await;
    let db = target.with_engine(|engine| engine.store().db().clone());
    assert!(db.get(Column::Meta, PENDING_KEY).unwrap().is_some());
    let restarted = fixture_backend(
        &fixture,
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    restarted.initialize_history().unwrap();
    restarted
        .initialize_bootstrap(&BootstrapConfig {
            enabled: false,
            ..enabled.clone()
        })
        .unwrap();
    assert_download_discarded(&restarted);
    restarted.with_engine(|engine| {
        assert_eq!(engine.head_hash(), fixture.spec.genesis_block_hash);
        assert_eq!(engine.head_state_root(), fixture.spec.genesis_state_root);
        assert_eq!(engine.finalized_next_chunk_id(), 0);
        assert_eq!(engine.latest_history_proof().unwrap(), None);
        for column in neutrin0_storage::ALL_COLUMNS {
            assert_eq!(
                engine.store().db().iter_column(column).unwrap(),
                before.iter_column(column).unwrap()
            );
        }
    });
    // Re-enabling uses the unchanged local anchor, not stale pending metadata.
    restarted.initialize_bootstrap(&enabled).unwrap();
    assert_eq!(restarted.bootstrap_origin(), Some(fixture.genesis()));
    assert_eq!(
        restarted.state_download_items(root).unwrap(),
        vec![neutrin0_consensus_types::bootstrap::StateItem::node(root)]
    );
    restarted
        .begin_bootstrap(None, source.serve_bootstrap(end).unwrap())
        .await
        .unwrap();
    while !receive(&source, &restarted, root).await.root_complete {}
    assert_installed(&fixture, &restarted);
    assert_eq!(
        restarted
            .with_engine(|engine| engine.store().db().get(Column::SigningJournal, b"preserve"))
            .unwrap(),
        Some(b"local-intent".to_vec())
    );
}

#[tokio::test]
async fn archive_restart_discards_staging_and_preserves_canonical_raw_sources() {
    let fixture = Fixture::new(Some(vec![3; 150_000]));
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    // Import genuine signed source data before requesting its proven checkpoint.
    let block = Block {
        header: fixture.header.clone(),
        body: fixture.body.clone(),
    };
    target
        .verify_and_import_proven_blocks(vec![fixture.publication(&target, block.clone())])
        .await
        .unwrap();
    target
        .initialize_bootstrap(&BootstrapConfig::default())
        .unwrap();
    target.with_engine_mut(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::SigningJournal, b"preserve", b"archive-intent")
            .unwrap();
    });
    let before = target.with_engine(|engine| engine.store().db().clone());
    let root = fixture.state.root();
    let manifest = source.serve_bootstrap(fixture.end()).unwrap();
    target.begin_bootstrap(None, manifest).await.unwrap();
    receive_until_large_fragment(&source, &target, root).await;
    let db = target.with_engine(|engine| engine.store().db().clone());
    let restarted = fixture_backend(
        &fixture,
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    restarted.initialize_history().unwrap();
    restarted.with_engine_mut(|engine| {
        engine
            .set_retention_policy(RetentionPolicy::Archive)
            .unwrap();
    });
    restarted.discard_bootstrap_download().unwrap();
    assert_download_discarded(&restarted);
    restarted.with_engine(|engine| {
        assert_eq!(engine.head_hash(), block.hash());
        assert_eq!(engine.head_height(), 1);
        assert_eq!(engine.finalized_next_chunk_id(), 0);
        assert_eq!(engine.latest_history_proof().unwrap(), None);
        assert_eq!(
            engine.retention_info().unwrap().policy,
            RetentionPolicy::Archive
        );
        assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 0);
        assert_eq!(
            engine.store().get_header_by_height(1).unwrap(),
            Some(block.header.clone())
        );
        assert!(
            engine
                .store()
                .db()
                .get(Column::Blocks, &block.hash())
                .unwrap()
                .is_some()
        );
        for column in neutrin0_storage::ALL_COLUMNS
            .into_iter()
            .filter(|column| *column != Column::Meta)
        {
            assert_eq!(
                engine.store().db().iter_column(column).unwrap(),
                before.iter_column(column).unwrap()
            );
        }
    });
}

#[test]
fn authenticated_bootstrap_program_scopes_are_counted_and_release_independently() {
    use neutrin0_proof_system::artifacts::ArtifactIdentity;
    let fixture = Fixture::new(None);
    let source = fixture.source();
    let data = source.serve_bootstrap(fixture.end()).unwrap();
    let target = fixture.backend(MemoryDatabase::new());
    let expected = super::snapshot_program_retention(&data).unwrap();
    let first = target.pin_bootstrap_programs(&data).unwrap();
    let second = target.pin_bootstrap_programs(&data).unwrap();
    assert_eq!(target.bootstrap_program_retention(), expected);
    assert!(expected.warm.contains(&ArtifactIdentity::Runtime(
        data.history.end().programs.runtime_code_hash
    )));
    assert!(
        expected
            .warm
            .iter()
            .all(|identity| expected.sources.contains(identity))
    );
    // Reconciliation cannot discard a scope that is independent of the
    // replaceable pending manifest. One attempt's completion releases only it.
    target.sync_programs();
    drop(first);
    assert_eq!(target.bootstrap_program_retention(), expected);
    drop(second);
    assert_eq!(
        target.bootstrap_program_retention(),
        neutrin0_proof_system::artifacts::ProgramRetention::default()
    );
}

#[tokio::test]
async fn a_download_begun_under_other_trust_is_dropped_at_restart() {
    let fixture = Fixture::new(Some(vec![6; 150_000]));
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    let trust = TrustedFile::new(&fixture.proof.end_checkpoint());
    target.initialize_bootstrap(&trust.config()).unwrap();
    let manifest = source.serve_bootstrap(fixture.end()).unwrap();
    assert!(
        !target
            .begin_bootstrap(None, manifest)
            .await
            .unwrap()
            .root_complete
    );
    // The operator drops the trusted checkpoint: the node starts anyway
    // and forgets the download it can no longer authenticate.
    let db = target.with_engine(|engine| engine.store().db().clone());
    let restarted = fixture_backend(
        &fixture,
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    restarted.initialize_history().unwrap();
    restarted
        .initialize_bootstrap(&BootstrapConfig::default())
        .unwrap();
    assert!(restarted.bootstrap_state().unwrap().is_none());
}
