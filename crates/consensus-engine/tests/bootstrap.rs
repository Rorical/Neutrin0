//! Native bootstrap authentication tests. Receipts are checked by an explicit
//! test-only backend; real compressed recursion runs in ignored tests.
//! The fixture's single chunk starts at genesis, so a genesis trust anchor
//! needs no opening.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrin0_consensus_engine::{Engine, RetentionPolicy};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history::{HistoryFrontier, HistoryPath};
use neutrin0_consensus_types::history_proof::{
    ChainBinding, Checkpoint, ChunkReceiptStatement, ConsensusBoundary, HistoryProof, ProofDomain,
};
use neutrin0_consensus_types::{BlockProofPublicInputs, Header};
use neutrin0_primitives::{BoundedBytes, ChainSpec, Hash, Validator};
use neutrin0_proof_system::{ProofError, ProofSystem, VerifiedHistory, verify_history_proof};
use neutrin0_prover_chunk::{
    consensus::{as_chunk, validate_consensus_with_context},
    history::{HistoricalChunk, HistoricalOpening},
};
use neutrin0_storage::{Column, Database, MemoryDatabase};
use neutrin0_trie::{NodeSource, Trie};

struct NativeHistory;
impl ProofSystem for NativeHistory {
    type BlockProof = Vec<u8>;
    type ChunkProof = Vec<u8>;
    fn prove_block(
        &self,
        _: &[u8],
        _: &BlockProofPublicInputs,
        _: neutrin0_primitives::Hash,
    ) -> Result<Vec<u8>, ProofError> {
        Err(ProofError::Unsupported)
    }
    fn verify_block(&self, _: &Vec<u8>, _: &BlockProofPublicInputs) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }
    fn history_domain(&self, spec: &ChainSpec) -> Result<ProofDomain, ProofError> {
        Ok(ProofDomain {
            chain: ChainBinding::new(spec),
            chunk: spec.genesis_chunk,
            programs: support::programs([1; 8], [4; 32]),
        })
    }
    fn programs(&self) -> Option<neutrin0_consensus_types::history_proof::GuestPrograms> {
        Some(neutrin0_consensus_types::history_proof::GuestPrograms {
            execution: support::programs([1; 8], [4; 32]).execution,
            chunk: support::chunk_program(),
        })
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

/// Stream `state` and then `sanctions` into `engine`'s store, as a
/// downloaded snapshot is installed.
fn stage(engine: &mut Engine<MemoryDatabase>, state: &Trie, sanctions: &Trie) {
    #[derive(Debug)]
    struct Both<'a>(&'a Trie, &'a Trie);
    impl NodeSource for Both<'_> {
        fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
            self.0.node(hash).or_else(|| self.1.node(hash))
        }
        fn value(&self, hash: &Hash) -> Option<Vec<u8>> {
            self.0.value(hash).or_else(|| self.1.value(hash))
        }
    }
    engine
        .store_mut()
        .install_state_slice(
            &[state.root(), sanctions.root()],
            &Both(state, sanctions),
            usize::MAX,
        )
        .unwrap();
}

struct Fixture {
    spec: ChainSpec,
    header: Header,
    validators: Vec<Validator>,
    frontier: HistoryFrontier,
    recent: Vec<HistoricalOpening>,
    proof: HistoryProof,
    /// Application state at the fixture's finalized head.
    state: Trie,
    identity_sanctions: Trie,
}
impl Fixture {
    fn new() -> Self {
        let (witness, input, _) = support::fixture([1; 8], [4; 32]);
        let mut state = support::executed(
            &support::fixture_genesis_live([1; 8], [4; 32], 30_000_000),
            &input,
        )
        .trie()
        .clone();
        // A bootstrap snapshot carries only the nodes its root reaches.
        state.retain_roots(&[]).unwrap();
        Self::from_witness(witness, state, Trie::new())
    }
    fn from_witness(
        witness: neutrin0_prover_chunk::consensus::ConsensusWitness,
        state: Trie,
        identity_sanctions: Trie,
    ) -> Self {
        let validated = validate_consensus_with_context(&witness).unwrap();
        let statement = validated.statement;
        let record = HistoricalChunk {
            runtime_code_hash: witness.context.programs.runtime_code_hash,
            block_guest_vk_digest: witness.context.programs.execution.block,
            start_boundary: statement.start.commitment(),
            chunk: as_chunk(&statement.chunk),
            validators: witness.context.active_validators,
            seed: witness.seed,
            finality: witness.finality_cert,
        };
        let leaf = commitment(&record.evidence_context());
        let frontier = HistoryFrontier::from_leaves(&[leaf]).unwrap();
        assert_eq!(
            statement.chain,
            NativeHistory
                .history_domain(&witness.chain_spec)
                .unwrap()
                .chain
        );
        Self {
            proof: HistoryProof {
                statement: ChunkReceiptStatement {
                    statement,
                    chunk_prover_address: [0; 32],
                },
                receipt: BoundedBytes::new(vec![7]).unwrap(),
            },
            header: witness.blocks[0].header.clone(),
            validators: validated.next_context.active_validators,
            spec: witness.chain_spec,
            frontier,
            state,
            identity_sanctions,
            recent: vec![HistoricalOpening {
                record,
                path: HistoryPath::build(&[leaf], 0).unwrap(),
            }],
        }
    }
    fn engine(&self) -> Engine<MemoryDatabase> {
        let mut engine = Engine::genesis(self.spec.clone(), MemoryDatabase::new()).unwrap();
        engine
            .set_history_domain(NativeHistory.history_domain(&self.spec).unwrap())
            .unwrap();
        engine
    }
    fn token(&self) -> VerifiedHistory {
        verify_history_proof(&NativeHistory, &self.spec, self.proof.clone()).unwrap()
    }
    const fn checkpoint(&self, boundary: &ConsensusBoundary) -> Checkpoint {
        Checkpoint {
            chain: *self.proof.chain(),
            boundary: *boundary,
        }
    }
    const fn genesis(&self) -> Checkpoint {
        self.checkpoint(&self.proof.statement.statement.start)
    }
    fn install(&self, engine: &mut Engine<MemoryDatabase>) -> bool {
        stage(engine, &self.state, &self.identity_sanctions);
        engine
            .install_bootstrap(
                self.token(),
                None,
                self.genesis(),
                &self.header,
                &self.validators,
                &self.frontier,
                &self.recent,
                None,
            )
            .is_ok()
    }
}

#[test]
fn authenticated_bootstrap_restores_execution_consensus_retention_and_restart() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    engine
        .store_mut()
        .db_mut()
        .put(Column::SigningJournal, b"reservation", b"preserved")
        .unwrap();
    assert_eq!(
        fixture.proof.statement.statement.start,
        ConsensusBoundary::genesis(&fixture.spec)
    );
    assert!(fixture.install(&mut engine));
    assert_eq!(engine.head_hash(), fixture.header.hash());
    assert_eq!(engine.finalized_next_chunk_id(), 1);
    // The installed receipt is this node's History proof from now on.
    assert_eq!(
        engine.latest_history_proof().unwrap(),
        Some(fixture.proof.clone())
    );
    // It is also the proof the next chunk's leader ratifies.
    let retained = engine.store().chunk_receipts(0).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(
        retained[0].statement_key,
        fixture.proof.statement.statement_key()
    );
    assert_eq!(engine.active_validator_set(), fixture.validators);
    assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 1);
    assert_eq!(
        engine
            .store()
            .db()
            .get(Column::SigningJournal, b"reservation")
            .unwrap(),
        Some(b"preserved".to_vec())
    );
    assert_eq!(
        engine.store().historical_opening(0, 1).unwrap(),
        fixture.recent[0]
    );
    let mut restarted = Engine::open(fixture.spec, engine.store().db().clone()).unwrap();
    assert_eq!(restarted.head_hash(), fixture.header.hash());
    assert_eq!(
        restarted.consensus_boundary(1).unwrap().0.history_root,
        fixture.frontier.root().unwrap()
    );
    assert_eq!(
        restarted.latest_history_proof().unwrap(),
        Some(fixture.proof.clone())
    );
    restarted.prune_finalized_history().unwrap();
    assert!(restarted.store().historical_opening(0, 1).is_ok());
}

/// A snapshot enters the store a bounded slice at a time and resumes after a
/// restart; once adopted, the replaced state is collected and exactly the
/// snapshot remains.
#[test]
fn a_snapshot_installs_in_bounded_slices_that_resume_after_a_restart() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    // The replaced chain's state shares most of its nodes with the snapshot.
    engine
        .install_genesis_state(
            support::fixture_genesis_live([1; 8], [4; 32], 30_000_000)
                .trie()
                .clone(),
        )
        .unwrap();
    let roots = [fixture.state.root(), neutrin0_trie::EMPTY_TRIE_ROOT];
    let mut slices = 0;
    while !engine
        .store_mut()
        .install_state_slice(&roots, &fixture.state, 2)
        .unwrap()
    {
        slices += 1;
        // Unfinished, the installation can be neither released nor
        // superseded, and each slice is durable, so a restart resumes it.
        assert!(engine.store_mut().release_state_install().is_err());
        assert!(
            engine
                .store_mut()
                .install_state_slice(&[[9; 32]], &fixture.state, 2)
                .is_err()
        );
        engine = Engine::open(fixture.spec.clone(), engine.store().db().clone()).unwrap();
    }
    assert!(slices > 1);
    assert!(fixture.install(&mut engine));
    assert_eq!(engine.store().state_install().unwrap(), None);
    while !engine.collect_state_slice(16).unwrap() {}
    let db = engine.store().db();
    assert_eq!(db.len(Column::TrieNodes), fixture.state.node_count());
    assert_eq!(db.len(Column::StateValues), fixture.state.value_count());
    assert_eq!(engine.state().root(), fixture.state.root());
}

#[test]
fn trusted_anchor_must_be_genesis_the_endpoint_or_opened_under_it() {
    let fixture = Fixture::new();
    let end = fixture.proof.end_checkpoint();
    let mut engine = fixture.engine();
    stage(&mut engine, &fixture.state, &Trie::new());
    engine
        .install_bootstrap(
            fixture.token(),
            None,
            end,
            &fixture.header,
            &fixture.validators,
            &fixture.frontier,
            &fixture.recent,
            None,
        )
        .unwrap();
    assert_eq!(engine.head_height(), 1);
    // A boundary the receipt does not place on its chain is never trusted:
    // a forged genesis, a conflicting endpoint, or an opening where none
    // belongs.
    let mut forged_genesis = fixture.genesis();
    forged_genesis.boundary.seed[0] ^= 1;
    let mut conflicting_end = end;
    conflicting_end.boundary.slot += 1;
    let opening = neutrin0_consensus_types::history_proof::AnchorOpening {
        context: fixture.recent[0].record.evidence_context(),
        path: fixture.recent[0].path.clone(),
    };
    for (anchor, opening) in [
        (forged_genesis, None),
        (conflicting_end, None),
        (end, Some(&opening)),
        (fixture.genesis(), Some(&opening)),
    ] {
        let mut fresh = fixture.engine();
        stage(&mut fresh, &fixture.state, &Trie::new());
        assert!(
            fresh
                .install_bootstrap(
                    fixture.token(),
                    opening,
                    anchor,
                    &fixture.header,
                    &fixture.validators,
                    &fixture.frontier,
                    &fixture.recent,
                    None
                )
                .is_err()
        );
        assert_eq!(fresh.finalized_next_chunk_id(), 0);
    }
}

#[test]
fn mutated_context_certificate_header_or_incomplete_snapshot_never_changes_live_state() {
    for mutation in 0..7 {
        let mut fixture = Fixture::new();
        let mut engine = fixture.engine();
        let mut state = fixture.state.clone();
        match mutation {
            0 => fixture.validators[0].effective_stake += 1,
            1 => fixture.frontier.peaks[0][0] ^= 1,
            2 => fixture.recent[0].path.siblings[63][0] ^= 1,
            3 => fixture.recent[0].record.finality.precommit.signature[0] ^= 1,
            4 => fixture.header.signature[0] ^= 1,
            5 => fixture.recent.clear(),
            _ => {
                state.insert(b"unrelated", vec![1]).unwrap();
            }
        }
        stage(&mut engine, &state, &Trie::new());
        assert!(
            engine
                .install_bootstrap(
                    fixture.token(),
                    None,
                    fixture.genesis(),
                    &fixture.header,
                    &fixture.validators,
                    &fixture.frontier,
                    &fixture.recent,
                    None
                )
                .is_err()
        );
        assert_eq!(engine.head_hash(), fixture.spec.genesis_block_hash);
        assert_eq!(engine.finalized_next_chunk_id(), 0);
        assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 0);
    }
}

#[test]
fn archive_role_and_uncovered_bft_sessions_reject_snapshot_bootstrap() {
    let fixture = Fixture::new();
    let mut archive = fixture.engine();
    archive
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    assert!(!fixture.install(&mut archive));
    // A lock beyond the endpoint would be lost, so installation refuses it.
    let mut locked = fixture.engine();
    locked
        .store_mut()
        .db_mut()
        .put(Column::BftSessions, &2_u64.to_be_bytes(), b"unfinalized")
        .unwrap();
    assert!(!fixture.install(&mut locked));
    assert_eq!(
        locked
            .store()
            .db()
            .get(Column::BftSessions, &2_u64.to_be_bytes())
            .unwrap(),
        Some(b"unfinalized".to_vec())
    );
    // The endpoint's own next chunk keeps its session across installation,
    // to resume when that chunk opens.
    let mut current = fixture.engine();
    current
        .store_mut()
        .db_mut()
        .put(Column::BftSessions, &1_u64.to_be_bytes(), b"current")
        .unwrap();
    assert!(fixture.install(&mut current));
    assert_eq!(
        current
            .store()
            .db()
            .get(Column::BftSessions, &1_u64.to_be_bytes())
            .unwrap(),
        Some(b"current".to_vec())
    );
}

#[test]
fn auxiliary_identity_sanctions_survive_bootstrap_restart_and_pruning() {
    use neutrin0_consensus_types::{evidence::SanctionKind, runtime::Sanction};
    use neutrin0_prover_chunk::{consensus::validate_candidate, identity_sanctions::identity_key};
    let keys: Vec<_> = [42, 43]
        .iter()
        .map(|byte| neutrin0_crypto::bls::SecretKey::key_gen(&[*byte; 32], &[]).unwrap())
        .collect();
    let (mut witness, _, _, post) = support::fixture_with_validator_keys([1; 8], [4; 32], &keys);
    let offender = witness.context.active_validators[0].clone();
    witness.blocks[0]
        .output
        .accountability
        .admitted
        .push(Sanction {
            offence_id: [91; 32],
            offender: offender.clone(),
            kind: SanctionKind::Slash,
        });
    // Explicit native receipt-checker seam: the real compressed pipeline is a
    // separate gate. Re-sign the changed candidate; no finalized value is patched.
    validate_candidate(&witness).unwrap();
    witness.finality_cert = support::certificate_with_precommitters(&witness, &keys, &[0, 1]);
    let mut sanctions = Trie::new();
    sanctions
        .insert(&identity_key(&offender.pubkey), vec![1])
        .unwrap();
    let mut state = post.trie().clone();
    state.retain_roots(&[]).unwrap();
    let fixture = Fixture::from_witness(witness, state, sanctions);
    let mut engine = fixture.engine();
    let mut missing = fixture.engine();
    // Without the sanctions trie the installed roots are not the endpoint's.
    stage(&mut missing, &fixture.state, &Trie::new());
    assert!(
        missing
            .install_bootstrap(
                fixture.token(),
                None,
                fixture.genesis(),
                &fixture.header,
                &fixture.validators,
                &fixture.frontier,
                &fixture.recent,
                None
            )
            .is_err()
    );
    assert_eq!(missing.finalized_next_chunk_id(), 0);
    assert!(fixture.install(&mut engine));
    let root = fixture.identity_sanctions.root();
    assert_eq!(
        engine
            .consensus_boundary(1)
            .unwrap()
            .0
            .identity_sanctions_root,
        root
    );
    assert_eq!(engine.active_validator_set().len(), 1);
    let mut restarted = Engine::open(fixture.spec, engine.store().db().clone()).unwrap();
    restarted.prune_finalized_history().unwrap();
    let nodes = restarted
        .store()
        .db()
        .iter_column(Column::TrieNodes)
        .unwrap();
    let values = restarted
        .store()
        .db()
        .iter_column(Column::StateValues)
        .unwrap();
    let mut restored: Trie = Trie::from_persisted(
        root,
        nodes
            .into_iter()
            .map(|(hash, bytes)| (hash.try_into().unwrap(), bytes)),
        values
            .into_iter()
            .map(|(hash, bytes)| (hash.try_into().unwrap(), bytes)),
    );
    restored.retain_roots(&[]).unwrap();
    assert_eq!(
        restored.get(&identity_key(&offender.pubkey)).unwrap(),
        Some(vec![1])
    );
    assert_eq!(
        restarted
            .consensus_boundary(1)
            .unwrap()
            .0
            .identity_sanctions_root,
        root
    );
}

/// A hard fork's successor starts in a fresh directory at the boundary its
/// specification pins, from the predecessor's endpoint data alone: no History
/// proof of its own exists yet, and the predecessor's certificates verify
/// under the predecessor's domain.
#[test]
fn a_fork_successor_starts_at_its_pinned_start_from_the_predecessor_endpoint() {
    let fixture = Fixture::new();
    let end = fixture.proof.statement.statement.end;
    let successor = successor_of(&fixture);
    let start = successor.fork.as_deref().unwrap().start;
    let start_with = |engine: &mut Engine<MemoryDatabase>, validators: &[Validator]| {
        engine.install_fork_start(
            &fixture.header,
            validators,
            &fixture.frontier,
            &fixture.recent,
        )
    };
    let mut engine = Engine::genesis(successor.clone(), MemoryDatabase::new()).unwrap();
    // Nothing starts before the endpoint's state is installed.
    assert!(start_with(&mut engine, &fixture.validators).is_err());
    stage(&mut engine, &fixture.state, &fixture.identity_sanctions);
    let mut other = fixture.validators.clone();
    other[0].effective_stake -= 1;
    assert!(start_with(&mut engine, &other).is_err());
    start_with(&mut engine, &fixture.validators).unwrap();
    assert_eq!(engine.head_hash(), fixture.header.hash());
    assert_eq!(engine.finalized_next_chunk_id(), end.next_chunk_id);
    assert_eq!(engine.store().consensus_boundary(1).unwrap(), Some(start));
    assert_eq!(engine.latest_history_proof().unwrap(), None);
    assert_eq!(engine.active_validator_set(), fixture.validators);
    assert_eq!(
        engine.store().historical_opening(0, 1).unwrap(),
        fixture.recent[0]
    );
    // It starts once.
    assert!(start_with(&mut engine, &fixture.validators).is_err());
    let restarted = Engine::open(successor.clone(), engine.store().db().clone()).unwrap();
    assert_eq!(restarted.head_hash(), fixture.header.hash());
    assert_eq!(restarted.finalized_next_chunk_id(), end.next_chunk_id);

    // The predecessor's own specification has no fork to start.
    let mut unforked = fixture.engine();
    stage(&mut unforked, &fixture.state, &fixture.identity_sanctions);
    assert!(start_with(&mut unforked, &fixture.validators).is_err());
    // An archive starts there too, its source history beginning at the fork.
    let archive = started(&fixture, &successor, RetentionPolicy::Archive);
    let restarted = Engine::open(successor, archive.store().db().clone()).unwrap();
    assert_eq!(restarted.head_hash(), fixture.header.hash());
    assert_eq!(
        restarted.retention_info().unwrap().policy,
        RetentionPolicy::Archive
    );
    // Its tree opens the endpoint's retained records.
    assert_eq!(
        restarted.store().historical_opening(0, 1).unwrap(),
        fixture.recent[0]
    );
}

/// The fixture's specification as the hard-fork successor of itself at the
/// fixture chunk's endpoint.
fn successor_of(fixture: &Fixture) -> ChainSpec {
    let end = fixture.proof.statement.statement.end;
    let mut successor = fixture.spec.clone();
    successor.fork = Some(Box::new(neutrin0_primitives::ForkAnchor {
        predecessor: fixture.spec.hash(),
        count: end.next_chunk_id,
        endpoint_programs: end.programs,
        start: ConsensusBoundary::fork_start(&end, &successor),
        endpoint_prover: neutrin0_primitives::runtime_account([5; 20]),
        prior_domains: vec![neutrin0_primitives::PriorDomain {
            chain_spec_hash: fixture.spec.hash(),
            end_chunk: end.next_chunk_id,
            end_height: end.height,
        }],
    }));
    successor.validate().unwrap();
    successor
}

/// A fresh `policy` node of `successor`, started from the fixture endpoint.
fn started(
    fixture: &Fixture,
    successor: &ChainSpec,
    policy: RetentionPolicy,
) -> Engine<MemoryDatabase> {
    let mut engine = Engine::genesis(successor.clone(), MemoryDatabase::new()).unwrap();
    engine.set_retention_policy(policy).unwrap();
    stage(&mut engine, &fixture.state, &fixture.identity_sanctions);
    engine
        .install_fork_start(
            &fixture.header,
            &fixture.validators,
            &fixture.frontier,
            &fixture.recent,
        )
        .unwrap();
    engine
}

/// What a predecessor's directory retained beyond the endpoint moves to its
/// hard fork's successor once: pooled raw offences into every node and a
/// reporter's retention into a reporter, whose watched chunks reopen under
/// the successor's frontier. An archive takes History only from an archive.
#[test]
fn a_fork_carry_moves_pooled_offences_and_reporter_retention_once() {
    let fixture = Fixture::new();
    let mut predecessor = fixture.engine();
    predecessor
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    assert!(fixture.install(&mut predecessor));
    let watched = predecessor.store().reporter_history_chunks().unwrap();
    assert_ne!(watched, Vec::<u64>::new());
    predecessor
        .store_mut()
        .db_mut()
        .put(Column::SlashingPool, &[1; 32], b"raw offence")
        .unwrap();
    let mut carry = Vec::new();
    let exported = predecessor.store().export_fork_carry(&mut carry).unwrap();
    assert_eq!(
        (exported.chain_spec_hash, exported.finalized_count),
        (fixture.spec.hash(), 1)
    );
    let successor = successor_of(&fixture);
    let raw = |engine: &Engine<MemoryDatabase>| {
        engine
            .store()
            .db()
            .get(Column::SlashingPool, &[1; 32])
            .unwrap()
    };

    // Nothing is carried before the successor starts.
    let mut early = Engine::genesis(successor.clone(), MemoryDatabase::new()).unwrap();
    assert!(early.import_fork_carry(&mut carry.as_slice()).is_err());

    // A node that becomes a reporter after the start retains nothing of its
    // own yet; the carry brings the predecessor's watched chunks.
    let mut reporter = started(&fixture, &successor, RetentionPolicy::Pruned);
    reporter
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let none: Vec<u64> = Vec::new();
    assert_eq!(reporter.store().reporter_history_chunks().unwrap(), none);
    let imported = reporter
        .import_fork_carry(&mut carry.as_slice())
        .unwrap()
        .unwrap();
    assert_eq!(imported.chain_spec_hash, fixture.spec.hash());
    assert_eq!(raw(&reporter), Some(b"raw offence".to_vec()));
    assert_eq!(reporter.store().reporter_history_chunks().unwrap(), watched);
    assert_eq!(reporter.store().reporter_dormant_chunks().unwrap(), none);
    assert_eq!(reporter.store().reporter_gaps().unwrap(), Vec::new());
    assert_eq!(
        reporter.import_fork_carry(&mut carry.as_slice()).unwrap(),
        None
    );

    let mut full = started(&fixture, &successor, RetentionPolicy::Pruned);
    full.import_fork_carry(&mut carry.as_slice()).unwrap();
    assert_eq!(raw(&full), Some(b"raw offence".to_vec()));
    assert_eq!(full.store().reporter_history_chunks().unwrap(), none);

    let mut archive = started(&fixture, &successor, RetentionPolicy::Archive);
    assert!(archive.import_fork_carry(&mut carry.as_slice()).is_err());
    // The header's specification hash follows the magic and its length.
    let mut foreign = carry.clone();
    foreign[20] ^= 1;
    let mut other = started(&fixture, &successor, RetentionPolicy::Pruned);
    assert!(other.import_fork_carry(&mut foreign.as_slice()).is_err());
    assert_eq!(raw(&other), None);
}
