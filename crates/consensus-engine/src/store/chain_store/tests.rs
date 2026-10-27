use super::evidence_pool::{StoredEvidenceReport, displaceable_reports};
use super::*;
use crate::BlockState;
use crate::test_db::header;
use neutrin0_consensus_types::{AggregatedVote, Body, Chunk, FinalityCert, SlashingEvidence};
use neutrin0_primitives::{BitVec, BlsSignature, Hash, ZERO_HASH};
use neutrin0_storage::MemoryDatabase;

fn h(b: u8) -> Hash {
    [b; 32]
}

fn sig(b: u8) -> BlsSignature {
    [b; 96]
}

fn aggregated(b: u8) -> AggregatedVote {
    let mut bits = BitVec::default();
    bits.push(true);
    AggregatedVote {
        aggregation_bits: bits,
        signature: sig(b),
    }
}

fn chunk(id: u64) -> Chunk {
    Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id: id,
        start_height: id * 128 + 1,
        end_height: id * 128 + 128,
        start_state_root: h(10),
        end_state_root: h(11),
        start_block_hash: h(12),
        end_block_hash: h(13),
        block_hash_root: h(14),
        block_proof_root: h(15),
        vrf_proof_root: h(16),
        active_validator_set_root: h(17),
        next_validator_set_root: h(17),
        da_root: h(18),
    }
}

#[test]
fn execution_index_follows_atomic_canonical_reorganization_and_restart() {
    let genesis = h(1);
    let mut store = ChainStore::new(crate::test_db::FaultDb::default());
    store
        .commit_tip(genesis, genesis, neutrin0_storage::Batch::new())
        .unwrap();
    let body = Body {
        transactions: vec![vec![7]],
        artifacts: neutrin0_runtime_abi::ExecutionArtifacts {
            transaction_ids: vec![(0, h(99))],
            receipts: vec![vec![8]],
            metadata: vec![9],
        },
        ..Body::default()
    };
    let mut original = neutrin0_consensus_types::Block {
        header: header(1, 1, genesis, h(2)),
        body: body.clone(),
    };
    original.header.receipts_root = body.artifacts.commitment();
    let mut replacement = original.clone();
    replacement.header.slot = 2;
    let original_hash = original.hash();
    let replacement_hash = replacement.hash();
    store
        .commit_tip(
            original_hash,
            genesis,
            ChainStore::<crate::test_db::FaultDb>::block_archive_batch(&original, None, None)
                .unwrap(),
        )
        .unwrap();
    store
        .db_mut()
        .write_batch(
            ChainStore::<crate::test_db::FaultDb>::block_archive_batch(&replacement, None, None)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        store.execution_transaction(&h(99)).unwrap(),
        Some((original_hash, 0))
    );
    store.db_mut().fail_batch = true;
    assert!(
        store
            .commit_tip(replacement_hash, genesis, neutrin0_storage::Batch::new())
            .is_err()
    );
    assert_eq!(
        store.execution_transaction(&h(99)).unwrap(),
        Some((original_hash, 0))
    );
    store.db_mut().fail_batch = false;
    store
        .commit_tip(replacement_hash, genesis, neutrin0_storage::Batch::new())
        .unwrap();
    assert_eq!(
        store.execution_transaction(&h(99)).unwrap(),
        Some((replacement_hash, 0))
    );
    let reopened = ChainStore::new(store.db().clone());
    assert_eq!(
        reopened.execution_transaction(&h(99)).unwrap(),
        Some((replacement_hash, 0))
    );
    let mut malformed = original;
    malformed.body.artifacts.transaction_ids.push((0, h(98)));
    assert!(
        ChainStore::<crate::test_db::FaultDb>::block_archive_batch(&malformed, None, None).is_err()
    );
}

#[test]
fn header_archival_preserves_canonical_index() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let hdr = header(7, 9, h(99), h(2));
    let hash = store.put_header(&hdr).expect("put");
    assert_eq!(hash, hdr.hash());
    assert_eq!(store.get_header(&hash).expect("get"), Some(hdr.clone()));
    assert_eq!(store.get_header_by_height(7).expect("get"), None,);
    assert_eq!(store.get_block_hash_by_height(7).expect("get"), None);
    assert_eq!(store.block_hashes_from_slot(9).expect("get"), vec![hash]);
    // A sibling of the same slot keeps its own entry.
    let sibling = header(7, 9, h(98), h(2));
    let sibling_hash = store.put_header(&sibling).expect("put");
    let mut both = store.block_hashes_from_slot(9).expect("get");
    both.sort_unstable();
    let mut expected = vec![hash, sibling_hash];
    expected.sort_unstable();
    assert_eq!(both, expected);
    assert_eq!(
        store.block_hashes_from_slot(10).expect("get"),
        [] as [[u8; 32]; 0]
    );
}

#[test]
fn missing_lookups_return_none() {
    let store = ChainStore::new(MemoryDatabase::new());
    assert_eq!(store.get_header(&h(0)).expect("get"), None);
    assert_eq!(store.get_header_by_height(0).expect("get"), None);
    assert_eq!(store.get_body(&h(0)).expect("get"), None);
    assert_eq!(store.get_block_proof(&h(0)).expect("get"), None);
    assert_eq!(store.get_chunk(0).expect("get"), None);
    assert_eq!(store.get_chunk_proof(0).expect("get"), None);
    assert_eq!(store.get_finality_cert(0).expect("get"), None);
    assert_eq!(store.get_validator_set_snapshot(0).expect("get"), None);
    assert_eq!(store.get_tip().expect("get"), None);
    assert_eq!(store.get_finalized_head().expect("get"), None);
    assert_eq!(store.get_latest_finalized_chunk_id().expect("get"), None);
    assert_eq!(store.get_chain_spec_hash().expect("get"), None);
}

#[test]
fn body_roundtrips_under_block_hash() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let body = Body {
        artifacts: neutrin0_runtime_abi::ExecutionArtifacts::default(),
        transactions: vec![vec![1, 2, 3]],
        participation: None,
        evidence_proofs: Vec::new(),
        programs: Vec::new(),
        participation_acks: Vec::new(),
    };
    let hash = h(123);
    store.put_body(&hash, &body).expect("put");
    assert_eq!(store.get_body(&hash).expect("get"), Some(body));
}

#[test]
fn block_proof_roundtrips() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let hash = h(33);
    let proof = neutrin0_consensus_types::BlockProof {
        height: 7,
        block_hash: hash,
        public_inputs: neutrin0_consensus_types::BlockProofPublicInputs {
            context: Box::default(),
            chain_id: 1,
            height: 7,
            parent_block_hash: h(32),
            block_hash: hash,
            state_root_before: h(40),
            state_root_after: h(41),
            transactions_root: ZERO_HASH,
            receipt_root: ZERO_HASH,
            da_root: ZERO_HASH,
            vm_code_hash: h(50),
            block_program: [50; 8],
            gas_used: 0,
            gas_limit: 1_000_000,
            proposer_address: [0u8; 32],
            runtime_extra: ZERO_HASH,
            inputs_root: [0; 32],
        },
        prover_address: [0; 32],
        statement_key: [0; 32],
        proof_bytes: vec![1, 2, 3, 4],
    };
    store.put_block_proof(&hash, &proof).expect("put");
    assert_eq!(
        store.get_block_proof(&hash).expect("get"),
        Some(proof.clone())
    );
    let mut alternate = proof.clone();
    alternate.proof_bytes.push(5);
    store
        .put_block_proof(&hash, &alternate)
        .expect("alternate verified receipt");
    store
        .put_proven_block(&hash, &alternate)
        .expect("concurrent completion");
    assert_eq!(
        store.get_block_proof(&hash).expect("get"),
        Some(proof.clone())
    );
    alternate.public_inputs.gas_used += 1;
    assert!(store.put_block_proof(&hash, &alternate).is_err());
    assert_eq!(store.get_block_proof(&hash).expect("get"), Some(proof));
}

#[test]
fn block_state_roundtrips_and_overwrites() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let hash = h(77);
    assert_eq!(store.get_block_state(&hash).expect("get"), None);

    store
        .put_block_state(&hash, BlockState::BlockProduced)
        .expect("put");
    assert_eq!(
        store.get_block_state(&hash).expect("get"),
        Some(BlockState::BlockProduced),
    );

    store
        .put_block_state(&hash, BlockState::PendingProof)
        .expect("put");
    assert_eq!(
        store.get_block_state(&hash).expect("get"),
        Some(BlockState::PendingProof),
    );

    store
        .put_block_state(&hash, BlockState::Proven)
        .expect("put");
    assert_eq!(
        store.get_block_state(&hash).expect("get"),
        Some(BlockState::Proven),
    );
}

#[test]
fn block_states_are_per_hash() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let a = h(101);
    let b = h(102);
    store
        .put_block_state(&a, BlockState::Proven)
        .expect("put a");
    store
        .put_block_state(&b, BlockState::BlockProduced)
        .expect("put b");
    assert_eq!(store.get_block_state(&a).unwrap(), Some(BlockState::Proven));
    assert_eq!(
        store.get_block_state(&b).unwrap(),
        Some(BlockState::BlockProduced),
    );
}

#[test]
fn chunk_and_chunk_proof_roundtrip() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let c = chunk(2);
    store.put_chunk(&c).expect("put chunk");
    assert_eq!(store.get_chunk(2).expect("get chunk"), Some(c.clone()));

    let cp = neutrin0_consensus_types::ChunkProof {
        finality_cert: FinalityCert {
            proposal: neutrin0_consensus_types::BftProposal {
                chunk: c.clone(),
                round: 0,
                proposer_index: 0,
                valid_quorum: None,
                round_change_certificate: None,
                proposal_slot: 0,
                receipts: Vec::new(),
                ratified_chunk_proofs: Vec::new(),
                signature: [0; 96],
            },
            prevote_attestations: Vec::new(),
            precommit_attestations: Vec::new(),
            proof_manifests: Vec::new(),
            chunk_id: 2,
            round: 0,
            chunk_hash: c.hash(),
            prevote: aggregated(1),
            precommit: aggregated(2),
            active_validator_set_root: c.active_validator_set_root,
        },
        chunk_id: 2,
        chunk_hash: c.hash(),
        prover_address: [0; 32],
        public_inputs: neutrin0_consensus_types::ChunkProofPublicInputs {
            next_identity_sanctions_root: [0; 32],

            chunk_id: 2,
            start_height: c.start_height,
            end_height: c.end_height,
            start_state_root: c.start_state_root,
            end_state_root: c.end_state_root,
            start_block_hash: c.start_block_hash,
            end_block_hash: c.end_block_hash,
            block_hash_root: c.block_hash_root,
            block_proof_root: c.block_proof_root,
            vrf_proof_root: c.vrf_proof_root,
            active_validator_set_root: c.active_validator_set_root,
            next_validator_set_root: c.next_validator_set_root,
            da_root: c.da_root,
        },
        proof_bytes: vec![9, 9],
    };
    store.put_chunk_proof(2, &cp).expect("put chunk proof");
    assert_eq!(store.get_chunk_proof(2).expect("get"), Some(cp));
}

#[test]
fn validator_set_snapshot_roundtrips() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let v = Validator {
        pubkey: [9; 48],
        withdrawal_credentials: h(60),
        effective_stake: 1_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    };
    let snap: ValidatorSetSnapshot = vec![v];
    store.put_validator_set_snapshot(5, &snap).expect("put");
    assert_eq!(
        store.get_validator_set_snapshot(5).expect("get"),
        Some(snap),
    );
}

#[test]
fn pointer_writes_and_reads_round_trip() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .commit_tip(h(1), h(1), neutrin0_storage::Batch::new())
        .expect("put");
    store.put_finalized_head(h(2)).expect("put");
    store.put_latest_finalized_chunk_id(42).expect("put");
    store.put_chain_spec_hash(h(99)).expect("put");
    assert_eq!(store.get_tip().expect("get"), Some(h(1)));
    assert_eq!(store.get_finalized_head().expect("get"), Some(h(2)));
    assert_eq!(
        store.get_latest_finalized_chunk_id().expect("get"),
        Some(42)
    );
    assert_eq!(store.get_chain_spec_hash().expect("get"), Some(h(99)));
}

#[test]
fn overwriting_a_pointer_replaces_the_value() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .commit_tip(h(1), h(1), neutrin0_storage::Batch::new())
        .expect("put");
    let hash = store.put_header(&header(1, 1, h(1), h(2))).unwrap();
    store
        .commit_tip(hash, h(1), neutrin0_storage::Batch::new())
        .expect("put");
    assert_eq!(store.get_tip().expect("get"), Some(hash));
}

#[test]
fn slashing_evidence_roundtrips_and_iterates_in_column() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let a = SlashingEvidence::DoubleProposal {
        proposer_index: 1,
        header_a: header(7, 9, h(0xAA), h(2)),
        header_b: header(7, 9, h(0xBB), h(2)),
    };
    let b = SlashingEvidence::DoubleProposal {
        proposer_index: 2,
        header_a: header(8, 10, h(0xCC), h(2)),
        header_b: header(8, 10, h(0xDD), h(2)),
    };
    let key_a = store
        .put_slashing_evidence(&a)
        .expect("put slashing evidence a");
    let key_b = store
        .put_slashing_evidence(&b)
        .expect("put slashing evidence b");
    assert_ne!(
        key_a, key_b,
        "distinct evidence content must yield distinct keys",
    );

    let mut listed = store.iter_slashing_evidence().expect("iter");
    listed.sort_by_key(|(k, _)| *k);
    let mut expected = vec![(key_a, a), (key_b, b.clone())];
    expected.sort_by_key(|(k, _)| *k);
    assert_eq!(listed, expected, "iter returns the persisted set");

    store
        .delete_slashing_evidence(&key_b)
        .expect("delete b removes the row");
    let remaining = store.iter_slashing_evidence().expect("iter after delete");
    assert_eq!(
        remaining.len(),
        1,
        "delete shrinks the column (got {remaining:?})",
    );
    assert_eq!(remaining[0].0, key_a, "the wrong row was deleted");
}

#[test]
fn corrupt_header_record_surfaces_codec_error() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .db_mut()
        .put(Column::Headers, &keys::hash_key(&h(7)), &[0xFF, 0xFF, 0xFF])
        .expect("put");
    match store.get_header(&h(7)) {
        Err(StoreError::Codec(_)) => {}
        other => panic!("expected codec error, got {other:?}"),
    }
}

fn pooled(
    id: u8,
    kind: neutrin0_consensus_types::evidence::SanctionKind,
    count: u64,
) -> (Vec<u8>, Vec<u8>) {
    use neutrin0_consensus_types::evidence::{
        EvidenceArtifact, EvidenceContext, EvidenceReport, EvidenceStatement,
    };
    let report = EvidenceReport {
        artifact: EvidenceArtifact {
            membership: neutrin0_consensus_types::evidence::EvidenceMembership::default(),
            evidence_guest_vk_digest: [2; 8],
            statement: EvidenceStatement {
                reporter: None,
                chain_id: 7,
                chain_spec_hash: h(1),
                block_guest_vk_digest: [1; 8],
                context: EvidenceContext {
                    chunk_id: 0,
                    chunk_hash: h(3),
                    end_height: 1,
                    validators_root: h(4),
                    seed: ZERO_HASH,
                    source_block_guest_vk_digest: [1; 8],
                    source_runtime_code_hash: h(5),
                    start_boundary: ZERO_HASH,
                },
                offender: neutrin0_primitives::Validator {
                    pubkey: [id; 48],
                    withdrawal_credentials: h(6),
                    effective_stake: 1,
                    activation_epoch: 0,
                    exit_epoch: u64::MAX,
                },
                kind,
                offence_id: h(id),
                facts_commitment: h(8),
            },
            proof_bytes: vec![1],
        },
        history: neutrin0_consensus_types::history::HistoryPath {
            index: 0,
            count,
            siblings: vec![ZERO_HASH; 64],
        },
    };
    let stored = StoredEvidenceReport {
        report,
        history_root: ZERO_HASH,
    };
    (vec![id], borsh::to_vec(&stored).unwrap())
}

#[test]
fn full_pools_yield_liveness_first_and_never_keep_a_safety_report_out() {
    use neutrin0_consensus_types::evidence::SanctionKind::{Inactivity, Slash};
    let entries = [
        pooled(1, Slash, 5),
        pooled(2, Inactivity, 7),
        pooled(3, Slash, 3),
        pooled(4, Inactivity, 2),
        pooled(5, Slash, 9),
        pooled(6, Inactivity, 9),
    ];
    let keys = |incoming| {
        displaceable_reports::<()>(&entries, incoming, Some(9))
            .unwrap()
            .into_iter()
            .map(|(key, _)| key[0])
            .collect::<Vec<_>>()
    };
    // Entry 5 holds a current opening and is never displaced; entry 6 does
    // too, but as a liveness receipt it still yields to a safety report.
    assert_eq!(keys(Slash), [4, 2, 3, 1, 6]);
    assert_eq!(keys(Inactivity), [4, 2]);
    assert_eq!(
        displaceable_reports::<()>(&entries, Slash, None).unwrap(),
        Vec::new()
    );
}
