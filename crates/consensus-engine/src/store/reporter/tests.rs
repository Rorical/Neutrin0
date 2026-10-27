use super::*;
use crate::{ProposerKey, RetentionPolicy};
use neutrin0_consensus_types::Header;
use neutrin0_consensus_types::{
    BlockProof, BlockProofPublicInputs, FinalityVoteData, FinalityVotePhase,
};
use neutrin0_primitives::ConsensusDomain;
use neutrin0_storage::MemoryDatabase;
use std::collections::{BTreeMap, BTreeSet};

fn bonded(pubkey: BlsPublicKey, withdrawal_credentials: [u8; 32]) -> Validator {
    Validator {
        pubkey,
        withdrawal_credentials,
        effective_stake: 100,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

#[test]
fn unobserved_multiblock_finalization_keeps_proposer_headers_but_no_canonical_receipt() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let mut record = super::super::history::tests::record(0);
    record.validators = [1u8, 2]
        .into_iter()
        .map(|tag| bonded([tag; 48], [tag; 32]))
        .collect();
    let identities: Vec<_> = record
        .validators
        .iter()
        .map(|v| (v.pubkey, v.withdrawal_credentials))
        .collect();
    store.set_reporter_eligible(&identities, 1).unwrap();
    let first = crate::test_db::header(1, 1, [0; 32], [1; 32]);
    let mut second = crate::test_db::header(2, 2, first.hash(), [2; 32]);
    second.proposer_index = 1;
    store.put_header(&first).unwrap();
    store.put_header(&second).unwrap();
    let proof = BlockProof {
        height: 2,
        block_hash: second.hash(),
        public_inputs: BlockProofPublicInputs {
            context: Box::default(),
            chain_id: 7,
            height: 2,
            parent_block_hash: first.hash(),
            block_hash: second.hash(),
            state_root_before: first.state_root,
            state_root_after: second.state_root,
            transactions_root: [0; 32],
            receipt_root: [0; 32],
            da_root: [0; 32],
            vm_code_hash: [0; 32],
            block_program: [0; 8],
            gas_used: 0,
            gas_limit: 1_000_000,
            proposer_address: [2; 32],
            runtime_extra: [0; 32],
            inputs_root: [0; 32],
        },
        prover_address: [2; 32],
        statement_key: [0; 32],
        proof_bytes: vec![1],
    };
    store.put_block_proof(&second.hash(), &proof).unwrap();
    let key = ProposerKey::from_ikm(&[2; 32], 1).unwrap();
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![SignedArtifact::BlockProof(proof).id()],
    };
    record.finality.proof_manifests = vec![manifest.clone()];
    record.finality.precommit_attestations = vec![key.attest_vote(
        ConsensusDomain::new(7, [9; 32]),
        FinalityVoteData {
            chunk_id: 0,
            round: 0,
            phase: FinalityVotePhase::Precommit,
            chunk_hash: record.chunk.hash(),
            selection: crate::bft_loop::fixture_selection(),
        },
        manifest.proof_hashes,
        None,
    )];
    let boundary = super::super::history::tests::boundary(0);
    let mut batch = Batch::new();
    store.append_history_batch(&mut batch, &record).unwrap();
    store
        .retain_reporter_finalization_batch(
            &mut batch,
            &record,
            &boundary,
            [first.clone(), second.clone()].into_iter(),
        )
        .unwrap();
    store.db_mut().write_batch_durable(batch).unwrap();
    store.put_latest_finalized_chunk_id(0).unwrap();
    let retained = store.reporter_storage_stats().unwrap();
    assert_eq!(retained.headers.records, 2);
    // The precommit accepted the canonical receipt, which the Chunk Guest
    // verified: no offence can cite it, so it is not copied.
    assert_eq!(retained.proof_dependencies.records, 0);
    // The only appended chunk has empty siblings: no subtree is kept.
    assert_eq!(retained.subtrees.records, 0);
    assert!(retained.contexts.bytes > 0);
    assert!(retained.signatures.records >= 2);
    assert_eq!(retained.signatures.bytes, retained.signatures.records * 96);
    // Each header belongs to its proposer: releasing the second proposer
    // keeps the first header for its independent, still-bonded proposer.
    store.set_reporter_eligible(&identities[..1], 1).unwrap();
    assert_eq!(store.reporter_header(&first.hash()).unwrap(), Some(first));
    assert!(store.reporter_header(&second.hash()).unwrap().is_none());
    let cleaned = store.reporter_storage_stats().unwrap();
    assert_eq!(cleaned.headers.records, 1);
    assert!(cleaned.cleaned_records > 0);
    assert!(cleaned.cleaned_bytes > 0);
    store.validate_reporter_history().unwrap();
}

fn proof_of(header: &Header) -> BlockProof {
    BlockProof {
        height: header.height,
        block_hash: header.hash(),
        public_inputs: BlockProofPublicInputs {
            context: Box::default(),
            chain_id: 7,
            height: header.height,
            parent_block_hash: header.parent_hash,
            block_hash: header.hash(),
            state_root_before: [0; 32],
            state_root_after: header.state_root,
            transactions_root: [0; 32],
            receipt_root: [0; 32],
            da_root: [0; 32],
            vm_code_hash: [0; 32],
            block_program: [0; 8],
            gas_used: 0,
            gas_limit: 1_000_000,
            proposer_address: [0; 32],
            runtime_extra: [0; 32],
            inputs_root: [0; 32],
        },
        prover_address: [0; 32],
        statement_key: [0; 32],
        proof_bytes: vec![1],
    }
}

#[test]
fn finalization_releases_a_copied_receipt_that_is_a_retained_canonical_one() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let record = super::super::history::tests::record(0);
    let header = crate::test_db::header(1, 1, [0; 32], [1; 32]);
    store.put_header(&header).unwrap();
    let proof = proof_of(&header);
    // A vote's dependency copied before finality; a different envelope of
    // the same block is not a retained receipt and stays.
    let copied = SignedArtifact::BlockProof(proof.clone());
    let mut other = proof.clone();
    other.proof_bytes = vec![2];
    let other = SignedArtifact::BlockProof(other);
    let mut batch = Batch::new();
    for source in [&copied, &other] {
        store
            .put_reporter_source_batch(&mut batch, 0, source.id(), source, &[[1; 48]])
            .unwrap();
    }
    store.db_mut().write_batch_durable(batch).unwrap();
    store
        .put_block_receipt(&proof, 1, 4, false, &BTreeSet::new())
        .unwrap();
    let mut batch = Batch::new();
    store
        .retain_reporter_finalization_batch(
            &mut batch,
            &record,
            &super::super::history::tests::boundary(0),
            core::iter::once(header),
        )
        .unwrap();
    store.db_mut().write_batch_durable(batch).unwrap();
    assert_eq!(store.reporter_sources_for_chunk(0).unwrap(), vec![other]);
}

#[test]
fn owners_staged_twice_in_one_batch_are_merged() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let first = crate::test_db::header(1, 1, [0; 32], [1; 32]);
    let second = crate::test_db::header(2, 2, first.hash(), [2; 32]);
    store.put_header(&first).unwrap();
    store.put_header(&second).unwrap();
    let (a, b): (BlsPublicKey, BlsPublicKey) = ([1; 48], [2; 48]);
    let later = SignedArtifact::BlockProof(proof_of(&second));
    let mut batch = Batch::new();
    // One vote's proof dependencies: `first` is both the parent of the
    // later proof's block and the block of the earlier proof, and the
    // later proof is accepted by both signers.
    for (proof, owner) in [
        (later.clone(), a),
        (SignedArtifact::BlockProof(proof_of(&first)), b),
        (later.clone(), b),
    ] {
        store
            .put_reporter_source_batch(&mut batch, 0, proof.id(), &proof, &[owner])
            .unwrap();
    }
    // Two withdrawal accounts of one identity staged by separate merges.
    for address in [[3; 32], [4; 32]] {
        store
            .merge_reporter_identities_batch(&mut batch, &[(a, address)])
            .unwrap();
    }
    store.db_mut().write_batch_durable(batch).unwrap();

    // Every merge saw the owners staged before it, not only stored ones.
    let header: Owned<Header> = store
        .get_decoded(Column::ReporterHeaders, &source_key(0, first.hash()))
        .unwrap()
        .unwrap();
    assert_eq!(header.owners, vec![a, b]);
    let source: Owned<SignedArtifact> = store
        .get_decoded(Column::ReporterSources, &source_key(0, later.id()))
        .unwrap()
        .unwrap();
    assert_eq!(source.owners, vec![a, b]);
    assert_eq!(
        store.reporter_tracked_validators().unwrap(),
        vec![(a, [3; 32]), (a, [4; 32])]
    );
}

#[test]
fn historical_withdrawal_addresses_survive_reseating_and_single_account_eligibility() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let key = [9; 48];
    let original = [10; 32];
    let replacement = [20; 32];
    store.set_reporter_eligible(&[(key, original)], 1).unwrap();
    for (id, address) in [(0, original), (1, replacement)] {
        let mut record = super::super::history::tests::record(id);
        record.validators = vec![bonded(key, address)];
        let mut batch = Batch::new();
        store.append_history_batch(&mut batch, &record).unwrap();
        store.db_mut().write_batch_durable(batch).unwrap();
        store.put_latest_finalized_chunk_id(id).unwrap();
    }
    // Old-account withdrawal followed by a new seat cannot overwrite the
    // old address: a new account never replaces an old account's accountability.
    let all = vec![(key, original), (key, replacement)];
    assert_eq!(store.reporter_tracked_validators().unwrap(), all);
    store
        .set_reporter_eligible(&[(key, replacement)], 1)
        .unwrap();
    assert_eq!(store.reporter_tracked_validators().unwrap(), all);
    assert!(store.reporter_opening(0).unwrap().is_some());
    let mut restarted = ChainStore::new(store.into_db());
    restarted
        .seed_reporter_tracking(&[(key, replacement), (key, original)])
        .unwrap();
    restarted
        .set_reporter_eligible(&[(key, original)], 1)
        .unwrap();
    assert_eq!(restarted.reporter_tracked_validators().unwrap(), all);
    assert_eq!(
        restarted.reporter_opening(0).unwrap().unwrap().path.count,
        2
    );
    restarted
        .set_reporter_eligible(
            &[(key, replacement), (key, original), (key, replacement)],
            1,
        )
        .unwrap();
    assert_eq!(restarted.reporter_tracked_validators().unwrap(), all);
    restarted.set_reporter_eligible(&[], 1).unwrap();
    assert_eq!(
        restarted.reporter_tracked_validators().unwrap(),
        [] as [crate::ReporterIdentity; 0]
    );
    assert!(!restarted.reporter_has_history().unwrap());
}

fn stored_subtrees(store: &ChainStore<MemoryDatabase>) -> BTreeMap<(u8, u64), Hash> {
    store
        .db
        .iter_prefix(Column::ReporterIndex, &[SUBTREE])
        .unwrap()
        .into_iter()
        .map(|(key, root)| {
            let start = u64::from_be_bytes(key[2..].try_into().unwrap());
            ((key[1], start), root.try_into().unwrap())
        })
        .collect()
}

/// The complete siblings of every watched chunk's verified current opening.
fn needed_subtrees(store: &ChainStore<MemoryDatabase>) -> BTreeMap<(u8, u64), Hash> {
    store
        .reporter_history_chunks()
        .unwrap()
        .into_iter()
        .flat_map(|chunk| {
            store
                .reporter_opening(chunk)
                .unwrap()
                .unwrap()
                .path
                .complete_siblings()
        })
        .map(|subtree| ((subtree.level, subtree.start), subtree.root))
        .collect()
}

#[test]
fn watched_chunks_keep_exactly_their_complete_siblings_and_release_only_unshared_ones() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let (a, b, address) = ([1; 48], [2; 48], [4; 32]);
    let owner = |id: u64| match id % 5 {
        0 | 3 => Some(a),
        1 => Some(b),
        _ => None,
    };
    for id in 0..37 {
        let mut record = super::super::history::tests::record(id);
        record.validators = vec![Validator {
            effective_stake: if owner(id).is_some() { 100 } else { 0 },
            ..bonded(owner(id).unwrap_or([3; 48]), address)
        }];
        let mut batch = Batch::new();
        store.append_history_batch(&mut batch, &record).unwrap();
        // An append rewrites no earlier watched chunk.
        assert!(batch.operations().iter().all(|op| !matches!(
            op,
            BatchOp::Put { column: Column::ReporterIndex, key, .. }
                if key[0] == CHUNK_LOOKUP && key[1..] != id.to_be_bytes()
        )));
        store.db_mut().write_batch_durable(batch).unwrap();
        store.put_latest_finalized_chunk_id(id).unwrap();
        assert_eq!(stored_subtrees(&store), needed_subtrees(&store));
    }
    let owned_by = |key| {
        (0..37)
            .filter(|id| owner(*id) == Some(key))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        store.reporter_history_chunks().unwrap(),
        (0..37)
            .filter(|id| owner(*id).is_some())
            .collect::<Vec<_>>()
    );
    store.set_reporter_eligible(&[(a, address)], 1).unwrap();
    assert_eq!(store.reporter_history_chunks().unwrap(), owned_by(a));
    assert_eq!(stored_subtrees(&store), needed_subtrees(&store));
    store.validate_reporter_history().unwrap();
    store.set_reporter_eligible(&[], 1).unwrap();
    assert!(stored_subtrees(&store).is_empty());
}

#[test]
fn an_owner_keeps_two_statements_per_step_and_lower_rounds_displace_the_highest() {
    use neutrin0_consensus_types::{RoundChange, RoundChangeCertificate};
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let mut batch = Batch::new();
    store
        .append_history_batch(&mut batch, &super::super::history::tests::record(0))
        .unwrap();
    store.db_mut().write_batch_durable(batch).unwrap();
    store.put_latest_finalized_chunk_id(0).unwrap();
    let report = |round: u32, tag: u8| RoundChange {
        chunk_id: 0,
        round,
        validator_index: 0,
        highest_quorum: None,
        signature: [tag; 96],
    };
    let retain = |store: &mut ChainStore<MemoryDatabase>, artifact: SignedArtifact| {
        store
            .retain_reporter_source_with(0, artifact.id(), &artifact, RetentionPolicy::Reporter)
            .unwrap();
    };
    let kept = |store: &ChainStore<MemoryDatabase>, artifact: SignedArtifact| {
        store.reporter_source(&artifact.id()).unwrap().is_some()
    };
    for tag in 1..=3 {
        retain(&mut store, SignedArtifact::RoundChange(report(1, tag)));
    }
    assert!(kept(&store, SignedArtifact::RoundChange(report(1, 1))));
    assert!(kept(&store, SignedArtifact::RoundChange(report(1, 2))));
    assert!(!kept(&store, SignedArtifact::RoundChange(report(1, 3))));
    // Re-bundling a kept statement retains nothing more for its owner.
    let certificate = SignedArtifact::RoundChangeCertificate(RoundChangeCertificate {
        chunk_id: 0,
        round: 1,
        reports: vec![report(1, 1)],
    });
    retain(&mut store, certificate.clone());
    assert!(!kept(&store, certificate));
    // 254 more fill the owner's 256 statements.
    for round in 10..264 {
        retain(&mut store, SignedArtifact::RoundChange(report(round, 0)));
    }
    retain(&mut store, SignedArtifact::RoundChange(report(1000, 0)));
    assert!(!kept(&store, SignedArtifact::RoundChange(report(1000, 0))));
    retain(&mut store, SignedArtifact::RoundChange(report(5, 0)));
    assert!(kept(&store, SignedArtifact::RoundChange(report(5, 0))));
    assert!(!kept(&store, SignedArtifact::RoundChange(report(263, 0))));
    assert!(kept(&store, SignedArtifact::RoundChange(report(262, 0))));
    store.validate_reporter_history().unwrap();
}
