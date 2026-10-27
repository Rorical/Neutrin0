use super::*;
use crate::{ChainStore, ProposerKey, RetentionPolicy, test_db::FaultDb};
use neutrin0_consensus_types::{
    FinalityVoteData, FinalityVotePhase, NilVote, NilVoteAttestation, NilVoteData,
};
use neutrin0_primitives::{BitVec, ConsensusDomain};

const DOMAIN: ConsensusDomain = ConsensusDomain::new(7, [9; 32]);
use neutrin0_storage::{Database, MemoryDatabase};

fn nil(round: u32) -> SignedArtifact {
    nil_for_chunk(0, round)
}
fn nil_for_chunk(chunk_id: ChunkId, round: u32) -> SignedArtifact {
    let key = ProposerKey::from_ikm(&[1; 32], 0).unwrap();
    let data = NilVoteData {
        chunk_id,
        round,
        phase: FinalityVotePhase::Prevote,
    };
    let signature = key.sign_raw(&data.signing_message(DOMAIN)).to_bytes();
    let mut claim = NilVoteAttestation {
        validator_index: 0,
        vote: data.clone(),
        vote_signature: signature,
        signature: [0; 96],
    };
    claim.signature = key.sign_raw(&claim.signing_message(DOMAIN)).to_bytes();
    SignedArtifact::NilVote(NilVote {
        data,
        aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
        signature,
        attestations: vec![claim],
    })
}
fn precommit(round: u32) -> SignedArtifact {
    let key = ProposerKey::from_ikm(&[1; 32], 0).unwrap();
    let data = FinalityVoteData {
        chunk_id: 0,
        round,
        phase: FinalityVotePhase::Precommit,
        chunk_hash: [u8::try_from(round).unwrap(); 32],
        selection: crate::bft_loop::fixture_selection(),
    };
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![[9; 32]],
    };
    let claim = key.attest_vote(DOMAIN, data.clone(), manifest.proof_hashes.clone(), None);
    SignedArtifact::Vote(neutrin0_consensus_types::FinalityVote {
        proof_manifests: vec![manifest],
        signature: key.sign_finality_vote(DOMAIN, &data),
        data,
        aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
        attestations: vec![claim],
    })
}

#[test]
fn shared_manifest_dependencies_preserve_distinct_receipts_and_reject_missing_lists() {
    use neutrin0_consensus_types::{FinalityVote, ProofManifest};
    let first = ProofManifest {
        proof_hashes: vec![[9; 32], [10; 32]],
    };
    let second = ProofManifest {
        proof_hashes: vec![[9; 32], [11; 32]],
    };
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 0,
        phase: FinalityVotePhase::Precommit,
        chunk_hash: [1; 32],
        selection: crate::bft_loop::fixture_selection(),
    };
    let keys = [
        ProposerKey::from_ikm(&[1; 32], 0).unwrap(),
        ProposerKey::from_ikm(&[2; 32], 1).unwrap(),
    ];
    let manifests = [first, second];
    let claims: Vec<_> = keys
        .iter()
        .zip(&manifests)
        .map(|(key, manifest)| {
            key.attest_vote(DOMAIN, data.clone(), manifest.proof_hashes.clone(), None)
        })
        .collect();
    let signatures: Vec<_> = keys
        .iter()
        .map(|key| {
            neutrin0_crypto::bls::Signature::from_bytes(&key.sign_finality_vote(DOMAIN, &data))
                .unwrap()
        })
        .collect();
    let mut dictionary = manifests.to_vec();
    dictionary.sort_by_key(ProofManifest::commitment);
    let vote = FinalityVote {
        data,
        aggregation_bits: BitVec::from_bytes(2, vec![3]).unwrap(),
        signature: neutrin0_crypto::bls::aggregate_signatures(
            &signatures.iter().collect::<Vec<_>>(),
        )
        .unwrap()
        .to_bytes(),
        attestations: claims,
        proof_manifests: dictionary,
    };
    let source = SignedArtifact::Vote(vote.clone());
    let mut store = ChainStore::new(MemoryDatabase::new());
    let id = store.put_signed_artifact(0, &source).unwrap();
    let metadata = store.signed_artifact_metadata_by_id(&id).unwrap().unwrap();
    assert_eq!(metadata.proof_hashes, vec![[9; 32], [10; 32], [11; 32]]);
    assert_eq!(store.signed_artifact(&id).unwrap().unwrap().1, source);
    let mut invalid = vote;
    invalid.proof_manifests.pop();
    let invalid = SignedArtifact::Vote(invalid);
    assert!(store.put_signed_artifact(0, &invalid).is_err());
    assert!(store.signed_artifact(&invalid.id()).unwrap().is_none());
    assert_eq!(
        store
            .signed_artifact_metadata_by_id(&id)
            .unwrap()
            .unwrap()
            .proof_hashes,
        metadata.proof_hashes
    );
}

#[test]
fn a_replaced_accepted_receipt_stays_addressable_as_its_exact_source() {
    use neutrin0_consensus_types::{BlockProof, BlockProofPublicInputs};
    const PROPOSER: Hash = [0xA1; 32];
    let block_hash = [7; 32];
    let receipt = |prover_address: Hash, key: u8| BlockProof {
        height: 1,
        block_hash,
        public_inputs: BlockProofPublicInputs {
            context: Box::default(),
            chain_id: 1,
            height: 1,
            parent_block_hash: [0; 32],
            block_hash,
            state_root_before: [0; 32],
            state_root_after: [0; 32],
            transactions_root: [0; 32],
            receipt_root: [0; 32],
            da_root: [0; 32],
            vm_code_hash: [0; 32],
            block_program: [0; 8],
            gas_used: 0,
            gas_limit: 1,
            proposer_address: PROPOSER,
            runtime_extra: [0; 32],
            inputs_root: [0; 32],
        },
        proof_bytes: vec![key; 64],
        prover_address,
        statement_key: [key; 32],
    };
    let foreign = receipt([0xB2; 32], 1);
    let source = SignedArtifact::BlockProof(foreign.clone());
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .put_block_receipt(&foreign, 1, 4, true, &std::collections::BTreeSet::new())
        .unwrap();
    let id = store.put_signed_artifact(0, &source).unwrap();
    store.compact_accepted_artifact(&foreign).unwrap();
    let stored = |store: &ChainStore<MemoryDatabase>| -> StoredArtifact {
        borsh::from_slice(&store.db.get(Column::SignedArtifacts, &id).unwrap().unwrap()).unwrap()
    };
    // While BlockProofs holds the accepted bytes, the row is a pointer.
    assert!(matches!(
        stored(&store).payload,
        StoredPayload::AcceptedBlockProof(hash) if hash == block_hash
    ));
    assert_eq!(store.signed_artifact(&id).unwrap().unwrap().1, source);

    // The proposer's receipt replaces it as the accepted proof; the
    // pointer becomes the exact source again in the same batch.
    let own = receipt(PROPOSER, 2);
    store
        .put_block_receipt(&own, 2, 4, true, &std::collections::BTreeSet::new())
        .unwrap();
    assert_eq!(store.get_block_proof(&block_hash).unwrap(), Some(own));
    assert!(matches!(stored(&store).payload, StoredPayload::Source(_)));
    assert_eq!(store.signed_artifact(&id).unwrap().unwrap().1, source);
    assert_eq!(
        store
            .signed_artifact_metadata_by_id(&id)
            .unwrap()
            .unwrap()
            .storage_bytes,
        u64::try_from(borsh::to_vec(&stored(&store)).unwrap().len()).unwrap()
    );
}

#[test]
fn a_named_receipt_survives_the_cap_when_the_proposer_receipt_arrives() {
    use neutrin0_consensus_types::{BlockProof, BlockProofPublicInputs};
    const PROPOSER: Hash = [0xA1; 32];
    let block_hash = [7; 32];
    let receipt = |prover_address: Hash, key: u8| BlockProof {
        height: 1,
        block_hash,
        public_inputs: BlockProofPublicInputs {
            context: Box::default(),
            chain_id: 1,
            height: 1,
            parent_block_hash: [0; 32],
            block_hash,
            state_root_before: [0; 32],
            state_root_after: [0; 32],
            transactions_root: [0; 32],
            receipt_root: [0; 32],
            da_root: [0; 32],
            vm_code_hash: [0; 32],
            block_program: [0; 8],
            gas_used: 0,
            gas_limit: 1,
            proposer_address: PROPOSER,
            runtime_extra: [0; 32],
            inputs_root: [0; 32],
        },
        proof_bytes: vec![key; 64],
        prover_address,
        statement_key: [key; 32],
    };
    let mut store = ChainStore::new(MemoryDatabase::new());
    let none = std::collections::BTreeSet::new();
    // Four third-party receipts fill the cap; the last is what a
    // proposal names.
    for key in 1..=4 {
        store
            .put_block_receipt(
                &receipt([0xB0 + key; 32], key),
                u64::from(key),
                4,
                true,
                &none,
            )
            .unwrap();
    }
    let named = std::collections::BTreeSet::from([[4; 32]]);
    // The proposer's receipt arrives late; the named one stays and an
    // unnamed one leaves instead.
    store
        .put_block_receipt(&receipt(PROPOSER, 9), 5, 4, true, &named)
        .unwrap();
    let mut held: Vec<_> = store
        .block_receipts(&block_hash)
        .unwrap()
        .into_iter()
        .map(|held| held.proof.statement_key[0])
        .collect();
    held.sort_unstable();
    assert_eq!(held, [1, 2, 4, 9]);
    // A named receipt fetched after the cap is full is still kept.
    store
        .put_block_receipt(&receipt([0xC0; 32], 3), 6, 4, true, &[[3; 32]].into())
        .unwrap();
    assert!(
        store
            .block_receipts(&block_hash)
            .unwrap()
            .iter()
            .any(|held| held.proof.statement_key == [3; 32])
    );
}

#[test]
fn protected_rolling_local_slots_keep_lock_and_survive_many_unfinalized_rounds() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    for round in 0..300 {
        store
            .put_local_signed_artifact_protected(0, &nil(round), &[])
            .unwrap();
    }
    assert_eq!(store.signed_artifact_metadata().unwrap().len(), 1);
    let locked = precommit(0);
    store
        .put_local_signed_artifact_protected(0, &locked, &[])
        .unwrap();
    store
        .put_local_signed_artifact_protected(0, &precommit(1), &[locked.id()])
        .unwrap();
    store
        .put_local_signed_artifact_protected(0, &precommit(2), &[locked.id()])
        .unwrap();
    assert!(store.signed_artifact(&locked.id()).unwrap().is_some());
    assert!(store.signed_artifact(&precommit(1).id()).unwrap().is_none());
    assert!(store.signed_artifact(&precommit(2).id()).unwrap().is_some());
    let reopened = ChainStore::new(store.into_db());
    assert_eq!(
        reopened.signed_artifact(&locked.id()).unwrap().unwrap().1,
        locked
    );
}

#[test]
fn failed_durable_slot_replacement_preserves_old_source_and_index() {
    let mut store = ChainStore::new(FaultDb::default());
    let old = nil(0);
    store
        .put_local_signed_artifact_protected(0, &old, &[])
        .unwrap();
    store.db_mut().fail_durable_after = Some(0);
    assert!(
        store
            .put_local_signed_artifact_protected(0, &nil(1), &[])
            .is_err()
    );
    let reopened = ChainStore::new(store.into_db());
    assert_eq!(reopened.signed_artifact(&old.id()).unwrap().unwrap().1, old);
    assert!(reopened.signed_artifact(&nil(1).id()).unwrap().is_none());
    assert_eq!(
        reopened
            .signed_artifact_inventory(0, None)
            .unwrap()
            .entries
            .len(),
        1
    );
}

#[test]
fn peer_record_capacity_preserves_local_publication_and_rolling_slots() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let mut batch = Batch::new();
    // Populate checked rows directly: this regression exercises admission
    // accounting without thousands of repeated full-index scans.
    for round in 0..MAX_PEER_SIGNED_ARTIFACTS {
        let artifact = nil(u32::try_from(round).unwrap());
        let id = artifact.id();
        let bytes = borsh::to_vec(&StoredArtifact {
            chunk_id: 0,
            payload: StoredPayload::Source(Box::new(artifact.clone())),
        })
        .unwrap();
        let mut metadata = SignedArtifactMetadata::for_artifact(0, id, &artifact).unwrap();
        metadata.storage_bytes = u64::try_from(bytes.len()).unwrap();
        batch.put(Column::SignedArtifacts, id, bytes);
        put_metadata(&mut batch, &metadata).unwrap();
    }
    store.db_mut().write_batch_durable(batch).unwrap();
    let latest = nil(4000);
    assert!(store.put_signed_artifact(0, &latest).is_err());
    store
        .put_local_signed_artifact_protected(0, &latest, &[])
        .unwrap();
    let next = nil(4001);
    store
        .put_local_signed_artifact_protected(0, &next, &[])
        .unwrap();
    assert!(store.signed_artifact(&latest.id()).unwrap().is_none());
    assert_eq!(store.signed_artifact(&next.id()).unwrap().unwrap().1, next);
    assert_eq!(
        store.signed_artifact_metadata().unwrap().len(),
        MAX_PEER_SIGNED_ARTIFACTS + 1
    );
}

#[test]
fn full_peer_capacity_never_consumes_local_capacity() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let mut batch = Batch::new();
    // Peer junk fills its share, and this node already holds 256 local
    // records beyond it.
    for (round, local) in (0..MAX_PEER_SIGNED_ARTIFACTS + 256)
        .map(|round| (round, round >= MAX_PEER_SIGNED_ARTIFACTS))
    {
        let artifact = nil(u32::try_from(round).unwrap());
        let id = artifact.id();
        let bytes = borsh::to_vec(&StoredArtifact {
            chunk_id: 0,
            payload: StoredPayload::Source(Box::new(artifact.clone())),
        })
        .unwrap();
        let mut metadata = SignedArtifactMetadata::for_artifact(0, id, &artifact).unwrap();
        metadata.storage_bytes = u64::try_from(bytes.len()).unwrap();
        metadata.local = local;
        batch.put(Column::SignedArtifacts, id, bytes);
        put_metadata(&mut batch, &metadata).unwrap();
    }
    store.db_mut().write_batch_durable(batch).unwrap();
    assert!(store.put_signed_artifact(0, &nil(9000)).is_err());
    let own = nil_for_chunk(1, 0);
    store.put_local_signed_artifact(1, &own).unwrap();
    assert_eq!(store.signed_artifact(&own.id()).unwrap().unwrap().1, own);
}

#[test]
fn a_published_peer_record_stays_peer_when_local_capacity_is_full() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let peer = nil_for_chunk(0, 9000);
    store.put_signed_artifact(0, &peer).unwrap();
    let mut batch = Batch::new();
    for round in 0..MAX_LOCAL_SIGNED_ARTIFACTS {
        let artifact = nil(u32::try_from(round).unwrap());
        let id = artifact.id();
        let mut metadata = SignedArtifactMetadata::for_artifact(0, id, &artifact).unwrap();
        metadata.local = true;
        put_metadata(&mut batch, &metadata).unwrap();
    }
    store.db_mut().write_batch_durable(batch).unwrap();
    // Publishing it again cannot lift the local budget past its bound.
    store.put_local_signed_artifact(0, &peer).unwrap();
    let metadata = store
        .signed_artifact_metadata_by_id(&peer.id())
        .unwrap()
        .unwrap();
    assert!(!metadata.local);
}

#[test]
fn archive_preserves_superseded_local_round_sources() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    for round in 0..40 {
        store
            .put_local_signed_artifact_protected(0, &nil(round), &[])
            .unwrap();
    }
    let first = store.signed_artifact_inventory(0, None).unwrap();
    assert_eq!(first.entries.len(), 32);
    let second = store.signed_artifact_inventory(0, first.next).unwrap();
    assert_eq!(second.entries.len(), 8);
    assert!(second.next.is_none());
    store.prune_signed_artifacts(u64::MAX).unwrap();
    assert_eq!(store.signed_artifact_metadata().unwrap().len(), 40);
}

#[test]
fn unpruned_old_rows_never_gate_live_publication() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let mut batch = Batch::new();
    for chunk in 0..30 {
        for round in 0..144 {
            let artifact = nil_for_chunk(chunk, round);
            let id = artifact.id();
            let bytes = borsh::to_vec(&StoredArtifact {
                chunk_id: chunk,
                payload: StoredPayload::Source(Box::new(artifact.clone())),
            })
            .unwrap();
            let mut metadata = SignedArtifactMetadata::for_artifact(chunk, id, &artifact).unwrap();
            metadata.storage_bytes = u64::try_from(bytes.len()).unwrap();
            batch.put(Column::SignedArtifacts, id, bytes);
            put_metadata(&mut batch, &metadata).unwrap();
        }
    }
    store.db_mut().write_batch_durable(batch).unwrap();
    store.put_latest_finalized_chunk_id(29).unwrap();
    store.prune_signed_artifacts(0).unwrap();
    assert!(store.signed_artifact_metadata().unwrap().len() > MAX_PEER_SIGNED_ARTIFACTS);
    let current = nil_for_chunk(30, 0);
    store
        .put_local_signed_artifact_protected(30, &current, &[])
        .unwrap();
    assert_eq!(
        store.signed_artifact(&current.id()).unwrap().unwrap().1,
        current
    );
    assert_eq!(
        store.signed_artifact_metadata_for_chunk(0).unwrap().len(),
        144
    );
    assert_eq!(
        store.active_signed_artifact_metadata().unwrap().len(),
        8 * 144 + 1
    );
    let reopened = ChainStore::new(store.into_db());
    assert_eq!(
        reopened
            .signed_artifact_metadata_for_chunk(0)
            .unwrap()
            .len(),
        144
    );
}
