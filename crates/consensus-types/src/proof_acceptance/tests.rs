use super::*;
use crate::{FinalityVoteData, FinalityVotePhase};

fn claim(manifest: Option<&ProofManifest>) -> VoteAttestation {
    VoteAttestation {
        validator_index: 0,
        vote: FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: [1; 32],
            selection: [0; 32],
            phase: FinalityVotePhase::Precommit,
        },
        vote_signature: [0; 96],
        proof_acceptance: manifest.map(ProofManifest::commitment),
        unlock_quorum: None,
        signature: [0; 96],
    }
}

#[test]
fn counted_positional_openings_reject_substitution_and_noncanonical_padding() {
    for count in [1, 2, 3, 5, 16] {
        let manifest = ProofManifest {
            proof_hashes: (0..count).map(|index| [index; 32]).collect(),
        };
        let commitment = manifest.commitment();
        for index in 0..count {
            let opening = manifest.opening(u64::from(index)).unwrap();
            assert!(commitment.verify(&[index; 32], &opening));
            let mut wrong = commitment;
            wrong.count += 1;
            assert!(!wrong.verify(&[index; 32], &opening));
            wrong = commitment;
            wrong.root[0] ^= 1;
            assert!(!wrong.verify(&[index; 32], &opening));
            let mut altered = opening.clone();
            altered.index = commitment.count;
            assert!(!commitment.verify(&[index; 32], &altered));
            altered = opening.clone();
            altered.siblings.push([0; 32]);
            assert!(!commitment.verify(&[index; 32], &altered));
            if !opening.siblings.is_empty() {
                altered = opening;
                altered.siblings[0][0] ^= 1;
                assert!(!commitment.verify(&[index; 32], &altered));
            }
        }
        assert!(manifest.opening(u64::from(count)).is_none());
    }
    let manifest = ProofManifest {
        proof_hashes: alloc::vec![[1; 32], [2; 32], [3; 32]],
    };
    let mut opening = manifest.opening(2).unwrap();
    opening.siblings[0] = [9; 32];
    // Even a root recomputed to match this path cannot bless a noncanonical
    // padding leaf. A path alone makes no availability claim for real siblings.
    let tree = parent(&opening.siblings[1], &parent(&leaf(2, &[3; 32]), &[9; 32]));
    let forged = ProofAcceptanceCommitment {
        count: 3,
        root: counted(3, &tree),
    };
    assert!(!forged.verify(&[3; 32], &opening));
    for count in [0, MAX_CONSENSUS_COMMITTEE_BLOCKS + 1, u64::MAX] {
        assert!(
            !ProofAcceptanceCommitment {
                count,
                root: [0; 32]
            }
            .verify(
                &[0; 32],
                &ProofAcceptanceOpening {
                    index: 0,
                    siblings: Vec::new()
                }
            )
        );
    }
}

#[test]
fn dictionaries_are_exact_unique_and_ordered_for_heterogeneous_receipts() {
    let first = ProofManifest {
        proof_hashes: alloc::vec![[1; 32], [2; 32]],
    };
    let second = ProofManifest {
        proof_hashes: alloc::vec![[1; 32], [3; 32]],
    };
    let claims = [claim(Some(&first)), claim(Some(&second))];
    let mut manifests = alloc::vec![first.clone(), second.clone()];
    manifests.sort_by_key(ProofManifest::commitment);
    assert!(proof_manifests_valid(&claims, &manifests));
    let index = ProofManifestIndex::new(&manifests).unwrap();
    assert_eq!(index.get(&first.commitment()), Some(&first));
    assert!(!proof_manifests_valid(&claims, &manifests[..1]));
    assert!(!proof_manifests_valid(&claims[..1], &manifests));
    assert!(!proof_manifests_valid(
        &claims,
        &[first.clone(), first.clone()]
    ));
    manifests.reverse();
    assert!(!proof_manifests_valid(&claims, &manifests));
    let selected = proof_manifests_for(
        &claims,
        [
            core::slice::from_ref(&second),
            core::slice::from_ref(&first),
        ],
    )
    .unwrap();
    assert!(proof_manifests_valid(&claims, &selected));
    assert_eq!(
        proof_manifests_for(&claims[..1], [selected.as_slice()]).unwrap(),
        [first]
    );
    assert!(proof_manifests_valid(&[claim(None)], &[]));
    assert!(!proof_manifests_valid(
        &claims,
        &[ProofManifest {
            proof_hashes: Vec::new()
        }]
    ));
}

#[test]
fn decoders_and_validation_bound_total_hashes_before_large_allocations() {
    use borsh::to_vec;
    let mut header = to_vec(&257_u32).unwrap();
    assert!(read_manifests(&mut header.as_slice()).is_err());
    header = to_vec(&u32::try_from(MAX_CONSENSUS_COMMITTEE_BLOCKS + 1).unwrap()).unwrap();
    assert!(ProofManifest::deserialize_reader(&mut header.as_slice()).is_err());
    let largest = ProofManifest {
        proof_hashes: alloc::vec![[1; 32]; usize::try_from(MAX_CONSENSUS_COMMITTEE_BLOCKS).unwrap()],
    };
    let claims = [claim(Some(&largest))];
    assert!(proof_manifests_valid(
        &claims,
        core::slice::from_ref(&largest)
    ));
    let other = ProofManifest {
        proof_hashes: alloc::vec![[2; 32]],
    };
    let mut manifests = alloc::vec![largest, other.clone()];
    manifests.sort_by_key(ProofManifest::commitment);
    assert!(!proof_manifests_valid(
        &[claims[0].clone(), claim(Some(&other))],
        &manifests
    ));
    let bytes = to_vec(&manifests).unwrap();
    assert!(read_manifests(&mut bytes.as_slice()).is_err());
    let too_deep = ProofAcceptanceOpening {
        index: 0,
        siblings: alloc::vec![[0; 32]; 15],
    };
    assert!(borsh::from_slice::<ProofAcceptanceOpening>(&to_vec(&too_deep).unwrap()).is_err());
}
