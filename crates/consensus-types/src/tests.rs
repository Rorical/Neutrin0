use super::*;
use borsh::{from_slice, to_vec};
use neutrin0_primitives::{BitVec, BlsSignature};

fn hash(byte: u8) -> Hash {
    [byte; 32]
}

fn sig(byte: u8) -> BlsSignature {
    [byte; 96]
}

fn bit_vec() -> BitVec {
    let mut bits = BitVec::default();
    bits.push(true);
    bits.push(false);
    bits.push(true);
    bits
}

fn header() -> Header {
    Header {
        height: 7,
        slot: 9,
        parent_hash: hash(1),
        proposer_index: 2,
        vrf_proof: sig(3),
        state_root: hash(4),
        transactions_root: hash(5),
        votes_root: hash(6),
        da_root: hash(9),
        runtime_extra: hash(10),
        inputs_root: [0; 32],
        receipts_root: hash(15),
        gas_used: 11,
        gas_limit: 12,
        timestamp: 13,
        signature: sig(14),
    }
}

fn vote_data(phase: FinalityVotePhase) -> FinalityVoteData {
    FinalityVoteData {
        chunk_id: 3,
        round: 4,
        chunk_hash: hash(15),
        selection: [0; 32],
        phase,
    }
}

fn aggregated_vote(byte: u8) -> AggregatedVote {
    AggregatedVote {
        aggregation_bits: bit_vec(),
        signature: sig(byte),
    }
}

fn indexed_vote(phase: FinalityVotePhase) -> IndexedVote {
    IndexedVote {
        data: vote_data(phase),
        signature: sig(17),
    }
}

fn chunk() -> Chunk {
    Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id: 5,
        start_height: 6,
        end_height: 7,
        start_state_root: hash(24),
        end_state_root: hash(25),
        start_block_hash: hash(26),
        end_block_hash: hash(27),
        block_hash_root: hash(28),
        block_proof_root: hash(29),
        vrf_proof_root: hash(30),
        active_validator_set_root: hash(31),
        next_validator_set_root: hash(32),
        da_root: hash(33),
    }
}

#[test]
fn header_hash_excludes_signature() {
    let mut first = header();
    let mut second = first.clone();
    second.signature = sig(99);

    assert_eq!(first.hash(), second.hash());

    first.height += 1;
    assert_ne!(first.hash(), second.hash());
}

#[test]
fn block_round_trip_preserves_all_body_lanes() {
    let block = Block {
        header: header(),
        body: Body {
            transactions: vec![vec![1, 2, 3]],
            ..Body::default()
        },
    };

    let encoded = to_vec(&block).expect("block serializes");
    let decoded: Block = from_slice(&encoded).expect("block deserializes");

    assert_eq!(decoded, block);
    assert_eq!(decoded.hash(), decoded.header.hash());
}

#[test]
fn finality_certificate_rejects_oversized_shared_quorum_bitmap_before_payload() {
    let mut prefix = to_vec(&1_u32).unwrap(); // One dictionary certificate.
    prefix.extend(to_vec(&vote_data(FinalityVotePhase::Prevote)).unwrap());
    let bits = bft::MAX_BFT_SIGNERS + 1;
    prefix.extend(to_vec(&bits).unwrap());
    prefix.extend(to_vec(&bits.div_ceil(8)).unwrap());
    // No bitmap bytes follow: InvalidData proves bounded rejection happened
    // at its declaration, rather than an EOF after trusting the allocation.
    let error = from_slice::<FinalityCert>(&prefix).unwrap_err();
    assert_eq!(error.kind(), borsh::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("bitmap exceeds transport bound"));
}

#[test]
fn finality_cert_round_trips() {
    let cert = FinalityCert {
        proof_manifests: Vec::new(),
        proposal: BftProposal {
            chunk: chunk(),
            round: 42,
            proposer_index: 0,
            valid_quorum: None,
            round_change_certificate: None,
            proposal_slot: 0,
            receipts: Vec::new(),
            ratified_chunk_proofs: Vec::new(),
            signature: sig(47),
        },
        prevote_attestations: Vec::new(),
        precommit_attestations: Vec::new(),
        chunk_id: 41,
        round: 42,
        chunk_hash: hash(43),
        prevote: aggregated_vote(44),
        precommit: aggregated_vote(45),
        active_validator_set_root: hash(46),
    };

    let encoded = to_vec(&cert).expect("cert serializes");
    let decoded: FinalityCert = from_slice(&encoded).expect("cert deserializes");

    assert_eq!(decoded, cert);
}

#[test]
fn tagged_commitment_hashes_tag_then_borsh_bytes() {
    let value = (chunk(), Some(7_u32), vec![1_u8, 2]);
    let mut bytes = b"neutrin0/test".to_vec();
    bytes.extend(to_vec(&value).expect("value serializes"));
    assert_eq!(
        tagged_commitment(b"neutrin0/test", &value),
        blake3_256(&bytes)
    );
    let cert_votes = FinalityCert {
        proof_manifests: Vec::new(),
        proposal: BftProposal {
            chunk: chunk(),
            round: 2,
            proposer_index: 0,
            valid_quorum: None,
            round_change_certificate: None,
            proposal_slot: 0,
            receipts: Vec::new(),
            ratified_chunk_proofs: Vec::new(),
            signature: sig(1),
        },
        prevote_attestations: vec![test_attestation(None)],
        precommit_attestations: Vec::new(),
        chunk_id: 5,
        round: 2,
        chunk_hash: chunk().hash(),
        prevote: aggregated_vote(2),
        precommit: aggregated_vote(3),
        active_validator_set_root: hash(4),
    };
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        let vote = cert_votes.vote(phase);
        assert_eq!(vote.data, cert_votes.vote_data(phase));
        assert_eq!(vote.data.phase, phase);
    }
    assert_eq!(
        cert_votes.prevote_vote().attestations,
        cert_votes.prevote_attestations
    );
    assert_eq!(
        cert_votes.precommit_vote().signature,
        cert_votes.precommit.signature
    );
}

#[test]
fn chunk_hash_is_tagged_borsh_blake3() {
    let mut base = chunk();
    let mut tagged = neutrin0_primitives::DOMAIN_CHUNK.to_vec();
    tagged.extend(to_vec(&base).expect("chunk serializes"));
    let expected = blake3_256(&tagged);

    assert_eq!(base.hash(), expected);

    let original = base.hash();
    base.end_height += 1;
    assert_ne!(base.hash(), original);
}

fn test_attestation(unlock_quorum: Option<QuorumCertificate>) -> VoteAttestation {
    VoteAttestation {
        vote_signature: [0; 96],
        validator_index: 5,
        vote: vote_data(FinalityVotePhase::Precommit),
        proof_acceptance: Some(
            ProofManifest {
                proof_hashes: vec![[1; 32]],
            }
            .commitment(),
        ),
        unlock_quorum,
        signature: [2; 96],
    }
}

#[test]
fn slashing_evidence_variants_round_trip() {
    let quorum = QuorumCertificate {
        data: vote_data(FinalityVotePhase::Prevote),
        aggregate: aggregated_vote(47),
    };
    let variants = vec![
        SlashingEvidence::DoubleProposal {
            proposer_index: 1,
            header_a: header(),
            header_b: header(),
        },
        SlashingEvidence::DoublePrecommit {
            validator_index: 3,
            vote_a: indexed_vote(FinalityVotePhase::Precommit),
            vote_b: indexed_vote(FinalityVotePhase::Precommit),
        },
        SlashingEvidence::LockViolation {
            validator_index: 4,
            vote_a: indexed_vote(FinalityVotePhase::Prevote),
            vote_b: indexed_vote(FinalityVotePhase::Precommit),
            lock_evidence: LockEvidence {
                locked_prevote_quorum: quorum.clone(),
                attestation: test_attestation(Some(quorum)),
            },
        },
        SlashingEvidence::InvalidProofSigning {
            proof_opening: ProofAcceptanceOpening {
                index: 0,
                siblings: Vec::new(),
            },
            validator_index: 5,
            attestation: test_attestation(None),
            vote: indexed_vote(FinalityVotePhase::Precommit),
            rejected_proof: BlockProof {
                height: 9,
                block_hash: hash(48),
                public_inputs: BlockProofPublicInputs {
                    context: alloc::boxed::Box::default(),
                    chain_id: 1,
                    height: 9,
                    parent_block_hash: hash(50),
                    block_hash: hash(48),
                    state_root_before: hash(51),
                    state_root_after: hash(52),
                    transactions_root: hash(53),
                    receipt_root: hash(54),
                    da_root: hash(55),
                    vm_code_hash: hash(56),
                    block_program: [56; 8],
                    gas_used: 0,
                    gas_limit: 1_000_000,
                    proposer_address: [0u8; 32],
                    runtime_extra: hash(57),
                    inputs_root: [0; 32],
                },
                prover_address: [0; 32],
                statement_key: [0; 32],
                proof_bytes: vec![0xFF; 8],
            },
            reason: ProofRejectionReason::PublicInputsMismatch,
        },
        SlashingEvidence::DaCommitmentFraud {
            proposer_index: 7,
            header: header(),
            fraud_proof: DaFraudProof {
                publication_signature: [0; 96],
                expected_da_root: hash(51),
                computed_da_root: hash(52),
                bundle_hash: hash(53),
                offending_bundle: vec![54, 55],
            },
        },
    ];

    for evidence in variants {
        let encoded = to_vec(&evidence).expect("evidence serializes");
        let decoded: SlashingEvidence = from_slice(&encoded).expect("evidence deserializes");
        assert_eq!(decoded, evidence);
    }
}

#[test]
fn proof_artifact_wrappers_round_trip() {
    let block_inputs = BlockProofPublicInputs {
        context: alloc::boxed::Box::default(),
        chain_id: 1,
        height: 2,
        parent_block_hash: hash(56),
        block_hash: hash(57),
        state_root_before: hash(58),
        state_root_after: hash(59),
        transactions_root: hash(60),
        receipt_root: hash(61),
        da_root: hash(62),
        vm_code_hash: hash(63),
        block_program: [63; 8],
        gas_used: 0,
        gas_limit: 1_000_000,
        proposer_address: [0u8; 32],
        runtime_extra: hash(64),
        inputs_root: [0; 32],
    };
    let block_proof = BlockProof {
        prover_address: block_inputs.proposer_address,
        statement_key: [0; 32],
        height: block_inputs.height,
        block_hash: block_inputs.block_hash,
        public_inputs: block_inputs,
        proof_bytes: vec![64, 65],
    };
    let chunk_inputs = ChunkProofPublicInputs {
        next_identity_sanctions_root: [0; 32],

        chunk_id: 3,
        start_height: 4,
        end_height: 5,
        start_state_root: hash(66),
        end_state_root: hash(67),
        start_block_hash: hash(68),
        end_block_hash: hash(69),
        block_hash_root: hash(70),
        block_proof_root: hash(71),
        vrf_proof_root: hash(72),
        active_validator_set_root: hash(73),
        next_validator_set_root: hash(74),
        da_root: hash(75),
    };
    let chunk_proof = ChunkProof {
        finality_cert: FinalityCert {
            proof_manifests: Vec::new(),
            proposal: BftProposal {
                chunk: chunk(),
                round: 0,
                proposer_index: 0,
                valid_quorum: None,
                round_change_certificate: None,
                proposal_slot: 0,
                receipts: Vec::new(),
                ratified_chunk_proofs: Vec::new(),
                signature: sig(47),
            },
            prevote_attestations: Vec::new(),
            precommit_attestations: Vec::new(),
            chunk_id: 3,
            round: 0,
            chunk_hash: chunk().hash(),
            prevote: aggregated_vote(44),
            precommit: aggregated_vote(45),
            active_validator_set_root: hash(73),
        },
        chunk_id: chunk_inputs.chunk_id,
        chunk_hash: chunk().hash(),
        public_inputs: chunk_inputs,
        prover_address: [0; 32],
        proof_bytes: vec![76, 77],
    };
    let encoded = to_vec(&(block_proof.clone(), chunk_proof.clone())).expect("proofs serialize");
    let decoded: (BlockProof, ChunkProof) = from_slice(&encoded).expect("proofs deserialize");
    assert_eq!(decoded.0, block_proof);
    assert_eq!(decoded.1, chunk_proof);
}
