//! Historical membership, objective evidence and canonical offence identities.
pub mod support;

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{
    Body, FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
};
use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::{BitVec, ChainSpec};
use neutrin0_prover_chunk::evidence::{EvidenceClaim, EvidenceWitness, validate_evidence};
use neutrin0_prover_chunk::{
    consensus::{as_chunk, validate_consensus},
    history::{HistoricalChunk, HistoricalContext, HistoryError, HistoryWitness},
};

fn test_domain() -> neutrin0_primitives::ConsensusDomain {
    support::fixture([1; 8], [4; 32])
        .0
        .chain_spec
        .consensus_domain()
}

fn fixture_with_source() -> (ChainSpec, HistoryWitness, HistoricalChunk) {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let proven = validate_consensus(&input).unwrap();
    let record = HistoricalChunk {
        runtime_code_hash: input.context.programs.runtime_code_hash,
        block_guest_vk_digest: input.context.programs.execution.block,
        start_boundary: proven.start.commitment(),
        chunk: as_chunk(&proven.chunk),
        validators: input.context.active_validators,
        seed: input.seed,
        finality: input.finality_cert,
    };
    let history = HistoryWitness::from_history(core::slice::from_ref(&record), &[0]).unwrap();
    (input.chain_spec, history, record)
}

fn fixture() -> (ChainSpec, HistoryWitness) {
    let (spec, history, _) = fixture_with_source();
    (spec, history)
}

/// `spec`'s successor, forking at chunk 1 after `end` from the specification
/// hashed `predecessor`.
fn forked_spec(
    spec: &ChainSpec,
    end: &neutrin0_consensus_types::history_proof::ConsensusBoundary,
    predecessor: [u8; 32],
) -> ChainSpec {
    let mut forked = spec.clone();
    forked.genesis_chunk = [8; 8];
    let start =
        neutrin0_consensus_types::history_proof::ConsensusBoundary::fork_start(end, &forked);
    forked.fork = Some(Box::new(neutrin0_primitives::ForkAnchor {
        predecessor,
        count: 1,
        endpoint_programs: end.programs,
        start,
        endpoint_prover: support::credentials(7),
        prior_domains: vec![neutrin0_primitives::PriorDomain {
            chain_spec_hash: predecessor,
            end_chunk: 1,
            end_height: spec.consensus.chunk_size,
        }],
    }));
    forked.validate().unwrap();
    // The specification pins the predecessor's endpoint whole, ending at the
    // fork governance scheduled for the successor's programs.
    assert_eq!(
        forked.fork_endpoint(),
        Some(neutrin0_consensus_types::history_proof::ConsensusBoundary {
            fork: Some(neutrin0_primitives::ScheduledFork {
                count: 1,
                successor: forked.pinned_programs().commitment(),
            }),
            ..*end
        })
    );
    forked
}

fn double_vote() -> SlashingEvidence {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let sign = |hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash: [hash; 32],
            selection: [0; 32],
            phase: FinalityVotePhase::Precommit,
        };
        let message = data.signing_message(test_domain());
        IndexedVote {
            data,
            signature: key.sign(&message).to_bytes(),
        }
    };
    SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(1),
        vote_b: sign(2),
    }
}

#[test]
fn nil_value_equivocation_is_objective_and_shares_the_phase_penalty_identity() {
    use neutrin0_consensus_types::{IndexedNilVote, NilVoteData};
    let (spec, _, source) = fixture_with_source();
    let SlashingEvidence::DoublePrecommit {
        validator_index,
        vote_a,
        ..
    } = double_vote()
    else {
        unreachable!()
    };
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let data = NilVoteData {
        chunk_id: vote_a.data.chunk_id,
        round: vote_a.data.round,
        phase: vote_a.data.phase,
    };
    let nil = IndexedNilVote {
        signature: key
            .sign(&data.signing_message(spec.consensus_domain()))
            .to_bytes(),
        data,
    };
    let evidence = SlashingEvidence::ConflictingNilVote {
        validator_index,
        value_vote: vote_a,
        nil_vote: nil,
    };
    let statement = validate_evidence(&EvidenceWitness {
        reporter: None,
        chain_spec: spec.clone(),
        source: source.clone(),
        claim: EvidenceClaim::Slash(evidence.clone()),
        block_guest_vk_digest: [1; 8],
    })
    .unwrap();
    let double = validate_evidence(&EvidenceWitness {
        reporter: None,
        chain_spec: spec.clone(),
        source: source.clone(),
        claim: EvidenceClaim::Slash(double_vote()),
        block_guest_vk_digest: [1; 8],
    })
    .unwrap();
    assert_eq!(statement.offence_id, double.offence_id);
    let mut bad = evidence;
    if let SlashingEvidence::ConflictingNilVote { nil_vote, .. } = &mut bad {
        nil_vote.data.phase = FinalityVotePhase::Prevote;
        nil_vote.signature = key
            .sign(&nil_vote.data.signing_message(spec.consensus_domain()))
            .to_bytes();
    }
    assert_eq!(
        validate_evidence(&EvidenceWitness {
            reporter: None,
            chain_spec: spec,
            source,
            claim: EvidenceClaim::Slash(bad),
            block_guest_vk_digest: [1; 8]
        }),
        Err(HistoryError::Evidence)
    );
}

#[test]
fn leader_equivocation_has_proven_facts_even_with_an_invalid_carried_quorum() {
    use neutrin0_prover_chunk::{
        evidence::{EvidenceBatchWitness, validate_evidence_batch, validate_evidence_using},
        facts::{FactRecorder, FactStatement, FactWitness, ProvenFact, validate_facts},
    };
    let (spec, _, source) = fixture_with_source();
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let first = source.finality.proposal.clone();
    let mut second = first.clone();
    second.chunk.end_state_root[0] ^= 1;
    // The leader cannot evade fork accountability by attaching nonsense QC data.
    second.valid_quorum = Some(neutrin0_consensus_types::QuorumCertificate {
        data: source.finality.prevote_vote().data,
        aggregate: source.finality.prevote.clone(),
    });
    second.signature = key
        .sign(&second.signing_message(spec.consensus_domain()))
        .to_bytes();
    let witness = EvidenceWitness {
        reporter: None,
        chain_spec: spec,
        source,
        claim: EvidenceClaim::Slash(SlashingEvidence::DoubleBftProposal {
            proposer_index: 0,
            proposal_a: first,
            proposal_b: second,
        }),
        block_guest_vk_digest: [1; 8],
    };
    let mut recorder = FactRecorder::default();
    let expected = validate_evidence_using(&witness, &mut recorder).unwrap();
    let checks = recorder.finish().unwrap();
    assert_eq!(checks.len(), 2);
    let fact = FactWitness {
        requests: checks.iter().map(|(request, _)| request.clone()).collect(),
        statement: FactStatement {
            facts: checks
                .iter()
                .map(|(request, valid)| ProvenFact {
                    id: request.id(),
                    valid: *valid,
                })
                .collect(),
        },
    };
    assert_eq!(validate_facts(&fact).unwrap(), fact.statement);
    let (_, statements) = validate_evidence_batch(&EvidenceBatchWitness {
        witnesses: vec![witness],
        facts: vec![fact.statement],
        receipts: Vec::new(),
        fact_guest_vk_digest: [3; 8],
    })
    .unwrap();
    assert_eq!(statements, vec![expected]);
}

#[test]
fn a_leader_splitting_one_chunk_by_payment_selection_equivocates() {
    use neutrin0_prover_chunk::{evidence::validate_evidence_using, facts::FactRecorder};
    let (spec, _, source) = fixture_with_source();
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let first = source.finality.proposal.clone();
    let sign = |mut proposal: neutrin0_consensus_types::BftProposal| {
        proposal.signature = key
            .sign(&proposal.signing_message(spec.consensus_domain()))
            .to_bytes();
        proposal
    };
    let claim = |second| EvidenceWitness {
        reporter: None,
        chain_spec: spec.clone(),
        source: source.clone(),
        claim: EvidenceClaim::Slash(SlashingEvidence::DoubleBftProposal {
            proposer_index: 0,
            proposal_a: first.clone(),
            proposal_b: second,
        }),
        block_guest_vk_digest: [1; 8],
    };
    // Same chunk, another payment selection: another BFT value.
    let mut reselected = first.clone();
    reselected.proposal_slot += 1;
    assert!(
        validate_evidence_using(&claim(sign(reselected)), &mut FactRecorder::default()).is_ok()
    );
    // Same chunk and selection with other attachments is one value.
    let mut same_value = first.clone();
    same_value.valid_quorum = Some(neutrin0_consensus_types::QuorumCertificate {
        data: source.finality.prevote_vote().data,
        aggregate: source.finality.prevote.clone(),
    });
    assert!(
        validate_evidence_using(&claim(sign(same_value)), &mut FactRecorder::default()).is_err()
    );
}

#[test]
fn history_openings_cannot_be_substituted_or_reordered() {
    let (_, history) = fixture();
    let root = history.frontier.root().unwrap();
    assert_eq!(history.authenticate(1, root), Ok(()));
    assert_eq!(
        history.records[0]
            .record
            .evidence_context()
            .source_runtime_code_hash,
        [4; 32]
    );
    let mut wrong = history.clone();
    wrong.records[0].record.runtime_code_hash[0] ^= 1;
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
    let mut wrong = history.clone();
    wrong.records[0].record.block_guest_vk_digest[0] ^= 1;
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
    let mut wrong = history.clone();
    wrong.records[0].record.seed[0] ^= 1;
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
    let mut wrong = history.clone();
    wrong.records[0].record.chunk.end_state_root[0] ^= 1;
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
    let mut wrong = history.clone();
    wrong.records[0].path.index = 1;
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
    let mut wrong = history.clone();
    wrong.records[0].path.count = 2;
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
    let mut wrong = history.clone();
    wrong.records[0].record.validators[0].withdrawal_credentials[0] ^= 1;
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
    assert_eq!(history.authenticate(0, root), Err(HistoryError::Anchor));
    let mut wrong = history.clone();
    wrong.records[0].path.siblings[0][0] ^= 1;
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
    let mut wrong = history.clone();
    wrong.records.push(wrong.records[0].clone());
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
    let mut wrong = history;
    wrong.frontier.count = 2;
    assert_eq!(wrong.authenticate(1, root), Err(HistoryError::Anchor));
}

#[test]
fn authenticated_old_votes_expire_at_the_eight_chunk_boundary() {
    use neutrin0_consensus_types::history::{HistoryFrontier, HistoryPath};
    use neutrin0_prover_chunk::history::HistoricalContextOpening;

    let (_, _, source) = fixture_with_source();
    let vote = source.finality.precommit_vote();
    let records: Vec<_> = (0..9)
        .map(|id| {
            let mut record = source.clone();
            record.chunk.chunk_id = id;
            record.chunk.start_height = id + 1;
            record.chunk.end_height = id + 1;
            record.finality.chunk_id = id;
            record.finality.chunk_hash = record.chunk.hash();
            record
        })
        .collect();
    let latest = HistoryWitness::from_history(&records[..8], &[0, 7]).unwrap();
    latest
        .authenticate(8, latest.frontier.root().unwrap())
        .unwrap();
    latest.record(vote.data.chunk_id).unwrap();

    let recent = HistoryWitness::from_history(&records, &[1, 8]).unwrap();
    recent
        .authenticate(9, recent.frontier.root().unwrap())
        .unwrap();
    assert!(HistoryWitness::from_history(&records, &[0]).is_none());

    // The old record still has a valid membership proof and signed vote. Its
    // exclusion is a protocol rule, including when an archive can supply it.
    let leaves: Vec<_> = records
        .iter()
        .map(|record| commitment(&record.evidence_context()))
        .collect();
    let stale = HistoryWitness {
        frontier: HistoryFrontier::from_leaves(&leaves).unwrap(),
        records: vec![HistoricalContextOpening {
            record: HistoricalContext::from(&source),
            path: HistoryPath::build(&leaves, 0).unwrap(),
        }],
    };
    let root = stale.frontier.root().unwrap();
    assert!(stale.records[0].path.verify(leaves[0], root));
    assert_eq!(stale.authenticate(9, root), Err(HistoryError::Anchor));
    assert_eq!(
        stale.record(vote.data.chunk_id).map(|_| ()),
        Err(HistoryError::Anchor)
    );
}

#[test]
fn historical_read_budgets_reject_declared_lengths_before_allocation() {
    use neutrin0_consensus_types::history::HistoryFrontier;
    use neutrin0_prover_chunk::history::{MAX_HISTORY_CONTEXT_RECORD_BYTES, MAX_HISTORY_READS};
    let mut encoded = borsh::to_vec(&HistoryFrontier::empty()).unwrap();
    encoded.extend_from_slice(&u32::try_from(MAX_HISTORY_READS + 1).unwrap().to_le_bytes());
    assert!(borsh::from_slice::<HistoryWitness>(&encoded).is_err());

    let mut encoded = borsh::to_vec(&HistoryFrontier::empty()).unwrap();
    encoded.extend_from_slice(&1_u32.to_le_bytes());
    encoded.extend_from_slice(
        &u32::try_from(MAX_HISTORY_CONTEXT_RECORD_BYTES + 1)
            .unwrap()
            .to_le_bytes(),
    );
    assert!(borsh::from_slice::<HistoryWitness>(&encoded).is_err());

    let (_, witness) = fixture();
    let decoded = borsh::from_slice::<HistoryWitness>(&borsh::to_vec(&witness).unwrap()).unwrap();
    assert_eq!(decoded, witness);
    decoded
        .authenticate(1, witness.frontier.root().unwrap())
        .unwrap();
    assert!(HistoryWitness::from_history(&[], &[0]).is_none());
    assert!(witness.record(1).is_err());
}

#[test]
fn thin_history_reads_preserve_full_sources_without_carrying_certificates() {
    use neutrin0_prover_chunk::history::{HistoricalContextOpening, HistoricalOpening};
    let (_, history, source) = fixture_with_source();
    let full = HistoricalOpening {
        record: source,
        path: history.records[0].path.clone(),
    };
    let full_bytes = borsh::to_vec(&full).unwrap();
    assert_eq!(
        borsh::from_slice::<HistoricalOpening>(&full_bytes).unwrap(),
        full
    );
    let thin = HistoricalContextOpening::from(&full);
    assert!(borsh::from_slice::<HistoricalContextOpening>(&full_bytes).is_err());
    assert!(borsh::from_slice::<HistoricalOpening>(&borsh::to_vec(&thin).unwrap()).is_err());
    assert_eq!(HistoricalContextOpening::from(full.clone()), thin);
    assert_eq!(thin, history.records[0]);
    assert_eq!(
        thin.record.evidence_context(),
        full.record.evidence_context()
    );
    assert!(borsh::object_length(&thin).unwrap() < full_bytes.len());
    // Different carrier signatures cannot change a history read. Membership
    // relies on a root appended by complete finalization, not this certificate.
    let mut different_certificate = full.clone();
    different_certificate.record.finality.precommit.signature[0] ^= 1;
    assert_ne!(borsh::to_vec(&different_certificate).unwrap(), full_bytes);
    assert_eq!(HistoricalContextOpening::from(&different_certificate), thin);
    // The full source still exists for independent signature verification.
    assert_ne!(different_certificate.record.finality, full.record.finality);
}

#[test]
fn maximum_thin_history_contexts_fit_the_bounded_wire_budget() {
    use neutrin0_consensus_types::history::{HistoryFrontier, HistoryPath};
    use neutrin0_primitives::MAX_CONSENSUS_VALIDATORS;
    use neutrin0_prover_chunk::history::{
        HistoricalContextOpening, MAX_HISTORY_CONTEXT_BYTES, MAX_HISTORY_CONTEXT_RECORD_BYTES,
        MAX_HISTORY_READS,
    };
    let (_, _, source) = fixture_with_source();
    let mut maximum = HistoricalContext::from(&source);
    // This measures the current fixed wire fields, not a usable signed
    // committee: complete Chunk validation independently authenticates it.
    maximum
        .validators
        .resize(MAX_CONSENSUS_VALIDATORS, maximum.validators[0].clone());
    maximum.chunk.active_validator_set_root = commitment(&maximum.validators);
    let record_bytes = borsh::object_length(&maximum).unwrap();
    assert_eq!(record_bytes, 508 + 112 * MAX_CONSENSUS_VALIDATORS);
    assert!(record_bytes <= MAX_HISTORY_CONTEXT_RECORD_BYTES);
    assert!(record_bytes * MAX_HISTORY_READS <= MAX_HISTORY_CONTEXT_BYTES);
    let contexts: Vec<_> = (0..u64::try_from(MAX_HISTORY_READS).unwrap())
        .map(|id| {
            let mut context = maximum.clone();
            context.chunk.chunk_id = id;
            context.chunk.start_height = id + 1;
            context.chunk.end_height = id + 1;
            context
        })
        .collect();
    let leaves: Vec<_> = contexts
        .iter()
        .map(|context| commitment(&context.evidence_context()))
        .collect();
    let witness = HistoryWitness {
        frontier: HistoryFrontier::from_leaves(&leaves).unwrap(),
        records: contexts
            .into_iter()
            .enumerate()
            .map(|(index, record)| HistoricalContextOpening {
                record,
                path: HistoryPath::build(&leaves, index).unwrap(),
            })
            .collect(),
    };
    // The budget bounds context records; paths and the frontier are fixed
    // shapes outside it. The bounded decoder accepts the maximum witness.
    let encoded = borsh::to_vec(&witness).unwrap();
    assert_eq!(
        borsh::from_slice::<HistoryWitness>(&encoded).unwrap(),
        witness
    );
    // A tiny input with an excessive inner count is rejected before attempting
    // to read or allocate any validator vector of that declared size.
    let mut malformed = borsh::to_vec(&maximum.chunk).unwrap();
    malformed.extend_from_slice(
        &u32::try_from(MAX_CONSENSUS_VALIDATORS + 1)
            .unwrap()
            .to_le_bytes(),
    );
    assert!(borsh::from_slice::<HistoricalContext>(&malformed).is_err());
}

#[test]
fn malformed_historical_ranges_and_validator_roots_fail_even_at_a_matching_leaf() {
    use neutrin0_consensus_types::history::{HistoryFrontier, HistoryPath};
    let (_, history) = fixture();
    for mutation in 0..3 {
        let mut wrong = history.clone();
        match mutation {
            0 => wrong.records[0].record.chunk.start_height = 0,
            1 => wrong.records[0].record.chunk.end_height = u64::MAX,
            _ => wrong.records[0].record.chunk.active_validator_set_root[0] ^= 1,
        }
        let leaves = [commitment(&wrong.records[0].record.evidence_context())];
        wrong.frontier = HistoryFrontier::from_leaves(&leaves).unwrap();
        wrong.records[0].path = HistoryPath::build(&leaves, 0).unwrap();
        assert_eq!(
            wrong.authenticate(1, wrong.frontier.root().unwrap()),
            Err(HistoryError::Anchor)
        );
    }
}

#[test]
#[cfg(feature = "sp1-verification")]
fn rejected_proof_requires_the_exact_signed_artifact() {
    use neutrin0_consensus_types::{BlockProof, ProofRejectionReason, VoteAttestation};
    let (spec, _, source) = fixture_with_source();
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let SlashingEvidence::DoublePrecommit { vote_a: vote, .. } = double_vote() else {
        unreachable!()
    };
    let rejected_proof = BlockProof {
        prover_address: input.blocks[0].public_inputs.proposer_address,
        statement_key: [0; 32],
        height: 1,
        block_hash: input.blocks[0].header.hash(),
        public_inputs: input.blocks[0].public_inputs.clone(),
        proof_bytes: vec![0xff],
    };
    let mut attestation = VoteAttestation {
        vote_signature: vote.signature,
        validator_index: 0,
        vote: vote.data.clone(),
        proof_acceptance: Some(
            neutrin0_consensus_types::ProofManifest {
                proof_hashes: vec![commitment(&rejected_proof)],
            }
            .commitment(),
        ),
        unlock_quorum: None,
        signature: [0; 96],
    };
    attestation.signature = key
        .sign(&attestation.signing_message(spec.consensus_domain()))
        .to_bytes();
    let mut evidence = SlashingEvidence::InvalidProofSigning {
        proof_opening: neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![commitment(&rejected_proof)],
        }
        .opening(0)
        .unwrap(),
        validator_index: 0,
        vote,
        attestation,
        rejected_proof,
        reason: ProofRejectionReason::MalformedProof,
    };
    let witness = EvidenceWitness {
        reporter: None,
        chain_spec: spec,
        source,
        claim: EvidenceClaim::Slash(evidence.clone()),
        block_guest_vk_digest: [1; 8],
    };
    validate_evidence(&witness).unwrap();
    if let SlashingEvidence::InvalidProofSigning { rejected_proof, .. } = &mut evidence {
        rejected_proof.proof_bytes.push(0);
    }
    let bad = EvidenceWitness {
        reporter: None,
        claim: EvidenceClaim::Slash(evidence),
        ..witness
    };
    assert_eq!(validate_evidence(&bad), Err(HistoryError::Evidence));
}

#[test]
#[allow(clippy::too_many_lines)] // One routing verifier, a signed acceptance and its forged source.
fn historical_proof_rejection_keeps_the_source_program_after_an_upgrade() {
    use neutrin0_consensus_types::{BlockProof, ProofRejectionReason, VoteAttestation};
    use neutrin0_primitives::{BlsPublicKey, BlsSignature};
    use neutrin0_prover_chunk::{bls, evidence::validate_evidence_using, facts::EvidenceVerifier};

    #[derive(Default)]
    struct ProgramRecorder {
        queried: Vec<[u32; 8]>,
    }
    impl bls::Verifier for ProgramRecorder {
        fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
            bls::verify(key, message, signature)
        }
        fn aggregate(
            &mut self,
            keys: &[BlsPublicKey],
            message: &[u8],
            signature: &BlsSignature,
        ) -> bool {
            bls::fast_aggregate_verify(keys, message, signature)
        }
        fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
            bls::verify_pop(key, signature)
        }
    }
    impl EvidenceVerifier for ProgramRecorder {
        fn rejects_block(
            &mut self,
            proof: &BlockProof,
            key: &[u32; 8],
        ) -> Result<bool, HistoryError> {
            self.queried.push(*key);
            // This routing fixture models a receipt accepted by its original
            // program. Real compressed verification is a separate gate.
            Ok(*key != proof.public_inputs.block_program)
        }
        fn accepts_block(
            &mut self,
            proof: &BlockProof,
            key: &[u32; 8],
        ) -> Result<bool, HistoryError> {
            self.rejects_block(proof, key).map(|rejected| !rejected)
        }
    }

    let (spec, history, source) = fixture_with_source();
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let SlashingEvidence::DoublePrecommit { vote_a: vote, .. } = double_vote() else {
        unreachable!()
    };
    let receipt = BlockProof {
        prover_address: input.blocks[0].public_inputs.proposer_address,
        statement_key: [0; 32],
        height: 1,
        block_hash: input.blocks[0].header.hash(),
        public_inputs: input.blocks[0].public_inputs.clone(),
        proof_bytes: vec![1],
    };
    let mut attestation = VoteAttestation {
        validator_index: 0,
        vote: vote.data.clone(),
        vote_signature: vote.signature,
        proof_acceptance: Some(
            neutrin0_consensus_types::ProofManifest {
                proof_hashes: vec![commitment(&receipt)],
            }
            .commitment(),
        ),
        unlock_quorum: None,
        signature: [0; 96],
    };
    attestation.signature = key
        .sign(&attestation.signing_message(spec.consensus_domain()))
        .to_bytes();
    let mut witness = EvidenceWitness {
        reporter: Some(support::credentials(42)),
        chain_spec: spec,
        source,
        claim: EvidenceClaim::Slash(SlashingEvidence::InvalidProofSigning {
            proof_opening: neutrin0_consensus_types::ProofManifest {
                proof_hashes: vec![commitment(&receipt)],
            }
            .opening(0)
            .unwrap(),
            validator_index: 0,
            vote,
            attestation,
            rejected_proof: receipt,
            reason: ProofRejectionReason::MalformedProof,
        }),
        block_guest_vk_digest: [9; 8],
    };
    let mut recorder = ProgramRecorder::default();
    assert_eq!(
        validate_evidence_using(&witness, &mut recorder),
        Err(HistoryError::Evidence)
    );
    assert_eq!(recorder.queried, vec![[1; 8]]);

    // Swapping the source key could fabricate a rejection, but changes the
    // authenticated leaf, so the original canonical path cannot authorize it.
    let root = history.frontier.root().unwrap();
    let opening = &history.records[0].path;
    witness.source.block_guest_vk_digest = [9; 8];
    let forged = validate_evidence_using(&witness, &mut ProgramRecorder::default()).unwrap();
    assert_eq!(forged.context.source_block_guest_vk_digest, [9; 8]);
    assert_eq!(forged.block_guest_vk_digest, [9; 8]);
    assert!(!opening.verify(commitment(&forged.context), root));
}

#[test]
fn da_fraud_requires_the_proposers_signature_on_the_exact_published_bundle() {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let header = &input.blocks[0].header;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let bad_body = Body {
        transactions: vec![vec![0xff]],
        ..Body::default()
    };
    let bytes = borsh::to_vec(&bad_body).unwrap();
    let hash = neutrin0_primitives::blake3_256(&bytes);
    let message = neutrin0_prover_chunk::slashing::da_publication_message(
        test_domain(),
        &header.hash(),
        &hash,
    );
    let mut fraud = neutrin0_consensus_types::DaFraudProof {
        publication_signature: key.sign(&message).to_bytes(),
        expected_da_root: header.da_root,
        computed_da_root: neutrin0_prover_chunk::consensus::body_da_root(&bad_body),
        bundle_hash: hash,
        offending_bundle: bytes,
    };
    assert!(
        neutrin0_prover_chunk::slashing::verify_da_fraud(
            test_domain(),
            &input.context.active_validators,
            header,
            &fraud
        )
        .is_ok()
    );
    fraud.publication_signature = header.signature;
    assert!(
        neutrin0_prover_chunk::slashing::verify_da_fraud(
            test_domain(),
            &input.context.active_validators,
            header,
            &fraud
        )
        .is_err()
    );
    fraud.publication_signature = key.sign(&message).to_bytes();
    fraud.offending_bundle.push(0);
    assert!(
        neutrin0_prover_chunk::slashing::verify_da_fraud(
            test_domain(),
            &input.context.active_validators,
            header,
            &fraud
        )
        .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Signed canonical and alternative certificates are built explicitly.
fn inactivity_requires_authenticated_certificate_non_inclusion() {
    let (spec, _, mut source) = fixture_with_source();
    let participating = EvidenceWitness {
        reporter: None,
        chain_spec: spec.clone(),
        source: source.clone(),
        claim: EvidenceClaim::Inactivity {
            validator_index: 0,
            certificate: source.finality.participation_certificate(),
        },
        block_guest_vk_digest: [1; 8],
    };
    assert_eq!(
        validate_evidence(&participating),
        Err(HistoryError::Evidence)
    );
    // A genuine quorum may omit a positive-stake validator; authorization is
    // explicitly certificate non-inclusion, not proof of an absent network vote.
    let record = &mut source;
    let mut missing = record.validators[0].clone();
    missing.pubkey = SecretKey::key_gen(&[43; 32], &[])
        .unwrap()
        .public_key()
        .to_bytes();
    missing.withdrawal_credentials = [9; 32];
    missing.effective_stake = 1;
    record.validators.push(missing);
    record.chunk.active_validator_set_root = commitment(&record.validators);
    record.finality.active_validator_set_root = record.chunk.active_validator_set_root;
    record.finality.chunk_hash = record.chunk.hash();
    record.finality.proposal.chunk = record.chunk.clone();
    let leader = neutrin0_consensus_types::bft_leader(
        7,
        record.chunk.chunk_id,
        0,
        &record.seed,
        &record.validators,
    )
    .unwrap();
    record.finality.proposal.proposer_index = leader;
    record.finality.proposal.signature =
        SecretKey::key_gen(&[42 + u8::try_from(leader).unwrap(); 32], &[])
            .unwrap()
            .sign(&record.finality.proposal.signing_message(test_domain()))
            .to_bytes();
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    for (phase, aggregate) in [
        (FinalityVotePhase::Prevote, &mut record.finality.prevote),
        (FinalityVotePhase::Precommit, &mut record.finality.precommit),
    ] {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: record.finality.chunk_hash,
            selection: record.finality.proposal.selection(),
            phase,
        };
        let message = data.signing_message(test_domain());
        aggregate.signature = key.sign(&message).to_bytes();
        aggregate.aggregation_bits = BitVec::from_bytes(2, vec![1]).unwrap();
    }
    let prevote = record.finality.prevote_vote();
    let claim = &mut record.finality.prevote_attestations[0];
    claim.vote = prevote.data;
    claim.vote_signature = prevote.signature;
    claim.signature = key.sign(&claim.signing_message(test_domain())).to_bytes();
    let data = record.finality.precommit_vote().data;
    let locking = neutrin0_consensus_types::QuorumCertificate {
        data: record.finality.prevote_vote().data,
        aggregate: record.finality.prevote.clone(),
    };
    let claim = &mut record.finality.precommit_attestations[0];
    claim.vote = data;
    claim.vote_signature = record.finality.precommit.signature;
    claim.unlock_quorum = Some(locking);
    claim.signature = key.sign(&claim.signing_message(test_domain())).to_bytes();
    // Inactivity means absence from a submitted valid certificate, not proof
    // that no vote was sent. Different valid certificates share one history root.
    let mut evidence = neutrin0_prover_chunk::evidence::EvidenceWitness {
        reporter: None,
        chain_spec: spec.clone(),
        source: record.clone(),
        claim: neutrin0_prover_chunk::evidence::EvidenceClaim::Inactivity {
            validator_index: 1,
            certificate: record.finality.participation_certificate(),
        },
        block_guest_vk_digest: [1; 8],
    };
    assert!(neutrin0_prover_chunk::evidence::validate_evidence(&evidence).is_ok());
    let mut alternate = record.finality.clone();
    alternate.round += 1;
    let quorum = neutrin0_consensus_types::QuorumCertificate {
        data: record.finality.prevote_vote().data,
        aggregate: record.finality.prevote.clone(),
    };
    let mut report = neutrin0_consensus_types::RoundChange {
        chunk_id: 0,
        round: alternate.round,
        validator_index: 0,
        highest_quorum: Some(quorum.clone()),
        signature: [0; 96],
    };
    report.signature = key.sign(&report.signing_message(test_domain())).to_bytes();
    alternate.proposal.round = alternate.round;
    alternate.proposal.valid_quorum = Some(quorum);
    alternate.proposal.round_change_certificate =
        Some(neutrin0_consensus_types::RoundChangeCertificate {
            chunk_id: 0,
            round: alternate.round,
            reports: vec![report],
        });
    let leader = neutrin0_consensus_types::bft_leader(
        test_domain().chain_id,
        record.chunk.chunk_id,
        alternate.round,
        &record.seed,
        &record.validators,
    )
    .unwrap();
    alternate.proposal.proposer_index = leader;
    alternate.proposal.signature =
        SecretKey::key_gen(&[42 + u8::try_from(leader).unwrap(); 32], &[])
            .unwrap()
            .sign(&alternate.proposal.signing_message(test_domain()))
            .to_bytes();
    for (phase, aggregate) in [
        (FinalityVotePhase::Prevote, &mut alternate.prevote),
        (FinalityVotePhase::Precommit, &mut alternate.precommit),
    ] {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: alternate.round,
            chunk_hash: alternate.chunk_hash,
            selection: alternate.proposal.selection(),
            phase,
        };
        let message = data.signing_message(test_domain());
        aggregate.signature = key.sign(&message).to_bytes();
    }
    let prevote = alternate.prevote_vote();
    let claim = &mut alternate.prevote_attestations[0];
    claim.vote = prevote.data;
    claim.vote_signature = prevote.signature;
    claim.signature = key.sign(&claim.signing_message(test_domain())).to_bytes();
    let vote = alternate.precommit_vote();
    alternate.precommit_attestations[0].vote = vote.data;
    alternate.precommit_attestations[0].vote_signature = alternate.precommit.signature;
    // The round-one precommit declares the retained round-zero prevote lock.
    alternate.precommit_attestations[0].unlock_quorum = alternate.proposal.valid_quorum.clone();
    alternate.precommit_attestations[0].signature = key
        .sign(&alternate.precommit_attestations[0].signing_message(test_domain()))
        .to_bytes();
    neutrin0_prover_chunk::finality::verify_finality(
        test_domain(),
        &spec.consensus,
        &record.validators,
        &record.seed,
        &record.chunk,
        &alternate,
    )
    .unwrap();
    evidence.claim = neutrin0_prover_chunk::evidence::EvidenceClaim::Inactivity {
        validator_index: 1,
        certificate: alternate.participation_certificate(),
    };
    assert!(neutrin0_prover_chunk::evidence::validate_evidence(&evidence).is_ok());
    let root = neutrin0_prover_chunk::history::history_commitment(core::slice::from_ref(record));
    let mut forged = record.clone();
    forged.finality.precommit.signature[0] ^= 1;
    assert_eq!(
        root,
        neutrin0_prover_chunk::history::history_commitment(core::slice::from_ref(&forged))
    );
    let authentic = HistoryWitness::from_history(core::slice::from_ref(record), &[0]).unwrap();
    let slim = HistoryWitness::from_history(core::slice::from_ref(&forged), &[0]).unwrap();
    assert_eq!(slim, authentic);
    slim.authenticate(1, root).unwrap();
    // A retained source certificate may differ. The supplied signed
    // participation certificate must authenticate independently of the path.
    evidence.source.finality = forged.finality.clone();
    let accepted = validate_evidence(&evidence).unwrap();
    assert_eq!(accepted.offender.withdrawal_credentials, [9; 32]);
    evidence.claim = EvidenceClaim::Inactivity {
        validator_index: 1,
        certificate: forged.finality.participation_certificate(),
    };
    assert_eq!(validate_evidence(&evidence), Err(HistoryError::Evidence));
}

#[test]
fn evidence_guest_statement_binds_identity_rules_and_canonical_event() {
    let (spec, _, source) = fixture_with_source();
    let mut witness = EvidenceWitness {
        reporter: None,
        chain_spec: spec,
        source,
        claim: EvidenceClaim::Slash(double_vote()),
        block_guest_vk_digest: [1; 8],
    };
    let claim = validate_evidence(&witness).unwrap();
    assert_eq!(claim.chain_spec_hash, witness.chain_spec.hash());
    assert_eq!(claim.context, witness.source.evidence_context());
    assert_eq!(claim.offender, witness.source.validators[0]);
    assert_eq!(claim.block_guest_vk_digest, [1; 8]);
    assert_eq!(claim.reporter, None);
    witness.reporter = Some(support::credentials(42));
    let rewarded = validate_evidence(&witness).unwrap();
    assert_eq!(rewarded.reporter, witness.reporter);
    assert_eq!(claim.offence_id, rewarded.offence_id);
    assert_eq!(claim.facts_commitment, rewarded.facts_commitment);
    assert_ne!(commitment(&claim), commitment(&rewarded));
    if let EvidenceClaim::Slash(SlashingEvidence::DoublePrecommit { vote_a, vote_b, .. }) =
        &mut witness.claim
    {
        std::mem::swap(vote_a, vote_b);
    }
    let reversed = validate_evidence(&witness).unwrap();
    assert_eq!(claim.offence_id, reversed.offence_id);
    assert_ne!(claim.facts_commitment, reversed.facts_commitment);
    let mut wrong = witness.clone();
    wrong.source.validators[0].withdrawal_credentials[0] ^= 1;
    assert!(validate_evidence(&wrong).is_err());
    let mut wrong = witness.clone();
    wrong.chain_spec.chain_id += 1;
    assert!(validate_evidence(&wrong).is_err());
    let mut wrong = witness.clone();
    wrong.source.chunk.end_height += 1;
    assert!(validate_evidence(&wrong).is_err());
    if let EvidenceClaim::Slash(SlashingEvidence::DoublePrecommit { vote_b, .. }) =
        &mut witness.claim
    {
        vote_b.signature[0] ^= 1;
    }
    assert!(validate_evidence(&witness).is_err());
}

#[test]
fn an_abandoned_height_needs_the_canonical_parent_and_a_late_replacement() {
    use neutrin0_consensus_types::evidence::{MerkleOpening, SanctionKind};
    let (mut spec, _, source) = fixture_with_source();
    let canonical = support::fixture([1; 8], [4; 32]).0.blocks[0].header.clone();
    assert_eq!(canonical.hash(), source.chunk.end_block_hash);
    // The canonical block came exactly one exclusive window after slot zero.
    spec.consensus.proof_exclusive_slots = canonical.slot;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let sign = |header: &mut neutrin0_consensus_types::Header| {
        let message = spec
            .consensus_domain()
            .at_height(header.height)
            .signing_message(neutrin0_primitives::DOMAIN_PROPOSER_SIG, &header.hash());
        header.signature = key.sign(&message).to_bytes();
    };
    let mut abandoned = canonical.clone();
    abandoned.slot = 0;
    abandoned.state_root[0] ^= 1;
    sign(&mut abandoned);
    let witness = |abandoned: &neutrin0_consensus_types::Header| EvidenceWitness {
        reporter: None,
        chain_spec: spec.clone(),
        source: source.clone(),
        claim: EvidenceClaim::Abandonment {
            abandoned: abandoned.clone(),
            canonical: canonical.clone(),
            opening: MerkleOpening::build(&[canonical.hash()], 0).unwrap(),
        },
        block_guest_vk_digest: [1; 8],
    };
    let statement = validate_evidence(&witness(&abandoned)).unwrap();
    assert_eq!(statement.kind, SanctionKind::Abandonment);
    assert_eq!(statement.offender, source.validators[0]);
    assert_eq!(
        statement.offence_id,
        neutrin0_prover_chunk::history::penalty_id(
            neutrin0_prover_chunk::history::PENALTY_ABANDONMENT,
            &source.validators[0],
            0,
            0,
        )
    );
    // Replaced inside the window: nothing to answer for.
    let mut early = abandoned.clone();
    early.slot = 1;
    sign(&mut early);
    assert!(validate_evidence(&witness(&early)).is_err());
    // Built on a parent the chain dropped.
    let mut orphan = abandoned.clone();
    orphan.parent_hash[0] ^= 1;
    sign(&mut orphan);
    assert!(validate_evidence(&witness(&orphan)).is_err());
    // The canonical block itself, or a forged signature, is no offence.
    assert!(validate_evidence(&witness(&canonical)).is_err());
    let mut forged = abandoned.clone();
    forged.signature[0] ^= 1;
    assert!(validate_evidence(&witness(&forged)).is_err());
    // The replacement must be the block the chunk committed.
    let mut wrong = witness(&abandoned);
    if let EvidenceClaim::Abandonment { canonical, .. } = &mut wrong.claim {
        canonical.slot += 1;
    }
    assert!(validate_evidence(&wrong).is_err());
}

#[test]
fn evidence_submission_rejects_wrong_anchor_window_and_history() {
    use neutrin0_consensus_types::evidence::{EvidenceAnchor, EvidenceSubmission};
    use neutrin0_consensus_types::history::HistoryPath;
    let (spec, _, source) = fixture_with_source();
    let claim = validate_evidence(&EvidenceWitness {
        reporter: None,
        chain_spec: spec.clone(),
        source,
        claim: EvidenceClaim::Slash(double_vote()),
        block_guest_vk_digest: [1; 8],
    })
    .unwrap();
    let leaves = [commitment(&claim.context)];
    let anchor = EvidenceAnchor {
        fact_guest_vk_digest: [3; 8],
        chain_spec_hash: spec.hash(),
        chunk_id: 1,
        history_root: neutrin0_consensus_types::history::history_root(&leaves),
        block_guest_vk_digest: [1; 8],
        evidence_guest_vk_digest: [2; 8],
        unbonding_delay_blocks: spec.runtime.unbonding_delay_blocks,
        chunk_size: spec.consensus.chunk_size,

        max_block_proving_input_bytes: neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
        block_gas_limit: spec.genesis_gas_limit,
    };
    let submission = EvidenceSubmission {
        statement: claim,
        history: HistoryPath::build(&leaves, 0).unwrap(),
    };
    assert!(submission.binds(7, 2, &anchor));
    assert!(!submission.binds(8, 2, &anchor));
    assert!(!submission.binds(7, 1, &anchor));
    let max_age = spec.runtime.evidence_max_age_blocks;
    // A safety claim has no age window; a liveness claim about the same
    // context expires with the governable window.
    assert!(submission.within_age(2 + max_age, max_age));
    let mut liveness = submission.clone();
    liveness.statement.kind = neutrin0_consensus_types::evidence::SanctionKind::Inactivity;
    assert!(liveness.within_age(1 + max_age, max_age));
    assert!(!liveness.within_age(2 + max_age, max_age));
    let mut wrong = anchor;
    wrong.chain_spec_hash[0] ^= 1;
    assert!(!submission.binds(7, 2, &wrong));
    let mut wrong = anchor;
    wrong.block_guest_vk_digest[0] ^= 1;
    assert!(!submission.binds(7, 2, &wrong));
    let mut wrong = submission;
    wrong.history.count += 1;
    assert!(!wrong.binds(7, 2, &anchor));
}

/// A hard fork's successor specification keeps punishing pre-fork safety
/// offences: signatures on chunks before the fork verify under the
/// predecessor's domain, and only the successor's own chunks under its own.
#[test]
fn pre_fork_safety_evidence_verifies_under_the_predecessor_domain() {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let proven = validate_consensus(&input).unwrap();
    let (spec, _, source) = fixture_with_source();
    let forked = |predecessor| forked_spec(&spec, &proven.end, predecessor);
    let witness = |chain_spec: ChainSpec| EvidenceWitness {
        reporter: None,
        chain_spec,
        source: source.clone(),
        claim: EvidenceClaim::Slash(double_vote()),
        block_guest_vk_digest: [1; 8],
    };
    let successor = forked(spec.hash());
    assert_ne!(successor.hash(), spec.hash());
    assert_eq!(
        validate_evidence(&witness(successor.clone()))
            .unwrap()
            .offence_id,
        validate_evidence(&witness(spec.clone()))
            .unwrap()
            .offence_id
    );
    // A successor naming another predecessor domain cannot authenticate them.
    assert_eq!(
        validate_evidence(&witness(forked([9; 32]))),
        Err(HistoryError::Evidence)
    );
    // The successor never proves a chunk of its predecessor.
    let mut below = input;
    below.chain_spec = successor.clone();
    below.context.chain_spec_hash = successor.hash();
    assert!(validate_consensus(&below).is_err());
}

/// A proof's rejection belongs to the verifier that judged it, which a fork
/// may replace (a new SP1 version rejects every older receipt): proof
/// acceptances signed before the fork lapse with it, though their signatures
/// still verify under the predecessor's domain.
#[test]
fn pre_fork_proof_acceptances_lapse_with_the_fork() {
    use neutrin0_consensus_types::{
        BlockProof, ProofManifest, ProofRejectionReason, VoteAttestation,
    };
    use neutrin0_primitives::{BlsPublicKey, BlsSignature};
    use neutrin0_prover_chunk::{bls, evidence::validate_evidence_using, facts::EvidenceVerifier};

    /// Rejects every receipt, as a successor's verifier rejects its
    /// predecessor's receipts after an SP1 upgrade.
    struct RejectsEverything;
    impl bls::Verifier for RejectsEverything {
        fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
            bls::verify(key, message, signature)
        }
        fn aggregate(
            &mut self,
            keys: &[BlsPublicKey],
            message: &[u8],
            signature: &BlsSignature,
        ) -> bool {
            bls::fast_aggregate_verify(keys, message, signature)
        }
        fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
            bls::verify_pop(key, signature)
        }
    }
    impl EvidenceVerifier for RejectsEverything {
        fn rejects_block(&mut self, _: &BlockProof, _: &[u32; 8]) -> Result<bool, HistoryError> {
            Ok(true)
        }
        fn accepts_block(&mut self, _: &BlockProof, _: &[u32; 8]) -> Result<bool, HistoryError> {
            Ok(false)
        }
    }

    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let proven = validate_consensus(&input).unwrap();
    let (spec, _, source) = fixture_with_source();
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let SlashingEvidence::DoublePrecommit { vote_a: vote, .. } = double_vote() else {
        unreachable!()
    };
    let receipt = BlockProof {
        prover_address: input.blocks[0].public_inputs.proposer_address,
        statement_key: [0; 32],
        height: 1,
        block_hash: input.blocks[0].header.hash(),
        public_inputs: input.blocks[0].public_inputs.clone(),
        proof_bytes: vec![1],
    };
    let manifest = ProofManifest {
        proof_hashes: vec![commitment(&receipt)],
    };
    let mut attestation = VoteAttestation {
        validator_index: 0,
        vote: vote.data.clone(),
        vote_signature: vote.signature,
        proof_acceptance: Some(manifest.commitment()),
        unlock_quorum: None,
        signature: [0; 96],
    };
    attestation.signature = key
        .sign(&attestation.signing_message(spec.consensus_domain()))
        .to_bytes();
    let witness = |chain_spec| EvidenceWitness {
        reporter: None,
        chain_spec,
        source: source.clone(),
        claim: EvidenceClaim::Slash(SlashingEvidence::InvalidProofSigning {
            proof_opening: manifest.opening(0).unwrap(),
            validator_index: 0,
            vote: vote.clone(),
            attestation: attestation.clone(),
            rejected_proof: receipt.clone(),
            reason: ProofRejectionReason::VerifierRejected,
        }),
        block_guest_vk_digest: [1; 8],
    };
    assert!(validate_evidence_using(&witness(spec.clone()), &mut RejectsEverything).is_ok());
    let successor = forked_spec(&spec, &proven.end, spec.hash());
    assert_eq!(
        validate_evidence_using(&witness(successor), &mut RejectsEverything),
        Err(HistoryError::Evidence)
    );
}

/// A fork's first chunk carries its predecessor's last certificate, verified
/// under the predecessor's domain, and its own report credits the endpoint
/// prover the specification pins for the proof it cannot ratify.
#[test]
fn a_forks_first_chunk_settles_its_predecessors_last_reports() {
    use neutrin0_prover_chunk::history::verify_carried;
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let proven = validate_consensus(&input).unwrap();
    let (spec, _, record) = fixture_with_source();
    let successor = forked_spec(&spec, &proven.end, spec.hash());
    assert_eq!(successor.carried_chunk(1), Some(0));
    // Chunk 0, the predecessor's last, signed under the predecessor's domain.
    let (_, last) =
        verify_carried(&successor, &record, &record.finality.carried_certificate()).unwrap();
    assert_eq!(last.chunk_provers, Vec::new());
    // Chunk 1, the fork's first, signed under the successor's own domain.
    let signing = neutrin0_prover_chunk::consensus::ConsensusWitness {
        chain_spec: successor.clone(),
        ..input
    };
    let (_, keys) = support::fixture_committee();
    let mut chunk = record.chunk.clone();
    chunk.chunk_id = 1;
    let finality = support::certificate_for_chunk(&signing, &chunk, &keys, &[0]);
    let first = HistoricalChunk {
        chunk,
        finality,
        ..record
    };
    let (_, report) =
        verify_carried(&successor, &first, &first.finality.carried_certificate()).unwrap();
    assert_eq!(report.chunk_provers, [(0, support::credentials(7))]);
}

#[test]
#[allow(clippy::too_many_lines)] // One claim, its batch verdicts and its reach across a fork.
fn an_execution_claim_needs_its_receipt_verified_by_recursion() {
    use neutrin0_consensus_types::BlockProof;
    use neutrin0_primitives::{BlsPublicKey, BlsSignature};
    use neutrin0_prover_chunk::evidence::{EvidenceBatchWitness, validate_evidence_batch};
    use neutrin0_prover_chunk::facts::{
        AcceptedReceipt, EvidenceVerifier, FactRecorder, FactStatement, ProvenFact,
    };
    use neutrin0_prover_chunk::{bls, evidence::validate_evidence_using};

    /// Records the signature facts the claim needs and accepts its receipt,
    /// whose real compressed verification is a separate gate.
    #[derive(Default)]
    struct Recording(FactRecorder);
    impl bls::Verifier for Recording {
        fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
            self.0.verify(key, message, signature)
        }
        fn aggregate(
            &mut self,
            keys: &[BlsPublicKey],
            message: &[u8],
            signature: &BlsSignature,
        ) -> bool {
            self.0.aggregate(keys, message, signature)
        }
        fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
            self.0.pop(key, signature)
        }
    }
    impl EvidenceVerifier for Recording {
        fn rejects_block(&mut self, _: &BlockProof, _: &[u32; 8]) -> Result<bool, HistoryError> {
            Ok(false)
        }
        fn accepts_block(&mut self, _: &BlockProof, _: &[u32; 8]) -> Result<bool, HistoryError> {
            Ok(true)
        }
    }

    let (spec, _, source) = fixture_with_source();
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let header = input.blocks[0].header.clone();
    // The honest execution of block 1 commits another post-state.
    let mut statement = input.blocks[0].statement();
    statement.output.post_state_root[0] ^= 1;
    let mut public_inputs = input.blocks[0].public_inputs.clone();
    public_inputs.state_root_after = statement.output.post_state_root;
    let receipt = BlockProof {
        prover_address: statement.prover_address,
        statement_key: commitment(&statement),
        height: 1,
        block_hash: header.hash(),
        public_inputs,
        proof_bytes: vec![1],
    };
    let witness = EvidenceWitness {
        reporter: Some(support::credentials(42)),
        chain_spec: spec,
        claim: EvidenceClaim::Slash(SlashingEvidence::InvalidExecutionClaim {
            proposer_index: header.proposer_index,
            header,
            parent: None,
            receipt,
        }),
        block_guest_vk_digest: source.block_guest_vk_digest,
        source: source.clone(),
    };
    let mut recording = Recording::default();
    let expected = validate_evidence_using(&witness, &mut recording).unwrap();
    let facts = FactStatement {
        facts: recording
            .0
            .finish()
            .unwrap()
            .into_iter()
            .map(|(request, valid)| ProvenFact {
                id: request.id(),
                valid,
            })
            .collect(),
    };
    let batch = |receipts: Vec<AcceptedReceipt>| {
        validate_evidence_batch(&EvidenceBatchWitness {
            witnesses: vec![witness.clone()],
            facts: vec![facts.clone()],
            receipts,
            fact_guest_vk_digest: [3; 8],
        })
    };
    let accepted = AcceptedReceipt {
        block_guest_vk_digest: source.block_guest_vk_digest,
        statement,
    };
    assert_eq!(batch(vec![accepted.clone()]).unwrap().1, vec![expected]);
    // Without the receipt, or with one under another program or of another
    // statement, nothing proves the receipt valid; a missing verdict is no
    // verdict.
    assert_eq!(batch(Vec::new()), Err(HistoryError::Unsupported));
    let foreign = AcceptedReceipt {
        block_guest_vk_digest: [9; 8],
        ..accepted.clone()
    };
    assert_eq!(batch(vec![foreign]), Err(HistoryError::Unsupported));
    let mut other = accepted;
    other.statement.prover_address[31] ^= 1;
    assert_eq!(batch(vec![other]), Err(HistoryError::Unsupported));

    // After a fork the original genesis still has no header, so the first
    // block stays accusable without a parent.
    let proven = validate_consensus(&input).unwrap();
    let forked = EvidenceWitness {
        chain_spec: forked_spec(&witness.chain_spec, &proven.end, witness.chain_spec.hash()),
        ..witness.clone()
    };
    assert_eq!(
        validate_evidence_using(&forked, &mut Recording::default())
            .unwrap()
            .offence_id,
        validate_evidence_using(&witness, &mut Recording::default())
            .unwrap()
            .offence_id
    );
}

#[test]
fn an_execution_claim_against_the_first_block_binds_the_first_boundary() {
    use neutrin0_consensus_types::BlockProof;
    use neutrin0_primitives::{BlsPublicKey, BlsSignature};
    use neutrin0_prover_chunk::{bls, evidence::validate_evidence_using, facts::EvidenceVerifier};

    /// Accepts every receipt: real compressed verification is a separate gate.
    struct Accepting;
    impl bls::Verifier for Accepting {
        fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
            bls::verify(key, message, signature)
        }
        fn aggregate(
            &mut self,
            keys: &[BlsPublicKey],
            message: &[u8],
            signature: &BlsSignature,
        ) -> bool {
            bls::fast_aggregate_verify(keys, message, signature)
        }
        fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
            bls::verify_pop(key, signature)
        }
    }
    impl EvidenceVerifier for Accepting {
        fn rejects_block(&mut self, _: &BlockProof, _: &[u32; 8]) -> Result<bool, HistoryError> {
            Ok(false)
        }
        fn accepts_block(&mut self, _: &BlockProof, _: &[u32; 8]) -> Result<bool, HistoryError> {
            Ok(true)
        }
    }

    let (spec, _, source) = fixture_with_source();
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let header = input.blocks[0].header.clone();
    assert_eq!(header.parent_hash, spec.genesis_block_hash);
    // The honest execution of block 1 commits another post-state.
    let mut public_inputs = input.blocks[0].public_inputs.clone();
    public_inputs.state_root_after[0] ^= 1;
    let receipt = BlockProof {
        prover_address: public_inputs.proposer_address,
        statement_key: [0; 32],
        height: 1,
        block_hash: header.hash(),
        public_inputs,
        proof_bytes: vec![1],
    };
    let witness = |parent, receipt: &BlockProof| EvidenceWitness {
        reporter: Some(support::credentials(42)),
        chain_spec: spec.clone(),
        source: source.clone(),
        claim: EvidenceClaim::Slash(SlashingEvidence::InvalidExecutionClaim {
            proposer_index: header.proposer_index,
            header: header.clone(),
            parent,
            receipt: receipt.clone(),
        }),
        block_guest_vk_digest: source.block_guest_vk_digest,
    };

    // The genesis boundary is the parent and binds the pre-state root.
    let statement = validate_evidence_using(&witness(None, &receipt), &mut Accepting)
        .expect("a claim against block 1 authorizes under the genesis boundary");
    assert_eq!(
        statement.offender,
        source.validators[header.proposer_index as usize]
    );

    // No header can stand in for the first boundary: a fabricated one is
    // refused even when it carries the genesis state root.
    let fabricated = neutrin0_consensus_types::Header {
        height: 0,
        state_root: spec.genesis_state_root,
        ..header.clone()
    };
    assert_eq!(
        validate_evidence_using(&witness(Some(fabricated), &receipt), &mut Accepting),
        Err(HistoryError::Evidence)
    );

    // A receipt executed over another pre-state contradicts nothing.
    let mut other_pre_state = receipt.clone();
    other_pre_state.public_inputs.state_root_before[0] ^= 1;
    assert_eq!(
        validate_evidence_using(&witness(None, &other_pre_state), &mut Accepting),
        Err(HistoryError::Evidence)
    );

    // A receipt agreeing with the header is no offence.
    let honest = BlockProof {
        public_inputs: input.blocks[0].public_inputs.clone(),
        ..receipt
    };
    assert_eq!(
        validate_evidence_using(&witness(None, &honest), &mut Accepting),
        Err(HistoryError::Evidence)
    );
}
