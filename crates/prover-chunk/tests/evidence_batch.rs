//! Batch membership, early fact reuse and negative-verdict soundness.
pub mod support;
use neutrin0_consensus_types::{
    SlashingEvidence,
    evidence::{EvidenceBatch, EvidenceMembership},
};
use neutrin0_crypto::bls::SecretKey;
use neutrin0_prover_chunk::{
    consensus::{as_chunk, validate_consensus},
    evidence::{
        EvidenceBatchWitness, EvidenceClaim, EvidenceWitness, validate_evidence_batch,
        validate_evidence_set_using, validate_evidence_using,
    },
    facts::{FactRecorder, FactStatement, FactWitness, ProvenFact, validate_facts},
    history::HistoricalChunk,
};

fn test_domain() -> neutrin0_primitives::ConsensusDomain {
    support::fixture([1; 8], [4; 32])
        .0
        .chain_spec
        .consensus_domain()
}

#[derive(Default)]
struct CountChecks {
    direct: neutrin0_prover_chunk::bls::DirectVerifier,
    calls: usize,
}

impl neutrin0_prover_chunk::bls::Verifier for CountChecks {
    fn verify(
        &mut self,
        key: &neutrin0_primitives::BlsPublicKey,
        message: &[u8],
        signature: &neutrin0_primitives::BlsSignature,
    ) -> bool {
        self.calls += 1;
        neutrin0_prover_chunk::bls::Verifier::verify(&mut self.direct, key, message, signature)
    }
    fn aggregate(
        &mut self,
        keys: &[neutrin0_primitives::BlsPublicKey],
        message: &[u8],
        signature: &neutrin0_primitives::BlsSignature,
    ) -> bool {
        self.calls += 1;
        neutrin0_prover_chunk::bls::Verifier::aggregate(&mut self.direct, keys, message, signature)
    }
    fn pop(
        &mut self,
        key: &neutrin0_primitives::BlsPublicKey,
        signature: &neutrin0_primitives::BlsSignature,
    ) -> bool {
        self.calls += 1;
        neutrin0_prover_chunk::bls::Verifier::pop(&mut self.direct, key, signature)
    }
}

impl neutrin0_prover_chunk::facts::EvidenceVerifier for CountChecks {
    fn rejects_block(
        &mut self,
        proof: &neutrin0_consensus_types::BlockProof,
        key: &[u32; 8],
    ) -> Result<bool, neutrin0_prover_chunk::history::HistoryError> {
        self.calls += 1;
        neutrin0_prover_chunk::facts::EvidenceVerifier::rejects_block(&mut self.direct, proof, key)
    }
    fn accepts_block(
        &mut self,
        proof: &neutrin0_consensus_types::BlockProof,
        key: &[u32; 8],
    ) -> Result<bool, neutrin0_prover_chunk::history::HistoryError> {
        self.calls += 1;
        neutrin0_prover_chunk::facts::EvidenceVerifier::accepts_block(&mut self.direct, proof, key)
    }
}

#[test]
fn shared_evidence_checks_exact_sources_once_and_retains_per_claim_bindings() {
    let [first, mut second] = inactivity_claims();
    second.reporter = Some(support::credentials(77));
    let mut single = CountChecks::default();
    let first_statement = validate_evidence_using(&first, &mut single).unwrap();
    assert!(single.calls > 0);
    let mut independent = CountChecks::default();
    let second_statement = validate_evidence_using(&second, &mut independent).unwrap();
    let mut shared = CountChecks::default();
    let statements =
        validate_evidence_set_using(&[first.clone(), second.clone()], &mut shared).unwrap();
    assert_eq!(statements, vec![first_statement, second_statement]);
    assert_eq!(shared.calls, single.calls);
    assert_eq!(statements[1].reporter, Some(support::credentials(77)));
    assert_ne!(statements[0].offender, statements[1].offender);
    assert_ne!(statements[0].offence_id, statements[1].offence_id);

    // Equal chunk ids and equal certificates do not authorize reuse across
    // another complete historical source, including its execution programs.
    second.source.runtime_code_hash[0] ^= 1;
    let mut separate = CountChecks::default();
    let statements = validate_evidence_set_using(&[first, second.clone()], &mut separate).unwrap();
    assert_eq!(separate.calls, single.calls * 2);
    assert_eq!(
        statements[1].context.source_runtime_code_hash,
        second.source.runtime_code_hash
    );
}

#[test]
fn evidence_memoization_never_reuses_a_changed_spec_certificate_or_offender_check() {
    let [first, second] = inactivity_claims();
    let mut wrong_spec = second.clone();
    wrong_spec.chain_spec.consensus.bft_round_timeout_base_secs += 1;
    assert!(
        validate_evidence_set_using(&[first.clone(), wrong_spec], &mut CountChecks::default())
            .is_err()
    );
    let mut wrong_certificate = second.clone();
    let EvidenceClaim::Inactivity { certificate, .. } = &mut wrong_certificate.claim else {
        unreachable!()
    };
    certificate.aggregate.signature[0] ^= 1;
    assert!(
        validate_evidence_set_using(
            &[first.clone(), wrong_certificate],
            &mut CountChecks::default()
        )
        .is_err()
    );
    let mut present_signer = second;
    let EvidenceClaim::Inactivity {
        validator_index, ..
    } = &mut present_signer.claim
    else {
        unreachable!()
    };
    *validator_index = 0;
    assert!(
        validate_evidence_set_using(&[first, present_signer], &mut CountChecks::default()).is_err()
    );
}

#[test]
fn compact_inactivity_requires_precommit_for_the_exact_authenticated_target_and_set() {
    let [witness, _] = inactivity_claims();
    validate_evidence_using(&witness, &mut CountChecks::default()).unwrap();

    // This is a genuine prevote quorum for the same finalized value and signer
    // subset. Its signatures cannot authorize a precommit participation claim.
    let mut prevote = witness.clone();
    let EvidenceClaim::Inactivity { certificate, .. } = &mut prevote.claim else {
        unreachable!()
    };
    *certificate = neutrin0_consensus_types::QuorumCertificate {
        data: witness.source.finality.prevote_vote().data,
        aggregate: witness.source.finality.prevote.clone(),
    };
    assert!(validate_evidence_using(&prevote, &mut CountChecks::default()).is_err());

    let mut wrong_target = witness.clone();
    let EvidenceClaim::Inactivity { certificate, .. } = &mut wrong_target.claim else {
        unreachable!()
    };
    certificate.data.chunk_hash[0] ^= 1;
    assert!(validate_evidence_using(&wrong_target, &mut CountChecks::default()).is_err());

    let mut wrong_set = witness;
    wrong_set.source.validators[0].effective_stake += 1;
    assert!(validate_evidence_using(&wrong_set, &mut CountChecks::default()).is_err());
}

/// A witness over the fixture's single finalized chunk carrying `claim`.
fn source_witness(claim: EvidenceClaim) -> EvidenceWitness {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let statement = validate_consensus(&input).unwrap();
    let chunk = as_chunk(&statement.chunk);
    EvidenceWitness {
        reporter: None,
        chain_spec: input.chain_spec,
        source: HistoricalChunk {
            runtime_code_hash: input.context.programs.runtime_code_hash,
            block_guest_vk_digest: input.context.programs.execution.block,
            start_boundary: statement.start.commitment(),
            chunk,
            validators: input.context.active_validators,
            seed: input.seed,
            finality: input.finality_cert,
        },
        claim,
        block_guest_vk_digest: [1; 8],
    }
}

/// A lock violation whose signed attestation names an unlock quorum that
/// fails verification: guilt rests on that negative aggregate verdict.
fn forged_unlock() -> EvidenceWitness {
    use neutrin0_consensus_types::{AggregatedVote, FinalityVotePhase, QuorumCertificate};
    use neutrin0_primitives::BitVec;
    let mut witness = locked_prevote();
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let EvidenceClaim::Slash(SlashingEvidence::LockViolation {
        vote_b,
        lock_evidence,
        ..
    }) = &mut witness.claim
    else {
        unreachable!()
    };
    let mut data = vote_b.data.clone();
    data.round = 1;
    data.phase = FinalityVotePhase::Prevote;
    lock_evidence.attestation.unlock_quorum = Some(QuorumCertificate {
        data,
        aggregate: AggregatedVote {
            aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: key.sign(b"not the unlock quorum").to_bytes(),
        },
    });
    lock_evidence.attestation.signature = key
        .sign(&lock_evidence.attestation.signing_message(test_domain()))
        .to_bytes();
    witness
}

#[test]
fn missing_negative_fact_cannot_establish_guilt_and_facts_bind_exact_bytes() {
    let witness = forged_unlock();
    let mut recorder = FactRecorder::default();
    let expected = validate_evidence_using(&witness, &mut recorder).unwrap();
    let checks = recorder.finish().unwrap();
    let facts = FactWitness {
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
    assert!(facts.statement.facts.iter().any(|fact| !fact.valid));
    assert_eq!(validate_facts(&facts).unwrap(), facts.statement);
    let input = EvidenceBatchWitness {
        witnesses: vec![witness],
        facts: vec![facts.statement.clone()],
        receipts: Vec::new(),
        fact_guest_vk_digest: [3; 8],
    };
    let (batch, statements) = validate_evidence_batch(&input).unwrap();
    assert_eq!(statements, vec![expected]);
    let mut switched_fact = input.clone();
    switched_fact.fact_guest_vk_digest = [9; 8];
    assert!(validate_evidence_batch(&switched_fact).is_err());
    let membership = EvidenceMembership::build(&statements, 0, [3; 8]).unwrap();
    assert_eq!(batch, membership.batch);
    assert!(membership.binds(&statements[0], &[3; 8]));
    assert!(!membership.binds(&statements[0], &[4; 8]));
    let mut missing = input.clone();
    missing.facts[0].facts.retain(|fact| fact.valid);
    assert!(validate_evidence_batch(&missing).is_err());
    let mut forged = facts;
    let negative = forged
        .statement
        .facts
        .iter_mut()
        .find(|fact| !fact.valid)
        .unwrap();
    negative.valid = true;
    assert!(validate_facts(&forged).is_err());
    let mut different_bytes = input;
    if let EvidenceClaim::Slash(SlashingEvidence::LockViolation { lock_evidence, .. }) =
        &mut different_bytes.witnesses[0].claim
        && let Some(unlock) = &mut lock_evidence.attestation.unlock_quorum
    {
        unlock.aggregate.signature = SecretKey::key_gen(&[42; 32], &[])
            .unwrap()
            .sign(b"another forged unlock")
            .to_bytes();
    }
    assert!(validate_evidence_batch(&different_bytes).is_err());
}

#[test]
fn batch_openings_bind_count_order_identity_and_reject_duplicate_offences() {
    let witness = locked_prevote();
    let statement = neutrin0_prover_chunk::evidence::validate_evidence(&witness).unwrap();
    let mut second = statement.clone();
    second.offence_id[0] ^= 1;
    let statements = [statement.clone(), second];
    let membership = EvidenceMembership::build(&statements, 0, [3; 8]).unwrap();
    assert!(membership.binds(&statement, &[3; 8]));
    assert!(!membership.binds(&statements[1], &[3; 8]));
    let mut redirected = statement.clone();
    redirected.reporter = Some([42; 32]);
    assert!(!membership.binds(&redirected, &[3; 8]));
    let mut wrong = membership.clone();
    wrong.batch.count += 1;
    assert!(!wrong.binds(&statement, &[3; 8]));
    let mut wrong = membership;
    wrong.opening.index = 1;
    assert!(!wrong.binds(&statement, &[3; 8]));
    assert!(EvidenceBatch::new(&[statement.clone(), statement], [3; 8]).is_none());
    assert!(EvidenceBatch::new(&[], [3; 8]).is_none());
}

fn locked_prevote() -> EvidenceWitness {
    use neutrin0_consensus_types::{
        AggregatedVote, FinalityVoteData, FinalityVotePhase, IndexedVote, LockEvidence,
        QuorumCertificate, VoteAttestation,
    };
    use neutrin0_primitives::BitVec;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let signed = |phase, round, hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            phase,
            round,
            chunk_hash: [hash; 32],
            selection: [0; 32],
        };
        let message = data.signing_message(test_domain());
        IndexedVote {
            data,
            signature: key.sign(&message).to_bytes(),
        }
    };
    let first = signed(FinalityVotePhase::Precommit, 0, 1);
    let later = signed(FinalityVotePhase::Prevote, 2, 2);
    let locking = signed(FinalityVotePhase::Prevote, 0, 1);
    let mut claim = VoteAttestation {
        validator_index: 0,
        vote: later.data.clone(),
        vote_signature: later.signature,
        proof_acceptance: None,
        unlock_quorum: None,
        signature: [0; 96],
    };
    claim.signature = key.sign(&claim.signing_message(test_domain())).to_bytes();
    source_witness(EvidenceClaim::Slash(SlashingEvidence::LockViolation {
        validator_index: 0,
        vote_a: first,
        vote_b: later,
        lock_evidence: LockEvidence {
            locked_prevote_quorum: QuorumCertificate {
                data: locking.data,
                aggregate: AggregatedVote {
                    aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
                    signature: locking.signature,
                },
            },
            attestation: claim,
        },
    }))
}

#[test]
fn locked_prevote_produces_an_authenticated_batch_statement() {
    let witness = locked_prevote();
    let expected = neutrin0_prover_chunk::evidence::validate_evidence(&witness).unwrap();
    let mut recorder = FactRecorder::default();
    assert_eq!(
        validate_evidence_using(&witness, &mut recorder).unwrap(),
        expected
    );
    let checks = recorder.finish().unwrap();
    let facts = validate_facts(&FactWitness {
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
    })
    .unwrap();
    let mut batch_input = EvidenceBatchWitness {
        witnesses: vec![witness],
        facts: vec![facts],
        receipts: Vec::new(),
        fact_guest_vk_digest: [3; 8],
    };
    let (batch, statements) = validate_evidence_batch(&batch_input).unwrap();
    assert_eq!(statements, vec![expected]);
    let membership = EvidenceMembership::build(&statements, 0, [3; 8]).unwrap();
    assert_eq!(membership.batch, batch);
    assert!(membership.binds(&statements[0], &[3; 8]));
    let EvidenceClaim::Slash(SlashingEvidence::LockViolation { lock_evidence, .. }) =
        &mut batch_input.witnesses[0].claim
    else {
        unreachable!()
    };
    lock_evidence.attestation.vote_signature[0] ^= 1;
    assert!(validate_evidence_batch(&batch_input).is_err());
}

#[test]
fn equal_chain_ids_do_not_replay_lock_evidence_or_its_authenticated_facts() {
    let witness = locked_prevote();
    let mut recorder = FactRecorder::default();
    let expected = validate_evidence_using(&witness, &mut recorder).unwrap();
    let checks = recorder.finish().unwrap();
    let facts = FactWitness {
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
    validate_facts(&facts).unwrap();
    let mut batch = EvidenceBatchWitness {
        witnesses: vec![witness],
        facts: vec![facts.statement],
        receipts: Vec::new(),
        fact_guest_vk_digest: [3; 8],
    };
    assert_eq!(validate_evidence_batch(&batch).unwrap().1, vec![expected]);
    let original = batch.witnesses[0].chain_spec.consensus_domain();
    batch.witnesses[0]
        .chain_spec
        .consensus
        .bft_round_timeout_base_secs += 1;
    batch.witnesses[0].chain_spec.validate().unwrap();
    let other = batch.witnesses[0].chain_spec.consensus_domain();
    assert_eq!(original.chain_id, other.chain_id);
    assert_ne!(original.chain_spec_hash, other.chain_spec_hash);
    assert!(neutrin0_prover_chunk::evidence::validate_evidence(&batch.witnesses[0]).is_err());
    // Exact source-domain equations remain valid facts, but cannot answer any
    // signature request derived by the Evidence Guest from the other spec.
    assert!(validate_evidence_batch(&batch).is_err());
}

fn resign_source_certificate(
    source: &HistoricalChunk,
    keys: &[SecretKey],
) -> neutrin0_consensus_types::FinalityCert {
    let mut certificate = source.finality.clone();
    certificate.chunk_hash = source.chunk.hash();
    certificate.active_validator_set_root = source.chunk.active_validator_set_root;
    certificate.proposal.chunk = source.chunk.clone();
    let leader = neutrin0_consensus_types::bft_leader(
        7,
        source.chunk.chunk_id,
        certificate.round,
        &source.seed,
        &source.validators,
    )
    .unwrap();
    certificate.proposal.proposer_index = leader;
    certificate.proposal.signature = keys[leader as usize]
        .sign(&certificate.proposal.signing_message(test_domain()))
        .to_bytes();
    certificate
}

fn inactivity_claims() -> [EvidenceWitness; 2] {
    use neutrin0_consensus_types::{
        AggregatedVote, FinalityVoteData, FinalityVotePhase, VoteAttestation,
    };
    use neutrin0_crypto::bls::aggregate_signatures;
    use neutrin0_primitives::BitVec;

    use neutrin0_consensus_types::evidence::commitment;
    let mut first = locked_prevote();
    // Five of seven equal seats sign: strictly above two thirds, leaving
    // seats five and six absent.
    let keys: Vec<_> = (20..27)
        .map(|byte| SecretKey::key_gen(&[byte; 32], &[]).unwrap())
        .collect();
    let template = first.source.validators[0].clone();
    first.source.validators = keys
        .iter()
        .enumerate()
        .map(|(index, key)| neutrin0_primitives::Validator {
            pubkey: key.public_key().to_bytes(),
            withdrawal_credentials: neutrin0_primitives::runtime_account(
                [u8::try_from(index).unwrap(); 20],
            ),
            effective_stake: 100,
            ..template.clone()
        })
        .collect();
    first.source.chunk.active_validator_set_root = commitment(&first.source.validators);
    let mut certificate = resign_source_certificate(&first.source, &keys);
    let selection = certificate.proposal.selection();
    let data = |phase| FinalityVoteData {
        chunk_id: 0,
        round: certificate.round,
        chunk_hash: certificate.chunk_hash,
        selection,
        phase,
    };
    let sign = |key: &SecretKey, phase| {
        let message = data(phase).signing_message(test_domain());
        key.sign(&message)
    };
    let aggregate = |phase| {
        let bits = BitVec::from_bytes(7, vec![0b001_1111]).unwrap();
        let signatures: Vec<_> = keys[..5].iter().map(|key| sign(key, phase)).collect();
        AggregatedVote {
            aggregation_bits: bits,
            signature: aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
                .unwrap()
                .to_bytes(),
        }
    };
    certificate.prevote = aggregate(FinalityVotePhase::Prevote);
    certificate.precommit = aggregate(FinalityVotePhase::Precommit);
    let claims = |phase| {
        keys[..5]
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let mut claim = VoteAttestation {
                    validator_index: u32::try_from(index).unwrap(),
                    vote: data(phase),
                    vote_signature: sign(key, phase).to_bytes(),
                    proof_acceptance: (phase == FinalityVotePhase::Precommit).then(|| {
                        neutrin0_consensus_types::ProofManifest {
                            proof_hashes: vec![[1; 32]],
                        }
                        .commitment()
                    }),
                    unlock_quorum: None,
                    signature: [0; 96],
                };
                claim.signature = key.sign(&claim.signing_message(test_domain())).to_bytes();
                claim
            })
            .collect()
    };
    let prevote_attestations = claims(FinalityVotePhase::Prevote);
    let precommit_attestations = claims(FinalityVotePhase::Precommit);
    certificate.prevote_attestations = prevote_attestations;
    certificate.precommit_attestations = precommit_attestations;
    first.source.finality = certificate.clone();
    first.claim = EvidenceClaim::Inactivity {
        validator_index: 5,
        certificate: certificate.participation_certificate(),
    };
    let second = EvidenceWitness {
        reporter: None,
        claim: EvidenceClaim::Inactivity {
            validator_index: 6,
            certificate: certificate.participation_certificate(),
        },
        ..first.clone()
    };
    [first, second]
}

#[test]
fn multiple_inactivity_claims_reuse_one_set_of_certificate_facts() {
    let [first, second] = inactivity_claims();
    let mut single = FactRecorder::default();
    validate_evidence_using(&first, &mut single).unwrap();
    let single_count = single.finish().unwrap().len();
    let mut shared = FactRecorder::default();
    for witness in [&first, &second] {
        validate_evidence_using(witness, &mut shared).unwrap();
    }
    let checks = shared.finish().unwrap();
    assert_eq!(checks.len(), single_count);
    let facts = FactWitness {
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
    let facts = validate_facts(&facts).unwrap();
    let (batch, statements) = validate_evidence_batch(&EvidenceBatchWitness {
        witnesses: vec![first, second],
        facts: vec![facts],
        receipts: Vec::new(),
        fact_guest_vk_digest: [3; 8],
    })
    .unwrap();
    assert_eq!(batch.count, 2);
    for (index, statement) in statements.iter().enumerate() {
        assert!(
            EvidenceMembership::build(&statements, index, [3; 8])
                .unwrap()
                .binds(statement, &[3; 8])
        );
    }
}
