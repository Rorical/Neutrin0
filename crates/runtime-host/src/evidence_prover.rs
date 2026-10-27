//! Fact reuse and batch evidence proving. All returned receipts are verified once.
//! Block receipts an offence needs valid are attached for recursion, never
//! proven valid by the Fact Guest.
//!
//! Programs are resolved from the registry by the digests the witnesses'
//! anchors name, so evidence for any installed program set can be proven.

use crate::{
    ProgramProver, Sp1BlockProof, Sp1ProofSystem,
    fact_cache::{FactReceipt, verify_receipt},
    programs::ProgramKeys,
    prove_compressed, push_receipt,
};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{
    evidence::{
        EvidenceArtifact, EvidenceBatch, EvidenceMembership, MAX_EVIDENCE_BATCH, MerkleOpening,
    },
    history_proof::{ExecutionPrograms, VkDigest},
};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofError;
use neutrin0_prover_chunk::{
    evidence::{
        EvidenceBatchWitness, EvidenceWitness, MAX_EVIDENCE_FACT_STATEMENTS,
        validate_evidence_batch, validate_evidence_set_using,
    },
    facts::{
        AcceptedReceipt, FactRecorder, FactRequest, FactStatement, FactWitness, MAX_FACTS,
        ProvenFact, pack_requests,
    },
    receipt_codec,
};
use sp1_sdk::{SP1ProofWithPublicValues, SP1Stdin};
use std::{collections::BTreeSet, sync::Arc};

/// Most fact requests one preproving call compresses.
const MAX_PREPROVED_REQUESTS: usize = 16_384;

/// A block receipt an offence needs valid: its Guest-facing summary, the
/// bundle queued for recursion and the keys it verifies under.
type AcceptedBlockReceipt<P> = (
    AcceptedReceipt,
    SP1ProofWithPublicValues,
    Arc<ProgramKeys<P>>,
);

/// What a set of fact receipts is ensured for, which decides how many
/// statements it may span.
#[derive(Clone, Copy)]
enum FactUse {
    /// Filling the reusable cache before any offence is known. Only the
    /// request count is bounded; no single batch carries the result.
    Preprove,
    /// Attaching to one evidence batch, whose Guest accepts at most
    /// [`MAX_EVIDENCE_FACT_STATEMENTS`] statements.
    EvidenceBatch,
}

impl FactUse {
    /// `true` when `cached` covering receipts plus the new statements
    /// proving `missing` requests, [`MAX_FACTS`] per statement, fit this use.
    const fn admits(self, cached: usize, missing: usize) -> bool {
        let statements = cached.saturating_add(missing.div_ceil(MAX_FACTS));
        match self {
            Self::Preprove => true,
            Self::EvidenceBatch => statements <= MAX_EVIDENCE_FACT_STATEMENTS,
        }
    }
}

/// Retain the longest coverage-ordered cache prefix that leaves enough slots
/// for all fresh fact groups. Rebuild its exact missing set after dropping any
/// tail receipts; a discarded receipt's verdict never counts as attached.
fn fit_cached_facts(
    requested: &BTreeSet<Hash>,
    statements: &[&FactStatement],
    purpose: FactUse,
) -> Result<(usize, BTreeSet<Hash>), ProofError> {
    let mut missing = requested.clone();
    let mut retained = purpose.admits(0, missing.len()).then_some(0);
    for (index, statement) in statements.iter().enumerate() {
        for fact in &statement.facts {
            missing.remove(&fact.id);
        }
        if purpose.admits(index + 1, missing.len()) {
            retained = Some(index + 1);
        }
    }
    let retained = retained.ok_or(ProofError::InvalidWitness)?;
    missing.clone_from(requested);
    for statement in &statements[..retained] {
        for fact in &statement.facts {
            missing.remove(&fact.id);
        }
    }
    Ok((retained, missing))
}

impl<P: ProgramProver> Sp1ProofSystem<P> {
    pub(super) fn compress_facts(
        &self,
        fact_program: &VkDigest,
        requests: &[FactRequest],
    ) -> Result<Vec<Arc<FactReceipt>>, ProofError> {
        // A batch may need many native Fact calls. Scope their priority without
        // holding the device between them or while waiting on fact single-flight.
        crate::backend::with_submission_priority(crate::backend::SubmissionPriority::Normal, || {
            self.compress_facts_inner(fact_program, requests)
        })
    }

    fn compress_facts_inner(
        &self,
        fact_program: &VkDigest,
        requests: &[FactRequest],
    ) -> Result<Vec<Arc<FactReceipt>>, ProofError> {
        if requests.len() > MAX_PREPROVED_REQUESTS {
            return Err(ProofError::InvalidWitness);
        }
        let known = self.with_fact_cache(fact_program, |cache| cache.verified())?;
        let mut recorder =
            FactRecorder::with_verifier(known, crate::native_bls::NativeBlstVerifier);
        for request in requests {
            recorder.check(request.clone());
        }
        self.ensure_facts(
            fact_program,
            recorder.finish().map_err(|_| ProofError::InvalidWitness)?,
            FactUse::Preprove,
        )
    }

    /// Receipts covering every request: cached receipts first, then new
    /// statements of at most [`MAX_FACTS`] proven requests each. Rejects a
    /// set `purpose` does not admit before proving anything.
    fn ensure_facts(
        &self,
        fact_program: &VkDigest,
        requests: Vec<(FactRequest, bool)>,
        purpose: FactUse,
    ) -> Result<Vec<Arc<FactReceipt>>, ProofError> {
        let fact = self.keys(fact_program)?;
        let _single_flight = self
            .fact_proving
            .lock()
            // This mutex is only a single-flight gate, not protected state.
            // A panicking prover must not permanently disable future evidence.
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let requested: BTreeSet<_> = requests.iter().map(|(request, _)| request.id()).collect();
        let mut uncovered = requested.clone();
        let mut receipts = self.with_fact_cache(fact_program, |cache| match purpose {
            FactUse::Preprove => cache.covering(&mut uncovered),
            FactUse::EvidenceBatch => {
                cache.covering_limited(&mut uncovered, MAX_EVIDENCE_FACT_STATEMENTS)
            }
        })?;
        let statements: Vec<_> = receipts.iter().map(|receipt| &receipt.statement).collect();
        let (retained, missing) = fit_cached_facts(&requested, &statements, purpose)?;
        receipts.truncate(retained);
        let requests: Vec<_> = requests
            .into_iter()
            .filter(|(request, _)| missing.contains(&request.id()))
            .collect();
        for group in pack_requests(requests).map_err(|_| ProofError::InvalidWitness)? {
            let statement = FactStatement {
                facts: group
                    .iter()
                    .map(|(request, valid)| ProvenFact {
                        id: request.id(),
                        valid: *valid,
                    })
                    .collect(),
            };
            let witness = FactWitness {
                requests: group.iter().map(|(request, _)| request.clone()).collect(),
                statement: statement.clone(),
            };
            let mut stdin = SP1Stdin::new();
            let bytes = borsh::to_vec(&witness).map_err(|_| ProofError::InvalidWitness)?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(ProofError::InvalidWitness);
            }
            stdin.write_vec(bytes);
            let bundle = crate::prove_compressed(&self.prover, &fact.pk, stdin)
                .map_err(|_| ProofError::BackendRejected)?;
            // Encode once: the length bounds the receipt and the bytes persist it.
            let encoded = receipt_codec::encode(&bundle).map_err(|_| ProofError::MalformedProof)?;
            let size = encoded.len();
            let receipt = Arc::new(FactReceipt::new(bundle, statement, &fact.vk, size)?);
            self.with_fact_cache(fact_program, |cache| {
                cache.insert(Arc::clone(&receipt), &encoded);
            })?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    pub(super) fn prove_batch(
        &self,
        witnesses: &[EvidenceWitness],
        execution: &ExecutionPrograms,
    ) -> Result<Vec<EvidenceArtifact>, ProofError> {
        crate::backend::with_submission_priority(crate::backend::SubmissionPriority::Normal, || {
            self.prove_batch_inner(witnesses, execution)
        })
    }

    fn prove_batch_inner(
        &self,
        witnesses: &[EvidenceWitness],
        execution: &ExecutionPrograms,
    ) -> Result<Vec<EvidenceArtifact>, ProofError> {
        // One batch is proven under the execution programs of the chunk it
        // is meant for: every witness must name that block program and this
        // backend must hold the fact and evidence programs.
        let (fact_program, evidence_program) = (execution.fact, execution.evidence);
        if fact_program != self.embedded.execution.fact
            || witnesses.is_empty()
            || witnesses.len() > MAX_EVIDENCE_BATCH
            || witnesses.iter().any(|witness| {
                witness.block_guest_vk_digest != execution.block
                    || witness.chain_spec.genesis_execution.fact != fact_program
            })
        {
            return Err(ProofError::InvalidWitness);
        }
        let fact = self.keys(&fact_program)?;
        let evidence = self.keys(&evidence_program)?;
        let known = self.with_fact_cache(&fact_program, |cache| cache.verified())?;
        let mut recorder =
            FactRecorder::with_verifier(known, crate::native_bls::NativeBlstVerifier);
        let statements = validate_evidence_set_using(witnesses, &mut recorder)
            .map_err(|_| ProofError::InvalidWitness)?;
        let batch =
            EvidenceBatch::new(&statements, fact_program).ok_or(ProofError::InvalidWitness)?;
        let accepted = self.accepted_block_receipts(&mut recorder)?;
        let facts = self.ensure_facts(
            &fact_program,
            recorder.finish().map_err(|_| ProofError::InvalidWitness)?,
            FactUse::EvidenceBatch,
        )?;
        let input = EvidenceBatchWitness {
            witnesses: witnesses.to_vec(),
            facts: facts
                .iter()
                .map(|receipt| receipt.statement.clone())
                .collect(),
            receipts: accepted
                .iter()
                .map(|(receipt, _, _)| receipt.clone())
                .collect(),
            fact_guest_vk_digest: fact_program,
        };
        let (actual, _) =
            validate_evidence_batch(&input).map_err(|_| ProofError::InvalidWitness)?;
        if actual != batch {
            return Err(ProofError::PublicInputMismatch);
        }
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&input).map_err(|_| ProofError::InvalidWitness)?);
        // The Guest verifies facts, then accepted receipts, in this order.
        for receipt in facts {
            push_receipt(&mut stdin, &receipt.bundle, &fact.vk)?;
        }
        for (_, bundle, keys) in &accepted {
            push_receipt(&mut stdin, bundle, &keys.vk)?;
        }
        let proof = prove_compressed(&self.prover, &evidence.pk, stdin)
            .map_err(|_| ProofError::BackendRejected)?;
        verify_receipt(&proof, &batch, &evidence.vk)?;
        let bytes = receipt_codec::encode(&proof).map_err(|_| ProofError::MalformedProof)?;
        if bytes.len() > neutrin0_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES {
            return Err(ProofError::MalformedProof);
        }
        Ok(evidence_artifacts(
            statements,
            &batch,
            evidence_program,
            &bytes,
        ))
    }

    /// Receipts the offences need valid are verified by recursion under
    /// their own programs, which this backend must hold.
    fn accepted_block_receipts(
        &self,
        recorder: &mut FactRecorder<crate::native_bls::NativeBlstVerifier>,
    ) -> Result<Vec<AcceptedBlockReceipt<P>>, ProofError> {
        let mut accepted = Vec::new();
        for (key, proof) in recorder.take_accepted() {
            let bundle = borsh::from_slice::<Sp1BlockProof>(&proof.proof_bytes)
                .map_err(|_| ProofError::MalformedProof)?
                .to_sp1()
                .map_err(|_| ProofError::MalformedProof)?;
            let statement = borsh::from_slice(bundle.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
            accepted.push((
                AcceptedReceipt {
                    block_guest_vk_digest: key,
                    statement,
                },
                bundle,
                self.keys(&key)?,
            ));
        }
        Ok(accepted)
    }
}

/// One artifact per statement, each opening its leaf in the proven batch and
/// carrying the shared receipt bytes.
fn evidence_artifacts(
    statements: Vec<neutrin0_consensus_types::evidence::EvidenceStatement>,
    batch: &EvidenceBatch,
    evidence_program: VkDigest,
    bytes: &[u8],
) -> Vec<EvidenceArtifact> {
    let leaves: Vec<_> = statements.iter().map(commitment).collect();
    statements
        .into_iter()
        .enumerate()
        .map(|(index, statement)| EvidenceArtifact {
            membership: EvidenceMembership {
                batch: batch.clone(),
                opening: MerkleOpening::build(&leaves, index).expect("existing batch leaf"),
            },
            evidence_guest_vk_digest: evidence_program,
            statement,
            proof_bytes: bytes.to_vec(),
        })
        .collect()
}

#[cfg(test)]
mod tests;
