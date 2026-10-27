//! Authentication, durable publication and order-independent source replay.

use crate::{Engine, StoreError};
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_consensus_types::{
    BlockProof, FinalityVote, QuorumCertificate, RoundChange, VoteAttestation,
};
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_prover_chunk::bls::Verifier as _;
use neutrin0_storage::Database;

mod replay;

/// Every prevote quorum `artifact` carries, including a standalone quorum, in
/// declaration order.
pub(crate) fn carried_quorums(
    artifact: &SignedArtifact,
) -> impl Iterator<Item = &QuorumCertificate> {
    let (own, attestations, reports): (_, &[VoteAttestation], &[RoundChange]) = match artifact {
        SignedArtifact::Quorum(quorum) => (Some(quorum), &[], &[]),
        SignedArtifact::Vote(vote) => (None, &vote.attestations, &[]),
        SignedArtifact::Proposal(proposal) => (proposal.valid_quorum.as_ref(), &[], &[]),
        SignedArtifact::RoundChange(report) => (report.highest_quorum.as_ref(), &[], &[]),
        SignedArtifact::RoundChangeCertificate(certificate) => (None, &[], &certificate.reports),
        SignedArtifact::BlockProof(_) | SignedArtifact::NilVote(_) => (None, &[], &[]),
    };
    let unlocks = attestations
        .iter()
        .filter_map(|claim| claim.unlock_quorum.as_ref());
    let highest = reports
        .iter()
        .filter_map(|report| report.highest_quorum.as_ref());
    own.into_iter().chain(unlocks).chain(highest)
}

impl<DB: Database> Engine<DB> {
    pub(crate) fn verify_bft_nil_conflict(
        &self,
        index: u32,
        value: &neutrin0_consensus_types::IndexedVote,
        nil: &neutrin0_consensus_types::IndexedNilVote,
    ) -> Result<(), crate::SlashingError> {
        neutrin0_prover_chunk::slashing::verify_conflicting_nil_vote_using(
            self.consensus_domain(),
            &self.forensic_validators(value.data.chunk_id)?,
            index,
            value,
            nil,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| crate::SlashingError::EvidenceFieldsInconsistent)
    }

    pub(crate) fn verify_bft_leader_conflict(
        &self,
        index: u32,
        first: &neutrin0_consensus_types::BftProposal,
        second: &neutrin0_consensus_types::BftProposal,
    ) -> Result<(), crate::SlashingError> {
        let (validators, seed) = self.forensic_context(first.chunk.chunk_id)?;
        neutrin0_prover_chunk::slashing::verify_double_bft_proposal_using(
            self.consensus_domain(),
            &validators,
            &seed,
            index,
            first,
            second,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| crate::SlashingError::EvidenceFieldsInconsistent)
    }

    /// Authenticate every vote/attestation equation and persist the exact envelope.
    /// Invalid unlock declarations remain available for objective attribution.
    pub fn retain_signed_vote(
        &mut self,
        vote: &FinalityVote,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.authenticate_artifact_vote(vote)?;
        let artifact = SignedArtifact::Vote(vote.clone());
        self.publish_signed_artifact(vote.data.chunk_id, &artifact, false)
    }

    fn authenticate_artifact_vote(&self, vote: &FinalityVote) -> Result<(), StoreError<DB::Error>> {
        let validators = self
            .forensic_validators(vote.data.chunk_id)
            .map_err(|_| StoreError::Corrupt("artifact source outside authenticated context"))?;
        neutrin0_prover_chunk::finality::verify_vote_signatures_using(
            self.consensus_domain(),
            &validators,
            vote,
            &self.chain_spec().consensus,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| StoreError::Corrupt("artifact vote authentication"))
    }

    /// Persist an independently verified lock quorum under the authenticated source set.
    pub fn retain_signed_quorum(
        &mut self,
        quorum: &QuorumCertificate,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.authenticate_artifact_quorum(quorum)?;
        let artifact = SignedArtifact::Quorum(quorum.clone());
        self.publish_signed_artifact(quorum.data.chunk_id, &artifact, false)
    }

    pub(super) fn authenticate_artifact_quorum(
        &self,
        quorum: &QuorumCertificate,
    ) -> Result<(), StoreError<DB::Error>> {
        let validators = self
            .forensic_validators(quorum.data.chunk_id)
            .map_err(|_| StoreError::Corrupt("quorum source outside authenticated context"))?;
        let params = &self.chain_spec().consensus;
        neutrin0_prover_chunk::slashing::verify_quorum_using(
            self.consensus_domain(),
            &validators,
            quorum,
            (
                params.bft_prevote_quorum_numerator,
                params.bft_prevote_quorum_denominator,
            ),
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| StoreError::Corrupt("artifact quorum authentication"))
    }

    /// Persist exact proof bytes only after binding every public input to a locally
    /// authenticated header and historical membership. The caller separately
    /// classifies proof validity; a stored source is not a proof acceptance token.
    pub fn retain_signed_proof(
        &mut self,
        proof: &BlockProof,
    ) -> Result<Hash, StoreError<DB::Error>> {
        let source = self.authenticate_artifact_proof(proof)?;
        let artifact = SignedArtifact::BlockProof(proof.clone());
        self.publish_signed_artifact(source, &artifact, false)
    }

    /// Recheck source context and signatures before admitting an availability hint.
    /// A block source is bound to authenticated inputs, without accepting its proof.
    pub fn validate_signed_artifact(&self, artifact: &SignedArtifact) -> bool {
        match artifact {
            SignedArtifact::Vote(vote) => self.authenticate_artifact_vote(vote).is_ok(),
            SignedArtifact::Quorum(quorum) => self.authenticate_artifact_quorum(quorum).is_ok(),
            SignedArtifact::BlockProof(proof) => self.authenticate_artifact_proof(proof).is_ok(),
            other => self.authenticate_bft_source(other),
        }
    }

    /// Verify and persist a current signed source; local publication has reserved capacity.
    pub fn retain_signed_artifact(
        &mut self,
        artifact: &SignedArtifact,
        local: bool,
    ) -> Result<Hash, StoreError<DB::Error>> {
        if !self.validate_signed_artifact(artifact) {
            return Err(StoreError::Corrupt("signed source authentication"));
        }
        let chunk = artifact
            .chunk_id(self.chunk_size())
            .ok_or(StoreError::Corrupt("signed source range"))?;
        self.publish_signed_artifact(chunk, artifact, local)
    }

    /// Prune expired sources, then persist an authenticated `artifact` of
    /// `chunk`. A local artifact and its carried unlock quorums use capacity
    /// reserved from peer artifacts.
    fn publish_signed_artifact(
        &mut self,
        chunk: ChunkId,
        artifact: &SignedArtifact,
        local: bool,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.prune_availability_sources()?;
        if local {
            let mut protected = self.protected_local_artifacts(chunk)?;
            if let SignedArtifact::Vote(value) = artifact {
                for claim in &value.attestations {
                    if let Some(quorum) = &claim.unlock_quorum
                        && self.authenticate_artifact_quorum(quorum).is_ok()
                    {
                        let dependency = SignedArtifact::Quorum(quorum.clone());
                        self.store_mut().put_local_signed_artifact_protected(
                            chunk,
                            &dependency,
                            &protected,
                        )?;
                        protected.push(dependency.id());
                    }
                }
            }
            self.store_mut()
                .put_local_signed_artifact_protected(chunk, artifact, &protected)
        } else {
            self.store_mut().put_signed_artifact(chunk, artifact)
        }
    }

    fn protected_local_artifacts(&self, chunk: u64) -> Result<Vec<Hash>, StoreError<DB::Error>> {
        let Some(session) = self.bft_session(chunk) else {
            return Ok(Vec::new());
        };
        let lock = session.highest_lock_quorum();
        let valid = session.highest_valid_quorum();
        let mut ids: Vec<_> = lock
            .into_iter()
            .chain(valid)
            .map(|quorum| SignedArtifact::Quorum(quorum.clone()).id())
            .collect();
        if let Some(lock) = lock {
            for item in self.store().signed_artifact_metadata_for_chunk(chunk)? {
                if item.chunk_id == chunk
                    && item.local
                    && item.kind
                        == neutrin0_consensus_types::signed_artifacts::SignedArtifactKind::Vote
                    && item.phase == Some(neutrin0_consensus_types::FinalityVotePhase::Precommit)
                    && item.round == Some(lock.data.round)
                    && item.target == Some(lock.data.chunk_hash)
                {
                    ids.push(item.id);
                }
            }
        }
        Ok(ids)
    }

    fn authenticate_bft_source(&self, artifact: &SignedArtifact) -> bool {
        let Some(chunk) = artifact.chunk_id(self.chunk_size()) else {
            return false;
        };
        let Ok((validators, seed)) = self.forensic_context(chunk) else {
            return false;
        };
        let params = &self.chain_spec().consensus;
        let fraction = (
            params.bft_prevote_quorum_numerator,
            params.bft_prevote_quorum_denominator,
        );
        let mut verifier = self.bls_verifier.borrow_mut();
        let domain = self.consensus_domain();
        match artifact {
            SignedArtifact::Proposal(value) => {
                neutrin0_consensus_types::bft_leader(
                    domain.chain_id,
                    chunk,
                    value.round,
                    &seed,
                    &validators,
                ) == Some(value.proposer_index)
                    && value.chunk.active_validator_set_root
                        == neutrin0_consensus_types::evidence::commitment(&validators)
                    && validators
                        .get(value.proposer_index as usize)
                        .is_some_and(|validator| {
                            verifier.verify(
                                &validator.pubkey,
                                &value.signing_message(domain),
                                &value.signature,
                            )
                        })
            }
            SignedArtifact::NilVote(value) => neutrin0_prover_chunk::bft::verify_nil_vote_using(
                domain,
                &validators,
                value,
                &mut *verifier,
            )
            .is_ok(),
            SignedArtifact::RoundChange(value) => {
                neutrin0_prover_chunk::bft::verify_round_change_using(
                    domain,
                    &validators,
                    value,
                    fraction,
                    &mut *verifier,
                )
                .is_ok()
            }
            SignedArtifact::RoundChangeCertificate(value) => {
                neutrin0_prover_chunk::bft::verify_round_change_certificate_using(
                    domain,
                    &validators,
                    value,
                    fraction,
                    &mut *verifier,
                )
                .is_ok()
            }
            _ => false,
        }
    }

    fn authenticate_artifact_proof(
        &self,
        proof: &BlockProof,
    ) -> Result<u64, StoreError<DB::Error>> {
        let source = self
            .chunk_of_height(proof.height)
            .ok_or(StoreError::Corrupt("artifact proof range"))?;
        let validators = self
            .forensic_validators(source)
            .map_err(|_| StoreError::Corrupt("artifact proof source"))?;
        let header = self
            .store()
            .get_header(&proof.block_hash)?
            .or(self.store().reporter_header(&proof.block_hash)?)
            .ok_or(StoreError::Corrupt("artifact proof header unavailable"))?;
        if header.height != proof.height || header.hash() != proof.block_hash {
            return Err(StoreError::Corrupt("artifact proof header mismatch"));
        }
        let first = neutrin0_primitives::ConsensusBoundary::first(self.chain_spec());
        let before = if header.parent_hash == first.block_hash {
            first.state_root
        } else {
            self.store()
                .get_header(&header.parent_hash)?
                .or(self.store().reporter_header(&header.parent_hash)?)
                .ok_or(StoreError::Corrupt("artifact proof parent unavailable"))?
                .state_root
        };
        let record = self.store().historical_chunk(source)?;
        let (vm_code_hash, block_program) = if let Some(record) = record {
            (record.runtime_code_hash, record.block_guest_vk_digest)
        } else {
            let programs = self
                .programs_for_height(header.height)
                .map_err(|_| StoreError::Corrupt("artifact proof program unavailable"))?;
            (programs.runtime_code_hash, programs.execution.block)
        };
        let proposer_address = validators
            .get(header.proposer_index as usize)
            .ok_or(StoreError::Corrupt("artifact proof proposer"))?
            .withdrawal_credentials;
        let finalized = if source == 0 {
            // The specification pins the complete genesis program set, so
            // process configuration never reconstructs or reinterprets this source.
            neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(self.chain_spec())
        } else {
            self.store()
                .consensus_boundary(source)?
                .or(self.store().reporter_boundary(source)?)
                .ok_or(StoreError::Corrupt("artifact proof boundary unavailable"))?
        };
        let expected = crate::prove::header_public_inputs(
            &neutrin0_consensus_types::runtime::ConsensusExecutionContext {
                slot: header.slot,
                timestamp: header.timestamp,
                parent_block_hash: header.parent_hash,
                proposer_vrf_output: neutrin0_vrf::proof_output(&header.vrf_proof),
                finalized,
            },
            self.chain_spec().chain_id,
            &header,
            before,
            proof.block_hash,
            &neutrin0_primitives::ProgramSet {
                runtime_code_hash: vm_code_hash,
                execution: neutrin0_primitives::ExecutionPrograms {
                    block: block_program,
                    ..finalized.programs.execution
                },
            },
            proposer_address,
        );
        if proof.public_inputs != expected {
            return Err(StoreError::Corrupt("artifact proof public inputs mismatch"));
        }
        Ok(source)
    }
}
