//! Assembly of the complete consensus witness of a chunk on a branch.

extern crate alloc;

use alloc::vec::Vec;
use neutrin0_consensus_types::{AggregatedVote, Chunk, FinalityCert};
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::{
    body::ConsensusBody,
    consensus::{
        ConsensusWitness, as_chunk, context_boundary, genesis_context, validate_candidate,
    },
    execution::{ExecutionContext, ProvenBlock},
    history::HistoryWitness,
};
use neutrin0_storage::Database;

use super::{BranchWitness, PreparedConsensusChunk};
use crate::{BlockState, Engine, FinalizeError};

impl<DB: Database> Engine<DB> {
    /// Load the trusted incoming consensus boundary; no peer input selects it.
    pub fn consensus_boundary(
        &self,
        chunk_id: ChunkId,
    ) -> Result<(ExecutionContext, Hash, HistoryWitness), FinalizeError<DB::Error>> {
        self.validate_chunk_id_sequence(chunk_id)?;
        let spec = self.chain_spec();
        if chunk_id == 0 {
            let programs = self.genesis_programs();
            return Ok((
                genesis_context(spec, programs),
                spec.genesis_seed,
                HistoryWitness::default(),
            ));
        }
        let previous = self
            .store()
            .get_consensus_state()?
            .ok_or(ProofError::InvalidWitness)?;
        if previous.next_context.chunk_id != chunk_id
            || context_boundary(&previous.next_context, previous.next_seed)
                .map_err(|_| ProofError::InvalidWitness)?
                != previous.boundary
            || previous.frontier.root() != Some(previous.boundary.history_root)
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok((
            previous.next_context,
            previous.next_seed,
            HistoryWitness {
                frontier: previous.frontier,
                records: Vec::new(),
            },
        ))
    }

    /// Assemble the complete witness from canonical blocks and the exact
    /// chunk-end trie root, even when the live runtime has advanced further.
    pub fn prepare_consensus_chunk<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        proof_system: &P,
    ) -> Result<PreparedConsensusChunk<P>, FinalizeError<DB::Error>> {
        let (_, end) = self
            .chunk_heights(chunk_id)
            .ok_or(FinalizeError::HeightRangeOverflow)?;
        let end_hash = self
            .store()
            .get_block_hash_by_height(end)?
            .ok_or(FinalizeError::MissingBlock { height: end })?;
        self.prepare_consensus_chunk_on_branch(chunk_id, end_hash, None, proof_system)
    }

    /// Prepare the fixed, previously signed BFT branch under the current proof
    /// backend, even if fork choice currently selects a competing branch.
    /// Without a session, prepare the current canonical candidate.
    pub fn prepare_bft_consensus_chunk<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        proof_system: &P,
    ) -> Result<PreparedConsensusChunk<P>, FinalizeError<DB::Error>> {
        let Some(session) = self.bft_session(chunk_id) else {
            return self.prepare_consensus_chunk(chunk_id, proof_system);
        };
        let prepared = self.prepare_consensus_chunk_on_branch(
            chunk_id,
            session.end_block_hash(),
            session.named_receipts().as_deref(),
            proof_system,
        )?;
        if as_chunk(&prepared.candidate.execution.chunk).hash() != session.chunk_hash() {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(prepared)
    }

    /// Prepare a complete candidate on an explicitly selected branch. Every
    /// receipt and consensus field is authenticated under the current backend.
    /// `receipts` names one statement key per height (a proposal's or
    /// certificate's selection); without it the locally preferred receipts
    /// are used (design 08).
    ///
    /// # Errors
    /// Returns unavailable ancestry, invalid receipts or consensus bindings.
    pub fn prepare_consensus_chunk_on_branch<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        end_hash: Hash,
        receipts: Option<&[Hash]>,
        proof_system: &P,
    ) -> Result<PreparedConsensusChunk<P>, FinalizeError<DB::Error>> {
        let (witness, proofs) =
            self.consensus_witness_on_branch(chunk_id, end_hash, receipts, proof_system)?;
        let candidate = validate_candidate(&witness).map_err(|_| ProofError::InvalidWitness)?;
        Ok(PreparedConsensusChunk {
            witness,
            candidate,
            proofs,
            ratified: Vec::new(),
        })
    }

    /// The complete, not yet validated witness of
    /// [`Self::prepare_consensus_chunk_on_branch`] with its verified receipts.
    pub(crate) fn consensus_witness_on_branch<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        end_hash: Hash,
        receipts: Option<&[Hash]>,
        proof_system: &P,
    ) -> Result<BranchWitness<P>, FinalizeError<DB::Error>> {
        let guests = proof_system.programs().ok_or(ProofError::Unsupported)?;
        let (context, seed, _) = self.consensus_boundary(chunk_id)?;
        // A node can only prove chunks whose program set its backend holds;
        // otherwise it follows by verification until the programs arrive. The
        // chunk Guest is pinned: the backend must embed this chain's.
        if guests.chunk != self.chain_spec().genesis_chunk
            || !proof_system.can_prove(&neutrin0_consensus_types::history_proof::GuestPrograms {
                execution: context.programs.execution,
                chunk: guests.chunk,
            })
        {
            return Err(ProofError::Unsupported.into());
        }
        let headers = self.branch_headers(chunk_id, end_hash)?;
        if receipts.is_some_and(|keys| keys.len() != headers.len()) {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let (blocks, bodies, proofs) =
            self.proven_branch_blocks(headers, receipts, proof_system)?;
        let post_root = blocks
            .last()
            .ok_or(ProofError::InvalidWitness)?
            .header
            .state_root;
        let post_state = self.consensus_rotation_witness(post_root)?;
        let identity_sanctions = self.identity_sanctions_witness(&context, &post_state, &blocks)?;
        let history = self.store().history_witness(
            chunk_id,
            bodies
                .iter()
                .flat_map(|body| {
                    body.participation_acks
                        .iter()
                        .map(|vote| vote.data.chunk_id)
                })
                .chain(self.chain_spec().carried_chunk(chunk_id)),
        )?;
        let witness = ConsensusWitness {
            chain_spec: self.chain_spec().clone(),
            context,
            seed,
            blocks,
            bodies,
            post_state,
            identity_sanctions,
            history,
            finality_cert: unfilled_finality_cert(chunk_id),
            facts: Vec::new(),
            ratified: Vec::new(),
        };
        Ok((witness, proofs))
    }

    /// The headers of `chunk_id`'s range in height order on the branch ending
    /// at `end_hash`; the trusted context's chunk size is the specification's.
    fn branch_headers(
        &self,
        chunk_id: ChunkId,
        end_hash: Hash,
    ) -> Result<Vec<neutrin0_consensus_types::Header>, FinalizeError<DB::Error>> {
        let (start, end) = self
            .chunk_heights(chunk_id)
            .ok_or(FinalizeError::HeightRangeOverflow)?;
        let mut headers = Vec::new();
        let mut cursor = end_hash;
        for height in (start..=end).rev() {
            let header = self
                .store()
                .get_header(&cursor)?
                .ok_or(FinalizeError::MissingBlock { height })?;
            if header.height != height || header.hash() != cursor {
                return Err(ProofError::PublicInputMismatch.into());
            }
            cursor = header.parent_hash;
            headers.push(header);
        }
        headers.reverse();
        Ok(headers)
    }

    /// Every block of the range with its verified receipt, the named one when
    /// `receipts` selects, and its consensus body and backend proof.
    #[allow(
        clippy::type_complexity,
        reason = "The three lanes travel together into the witness."
    )]
    fn proven_branch_blocks<P: ProofSystem>(
        &self,
        headers: Vec<neutrin0_consensus_types::Header>,
        receipts: Option<&[Hash]>,
        proof_system: &P,
    ) -> Result<(Vec<ProvenBlock>, Vec<ConsensusBody>, Vec<P::BlockProof>), FinalizeError<DB::Error>>
    {
        let mut blocks = Vec::new();
        let mut bodies = Vec::new();
        let mut proofs = Vec::new();
        for (index, header) in headers.into_iter().enumerate() {
            let height = header.height;
            let hash = header.hash();
            let state = self
                .store()
                .get_block_state(&hash)?
                .unwrap_or(BlockState::BlockProduced);
            if !matches!(state, BlockState::Proven) {
                return Err(FinalizeError::BlockNotProven { hash, state });
            }
            let wire = match receipts {
                Some(keys) => {
                    let statement_key = keys[index];
                    self.store()
                        .block_receipt_by_key(&hash, &statement_key)?
                        .map(|receipt| receipt.proof)
                        .ok_or(FinalizeError::MissingBlockReceipt {
                            hash,
                            statement_key,
                        })?
                }
                None => self
                    .store()
                    .get_block_proof(&hash)?
                    .ok_or(FinalizeError::MissingBlockProof { hash })?,
            };
            if wire.height != height || wire.block_hash != hash {
                return Err(ProofError::PublicInputMismatch.into());
            }
            let proof = borsh::from_slice(&wire.proof_bytes)?;
            let statement = proof_system.verify_block_statement(&proof, &wire.public_inputs)?;
            if statement.prover_address != wire.prover_address
                || crate::prove::statement_key(&statement) != wire.statement_key
            {
                return Err(ProofError::PublicInputMismatch.into());
            }
            let body = self
                .store()
                .get_body(&hash)?
                .ok_or(ProofError::InvalidWitness)?;
            blocks.push(ProvenBlock {
                header,
                public_inputs: wire.public_inputs,
                output: statement.output,
                prover_address: statement.prover_address,
            });
            bodies.push(ConsensusBody::from_body(&body).map_err(|_| ProofError::InvalidWitness)?);
            proofs.push(proof);
        }
        Ok((blocks, bodies, proofs))
    }
}

/// The certificate slot of a candidate witness before certification.
/// Candidate validation does not inspect finality. The prepared
/// input receives the authenticated live certificate before proving.
fn unfilled_finality_cert(chunk_id: ChunkId) -> FinalityCert {
    let aggregate = AggregatedVote {
        aggregation_bits: neutrin0_primitives::BitVec::default(),
        signature: [0; 96],
    };
    FinalityCert {
        proof_manifests: Vec::new(),
        proposal: neutrin0_consensus_types::BftProposal {
            chunk: Chunk {
                next_identity_sanctions_root: [0; 32],

                chunk_id,
                start_height: 0,
                end_height: 0,
                start_state_root: [0; 32],
                end_state_root: [0; 32],
                start_block_hash: [0; 32],
                end_block_hash: [0; 32],
                block_hash_root: [0; 32],
                block_proof_root: [0; 32],
                vrf_proof_root: [0; 32],
                active_validator_set_root: [0; 32],
                next_validator_set_root: [0; 32],
                da_root: [0; 32],
            },
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
        chunk_id,
        round: 0,
        chunk_hash: [0; 32],
        prevote: aggregate.clone(),
        precommit: aggregate,
        active_validator_set_root: [0; 32],
    }
}
