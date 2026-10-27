//! Compact consensus body: ordinary transactions never enter the chunk Guest.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::{Body, Header};
use neutrin0_primitives::merkle_root_from_hashes;
use neutrin0_runtime_abi::{RuntimeTransaction, TransactionSummary};

use crate::{consensus::ConsensusError, history::HistoryError};
use neutrin0_consensus_types::evidence::commitment;

/// Only data actually consumed by consensus validation. The block proof binds
/// the omitted transaction DA lane; sanctions come from its public output.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusBody {
    /// Individually signed economic precommits: the header-committed vote DA lane.
    #[borsh(
        deserialize_with = "neutrin0_consensus_types::participation::read_participation_votes"
    )]
    pub participation_acks: Vec<neutrin0_consensus_types::participation::ParticipationVote>,
    /// Previous-chunk certificate selected before this chunk's execution.
    /// In each chunk after the first exactly one block carries it: the carrier,
    /// the first produced while holding that certificate. Its exact bytes bind
    /// the report choice.
    pub participation: Option<neutrin0_consensus_types::proving::CarriedCertificate>,
    /// Bytes-free descriptors of the program-artifact lane, in lane order.
    /// Each binds its piece bytes by hash and opens the piece in its
    /// artifact; the bytes never enter consensus validation (design 20).
    pub program_pieces: Vec<neutrin0_consensus_types::ProgramPieceDescriptor>,
}

impl ConsensusBody {
    /// Construct a compact witness after checking canonical transaction decoding.
    /// The block proof authenticates the omitted transaction bytes.
    pub fn from_body(body: &Body) -> Result<Self, HistoryError> {
        for bytes in &body.transactions {
            let _: RuntimeTransaction =
                borsh::from_slice(bytes).map_err(|_| HistoryError::Transaction)?;
        }
        if !body.programs_well_formed() {
            return Err(HistoryError::Program);
        }
        Ok(Self {
            participation_acks: body.participation_acks.clone(),
            participation: body.participation.clone(),
            program_pieces: body
                .programs
                .iter()
                .map(neutrin0_consensus_types::ProgramPiece::descriptor)
                .collect(),
        })
    }

    /// The program-lane references the block's execution consumed: every
    /// descriptor must authenticate its piece inside its artifact.
    pub fn program_refs(
        &self,
    ) -> Result<Vec<neutrin0_consensus_types::ProgramPieceRef>, ConsensusError> {
        self.program_pieces
            .iter()
            .map(|descriptor| {
                descriptor
                    .authenticates()
                    .then(|| descriptor.reference())
                    .ok_or(ConsensusError::Header)
            })
            .collect()
    }

    /// Bind every consumed byte to the header and the recursively authenticated
    /// block output.
    ///
    /// No ordinary transaction is decoded or hashed here.
    pub fn validate(
        &self,
        header: &Header,
        summary: &TransactionSummary,
    ) -> Result<(), ConsensusError> {
        if !neutrin0_consensus_types::participation::vote_lane_is_bounded(&self.participation_acks)
        {
            return Err(ConsensusError::Header);
        }
        let votes =
            neutrin0_consensus_types::participation::vote_lane_root(&self.participation_acks);
        if self.program_pieces.len() > neutrin0_consensus_types::MAX_PROGRAM_PIECES_PER_BLOCK {
            return Err(ConsensusError::Header);
        }
        let da = neutrin0_primitives::da_root_from_lane_roots([
            (summary.transaction_count, header.transactions_root),
            (
                neutrin0_consensus_types::participation::vote_lane_count(&self.participation_acks),
                votes,
            ),
            (
                u32::try_from(self.program_pieces.len()).map_err(|_| ConsensusError::Header)?,
                merkle_root_from_hashes(self.program_pieces.iter().map(commitment).collect()),
            ),
            (
                u32::from(self.participation.is_some()),
                merkle_root_from_hashes(self.participation.iter().map(commitment).collect()),
            ),
        ]);
        if header.votes_root != votes || header.da_root != da {
            return Err(ConsensusError::Header);
        }
        Ok(())
    }
}
