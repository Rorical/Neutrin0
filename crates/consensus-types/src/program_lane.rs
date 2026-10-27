//! Program-artifact pieces of the block body's data-availability lane (design 20).

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{Hash, blake3_256};

use crate::{evidence, hashing};

/// Fixed size of every program-artifact piece except the last one.
pub const MAX_PROGRAM_PIECE_BYTES: usize = 512 * 1024;
/// Upper bound of program-artifact pieces per block.
pub const MAX_PROGRAM_PIECES_PER_BLOCK: usize = 2;
/// Upper bound of one complete program artifact (runtime WASM or Guest ELF).
pub const MAX_PROGRAM_BYTES: u32 = 16 * 1024 * 1024;

/// Number of pieces an artifact of `total_len` bytes splits into.
#[must_use]
pub const fn program_piece_count(total_len: u32) -> u64 {
    (total_len as u64).div_ceil(MAX_PROGRAM_PIECE_BYTES as u64)
}

/// Content hash governance names for an artifact.
///
/// It is the counted Merkle root of the pieces' BLAKE3 hashes bound to the
/// artifact length. Every piece is authenticated against it on arrival, so a
/// forged piece can never spoil the reassembly of an honest artifact.
#[must_use]
pub fn program_content_hash(total_len: u32, root: Hash) -> Hash {
    crate::tagged_commitment(b"neutrin0-program-artifact", &(total_len, root))
}

/// The bytes-free form of a [`ProgramPiece`] the program lane commits.
///
/// `bytes_hash` binds the piece bytes, so the lane commitment authenticates
/// them, while the descriptor alone proves the piece belongs to its artifact:
/// the opening verifies `bytes_hash` under the artifact's piece tree. The
/// chunk Guest therefore checks program-lane pieces without their bytes.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct ProgramPieceDescriptor {
    /// Merkle root of the artifact's piece hashes.
    pub root: Hash,
    /// Length of the complete artifact.
    pub total_len: u32,
    /// Offset of the piece inside the artifact; a multiple of the piece size.
    pub offset: u32,
    /// `BLAKE3` of the piece bytes: the leaf the opening authenticates.
    pub bytes_hash: Hash,
    /// Opening of `bytes_hash` in the artifact's piece tree.
    pub opening: evidence::MerkleOpening,
}

impl ProgramPieceDescriptor {
    /// Content hash of the artifact the piece belongs to.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        program_content_hash(self.total_len, self.root)
    }

    /// `true` when the offsets and the opening shape are consistent and the
    /// opening authenticates `bytes_hash` at the piece index.
    #[must_use]
    pub fn authenticates(&self) -> bool {
        let piece = MAX_PROGRAM_PIECE_BYTES as u64;
        let (total, offset) = (u64::from(self.total_len), u64::from(self.offset));
        self.total_len > 0
            && self.total_len <= MAX_PROGRAM_BYTES
            && offset % piece == 0
            && offset < total
            && self.opening.count == program_piece_count(self.total_len)
            && self.opening.index == offset / piece
            && self.opening.siblings.len() <= 64
            && self.opening.verify(
                self.bytes_hash,
                evidence::counted_merkle_root(self.opening.count, self.root),
            )
    }

    /// The artifact, index and piece count the runtime tracks.
    #[must_use]
    pub fn reference(&self) -> ProgramPieceRef {
        ProgramPieceRef {
            artifact: self.content_hash(),
            index: self.opening.index,
            count: self.opening.count,
        }
    }
}

/// One authenticated program-lane piece as the runtime consumes it: which
/// artifact it belongs to, its index and the artifact's piece count.
///
/// The runtime records the pieces of artifacts a scheduled upgrade names, so
/// a switch activates only once every piece was published (design 20).
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProgramPieceRef {
    /// Content hash of the artifact.
    pub artifact: Hash,
    /// Piece index inside the artifact.
    pub index: u64,
    /// Number of pieces of the artifact.
    pub count: u64,
}

/// Commitment of the program-lane references a block's execution consumed;
/// zero for none.
#[must_use]
pub fn program_pieces_commitment(pieces: &[ProgramPieceRef]) -> Hash {
    if pieces.is_empty() {
        return [0; 32];
    }
    hashing::borsh_commitment(b"NTRO/program-pieces", pieces)
}

/// The references of a body's program lane, in lane order.
#[must_use]
pub fn program_piece_refs(programs: &[ProgramPiece]) -> Vec<ProgramPieceRef> {
    programs
        .iter()
        .map(|piece| piece.descriptor().reference())
        .collect()
}

/// One self-authenticating slice of a program artifact in the DA lane.
///
/// Its bytes open the artifact's piece Merkle tree at the piece index, and
/// the artifact's content hash follows from `total_len` and `root`. The lane
/// commits its [`ProgramPieceDescriptor`].
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct ProgramPiece {
    /// Merkle root of the artifact's piece hashes.
    pub root: Hash,
    /// Length of the complete artifact.
    pub total_len: u32,
    /// Offset of `bytes` inside the artifact; a multiple of the piece size.
    pub offset: u32,
    /// Piece bytes: exactly the piece size except for the last piece.
    pub bytes: Vec<u8>,
    /// Opening of `BLAKE3(bytes)` in the artifact's piece tree.
    pub opening: evidence::MerkleOpening,
}

impl ProgramPiece {
    /// Content hash of the artifact this piece belongs to.
    #[must_use]
    pub fn content_hash(&self) -> Hash {
        program_content_hash(self.total_len, self.root)
    }

    /// The bytes-free descriptor the program lane commits.
    #[must_use]
    pub fn descriptor(&self) -> ProgramPieceDescriptor {
        ProgramPieceDescriptor {
            root: self.root,
            total_len: self.total_len,
            offset: self.offset,
            bytes_hash: blake3_256(&self.bytes),
            opening: self.opening.clone(),
        }
    }

    /// `true` when sizes, offsets and the opening shape are consistent.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let piece = MAX_PROGRAM_PIECE_BYTES as u64;
        let (total, offset) = (u64::from(self.total_len), u64::from(self.offset));
        let expected_len = (total.saturating_sub(offset)).min(piece);
        self.total_len > 0
            && self.total_len <= MAX_PROGRAM_BYTES
            && offset % piece == 0
            && offset < total
            && self.bytes.len() as u64 == expected_len
            && self.opening.count == program_piece_count(self.total_len)
            && self.opening.index == offset / piece
            && self.opening.siblings.len() <= 64
    }

    /// `true` when the piece is well formed and its bytes open the artifact's
    /// piece tree at this index.
    #[must_use]
    pub fn authenticates(&self) -> bool {
        self.is_well_formed()
            && self.opening.verify(
                blake3_256(&self.bytes),
                evidence::counted_merkle_root(self.opening.count, self.root),
            )
    }
}
