//! Canonical Borsh commitments without temporary serialized buffers.

use borsh::{BorshSerialize, io};
use neutrin0_primitives::{Blake3Hasher, DomainTag, Hash};

/// A type committed by [`crate::evidence::commitment`]: the tag is hashed
/// ahead of its Borsh encoding, so separation between committed types never
/// rests on their encodings having different lengths.
pub trait Committed: BorshSerialize {
    /// Domain tag distinct to this type.
    const COMMITMENT_TAG: DomainTag;
}

struct HashWriter(Blake3Hasher);

impl io::Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Hash exactly `domain || borsh(value)` without allocating that byte string.
///
/// # Panics
/// Panics if the value cannot be encoded canonically, including oversized Borsh lengths.
#[must_use]
pub fn borsh_commitment<T: BorshSerialize + ?Sized>(domain: &[u8], value: &T) -> Hash {
    let mut writer = HashWriter(Blake3Hasher::new());
    writer.0.update(domain);
    value
        .serialize(&mut writer)
        .expect("canonical Borsh commitment");
    *writer.0.finalize().as_bytes()
}

macro_rules! committed {
    ($($type:ty => $tag:ident;)+) => {
        $(impl Committed for $type {
            const COMMITMENT_TAG: DomainTag = neutrin0_primitives::$tag;
        })+
    };
}

committed! {
    [neutrin0_primitives::Validator] => DOMAIN_VALIDATORS;
    alloc::vec::Vec<neutrin0_primitives::Validator> => DOMAIN_VALIDATORS;
    crate::evidence::EvidenceAnchor => DOMAIN_EVIDENCE_ANCHOR;
    crate::evidence::EvidenceContext => DOMAIN_EVIDENCE_CONTEXT;
    crate::evidence::EvidenceStatement => DOMAIN_EVIDENCE_STATEMENT;
    crate::participation::ParticipationVote => DOMAIN_PARTICIPATION_VOTE;
    crate::BlockProof => DOMAIN_BLOCK_PROOF;
    crate::history_proof::ChunkReceiptStatement => DOMAIN_CHUNK_STATEMENT;
    crate::BlockProofPublicInputs => DOMAIN_BLOCK_INPUTS;
    crate::ProgramPieceDescriptor => DOMAIN_PROGRAM_PIECE;
    crate::proving::CarriedCertificate => DOMAIN_CARRIED_CERT;
    crate::FinalityCert => DOMAIN_FINALITY_CERT;
    crate::VoteAttestation => DOMAIN_ATTESTATION_ID;
    crate::bft::NilVoteAttestation => DOMAIN_NIL_ATTESTATION_ID;
    crate::RoundChange => DOMAIN_ROUND_CHANGE_ID;
    crate::evidence::EvidenceBatch => DOMAIN_EVIDENCE_BATCH;
}

impl<T: Committed + ?Sized> Committed for &T {
    const COMMITMENT_TAG: DomainTag = T::COMMITMENT_TAG;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    #[test]
    fn streamed_commitments_preserve_framing_across_hash_chunks() {
        for length in [0, 1, 63, 64, 1023, 1024, 1025, 8193] {
            let value = (
                17_u64,
                vec![0xa7_u8; length],
                vec![vec![1_u8; 33], Vec::new()],
            );
            for domain in [b"".as_slice(), b"NTRO/streaming-test".as_slice()] {
                let mut encoded = domain.to_vec();
                encoded.extend(borsh::to_vec(&value).unwrap());
                assert_eq!(
                    borsh_commitment(domain, &value),
                    neutrin0_primitives::blake3_256(&encoded)
                );
            }
        }
        assert_ne!(
            borsh_commitment(b"", &vec![1_u8]),
            borsh_commitment(b"", &vec![1_u8, 0])
        );
    }
}
