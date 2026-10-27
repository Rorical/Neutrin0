//! The persisted [`BlockWitness`] bundle and its bounded borsh codec.

// The envelope-bounded writer is shared with the crate's block stdin encoder.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible writer of a private module; `pub` would be unreachable."
)]

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_runtime_abi::RuntimeBlockInput;

/// Encode the persisted [`BlockWitness`], including ordered proof attachments.
///
/// The Guest receives only the input and state fields as normal stdin.
///
/// # Errors
/// Returns a codec error when the input, witness or attachments cannot be encoded.
pub fn encode_witness_bundle(
    input: &RuntimeBlockInput,
    witness: &neutrin0_runtime_abi::StateWitness,
    evidence_proofs: &[neutrin0_consensus_types::evidence::EvidenceArtifact],
) -> Result<Vec<u8>, borsh::io::Error> {
    let mut bytes = ProvingInputWriter::new(input.evidence_anchor.max_block_proving_input_bytes)?;
    BorshSerialize::serialize(input, &mut bytes)?;
    BorshSerialize::serialize(witness, &mut bytes)?;
    BorshSerialize::serialize(evidence_proofs, &mut bytes)?;
    Ok(bytes.into_bytes())
}

/// Serialization sink that rejects a write before growing past its allocation envelope.
pub(crate) struct ProvingInputWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl ProvingInputWriter {
    pub(crate) fn new(limit: u64) -> Result<Self, borsh::io::Error> {
        if limit == 0 || limit > neutrin0_primitives::MAX_BLOCK_PROVING_INPUT_BYTES {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid proving allocation limit",
            ));
        }
        let limit = usize::try_from(limit).map_err(|_| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "proving allocation limit is unrepresentable",
            )
        })?;
        Ok(Self {
            bytes: Vec::new(),
            limit,
        })
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl borsh::io::Write for ProvingInputWriter {
    fn write(&mut self, bytes: &[u8]) -> borsh::io::Result<usize> {
        let Some(size) = self.bytes.len().checked_add(bytes.len()) else {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "proving input length overflow",
            ));
        };
        if size > self.limit {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "block proving envelope exceeds authenticated allocation limit",
            ));
        }
        if size > self.bytes.capacity() {
            self.bytes
                .try_reserve_exact(size - self.bytes.len())
                .map_err(|error| {
                    borsh::io::Error::new(borsh::io::ErrorKind::OutOfMemory, error.to_string())
                })?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> borsh::io::Result<()> {
        Ok(())
    }
}

/// Decode the complete persisted [`BlockWitness`] without trailing bytes.
///
/// Inverse of [`encode_witness_bundle`]; called by
/// [`neutrin0_proof_system::ProofSystem::prove_block`] before forwarding to the
/// SP1 prover.
///
/// # Errors
/// Returns [`borsh::io::Error`] if the blob is not a valid encoding
/// of the complete witness bundle.
pub fn decode_witness_bundle(bytes: &[u8]) -> Result<BlockWitness, borsh::io::Error> {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if length > neutrin0_primitives::MAX_BLOCK_PROVING_INPUT_BYTES {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "block proving envelope exceeds absolute allocation ceiling",
        ));
    }
    let bundle: BlockWitness = borsh::from_slice(bytes)?;
    if !bundle
        .input
        .evidence_anchor
        .accepts_proving_input_size(length)
    {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "block proving envelope exceeds authenticated allocation limit",
        ));
    }
    Ok(bundle)
}

/// Persisted proving input, including proof attachments outside STF semantics.
#[derive(BorshDeserialize, BorshSerialize)]
pub struct BlockWitness {
    /// Consensus transaction and execution context.
    pub input: RuntimeBlockInput,
    /// Authenticated state openings.
    pub state: neutrin0_runtime_abi::StateWitness,
    /// Ordered proof witnesses for the evidence statements.
    pub evidence_proofs: Vec<neutrin0_consensus_types::evidence::EvidenceArtifact>,
}
