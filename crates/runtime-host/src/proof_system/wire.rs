//! Borsh wire envelopes around SP1 block and chunk receipts.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_prover_chunk::receipt_codec;
use sp1_sdk::SP1ProofWithPublicValues;

use crate::{Sp1HostError, guarded};

/// Largest chunk-proof envelope accepted off the wire, leaving room for its
/// Borsh length prefix inside a History proof receipt.
const CHUNK_PROOF_WIRE_LIMIT: usize =
    neutrin0_consensus_types::history_proof::MAX_HISTORY_RECEIPT_BYTES - 4;

/// Declare a borsh wire wrapper around a bincode-serialized
/// [`SP1ProofWithPublicValues`].
///
/// Borsh on the outside satisfies the `ProofSystem` associated-type bounds
/// while the inside keeps SP1's native serde format. `$wire_limit` bounds
/// the envelope before decoding and `$decode_limit` bounds the decoder.
macro_rules! sp1_wire_proof {
    ($(#[$meta:meta])* $name:ident, wire = $wire_limit:expr, decode = $decode_limit:expr $(,)?) => {
        $(#[$meta])*
        #[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            /// `receipt_codec::encode(&SP1ProofWithPublicValues)` bytes.
            pub bytes: Vec<u8>,
        }

        impl $name {
            /// Serialize an SP1 proof bundle for storage on the wire.
            pub fn from_sp1(proof: &SP1ProofWithPublicValues) -> Result<Self, Sp1HostError> {
                let bytes = receipt_codec::encode(proof)
                    .map_err(|err| Sp1HostError::Codec(err.to_string()))?;
                Ok(Self { bytes })
            }

            /// Decode the inner SP1 proof bundle, rejecting oversized envelopes
            /// and every encoding but the canonical one.
            pub fn to_sp1(&self) -> Result<SP1ProofWithPublicValues, Sp1HostError> {
                if self.bytes.len() > $wire_limit {
                    return Err(Sp1HostError::Codec(concat!(
                        stringify!($name),
                        " exceeds wire limit"
                    )
                    .to_owned()));
                }
                let bundle = guarded(|| {
                    receipt_codec::decode_canonical::<SP1ProofWithPublicValues, { $decode_limit }>(
                        &self.bytes,
                    )
                })
                .map_err(|_| Sp1HostError::Sdk("receipt decoder panicked".into()))?
                .map_err(|err| Sp1HostError::Codec(err.to_string()))?;
                // Verification ignores the TEE attestation, so it would give
                // one proof unboundedly many byte identities.
                if bundle.tee_proof.is_some() {
                    return Err(Sp1HostError::Codec("receipt carries a TEE attestation".into()));
                }
                Ok(bundle)
            }
        }
    };
}

sp1_wire_proof! {
    /// Wire form of an SP1 block proof produced by the EVM runtime guest.
    /// Public values are a borsh-encoded [`RuntimeBlockOutput`].
    ///
    /// [`RuntimeBlockOutput`]: neutrin0_runtime_abi::RuntimeBlockOutput
    Sp1BlockProof,
    wire = neutrin0_prover_chunk::proof_verification::MAX_PROOF_BYTES - 4,
    decode = neutrin0_prover_chunk::proof_verification::MAX_PROOF_BYTES,
}

sp1_wire_proof! {
    /// Wire form of an SP1 complete consensus chunk proof. Public values are a
    /// borsh-encoded [`neutrin0_consensus_types::history_proof::ChunkReceiptStatement`].
    Sp1ChunkProof,
    wire = CHUNK_PROOF_WIRE_LIMIT,
    decode = neutrin0_consensus_types::history_proof::MAX_HISTORY_RECEIPT_BYTES,
}
