//! Wire format between a node and its signer: length-prefixed borsh frames,
//! one request and its response at a time on a connection.

use std::io::{Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_engine::SignRequest;
use neutrin0_primitives::{BlsPublicKey, BlsSignature};

/// Bound on one frame: a round leader's proposal with its carried
/// certificates is the largest request.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// What a node asks its signer.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// The public keys the signer holds.
    Identities,
    /// Sign `request` with `identity`'s key.
    Sign {
        /// Key to sign with.
        identity: BlsPublicKey,
        /// What to sign.
        request: Box<SignRequest>,
    },
}

/// The signer's answer.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub enum Response {
    /// The public keys the signer holds.
    Identities(Vec<BlsPublicKey>),
    /// The request's signatures, in [`SignRequest::sign_with`] order.
    Signatures(Vec<BlsSignature>),
    /// Why the request was not signed.
    Refused(Refusal),
}

/// Why a signer refused a request.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Refusal {
    /// The signer holds no key of that identity.
    #[error("the signer holds no such key")]
    UnknownIdentity,
    /// This client may not use that key.
    #[error("this client may not use that key")]
    NotPermitted,
    /// It would conflict with a message already signed.
    #[error("conflicts with a message already signed")]
    Conflict,
    /// It is at an earlier slot or round than one already signed.
    #[error("earlier than a message already signed")]
    Regression,
    /// It is for a chunk below the journal's window.
    #[error("below the signing journal's window")]
    Expired,
    /// The journal could not be read or written.
    #[error("signing journal: {0}")]
    Storage(String),
    /// It is further ahead of the highest slot or chunk signed than time
    /// since then allows.
    #[error("ahead of the pace slots and chunks can advance")]
    TooFarAhead,
}

/// Write `value` as one frame.
///
/// # Errors
/// Returns write failures and a value above [`MAX_FRAME`].
pub fn write_frame(out: &mut impl Write, value: &impl BorshSerialize) -> std::io::Result<()> {
    let bytes = borsh::to_vec(value)?;
    let length = u32::try_from(bytes.len())
        .ok()
        .filter(|length| *length <= MAX_FRAME)
        .ok_or_else(|| std::io::Error::other("frame exceeds its bound"))?;
    out.write_all(&length.to_le_bytes())?;
    out.write_all(&bytes)?;
    out.flush()
}

/// Read one frame and decode it.
///
/// # Errors
/// Returns read failures, a frame above [`MAX_FRAME`] and a value that does
/// not decode.
pub fn read_frame<T: BorshDeserialize>(input: &mut impl Read) -> std::io::Result<T> {
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length);
    if length > MAX_FRAME {
        return Err(std::io::Error::other("frame exceeds its bound"));
    }
    let mut bytes = vec![0; length as usize];
    input.read_exact(&mut bytes)?;
    borsh::from_slice(&bytes)
}
