//! Immediate native BLS checks with bounded reuse of exact equations.
//!
//! Only cryptographic verdicts are retained. Consensus membership, stake, quorum,
//! tuple, coverage and history policy must be checked on every admission.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use neutrin0_crypto::bls::{PublicKey, Signature};
use neutrin0_primitives::{BlsPublicKey, BlsSignature, Hash};
use neutrin0_prover_chunk::bls::Verifier;

extern crate alloc;

const MAX_VERDICTS: usize = 4096;

/// Immediate native verification with bounded reuse of cryptographic verdicts.
#[derive(Debug, Default)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "Keep this host verifier crate-private rather than exporting a consensus API."
)]
pub(crate) struct NativeBlsVerifier {
    verdicts: BTreeMap<Hash, bool>,
    order: VecDeque<Hash>,
    #[cfg(test)]
    pub(crate) checks: usize,
}

impl NativeBlsVerifier {
    fn equation(
        &mut self,
        operation: u8,
        dst: &[u8],
        keys: &[BlsPublicKey],
        message: &[u8],
        signature: &BlsSignature,
        check: impl FnOnce() -> bool,
    ) -> bool {
        // Borsh frames every variable-length field and the ordered key count.
        // Operation and cipher suite distinguish single, aggregate and POP checks.
        let id = neutrin0_consensus_types::tagged_commitment(
            b"NTRO/host-bls-verdict",
            &(operation, dst, keys, message, signature),
        );
        if let Some(verdict) = self.verdicts.get(&id) {
            return *verdict;
        }
        #[cfg(test)]
        {
            self.checks += 1;
        }
        let verdict = check();
        self.remember(id, verdict);
        verdict
    }

    fn remember(&mut self, id: Hash, verdict: bool) {
        if self.verdicts.len() == MAX_VERDICTS {
            let oldest = self
                .order
                .pop_front()
                .expect("full cache has an oldest entry");
            self.verdicts.remove(&oldest);
        }
        self.verdicts.insert(id, verdict);
        self.order.push_back(id);
    }
}

impl Verifier for NativeBlsVerifier {
    fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
        self.equation(
            0,
            neutrin0_crypto::bls::SIG_DST,
            &[*key],
            message,
            signature,
            || {
                let (Ok(key), Ok(signature)) =
                    (PublicKey::from_bytes(key), Signature::from_bytes(signature))
                else {
                    return false;
                };
                key.verify(message, &signature).is_ok()
            },
        )
    }

    fn aggregate(
        &mut self,
        keys: &[BlsPublicKey],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        self.equation(
            1,
            neutrin0_crypto::bls::SIG_DST,
            keys,
            message,
            signature,
            || {
                let Ok(keys) = keys
                    .iter()
                    .map(PublicKey::from_bytes)
                    .collect::<Result<Vec<_>, _>>()
                else {
                    return false;
                };
                let Ok(signature) = Signature::from_bytes(signature) else {
                    return false;
                };
                neutrin0_crypto::bls::fast_aggregate_verify(
                    &keys.iter().collect::<Vec<_>>(),
                    message,
                    &signature,
                )
                .is_ok()
            },
        )
    }

    fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
        self.equation(
            2,
            neutrin0_crypto::bls::POP_DST,
            &[*key],
            key,
            signature,
            || {
                let (Ok(key), Ok(signature)) =
                    (PublicKey::from_bytes(key), Signature::from_bytes(signature))
                else {
                    return false;
                };
                key.verify_pop(&signature).is_ok()
            },
        )
    }
}

#[cfg(test)]
mod tests;
