//! The genesis allocation and validator set the file declares.

#![allow(clippy::redundant_pub_crate)] // Crate-internal helpers re-exported by the parent module.

use neutrin0_primitives::{Hash, Validator};

use super::{ChainSpecError, ChainSpecFile, decode_hash_or_zero, decode_hex_exact};

impl ChainSpecFile {
    /// Runtime-specific Borsh genesis configuration for this file's allocation.
    pub(super) fn genesis_configuration(&self) -> Result<Vec<u8>, ChainSpecError> {
        let accounts = self
            .accounts
            .iter()
            .map(|entry| {
                let raw = entry
                    .address_hex
                    .strip_prefix("0x")
                    .unwrap_or(&entry.address_hex);
                let address = if raw.len() == 40 {
                    decode_hex_exact::<20>(raw, "Ethereum genesis address")?
                } else {
                    let padded = decode_hex_exact::<32>(raw, "Ethereum genesis address")?;
                    if padded[..12] != [0; 12] {
                        return Err(ChainSpecError::Validation(
                            "Ethereum address must be canonically padded".into(),
                        ));
                    }
                    padded[12..].try_into().expect("20-byte address")
                };
                let balance = if let Some(balance) = &entry.balance_hex {
                    if entry.balance != 0 {
                        return Err(ChainSpecError::Validation(
                            "specify only one Ethereum allocation balance".into(),
                        ));
                    }
                    decode_hex_exact::<32>(balance, "Ethereum genesis balance")?
                } else {
                    let mut word = [0; 32];
                    word[16..].copy_from_slice(&entry.balance.to_be_bytes());
                    word
                };
                Ok(neutrin0_runtime_abi::ethereum::GenesisAccount {
                    address,
                    balance,
                    nonce: 0,
                    code: Vec::new(),
                    storage: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, ChainSpecError>>()?;
        Ok(
            borsh::to_vec(&neutrin0_runtime_abi::ethereum::EvmGenesisConfig {
                initial_base_fee: self.initial_base_fee.unwrap_or(1_000_000_000),
                accounts,
            })
            .expect("EVM genesis config"),
        )
    }

    /// Initial consensus identities supplied to runtime initialization.
    /// # Errors
    /// Reports malformed BLS keys or withdrawal credentials and keys whose
    /// proof of possession does not verify for their credentials.
    pub fn genesis_validators(&self) -> Result<Vec<Validator>, ChainSpecError> {
        self.validators
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let pubkey = decode_bls_pubkey(&entry.pubkey_hex, index)?;
                let withdrawal_credentials =
                    Self::decode_credentials(entry.withdrawal_credentials_hex.as_deref())?;
                verify_genesis_possession(index, &pubkey, &withdrawal_credentials, &entry.pop_hex)?;
                Ok(Validator {
                    pubkey,
                    withdrawal_credentials,
                    effective_stake: entry.effective_stake,
                    activation_epoch: 0,
                    exit_epoch: u64::MAX,
                })
            })
            .collect()
    }

    fn decode_credentials(credentials: Option<&str>) -> Result<Hash, ChainSpecError> {
        if let Some(encoded) = credentials
            && encoded.strip_prefix("0x").unwrap_or(encoded).len() == 40
        {
            let mut padded = [0; 32];
            padded[12..].copy_from_slice(&decode_hex_exact::<20>(
                encoded,
                "validator Ethereum address",
            )?);
            return Ok(padded);
        }
        decode_hash_or_zero(credentials, "validator withdrawal credentials")
    }
}

fn decode_bls_pubkey(hex: &str, validator_index: usize) -> Result<[u8; 48], ChainSpecError> {
    let field = format!("validators[{validator_index}].pubkey_hex");
    decode_hex_exact::<48>(hex, &field)
}

/// Seat a genesis key only with the registration proof its holder signed for
/// these credentials. Aggregate-only quorum checks trust every seated key, so
/// a key chosen as a function of the others (a rogue key nobody holds) would
/// forge any quorum certificate; rotation applies the same rule to later keys.
fn verify_genesis_possession(
    validator_index: usize,
    pubkey: &[u8; 48],
    credentials: &[u8; 32],
    pop_hex: &str,
) -> Result<(), ChainSpecError> {
    let invalid = |reason: &str| {
        ChainSpecError::Validation(format!("validators[{validator_index}]: {reason}"))
    };
    let public = neutrin0_crypto::bls::PublicKey::from_bytes(pubkey)
        .map_err(|_| invalid("pubkey_hex is not a BLS public key in the prime-order subgroup"))?;
    let pop = decode_hex_exact::<96>(pop_hex, &format!("validators[{validator_index}].pop_hex"))?;
    let signature = neutrin0_crypto::bls::Signature::from_bytes(&pop)
        .map_err(|_| invalid("pop_hex is not a BLS signature"))?;
    public
        .verify_registration(credentials, &signature)
        .map_err(|_| {
            invalid(
                "pop_hex does not prove possession of pubkey_hex for withdrawal_credentials_hex",
            )
        })
}

/// `[[validators]]` fields of the test key derived from `seed`, with its
/// proof of possession for `credentials` (a 20-byte address, padded).
#[cfg(test)]
pub(crate) fn test_validator_fields(seed: u8, credentials: [u8; 20]) -> String {
    let key = neutrin0_crypto::bls::SecretKey::key_gen(&[seed; 32], &[]).unwrap();
    let pop = key.prove_registration(&neutrin0_primitives::runtime_account(credentials));
    format!(
        "pubkey_hex = \"{}\"\nwithdrawal_credentials_hex = \"{}\"\npop_hex = \"{}\"\n",
        hex::encode(key.public_key().to_bytes()),
        hex::encode(credentials),
        hex::encode(pop.to_bytes()),
    )
}
