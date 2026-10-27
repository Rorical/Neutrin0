//! EIP-2335 encrypted keystores for validator BLS keys.
//!
//! A keystore holds the 32-byte BLS secret key encrypted with AES-128-CTR
//! under a scrypt-derived key, and a SHA-256 checksum that refuses a wrong
//! password before any secret is used. Passwords are NFKD-normalised and
//! stripped of control codes as EIP-2335 requires, so a keystore written by
//! any conforming tool opens here and the reverse. Neutrin0's BLS scheme is
//! min-pk over BLS12-381 with 32-byte big-endian secret keys, the scheme
//! these keystores were defined for.

#![deny(unsafe_code)]

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{KeyIvInit, StreamCipher};
use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::BlsPublicKey;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// scrypt work factor EIP-2335 recommends: 2^18 rounds of 1 KiB blocks,
/// 256 MiB of memory and about a second per derivation.
pub const SCRYPT_LOG_N: u8 = 18;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
/// Memory a keystore may demand (`128 · r · n` bytes): 1 GiB, four times the
/// recommendation, so opening a hostile file cannot exhaust the host.
const MAX_SCRYPT_BYTES: u64 = 1 << 30;
/// Bound on `p`, whose derivations run one after another.
const MAX_SCRYPT_P: u32 = 16;

/// Why a keystore could not be written or opened.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The JSON is not a well-formed EIP-2335 keystore.
    #[error("malformed keystore: {0}")]
    Malformed(&'static str),
    /// A version, function or parameter this implementation does not accept.
    #[error("unsupported keystore: {0}")]
    Unsupported(&'static str),
    /// The checksum refused the password.
    #[error("wrong keystore password")]
    WrongPassword,
    /// The decrypted secret is not the key the keystore names.
    #[error("keystore secret does not match its public key")]
    PublicKeyMismatch,
    /// The system could not supply randomness for salt, IV or UUID.
    #[error("system randomness unavailable")]
    Randomness,
    /// The JSON does not parse or serialise.
    #[error("keystore JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// An EIP-2335 (version 4) keystore.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Keystore {
    crypto: Crypto,
    #[serde(default)]
    description: String,
    pubkey: String,
    #[serde(default)]
    path: String,
    uuid: String,
    version: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Crypto {
    kdf: Module<KdfParams>,
    checksum: Module<Empty>,
    cipher: Module<CipherParams>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Module<P> {
    function: String,
    params: P,
    message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct KdfParams {
    dklen: u32,
    n: u64,
    p: u32,
    r: u32,
    salt: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct Empty {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CipherParams {
    iv: String,
}

impl Keystore {
    /// Encrypt `secret` under `password` with the recommended work factor.
    ///
    /// # Errors
    /// Fails only when the system has no randomness.
    pub fn encrypt(
        secret: &SecretKey,
        password: &str,
        description: &str,
    ) -> Result<Self, KeystoreError> {
        Self::encrypt_with(secret, password, description, SCRYPT_LOG_N)
    }

    fn encrypt_with(
        secret: &SecretKey,
        password: &str,
        description: &str,
        log_n: u8,
    ) -> Result<Self, KeystoreError> {
        let mut salt = [0; 32];
        let mut iv = [0; 16];
        let mut uuid = [0; 16];
        for buffer in [&mut salt[..], &mut iv[..], &mut uuid[..]] {
            getrandom::fill(buffer).map_err(|_| KeystoreError::Randomness)?;
        }
        let kdf = KdfParams {
            dklen: 32,
            n: 1 << log_n,
            p: SCRYPT_P,
            r: SCRYPT_R,
            salt: hex::encode(salt),
        };
        let key = derive_key(&kdf, password)?;
        let mut ciphertext = Zeroizing::new(secret.to_bytes());
        Aes128Ctr::new(
            GenericArray::from_slice(&key[..16]),
            GenericArray::from_slice(&iv),
        )
        .apply_keystream(ciphertext.as_mut());
        Ok(Self {
            crypto: Crypto {
                checksum: Module {
                    function: "sha256".into(),
                    params: Empty {},
                    message: hex::encode(checksum(&key, ciphertext.as_ref())),
                },
                kdf: Module {
                    function: "scrypt".into(),
                    params: kdf,
                    message: String::new(),
                },
                cipher: Module {
                    function: "aes-128-ctr".into(),
                    params: CipherParams {
                        iv: hex::encode(iv),
                    },
                    message: hex::encode(ciphertext.as_ref()),
                },
            },
            description: description.into(),
            pubkey: hex::encode(secret.public_key().to_bytes()),
            path: String::new(),
            uuid: format_uuid(uuid),
            version: 4,
        })
    }

    /// Parse a keystore file's JSON.
    ///
    /// # Errors
    /// Refuses JSON that is not a keystore of a public key.
    pub fn from_json(json: &str) -> Result<Self, KeystoreError> {
        let keystore: Self = serde_json::from_str(json)?;
        keystore.public_key()?;
        Ok(keystore)
    }

    /// Read and parse the keystore file at `path`, of at most 64 KiB.
    ///
    /// # Errors
    /// Returns an unreadable or oversized file and invalid JSON, naming the
    /// path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        use std::io::Read as _;
        const MAX_BYTES: u64 = 64 * 1024;
        let mut text = String::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(MAX_BYTES + 1).read_to_string(&mut text))
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if text.len() as u64 > MAX_BYTES {
            return Err(format!(
                "{} exceeds the keystore size bound",
                path.display()
            ));
        }
        Self::from_json(&text).map_err(|error| format!("{}: {error}", path.display()))
    }

    /// This keystore as pretty JSON.
    ///
    /// # Errors
    /// Never fails for a keystore this crate built or parsed.
    pub fn to_json(&self) -> Result<String, KeystoreError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// The public key the keystore names, readable without the password.
    ///
    /// # Errors
    /// Refuses a public key that is not 48 bytes of hex.
    pub fn public_key(&self) -> Result<BlsPublicKey, KeystoreError> {
        decode_exact(&self.pubkey, "pubkey")
    }

    /// Decrypt the secret key with `password`.
    ///
    /// # Errors
    /// Refuses another version, function or an unbounded work factor, a wrong
    /// password and a secret that is not the named key.
    pub fn decrypt(&self, password: &str) -> Result<SecretKey, KeystoreError> {
        let crypto = &self.crypto;
        if self.version != 4 {
            return Err(KeystoreError::Unsupported("version other than 4"));
        }
        if crypto.kdf.function != "scrypt" {
            return Err(KeystoreError::Unsupported(
                "key derivation other than scrypt",
            ));
        }
        if crypto.checksum.function != "sha256" || crypto.cipher.function != "aes-128-ctr" {
            return Err(KeystoreError::Unsupported(
                "checksum other than sha256 or cipher other than aes-128-ctr",
            ));
        }
        let iv: [u8; 16] = decode_exact(&crypto.cipher.params.iv, "cipher iv")?;
        let mut secret: Zeroizing<[u8; 32]> =
            Zeroizing::new(decode_exact(&crypto.cipher.message, "cipher message")?);
        let expected: [u8; 32] = decode_exact(&crypto.checksum.message, "checksum")?;
        let key = derive_key(&crypto.kdf.params, password)?;
        if checksum(&key, secret.as_ref()) != expected {
            return Err(KeystoreError::WrongPassword);
        }
        Aes128Ctr::new(
            GenericArray::from_slice(&key[..16]),
            GenericArray::from_slice(&iv),
        )
        .apply_keystream(secret.as_mut());
        let secret = SecretKey::from_bytes(&secret)
            .map_err(|_| KeystoreError::Malformed("secret is not a BLS scalar"))?;
        if secret.public_key().to_bytes() != self.public_key()? {
            return Err(KeystoreError::PublicKeyMismatch);
        }
        Ok(secret)
    }
}

/// Read a keystore password from `path`: a regular file (not a symlink) no
/// other user may read, of at most 4 KiB, without its surrounding whitespace.
///
/// # Errors
/// Refuses anything else, naming the path.
pub fn read_password_file(path: &std::path::Path) -> Result<Zeroizing<String>, String> {
    use std::io::Read as _;
    let display = path.display();
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{display}: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "{display}: not a regular file (symlinks are refused)"
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{display} has mode {mode:o}; it must not be group or world readable"
            ));
        }
    }
    let mut text = Zeroizing::new(String::new());
    std::fs::File::open(path)
        .and_then(|file| file.take(4097).read_to_string(&mut text))
        .map_err(|error| format!("{display}: {error}"))?;
    if text.len() > 4096 {
        return Err(format!("{display} exceeds 4096 bytes"));
    }
    Ok(Zeroizing::new(text.trim().to_owned()))
}

/// The 32-byte decryption key EIP-2335's scrypt derives from `password`.
fn derive_key(kdf: &KdfParams, password: &str) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    if kdf.dklen != 32 {
        return Err(KeystoreError::Unsupported(
            "derived key length other than 32",
        ));
    }
    if !kdf.n.is_power_of_two() || kdf.n < 2 {
        return Err(KeystoreError::Malformed("scrypt n is not a power of two"));
    }
    let memory = u64::from(kdf.r)
        .checked_mul(kdf.n)
        .and_then(|blocks| blocks.checked_mul(128));
    if memory.is_none_or(|memory| memory > MAX_SCRYPT_BYTES) || kdf.p > MAX_SCRYPT_P {
        return Err(KeystoreError::Unsupported(
            "scrypt work factor above the bound",
        ));
    }
    let log_n =
        u8::try_from(kdf.n.trailing_zeros()).map_err(|_| KeystoreError::Malformed("scrypt n"))?;
    let params = scrypt::Params::new(log_n, kdf.r, kdf.p, 32)
        .map_err(|_| KeystoreError::Malformed("scrypt parameters"))?;
    let salt = hex::decode(&kdf.salt).map_err(|_| KeystoreError::Malformed("salt"))?;
    let mut key = Zeroizing::new([0; 32]);
    scrypt::scrypt(&normalized(password), &salt, &params, key.as_mut())
        .map_err(|_| KeystoreError::Malformed("scrypt output length"))?;
    Ok(key)
}

/// EIP-2335's password bytes: NFKD, without C0, C1 and delete control codes.
fn normalized(password: &str) -> Zeroizing<Vec<u8>> {
    let kept: Zeroizing<String> = Zeroizing::new(
        password
            .nfkd()
            .filter(|c| !matches!(*c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
            .collect(),
    );
    Zeroizing::new(kept.as_bytes().to_vec())
}

/// `SHA-256(key[16..32] || ciphertext)`.
fn checksum(key: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut input = Zeroizing::new(Vec::with_capacity(16 + ciphertext.len()));
    input.extend_from_slice(&key[16..]);
    input.extend_from_slice(ciphertext);
    neutrin0_crypto::hash::sha256(&input)
}

fn decode_exact<const N: usize>(text: &str, field: &'static str) -> Result<[u8; N], KeystoreError> {
    hex::decode(text.trim_start_matches("0x"))
        .ok()
        .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
        .ok_or(KeystoreError::Malformed(field))
}

/// A random (version 4) UUID in its canonical text form.
fn format_uuid(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let text = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    )
}

#[cfg(test)]
mod tests;
