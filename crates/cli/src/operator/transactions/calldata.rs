//! ABI calldata for the staking and voting operations of the system precompile.

use alloy_primitives::U256;

use super::{Arguments, Error, read_key};

pub(super) fn amount(options: &Arguments, required: bool) -> Result<U256, Error> {
    let value = if required {
        options.required("amount")?
    } else {
        options.get("amount").unwrap_or("0")
    };
    U256::from_str_radix(value, 10).map_err(|_| {
        Error::Usage("--amount must be an unsigned decimal integer in wei (18 decimals)".into())
    })
}

pub(super) fn evm_data(
    operation: &str,
    address: [u8; 32],
    options: &Arguments,
) -> Result<Vec<u8>, Error> {
    let (signature, words) = match operation {
        "stake" => (
            "stake(uint256)",
            vec![amount(options, true)?.to_be_bytes::<32>()],
        ),
        "unstake" => (
            "unstake(uint256)",
            vec![amount(options, true)?.to_be_bytes::<32>()],
        ),
        "exit" => ("exit()", vec![]),
        "withdraw" => ("withdraw()", vec![]),
        "vote" => ("vote(bytes32)", vec![options.hash("proposal-id")?.0]),
        "register" => {
            let seed = read_key(options.required("ikm-path")?)?;
            let proposer = neutrin0_consensus_engine::ProposerKey::from_ikm(seed.as_ref(), 0)
                .map_err(|_| Error::Local("invalid BLS key material".into()))?;
            let public_key = proposer.public_key_bytes();
            let pop = proposer.prove_registration(&address).to_bytes();
            let mut data =
                neutrin0_crypto::keccak256(b"registerValidator(bytes,bytes,uint256)")[..4].to_vec();
            // Three head words; bytes48 occupies 96 bytes, bytes96 occupies 128.
            data.extend_from_slice(&U256::from(96).to_be_bytes::<32>());
            data.extend_from_slice(&U256::from(192).to_be_bytes::<32>());
            data.extend_from_slice(&amount(options, true)?.to_be_bytes::<32>());
            data.extend_from_slice(&U256::from(48).to_be_bytes::<32>());
            data.extend_from_slice(public_key);
            data.extend_from_slice(&[0; 16]);
            data.extend_from_slice(&U256::from(96).to_be_bytes::<32>());
            data.extend_from_slice(&pop);
            return Ok(data);
        }
        "rotate-key" => {
            let key = new_bls_key(options)?;
            let pop = key.prove_registration(&address).to_bytes();
            let mut data = neutrin0_crypto::keccak256(b"rotateKey(bytes,bytes)")[..4].to_vec();
            // Two head words; bytes48 occupies 96 bytes, bytes96 occupies 128.
            data.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
            data.extend_from_slice(&U256::from(160).to_be_bytes::<32>());
            data.extend_from_slice(&U256::from(48).to_be_bytes::<32>());
            data.extend_from_slice(&key.public_key().to_bytes());
            data.extend_from_slice(&[0; 16]);
            data.extend_from_slice(&U256::from(96).to_be_bytes::<32>());
            data.extend_from_slice(&pop);
            return Ok(data);
        }
        _ => return Err(Error::Usage("unsupported system transaction".into())),
    };
    let mut data = neutrin0_crypto::keccak256(signature.as_bytes())[..4].to_vec();
    for word in words {
        data.extend_from_slice(&word);
    }
    Ok(data)
}

/// The key a rotation installs: an EIP-2335 keystore (`--keystore` with
/// `--password-file`) or an IKM file (`--ikm-path`).
fn new_bls_key(options: &Arguments) -> Result<neutrin0_crypto::bls::SecretKey, Error> {
    if let Some(path) = options.get("keystore") {
        let password = neutrin0_keystore::read_password_file(std::path::Path::new(
            options.required("password-file")?,
        ))
        .map_err(Error::Local)?;
        return neutrin0_keystore::Keystore::from_file(std::path::Path::new(path))
            .map_err(Error::Local)?
            .decrypt(&password)
            .map_err(|error| Error::Local(format!("{path}: {error}")));
    }
    let seed = read_key(options.required("ikm-path")?)?;
    neutrin0_crypto::bls::SecretKey::key_gen(seed.as_ref(), &[])
        .map_err(|_| Error::Local("invalid BLS key material".into()))
}
