//! The `keygen` command: a validator's BLS, Ethereum and libp2p key files.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Entry points are private binary implementation, not exported library APIs."
)]

use std::fs;
use std::path::{Path, PathBuf};

use getrandom::SysRng;
use neutrin0_consensus_engine::ProposerKey;
use rand_core::UnwrapErr;

use crate::Options;
use crate::secret::write_secret;

pub(super) fn keygen(opts: &Options) -> Result<(), String> {
    let out = PathBuf::from(opts.require("out")?);
    let name = opts.get("name").unwrap_or("validator");
    fs::create_dir_all(&out).map_err(|err| format!("create {}: {err}", out.display()))?;
    // Checked first so a refusal leaves no partial key set behind.
    let network_path = out.join(format!("{name}.p2p"));
    if network_path.exists() {
        return Err(format!("{} already exists", network_path.display()));
    }

    let mut ikm = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(ikm.as_mut()).map_err(|err| format!("system randomness unavailable: {err}"))?;
    let proposer = ProposerKey::from_ikm(ikm.as_ref(), 0).map_err(|err| err.to_string())?;
    // With a password the BLS key is written only encrypted (EIP-2335).
    let (key_setting, key_path) = if let Some(password) = opts.get("keystore-password-file") {
        let path = out.join(format!("{name}.keystore.json"));
        let secret = neutrin0_crypto::bls::SecretKey::key_gen(ikm.as_ref(), &[])
            .map_err(|err| err.to_string())?;
        crate::keys::write_keystore(&path, &secret, Path::new(password), name)?;
        ("proposer_keystore_path", path)
    } else {
        let path = out.join(format!("{name}.ikm"));
        write_secret(&path, &hex::encode(ikm.as_ref()))?;
        ("proposer_ikm_path", path)
    };

    let account = neutrin0_crypto::secp256k1::SecretKey::generate(&mut UnwrapErr(SysRng));
    let account_path = out.join(format!("{name}.secp256k1"));
    write_secret(&account_path, &hex::encode(account.to_bytes()))?;
    let ethereum = account.public_key().ethereum_address();
    let mut credentials = [0; 32];
    credentials[12..].copy_from_slice(&ethereum);
    let peer_id =
        neutrin0_node::identity::ensure_peer_id(&network_path).map_err(|err| err.to_string())?;

    println!("{key_setting:<26} = {}", key_path.display());
    println!("account_key_path           = {}", account_path.display());
    println!("network_key_path           = {}", network_path.display());
    println!("peer_id                    = {peer_id}");
    println!("# bootnode address: /ip4/<host>/tcp/<port>/p2p/{peer_id}");
    println!();
    println!("# chain-spec.toml entries");
    println!("# Amounts are wei: \"32000000000000000000\" is 32 tokens.");
    println!("[[validators]]");
    println!(
        "pubkey_hex = \"{}\"",
        hex::encode(proposer.public_key_bytes())
    );
    println!(
        "withdrawal_credentials_hex = \"{}\"",
        hex::encode(credentials)
    );
    // Binds the key to these credentials; another address needs a new proof.
    println!(
        "pop_hex = \"{}\"",
        hex::encode(proposer.prove_registration(&credentials).to_bytes())
    );
    println!("effective_stake = \"<stake>\"");
    println!();
    println!("[[accounts]]");
    println!("address_hex = \"{}\"", hex::encode(ethereum));
    println!("balance = \"<balance>\"");
    println!("# Ethereum account: 0x{}", hex::encode(ethereum));
    Ok(())
}
