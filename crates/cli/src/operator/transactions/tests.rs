//! System calldata, key-file handling and offline preparation checks.

use super::calldata::evm_data;
use super::*;
use alloy_primitives::{Address, U256};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct KeyFile {
    path: PathBuf,
}

impl KeyFile {
    fn new(seed: [u8; 32]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "neutrin0-cli-key-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path).expect("key file");
        file.write_all(hex::encode(seed).as_bytes())
            .expect("key contents");
        Self { path }
    }
    fn name(&self) -> &str {
        self.path.to_str().expect("path")
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn options(values: &[&str]) -> Arguments {
    let values: Vec<_> = values.iter().map(|value| (*value).into()).collect();
    Arguments::parse(
        &values,
        super::super::SIGN_OPTIONS
            .iter()
            .copied()
            .chain(["amount", "to", "ikm-path"])
            .collect::<Vec<_>>()
            .as_slice(),
    )
    .expect("parse")
}

#[test]
fn registration_abi_carries_a_proof_bound_to_the_withdrawal_account() {
    let ikm = KeyFile::new([9; 32]);
    let options = options(&["--ikm-path", ikm.name(), "--amount", "123"]);
    let address = [4; 32];
    let data = evm_data("register", address, &options).expect("registration");
    assert_eq!(
        &data[..4],
        &neutrin0_crypto::keccak256(b"registerValidator(bytes,bytes,uint256)")[..4]
    );
    assert_eq!(data.len(), 324);
    assert_eq!(U256::from_be_slice(&data[4..36]), U256::from(96));
    assert_eq!(U256::from_be_slice(&data[36..68]), U256::from(192));
    assert_eq!(U256::from_be_slice(&data[68..100]), U256::from(123));
    let public: [u8; 48] = data[132..180].try_into().expect("public key");
    let pop: [u8; 96] = data[228..324].try_into().expect("proof");
    let key = neutrin0_crypto::bls::PublicKey::from_bytes(&public).expect("decode public key");
    let proof = neutrin0_crypto::bls::Signature::from_bytes(&pop).expect("decode proof");
    key.verify_registration(&address, &proof)
        .expect("bound proof");
    assert!(key.verify_registration(&[3; 32], &proof).is_err());
}

#[test]
fn rotation_abi_carries_the_new_key_with_a_proof_bound_to_the_account() {
    let ikm = KeyFile::new([9; 32]);
    let options = options(&["--ikm-path", ikm.name()]);
    let address = [4; 32];
    let data = evm_data("rotate-key", address, &options).expect("rotation");
    assert_eq!(
        &data[..4],
        &neutrin0_crypto::keccak256(b"rotateKey(bytes,bytes)")[..4]
    );
    assert_eq!(data.len(), 292);
    assert_eq!(U256::from_be_slice(&data[4..36]), U256::from(64));
    assert_eq!(U256::from_be_slice(&data[36..68]), U256::from(160));
    let public: [u8; 48] = data[100..148].try_into().expect("public key");
    let pop: [u8; 96] = data[196..292].try_into().expect("proof");
    let key = neutrin0_crypto::bls::PublicKey::from_bytes(&public).expect("decode public key");
    assert_eq!(
        public,
        neutrin0_crypto::bls::SecretKey::key_gen(&[9; 32], &[])
            .unwrap()
            .public_key()
            .to_bytes()
    );
    let proof = neutrin0_crypto::bls::Signature::from_bytes(&pop).expect("decode proof");
    key.verify_registration(&address, &proof)
        .expect("bound proof");
}

#[cfg(unix)]
#[test]
fn insecure_and_symlinked_keys_are_refused_and_outputs_never_overwrite() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let key = KeyFile::new([9; 32]);
    fs::set_permissions(&key.path, fs::Permissions::from_mode(0o644)).expect("permissions");
    assert!(read_key(key.name()).is_err());
    fs::set_permissions(&key.path, fs::Permissions::from_mode(0o600)).expect("permissions");
    let link = key.path.with_extension("link");
    symlink(&key.path, &link).expect("symlink");
    assert!(read_key(link.to_str().expect("path")).is_err());
    fs::remove_file(link).expect("remove link");
    assert!(write_new(key.name(), &[0]).is_err());
    assert_eq!(read_key(key.name()).expect("read").as_ref(), &[9; 32]);
}

#[tokio::test]
async fn evm_prepare_uses_pending_nonce_simulates_and_signs_without_broadcast() {
    use alloy_consensus::transaction::SignerRecoverable as _;
    use jsonrpsee::{
        server::{RpcModule, Server},
        types::ErrorObjectOwned,
    };
    let key = KeyFile::new([5; 32]);
    let mut module = RpcModule::new(());
    module
        .register_method("chain_head", |_params, _context, _extensions| {
            Ok::<_, ErrorObjectOwned>(neutrin0_rpc::HeadInfoJson {
                height: 3,
                slot: 3,
                hash: HashHex([2; 32]),
                state_root: HashHex([3; 32]),
            })
        })
        .expect("head");
    module
        .register_method("system_chainId", |_params, _context, _extensions| 7_u64)
        .expect("chain");
    module
        .register_method("runtime_call", |params, _context, _extensions| {
            let value: Value = params.parse()?;
            assert_eq!(value["method"], "runtime_info");
            Ok::<_, ErrorObjectOwned>(neutrin0_rpc::RuntimeCallResultJson {
                code: 0,
                payload: BytesHex(
                    borsh::to_vec(&neutrin0_primitives::RuntimeInfo {
                        spec_name: *b"NEUTRIN0_EVM\0\0\0\0",
                    })
                    .expect("info"),
                ),
                gas_used: 0,
            })
        })
        .expect("runtime");
    module
        .register_method(
            "eth_getTransactionCount",
            |params, _context, _extensions| {
                let (_, at): (String, String) = params.parse()?;
                assert_eq!(at, "pending");
                Ok::<_, ErrorObjectOwned>("0x4")
            },
        )
        .expect("nonce");
    module
        .register_method(
            "eth_maxPriorityFeePerGas",
            |_params, _context, _extensions| "0x2",
        )
        .expect("tip");
    module
        .register_method("eth_gasPrice", |_params, _context, _extensions| "0x6")
        .expect("price");
    module
        .register_method("eth_estimateGas", |_params, _context, _extensions| "0x5208")
        .expect("gas");
    module
        .register_method("eth_call", |params, _context, _extensions| {
            let (call, at): (Value, String) = params.parse()?;
            assert_eq!(at, "pending");
            assert_eq!(call["gas"], "0x5208");
            Ok::<_, ErrorObjectOwned>(BytesHex(vec![]))
        })
        .expect("simulation");
    // No eth_sendRawTransaction method is installed; default preparation must not broadcast.
    let server = Server::builder().build("127.0.0.1:0").await.expect("bind");
    let endpoint = format!("http://{}", server.local_addr().expect("address"));
    let handle = server.start(module);
    let client = NodeClient::connect(&endpoint, std::time::Duration::from_secs(1)).expect("client");
    let destination = "07".repeat(20);
    let options = options(&[
        "--key-file",
        key.name(),
        "--to",
        &destination,
        "--amount",
        "123",
    ]);
    let prepared = prepare(&client, "tx", "transfer", &options)
        .await
        .expect("prepared");
    assert_eq!(prepared["submitted"], false);
    let bytes = decode_bytes(prepared["signed_bytes"].as_str().expect("bytes")).expect("hex");
    let tx = TxEnvelope::decode_2718(&mut bytes.as_slice()).expect("Ethereum envelope");
    assert_eq!(tx.chain_id(), Some(7));
    assert_eq!(tx.nonce(), 4);
    assert_eq!(tx.gas_limit(), 21_000);
    assert_eq!(tx.value(), U256::from(123));
    assert_eq!(tx.to(), Some(Address::from([7; 20])));
    assert_eq!(
        format!("{:#x}", tx.recover_signer().expect("signer")),
        prepared["from"]
    );
    handle.stop().expect("stop");
}
