use super::*;

/// EIP-2335's scrypt test vector.
const VECTOR: &str = r#"{
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {"iv": "264daa3f303d7259501c93d997d84fe6"},
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
            }
        },
        "description": "This is a test keystore that uses scrypt to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/3141592653/589793238",
        "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
        "version": 4
}"#;

#[test]
fn the_eip_2335_vector_opens_with_its_normalised_password() {
    let keystore = Keystore::from_json(VECTOR).unwrap();
    assert_eq!(
        normalized("𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑").as_slice(),
        hex::decode("7465737470617373776f7264f09f9491")
            .unwrap()
            .as_slice()
    );
    let secret = keystore.decrypt("𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑").unwrap();
    assert_eq!(
        hex::encode(secret.to_bytes()),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
    assert!(matches!(
        keystore.decrypt("testpassword"),
        Err(KeystoreError::WrongPassword)
    ));
}

#[test]
fn written_keystores_round_trip_and_refuse_tampering() {
    let secret = SecretKey::key_gen(&[7; 32], &[]).unwrap();
    // A small work factor keeps the test fast; the format is the same.
    let keystore = Keystore::encrypt_with(&secret, "pass\u{7}word", "v0", 4).unwrap();
    let reopened = Keystore::from_json(&keystore.to_json().unwrap()).unwrap();
    assert_eq!(reopened, keystore);
    assert_eq!(
        reopened.public_key().unwrap(),
        secret.public_key().to_bytes()
    );
    // Control codes are not part of the password.
    assert_eq!(
        reopened.decrypt("password").unwrap().to_bytes(),
        secret.to_bytes()
    );
    let mut swapped = keystore.clone();
    swapped.pubkey = hex::encode(
        SecretKey::key_gen(&[8; 32], &[])
            .unwrap()
            .public_key()
            .to_bytes(),
    );
    assert!(matches!(
        swapped.decrypt("password"),
        Err(KeystoreError::PublicKeyMismatch)
    ));
    let mut hostile = keystore;
    hostile.crypto.kdf.params.n = 1 << 30;
    assert!(matches!(
        hostile.decrypt("password"),
        Err(KeystoreError::Unsupported(_))
    ));
}
