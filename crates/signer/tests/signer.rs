//! A node signs through `neutrin0-signer` over a Unix socket and over
//! mutually authenticated TLS; the signer refuses what its journal refuses,
//! and the node refuses signatures that do not verify for its chain.

use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use neutrin0_consensus_engine::{ProposerKey, SignRequest};
use neutrin0_consensus_types::{
    FinalityVoteData, FinalityVotePhase, NilVoteAttestation, NilVoteData, VoteAttestation,
};
use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::{ConsensusDomain, PriorDomains};
use neutrin0_signer::{Client, Endpoint, Signer, tls};
use neutrin0_storage::MemoryDatabase;

const IKM: [u8; 32] = [3; 32];

const fn domain(chain_spec_hash: u8) -> ConsensusDomain {
    ConsensusDomain {
        chain_id: 7,
        chain_spec_hash: [chain_spec_hash; 32],
        prior: PriorDomains::NONE,
    }
}

const fn nil(round: u32) -> SignRequest {
    SignRequest::NilVote(NilVoteAttestation {
        validator_index: 0,
        vote: NilVoteData {
            chunk_id: 0,
            round,
            phase: FinalityVotePhase::Prevote,
        },
        vote_signature: [0; 96],
        signature: [0; 96],
    })
}

const fn prevote(round: u32) -> SignRequest {
    SignRequest::Vote(VoteAttestation {
        validator_index: 0,
        vote_signature: [0; 96],
        vote: FinalityVoteData {
            chunk_id: 0,
            round,
            chunk_hash: [4; 32],
            selection: [5; 32],
            phase: FinalityVotePhase::Prevote,
        },
        proof_acceptance: None,
        unlock_quorum: None,
        signature: [0; 96],
    })
}

/// A fresh directory under the system's temporary one.
struct Directory(PathBuf);

impl Directory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "neutrin0-signer-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Serve a signer of the `IKM` key for `chain_spec_hash` on a new socket.
fn unix_signer(directory: &Path, chain_spec_hash: u8) -> PathBuf {
    let signer = Arc::new(Signer::new(
        domain(chain_spec_hash),
        vec![SecretKey::key_gen(&IKM, &[]).unwrap()],
        MemoryDatabase::new(),
    ));
    let path = directory.join(format!("signer-{chain_spec_hash}.sock"));
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || signer.serve_unix(&listener));
    path
}

#[test]
fn a_node_signs_through_the_socket_and_the_journal_refuses_conflicts() {
    let directory = Directory::new("unix");
    let local = ProposerKey::from_ikm(&IKM, 0).unwrap();
    let identity = *local.public_key_bytes();
    let client = Arc::new(Client::new(Endpoint::Unix(unix_signer(&directory.0, 9))));
    assert_eq!(client.identities().unwrap(), vec![identity]);
    let remote = ProposerKey::remote(identity, client, 0);

    // The signatures are the local key's, checked by the node before use.
    let signatures = remote.sign(domain(9), &nil(0)).unwrap();
    assert_eq!(signatures, local.sign(domain(9), &nil(0)).unwrap());
    assert_eq!(remote.sign(domain(9), &nil(0)).unwrap(), signatures);
    // A value prevote where the nil prevote was signed is refused.
    let refused = remote.sign(domain(9), &prevote(0)).unwrap_err();
    assert!(refused.to_string().contains("conflicts"), "{refused}");
    assert_eq!(
        remote.sign(domain(9), &prevote(1)).unwrap(),
        local.sign(domain(9), &prevote(1)).unwrap()
    );

    // A key the signer does not hold, and a signer of another chain whose
    // signatures do not verify for this one, sign nothing usable.
    let other_chain = unix_signer(&directory.0, 8);
    let stranger = ProposerKey::remote(
        [7; 48],
        Arc::new(Client::new(Endpoint::Unix(other_chain.clone()))),
        0,
    );
    assert!(stranger.sign(domain(9), &nil(2)).is_err());
    let misconfigured = ProposerKey::remote(
        identity,
        Arc::new(Client::new(Endpoint::Unix(other_chain))),
        0,
    );
    assert!(misconfigured.sign(domain(9), &nil(2)).is_err());
}

/// A certificate authority, written as `<name>.crt` under `directory`.
fn authority(directory: &Path, name: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let certificate = params.self_signed(&key).unwrap();
    std::fs::write(directory.join(format!("{name}.crt")), certificate.pem()).unwrap();
    (certificate, key)
}

/// A certificate `authority` issued for `name`, written as `<name>.crt` and
/// `<name>.key` under `directory`; returns the SHA-256 of its DER.
fn issue(
    directory: &Path,
    authority: &(rcgen::Certificate, rcgen::KeyPair),
    name: &str,
    purpose: rcgen::ExtendedKeyUsagePurpose,
) -> [u8; 32] {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.extended_key_usages = vec![purpose];
    let certificate = params.signed_by(&key, &authority.0, &authority.1).unwrap();
    std::fs::write(directory.join(format!("{name}.crt")), certificate.pem()).unwrap();
    std::fs::write(directory.join(format!("{name}.key")), key.serialize_pem()).unwrap();
    neutrin0_crypto::hash::sha256(certificate.der())
}

#[test]
fn tls_signing_needs_a_listed_client_certificate_and_uses_only_its_keys() {
    use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};
    let directory = Directory::new("tls");
    let path = |file: &str| directory.0.join(file);
    let signers = authority(&directory.0, "signers-ca");
    let nodes = authority(&directory.0, "nodes-ca");
    let strangers = authority(&directory.0, "strangers-ca");
    issue(&directory.0, &signers, "localhost", ServerAuth);
    let node = issue(&directory.0, &nodes, "node", ClientAuth);
    let unlisted = issue(&directory.0, &nodes, "unlisted", ClientAuth);
    let other = issue(&directory.0, &nodes, "other", ClientAuth);
    issue(&directory.0, &strangers, "stranger", ClientAuth);
    let local = ProposerKey::from_ikm(&IKM, 0).unwrap();
    let identity = *local.public_key_bytes();
    let signer = Arc::new(Signer::new(
        domain(9),
        vec![SecretKey::key_gen(&IKM, &[]).unwrap()],
        MemoryDatabase::new(),
    ));
    let server = tls::server_config(
        &path("localhost.crt"),
        &path("localhost.key"),
        &path("nodes-ca.crt"),
    )
    .unwrap();
    let mut clients = neutrin0_signer::TlsClients::new();
    clients.insert(node, [identity].into());
    clients.insert(other, [[7; 48]].into());
    assert!(!clients.contains_key(&unlisted));
    let clients = Arc::new(clients);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || signer.serve_tls(&listener, &server, &clients));

    let client = |name: &str| {
        Client::new(
            Endpoint::tls(
                address.clone(),
                "localhost",
                &path("signers-ca.crt"),
                &path(&format!("{name}.crt")),
                &path(&format!("{name}.key")),
            )
            .unwrap(),
        )
    };
    let node = client("node");
    assert_eq!(node.identities().unwrap(), vec![identity]);
    let remote = ProposerKey::remote(identity, Arc::new(node), 0);
    assert_eq!(
        remote.sign(domain(9), &nil(0)).unwrap(),
        local.sign(domain(9), &nil(0)).unwrap()
    );
    // A certificate the signer does not list, or another authority issued,
    // gets no connection; one listed for other keys cannot use this one.
    assert!(client("unlisted").identities().is_err());
    assert!(client("stranger").identities().is_err());
    let other = client("other");
    assert_eq!(other.identities().unwrap(), Vec::<[u8; 48]>::new());
    let refused = ProposerKey::remote(identity, Arc::new(other), 0)
        .sign(domain(9), &nil(1))
        .unwrap_err();
    assert!(refused.to_string().contains("may not use"), "{refused}");
}
