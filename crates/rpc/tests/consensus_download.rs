//! Content pinning covers every slice and the completed envelope.
use jsonrpsee::{
    server::{RpcModule, Server},
    types::ErrorObjectOwned,
};
use neutrin0_primitives::blake3_256;
use neutrin0_rpc::{
    client::{ClientError, NodeClient},
    types::{ArtifactIdJson, ArtifactInfoJson, ArtifactSliceJson, BytesHex, HashHex},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

async fn download(corruption: u8) -> (Result<(ArtifactInfoJson, Vec<u8>), ClientError>, usize) {
    let bytes = Arc::new(vec![17_u8; 1024 * 1024 + 27]);
    let hash = HashHex(blake3_256(&bytes));
    let id = ArtifactIdJson::ChunkProof { chunk: 3 };
    let info = ArtifactInfoJson {
        id: id.clone(),
        artifact_hash: hash,
        encoded_bytes: bytes.len() as u64,
        proof_bytes: 19,
        public_values: None,
    };
    let mut module = RpcModule::new(());
    module
        .register_method("chain_getArtifact", move |params, _context, _extensions| {
            let (id,): (ArtifactIdJson,) = params.parse()?;
            assert_eq!(id, info.id);
            Ok::<_, ErrorObjectOwned>(info.clone())
        })
        .unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    module
        .register_method(
            "chain_getArtifactBytes",
            move |params, _context, _extensions| {
                let (id, expected, offset, length): (ArtifactIdJson, HashHex, u64, u32) =
                    params.parse()?;
                assert_eq!(id, ArtifactIdJson::ChunkProof { chunk: 3 });
                assert_eq!(expected, hash);
                assert_eq!(length, 1024 * 1024);
                count.fetch_add(1, Ordering::Relaxed);
                let start = usize::try_from(offset).unwrap();
                let end = (start + length as usize).min(bytes.len());
                let mut slice = ArtifactSliceJson {
                    artifact_hash: hash,
                    encoded_bytes: bytes.len() as u64,
                    offset,
                    bytes: BytesHex(bytes[start..end].to_vec()),
                };
                match corruption {
                    1 => slice.artifact_hash = HashHex([0; 32]),
                    2 => slice.encoded_bytes += 1,
                    3 => slice.offset += 1,
                    4 => slice.bytes.0.clear(),
                    5 => slice.bytes.0[0] ^= 1,
                    6 => slice.bytes.0.truncate(1),
                    7 => slice.bytes.0.resize(1024 * 1024 + 1, 17),
                    _ => {}
                }
                Ok::<_, ErrorObjectOwned>(slice)
            },
        )
        .unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let client = NodeClient::connect(
        &format!("http://{}", server.local_addr().unwrap()),
        Duration::from_secs(5),
    )
    .unwrap();
    let handle = server.start(module);
    let result = client.download_artifact(id).await;
    handle.stop().unwrap();
    handle.stopped().await;
    (result, requests.load(Ordering::Relaxed))
}

#[tokio::test]
async fn segmented_download_preserves_exact_bytes() {
    let (result, requests) = download(0).await;
    let (info, bytes) = result.unwrap();
    assert_eq!(requests, 2);
    assert_eq!(bytes, vec![17; 1024 * 1024 + 27]);
    assert_eq!(info.artifact_hash.0, blake3_256(&bytes));
}

#[tokio::test]
async fn corrupt_slice_identity_size_offset_and_bytes_are_rejected() {
    for corruption in 1..=7 {
        let (result, _) = download(corruption).await;
        assert!(
            matches!(result, Err(ClientError::InvalidResponse(_))),
            "corruption {corruption}"
        );
    }
}
