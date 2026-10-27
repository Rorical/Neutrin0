//! HTTP node client with bounded artifact downloads and confirmation polling.

use std::time::Duration;

use borsh::BorshDeserialize;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

use super::{ClientError, NodeApiClient, NodeStatusJson, PinnedBlock, TransactionConfirmation};
use crate::{BlockId, BlockIdJson, BytesHex, HashHex};

/// HTTP connection with bounded requests and typed operator helpers.
pub struct NodeClient {
    inner: HttpClient,
}

impl NodeClient {
    /// Connect to an HTTP(S) RPC endpoint; no request is retried implicitly.
    pub fn connect(endpoint: &str, request_timeout: Duration) -> Result<Self, ClientError> {
        if request_timeout.is_zero() {
            return Err(ClientError::InvalidResponse(
                "request timeout must be positive".into(),
            ));
        }
        let inner = HttpClientBuilder::default()
            .request_timeout(request_timeout)
            .max_response_size(32 * 1024 * 1024)
            .build(endpoint)?;
        Ok(Self { inner })
    }

    /// Access the shared typed RPC methods.
    pub const fn rpc(&self) -> &HttpClient {
        &self.inner
    }

    /// Read the operator summary.
    pub async fn status(&self) -> Result<NodeStatusJson, ClientError> {
        let (chain_id, health, info, head, finalized, retention, diagnostics) = tokio::try_join!(
            Box::pin(self.inner.chain_id()),
            Box::pin(self.inner.health()),
            Box::pin(self.inner.info()),
            Box::pin(self.inner.head()),
            Box::pin(self.inner.finalized()),
            Box::pin(self.inner.retention()),
            Box::pin(self.inner.diagnostics())
        )?;
        Ok(NodeStatusJson {
            chain_id,
            health,
            info,
            head,
            finalized,
            retention,
            diagnostics,
        })
    }

    /// Download a content-pinned canonical Borsh artifact and verify its envelope hash.
    ///
    /// # Errors
    /// Refuses unknown artifacts, malformed/changing slices and envelopes over 64 MiB.
    pub async fn download_artifact(
        &self,
        id: crate::types::ArtifactIdJson,
    ) -> Result<(crate::types::ArtifactInfoJson, Vec<u8>), ClientError> {
        let info = self
            .inner
            .artifact(id.clone())
            .await?
            .ok_or_else(|| ClientError::InvalidResponse("artifact is not known".into()))?;
        if info.id != id || info.encoded_bytes == 0 || info.encoded_bytes > 64 * 1024 * 1024 {
            return Err(ClientError::InvalidResponse(
                "invalid artifact locator or envelope size".into(),
            ));
        }
        let mut bytes = Vec::new();
        while (bytes.len() as u64) < info.encoded_bytes {
            let offset = bytes.len() as u64;
            let slice = self
                .inner
                .artifact_bytes(id.clone(), info.artifact_hash, offset, 1024 * 1024)
                .await?;
            if slice.artifact_hash != info.artifact_hash
                || slice.encoded_bytes != info.encoded_bytes
                || slice.offset != offset
                || slice.bytes.0.len() as u64 != (info.encoded_bytes - offset).min(1024 * 1024)
            {
                return Err(ClientError::InvalidResponse(
                    "artifact slice differs from pinned envelope".into(),
                ));
            }
            bytes.extend_from_slice(&slice.bytes.0);
        }
        if neutrin0_primitives::blake3_256(&bytes) != info.artifact_hash.0 {
            return Err(ClientError::InvalidResponse(
                "artifact envelope hash mismatch".into(),
            ));
        }
        Ok((info, bytes))
    }

    /// Resolve latest/finalized once, then use its hash for every related state query.
    pub async fn pin(&self, at: BlockIdJson) -> Result<PinnedBlock, ClientError> {
        if matches!(at.0, BlockId::Height(0) | BlockId::Hash(_))
            && let Some(genesis) = self.inner.genesis().await?
            && (at.0 == BlockId::Height(0) || at.0 == BlockId::Hash(genesis.hash.0))
        {
            return Ok(PinnedBlock {
                hash: genesis.hash,
                height: 0,
            });
        }
        match at.0 {
            BlockId::Latest => {
                let head = self.inner.head().await?;
                Ok(PinnedBlock {
                    hash: head.hash,
                    height: head.height,
                })
            }
            BlockId::Finalized => {
                let boundary = self.inner.finalized().await?;
                Ok(PinnedBlock {
                    hash: boundary.block_hash,
                    height: boundary.height,
                })
            }
            _ => self
                .inner
                .header(at)
                .await?
                .map(|header| PinnedBlock {
                    hash: header.block_hash,
                    height: header.height,
                })
                .ok_or_else(|| {
                    ClientError::InvalidResponse("selected block is not known locally".into())
                }),
        }
    }

    /// Decode a runtime-owned Borsh response; failures never become default values.
    pub async fn query<T: BorshDeserialize>(
        &self,
        method: &str,
        args: Vec<u8>,
        block: PinnedBlock,
    ) -> Result<T, ClientError> {
        let response = self
            .inner
            .runtime_call(
                method.into(),
                BytesHex(args),
                BlockIdJson(BlockId::Hash(block.hash.0)),
            )
            .await?;
        if response.code != 0 {
            return Err(ClientError::Runtime {
                method: method.into(),
                code: response.code,
                payload: response.payload,
            });
        }
        borsh::from_slice(&response.payload.0).map_err(|error| {
            ClientError::InvalidResponse(format!("malformed `{method}` response: {error}"))
        })
    }

    /// Wait for canonical Ethereum inclusion, optionally through complete-chunk finality.
    /// An orphaned receipt never establishes confirmation. Failed execution is returned explicitly.
    pub async fn wait_ethereum(
        &self,
        hash: HashHex,
        finalized: bool,
        timeout: Duration,
        poll: Duration,
    ) -> Result<TransactionConfirmation, ClientError> {
        self.wait_deadline(hash, timeout, poll, async {
            loop {
                if let Some(receipt) = self.inner.receipt(hash).await? {
                    if receipt.transaction_hash != hash {
                        return Err(ClientError::InvalidResponse(
                            "receipt transaction hash mismatch".into(),
                        ));
                    }
                    let height = quantity_u64(&receipt.block_number)?;
                    let success = match receipt.status.as_str() {
                        "0x1" => true,
                        "0x0" => false,
                        _ => {
                            return Err(ClientError::InvalidResponse(
                                "invalid receipt status".into(),
                            ));
                        }
                    };
                    let final_height = self.inner.finalized().await?.height;
                    if self.canonical(receipt.block_hash, height).await?
                        && (!finalized || height <= final_height)
                    {
                        return Ok(TransactionConfirmation {
                            hash,
                            block: PinnedBlock {
                                hash: receipt.block_hash,
                                height,
                            },
                            finalized: height <= final_height,
                            execution_success: success,
                        });
                    }
                }
                tokio::time::sleep(poll).await;
            }
        })
        .await
    }

    async fn canonical(&self, hash: HashHex, height: u64) -> Result<bool, ClientError> {
        Ok(self
            .inner
            .header(BlockIdJson(BlockId::Height(height)))
            .await?
            .is_some_and(|header| header.block_hash == hash && header.height == height))
    }

    async fn wait_deadline<T>(
        &self,
        hash: HashHex,
        timeout: Duration,
        poll: Duration,
        future: impl std::future::Future<Output = Result<T, ClientError>>,
    ) -> Result<T, ClientError> {
        if timeout.is_zero() || poll.is_zero() {
            return Err(ClientError::InvalidResponse(
                "confirmation timeout and poll interval must be positive".into(),
            ));
        }
        tokio::time::timeout(timeout, future)
            .await
            .unwrap_or_else(|_| Err(ClientError::ConfirmationTimeout(hex::encode(hash.0))))
    }
}

/// Decode a canonical Ethereum height/nonce quantity without truncation.
pub fn quantity_u64(value: &str) -> Result<u64, ClientError> {
    let digits = value
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty() && (digits.len() == 1 || !digits.starts_with('0')))
        .ok_or_else(|| ClientError::InvalidResponse("invalid Ethereum quantity".into()))?;
    u64::from_str_radix(digits, 16).map_err(|error| {
        ClientError::InvalidResponse(format!("invalid Ethereum quantity: {error}"))
    })
}
