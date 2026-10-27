//! Read-only node adapter. No chain engine, block execution or peer networking is instantiated.
use crate::{Error, Result, config::Config, model::Binding};
use async_trait::async_trait;
use neutrin0_rpc::{
    BlockId, BlockIdJson, HashHex,
    client::{NodeApiClient, NodeClient},
    types::{
        ArtifactIdJson, ArtifactInfoJson, BlockArtifactsJson, BlockJson, CertificateJson,
        ChainCursorJson, ChainEventPageJson, ChunkJson, ValidatorJson,
    },
};
use serde_json::Value;

/// Source contract shared by the HTTP adapter and recovery fixtures.
#[async_trait]
pub trait Source: Send + Sync {
    /// Independently pinned immutable source facts.
    async fn binding(&self, config: &Config) -> Result<Binding>;
    /// Durable event observation/replay; caller checkpoints only after data reconciliation.
    async fn events(&self, after: Option<ChainCursorJson>) -> Result<ChainEventPageJson>;
    /// Header lookup also works when the body is unavailable.
    async fn header(&self, height: u64) -> Result<Option<neutrin0_rpc::HeaderJson>>;
    /// Current canonical block at a height.
    async fn block(&self, height: u64) -> Result<Option<BlockJson>>;
    /// Exact runtime artifacts for a hash-pinned block.
    async fn artifacts(&self, hash: HashHex) -> Result<Option<BlockArtifactsJson>>;
    /// Historically decoded Ethereum block and all its receipts.
    async fn ethereum(
        &self,
        hash: HashHex,
    ) -> Result<(Value, Vec<neutrin0_rpc::client::EthereumReceiptJson>)>;
    /// Retained finalized Chunk.
    async fn chunk(&self, id: u64) -> Result<Option<ChunkJson>>;
    /// Retained finalized certificate.
    async fn certificate(&self, id: u64) -> Result<Option<CertificateJson>>;
    /// Exact proof/certificate metadata; no proving job is created.
    async fn proof(&self, id: ArtifactIdJson) -> Result<Option<ArtifactInfoJson>>;
    /// Current consensus committee observation.
    async fn validators(&self) -> Result<Vec<ValidatorJson>>;
}
/// HTTP full-node connection backed by the shared typed RPC client.
pub struct HttpSource {
    client: NodeClient,
}
impl HttpSource {
    /// Connect without loading any runtime/proof execution implementation.
    pub fn connect(config: &Config) -> Result<Self> {
        let client = NodeClient::connect(&config.rpc_url, config.timeout())
            .map_err(|_| Error::Config("invalid node HTTP endpoint".into()))?;
        Ok(Self { client })
    }
}
#[async_trait]
impl Source for HttpSource {
    async fn binding(&self, config: &Config) -> Result<Binding> {
        let status = self.client.rpc().chain_events(None, 1).await?.status;
        let spec = crate::model::hex(&status.chain_spec_hash.0);
        if spec != crate::model::hash(&config.chain_spec_hash)? {
            return Err(Error::Binding(
                "node differs from configured chain specification".into(),
            ));
        }
        let genesis = self
            .client
            .rpc()
            .genesis()
            .await?
            .ok_or_else(|| Error::Data("node genesis unavailable".into()))?;
        let diagnostics = self.client.rpc().diagnostics().await?;
        if diagnostics.chain_spec_hash != status.chain_spec_hash || diagnostics.chunk_size == 0 {
            return Err(Error::Binding("inconsistent source identity".into()));
        }
        Ok(Binding {
            chain_spec_hash: spec,
            chain_id: self.client.rpc().chain_id().await?.to_string(),
            genesis,
            chunk_size: diagnostics.chunk_size,
            decoder_hash: config.decoder_hash()?,
        })
    }
    async fn events(&self, after: Option<ChainCursorJson>) -> Result<ChainEventPageJson> {
        Ok(self.client.rpc().chain_events(after, 1).await?)
    }
    async fn header(&self, height: u64) -> Result<Option<neutrin0_rpc::HeaderJson>> {
        Ok(self
            .client
            .rpc()
            .header(BlockIdJson(BlockId::Height(height)))
            .await?)
    }
    async fn block(&self, height: u64) -> Result<Option<BlockJson>> {
        Ok(self
            .client
            .rpc()
            .block(BlockIdJson(BlockId::Height(height)))
            .await?)
    }
    async fn artifacts(&self, hash: HashHex) -> Result<Option<BlockArtifactsJson>> {
        Ok(self.client.rpc().block_artifacts(hash).await?)
    }
    async fn ethereum(
        &self,
        hash: HashHex,
    ) -> Result<(Value, Vec<neutrin0_rpc::client::EthereumReceiptJson>)> {
        let block = self
            .client
            .rpc()
            .ethereum_block(hash, true)
            .await?
            .ok_or(Error::BranchChanged)?;
        let receipts = self
            .client
            .rpc()
            .block_receipts(serde_json::to_value(hash)?)
            .await?
            .ok_or(Error::BranchChanged)?;
        Ok((block, receipts))
    }
    async fn chunk(&self, id: u64) -> Result<Option<ChunkJson>> {
        Ok(self.client.rpc().chunk(Some(id)).await?)
    }
    async fn certificate(&self, id: u64) -> Result<Option<CertificateJson>> {
        Ok(self.client.rpc().certificate(id).await?)
    }
    async fn proof(&self, id: ArtifactIdJson) -> Result<Option<ArtifactInfoJson>> {
        Ok(self.client.rpc().artifact(id).await?)
    }
    async fn validators(&self) -> Result<Vec<ValidatorJson>> {
        Ok(self.client.rpc().validators().await?)
    }
}
