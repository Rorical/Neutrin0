//! Event-driven snapshot reconciliation with bounded backfill and finalized rollback protection.
use crate::{
    Error, Result,
    config::Config,
    db::{Store, Writer},
    extract,
    source::Source,
};
use neutrin0_rpc::types::{ArtifactIdJson, ChainEventStatusJson, ChainPointJson};
use std::sync::Arc;

/// One independent ingestion worker. Its PostgreSQL session owns the single-writer lease.
pub struct Indexer {
    config: Config,
    store: Store,
    source: Arc<dyn Source>,
    writer: Writer,
}
impl Indexer {
    /// Bind source identity/decoder semantics and acquire ingestion ownership.
    pub async fn new(config: Config, store: Store, source: Arc<dyn Source>) -> Result<Self> {
        config.validate()?;
        let mut writer = store.writer().await?;
        let binding = match source.binding(&config).await {
            Ok(binding) => binding,
            Err(error) => {
                if let Some(state) = store.state().await? {
                    let _ = writer
                        .observe(
                            state.source_head,
                            state.source_finalized,
                            Some(error.to_string()),
                        )
                        .await;
                }
                return Err(error);
            }
        };
        if binding.chain_spec_hash != crate::model::hash(&config.chain_spec_hash)?
            || binding.chunk_size == 0
        {
            return Err(Error::Binding(
                "source identity differs from configured profile".into(),
            ));
        }

        writer.bind(binding).await?;
        Ok(Self {
            config,
            store,
            source,
            writer,
        })
    }
    /// Reconcile a bounded batch. True means a complete source observation was durably checkpointed.
    /// Intermediate event heads are not required: the current atomic status is the canonical target.
    pub async fn step(&mut self) -> Result<bool> {
        let saved = self
            .store
            .state()
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        let page = match self.source.events(saved.cursor.clone()).await {
            Ok(page) => page,
            Err(Error::Rpc(jsonrpsee::core::client::Error::Call(error)))
                if error.code() == -32028 =>
            {
                self.source.events(None).await?
            }
            Err(error) => return Err(error),
        };
        let target = page.status;
        self.check_status(&target).await?;
        let finalized_floor = saved.finalized.height;
        if target.finalized.height < finalized_floor
            || target.finalized_chunks < saved.finalized_chunks
            || target.head.height < finalized_floor
        {
            return Err(Error::SourceBehind);
        }
        self.writer
            .observe(target.head, target.finalized, None)
            .await?;
        self.reconcile_fork(&target).await?;
        let start = self
            .store
            .state()
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?
            .head
            .height;
        let end = start
            .saturating_add(u64::from(self.config.batch_blocks))
            .min(target.head.height);
        for height in (start..end).map(|height| height + 1) {
            let block = self.source.block(height).await?.ok_or_else(|| Error::Data(format!("source block {height} unavailable; historical backfill requires retained bodies")))?;
            if block.header.height != height {
                return Err(Error::BranchChanged);
            }
            let indexed = extract::block(self.source.as_ref(), &self.config, block).await?;
            self.writer.append(&indexed).await?;
            self.observe_proof(
                ArtifactIdJson::BlockProof {
                    block: indexed.header.block_hash,
                },
                indexed.header.height,
            )
            .await?;
        }
        self.index_chunks(&target).await?;
        let state = self
            .store
            .state()
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        self.writer
            .prune_orphans(
                state
                    .head
                    .height
                    .saturating_sub(u64::from(self.config.orphan_retention_blocks)),
            )
            .await?;
        self.refresh_proofs().await?;
        if state.head != target.head
            || state.finalized != target.finalized
            || state.finalized_chunks != target.finalized_chunks
        {
            return Ok(false);
        }
        let validators = self.source.validators().await?;
        let fresh = self.source.events(None).await?.status;
        self.check_status(&fresh).await?;
        if fresh.head != target.head
            || fresh.finalized != target.finalized
            || fresh.finalized_chunks != target.finalized_chunks
        {
            return Ok(false);
        }
        self.writer
            .checkpoint(
                target.latest,
                target.head,
                target.finalized,
                target.finalized_chunks,
                &validators,
            )
            .await?;
        Ok(true)
    }
    /// Persist an honest error state without acknowledging new source events.
    pub async fn record_error(&mut self, error: &Error) -> Result<()> {
        let state = self
            .store
            .state()
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        self.writer
            .observe(
                state.source_head,
                state.source_finalized,
                Some(error.to_string()),
            )
            .await
    }
    async fn check_status(&self, status: &ChainEventStatusJson) -> Result<()> {
        let state = self
            .store
            .state()
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        if crate::model::hex(&status.chain_spec_hash.0) != state.binding.chain_spec_hash {
            return Err(Error::Binding(
                "node event stream belongs to another specification".into(),
            ));
        }
        if status.finalized.height == state.finalized.height
            && status.finalized.hash != state.finalized.hash
        {
            return Err(Error::FinalityConflict);
        }
        if (status.head.height == 0 && status.head.hash != state.binding.genesis.hash)
            || (status.finalized.height == 0 && status.finalized.hash != state.binding.genesis.hash)
            || status.finalized.height > status.head.height
            || status
                .finalized_chunks
                .checked_mul(state.binding.chunk_size)
                != Some(status.finalized.height)
        {
            return Err(Error::Data("inconsistent source finality status".into()));
        }
        Ok(())
    }
    async fn reconcile_fork(&mut self, target: &ChainEventStatusJson) -> Result<()> {
        let state = self
            .store
            .state()
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        let anchor = if state.finalized.height == 0 {
            state.binding.genesis.hash
        } else {
            self.source
                .header(state.finalized.height)
                .await?
                .ok_or_else(|| Error::Data("saved finalized anchor unavailable on source".into()))?
                .block_hash
        };
        if anchor != state.finalized.hash {
            return Err(Error::FinalityConflict);
        }
        let mut height = state.head.height.min(target.head.height);
        let mut searched = 0;
        let ancestor = loop {
            let remote = if height == 0 {
                state.binding.genesis.hash
            } else {
                self.source
                    .header(height)
                    .await?
                    .ok_or_else(|| Error::Data("canonical ancestry unavailable on source".into()))?
                    .block_hash
            };
            if self.store.canonical(height).await? == Some(remote) {
                break ChainPointJson {
                    hash: remote,
                    height,
                };
            }
            if height <= state.finalized.height {
                return Err(Error::FinalityConflict);
            }
            if searched >= self.config.max_reorg_blocks {
                return Err(Error::Data("rollback search limit exceeded; an archive source/manual reconciliation is required".into()));
            }
            height -= 1;
            searched += 1;
        };
        self.writer.rollback(ancestor).await
    }
    async fn index_chunks(&mut self, target: &ChainEventStatusJson) -> Result<()> {
        let state = self
            .store
            .state()
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        let count = (state.head.height / state.binding.chunk_size).min(target.finalized_chunks);
        for id in state.finalized_chunks..count {
            let chunk = self
                .source
                .chunk(id)
                .await?
                .ok_or_else(|| Error::Data(format!("finalized Chunk {id} is unavailable")))?;
            let certificate = self
                .source
                .certificate(id)
                .await?
                .ok_or_else(|| Error::Data(format!("certificate {id} is unavailable")))?;
            self.writer.finalize(&chunk, &certificate).await?;
            self.observe_proof(ArtifactIdJson::ChunkProof { chunk: id }, chunk.end_height)
                .await?;
            self.observe_proof(ArtifactIdJson::Certificate { chunk: id }, chunk.end_height)
                .await?;
        }
        Ok(())
    }
    async fn refresh_proofs(&mut self) -> Result<()> {
        for (height, id) in self
            .store
            .proof_candidates(self.config.proof_refresh_blocks)
            .await?
        {
            self.observe_proof(id, height).await?;
        }
        Ok(())
    }
    async fn observe_proof(&mut self, id: ArtifactIdJson, height: u64) -> Result<()> {
        let (info, availability) = match self.source.proof(id.clone()).await {
            Ok(Some(info)) if info.id == id => (Some(info), "available"),
            Ok(Some(_)) => {
                return Err(Error::Data(
                    "proof metadata names a different locator".into(),
                ));
            }
            Ok(None) => (None, "not_available"),
            Err(Error::Rpc(jsonrpsee::core::client::Error::Call(error)))
                if matches!(error.code(), -32026 | -32024) =>
            {
                (
                    None,
                    if error.code() == -32024 {
                        "pruned"
                    } else {
                        "unavailable"
                    },
                )
            }
            Err(error) => return Err(error),
        };
        self.writer
            .proof(&id, height, info.as_ref(), availability)
            .await
    }
}
