//! Derived rows and progress are committed together; orphan data never contributes to canonical queries.
use super::{Writer, save_state, state_in};
use crate::{Error, Result, model::IndexedBlock};
use neutrin0_rpc::types::{
    ArtifactIdJson, ArtifactInfoJson, CertificateJson, ChainCursorJson, ChainPointJson, ChunkJson,
    ValidatorJson,
};
use sqlx::{Connection, Postgres, Row, Transaction, types::Json};

impl Writer {
    /// Atomically append one complete block and all its transaction/log/token rows.
    pub async fn append(&mut self, block: &IndexedBlock) -> Result<()> {
        let mut tx = self.connection.begin().await?;
        let mut state = state_in(&mut tx)
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        if state.head.height.checked_add(1) != Some(block.header.height)
            || state.head.hash != block.header.parent_hash
        {
            return Err(Error::BranchChanged);
        }
        insert_block(&mut tx, block).await?;
        let hash = crate::model::hex(&block.header.block_hash.0);
        sqlx::query("INSERT INTO canonical_blocks(height,hash) VALUES($1::numeric,$2)")
            .bind(block.header.height.to_string())
            .bind(&hash)
            .execute(&mut *tx)
            .await?;
        let locator = serde_json::to_string(&ArtifactIdJson::BlockProof {
            block: block.header.block_hash,
        })?;
        sqlx::query("INSERT INTO proof_metadata(locator,height,kind,block_hash,availability) VALUES($1,$2::numeric,'block_proof',$3,'not_observed') ON CONFLICT DO NOTHING")
            .bind(locator).bind(block.header.height.to_string()).bind(&hash).execute(&mut *tx).await?;
        state.head = ChainPointJson {
            hash: block.header.block_hash,
            height: block.header.height,
        };
        state.transactions = state
            .transactions
            .checked_add(block.transactions.len() as u64)
            .ok_or_else(|| Error::Data("transaction total exhausted".into()))?;
        state.logs = state
            .logs
            .checked_add(block.logs.len() as u64)
            .ok_or_else(|| Error::Data("log total exhausted".into()))?;
        let gas = state
            .gas
            .parse::<u128>()
            .map_err(|_| Error::Data("invalid saved gas total".into()))?;
        state.gas = gas
            .checked_add(u128::from(block.header.gas_used))
            .ok_or_else(|| Error::Data("gas total exhausted".into()))?
            .to_string();
        save_state(&mut tx, &state).await?;
        tx.commit().await?;
        Ok(())
    }
    /// Roll back only unfinalized canonical membership and exact totals. Retain bounded orphan detail separately.
    pub async fn rollback(&mut self, ancestor: ChainPointJson) -> Result<()> {
        let mut tx = self.connection.begin().await?;
        let mut state = state_in(&mut tx)
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        if ancestor.height < state.finalized.height {
            return Err(Error::FinalityConflict);
        }
        if canonical_hash(&mut tx, ancestor.height, state.binding.genesis.hash).await?
            != Some(ancestor.hash)
        {
            return Err(Error::BranchChanged);
        }
        if ancestor == state.head {
            tx.commit().await?;
            return Ok(());
        }
        let sums = sqlx::query("SELECT COALESCE(SUM(b.transaction_count),0)::text AS txs,COALESCE(SUM(b.log_count),0)::text AS logs,COALESCE(SUM(b.gas_used),0)::text AS gas FROM canonical_blocks c JOIN blocks b ON b.hash=c.hash WHERE c.height>$1::numeric")
            .bind(ancestor.height.to_string()).fetch_one(&mut *tx).await?;
        let value = |name| -> Result<u128> {
            sums.try_get::<String, _>(name)?
                .parse()
                .map_err(|_| Error::Data("invalid canonical totals".into()))
        };
        state.transactions = state
            .transactions
            .checked_sub(
                u64::try_from(value("txs")?)
                    .map_err(|_| Error::Data("transaction total overflow".into()))?,
            )
            .ok_or_else(|| Error::Data("transaction total underflow".into()))?;
        state.logs = state
            .logs
            .checked_sub(
                u64::try_from(value("logs")?)
                    .map_err(|_| Error::Data("log total overflow".into()))?,
            )
            .ok_or_else(|| Error::Data("log total underflow".into()))?;
        state.gas = state
            .gas
            .parse::<u128>()
            .map_err(|_| Error::Data("invalid gas total".into()))?
            .checked_sub(value("gas")?)
            .ok_or_else(|| Error::Data("gas total underflow".into()))?
            .to_string();
        sqlx::query("DELETE FROM canonical_blocks WHERE height>$1::numeric")
            .bind(ancestor.height.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM proof_metadata WHERE block_hash IN (SELECT hash FROM blocks WHERE height>$1::numeric)").bind(ancestor.height.to_string()).execute(&mut *tx).await?;
        state.head = ancestor;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::Data("query generation exhausted".into()))?;
        save_state(&mut tx, &state).await?;
        tx.commit().await?;
        Ok(())
    }
    /// Publish an indexed complete Chunk only when its endpoints and contiguous range match local canonical data.
    pub async fn finalize(
        &mut self,
        chunk: &ChunkJson,
        certificate: &CertificateJson,
    ) -> Result<()> {
        let mut tx = self.connection.begin().await?;
        let mut state = state_in(&mut tx)
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        if chunk.chunk_id != state.finalized_chunks
            || chunk.start_height
                != state
                    .finalized
                    .height
                    .checked_add(1)
                    .ok_or_else(|| Error::Data("height exhausted".into()))?
            || chunk
                .end_height
                .checked_sub(chunk.start_height)
                .and_then(|n| n.checked_add(1))
                != Some(state.binding.chunk_size)
            || chunk.end_height > state.head.height
            || certificate.chunk_id != chunk.chunk_id
            || certificate.chunk_hash != chunk.hash
            || canonical_hash(&mut tx, chunk.start_height, state.binding.genesis.hash).await?
                != Some(chunk.start_block_hash)
            || canonical_hash(&mut tx, chunk.end_height, state.binding.genesis.hash).await?
                != Some(chunk.end_block_hash)
        {
            return Err(Error::Data(
                "Chunk/certificate do not match the indexed canonical range".into(),
            ));
        }
        sqlx::query("INSERT INTO chunks(chunk_id,end_height,data,certificate) VALUES($1::numeric,$2::numeric,$3,$4)")
            .bind(chunk.chunk_id.to_string()).bind(chunk.end_height.to_string()).bind(Json(chunk)).bind(Json(certificate)).execute(&mut *tx).await?;
        state.finalized_chunks = state
            .finalized_chunks
            .checked_add(1)
            .ok_or_else(|| Error::Data("chunk count exhausted".into()))?;
        state.finalized = ChainPointJson {
            hash: chunk.end_block_hash,
            height: chunk.end_height,
        };
        save_state(&mut tx, &state).await?;
        tx.commit().await?;
        Ok(())
    }
    /// Store a content-pinned artifact observation; bytes remain owned by the source node.
    pub async fn proof(
        &mut self,
        id: &ArtifactIdJson,
        height: u64,
        info: Option<&ArtifactInfoJson>,
        availability: &str,
    ) -> Result<()> {
        let block = match id {
            ArtifactIdJson::BlockProof { block } => Some(crate::model::hex(&block.0)),
            _ => None,
        };
        let kind = match id {
            ArtifactIdJson::BlockProof { .. } => "block_proof",
            ArtifactIdJson::ChunkProof { .. } => "chunk_proof",
            ArtifactIdJson::Certificate { .. } => "certificate",
        };
        sqlx::query("INSERT INTO proof_metadata(locator,height,kind,block_hash,data,availability) VALUES($1,$2::numeric,$3,$4,$5,$6) ON CONFLICT(locator) DO UPDATE SET data=COALESCE(EXCLUDED.data,proof_metadata.data),availability=EXCLUDED.availability,observed_at=CURRENT_TIMESTAMP")
            .bind(serde_json::to_string(id)?).bind(height.to_string()).bind(kind).bind(block).bind(info.map(Json)).bind(availability).execute(&mut *self.connection).await?;
        Ok(())
    }
    /// Advance the durable event cursor only after complete endpoint reconciliation.
    pub async fn checkpoint(
        &mut self,
        cursor: ChainCursorJson,
        head: ChainPointJson,
        finalized: ChainPointJson,
        finalized_chunks: u64,
        validators: &[ValidatorJson],
    ) -> Result<()> {
        let mut tx = self.connection.begin().await?;
        let mut state = state_in(&mut tx)
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        if state.head != head
            || state.finalized != finalized
            || state.finalized_chunks != finalized_chunks
        {
            return Err(Error::BranchChanged);
        }
        sqlx::query("INSERT INTO validator_snapshots(finalized_chunks,finalized_hash,data) VALUES($1::numeric,$2,$3) ON CONFLICT(finalized_chunks) DO UPDATE SET data=EXCLUDED.data,observed_at=CURRENT_TIMESTAMP")
            .bind(finalized_chunks.to_string()).bind(crate::model::hex(&finalized.hash.0)).bind(Json(validators)).execute(&mut *tx).await?;
        state.cursor = Some(cursor);
        state.source_head = head;
        state.source_finalized = finalized;
        state.phase = "live".into();
        state.last_error = None;
        state.observed_at = sqlx::query_scalar("SELECT CURRENT_TIMESTAMP::text")
            .fetch_one(&mut *tx)
            .await?;
        save_state(&mut tx, &state).await?;
        tx.commit().await?;
        Ok(())
    }
    /// Delete only orphan bodies below the configured orphan detail horizon.
    pub async fn prune_orphans(&mut self, floor: u64) -> Result<()> {
        sqlx::query("DELETE FROM blocks b WHERE height<$1::numeric AND NOT EXISTS(SELECT 1 FROM canonical_blocks c WHERE c.hash=b.hash)")
            .bind(floor.to_string()).execute(&mut *self.connection).await?;
        Ok(())
    }
}
pub(super) async fn canonical_hash(
    tx: &mut Transaction<'_, Postgres>,
    height: u64,
    genesis: neutrin0_rpc::HashHex,
) -> Result<Option<neutrin0_rpc::HashHex>> {
    if height == 0 {
        return Ok(Some(genesis));
    }
    let hash: Option<String> =
        sqlx::query_scalar("SELECT hash FROM canonical_blocks WHERE height=$1::numeric")
            .bind(height.to_string())
            .fetch_optional(&mut **tx)
            .await?;
    hash.map(|value| serde_json::from_value(serde_json::Value::String(value)).map_err(Error::from))
        .transpose()
}
async fn insert_block(tx: &mut Transaction<'_, Postgres>, block: &IndexedBlock) -> Result<()> {
    let hash = crate::model::hex(&block.header.block_hash.0);
    // Re-adopting an orphan starts from its exact rows; no duplicate derived effects survive.
    sqlx::query("DELETE FROM blocks WHERE hash=$1 AND NOT EXISTS(SELECT 1 FROM canonical_blocks WHERE hash=$1)").bind(&hash).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO blocks(hash,height,parent_hash,timestamp,gas_used,runtime_hash,decoding,header,artifacts,transaction_count,log_count) VALUES($1,$2::numeric,$3,$4::numeric,$5::numeric,$6,$7,$8,$9,$10,$11)")
        .bind(&hash).bind(block.header.height.to_string()).bind(crate::model::hex(&block.header.parent_hash.0)).bind(block.header.timestamp.to_string()).bind(block.header.gas_used.to_string())
        .bind(&block.runtime_hash).bind(&block.decoding).bind(Json(&block.header)).bind(&block.artifacts).bind(i64::try_from(block.transactions.len()).map_err(|_| Error::Data("too many transactions".into()))?).bind(i64::try_from(block.logs.len()).map_err(|_| Error::Data("too many logs".into()))?).execute(&mut **tx).await?;
    for item in &block.transactions {
        sqlx::query("INSERT INTO transactions(block_hash,position,height,hash,envelope_hash,from_address,to_address,kind,status,data,raw,contract_address) VALUES($1,$2,$3::numeric,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
            .bind(&hash).bind(i64::from(item.position)).bind(block.header.height.to_string()).bind(&item.hash).bind(&item.envelope_hash).bind(&item.from).bind(&item.to).bind(&item.kind).bind(&item.status).bind(Json(item)).bind(&item.raw).bind(&item.contract_address).execute(&mut **tx).await?;
    }
    for item in &block.logs {
        sqlx::query("INSERT INTO logs(block_hash,log_index,transaction_position,height,address,topics,data) VALUES($1,$2,$3,$4::numeric,$5,$6,$7)")
            .bind(&hash).bind(i64::from(item.index)).bind(i64::from(item.transaction_position)).bind(block.header.height.to_string()).bind(&item.address).bind(&item.topics).bind(Json(item)).execute(&mut **tx).await?;
    }
    for item in &block.transfers {
        sqlx::query("INSERT INTO token_transfers(block_hash,log_index,item_index,height,contract,from_address,to_address,standard,data) VALUES($1,$2,$3,$4::numeric,$5,$6,$7,$8,$9)")
            .bind(&hash).bind(i64::from(item.log_index)).bind(i64::from(item.item_index)).bind(block.header.height.to_string()).bind(&item.contract).bind(&item.from).bind(&item.to).bind(&item.standard).bind(Json(item)).execute(&mut **tx).await?;
    }
    Ok(())
}
