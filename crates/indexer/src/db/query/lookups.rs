//! Exact single-row and aggregate lookups inside the request snapshot.
use super::{Kind, Record, page::base};
use crate::{Error, Result, db::ReadView};
use serde_json::Value;
use sqlx::{Row, types::Json};

impl ReadView {
    /// Exact canonical membership within this request snapshot.
    pub async fn canonical_hash(&self, height: u64) -> Result<Option<String>> {
        if height == 0 {
            return Ok(Some(crate::model::hex(&self.state.binding.genesis.hash.0)));
        }
        let mut tx = self.transaction.lock().await;
        let hash = sqlx::query_scalar("SELECT hash FROM canonical_blocks WHERE height=$1::numeric")
            .bind(height.to_string())
            .fetch_optional(&mut **tx)
            .await?;
        drop(tx);
        Ok(hash)
    }
    /// Stored block detail by exact hash, including retained orphans.
    pub async fn block(&self, hash: &str) -> Result<Option<Record>> {
        let hash = crate::model::hash(hash)?;
        let mut tx = self.transaction.lock().await;
        let row = sqlx::query("SELECT height::text,hash AS block_hash, jsonb_build_object('header',header,'runtimeHash',runtime_hash,'decoding',decoding,'txCount',transaction_count::text) AS data FROM blocks WHERE hash=$1").bind(hash).fetch_optional(&mut **tx).await?;
        drop(tx);
        row.map(|row| {
            Ok(Record {
                height: crate::model::number(&row.try_get::<String, _>("height")?)?,
                block_hash: row.try_get("block_hash")?,
                order: 0,
                suborder: 0,
                cursor: String::new(),
                data: row.try_get::<Json<Value>, _>("data")?.0,
            })
        })
        .transpose()
    }
    /// Native envelope bytes are exposed only through bounded slices.
    pub async fn raw(
        &self,
        block_hash: &str,
        position: u32,
        offset: u32,
        length: u32,
    ) -> Result<(u64, Vec<u8>)> {
        if length == 0 || length > 65_536 {
            return Err(Error::Data("raw slice length must be 1..65536".into()));
        }
        let start = i32::try_from(u64::from(offset) + 1)
            .map_err(|_| Error::Data("raw offset exceeds supported range".into()))?;
        let count = i32::try_from(length).expect("bounded slice");
        let mut tx = self.transaction.lock().await;
        let row = sqlx::query("SELECT octet_length(raw)::bigint AS total,substring(raw FROM $3 FOR $4) AS bytes FROM transactions WHERE block_hash=$1 AND position=$2")
            .bind(block_hash).bind(i64::from(position)).bind(start).bind(count).fetch_one(&mut **tx).await?;
        drop(tx);
        let total = u64::try_from(row.try_get::<i64, _>("total")?)
            .map_err(|_| Error::Data("negative byte length".into()))?;
        if u64::from(offset) > total {
            return Err(Error::Data("raw slice offset exceeds length".into()));
        }
        Ok((total, row.try_get("bytes")?))
    }
    /// Current source committee observation, tied to its indexed finalized boundary.
    pub async fn validators(&self) -> Result<Value> {
        let mut tx = self.transaction.lock().await;
        let value: Option<Json<Value>> = sqlx::query_scalar(
            "SELECT data FROM validator_snapshots WHERE finalized_chunks=$1::numeric",
        )
        .bind(self.state.finalized_chunks.to_string())
        .fetch_optional(&mut **tx)
        .await?;
        drop(tx);
        value.map_or(Ok(Value::Null), |json| {
            let validators: Vec<neutrin0_rpc::types::ValidatorJson> = serde_json::from_value(json.0)?;
            Ok(Value::Array(validators.into_iter().map(|v| serde_json::json!({"pubkey":v.pubkey,"withdrawalCredentials":v.withdrawal_credentials,"effectiveStake":v.effective_stake.to_string(),"activationEpoch":v.activation_epoch.to_string(),"exitEpoch":v.exit_epoch.to_string()})).collect()))
        })
    }
    /// Address activity counts are indexed participation, not account balances.
    pub async fn address(&self, address: &str) -> Result<Value> {
        let address = crate::model::address(address)?;
        let mut tx = self.transaction.lock().await;
        let row = sqlx::query("SELECT COUNT(*)::text AS transactions,MIN(t.height)::text AS first_height,MAX(t.height)::text AS last_height FROM transactions t JOIN canonical_blocks c ON c.hash=t.block_hash WHERE t.from_address=$1 OR t.to_address=$1 OR t.contract_address=$1").bind(&address).fetch_one(&mut **tx).await?;
        let transfers: String = sqlx::query_scalar("SELECT COUNT(*)::text FROM token_transfers t JOIN canonical_blocks c ON c.hash=t.block_hash WHERE t.from_address=$1 OR t.to_address=$1").bind(&address).fetch_one(&mut **tx).await?;
        drop(tx);
        Ok(
            serde_json::json!({"address":address,"transactionCount":row.try_get::<String,_>("transactions")?,"tokenTransferCount":transfers,"firstHeight":row.try_get::<Option<String>,_>("first_height")?,"lastHeight":row.try_get::<Option<String>,_>("last_height")?}),
        )
    }
    /// Bounded time buckets over committed canonical blocks, including only actual indexed counts.
    pub async fn activity(&self, buckets: i32, seconds: i32) -> Result<Vec<Value>> {
        if !(1..=168).contains(&buckets) || !matches!(seconds, 3600 | 86400) {
            return Err(Error::Data(
                "activity requires 1..168 hourly/daily buckets".into(),
            ));
        }
        let mut tx = self.transaction.lock().await;
        let rows = sqlx::query("WITH tip AS (SELECT COALESCE((SELECT timestamp FROM blocks WHERE hash=$3),0) AS time) SELECT (floor(b.timestamp/$1::numeric)*$1::numeric)::text AS bucket,COUNT(*)::text AS blocks,SUM(b.transaction_count)::text AS transactions,SUM(b.gas_used)::text AS gas FROM blocks b JOIN canonical_blocks c ON c.hash=b.hash,tip WHERE b.timestamp>=GREATEST(0,floor(tip.time/$1::numeric)*$1::numeric-($2::numeric-1)*$1::numeric) GROUP BY floor(b.timestamp/$1::numeric) ORDER BY floor(b.timestamp/$1::numeric)")
            .bind(seconds).bind(buckets).bind(crate::model::hex(&self.state.head.hash.0)).fetch_all(&mut **tx).await?;
        drop(tx);
        rows.into_iter().map(|row| Ok(serde_json::json!({"timestamp":row.try_get::<String,_>("bucket")?,"blockCount":row.try_get::<String,_>("blocks")?,"transactionCount":row.try_get::<String,_>("transactions")?,"gasUsed":row.try_get::<String,_>("gas")?}))).collect()
    }
}

impl ReadView {
    /// Exact stored proof/certificate metadata by its source locator, without an upstream call.
    pub async fn proof(&self, id: &neutrin0_rpc::types::ArtifactIdJson) -> Result<Option<Record>> {
        let mut tx = self.transaction.lock().await;
        let sql = format!("{} WHERE t.locator=$1", base(Kind::Proofs).0);
        let row = sqlx::query(&sql)
            .bind(serde_json::to_string(id)?)
            .fetch_optional(&mut **tx)
            .await?;
        drop(tx);
        row.map(|row| {
            Ok(Record {
                height: crate::model::number(&row.try_get::<String, _>("height")?)?,
                block_hash: row.try_get("block_hash")?,
                order: 0,
                suborder: 0,
                cursor: String::new(),
                data: row.try_get::<Json<Value>, _>("data")?.0,
            })
        })
        .transpose()
    }
    /// Exact finalized Chunk lookup.
    pub async fn chunk(&self, id: &str) -> Result<Option<Record>> {
        crate::model::number(id)?;
        let mut tx = self.transaction.lock().await;
        let row=sqlx::query("SELECT end_height::text AS height,jsonb_build_object('chunk',data) AS data FROM chunks WHERE chunk_id=$1::numeric").bind(id).fetch_optional(&mut **tx).await?;
        drop(tx);
        row.map(|row| {
            Ok(Record {
                height: crate::model::number(&row.try_get::<String, _>("height")?)?,
                block_hash: String::new(),
                order: 0,
                suborder: 0,
                cursor: String::new(),
                data: row.try_get::<Json<Value>, _>("data")?.0,
            })
        })
        .transpose()
    }
    /// Certificate summary; very large certificates remain accessible through source artifact downloads.
    pub async fn certificate(&self, id: &str) -> Result<Option<Value>> {
        crate::model::number(id)?;
        let mut tx = self.transaction.lock().await;
        let row = sqlx::query("SELECT CASE WHEN octet_length(certificate::text)<=1048576 THEN certificate ELSE NULL END AS data,COALESCE(octet_length(certificate::text)>1048576,FALSE) AS oversized FROM chunks WHERE chunk_id=$1::numeric")
            .bind(id).fetch_optional(&mut **tx).await?;
        drop(tx);
        row.map(|row| {
            if row.try_get::<bool, _>("oversized")? {
                return Err(Error::Data(
                    "certificate summary exceeds 1 MiB; download its artifact from the node".into(),
                ));
            }
            let value: Option<Json<Value>> = row.try_get("data")?;
            Ok(value.map(|value| value.0))
        })
        .transpose()
        .map(Option::flatten)
    }
    /// Bounded event data slice from exact retained block/log identity.
    pub async fn log_data(
        &self,
        block: &str,
        index: u32,
        offset: u32,
        length: u32,
    ) -> Result<(u64, String)> {
        let block = crate::model::hash(block)?;
        if length == 0 || length > 65536 {
            return Err(Error::Data("log data length must be 1..65536".into()));
        }
        let start = i32::try_from(u64::from(offset) * 2 + 3)
            .map_err(|_| Error::Data("event offset exceeds supported range".into()))?;
        let count = i32::try_from(length * 2).expect("bounded slice");
        let mut tx = self.transaction.lock().await;
        let row=sqlx::query("SELECT ((length(data->>'data')-2)/2)::bigint AS total,substring(data->>'data' FROM $3 FOR $4) AS bytes FROM logs WHERE block_hash=$1 AND log_index=$2")
            .bind(block).bind(i64::from(index)).bind(start).bind(count).fetch_one(&mut **tx).await?;
        drop(tx);
        let total = u64::try_from(row.try_get::<i64, _>("total")?)
            .map_err(|_| Error::Data("invalid log data length".into()))?;
        if u64::from(offset) > total {
            return Err(Error::Data("event offset exceeds length".into()));
        }
        Ok((total, format!("0x{}", row.try_get::<String, _>("bytes")?)))
    }
}
