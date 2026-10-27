//! PostgreSQL publication, writer ownership and consistent read snapshots.
mod publish;
pub mod query;
use crate::{
    Error, Result,
    model::{Binding, IndexState},
};
use sqlx::{
    ConnectOptions, Connection, PgPool, Postgres, Row, Transaction,
    pool::PoolConnection,
    postgres::{PgConnectOptions, PgPoolOptions},
    types::Json,
};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::sync::Mutex;

const SCHEMA: &str = include_str!("schema.sql");
const LOCK_CLASS: i32 = 1_313_477_711;
/// PostgreSQL index store. All names live in the configured dedicated schema.
#[derive(Clone)]
pub struct Store {
    pub(crate) pool: PgPool,
    schema: String,
}
/// One connection owns the ingestion lease; it is closed instead of pooled on drop.
pub struct Writer {
    pub(crate) connection: PoolConnection<Postgres>,
}
/// One read-only repeatable-read transaction shared by every resolver in a request.
pub struct ReadView {
    pub(crate) transaction: Mutex<Transaction<'static, Postgres>>,
    /// Index progress captured in the same snapshot as all query results.
    pub state: IndexState,
}
impl Store {
    /// Dedicated schema shared by the ingestion worker and query replicas.
    pub fn schema(&self) -> &str {
        &self.schema
    }
    /// Open a dedicated schema, refusing one created with another schema format.
    pub async fn open(url: &str, schema: &str) -> Result<Self> {
        crate::config::validate_schema(schema)?;
        let pool = connect(url, schema).await?;
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1,hashtext($2))")
            .bind(LOCK_CLASS + 1)
            .bind(schema)
            .execute(&mut *tx)
            .await?;
        sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\""))
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql(SCHEMA).execute(&mut *tx).await?;
        let schema_hash = crate::model::hex(&neutrin0_primitives::blake3_256(SCHEMA.as_bytes()));
        sqlx::query(
            "INSERT INTO index_meta(singleton,schema_hash) VALUES(TRUE,$1) ON CONFLICT DO NOTHING",
        )
        .bind(&schema_hash)
        .execute(&mut *tx)
        .await?;
        let stored: String =
            sqlx::query_scalar("SELECT schema_hash FROM index_meta WHERE singleton")
                .fetch_one(&mut *tx)
                .await?;
        if stored != schema_hash {
            return Err(Error::Binding(
                "incompatible index schema; use a fresh dedicated schema".into(),
            ));
        }
        tx.commit().await?;
        Ok(Self {
            pool,
            schema: schema.into(),
        })
    }
    /// Open a read-only query replica against an already initialized dedicated schema.
    pub async fn open_read_only(url: &str, schema: &str) -> Result<Self> {
        crate::config::validate_schema(schema)?;
        let pool = connect(url, schema).await?;
        let stored: String =
            sqlx::query_scalar("SELECT schema_hash FROM index_meta WHERE singleton")
                .fetch_one(&pool)
                .await?;
        if stored != crate::model::hex(&neutrin0_primitives::blake3_256(SCHEMA.as_bytes())) {
            return Err(Error::Binding("incompatible index schema".into()));
        }
        Ok(Self {
            pool,
            schema: schema.into(),
        })
    }
    /// Acquire exclusive ingestion ownership. Query-only replicas do not need this lease.
    pub async fn writer(&self) -> Result<Writer> {
        let mut connection = self.pool.acquire().await?;
        connection.close_on_drop();
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1,hashtext($2))")
            .bind(LOCK_CLASS)
            .bind(&self.schema)
            .fetch_one(&mut *connection)
            .await?;
        if !acquired {
            return Err(Error::WriterBusy);
        }
        Ok(Writer { connection })
    }
    /// Read current progress, absent before the first successful source binding.
    pub async fn state(&self) -> Result<Option<IndexState>> {
        let value: Option<Json<IndexState>> =
            sqlx::query_scalar("SELECT state FROM index_meta WHERE singleton")
                .fetch_one(&self.pool)
                .await?;
        Ok(value.map(|json| json.0))
    }
    /// Whether the durable source checkpoint is live and has been observed within three minutes.
    pub async fn ready(&self) -> Result<bool> {
        Ok(sqlx::query_scalar("SELECT COALESCE(state->>'phase'='live' AND state->'cursor'<>'null'::jsonb AND NULLIF(state->>'observed_at','')::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '180 seconds', FALSE) FROM index_meta WHERE singleton")
            .fetch_one(&self.pool).await?)
    }
    /// Saved canonical membership, used for bounded rollback/restart reconciliation.
    pub async fn canonical(&self, height: u64) -> Result<Option<neutrin0_rpc::HashHex>> {
        let mut tx = self.pool.begin().await?;
        let state = state_in(&mut tx)
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        let hash = publish::canonical_hash(&mut tx, height, state.binding.genesis.hash).await?;
        tx.commit().await?;
        Ok(hash)
    }
    /// Fair bounded retry queue for delayed/missed proofs, combined with recent observations.
    pub async fn proof_candidates(
        &self,
        limit: u32,
    ) -> Result<Vec<(u64, neutrin0_rpc::types::ArtifactIdJson)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query("SELECT DISTINCT height::text AS height,locator FROM ((SELECT height,locator FROM proof_metadata WHERE availability IN ('not_observed','pending','unavailable') ORDER BY observed_at ASC LIMIT $1) UNION ALL (SELECT c.height,p.locator FROM canonical_blocks c JOIN proof_metadata p ON p.block_hash=c.hash AND p.kind='block_proof' ORDER BY c.height DESC LIMIT $2)) q")
            .bind(i64::from(limit.div_ceil(2))).bind(i64::from(limit/2)).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    crate::model::number(&row.try_get::<String, _>("height")?)?,
                    serde_json::from_str(&row.try_get::<String, _>("locator")?)?,
                ))
            })
            .collect()
    }
    /// Open an immutable, request-local database snapshot.
    pub async fn read_view(&self) -> Result<Arc<ReadView>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        let state = state_in(&mut tx)
            .await?
            .ok_or_else(|| Error::Data("index is not bound to a source yet".into()))?;
        Ok(Arc::new(ReadView {
            transaction: Mutex::new(tx),
            state,
        }))
    }
    /// Release pooled reader connections during orderly service shutdown.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}
pub(crate) async fn state_in(tx: &mut Transaction<'_, Postgres>) -> Result<Option<IndexState>> {
    let value: Option<Json<IndexState>> =
        sqlx::query_scalar("SELECT state FROM index_meta WHERE singleton")
            .fetch_one(&mut **tx)
            .await?;
    Ok(value.map(|json| json.0))
}
pub(crate) async fn save_state(
    tx: &mut Transaction<'_, Postgres>,
    state: &IndexState,
) -> Result<()> {
    sqlx::query("UPDATE index_meta SET state=$1 WHERE singleton")
        .bind(Json(state))
        .execute(&mut **tx)
        .await?;
    Ok(())
}
impl Writer {
    /// Establish or check an immutable chain/decoder binding before indexing data.
    pub async fn bind(&mut self, binding: Binding) -> Result<IndexState> {
        let mut tx = self.connection.begin().await?;
        if let Some(state) = state_in(&mut tx).await? {
            if state.binding != binding {
                return Err(Error::Binding(
                    "source or decoder differs from saved index".into(),
                ));
            }
            tx.commit().await?;
            return Ok(state);
        }
        let genesis = neutrin0_rpc::types::ChainPointJson {
            hash: binding.genesis.hash,
            height: 0,
        };
        let state = IndexState {
            binding,
            head: genesis,
            finalized: genesis,
            finalized_chunks: 0,
            cursor: None,
            generation: 0,
            transactions: 0,
            logs: 0,
            gas: "0".into(),
            source_head: genesis,
            source_finalized: genesis,
            phase: "starting".into(),
            last_error: None,
            observed_at: String::new(),
        };
        save_state(&mut tx, &state).await?;
        tx.commit().await?;
        Ok(state)
    }
    /// Publish sync status without advancing its event checkpoint.
    pub async fn observe(
        &mut self,
        head: neutrin0_rpc::types::ChainPointJson,
        finalized: neutrin0_rpc::types::ChainPointJson,
        error: Option<String>,
    ) -> Result<()> {
        let mut tx = self.connection.begin().await?;
        let mut state = state_in(&mut tx)
            .await?
            .ok_or_else(|| Error::Data("unbound index".into()))?;
        state.source_head = head;
        state.source_finalized = finalized;
        state.phase = if error.is_some() {
            "error"
        } else if state.cursor.is_some() && state.head == head && state.finalized == finalized {
            "live"
        } else {
            "backfilling"
        }
        .into();
        state.last_error = error;
        state.observed_at = sqlx::query("SELECT CURRENT_TIMESTAMP::text AS time")
            .fetch_one(&mut *tx)
            .await?
            .try_get("time")?;
        save_state(&mut tx, &state).await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn connect(url: &str, schema: &str) -> Result<PgPool> {
    let options = PgConnectOptions::from_str(url)?.disable_statement_logging();
    let scope = schema.to_owned();
    let pool = PgPoolOptions::new().max_connections(18).acquire_timeout(Duration::from_secs(10))
            .after_connect(move |connection, _| {
                let search_path = format!("\"{scope}\", pg_catalog");
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path',$1,false),set_config('statement_timeout','5000',false),set_config('idle_in_transaction_session_timeout','15000',false)")
                        .bind(search_path).execute(connection).await?;
                    Ok(())
                })
            }).connect_with(options).await?;
    Ok(pool)
}
