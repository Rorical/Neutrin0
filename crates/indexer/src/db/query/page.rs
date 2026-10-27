//! Keyset page assembly: cursor parsing, listing SQL and row decoding.
use super::{Cursor, Filter, Kind, Page, Record};
use crate::{Error, Result, db::ReadView};
use serde_json::Value;
use sqlx::{Postgres, QueryBuilder, Row, postgres::PgRow, types::Json};

impl ReadView {
    /// Query at most 100 rows without OFFSET or cross-reorg pagination.
    pub async fn page(
        &self,
        kind: Kind,
        filter: Filter,
        first: i32,
        after: Option<&str>,
    ) -> Result<Page> {
        if !(1..=100).contains(&first) {
            return Err(Error::Data("first must be between 1 and 100".into()));
        }
        let filter = filter.normalize()?;
        let scope = crate::model::hex(&neutrin0_primitives::blake3_256(&serde_json::to_vec(&(
            &self.state.binding.chain_spec_hash,
            kind,
            &filter,
        ))?));
        let cursor = parse_cursor(after, self.state.generation, &scope)?;
        let mut sql = self.page_sql(kind, &filter, cursor.as_ref(), first)?;
        let mut tx = self.transaction.lock().await;
        let rows = sql.build().fetch_all(&mut **tx).await?;
        drop(tx);
        let count = usize::try_from(first).expect("validated positive page size");
        let has_more = rows.len() > count;
        let records = rows
            .into_iter()
            .take(count)
            .map(|row| self.page_record(&row, &scope))
            .collect::<Result<_>>()?;
        Ok(Page { records, has_more })
    }

    fn page_sql<'a>(
        &self,
        kind: Kind,
        filter: &'a Filter,
        cursor: Option<&Cursor>,
        first: i32,
    ) -> Result<QueryBuilder<'a, Postgres>> {
        let (base, alias, order, suborder) = base(kind);
        let mut sql = QueryBuilder::<Postgres>::new(base);
        sql.push(" WHERE ")
            .push(alias)
            .push("<=")
            .push_bind(self.state.head.height.to_string())
            .push("::numeric");
        if filter.finalized_only {
            sql.push(" AND ")
                .push(alias)
                .push("<=")
                .push_bind(self.state.finalized.height.to_string())
                .push("::numeric");
        }
        apply_filters(&mut sql, kind, filter);
        if let Some(cursor) = cursor {
            sql.push(" AND (")
                .push(alias)
                .push(",")
                .push(order)
                .push(",")
                .push(suborder)
                .push(") < (")
                .push_bind(cursor.height.to_string())
                .push("::numeric,")
                .push_bind(
                    i64::try_from(cursor.order).map_err(|_| Error::Cursor("INVALID_CURSOR"))?,
                )
                .push(",")
                .push_bind(
                    i64::try_from(cursor.suborder).map_err(|_| Error::Cursor("INVALID_CURSOR"))?,
                )
                .push(")");
        }
        sql.push(" ORDER BY ")
            .push(alias)
            .push(" DESC,")
            .push(order)
            .push(" DESC,")
            .push(suborder)
            .push(" DESC LIMIT ")
            .push_bind(i64::from(first) + 1);
        Ok(sql)
    }

    fn page_record(&self, row: &PgRow, scope: &str) -> Result<Record> {
        let height = crate::model::number(&row.try_get::<String, _>("height")?)?;
        let order = u64::try_from(row.try_get::<i64, _>("order1")?)
            .map_err(|_| Error::Data("negative stored position".into()))?;
        let suborder = u64::try_from(row.try_get::<i64, _>("order2")?)
            .map_err(|_| Error::Data("negative stored position".into()))?;
        let cursor = hex::encode(serde_json::to_vec(&Cursor {
            generation: self.state.generation,
            scope: scope.to_owned(),
            height,
            order,
            suborder,
        })?);
        Ok(Record {
            height,
            order,
            suborder,
            cursor,
            block_hash: row.try_get("block_hash")?,
            data: row.try_get::<Json<Value>, _>("data")?.0,
        })
    }
}
fn parse_cursor(raw: Option<&str>, generation: u64, scope: &str) -> Result<Option<Cursor>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.len() > 1024 {
        return Err(Error::Cursor("INVALID_CURSOR"));
    }
    let cursor: Cursor =
        serde_json::from_slice(&hex::decode(raw).map_err(|_| Error::Cursor("INVALID_CURSOR"))?)
            .map_err(|_| Error::Cursor("INVALID_CURSOR"))?;
    if cursor.generation != generation {
        return Err(Error::Cursor("STALE_CURSOR"));
    }
    if cursor.scope != scope {
        return Err(Error::Cursor("INVALID_CURSOR_SCOPE"));
    }
    Ok(Some(cursor))
}
pub(super) const fn base(kind: Kind) -> (&'static str, &'static str, &'static str, &'static str) {
    match kind {
        Kind::Blocks => (
            "SELECT b.height::text,c.hash AS block_hash,0::bigint AS order1,0::bigint AS order2,jsonb_build_object('header',b.header,'runtimeHash',b.runtime_hash,'decoding',b.decoding,'txCount',b.transaction_count::text) AS data FROM canonical_blocks c JOIN blocks b ON b.hash=c.hash",
            "b.height",
            "0::bigint",
            "0::bigint",
        ),
        Kind::Transactions => (
            "SELECT t.height::text,t.block_hash,t.position AS order1,0::bigint AS order2,t.data FROM transactions t JOIN canonical_blocks c ON c.hash=t.block_hash",
            "t.height",
            "t.position",
            "0::bigint",
        ),
        Kind::Logs => (
            "SELECT t.height::text,t.block_hash,t.log_index AS order1,0::bigint AS order2,(t.data-'data')||jsonb_build_object('data',left(t.data->>'data',514),'dataBytes',((length(t.data->>'data')-2)/2)::text) AS data FROM logs t JOIN canonical_blocks c ON c.hash=t.block_hash",
            "t.height",
            "t.log_index",
            "0::bigint",
        ),
        Kind::Transfers => (
            "SELECT t.height::text,t.block_hash,t.log_index AS order1,t.item_index AS order2,t.data FROM token_transfers t JOIN canonical_blocks c ON c.hash=t.block_hash",
            "t.height",
            "t.log_index",
            "t.item_index",
        ),
        Kind::Chunks => (
            "SELECT t.end_height::text AS height,''::text AS block_hash,0::bigint AS order1,0::bigint AS order2,jsonb_build_object('chunk',t.data) AS data FROM chunks t",
            "t.end_height",
            "0::bigint",
            "0::bigint",
        ),
        Kind::Proofs => (
            "SELECT t.height::text,COALESCE(t.block_hash,'') AS block_hash,(CASE t.kind WHEN 'block_proof' THEN 0 WHEN 'chunk_proof' THEN 1 ELSE 2 END)::bigint AS order1,0::bigint AS order2,jsonb_build_object('locator',t.locator::jsonb,'kind',t.kind,'info',t.data,'availability',t.availability,'observedAt',t.observed_at::text) AS data FROM proof_metadata t LEFT JOIN canonical_blocks c ON c.hash=t.block_hash",
            "t.height",
            "CASE t.kind WHEN 'block_proof' THEN 0 WHEN 'chunk_proof' THEN 1 ELSE 2 END",
            "0::bigint",
        ),
    }
}
fn apply_filters<'a>(sql: &mut QueryBuilder<'a, Postgres>, kind: Kind, filter: &'a Filter) {
    match kind {
        Kind::Transactions => {
            if let Some(value) = &filter.address {
                sql.push(" AND (t.from_address=")
                    .push_bind(value)
                    .push(" OR t.to_address=")
                    .push_bind(value)
                    .push(" OR t.contract_address=")
                    .push_bind(value)
                    .push(")");
            }
            if let Some(value) = &filter.hash {
                sql.push(" AND (t.hash=")
                    .push_bind(value)
                    .push(" OR t.envelope_hash=")
                    .push_bind(value)
                    .push(")");
            }
            if let Some(value) = &filter.kind {
                sql.push(" AND t.kind=").push_bind(value);
            }
            if let Some(value) = &filter.status {
                sql.push(" AND t.status=").push_bind(value);
            }
        }
        Kind::Logs => {
            if let Some(value) = filter.contract.as_ref().or(filter.address.as_ref()) {
                sql.push(" AND t.address=").push_bind(value);
            }
            if let Some(value) = &filter.topic0 {
                sql.push(" AND t.topics[1]=").push_bind(value);
            }
            if let Some(value) = &filter.hash {
                sql.push(" AND t.data->>'transaction_hash'=")
                    .push_bind(value);
            }
        }
        Kind::Transfers => {
            if let Some(value) = &filter.address {
                sql.push(" AND (t.from_address=")
                    .push_bind(value)
                    .push(" OR t.to_address=")
                    .push_bind(value)
                    .push(")");
            }
            if let Some(value) = &filter.contract {
                sql.push(" AND t.contract=").push_bind(value);
            }
            if let Some(value) = &filter.hash {
                sql.push(" AND t.data->>'transaction_hash'=")
                    .push_bind(value);
            }
        }
        Kind::Proofs => {
            sql.push(" AND (t.block_hash IS NULL OR c.hash IS NOT NULL)");
            if let Some(value) = &filter.kind {
                sql.push(" AND t.kind=").push_bind(value);
            }
        }
        Kind::Blocks | Kind::Chunks => {}
    }
    if let Some(value) = &filter.block_hash {
        match kind {
            Kind::Blocks => {
                sql.push(" AND b.hash=").push_bind(value);
            }
            Kind::Chunks => {}
            _ => {
                sql.push(" AND t.block_hash=").push_bind(value);
            }
        }
    }
}
