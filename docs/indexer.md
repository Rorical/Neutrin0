# PostgreSQL indexer

`neutrin0-indexer` is an independent ingestion and GraphQL service. It connects
only to a full/archive node's public HTTP RPC. It does not start a chain engine,
join P2P, execute blocks, create proofs, sign transactions or control validators.
All queries are served from PostgreSQL; a disconnected source does not prevent
queries over already indexed data.

## Run against an existing PostgreSQL database

Use PostgreSQL 14 or newer. The acceptance gate uses PostgreSQL 17. Give the
writer database role permission to create a **dedicated schema**, or have the
administrator create it with that role as owner. Tables are isolated under
`database_schema`; the service rejects `public`, reserved schema names and unsafe
identifiers. It does not change unrelated application tables.

```sh
cp indexer.example.toml indexer.toml
# Edit rpc_url, chain_spec_hash, runtime and cors_origins in indexer.toml.
export NEUTRIN0_INDEXER_DATABASE_URL='postgres://indexer:password@127.0.0.1:5432/indexer'
cargo build --locked -p neutrin0-indexer
RUST_LOG=info ./target/debug/neutrin0-indexer --config indexer.toml
```

Keep credentials in the environment or your service's secret store. The
configuration contains the environment variable's name, not the credentials.
Follow your database's TLS configuration when setting the connection string.
The source's **complete chain-specification hash** must match the explicitly
pinned value. A schema is bound to its chain ID, genesis facts, chunk size and
runtime decoding profile. Switching chains or decoding profiles requires a new
schema. This development implementation checks an exact SQL format checksum and
refuses incompatible schemas; it does not perform automatic format migrations.

`runtime = "evm"` decodes the embedded EVM runtime's transactions, receipts,
logs and token movements. `opaque` preserves common envelopes/artifacts and
reports unknown execution fields rather than assigning runtime semantics.

Start additional query services against the same schema with:

```sh
./target/debug/neutrin0-indexer --config indexer.toml --serve-only
```

`--serve-only` reads the existing schema, does not run DDL, acquire the writer
lease or contact the source, and supports a PostgreSQL role with schema `USAGE`
and table `SELECT`. Ingestion uses a PostgreSQL advisory lock held by its own
connection; another writer cannot publish into the same schema concurrently.
Connection loss releases ownership and the worker reacquires it before resuming.

Endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /graphql` | Read-only GraphQL queries and introspection |
| `GET /graphql/schema` | Current SDL for client code generation |
| `GET /health/live` | HTTP process liveness |
| `GET /health/ready` | Last fully reconciled source observation is live and at most 180 seconds old |

Readiness is a checkpoint freshness check, not an independent proof of node
connectivity. The query service remains usable while readiness is false. GraphQL
`status` exposes indexed and source heights separately, finalized
height, phase, last error, event checkpoint and observation time.
`--print-schema` emits SDL without opening a database or contacting a node.

## Queries

Large integers in typed GraphQL fields are **decimal strings**: heights, counters,
nonces, native values, token IDs and quantities never round in JavaScript. JSON
fields retain source representations except for address/activity counters and
validator stakes/epochs, which are also decimal strings. Use typed fields for
chain heights and Chunk IDs rather than numeric fields inside source JSON.

```graphql
query Overview {
  status {
    chainId chainSpecHash indexedHeight sourceHeight finalizedHeight
    finalizedChunks blockCount transactionCount logCount gasUsed
    phase lastError observedAt eventCursor generation
  }
  blocks(first: 10) {
    edges { cursor node { hash height timestamp gasUsed transactionCount finalized } }
    pageInfo { hasNextPage endCursor }
  }
  activity(buckets: 24, seconds: 3600)
}

query Account($address: String!, $after: String) {
  address(address: $address)
  transactions(first: 20, after: $after, filter: { address: $address }) {
    edges { cursor node { hash envelopeHash blockHash height kind from to contractAddress nonce value status gasUsed } }
    pageInfo { hasNextPage endCursor }
  }
  tokenTransfers(first: 20, filter: { address: $address }) {
    edges { node { contract standard from to amount tokenId blockHash height } }
    pageInfo { hasNextPage endCursor }
  }
}

query Finality {
  chunks(first: 5) {
    edges { node { id hash startHeight endHeight endBlockHash certificate } }
    pageInfo { hasNextPage endCursor }
  }
  validators
  proof(locator: { kind: "chunk_proof", chunk: 0 }) { height kind availability artifactHash }
  proofs(first: 10, kind: "chunk_proof") {
    edges { node { kind height availability artifactHash encodedBytes proofBytes storedBytes observedAt } }
    pageInfo { hasNextPage endCursor }
  }
}
```

`block(height: "123")` selects canonical membership; `block(hash: "0x...")`
can also inspect retained orphan detail and exposes `canonical`. `transaction`
returns the newest canonical attempt for a runtime or envelope ID; filtering
`transactions` by that ID returns all indexed attempts, including failed
resubmissions. Address activity means declared/recovered transaction participants,
created contract addresses and event-declared token participants. Failed
transactions retain their declared sender/value and failed receipt status.
These counts are not balances or internal-call traces.

`logs` supports emitter, topic-zero, transaction and block filters. Ethereum
transaction receipts expose metadata; log bodies are queried through the paginated
log connection. `tokenTransfers` recognizes exact ERC20/ERC721/ERC1155 event
layouts, including mint/burn zero addresses and each item in an ERC1155 batch.
Malformed or ambiguous layouts remain ordinary logs. Event shape alone does not
assert token-interface compliance. Token names, supplies, balances, account state,
internal traces and prices are not inferred.

`TransactionRecord.rawEnvelope(offset, length)` and
`logData(blockHash, logIndex, offset, length)` return exact slices of at most
65,536 bytes. Transaction input/log previews are bounded; their complete source
bytes stay in PostgreSQL. `genesis` serves immutable facts, without synthesizing a
normal height-zero body. Validators are an observed current source committee,
anchored to the indexed finalized boundary; missing observations return null.
The indexer does not invent historical committees. Proofs expose observed source
hash/size/public-input/availability metadata; **raw proof bytes are not stored**.
Certificate summaries above 1 MiB return an explicit error directing the caller
to the node artifact endpoint. Certificates contain the source's inspectable summary; exact individual signed
attestations remain available through node artifact downloads.

Every request uses one read-only, repeatable-read PostgreSQL transaction. Status
fields, membership flags, lists and finalized markers in that request share one
snapshot even during reorganization. Lists use descending keyset cursors bound to
the query's filters, chain identity and canonical generation. After a rollback,
continuing an older list returns `STALE_CURSOR`; restart that list without its
cursor. Reusing a cursor for different filters returns `INVALID_CURSOR_SCOPE`.
Page sizes are 1–100; `finalizedOnly` restricts transaction/log/transfer lists to
indexed complete-Chunk finality.

The server limits query depth to 8, complexity to 1,024, request bodies to 64 KiB,
responses to 4 MiB, concurrent data queries to 8 and request execution to 10 seconds.
SQL statements time out after 5 seconds. CORS permits only configured exact origins.
Bind behind your existing HTTP ingress if public hosting needs authentication or
rate limits.

## Ingestion and recovery

The worker polls the durable `chain_getEvents` endpoint and reconciles its atomic
current head/finality snapshot. It does not need each intermediate abandoned
branch's bodies. Backfill starts at height one, yields after `batch_blocks`, and
commits block rows, transactions, logs, transfers, totals and proof retry entries
in one transaction. Publication acknowledges the source cursor only after the
entire target head and all intervening finalized Chunks/certificates are indexed,
and a fresh source observation confirms the same endpoints. Restart resumes from
the saved complete block even if a batch was interrupted before cursor publication.

Unfinalized forks roll back canonical membership and totals to a checked common
ancestor, increment the query generation, then backfill the selected branch.
Orphan detail is retained for `orphan_retention_blocks`; canonical history is kept.
An indexed finalized anchor cannot roll back. A lagging provider, finality conflict,
unknown native layout or missing committed data preserves progress and reports an
explicit error. Transient upstream/database failures retry with bounded backoff.

Expired or replaced node-stream cursors trigger snapshot reconciliation, including
chain identity and the saved finalized anchor, before adopting a new cursor.
Changing to an equivalent provider does not authorize skipping missing history.
Use an archive endpoint for an initial full historical backfill when a full node
has already pruned old bodies, receipts, certificates or historical EVM runtimes.
A History proof (the latest finalized chunk receipt) proves coverage but cannot
reconstruct the indexed source material. The indexer trusts its configured node; commitment/identity checks detect
mixed data but are not an independent consensus/proof verifier.

Proof availability is sampled at ingestion, then refreshed with a bounded fair
retry queue and recent-block observations. Metadata records source observations,
not proof creation or local validity. No-op source polls still refresh delayed
proofs and checkpoint freshness. Canonical transaction/log counts include only
current membership, and counts/gas are adjusted exactly on rollback.

## Validation

```sh
cargo test --locked -p neutrin0-indexer
cargo clippy --locked -p neutrin0-indexer --all-targets -- -D warnings
# Use a disposable PostgreSQL database, never the application database:
NEUTRIN0_INDEXER_TEST_DATABASE_URL='postgres://postgres@127.0.0.1:5432/indexer_test' \
  cargo test --locked -p neutrin0-indexer --test postgres -- --ignored
```

The explicit PostgreSQL gate covers writer exclusivity, interrupted backfill,
restart/cursor recovery, expiration/provider-stream replacement, unfinalized reorgs,
request snapshot consistency, forbidden finalized rollback, atomic row publication,
missing/corrupt source data, delayed proofs, lossless values, GraphQL HTTP/CORS,
pagination and resource limits. Fixtures model trusted RPC observations; this gate
does not claim proof-system acceptance. Workspace CI checks and real compressed
proof composition remain separate project acceptance gates.
