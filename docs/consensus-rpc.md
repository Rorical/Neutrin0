# Consensus artifacts and recoverable chain events

These read-only methods use the public HTTP/WebSocket JSON-RPC endpoint. Full,
validator, archive and reporter nodes serve their locally retained data. Light
clients return state unavailable. RPC observations trust the selected provider;
artifact hashes identify bytes and do not independently establish proof validity.

## Queries

All parameters are positional. Hashes and byte strings use `0x` hexadecimal.
Chunk IDs start at zero. Omitted or null Chunk IDs select the latest finalized
Chunk; before the first complete Chunk finalizes, the result is null.

| Method | Parameters | Result |
| --- | --- | --- |
| `chain_getChunk` | `[chunk_id?]` | All canonical Chunk fields and its commitment, plus proof/certificate availability |
| `chain_getCertificate` | `[chunk_id]` | Certified round, committee root, leader index, exact Borsh signed proposal, prevote/precommit signers and aggregate signatures, attestation counts, proof manifests and envelope metadata |
| `chain_getArtifact` | `[artifact_id]` | Exact Borsh envelope hash/length, raw proof length and encoded public values where applicable |
| `chain_getArtifactBytes` | `[artifact_id, expected_hash, offset, length]` | A slice of that exact Borsh envelope |
| `chain_getEvents` | `[after_cursor?, limit?]` | Atomic chain status, transitions strictly after the cursor, next cursor and `has_more` |

Artifact IDs are one of:

```json
{"kind":"block_proof","block":"0x<32-byte native block hash>"}
{"kind":"chunk_proof","chunk":0}
{"kind":"certificate","chunk":0}
```

Envelopes decode into the `BlockProof`, `ChunkProof` and `FinalityCert`
Borsh types. The artifact hash is BLAKE3 over the entire encoded envelope, including
its proof bytes and embedded certificate. It is distinct from the Chunk commitment
and from the SP1 proof's cryptographic identity. Block public values encode
`BlockProofPublicInputs`; Chunk public values encode the authenticated stored
`ConsensusStatement`, including its boundaries and certificate commitment.

Fetch metadata first and pin its hash on every slice request. Length must be
1–1,048,576 bytes. Offsets beyond the envelope fail; an offset equal to its length
returns an empty slice. Verify the complete envelope hash after assembly. The typed
client and CLI do this, with a 64 MiB download ceiling. Downloaded files contain
exact Borsh bytes and are created exclusively; an existing file is never overwritten.
Large certificates can be downloaded through the artifact methods without requesting
the expanded JSON certificate response.

Unknown block hashes and not-yet-finalized Chunk IDs return null from metadata
queries. Known objects with missing artifacts report `-32026` (unavailable), or
`-32024` (pruned, with retained range data) when below the saved local retention
watermark. A missing requested byte envelope reports unavailable. Changed expected
hashes report `-32027`; invalid ranges/limits/parameters report `-32602`. Stored
objects that disagree with their indexes or authenticated commitments report a
storage error. History coverage does not imply that old block bodies, certificates
or execution receipts are reconstructible.

## Indexer data lanes

`chain_getBlockArtifacts([block_hash])` returns the exact canonical Borsh
`ExecutionArtifacts` and the historical runtime content hash for a retained block.
The artifact commitment must match `header.receipts_root`; native body transactions
remain opaque common envelopes in `chain_getBlock`. Unknown/genesis bodies return
null; unavailable/pruned retained bodies follow the normal query error policy.
The query does not execute the runtime or produce a proof.

`eth_getBlockReceipts([selector])` returns all historically decoded committed
Ethereum receipts in transaction order, with block-global log indices. Select by
block hash, hexadecimal height or `latest`/`safe`/`finalized`/`earliest`; an EIP-1898
object is also accepted and `requireCanonical: true` is enforced. Genesis returns
an empty receipt array, unknown blocks return null and `pending` is rejected.
It uses the same historical runtime projection as individual receipt queries,
decoding the artifact lane once for the whole block. This avoids one receipt RPC
per transaction during indexing. Missing/pruned source material is an error, not
an empty receipt set.

The standalone [indexer](indexer.md) persists these data lanes in PostgreSQL and
serves frontend queries without calling node runtime/control methods.

## Durable event stream

A cursor has a random database-local `stream_id` and a canonical decimal string
`sequence`, avoiding JavaScript integer rounding. Apply the event and save its
cursor in one consumer-side database transaction; ignore already-applied cursors
when retrying. Normal restart preserves stream identity and
sequence. A freshly initialized database has a different stream identity.

The node retains the last 4,096 transitions. Head/finality publication and the
journal update share one durable database batch, so failed publication cannot
advance the cursor. No-op publication emits nothing. The journal is independent of
body/proof retention and includes no transaction bodies. On startup, saved chain
endpoints and journal continuity are checked before workers start.

Without a cursor, `chain_getEvents` returns current status and its latest cursor,
with no past events. With a cursor, it returns up to `limit` transitions (default
128, maximum 256). Continue immediately while `has_more` is true. `next` is the last
returned sequence, or the supplied sequence when caught up. Status includes current
head, finalized block, finalized Chunk count, authenticated chain-spec hash, latest
cursor and `replay_from`, the earliest supported starting cursor.

Transitions contain previous/new head and finalized endpoints, previous/new
finalized Chunk counts and the common ancestor when retained ancestry permits it:

| `kind` | Meaning |
| --- | --- |
| `snapshot` | First event of a newly initialized stream |
| `head` | Canonical head extends its previous branch |
| `reorg` | Canonical branch changes; roll back to `common_ancestor` before backfill |
| `finalized` | Finality changes while the selected head stays unchanged |
| `checkpoint` | A bootstrap jump or unavailable/bounded ancestry prevents common-ancestor reconstruction |

One atomic transition can change both head and finality or advance multiple Chunks.
Events provide range endpoints, not one notification per transaction or finalized
Chunk. Backfill the intervening range using queries. For `checkpoint`, reconcile a
fresh authenticated snapshot rather than guessing intermediate blocks. Ancestry
search is capped at 16,384 headers; exceeding it also produces `checkpoint`.

Malformed, future, expired or foreign cursors return `-32028`, with
`data.reason` (`malformed`, `future`, `expired`, `wrong_stream`) and an atomic current
`data.status`. Invalid cursors are never silently replaced by the latest cursor.
An expired cursor requires snapshot/backfill reconciliation before resuming. A
consumer starting from scratch can use `replay_from` to inspect the retained tail,
but that tail cannot reconstruct earlier missing history.

## WebSocket subscriptions

Subscribe using `chain_subscribeEvents` with `[after_cursor?]`. Notifications use
`chain_event`; unsubscribe using `chain_unsubscribeEvents` and the subscription ID.
The typed WebSocket client exposes `ChainEventsApiClient::subscribe_events`.

The first notification is `{"type":"snapshot","status":...,"after":...}`.
`after` is the requested replay position, or the latest cursor for a fresh watcher.
The current status is an observation target: when resuming from an older cursor,
its `latest` must not replace the consumer's saved cursor before replay completes.
Subsequent notifications are `{"type":"event","event":...}`. Retained events
are replayed in order, then the server follows durable publications with a 500 ms
poll interval. The server admits at most 64 active chain event subscriptions, and
separately 64 `eth_subscribe` subscriptions, across connections; further ones
return `-32005`. The transport also refuses a connection's seventeenth live
subscription. The public server serves at most `max_ws_connections` (32)
WebSocket sessions at once and bounds each session's outgoing message buffer at
four entries, so a slow reader waits instead of holding memory. A disconnected
client reconnects using the last applied event's
cursor; no server-side connection state is needed for recovery.

Invalid cursors reject subscription creation with the same structured error as
HTTP. If the subscriber falls behind retention after acceptance, the server sends
`{"type":"reset_required","reason":"expired","status":...}` and ends the
subscription. Other read failures also end it with an explicit reset notification,
whose status may be null. Transport disconnection can prevent delivery of that last
notification; cursor validation on reconnect remains authoritative.

## CLI

```sh
neutrin0-cli chunk get --id 0 --json
neutrin0-cli chunk certificate --id 0 --json
neutrin0-cli chunk proof --id 0 --out chunk-0.borsh --json
neutrin0-cli proof get --kind block --hash 0x... --out block.borsh --json
neutrin0-cli proof get --kind certificate --id 0 --out certificate.borsh --json
neutrin0-cli chain events --json
neutrin0-cli chain events --after-stream 0x... --after-sequence 42 --limit 128 --json
neutrin0-cli chain watch-events --after-stream 0x... --after-sequence 42 --json
```

Omitting `--id` from Chunk commands selects latest finalized. Omitting `--out`
from proof commands prints envelope metadata. `watch-events` polls HTTP using the
same durable cursors, prints one event per line and supports `--interval-secs`,
`--count` (events, zero means continuous), and Ctrl-C. A watcher without a cursor
first prints a status snapshot. Cursor flags must be supplied together. Errors retain
JSON-RPC codes and recovery data on stderr; the CLI never resets an expired cursor
on behalf of an indexer.
