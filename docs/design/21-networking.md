# Networking and sync

Nodes talk over libp2p: gossipsub for publications and votes, one
request/response protocol per query, Kademlia for discovery and Identify and
Ping for connection upkeep. Every payload is Borsh with an exact byte cap, and
every peer is a stranger: a libp2p identity proves nothing about validator
membership, so the network layer only bounds what a peer can make the node do,
while authenticity comes from signatures and proofs the application verifies.
A peer's advertisement only chooses what to download; progress counts once the
node has verified it locally.

The protocol ids, topics and caps below are defined in
`crates/network/src/topic.rs` and `crates/network/src/rpc.rs` (payloads in
`rpc/messages.rs` and `rpc/transactions.rs`, envelopes in `rpc/envelope.rs`, the
framing in `rpc/codec.rs`); the sync driver lives in `crates/sync`.

## Transport and identity

The swarm runs TCP with Noise and Yamux, QUIC and DNS resolution, closes idle
connections after 60 seconds and pings every 15 seconds. Identify runs as
`/neutrin0/identify` and Kademlia as `/neutrin0/kad`; gossip topics are
`/neutrin0/<topic>/borsh` and request protocols `/neutrin0/req/<name>`. Each has
one unversioned path.

A node persists its libp2p identity at `network_key_path`, or
`<data_dir>/p2p-key` when that is unset. The first start creates the key
atomically (a completed staging file is linked into place, so competing creators
load the winner and no reader sees a partial file) and never overwrites an
existing one. A malformed key or a Unix mode other than `600` fails startup. A
node with neither path uses an ephemeral identity and warns that it changes on
restart.

Every connection starts with the `Status` handshake. Until a peer's status
matches the local chain id and complete chain-spec hash (which commits the
pinned programs), the node admits no gossip or data request from it, answers
other requests with `Unavailable("chain handshake required")`, and drops it after
30 seconds; a mismatching status disconnects at once. Status and ping are
answered inside the network service, so they work even when the application
mailbox is full.

## Peer discovery

Configured bootnodes (at most 64 addresses, each 1 to 2,048 bytes, never naming
the local identity) are the only addresses with a reconnect schedule. Each has
one dial in flight; failures back off exponentially with identity- and
address-specific jitter between 1 and 60 seconds, a connection resets the
backoff, and retries resume when its last connection closes. An address with a
`/p2p/` suffix authenticates that identity; a bare address accepts whatever
identity answers.

Without discovery every node's outbound peers would be exactly its bootnodes, a
star a few subnets could saturate or eclipse. Outbound connections are the ones an
attacker filling inbound slots cannot choose, so while the node has fewer than 16
outbound connections it walks the DHT from a random key every 30 seconds and
dials up to four learned peers per walk, at most one per peer and per IPv4 /24 or
IPv6 /48. The learned book is bounded:

| Rule | Value |
| --- | --- |
| Entries | 256, oldest forgotten first; one entry per peer and prefix |
| Entries per prefix | 4 |
| Addresses per entry | 4, all inside the first address's prefix |
| Redial of an entry | not sooner than 10 minutes |
| Dialable address | unicast IP with a TCP or UDP port, at most 256 bytes, naming no other identity |

A reply can add addresses to an existing entry or a new entry while its prefix is
below its bound, and never replaces what another reply taught; a failed dial
forgets only the entry it dialed. Loopback, private, link-local, shared and
unique-local targets are dialable only when a configured bootnode is itself local
(a development or private network), both for learned dials and for the addresses
Kademlia's own queries dial, so a reply cannot aim a public node at internal
hosts. Kademlia inserts routing entries manually, only for handshaken peers, from
at most eight Identify addresses each (at most 2,048 bytes, bound to the observed
IP unless the peer is a configured bootnode), and filters record storage.
Identify keeps no address cache, so claimed listen addresses never become dial
targets by another route.

## Gossip

Gossipsub runs with mesh degree 8 (low 6, high 12), a 700 ms heartbeat, a
six-heartbeat gossip window over a ten-heartbeat history, a 60-second duplicate
cache, signed messages with strict validation, and manual validation so the
application's verdict feeds peer scoring. Message ids are
`BLAKE3(len(topic) LE8 || topic || data)`: binding the topic keeps bytes
delivered on one topic from suppressing their delivery on another through the
shared duplicate cache. The subscription filter whitelists the 28 registered
topics with at most 64 subscription changes per request, so unknown names
cannot grow routing state; an RPC carries at most 32 published and 256 control
messages, and a message on an unknown topic is rejected.

Topic caps are the gossipsub transmission limit for each topic (framing
included, so they exceed the strictly decoded payload):

| Topic | Payload | Cap |
| --- | --- | --- |
| `blocks` | `CandidateBlock` (signed block and write set) | 18 MiB (`MAX_PROVEN_BLOCK_BYTES`) |
| `receipts` | `BlockReceipt` (block hash and receipt bytes) | 2 MiB |
| `txs` | `TransactionAnnouncement` | 128 KiB |
| `slashing_evidence` | `SlashingEvidence` (raw report) | 8 MiB |
| `evidence_proofs` | `EvidenceReport` | 8 MiB |
| `chunk_proofs` | `ChunkProof` | 8 MiB |
| `checkpoints` | `CheckpointAnnouncement` | 1 KiB |
| `bft_candidates` | `BftCandidate` | 16 KiB |
| `signed_artifacts` | `SignedArtifactInventory` | 2 KiB |
| `bft_messages` | `BftMessage` | 8 MiB |
| `finality_votes_prevote`, `finality_votes_precommit` | `BftVote` | 8 MiB |
| `aggregate_finality_votes_<n>`, `n` in `0..16` | `BftVote` | 8 MiB |

The 16 aggregate-vote subnets (`VOTE_SUBNETS`) carry aggregated votes. The
aggregate of chunk `c` goes to subnet `c mod vote_subnets`, and the aggregators
of a chunk and round are elected by stake from the finalized seed with
`expected_aggregators_per_round` expected members
([consensus parameters](09-consensus.md#parameters)). Vote and message semantics
are in the [BFT protocol](10-bft-protocol.md).

What each topic carries is owned elsewhere:

| Object | Publication and recovery | Owner |
| --- | --- | --- |
| Transactions | RPC admission publishes a `TransactionAnnouncement` binding the bytes to the runtime hash that admitted them; full and validator nodes repair missed gossip by [pool repair](#transaction-pool-repair). Every receiver runs its own admission. | [runtime interface](02-runtime-interface.md) |
| Blocks and receipts | The producer publishes `CandidateBlock` as soon as it has executed; whoever proves the block publishes `BlockReceipt`. Each is accepted or rejected as a unit, and a receipt ahead of its block waits for `proof_orphan_slots`. Only a receipt that newly proves a block, or the proposer's own receipt of a block another receipt proved first, is relayed. | [proof-following nodes](07-proof-following-nodes.md), [proof market](08-proof-market.md) |
| Chunks, certificates, chunk proofs | `BftCandidate` advertises a fully proven next-chunk branch; votes and leader messages run on the BFT topics; after commit, `chunk_proofs` carries the proof. | [certified execution](11-certified-execution.md), [chunk proofs](12-chunk-proofs.md) |
| History endpoints | Each finality advance publishes a 40-byte `CheckpointAnnouncement { chunk_count, checkpoint_hash }`. A notice of nothing beyond local finality is ignored and not relayed, and no notice clears a provider's backoff. | [recursive history](13-recursive-history.md), [light clients](14-light-clients.md) |
| Evidence | Raw reports trigger bounded background proving; verified `EvidenceReport`s are pooled, persisted and gossiped by statement identity. | [evidence proofs](16-evidence-proofs.md) |
| Signed sources | `signed_artifacts` announces sorted inventories of at most 32 exact source references. | [evidence availability](17-evidence-availability.md) |
| Validator membership | No gossip: transactions and proven execution feed the next chunk's context, and the committee comes from the durably certified incoming boundary. Address discovery is unrelated to membership. | [consensus](09-consensus.md#validator-set-rotation) |

Publishing acknowledges a handoff to the local command channel, not delivery, so
every lane above has a pull-based recovery path; none of them establishes
bounded recovery under malicious peers, saturated queues or arbitrary partitions.

## Request/response protocols

Each protocol runs as its own libp2p request/response behaviour, so caps,
timeouts and read budgets are set per protocol. Every message is one frame, a
little-endian `u32` length followed by exactly that many Borsh bytes, written
without closing the stream, so no read waits for the sender to close. Every
response is a Borsh `Result<Payload, RpcFailure>`:

| `RpcFailure` | Meaning |
| --- | --- |
| `Unavailable(reason)` | Not retained or not yet produced, or the provider is busy |
| `Pruned { retained_from_chunk, retained_from_height }` | Deliberately removed below the persisted retention watermark |
| `Storage(reason)` | Local storage failed or held inconsistent authenticated data |
| `InvalidRequest(reason)` | Not a supported bounded query |

Missing bodies are never manufactured and hash-list requests do not silently
omit entries, except the best-effort pending-transaction lookup. A stream closed
without a frame is a missing response, never invalid data, so a provider that
refused or failed is not scored as malformed.

| Protocol | Request → response | Request / response cap | Timeout |
| --- | --- | --- | --- |
| `status` | `Status` → `Status` | 161 B / 1 KiB | 15 s |
| `metadata` | `MetadataRequest` (empty) → `Metadata` | 0 / 1 KiB | 15 s |
| `ping` | `PingPayload { nonce: u64 }` → `PingPayload` | 8 B / 1 KiB | 15 s |
| `blocks_by_range` | `{ head_block_hash, start_height, count }` → `{ blocks: Vec<ProvenBlock>, candidates: Vec<CandidateBlock> }` | 1 MiB / 32 MiB | 30 s |
| `receipts_by_hash` | at most 16 block hashes → retained `BlockReceipt`s | 1 MiB / 32 MiB | 30 s |
| `state_by_root` | `{ state_root, items }` → fragments | 1 MiB / 32 MiB | 30 s |
| `chunk_proof_by_id` | `{ chunk_ids, statement_keys }` → at most 2 `ChunkProof`s | 1 MiB / 32 MiB | 30 s |
| `history_proof` | `HistoryProofRequest` → `HistoryProofResponse` | 1 MiB / 32 MiB | 30 s |
| `finality_cert_by_chunk` | chunk ids → at most 16 `FinalityCert`s | 1 MiB / 32 MiB | 15 s |
| `witness_by_block` | block hashes → at most 4 opaque witnesses | 1 MiB / 32 MiB | 60 s |
| `candidate_by_chunk` | `{ chunk_id, chunk_hash: Option }` → `BftCandidate` | 1 MiB / 32 MiB | 15 s |
| `bft_round_by_chunk` | `{ chunk_id }` → `{ proposal, round_change }` | 64 B / 8 MiB | 15 s |
| `signed_artifact_inventory_by_chunk` | `{ chunk_id, after }` → at most 32 references | 64 B / 2 KiB | 15 s |
| `signed_artifact_by_id` | `{ id }` → one exact `SignedArtifact` | 64 B / 8 MiB + 16 B | 15 s |
| `transaction_inventory` | `{ after }` → at most 128 hashes | 33 B / 4,101 B | 15 s |
| `transactions_by_hash` | at most 16 hashes → bodies of at most 256 KiB | 516 B / 4,194,373 B | 15 s |

Exact caps apply on writes, and reads refuse oversized or trailing bytes. BFT,
inventory and transaction readers refuse excessive counts and lengths before
allocating collections, and signed-source decoding also enforces its total byte
cap.

`Status` carries `chain_id`, `chain_spec_hash`, `finalized_chunk_id:
Option<ChunkId>` (chunk 0 is `Some(0)`, genesis `None`), the finalized chunk's
hash, the `checkpoint_hash` of the boundary it ends in, and the head's hash, slot
and height. The latest finalized chunk receipt is the History proof of that
endpoint, so History coverage and finality are one count.

`Metadata` advertises `role_flags` (`FULL_NODE`, `LIGHT_CLIENT`, `ARCHIVE`) and
`retained_from_chunk` and `retained_from_height` from the committed deletion
watermark; `None` makes no availability claim, which light clients use.
`ARCHIVE` requires archive policy and an unbroken retention window from genesis;
selecting archive mode cannot restore deleted data. A node that needs old history
(an archive syncing sources, or a reporter with dormant paths) asks each new
connection for its metadata once: complete-chunk sync never asks a provider for a
chunk below its advertised floor, and a reporter's old dormant paths are
requested from `ARCHIVE` peers first ([reporter nodes](18-reporter-nodes.md)).
Other nodes learn a provider's floor from its first `Pruned` answer. A provider
that overstates its floor still answers `Pruned` and is skipped. These hints never
authenticate a checkpoint or change a trust anchor.

`BlocksByRange` names a branch by the `head_block_hash` of the provider's status.
The provider resolves that anchor's ancestry under one engine lock, even after it
reorganises: a canonical anchor, or an unfinalized branch once it joins the
canonical chain, reads the height index, and an anchor more than
`4 × chunk_size + 16` blocks off the canonical chain is refused rather than
walked. A page holds at most 16 complete `ProvenBlock`s in height order and
stops before the 32 MiB response cap, then continues past the provider's last
proven block with `CandidateBlock`s whose receipt has not arrived; a page never
places a proven block after a candidate, and a short page is partial. Numeric
requests below the retention watermark return `Pruned` with both retained
boundaries. Unknown hashes and removed indexes are `Unavailable`: no unbounded
tombstone index distinguishes an old deleted hash from one that never existed.

`StateByRoot` serves content-addressed objects under an available, hash-checked
root node (or the canonical empty root). A request names at most 128 typed items,
each by its complete hash and a byte offset; every fragment but the last carries
exactly 64 KiB, and a response carries at most 8 MiB of payload. Item kinds are
`Node`, `Value`, `Runtime` (a WASM by its raw BLAKE3 code hash) and `Guest` (an
ELF by its eight little-endian verifying-key words); program requests name no
state root ([upgrades and forks](20-upgrades-and-forks.md#fetching-programs-from-peers)).
The provider checks object hashes without walking the tree per fragment and does
not assert that an object is reachable from the root; the receiver authenticates
reachability from the root down through verified child hashes, and a final
complete-root check refuses missing, corrupt or unreachable entries before
installation. Partial bytes and progress survive restart.

`HistoryProofRequest { anchor_chunks, end_chunks, checkpoint_hash, bootstrap }`
(49 bytes) returns `HistoryProofResponse { proof, anchor, bootstrap }`: the
receipt ending at the canonical boundary of `end_chunks` whose checkpoint hash
matches, the `AnchorOpening` of the boundary at `anchor_chunks` under it (none for
the specification's start or the endpoint itself, and omitted from a
non-bootstrap reply when the provider does not retain it) and, when `bootstrap`
is set, the snapshot manifest. The provider refuses an endpoint other than its
own canonical one rather than substituting it, and reports a pruned receipt as
pruned.

`ChunkProofById` with empty `statement_keys` returns each chunk's canonical
proof; otherwise one key per id selects the retained proof with that key, as a
voter fetching a ratification needs ([proof market](08-proof-market.md)).
`ReceiptsByHash` returns every retained receipt of each block, the canonical one
first, and refuses more than 16 hashes before any lookup. `FinalityCertByChunk`
may return a certificate whose chunk proof has not arrived; a certificate alone
authenticates no finalized state. `CandidateByChunk` serves only the provider's
next unfinalized chunk: the active candidate, or an exact target a vote named,
including a retained proven branch an earlier quorum named
([certified execution](11-certified-execution.md)). `BftRoundByChunk` returns the
provider's current signed proposal and round-change certificate for an
unfinalized chunk; it is an availability hint whose contents are authenticated
independently ([BFT protocol](10-bft-protocol.md)). The signed-artifact
protocols are specified in
[evidence availability](17-evidence-availability.md). `WitnessByBlock` serves
the execution witnesses an executing node retains; a node without them returns an
empty reply.

## Transaction pool repair

Full and validator nodes repair missed transaction gossip by pulling. After a
matching handshake the driver tracks at most 256 providers and runs four
requests at once, one per peer. `TransactionInventory(after)` returns at most 128
strictly increasing BLAKE3 content hashes of pending bodies; a full page
continues from its last hash and a short page resets the next scan.
`TransactionsByHash` fetches at most 16 missing bodies of at most 256 KiB each;
bodies that left the serving pool may be omitted. The receiver refuses
duplicate, unsolicited or oversized bodies and runs ordinary local admission on
each returned transaction. Completed scans and transport failures cool down for
five seconds, polling is round-robin, a disconnect drops that peer's scan, and
request nonces fence responses from earlier connections. A peer whose bodies are
all refused backs off like a failed provider. Light clients do not repair. These
content hashes are distinct from the runtime's transaction identifiers, and an
inventory never replaces local validation or consensus.

The pool itself is local policy that never changes block validity or a Guest
identity: 256 KiB in total; an account holds at most 64 KiB and 32 entries;
future nonces share at most half the pool, and the EVM runtime admits nonces at
most 64 ahead. Zero fee caps are refused, so an unfunded account cannot fill the
pool with zero-fee entries that crowd out a funded transfer. Entries expire 15
minutes after admission (checked on admission, revalidation and pool access, and
never renewed by duplicates or revalidation), a strictly better runtime bid can
atomically evict worse ones, and bodies over the pool capacity or exact admitted
duplicates return before any state snapshot or WASM validation. Undecodable or
unsigned bodies are the sender's fault under any runtime. WASM admission has a
100-million-instruction fuel budget by default, enough for large-calldata EVM
transactions.

## Sync state machine

`neutrin0_network::sync::SyncMachine` is a pure state machine: it owns no I/O,
performs no verification and persists nothing. The sync driver translates its
commands into network requests, runs verification and storage, and feeds the
results back as events.

```text
LightClient:     Init → HistoryFetch → Following, or → Stalled(HistoryConflict)
Snap, Archive:   Init → Following
```

Full, validator and reporter nodes run `Snap`; archives run `Archive`. They
enter `Following` on the first peer status ahead of them and catch up outside the
machine, by sequential complete-chunk sync, BFT candidate backfill or snapshot
bootstrap. A light client samples the last `sample_peers` distinct hosts
(identities sharing one network prefix count as one sample), fetches the
highest endpoint that `sample_quorum` of them advertise identically, and stalls
on two verified History proofs that disagree at one chunk count; the sampling,
opening and conflict rules are in [light clients](14-light-clients.md).

### Complete-chunk sync

Sequential sync fetches complete publications through `BlocksByRange`. Each
`ProvenBlock` carries the signed block, its receipt and its write set and imports
as one unit once the receipt verifies under locally derived public inputs and
the writes reproduce the header's state root, or, on an executing node, once
re-execution agrees ([proof-following nodes](07-proof-following-nodes.md)). The
driver keeps a per-provider branch cursor and verifies contiguous heights,
parents and proof bindings; a cursor survives the provider's head moving within
the chunk, so the current chunk is never fetched twice, and a page that does not link
restarts it. It then fetches the chunk's proof through `ChunkProofById`.
A verified chunk on a competing unfinalized branch selects its replayed state,
canonical index and finality in one atomic batch. Branch replacement works after
pruning: the host walks both heads by height to their common ancestor without
old finalized headers, and re-execution and the finalized-height floor still
precede atomic state and head publication. A locally missing parent header is an
unavailable dependency, never proof that its sender sent invalid data.

An exact candidate and its `FinalityCertByChunk` certificate authorize one
successor chunk after complete native consensus validation and durable
certification; missing dependencies trigger backfill and block advancement
([certified execution](11-certified-execution.md)). Candidate backfill retains
a vote's propagation source, fetches unknown candidates and backfills their fixed
endpoint through ordinary block and proof requests, rotating among bounded
targets so repeated status announcements cannot starve the branch with the
highest valid quorum. Gossip and RPC share one proof finalization path.

### Provider choice

Providers are ranked by measured latency, a running mean that weights the newest
sample a quarter, with a peer never asked before first; a request that made no
progress counts as 30 seconds. A peer's own advertisement says nothing about how
it serves, so a provider that answers slowly but validly loses requests to
faster ones. Only proven-invalid data or an unreachable provider backs a provider
off: 30 seconds, doubling with each repeated failure up to 30 minutes, kept
across reconnects and notices, and cleared only by a served request. At most 256
providers are remembered. A provider that holds only candidates past the cursor,
lags or reorganised is retried at the next status tick. Snapshot bootstrap,
program fetches and transaction repair keep their own rankings by the same rule.
Local capacity failures leave a provider's standing unchanged.

A node reports itself syncing while a block page is outstanding, while a light
client is behind its target, while stalled, or while some peer not backed off is
more than two blocks ahead of its head or proven head, or more than one finalized
chunk ahead; ordinary following therefore does not flap.

### Snapshot bootstrap

A `Snap` node bootstraps from a snapshot when it is fresh, or when a peer has
finalized more than eight chunks (the window peers retain) beyond it; within the
window sequential sync catches up, and the trust origin is derived from current
finality each time. It requests the provider's latest endpoint with
`bootstrap = true`, verifies the History proof from the specification's start and
the anchor opening of its local trust boundary under it
([recursive history](13-recursive-history.md)). It downloads the highest endpoint
that at least two peers advertise identically, else the highest any peer
advertises, so one peer's claim never outranks what others agree on, from the
agreeing provider that has served fastest. State fragments go to the fastest
provider not backed off. A partly received object is finished from the provider
that began it; any other provider, or the same one after a restart, fetches it
again from byte zero, so every byte of an object comes from one peer and a
content mismatch backs off only that peer. A node whose anchor opening a provider
does not retain keeps that anchor and asks another provider; it cannot replace
the anchor with a recent checkpoint a server advertises. Archives replay sources
instead, from peers whose `Metadata` retention covers them.

History requests are reconciled without relying on gossip: the driver polls one
connected provider every five seconds, tries each provider at most once per
endpoint and availability event after an unavailable or pruned answer, and
re-arms an exhausted light-client endpoint after 30 seconds. Every callback keeps
its exact endpoint and a monotonic request identity, so a reconnection cannot turn
an old response into a new request's result.

## Resource bounds

The host budgets below are local policy, not consensus rules. They bound queues
and stream readers; they are not an RSS ceiling for libp2p, WASM, SP1 or the
operating system.

| Surface | Bound |
| --- | --- |
| Connections | 16 pending in and out; 32 established in and out; 64 total; 2 per identity. Unpinned outbound connections use at most 24 slots, reserving the rest for identity-pinned bootnodes. A connection is refused while 256 control events are queued. |
| Address diversity | 4 peers per IP and 8 per IPv4 /24 or IPv6 /48; IPv4-mapped IPv6 normalises to IPv4. Loopback and configured bootnodes are exempt. |
| Per-peer intake | Per 5 seconds: 16 requests, 128 gossip deliveries and 32 MiB, response bytes included. |
| Network-group intake | Per /24 or /48 per 5 seconds: 64 requests, 512 gossip deliveries and 128 MiB, surviving identity and socket churn; at most 512 groups tracked. Loopback and bootnodes are exempt. |
| RPC streams | 16 concurrent per protocol and connection, both directions together (above the drivers' four-request parallelism, since libp2p silently drops an excess inbound stream). Frames above 64 KiB wait at most 2 s for a shared reader budget of 3 chain-data, 2 auxiliary or 64 control readers per direction; smaller frames need none. An inbound request must arrive within 5 s. |
| Inbound host requests | At most 20 pending: 16 bulk (4 per peer) and 4 control (1 per peer); auxiliary protocols at most 14 (3 per peer). Each is charged until its response is delivered; excess gets `Unavailable`. |
| Inbound query execution | The driver answers status, metadata and ping itself and serves data queries on a separate task, at most four at once and one per peer; a query waiting more than 5 s is refused as busy. |
| Outbound requests | At most 8 bulk (4 per peer, 128 MiB reserved) and 64 control (1 per peer); auxiliary protocols at most 6 and 64 MiB. The driver holds 16 bulk response slots (128 MiB) and 64 control slots (64 KiB), and an auxiliary request needs 64 MiB beyond its own reservation free, so chain retrieval always has room. |
| Gossip queue | 24 MiB for bulk topics plus 8 MiB reserved for BFT votes and messages. A bulk delivery is admitted while fewer than 96 messages await a verdict, a BFT one while fewer than 128 do. Bytes stay charged until the application's verdict. |
| Application delivery | The swarm never awaits a send into the application mailbox: overload ignores gossip or returns `Unavailable`. A bounded driver backlog prioritises control and BFT intake. |
| BFT driver | Authenticated votes deferred until their proposal or branch arrives: 128 and 8 MiB, with an independent 128 and 8 MiB queue for votes on unknown branches; pending proposals 8; candidate targets 8 and candidate queries 16. Round recovery runs 4 concurrent `BftRoundByChunk` requests over at most 256 providers, retrying each after a 5-second cooldown on status events and the 5-second retry timer, least recently tried first; a local chunk or round change clears cooldowns. |

Every driver fences callbacks with a connection generation, a monotonic request
nonce and the exact request identity, so a stale response never releases or
completes a replacement request.

## Peer scoring and quarantine

Gossipsub scoring rewards validated first deliveries (weight 0.5, capped at 4
per topic, total topic score capped at 32) and charges 160 per invalid delivery,
so one confirmed reject outweighs every positive reward and crosses the graylist
threshold (−80; gossip −10, publish −50). Mesh-delivery and time-in-mesh terms
are zero: silence on sparse proof topics is not misconduct, and proof latency or
inactivity alone are not evidence. Localhost is exempt from IP colocation
scoring.

Transactions, leader proposals, votes, round messages and raw evidence return
semantic verdicts: malformed data and invalid signatures are rejected, while
missing context, duplicates, pool policy and honest stale state stay neutral. A
transaction announcement made under a different runtime hash than the local one
is ignored before WASM execution, so an upgrade race cannot turn an honest
transaction into a penalty. Vote signature attribution is retained separately
from live BFT policy, including signed invalid unlock declarations objective
evidence needs; nil and round messages stay authenticated without a live session,
and exhausting optional source retention never bypasses authentication or blocks
otherwise valid live BFT admission.

A strike is a rejected gossip delivery, a malformed RPC response, or an inbound
request that is malformed or stalls past its read deadline. Outbound response
timeouts are availability failures and never strike, since they include remote
load and transport delay. Three strikes within a minute quarantine the identity
for five minutes across protocols and disconnect it (at most 256 quarantined
identities, oldest released first). Six strikes within a minute from one address,
across any identities, quarantine the address for five minutes, so fresh
identities do not reset the count. Guard actions are counted in
`neutrin0_network_guard_actions_total{reason}` with reasons `connection_limit`,
`handshake`, `gossip_budget`, `inbound_rpc_budget`, `outbound_rpc_budget`,
`quarantine` and `address_filter`, beside the transport, gossip, RPC and
bootnode metrics.

## Health probes

The metrics listener serves `/health` and `/ready` for readiness and `/live` for
process liveness. A supervised one-second sampler tracks connected peers, sync
and bootstrap completion, proof-only trust-anchor expiry and time since finality
last advanced. Readiness needs at least `[health] min_peers` peers (default 1;
0 permits intentional isolation) and finality progress within
`finality_stall_timeout_secs` (default `max(1800, 3 × chunk_size ×
slot_duration_secs)`). Head movement and scrapes cannot reset the finality timer,
and a stale sampler cannot keep reporting a healthy cached state. Termination of
any critical worker task is a node failure. These probes are operational; they
establish no consensus trust and change no finalization rule.

## Threat model

Consensus verification and network availability are separate properties. A free
libp2p identity is not a staked validator identity, and surrounding a node with
peers cannot forge validator signatures or valid proofs. It can withhold data,
censor the node's view of transactions, stall finality and exhaust local
resources up to the budgets above. Health checks detect stale progress; they do
not restore peer diversity. Sybil and eclipse resistance rest on the discovery and
diversity bounds above and are not established by a controlled-network test
([roadmap](22-roadmap.md)). The DA root commits lane contents; erasure-coded data
availability sampling is not part of the protocol.

The defaults follow the upstream
[gossipsub v1.1 security specification](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md)
(outbound quotas, delivery scoring, opportunistic grafting) and the
[libp2p DoS guidance](https://libp2p.io/docs/dos-mitigation/) (connection,
stream, rate and resource controls).
