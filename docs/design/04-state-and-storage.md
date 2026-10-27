# State and storage

Execution state is a binary sparse Merkle trie hashed with Poseidon2, the hash
SP1 proves cheaply, while chain objects and protocol commitments use BLAKE3;
state roots and consensus validator roots are different objects. Nodes keep
state in RocksDB and never hold it in memory whole: a trie reads the nodes on
its paths on demand, stored entries are reference counted, and pruning and
snapshot installation run in bounded slices. Storage holds one format; the
chain-spec hash is checked when the database opens
([overview](00-overview.md#trust-model)).

## State trie

`neutrin0-trie` is a binary sparse Merkle trie with prefix compression. A raw
key becomes the bit path `key_len u32 LE || key`, read MSB first, so arbitrary
byte keys are supported, including keys that are prefixes of each other. Values
are stored by content hash and nodes by node hash. Nodes encode as:

| Node | Encoding |
| --- | --- |
| Leaf | `0x00 \|\| BitPath(key_suffix) \|\| value_hash[32]` |
| Branch | `0x01 \|\| left[32] \|\| right[32]`, `[0; 32]` for an empty side |
| Extension | `0x02 \|\| BitPath(prefix) \|\| child[32]` |

The empty trie's root is `[0; 32]`. `Poseidon2Hasher` uses SP1's KoalaBear
Poseidon2 instance (width 16, `x^3` S-box, 8 external and 20 internal rounds)
with SP1's byte-hashing convention: a `u64` length block, then 24-byte blocks of
eight field elements, and the first eight state elements as the 32-byte digest
(248 bits of entropy). Inside the Guest each permutation is one SP1 precompile
call; outside it a software implementation produces identical digests. Node
hashes prepend the 16-byte domain `NTRO_TR_NODE_P2_`; values are hashed without
a tag because they live in a separate column. The trie also has a BLAKE3 hasher
for generic consumers and tests; execution state always uses Poseidon2.

The trie produces and verifies inclusion and exclusion proofs and collects the
on-path nodes that form a block witness
([runtime interface](02-runtime-interface.md#witness)).

### Unavailable state

A trie that does not hold a node or value on a traversed path reports
`TrieError::MissingRetainedEntry` from reads, writes, deletes, proofs and path
collection, and malformed node bytes report their decode error. Hosts treat this
as unavailable state, never as absence: the tracer records the fault and
refuses to produce a post-state, witness or diff, the WASM host fails the run,
and engine and RPC callers return errors. Only the SP1 Guest aborts, because an
incomplete witnessed path must never prove a transition.

## Database

`ChainStore` (in `consensus-engine`) persists every chain object in named
RocksDB column families of `neutrin0-storage`. Each write that must be atomic is
one batch.

| Group | Columns |
| --- | --- |
| State | `TrieNodes`, `StateValues`, `StateRefs`, `StatePins`, `StateReleases` |
| Blocks | `Headers`, `Blocks`, `HeaderByHeight`, `HeaderBySlot`, `BlockStates`, `Witnesses`, `StateDiffs`, `ExecutionTransactions`, `AbandonedHeaders` |
| Receipts and proofs | `BlockProofs`, `BlockReceipts`, `ChunkProofs`, `ChunkReceipts` |
| Chunks and history | `Chunks`, `ChunkStatements`, `ConsensusBoundaries`, `HistoricalChunks`, `HistoryFrontiers`, `HistoryPaths`, `HistoryNodes` (archive only), `ValidatorSetSnapshots`, `Finalized` |
| Accountability | `SlashingPool`, `EvidenceProofs`, `FinalizedOffences`, `FinalizedSlashes`, `SignedArtifacts`, `SignedArtifactIndex` |
| Reporter | `ReporterHistory`, `ReporterSources`, `ReporterHeaders`, `ReporterBoundaries`, `ReporterValidators`, `ReporterIndex` |
| Node-local | `Meta`, `SigningJournal`, `BftSessions` |

`TrieNodes`, `StateValues` and `StateRefs` share a 256 MiB LRU block cache, use
bloom filters (10 bits per key) to answer absent hashes, and keep index and
filter blocks in the cache. RocksDB keeps four informational logs of up to
32 MiB and at most 1 GiB of write-ahead log; its checksums cover disk
corruption.

Complete chunk finalization stores the chunk proof, its history record and the
next consensus context in one atomic batch, then installs the verified
validator and seed boundary; the finality certificate is stored once, in the
chunk's historical record, and served from there for the record window. Genesis
metadata, pointers and state are one durable batch, so a crash during
initialization leaves either no chain or a complete genesis. Restart reloads the
boundary and the persistent evidence reports and receipts.

### Canonical index

Header archival never selects a branch. The materialized tip, the canonical
height index (`HeaderByHeight`) and the trie writes commit in one batch; a
reorganization replaces changed ancestry and deletes stale heights. Startup
validates the retained index against its pruning boundary and tip and restores
the retained candidate DAG and proven statuses above the finalized anchor. RPC,
chunk preparation and current-head peer ranges share this index, and explicit
hashes still address retained side branches.

## State on demand

A `Trie` opened at a root holds no nodes of its own. Traversals read the nodes
and values on their path from `TrieNodes` and `StateValues`, and the trie keeps
only what it writes, as an overlay. Cloning one copies its root and overlay, so
the head state, a sibling's parent state, a query at any retained block and a
WASM call each cost what they read, and memory is bounded by the caches rather
than the state. A node missing on a path is unavailable state; `null` from
`state_getStorage` still means authenticated absence.

## Reference counting

`StateRefs` counts the references that reach each stored node or value: one per
edge from a stored node (a leaf's edge to its value included) and one per pin
in `StatePins`. Every retained block pins its post-state, each snapshot lease
pins its root, the live identity-sanctions trie holds one pin, and an
installation in progress pins its roots. Persisting a trie under a pin writes
only the entries the store lacks and adds their edge counts with RocksDB merge
operands, so counting never reads.

Deleting a block, an expired lease or a replaced sanctions root drops its pin
and queues one release in `StateReleases`. Bounded slices apply queued releases,
delete an entry once its count reaches zero and queue the references it held.
Each slice is one atomic batch and the node releases the engine lock between
slices, so a crash resumes from the queue, nothing loads the state columns
whole, and collection costs what it frees.

### Snapshot installation

A downloaded snapshot (a bootstrap's state and sanctions tries, or a head state
fetched by `StateByRoot`) enters the same way in reverse. Fragments and progress
persist separately until the complete download authenticates against its root.
Its roots are then pinned as installation pins, and the depth-first walk that
persists a block's state counts their edges a bounded slice at a time, reading
each entry the store lacks from the staged download and checking it against its
hash. The edges not yet counted, at most two per trie level, persist with each
slice, so a restart resumes the walk. A begun installation runs to completion,
because its partial nodes count edges to entries only finishing can write;
anything that would drop staged objects finishes it first. A finished
installation is adopted, its pins becoming the endpoint block's and the
sanctions pin or the head block's, or released like any pin. Bootstrap then
publishes the adopted roots, canonical anchor, consensus context and the
endpoint's chunk receipt in one durable batch and releases every pin of the
replaced chain for bounded collection
([recursive history](13-recursive-history.md)).

## Retention and pruning

Retention depends on the node's role:

| Role | Keeps |
| --- | --- |
| Validator, full | Current state, the preceding eight finalized chunks' sources and records, no `HistoryNodes` |
| Archive | Every source and the complete immutable history tree |
| Reporter | The full-node window plus the six private reporter columns for watched identities ([reporter nodes](18-reporter-nodes.md)) |
| Light client | Only its latest accepted History proof, its trust state and, after a conflict, the conflicting evidence ([light clients](14-light-clients.md)) |

Full and validator nodes authenticate retained records with a fixed-depth
append frontier (`HistoryFrontiers`) and bounded cached openings
(`HistoryPaths`), which also keep the finalized endpoint's bootstrap manifest
and anchor openings available for one unbonding delay. Each finalized append
updates the cached paths and the paths of active pooled `EvidenceReport`s in the
same batch as the new history root. A report that a snapshot jump cannot
refresh keeps its locally authenticated root in the private report wrapper and
stays dormant until its holder supplies a current opening
([evidence availability](17-evidence-availability.md)). The exact retention
boundary and the archive mode are in
[recursive history](13-recursive-history.md). Current state, recent evidence
openings and admitted withdrawal obligations survive pruning.

A bootstrapped node advertises its raw-data watermark at the installed
endpoint, keeps the preceding eight consensus records and their paths without
claiming their transaction bodies, and rebuilds the recent raw window from new
chunks. The source floor never regresses, and historical consensus records have
their own eight-chunk floor. Installation keeps signing intents and refuses to
erase unfinalized locks ([validator keys](19-validator-keys.md)).

Count- and height-keyed columns are pruned through bounded key ranges below the
watermark, and per-block columns through key-only scans.

### Unfinalized candidates

Pruning follows finality, but unfinalized candidates are bounded without it. A
node keeps only the first unproven candidate a proposer signed for a slot (a
second is a double proposal and is admitted only with a receipt), holds at most
`2 * chunk_size` unproven candidates above finality and pauses production at
the same bound, and deletes a stale candidate with its descendants one
exclusive window after it went stale
([proof-following nodes](07-proof-following-nodes.md)). The header of each
stale subtree's root stays in `AbandonedHeaders` for abandonment detection until
its height leaves the eight-chunk liveness window.

### Storage quota

A free-space quota on the data filesystem applies regardless of finality:

| Setting | Default | Effect |
| --- | --- | --- |
| `[storage] min_free_bytes` | 10 GiB | Below it the node stops producing and ignores new peer candidates, which also keeps a validator from voting on chunks whose blocks it lacks; receipts, BFT messages and complete-chunk sync continue so finality and its pruning can free space. Pressure clears a tenth above the threshold |
| `[storage] halt_free_bytes` | 2 GiB | Below it the node stops before the database fills the filesystem; must be positive and below `min_free_bytes` |

SP1 verifying-key and fact-receipt caches live in `<data_dir>/sp1-cache`. At
start the node drops entries of other SP1 circuit versions and keeps the 64
newest verifying keys and the two newest fact directories.

## Finalized and genesis views

`chain_finalized` returns `chunk_id`, `block_hash`, `height` and `state_root`
from the verified chunk boundary; `chunk_id` is `null` at genesis. Genesis is a
trusted chain-spec anchor without a stored header or body, so header and block
queries at genesis return `null` while genesis metadata stays available, and
genesis state is queryable only while its state data is retained.

State queries distinguish an unknown block (`-32020`), unavailable state
(`-32021`) and storage failure or corruption (`-32022`). A known block whose body
is missing yields `-32023` from `chain_getBlock`, never an empty body. Queries
below the advertised retention watermark return `-32024` with
`retained_from_chunk` and `retained_from_height`, and a missing History range
endpoint returns `-32025`. Unknown hashes are not kept as tombstones, so their
lookup stays unavailable or `null` without claiming they once existed
([consensus RPC](../consensus-rpc.md)).
