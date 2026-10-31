# Recursive history

Every complete Chunk Guest after a chain's first chunk recursively verifies the
previous chunk's receipt, and the first chunk starts at the boundary the chain
specification pins: genesis, or a hard fork's start
([upgrades and forks](20-upgrades-and-forks.md)). The latest finalized chunk
receipt therefore proves the whole chain from that start, and it is the History
proof. Finality and History coverage are the same count, so there is no separate
History prover, background job, queue, batching policy or second Guest. Nodes keep
that one receipt plus a bounded window of recent records, which keeps their
storage independent of chain age.

All receipts are SP1 Compressed STARKs ([proof system](06-proof-system.md)).

## Proof responsibilities

```text
Fact → Evidence → Block ─┐
                          ├─ Chunk N  (verifies Chunk N−1's receipt)
       Chunk N−1 receipt ─┘     │
                                └─ receipt of Chunk N = History proof of [first, N+1)
```

The Block Guest proves the state transition, transaction and execution
commitments and accountability effects. The Chunk Guest verifies complete
consensus, authenticates referenced history, derives the next consensus
boundary and, for every chunk `N` after the first, verifies exactly chunk
`N − 1`'s receipt, whose end boundary must equal chunk `N`'s start. That check is
the ratification the [proof market](08-proof-market.md) pays for: the proposal of
chunk `N` names a proof of chunk `N − 1`, the Guest verifies it and the proving
report credits its prover. Paid chunk proving and History coverage are one step.

A History proof is conditional only on the trusted chain binding. Its start,
`ConsensusBoundary::first(spec)`, is read from the verifier's own specification.
Its end is a rules-valid history, not a claim that it is the latest one; how a
light client picks an endpoint is in [light clients](14-light-clients.md), and a
verifier trusting a boundary after the start also needs an
[anchor opening](#anchors-and-anchor-openings).

## Statements and identities

The Borsh types live in
[`consensus-types::history_proof`](../../crates/consensus-types/src/history_proof.rs)
and [`primitives::boundary`](../../crates/primitives/src/boundary.rs). There is one
format, with no version suffixes or fallback decoders.

`ChainBinding { chain_spec_hash }` commits the complete specification, which pins
the chain id, the chunk size, the immutable Fact Guest and the chunk Guest
(`genesis_chunk`). Consumers read those values from the specification they hold,
never from a copy in the binding. The binding never changes for the life of a
chain, so changing the chunk Guest is a hard fork. Execution program identities
travel in every boundary as a `ProgramSet` (runtime code hash plus Fact, Evidence
and Block verifying-key digests), so governance can switch execution programs at
a chunk boundary without changing the binding
([upgrades and forks](20-upgrades-and-forks.md)).

`ProofDomain { chain, chunk, programs }` is a verifier's trust profile: the
binding, the specification's chunk Guest and the program set trusted at its
anchor. `ProofDomain::is_valid(spec)` requires exactly the specification's binding
and chunk Guest and a program set the specification accepts. A node builds its
proof backend from the pinned program bytes and uses it only when the keys it
derived locally match the pins. Block receipts are verified under the program set
of the chunk's start boundary, which the verifier has already authenticated, and
chunk receipts under the specification's chunk Guest. No receipt selects the key
it is checked against.

`ConsensusBoundary` is the state immediately before a chunk:

| Field | Meaning |
| --- | --- |
| `next_chunk_id` | Next chunk to execute; also the count of chunks before it |
| `height`, `block_hash`, `state_root`, `slot` | The preceding block |
| `validators_root` | Canonical ordered active validator commitment |
| `identity_sanctions_root` | Append-only trie of permanently banned BLS identities, which execution programs cannot erase |
| `seed` | Randomness for the next chunk ([randomness](15-randomness.md)) |
| `history_root` | Counted root of the History tree |
| `programs` | `ProgramSet` that executes and proves the next chunk |
| `participation` | Commitment of the latest `ParticipationReport` consumed by the chunk ending here; zero at genesis and after the first chunk |
| `proving` | Commitment of the latest `ProvingReport` consumed alongside it ([proof market](08-proof-market.md)) |
| `fork` | The scheduled hard fork, from the boundary after its enactment up to its count; the boundary at the count is the chain's endpoint and no chunk starts from it |

`is_well_formed(spec)` requires accepted programs and
`next_chunk_id * chunk_size == height` with checked arithmetic. A boundary carries
no ratification count and no link to its predecessor: which proof a certificate
ratifies follows from the chunk id and the specification's first chunk, and the
ratified proof needs no binding to its own start because it verified its
predecessor the same way, back to the first boundary.

The participation and proving commitments come from the certificate of chunk
`k − 1` that the carrier block of chunk `k` selects
([proof market](08-proof-market.md)). That selection is part of the signed block
before BFT votes, so alternative valid finality certificates for chunk `k` cannot
change its outgoing boundary. Nodes take reports from each block's own branch;
restart, replay and historical queries never substitute whichever certificate a
host stored first.

```rust
struct ConsensusStatement {
    chain: ChainBinding,
    start: ConsensusBoundary,          // its programs verified this chunk
    end: ConsensusBoundary,            // its programs rule the next chunk
    chunk: ChunkProofPublicInputs,
    finality_cert_hash: Hash,
}

struct ChunkReceiptStatement {         // exact public values of a chunk receipt
    statement: ConsensusStatement,
    chunk_prover_address: Hash,        // outside the consensus statement
}

struct HistoryProof {
    statement: ChunkReceiptStatement,
    receipt: BoundedBytes<MAX_HISTORY_RECEIPT_BYTES>, // 8 MiB
}

struct Checkpoint { chain: ChainBinding, boundary: ConsensusBoundary }
```

A chunk's blocks are verified under the start boundary's Block program; a
scheduled upgrade read from the post-state witness may give the end boundary a
different program set. Full next-context vectors are node-side results, not
public values. Wire chunk metadata and the supplied certificate must match the
committed statement exactly.

A `HistoryProof` is a finalized chunk receipt without its certificate. `receipt`
is the exact `ChunkProof.proof_bytes` (Borsh of the compressed `Sp1ChunkProof`);
chunk proofs are capped so every finalized receipt fits the 8 MiB bound. Two
receipts of one certificate with different provers finalize the same chunk and
prove the same History. `Checkpoint::hash` is tagged with `DOMAIN_CHECKPOINT` and
excludes proof bytes and prover, so every receipt ending at one boundary names the
same endpoint.

## Verification

`verify_history_proof(backend, spec, proof)`
([`proof-system::history`](../../crates/proof-system/src/history.rs)) asks the
backend for its domain under `spec` and requires that the domain is valid for
`spec`, that the statement names that binding, that the end boundary is well
formed and that it counts at least one chunk. The backend then verifies the
receipt under the specification's chunk Guest and compares the exact public
values with the statement. The SP1 host requires `SP1Proof::Compressed` and runs
the real verifier, so a mock receipt cannot pass. Nothing is wrapped in Groth16 or
PLONK. The result is a `VerifiedHistory` token, produced outside engine locks and
consumed after the caller's own boundary checks.

Recursion soundness rests on the chunk Guest. It reads the specification from its
witness (a Guest cannot embed its own key), refuses any chunk below the
specification's first chunk, refuses the first chunk unless its start is the
canonical genesis boundary with the genesis seed or, under a fork, exactly the
pinned start, and refuses every chunk at or beyond a scheduled fork's count. For
each later chunk it requires the ratified statement to match the proposal's
`ratified_chunk_proofs` entry, name this chain and end at its own start, then
verifies that receipt recursively under `genesis_chunk`. A receipt for chunk `N`
therefore exists only if receipts for every earlier chunk existed under the same
binding.

## Anchors and anchor openings

A node or light client that trusts a boundary after the History's start must not
move to a chain that does not contain it. The History leaf of chunk `m` commits
its `EvidenceContext`, whose `start_boundary` is the commitment of the boundary
chunk `m` started from. An `AnchorOpening { context, path }` of leaf `m` under the
history root of a later boundary `B_n` therefore authenticates `B_m` as an
ancestor of `B_n`. Every leaf was appended by a complete chunk Guest, so the
opening is as strong as the receipt that proves `B_n`.

`check_anchor(start, anchor, end, opening)` returns one of four outcomes, and
`anchors` is its `Extends` case. `start` is `ConsensusBoundary::first(spec)`.

| Outcome | When |
| --- | --- |
| `Extends` | `anchor == end` with no opening; `anchor == start` with no opening; or the opening of leaf `anchor.next_chunk_id`, counted at `end.next_chunk_id`, verifies under `end.history_root` and its `start_boundary` equals `anchor.commitment()` |
| `Unopened` | The anchor needs an opening and none was supplied |
| `Invalid` | The anchor lies below `start` or above `end`, the path does not verify, or an opening was supplied for the start or the endpoint. A provider fault that says nothing about the chain |
| `Conflicts` | A verified opening's leaf started from another boundary, or `end` is a different boundary at the anchor's own count. The proven chain does not contain the anchor |

`needs_opening(first, anchor, end)` tells a provider exactly when to send one:
for every anchor except the start and the endpoint.

`Engine::anchor_opening(anchor, end)` builds an opening from the retained record
of chunk `anchor` and its cached path under the count `end`. It needs neither the
boundary `B_anchor`, which pruning removes, nor the full tree, because the
requester compares `start_boundary` with its own trusted boundary. Pruned nodes
open every anchor within `history_record_window_chunks` (one unbonding delay,
which bounds the weak-subjectivity period); archives open any finalized record. An
opening is 64 sibling hashes plus one thin context regardless of chain age.

## Bounded historical access

The History commitment is an append-only tree over the `u64` chunk index space
with exactly 64 levels (`HISTORY_DEPTH`). Separate tags distinguish empty and
occupied leaves (`DOMAIN_HISTORY_LEAF`), inner nodes (`DOMAIN_HISTORY_NODE`) and
the counted root (`DOMAIN_HISTORY_ROOT`). Reads bind both the index and the leaf
count; appends use a fixed-size frontier and a checked count increment. Every
root constructor uses the same canonical empty tree.

A chunk witness carries only the certificate-independent contexts its
participation selection and compact acknowledgements reference, each with its
membership path. Decoding enforces the limits in
[`prover-chunk::history::witness`](../../crates/prover-chunk/src/history/witness.rs):

| Limit | Value |
| --- | --- |
| Distinct historical reads per witness (`MAX_HISTORY_READS`) | 8 |
| One thin context (`MAX_HISTORY_CONTEXT_RECORD_BYTES`) | 32 KiB |
| All thin contexts (`MAX_HISTORY_CONTEXT_BYTES`) | 256 KiB |
| One full `HistoricalOpening` source record (`MAX_HISTORY_RECORD_BYTES`) | 8 MiB |

A thin context encodes in `508 + 112N` bytes for `N` validators (each weight a
`u128` in wei): 29,180 bytes at the 256-validator maximum, 233,440 bytes for
eight records before paths and frontier. Full `HistoricalOpening` carriers share
exact proof manifests and quorum certificates through canonical dictionaries;
distinct valid subsets and proof encodings stay distinct, and sharing never
admits a committee beyond the consensus bounds. These are wire-size bounds, not
proving costs.

For each appended context commitment, the frontier yields the new leaf's complete
path without a tree lookup. An existing path changes only at the sibling of the
highest differing bit between its index and the append index. Bounded path caches
and pooled evidence-report paths therefore advance with each finalized leaf
without retaining historical nodes. A reporter's watched openings follow instead
from the complete subtrees appends form, so nothing watched is rewritten
([reporter nodes](18-reporter-nodes.md)). The Chunk Guest authenticates the old
frontier against its start boundary and derives the appended root in its end
boundary, so validators produce the transition without the full tree.

For incoming chunk `n`, historical source indices must lie in
`[n.saturating_sub(8), n)` (`is_recent_history_index`): chunk 10,000 can reference
chunk 9,992 but not 9,991 or 1, even with a valid archive opening. An opening
targets the current incoming history root, so one made for an older leaf count
cannot be reused unchanged. It authenticates the historical validator context,
not past inclusion of a particular vote: full votes keep their separate vote and
attestation checks, and compact acknowledgements check each precommit signature.
Old certificates are not repeated in contexts, because their leaves were appended
only after complete chunk verification. Liveness evidence admission applies the
same eight-chunk window plus the governable evidence-age window (1,024 blocks by
default); safety evidence has no age limit and opens any finalized record through
the same fixed-depth path ([evidence proofs](16-evidence-proofs.md)).

Fixed depth bounds work with respect to chain age; work still varies with current
transactions, validators, evidence and the number of referenced records. A root
or a recursive proof cannot reconstruct deleted records, so raw data must still be
available from a node that retains it.

The chunk carries no consumed-penalty set or penalty root. The Block STF rejects
repeated offence ids and stores admitted offences in authenticated state, and
continuous proven state roots extend that replay protection across chunks.
Evidence pruning follows atomically recorded finalized admissions, never a
reversible head. Those runtime markers are live state, which recursion does not
make constant-size.

## Persistence

Chunk finalization atomically stores the verified compact statement, the receipt,
the full next context, the immutable boundary and the appended frontier, together
with the updated cached and active pooled History paths. Archives also persist the
full tree append. `Engine::history_proof(count)` reads the History proof of
`count` from chunk `count − 1`'s stored receipt and statement and checks it against
the canonical boundary `count` under the pinned binding. Nothing else is stored for
History: no range proofs, range indices, checkpoint records, coverage pointers or
job queues.

At startup `Engine::set_history_domain` pins the trust profile the specification
defines, accepted only from a backend that derived the same keys, and an existing
database with a different binding or genesis program set is refused. After each
finality advance the node prunes below the new window off the caller's path and
announces the new endpoint it serves.

## Eight-chunk retention and archive mode

Let `F` be the count of finalized chunks. Ordinary nodes delete chunk ids strictly
below `F.saturating_sub(8)` (`HISTORY_RETENTION_CHUNKS`), never below the durable
bootstrap source floor. A freshly bootstrapped node's source floor is `F`, yet its
consensus columns still keep chunk `F − 1`: that chunk's receipt, statement and
start boundary are its History proof and the proof the next certificate ratifies.
With finality at 10,000, the retained finalized chunk ids are `[9,992, 10,000)`
plus current unfinalized work, and the boundary before chunk 9,992 stays
authenticated. Recursion never lags finality, so no input waits for a History job
and the window does not grow while proving stalls; an unproven chunk is simply not
final.

The pruning batch removes old raw blocks, headers and their indices, execution
witnesses, block and chunk receipts and certificates, and obsolete historical
records. It keeps the latest finalized receipt (the current History proof), the
current boundary and its identity-sanctions root, the recent window and the state
reachable from retained roots ([state and storage](04-state-and-storage.md)).
Ordinary nodes keep no `HistoryNodes`. Frontiers and cached paths are bounded by
the record window and the preceding eight boundaries. Active and dormant evidence
paths and their saved roots share the evidence pool's 256-report and 32 MiB
limits; finalization updates active paths in the same batch as the root, and
dormant paths wait for a holder's refresh without blocking appends
([evidence availability](17-evidence-availability.md)). Persistent deletions and
the watermark commit atomically before in-memory state changes, and restart
validates the retained canonical suffix against its boundary.

Complete historical records (validator vector, seed, certificate) stay for
`history_record_window_chunks`: one unbonding delay in chunks, at least eight
(2,363 chunks under the default 14-day delay and 128-block chunks). Within that
horizon a node builds safety evidence from available raw reports and serves the
anchor opening of any trust boundary younger than the weak-subjectivity period. A
validator can stay bonded beyond the horizon; older evidence then needs a
retaining reporter or archive. Reports carry an opening under a current or
preceding-eight authenticated root; ordinary nodes advance it over the bounded
append suffix and defer older anchors for refresh without expiring the safety
claim. Reporters keep source contexts and, apart from them, continuously updated
paths for slashable identities, store no complete tree and apply the ordinary
raw-block deletion watermark ([reporter nodes](18-reporter-nodes.md)).

`role = "archive"` preserves complete source history and the full immutable tree,
and opens any finalized record. A node advertises archive capability only for an
unpruned archive database; switching a pruned database to archive needs the
missing history rebuilt from another source, because configuration cannot recover
deleted bytes. Current execution state, pending sanctions and offence markers are
live state and grow independently of raw history.

Old transactions and state become unavailable network-wide if no archive keeps
them; this is an accepted trade-off, since recursive proofs establish past
validity but cannot reconstruct discarded data. `Metadata` and
`history_getRetention` report actual retention, not an assumed window. Payload
requests for known heights or chunks below the watermark return `Pruned`, while the
retained boundary header stays readable as an anchor. Unknown hashes have no
tombstone index, so a pruned hash and an unknown one get the same unavailable
reply. No query falls back to the head.

## Snapshot bootstrap

A full or validator node can install a finalized endpoint with an authenticated
execution-state snapshot and continue source replay from it.

### Trust

Bootstrap verifies the provider's latest finalized receipt as a History proof from
the specification's start and, unless local trust is that start or the endpoint
itself, an anchor opening that places the local trust boundary on that chain.
Admitting a manifest applies the light client's weak-subjectivity, freshness and
future-slot policy ([light clients](14-light-clients.md#trust-configuration)); a
peer cannot supply or refresh `trusted_at`. An explicitly trusted endpoint needs
no opening but still passes the time checks. Installation and restart verify the
admitted manifest's proof and opening again and refuse an expired trust anchor,
but do not judge the endpoint stale: freshness chooses which endpoint to download,
and a long download weakens nothing already verified. A restart with an expired
anchor stops with an error naming the remedy, a newer trusted checkpoint.

Bootstrap is enabled by default for full and validator roles. Without an explicit
checkpoint, the local finalized boundary is the trust origin, timed by its block's
original timestamp rather than the restart time. The origin is derived each time
bootstrap is considered, so a running node, including one that already
bootstrapped, can bootstrap again; an explicit checkpoint applies until local
finality passes it, and a download keeps the origin it was admitted under. A fresh
node snapshots as soon as any peer has finalized a chunk. Any other node snapshots
only to a peer that has finalized more than eight chunks beyond its own, past the
window peers retain, and otherwise catches up by sequential complete-chunk sync.
Ordinary signing and imports pause during manifest selection and download and
resume after installation or source fallback.

### Bootstrap data

```rust
struct BootstrapData {
    history: HistoryProof,         // receipt ending at the endpoint
    anchor_header: Header,         // header at the end boundary
    validators: BootstrapValidators, // ordered active validators for the next chunk
    frontier: HistoryFrontier,     // counted frontier at the endpoint
    recent: BootstrapHistory,      // the preceding min(F, 8) HistoricalOpenings
}
```

Every part is bound to the proven boundary at count `F`; each record certificate
and the endpoint proposer signature are checked independently, and the recent
openings target the endpoint's history root and count. Installation stores the
receipt and statement as chunk `F − 1`'s, so the node immediately serves the same
History proof and, as chunk `F`'s leader, ratifies it without fetching it first. It
records the genesis, start and end boundaries, installs the supplied paths in its
bounded cache, and appends future leaves from the frontier without restoring tree
nodes or downloading older records. Durable consensus state stores the boundary
directly; an unauthenticated last chunk statement is never installed as finality.

The raw source watermark begins at `F`, so earlier transaction bodies are absent,
while historical consensus records keep `[F.saturating_sub(8), F)`. A durable
bootstrap provenance stops the raw watermark from regressing while new chunks
rebuild the recent source window. Archive nodes always replay sources (under a
fork's successor, from its start) and never advertise a snapshot-bootstrapped
database as complete history. Snapshot installation can skip the append data that
pooled evidence paths for arbitrary old sources would need; those reports stay
dormant until their holder refreshes them
([evidence availability](17-evidence-availability.md)).

### State download

Execution state downloads use typed content hashes and offsets with durable
progress. The downloaded state never sits in memory whole: it enters the state
store in bounded, restart-resumable slices under installation pins, and the
installation adopts those roots ([state and storage](04-state-and-storage.md)).

| Bound | Value |
| --- | --- |
| Entries per state request (`MAX_STATE_ITEMS`) | 128 |
| Fragment size (`MAX_STATE_FRAGMENT_BYTES`); every fragment but an object's last is full | 64 KiB |
| One object | 64 MiB (1,024 fragments) |
| Objects per root | 2,000,000 |
| Total staged data | 64 GiB |
| Assembled request/response message ([networking](21-networking.md)) | 32 MiB |

Hashes and the final root authenticate every byte; these limits do not certify
state validity or add consensus limits. Hash checks authorize following children,
and complete root authentication takes exactly the objects the root reaches and
rejects missing or corrupt ones. The endpoint boundary authenticates both the
execution-state root and the identity-sanctions root; downloads track each root
across restart, and both complete tries must authenticate before installation.
Objects are staged once by kind and hash and shared by every root: each root keeps
its own pending and resolved rows, a partial object its fragments and progress, so
a response writes only what it changes, without forcing a disk sync. A replacement
manifest drops only the replaced roots' progress; staged objects stay, and the new
roots resolve objects already present without fetching them. Objects no live root
holds or awaits are swept only when the 64 GiB budget would otherwise be exceeded.
A provider that cannot serve a manifest within these bounds reports unavailable,
and the requester turns to another provider or to source replay.

No live state or finality pointer changes before one durable installation batch.
The batch preserves signing journals and refuses a newer local head or unfinalized
BFT locks beyond the endpoint; a saved session of the endpoint's next chunk
survives installation and resumes when that chunk opens. Restart handles
interrupted downloads and completed installations whose staging cleanup was
interrupted.

An authenticated pending snapshot names its endpoint programs and the retained
recent runtime and Block sources before any artifact installation. Serialized
retention and counted temporary scopes keep those sources through validation,
manifest replacement and installation, and one completed attempt cannot release
another's. Only the endpoint `ProgramSet` and the runtime that produced its state
stay warm; older recent versions keep authenticated source authority without
compiled modules or CUDA sessions. Installers are serialized, the final commit
rechecks the exact pending manifest so an older attempt cannot clear a
replacement, and restart reauthenticates pending metadata before program-source
pruning.

### Provider leases

Providers serve only their latest finalized endpoint and lease at most eight state
roots for snapshot service: the execution and identity-sanctions roots of four
manifests. The current and the finalized endpoint's auxiliary roots stay retained;
intermediate versions need no historical state service. A lease expires after five
idle minutes and at most 24 hours in total; valid state requests renew it once
less than half its idle window remains. Lease writes are not synced, since a lease
lost to a crash only ends a transfer early. A full table never refuses the latest
endpoint: it frees the least recently renewed lease, whose downloader resumes from
a newer manifest with the objects it staged, so no peer can exhaust the table
against new nodes. A clock stepped back below a lease's creation restarts its
lifetime there, and a malformed lease is released rather than failing a prune
(`neutrin0_history_prune_failures_total` counts deferred prunes). Leases pin only
execution state, never transaction bodies or the raw-history watermark.

### Snapshot files

`neutrin0-cli node export-snapshot --out FILE [--anchor-chunks N]` writes the
running node's latest finalized endpoint with the same manifest and objects, and,
with `--anchor-chunks`, the anchor opening for that trust boundary. A node without
reachable peers sets `[bootstrap] snapshot_path`; the importer stages each object
against its key, then resolves and installs the download as above. The manifest is
authenticated exactly as a network one, except that an operator-supplied endpoint
is not judged stale; the trust anchor must still be unexpired, and an endpoint
local finality already reached is skipped.

### Configuration

```toml
[bootstrap]
enabled = true                       # default for full and validator roles
trusted_checkpoint_path = "trusted-checkpoint.borsh"
trusted_at = 1790985600              # required with the checkpoint path
max_future_drift_secs = 30
# snapshot_path = "endpoint.snapshot"
# fork_from = "<predecessor data_dir>"   (design 20)
```

A node whose genesis trust has expired needs an independently obtained Borsh
`Checkpoint` and the Unix time it was trusted; the weak-subjectivity period runs
from the earlier of that time and the checkpoint block's slot time. Peer
advertisements never choose this origin. `enabled = false` keeps ordinary source
replay.

## Transport and RPC

`/neutrin0/req/history_proof` takes
`HistoryProofRequest { anchor_chunks, end_chunks, checkpoint_hash, bootstrap }` and
returns `HistoryProofResponse { proof, anchor, bootstrap }`: the History proof
ending at the canonical boundary of `end_chunks` whose checkpoint hash is
`checkpoint_hash`, the opening of the boundary at `anchor_chunks` under it (absent
when `needs_opening` is false) and, when requested, the `BootstrapData`. A provider
that cannot supply an opening the requester needs reports the request
unavailable, since the requester would refuse the reply without it. Providers
refuse a different endpoint rather than substituting their own and report pruned
receipts as pruned. A light node opens nothing.

`Status` advertises the finalized endpoint's checkpoint hash, which is also the
History endpoint, and each finality advance publishes
`CheckpointAnnouncement { chunk_count, checkpoint_hash }` on the checkpoint topic.
An announcement is never accepted as a proof or trust anchor. Unavailable replies
try other known providers at most once per availability event; after exhausting
them the requester waits for a new event. Full nodes finalize every chunk
themselves and never import History proofs.

| JSON-RPC method | Result |
| --- | --- |
| `history_getLatest` | Borsh bytes of the latest finalized receipt as a `HistoryProof` (a light client returns its latest accepted proof) |
| `history_getRetention` | `archive`, `retained_from_chunk`, `retained_from_height` and `finalized_chunks` |

## Real-proof verification

Native and execution-only tests establish statement chaining but not receipt
authenticity: SP1 execution mode skips deferred proof verification, so only real
compressed proving shows that the Guest binds the ratified receipt. The ignored
integration tests in
[`history_recursion.rs`](../../crates/runtime-host/tests/history_recursion.rs)
prove consecutive compressed chunk receipts with real recursion, verify the last
as a History proof under an independent verifier, and check that a missing,
misattributed or duplicated ratified receipt cannot prove. A result applies only
to the Guest ELFs it ran on. Commands and hardware requirements are in
[proving acceptance](../gpu-proving.md#gpu-tests).

## Scope

This gives constant-size History verification state, not lossless archival
compression. Raw-data availability, live application state, misconduct discovery,
evidence publication and inclusion, authenticated query proofs, snapshot data
availability, runtime upgrades and proof-of-stake weak subjectivity are separate
concerns.
