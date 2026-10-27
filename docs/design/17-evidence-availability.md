# Signed sources and evidence availability

An objective sanction needs the signed source of the offence. A recursive
EvidenceProof makes the eventual claim compact ([evidence proofs](16-evidence-proofs.md)),
but it cannot recover a signature or proof envelope that nobody published. This
layer retains, announces and retrieves the original signed sources needed to
construct those claims, within bounded storage and without ever gating live BFT
progress.

## Sources and identities

`SignedArtifact` is one of:

| Variant | Content |
| --- | --- |
| `Vote` | an attested value vote with every required individual attestation |
| `NilVote` | an explicit nil vote with its signer declarations |
| `Quorum` | a prevote quorum certificate (a lock or unlock quorum) |
| `Proposal` | a signed round-leader proposal |
| `RoundChange` | a signed round-change report carrying its highest quorum |
| `RoundChangeCertificate` | a signed pacemaker quorum |
| `BlockProof` | an exact block proof envelope, accepted or rejected |

A precommit signs the count and root of the exact proof envelopes its signer
accepted, and its value vote exposes the complete ordered manifest through a
canonical dictionary shared by the signers. Dictionary roots, count, sorted
unique ordering and complete required coverage are authenticated before
dependency indexing. A later prevote exposes its signed unlock declaration and
any independently carried quorum. One encoded source is at most 8 MiB.

Every source has an immutable content identity and an explicit
`SignedArtifactKind`. A block proof's identity is exactly
`BLAKE3(DOMAIN_BLOCK_PROOF || borsh(BlockProof))`, matching the precommit
declaration; other identities include their artifact domain. Retrieval checks the
kind, source chunk and exact content hash. A different valid receipt for the same
block has a different identity, so serving it cannot satisfy a request for the
originally attested bytes.

The first accepted block receipt lives in block-proof storage, and its
availability row points to it. When a preferred receipt later replaces it there,
the same batch expands the row back to the exact original bytes, so the attested
source stays addressable. A later normal import compacts a matching raw row into
a receipt reference. Neither operation changes the content identity or any
signed declaration.

A rejected proof encoding matters only as the exact bytes an authenticated
precommit accepted, and anyone can fabricate rejected envelopes of a known
header. A node therefore stores and relays one only after a retained vote (live
or in reporter records) lists its identity in a proof manifest. Until then it
waits, keyed by its exact identity and never overwritten, in an in-memory buffer
of 64 envelopes and 32 MiB (oldest out first), separate from the import path's
rejection cache, so a precommit that later accepts it is still detected. The
buffer is best effort, since fabricated envelopes can flush it. The primary path
does not depend on it: a signer's node keeps the sources its own votes name as
local records, and the missing-dependency fetch retrieves named bytes once the
vote arrives. Proof-acceptance evidence carries the rejected envelope and a
canonical opening built from the retained manifest. Different complete manifests
for one chunk all stay available, and a missing manifest never establishes
rejection.

## Authentication and durable publication

Sources are checked against the locally authenticated validator context of
their chunk before retention. Value and nil votes require complete signer
coverage, individual attestations and the aggregate signature. Quorums and
pacemaker certificates authenticate their weighted membership and signatures.
The signature domain is derived locally from the full chain specification, never
selected by the source or an RPC response; a source on chunk `c` verifies under
the domain in force at `c` ([upgrades and forks](20-upgrades-and-forks.md)). A
block envelope must match its known header, state transition, historical
proposer and accepted block program before its proof verdict is considered, and
an operational verifier error never establishes an invalid-proof offence.

Proposal attribution checks the designated leader, the authenticated validator
root and the exact proposal signature. It runs before live proposal admission,
so a signed fork stays attributable even when its carried quorum or round-entry
certificate is invalid. BFT admission still checks those certificates and all
proposal policy before a proposal can influence consensus
([BFT protocol](10-bft-protocol.md)).

Locally signed messages enter durable source storage before publication, in
addition to the signing journal. Before this node publishes a proof-acceptance
attestation, every accepted receipt it references must resolve to the exact
original bytes. Sources and their dependency metadata are installed atomically.
A duplicate arrival keeps the original row and triggers no new inventory
broadcast.

Source caching has its own authority, separate from live BFT admission. A full
forensic cache can defer retention of a valid peer message while that message
continues through ordinary BFT processing. A cache entry, gossip announcement or
earlier host verdict never substitutes for the protocol's proof and signature
checks.

## Inventory and retrieval

Gossip on the `signed_artifacts` topic announces a sorted inventory of at most 32
exact references (`MAX_ARTIFACT_INVENTORY`). Peers serve two request protocols
([networking](21-networking.md)): `signed_artifact_inventory_by_chunk`, a
paginated inventory of one source chunk with an exclusive content-ID cursor, and
`signed_artifact_by_id`, one exact source. `bft_round_by_chunk` separately serves
the current signed proposal and round-change certificate needed for BFT
progress. Transport readers bound artifact envelopes, nested signature lists and
inventory counts before allocating from untrusted lengths.

The sync driver follows missing precommit receipt references and inventories for
earlier locked votes and quorums, with these bounds:

| Bound | Value |
| --- | --- |
| queued jobs | 128 |
| jobs per provider | 32 |
| concurrent requests | 4 |
| providers per job | 4 |
| attempts per provider | 3 |

Failed providers can be replaced, and exhausted hints expire after the retry
cooldown. A callback is bound to its peer connection generation, request nonce
and exact query, so an old response cannot complete a new request after a
reconnection or an authenticated bootstrap installation. Future or
unauthenticated source hints cannot move local history or its pruning boundary.

## Delayed detection

Fetched sources follow the same authentication and evidence paths as locally
observed messages. New proof bytes re-evaluate only the votes that reference
their exact identity. A newly arrived earlier vote or quorum re-evaluates the
related later votes in round order. This closes arrival-order gaps: a precommit
may arrive before its rejected proof envelope, or a conflicting prevote before
the earlier lock quorum. The original signatures stay attached to the resulting
evidence.

After a restart the node performs one authenticated replay of retained source
metadata and original signed artifacts before it resumes signing. The replay
feeds discovered offences into the persistent evidence pool, subject to the
once-per-identity safety rule of [evidence proofs](16-evidence-proofs.md#node-evidence-pool).
Steady-state observation uses dependency metadata and cached exact receipt
verdicts instead of rescanning or re-verifying every receipt after each vote.

A cached receipt verdict is bound to the exact canonical envelope identity, the
configured block program verification key and the chain-specification hash; a
backend without an explicit block program key caches nothing. The import path's
rejection cache holds at most 512 envelopes. A durable bootstrap installation
clears the verdict cache while the engine signing barrier is held and advances
its generation, so verification started before the installation cannot return
or publish a cached verdict afterwards.

The in-memory equivocation monitor turns observed headers, votes, nil votes,
proposals, prevote quorums and attestations into evidence. Outside a reporter it
is bounded and never stops observing: each map holds at most 9 × 256 × 2 × 7
entries (the nine-chunk live window, the largest committee, both phases and
seven rounds a chunk on average) and the sized maps at most 64 MiB. A full map
evicts the latest round or slot of the signer holding the most entries (for
prevote quorums, of the chunk), so a signer flooding its own rounds displaces
only itself and the earliest rounds, where locks form, stay. A reporter's durable
replay is unbounded.

## Retention

Ordinary source observation accepts the current unfinalized chunk and the eight
preceding authenticated finalized chunks. Full and validator nodes delete older
source rows below that window as local finality advances. Archive nodes can keep
and serve older sources, and old sources never widen the protocol's admission
windows. Evidence admission needs a finalized source chunk and its authenticated
opening; liveness evidence also needs one of the preceding eight chunks and its
block-age limit.

Safety evidence has no age window. Historical records keep each finalized
certificate's individual attestations for `history_record_window_chunks` (one
unbonding delay) on ordinary nodes and indefinitely on archives. This is a local
service horizon: a validator that stays staked can have signed much older
offences. A late report needs whoever retained the sources, the historical
validator context and a History opening. The conflicting side of a fork claim
often comes from the light client or bridge it was shown to; an archive or
reporter supplies old canonical material. The History commitment authenticates
that material but cannot recover it once every retaining party deleted it.
Reporter nodes retain sources selectively for accountable identities
([reporter nodes](18-reporter-nodes.md)).

The full and validator source cache has two separate budgets:

| Budget | Records | Bytes |
| --- | --- | --- |
| peer-origin records | 3,840 | 384 MiB |
| local records: this node's signed publications and the sources its votes name | 4,096 | 512 MiB |

Peer records therefore never starve the votes a validator must retain before
publishing them. Named receipts other than the preferred one are stored in full
under the local budget. A peer record this node then publishes moves to the local
budget while that budget has room and otherwise stays under the peer budget.
Accepted receipt references count their small index entry and never duplicate
the block-proof bytes. Archives apply these limits per source chunk and keep
retained superseded records; their disk provisioning is the operator's
responsibility.

Older rows not yet pruned stay durable and do not consume the active publication
quota. Chunk-prefixed metadata indexes and direct prefix seeks keep live
observation, replay and admission independent of that backlog. Pruning follows
local finality, so a stalled chunk proof stalls finality and pruning together,
and this layer claims no total disk bound while finality is stalled. The backlog
never blocks current honest BFT publication.

An unfinalized chunk can run arbitrarily many BFT rounds, and finite storage
cannot keep every message from all of them. Full and validator nodes therefore
atomically replace superseded local publication slots by source chunk, message
kind and vote phase. They keep the latest local messages, the highest actual
lock quorum, the highest valid quorum and the earlier local precommit that
established the retained lock; actual lock and proof dependencies are protected
during replacement. Honest signing can then continue after a long partition
without old round announcements consuming every local slot. Superseded
uninvolved round sources may consequently expire even inside the eight-chunk
window. These forensic limits never authorize conflicting signatures and never
gate BFT progress: the signing journals and authenticated BFT sessions are the
signing authority, and actual unfinalized locks are never discarded.

The availability guarantee is therefore: retained published sources are
durable, content-addressed and retrievable; delayed dependencies can complete
objective detection; admitted evidence reaches the mandatory FIFO while the
chain progresses. The protocol does not guarantee discovery of hidden
signatures, availability of bytes nobody published, or retention of unboundedly
many unfinalized rounds. A volunteer archive improves source availability
without changing consensus validity.

Receipt and chunk-proof retention for payment is a separate mechanism with its
own bounds (`max_receipts_per_block`), defined in [proof market](08-proof-market.md).
