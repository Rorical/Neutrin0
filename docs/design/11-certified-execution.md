# Certified execution

A complete Chunk proof takes far longer than a chunk of slots, so if each chunk
waited for its predecessor's proof the chain would stall at every boundary.
Certified execution lets exactly one successor chunk execute while its
predecessor's proof is pending, using the predecessor's natively validated
outgoing boundary as its execution input. It adds no finalization path: light
clients, History, snapshots, pruning and finalized RPC queries use only
verified Chunk receipts, the latest of which is the History proof
([recursive history](13-recursive-history.md)).

The engine code is `crates/consensus-engine/src/certified.rs` (the durable
dependency) and `crates/consensus-engine/src/projected.rs` (the projection
before a certificate exists).

## Successor boundaries

The engine's successor state is the certified one when it exists and the
projected one otherwise (`Engine::successor_state`).

A projected boundary ([proof market](08-proof-market.md)) exists once every
receipt of the predecessor's range is held and its BFT session is open: the
same native candidate validation the Chunk Guest runs yields the successor
boundary and execution context without the finality checks. The projection
follows the session's candidate, extends only the head its boundary ends in,
and is dropped by a certificate, a new candidate or finality; successor blocks
built on a losing projection are orphaned by ordinary reorganization.

A certified boundary exists once a full node has verified every predecessor
block receipt, the exact signed leader proposal, both BFT quorums with their
attestations and the complete native consensus transition. Native validation
evaluates cryptographic checks directly; unauthenticated Fact verdicts cannot
authorize it. The resulting `CertifiedExecution` (witness, outgoing state,
history record and the time it was first authenticated) is written under the
`certified_execution` key, bounded to 64 MiB, before any successor header is
signed. It is an execution dependency, never a finalized checkpoint.

The node captures owned headers, selected receipt envelopes, consensus bodies
and authenticated state witnesses under the engine lock. A bounded blocking
worker verifies receipts and native consensus after releasing that lock. Its
validation result owns the exact witness and has private fields. The commit
rechecks the trusted incoming context, seed, History frontier and stored proven
sources; local quorum work also rechecks its exact certificate identity and
bootstrap admission. Durable publication still precedes successor signing.
Cancelled callers retain their preparation slot until the blocking worker exits.
Successor projection and signing prevalidation use the same separation and
reject results from a changed boundary or session value.

Both carry the next validator vector, seed, program set, identity-sanctions
root, consumed participation and proving commitments and History frontier that
the predecessor's Chunk Guest must eventually prove. Production and import of
successor blocks use the successor boundary's committee and seed
(`Engine::production_committee`). The successor's carrier block, the first
block produced while holding the certificate, selects the predecessor's
compact certificate ([proof market](08-proof-market.md)); its branch keeps that
selection.

## Bounded window

The pipeline admits one successor chunk beyond the chunk waiting for its
proof. `Engine::execution_boundary` serves the successor boundary only for the
chunk right after the finalized one, so production that fills the successor
stops (backpressure) until proof finality advances, and
`Engine::can_extend_execution` also refuses to extend any head other than the
block the successor boundary ends in. Only the next unfinalized chunk runs BFT
and finalizes; its successor may execute and prove blocks meanwhile. Proof
throughput must still sustain the slot schedule, and the bounded window cannot
hide indefinite proof withholding or an undersized prover.

`ConsensusExecutionContext.finalized` is the authenticated incoming boundary of
the executing chunk, taken from `Engine::execution_boundary`: for the successor
chunk it is the certified or projected boundary. The successor's public inputs bind that exact boundary, and its own
chunk can finalize only after the predecessor does.

## Safety and recovery

- Certification pins the predecessor value in fork choice without moving the
  finalized anchor: the head is chosen among descendants of the certified
  boundary's block, and competing descendants can still reorganize above it.
- Proposer journals use the committee of the block's exact incoming boundary.
  BFT locks and slot reservations stay durable; no signing history is reset or
  bypassed.
- A delayed proof must reproduce the certified boundary before it can commit.
  A failed proof or storage batch leaves certification, head state and finality
  unchanged, and successful finalization keeps the descendants already
  executed.
- Restart checks the certified witness against local authenticated finality,
  stored proven blocks and the native consensus transition before enabling the
  execution context. The certificate and sources stay available so any node
  can prove the certified chunk (`Engine::prepare_certified_execution`).
- Certificates for one chunk may contain different valid quorum subsets. The
  history leaf and the outgoing boundary exclude that non-unique encoding. A
  locally started proof keeps its exact certificate identity; independently
  verified peer proofs may carry another certificate for the same value and
  boundary.
- Governance uses the program set derived from the certified post-state. Old
  and successor programs stay pinned while both are needed, and verification
  selects keys from authenticated boundaries, never from a mutable
  current-program hint.
- Historical records and openings used only for successor execution are kept
  apart from finalized history. Certification never advances pruning, reporter
  cleanup, public finalized state or History; only the verified chunk receipt
  does.
- Evidence admission authenticates the reporter's finalized opening first and
  then extends a disposable copy over the certified predecessor leaf for
  successor execution. Durable reports keep their proof-finalized anchors, and
  a certified-context opening never bypasses finalized report authentication.
- Host receipt decoding and verification contain upstream panics: host
  profiles unwind, while governed WASM artifacts and SP1 Guests keep their
  abort profiles. A verifier failure cannot establish a slashable offence.
- Snapshot installation keeps existing signing locks and never silently
  discards an outstanding certified value. A snapshot supersedes the
  dependency only when its endpoint lies beyond the certified chunk and its
  History holds exactly that chunk's context (`Engine::certified_history_context`),
  shown by the opening of the trusted boundary's leaf or by a retained recent
  record. Another context there is a conflicting finalization and is refused.
  Without this rule, a node restarted while certified with peers ahead, or
  offline past the eight-chunk window after peers pruned the chunk's proof,
  could leave the dependency only by proving the chunk itself. A dependency on
  the specification's first chunk has no opening; beyond the recent records it
  still needs an archive peer or its own proof
  ([state and storage](04-state-and-storage.md)).

## Monitoring

| Metric | Meaning |
| --- | --- |
| `neutrin0_certified_execution_height` | Height of the certified boundary; 0 when absent |
| `neutrin0_execution_ahead_blocks` | Executed blocks above complete-proof finality |
| `neutrin0_execution_certification_age_seconds` | Seconds since the pending certificate was durably authenticated; 0 when absent |
| `neutrin0_execution_backpressure` | 1 when production has filled its execution window |

They separate proof lag from a full execution window without reporting
certified blocks as finalized. A projection alone sets none of the certificate
gauges.
