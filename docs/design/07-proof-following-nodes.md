# Proof-following nodes

A block is executed once, by its producer. Every other validator, full node and
reporter verifies the producer's receipt and applies the producer's write set:
it checks every header, every receipt and every complete chunk proof and skips
only the WASM re-execution whose result the receipt already proves. The write
set travels so that state is available at slot speed without trusting anyone,
because a receiver accepts it only when it reproduces the signed state root.
Finality, History, pruning and snapshot bootstrap still require complete chunk
proofs, and the latest finalized one is the History proof.

## Publication

A producer publishes two artifacts, each accepted or rejected as one unit:

| Artifact | Topic | Sent | Contents |
| --- | --- | --- | --- |
| `CandidateBlock { block, writes }` | `blocks` | As soon as the block has executed | The signed block and the final value of every state key its execution wrote |
| `BlockReceipt { block_hash, proof_bytes }` | `receipts` | When a proof completes, by the producer or any node that proved the block | The backend receipt bytes |

Neither carries anything the header already states. Every receiver derives the
rest locally and identically: the receipt envelope (height, block hash and the
public inputs of the header under the parent's state root and the program set
of the block's chunk) and the diff record. A candidate without a receipt is a
block the network holds but does not trust; how it becomes proven, stale or
paid is specified in [the proof market](08-proof-market.md).

`ProvenBlock { block, proof_bytes, writes }` is the complete unit for a block
with a retained receipt. `BlocksByRange { head_block_hash, start_height, count
}` serves these in height order under the anchored branch and continues past
the last proven block with the candidates that follow it, so a page never
places a proven block after a candidate. `ReceiptsByHash` returns retained
receipts by block hash. There is no separate diff transport and no staging of
partial units.

## Execution mode

`[execution] mode` selects how peer blocks are imported.

| Role | Default mode | Notes |
| --- | --- | --- |
| `validator`, `full`, `reporter` | `proof_follow` | A validator still executes the blocks it produces |
| `archive` | `execute` | A genesis replay needs every historical write set, which pruned nodes do not serve, and an executing archive holds historical witnesses |
| `light-client` | none in effect | Holds no execution state; `proof_follow` is refused |

Any non-light node may set `mode = "execute"` to re-execute every block and
retain its witness. Only such a node may set `[proving] prove_foreign_blocks =
true`, which proves candidates it did not produce from those witnesses and
publishes their receipts; startup refuses the key in `proof_follow` mode. A
node with `prove_foreign_blocks` and no proposer key runs the proof loop alone.

Execution mode and proving duties are independent. Ordinary full and archive
nodes use a verification-only proof backend and generate no Fact, Evidence or
Chunk proofs. Validators generate proofs; reporters generate Evidence proofs
with any required Facts on demand. Setting `prove_foreign_blocks = true` opts a
non-validator into the prover loop, proactive Fact caching and fallback Chunk
and Evidence proving. It does not grant a validator key or signing authority.
Light clients only verify proofs.

A proof-following node still installs its WASM runtime, for production, RPC
queries, transaction admission and program authentication. Its engine runs
with `StateSource::ReceiptDiffs`: branch replay applies retained diffs, and
peer imports go through `Engine::import_candidate_block`,
`Engine::import_block_receipt` and, for range publications,
`Engine::import_proven_block`, all without an executor. An executing node
(`StateSource::Execution`) passes its executor to the same entry points.

## State diff

```rust
pub struct BlockStateDiff {
    pub height: Height,
    pub block_hash: BlockHash,
    pub state_root_before: StateRoot,
    pub state_root_after: StateRoot,
    pub writes: Vec<StateWrite>, // strictly increasing keys; value None deletes
}
```

Executing nodes record the diff during ordinary execution: the WASM host and the
native tracer keep a final-value map beside the read witness, and
`ExecutionOutcome.state_writes` carries it to the engine. Producers,
executor-equipped imports and branch replay persist it under
`Column::StateDiffs`, keyed by block hash, beside the witness; a
proof-following import persists the published writes under the locally derived
record. Retention prunes diffs with the other per-block sources.

One block's writes are at most `MAX_STATE_DIFF_BYTES` (8 MiB). Honest
production refuses to sign a block whose writes exceed it and retries with
fewer user transactions, the same policy that bounds witness and body size.

The diff is a transport artifact. It is never a consensus commitment, never
enters a Guest and never authorizes finality. Any executing node reproduces the
same writes, so availability does not depend on the producer, and a receiver
trusts no provider: it applies the writes to a scratch copy of the exact
pre-state trie and accepts them only when the resulting root equals the
header's state root. A trie root commits to the complete key/value map, so an
incomplete, reordered or forged write set cannot reproduce it. The root check
binds the writes to the signed header and nothing more; correctness of the
execution comes from the receipt.

## Import

Every import path first runs the shared header and body admission. A candidate
is then judged by mode:

- With an executor, the body is re-executed over the exact pre-state and its
  commitments are checked against the header. The published writes must equal
  the local ones or, failing that, reproduce the header's state root, which is
  the rule a proof-following node applies, so executing and following nodes
  accept the same publications. The local diff and witness are archived.
- Without an executor under `StateSource::ReceiptDiffs`, the published writes
  must reproduce the header's state root over a scratch copy of the parent
  state, which then becomes the new state.
- Without an executor under `StateSource::Execution`, the candidate is refused
  with `ImportError::ExecutorRequired`. No mode trusts a header:
  `Engine::import_block` always executes, and a node that can neither execute
  nor follow reports the block as unavailable rather than judging it.

A candidate whose execution contradicts its header while its writes still
reproduce the root is one a following node accepts. An executing node ignores
it instead of rejecting it, so no honest relayer is penalized, and proves the
honest execution for an invalid execution claim ([proof
market](08-proof-market.md)).

`Engine::import_proven_block` additionally derives the canonical public inputs
from the header and the parent's state root, verifies the receipt under the
program set of the block's chunk and checks the receipt's body-selected
execution bindings, all before any state is touched. Block, receipt and diff
are then archived in one batch with the block already `Proven`; an extending
block also publishes the new head state. A failure anywhere imports nothing.

A publication for a block the node already retains is judged by what it adds:

- the retained receipt bytes again return the head unchanged;
- other receipt bytes are verified; a rejected receipt is cached as exact
  evidence for later signed proof attestations and the publication is
  rejected, while a valid one is retained as a further receipt of a proven
  block (within the per-block bound of the proof market) and only verified for
  a finalized one;
- a retained block still awaiting its receipt admits the published one, and a
  retained block without a diff keeps the published writes once they reproduce
  its root.

## Replay

Selecting another branch replays it from retained receipts and diffs, or by
execution on an executing node: every block of the branch must be archived as
proven or finalized with a retained diff that extends the running root and
reproduces its header. Branches whose common ancestor lies below the finalized
or certified floor are refused. A replay the node cannot perform fails the
import, so the head never moves without its state.

State the node does not hold is an error, never a crash. The state trie reports
a missing or malformed node on an accessed path as `TrieError`, the host tracer
condemns the execution that hit it, the WASM host traps the run, and consensus
and RPC paths map it to an unavailable-state error. Only the SP1 Guest aborts on
an incomplete witnessed path, which is the fail-closed behaviour proving
requires.

## Transport

| Item | Bound |
| --- | --- |
| `blocks` gossip message | One candidate, at most `MAX_PROVEN_BLOCK_BYTES` (18 MiB) |
| `receipts` gossip message | One receipt, at most 2 MiB |
| `BlocksByRange` page | At most 16 entries (`MAX_BLOCKS_PER_RESPONSE`), further bounded by the response byte cap |
| `ReceiptsByHash` | At most 16 block hashes per request and 16 receipts per response |
| `WitnessByBlock` | At most 4 witnesses per request; served by any node that retains them |

A candidate whose parent is unknown locally is ignored without judgement, and
range sync fetches it. A candidate whose writes are not canonically ordered is
rejected before it reaches the backend. A receipt is relayed once it has newly
proven a block here, and so is the proposer's own receipt of a block another
receipt proved first, since selection prefers it; a receipt held for the
orphan window or otherwise already known is not relayed. A receipt crediting a
value that is not a runtime account (twelve zero bytes, then the 20-byte
address) is invalid. A header that fails signature or VRF authentication
against a successor context this node only projected is ignored, not
rejected: another candidate of the open chunk may still win and give the header
a different committee or seed ([proof market](08-proof-market.md)).

A `BlocksByRange` page lists complete publications first. From the first block
without a retained receipt it continues with candidates, and it ends where the
provider holds no write set, so a short page is partial and the requester
continues from the next height. A full node's sync machine runs from `Init` to
`Following` ([networking](21-networking.md)). Sequential complete-chunk sync
fetches a chunk's publications and then its complete proof; BFT candidate
backfill fetches the candidate branch's publications and then its certificate.
Each publication imports as it arrives, in height order, and the engine head,
finality and every index advance only through that import.

Every non-light node applies the stale rule and opens the next chunk's session
on its own slot timer, producer or not. Which blocks the proving loop picks up
(own productions, foreign candidates with `prove_foreign_blocks`, and rescue
proofs) is specified in [the proof market](08-proof-market.md).

## Failure handling

Each artifact is judged as one unit.

| Condition | Outcome |
| --- | --- |
| Header or body admission fails, writes do not reproduce the state root, or the body does not match the signed header | Candidate rejected; the source is penalized |
| Receipt fails verification under the derived public inputs | Receipt rejected; the source is penalized |
| Parent unknown locally (`ChainBehind`) | Ignored without judgement; the driver backfills |
| Candidate beyond the pending-chain bound or the unproven-candidate bound | Ignored without judgement |
| Second candidate its proposer signed for one slot | Recorded as a double proposal, then ignored unless a receipt proves it |
| Data filesystem below `[storage] min_free_bytes` | New candidates ignored ([state and storage](04-state-and-storage.md)) |

Gossip reports `Reject` for a rejected artifact, and a range provider that
served one is penalized and replaced. A receipt that arrives before its block
waits in the orphan buffer ([proof market](08-proof-market.md)). Restarting a
node loses only that buffer, which gossip and `ReceiptsByHash` refill.

## Incentives

A candidate without a receipt earns nothing: it enters no certified chunk, so
neither its fees nor any issuance for it ever finalizes. The producer is the
only node that executes the block; withholding the writes would force every
other node into the duplicated execution the protocol avoids, and a candidate
without writes is not admitted at all. Who may prove a block, how its receipt
is chosen and how proposers and provers are paid is [the proof
market](08-proof-market.md).
