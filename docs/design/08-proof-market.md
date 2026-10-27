# Proof market

Blocks are published before they are proven, proven in parallel by whoever
chooses to, and paid for after a chunk certificate fixes which receipt counts
for each height. This document specifies candidate publication and receipts,
the stale rule for blocks nobody proves, receipt and chunk-proof selection, the
carrier block that consumes a certificate, the economics that pay proposers,
provers and committees, and the invalid-execution offence. Transport and import
are in [proof-following nodes](07-proof-following-nodes.md); chunk validity is
in [chunk proofs](12-chunk-proofs.md); round leadership and pacing are in the
[BFT protocol](10-bft-protocol.md).

## Why receipts travel separately

If a block were published only with its receipt, the chain would advance at the
speed of one serial block proof: the next slot's proposer needs the parent's
post-state, and a full block takes far longer to prove than a 4 s slot. A block
receipt, however, depends only on the block's pre-state root, body and
authenticated context, never on the parent's receipt. Once the writes of block
`N` are public, the pre-state of block `N + 1` is known, and the receipts of a
chunk's blocks can be produced in parallel by different machines. Proofs must
be complete at the chunk certificate, not at block publication.

The design therefore separates state availability from state being proven:

- a candidate block is signed by its proposer, carries its write set and is
  accepted at slot speed by every node without execution;
- a block receipt proves a candidate and may come from anyone; the chunk
  certificate names exactly one receipt per height, and the runtime pays
  whoever it names.

Chunks keep fixed height ranges: chunk `k` covers heights
`k * chunk_size + 1 ..= (k + 1) * chunk_size` (`chunk_of_height`). A chunk is
certified only when every height of its range holds a proven block on one
branch. A block that is never proven is abandoned and its height produced again
on another branch, so chunk ids, evidence windows, History records and height
arithmetic stay fixed.

## Candidate blocks

`CandidateBlock { block, writes }` carries the proposer's BLS-signed,
VRF-eligible block and the write set of its execution
([proof-following nodes](07-proof-following-nodes.md)); the candidate adds no
signature. A receiver admits it in three steps:

1. header admission: parent known, slot increasing, timestamp equal to the slot
   start, signature, VRF eligibility and the body commitments, including
   `body.artifacts.commitment() == header.receipts_root`;
2. the parent is a local candidate, proven or finalized block whose state the
   node holds;
3. the writes, applied to a scratch copy of the exact parent state, reproduce
   `header.state_root`.

A candidate that fails a step is rejected whole and counted against its
source. One that passes is stored as unproven, its diff recorded and its
post-state made available. The root check proves only that the writes are the
ones the proposer signed for, not that the proposer executed correctly.

## Block receipts

`BlockReceipt { block_hash, proof_bytes }` travels on the `receipts` topic and
through `ReceiptsByHash { block_hashes }`, which returns every receipt the
provider retains for each block, its preferred receipt first. The envelope and
public inputs are derived locally, and the receipt is verified under the
program set of the block chunk's start boundary.

The Block Guest commits its output together with the account the prover names:

```rust
pub struct BlockReceiptStatement {
    pub output: RuntimeBlockOutput,
    pub prover_address: [u8; 32], // runtime account paid for this receipt
}
```

The verifier accepts any value of `prover_address` that is a runtime account:
twelve zero bytes, then the 20-byte Ethereum address. The same rule applies to
a chunk proof's `chunk_prover_address` and an evidence statement's reporter.
The runtime pays nothing to any other value, so receipt import, the Chunk
Guest's receipt choices and ratification, the Evidence Guest and node
configuration all refuse one.

The statement key of a receipt is the commitment of its complete public
values. Every proof of the same statement has the same key, so re-running the
last proving stage cannot produce a new key, and a distinct key costs a
distinct complete proof. Two valid receipts for one block with different
attribution are two statements.

### Retention

A node retains at most `max_receipts_per_block` distinct valid statements per
block: the receipt attributed to the block's proposer whenever it holds one,
then the others in the order it first verified them. Beyond that bound it keeps
every receipt that a value still needs: any receipt an open session's
proposal, valid value or known selection names, the certified execution's
receipts, and those of an authenticated proposal or verified certificate whose
receipts it is still fetching. Evicting one would leave a value nobody can vote
for or prove. Every other receipt is verified, counted for accountability and
discarded. Each retained receipt records the local slot at which the node first
verified it. The same bound applies to valid proofs of a finalized chunk kept
for ratification, with the node's own proofs kept first.

A receipt for a block the node does not hold yet waits in a bounded orphan
buffer, with the peer it came from, for `proof_orphan_slots`. The buffer holds
at most 256 receipts and 32 MiB, one receipt per source per block and at most
`max_receipts_per_block` per block, none replacing another; one source holds at
most 16, and the caps evict from the source holding the most first, so no peer
can displace an honest receipt or flush the buffer. A receipt that fails
verification is rejected and counted against its source: a gossiped one at
once, a buffered one once its block arrives, after which that source's orphans
are refused for thirty minutes.

A candidate and its diff are retained until the block finalizes or is
abandoned; an abandoned block's records are deleted with the stale rule below.
Valid receipts that were not selected are deleted when their block's chunk
finalizes. Selected receipts, diffs and witnesses then follow ordinary
retention ([state and storage](04-state-and-storage.md)).

### Witness availability

A third-party prover needs the complete proving input, not only the writes.
Two paths exist: `WitnessByBlock { block_hashes }`, served by any node that
retains the witness (the producer and every node in `mode = "execute"`), at
most four per request and bounded by `max_block_proving_input_bytes`; and
re-execution by any executing node that holds the pre-state. A proposer that
withholds its witness gains nothing, because executing provers rebuild it. The
witness is never a consensus object. A node proving foreign candidates uses its
own retained witnesses, which is why `[proving] prove_foreign_blocks` requires
`mode = "execute"`.

## Block states and heads

Every block a node holds is in one state:

```text
Candidate  --receipt-->  Proven  --certificate + chunk proof-->  Finalized
```

A block never moves backwards. A stale candidate is a candidate that fork
choice excludes; a valid receipt for it still makes it `Proven`.

| Head | Definition | Served as |
| --- | --- | --- |
| Pending head | Tip of the candidate chain the node follows | RPC `latest`, `eth_blockNumber`, `chain_head`, numeric heights; mempool nonce queues; production |
| Proven head | Highest block whose every ancestor since finality is `Proven` | RPC `safe` |
| Finalized head | End of the latest chunk finalized by its complete proof | RPC `finalized` |

Ethereum `pending` is a simulated block above the pending head. On a following
node `latest` is signed and root-reproducing but not yet proven; `safe` is the
proven state. A block prover builds on any candidate with a known pre-state,
and a chunk leader proposes the branch whose chunk range is completely proven.
Light clients, snapshots and bootstrap never see candidate state: snapshots
install only finalized state, and the pending chain is rebuilt from
publications after bootstrap.

The pending chain is bounded. A node refuses a candidate more than
`2 * chunk_size` heights above the finalized head (the chunk awaiting its
certificate and proof plus the chunk being produced, the bounded pipeline of
[certified execution](11-certified-execution.md)). Within that bound fork
choice ranks branches by chunk-vote score, then by proven prefix (the height of
the highest block whose every ancestor down to finality is proven), then by
height and the VRF tie-breaker. A proven branch outranks a taller unproven one,
so honest proposers stop piling blocks on a candidate its proposer is not
proving. Receipt arrival order does not otherwise move fork choice; the stale
rule is the other input.

## Stale candidates

A candidate nobody proves is the one way the pending chain can cost
throughput, since every block built on it is abandoned with it. The stale rule,
rescue proving, the proposer lease of rule P and the abandonment penalty bound
that cost.

A candidate is stale when `proof_exclusive_slots` have passed since its stale
clock and the node holds no valid receipt for it. The stale clock is the
block's slot, lowered to the earliest slot among unproven siblings on the same
parent: a later sibling inherits the window of the first block at its height,
so a proposer cannot restart the window by signing another candidate for a
height it already holds unproven. Every non-light node applies the rule on its
own slot timer, producer or not, so fork choice, RPC heads and mempool queues
leave an abandoned branch everywhere.

A proposer never extends a branch through a stale candidate. It builds on the
highest block of that branch below the oldest stale candidate, which is proven
or a younger candidate, and produces the stale block's height again. The
abandoned suffix is at most `proof_exclusive_slots` blocks whatever the chunk
size, and its transactions return to the mempool as ordinary unconfirmed
transactions.

Staleness is a local judgement, so two proposers may briefly disagree and
produce siblings; fork choice and finally the chunk certificate resolve that
like any multi-proposer slot. A valid receipt for a stale candidate that
arrives before the candidate is deleted restores it: the block becomes `Proven`
and fork choice judges its branch again, so nodes that saw the receipt at
different times converge instead of splitting on their timers. A receipt that
contradicts the header still yields an invalid execution claim. One more
exclusive window after the candidate went stale, it is deleted with its
descendants, bodies, diffs, witnesses and post-states. A certified chunk that
still contains such a block brings it back through complete-chunk sync with its
proof. When a candidate goes stale, the node keeps its header, and that of
every stale candidate whose parent is not stale, under `AbandonedHeaders` until
the height leaves the liveness evidence window.

### Rescue proving

A node with an executor and `[proving] rescue_unproven_blocks` (default: on for
the CUDA backend only, since a CPU prover cannot finish before the block goes
stale) proves a head-branch block whose proposer has published no receipt once
the proposer's lease has passed since the block's slot, plus a stagger of zero
or four slots drawn from the block hash and the node's key so rescuers mostly
do not duplicate work. It rebuilds the witness on demand and rescues at most
one block per pass. A rescue receipt keeps the block from going stale; it
becomes selectable under rule L when the exclusive window closes.

### Abandonment penalty

A proposer whose signed block the canonical chain replaced after the exclusive
window pays the governed `abandonment_penalty_amount`. The offence is
objective: the Evidence Guest checks the proposer's signature on header `H`,
an opening of the canonical block `F` at `H.height` in the finalized chunk's
`block_hash_root`, `H.parent_hash == F.parent_hash`, `H != F` and
`F.slot >= H.slot + proof_exclusive_slots`. Only the deepest abandoned block is
charged, because a block built on an abandoned parent does not share the
canonical parent. A block replaced inside the window, or one proven and then
outranked, establishes nothing. The offence is a liveness class
(`SanctionKind::Abandonment`) with identity `penalty_id(10, validator, H.slot,
0)`, admitted once within the liveness evidence window, its replay marker swept
like inactivity's ([evidence proofs](16-evidence-proofs.md)). Nodes detect it
once the chunk holding `H.height` finalizes, from the headers their slashing
monitor observed and the abandoned headers they keep. A leader that finalizes a
different complete proven branch could charge an honest proposer whose block
was proven, but only by producing every height after `F` on that branch from
its own coalition's eligible slots within the chunk's rounds.

### Issuance cap

A block accrues issuance for at most `MAX_ACCRUAL_SLOTS = 8` slots since the
previous executed block; a longer gap mints only eight slots' worth. The block
that replaces an abandoned height earns no windfall for the slots the height
waited.

The stale rule also bounds a block too slow to prove, such as one filled with
software-precompile work far beyond any prover's window: its proposer forfeits
that slot's rewards and pays the abandonment penalty, the chain loses at most
`proof_exclusive_slots` slots of other proposers' work, and the height is
produced again. Pricing such work correctly in gas is the remaining defence.
No block is unprovable by construction, because the runtime's transition is
total (see "Invalid execution claim").

## Chunk assembly

A chunk's candidate value is a branch on which every height of the chunk's
range holds a block proven for chunk purposes: it has a receipt the selection
rule may name at the proposal's slot. A proven block whose parent is only a
candidate does not complete a range, because its receipt proves execution from
a pre-state nothing has established yet.

The round leader proposes as soon as its followed branch completes the range.
There is no partial proposal and no deadline other than the stale rule: a
height whose block stays unproven is produced again, and the chunk closes when
the range is complete. Round deadlines then follow the [BFT
protocol](10-bft-protocol.md).

Each proposal carries `proposal_slot`, the leader's wall-clock slot but never
below the slot of the range's last block, signed with the rest of the proposal.
Voters refuse a proposal whose `proposal_slot` is below the slot of the range's
last block or ahead of their own clock by more than the header timestamp drift
(`MAX_CLOCK_DRIFT_SECS`, 60 s). The Chunk Guest reads it to evaluate the
exclusive window.

Re-chunking cannot shorten a stall: a block executed under chunk `N`'s start
boundary cannot join chunk `N + 1`, because its receipt binds that boundary.

### The pause between chunks

The first block of chunk `N + 1` executes under chunk `N`'s end boundary. If
that boundary existed only once `N`'s certificate fixed the participation and
proving reports, production would pause between `N`'s last block and its
certificate, for the proof latency of the last block plus the BFT round. The
carrier rule below takes the BFT round off that path; the last block's proof
latency stays on it.

The remaining pause is visible in local stage metrics, measured from the start
of the chunk's last slot: `neutrin0_chunk_tail_ready` (session opening, which
needs every block proof of the chunk), `neutrin0_bft_certificate` (opening to
certificate), `neutrin0_chunk_certificate_lag` (slot start to certificate),
`neutrin0_chunk_certificate_stall` (certificate past the slot end) and
`neutrin0_chunk_finality_lag`, so the proof term and the BFT term can be told
apart.

A chunk proof takes minutes and cannot be preempted, while production waits on
block proofs. With `[proving] prioritize_block_proofs` (default on) a node
starts a chunk proof only once it has no block proof pending, waiting at most
one slot after the certificate, so a single proving worker never holds the
receipt production needs behind a chunk proof. The pause can be shortened
further by shaping a chunk's last heights cheap (for example a lower gas
ceiling, so the critical proof is an empty-block proof of a few seconds), by a
longer chunk that dilutes a fixed pause, or by a prover that shards one proof
across several GPUs.

## Receipt selection

For each block of the range the proposal names one `ReceiptChoice {
prover_address, statement_key }`, and precommit attestations pin the complete
list through the proof manifests. The key commits the prover address, so the
pair is redundant for a voter holding the receipt; it travels so the chunk
consuming the certificate can attribute the block without the receipt. The
leader applies, and every voter checks, this rule over the set `R(b)` of valid
receipts held for block `b`:

```text
select(b, R, proposal_slot):
  if the proposer's receipt r is in R and has priority      -> r        (rule P)
  else if proposal_slot < b.slot + proof_exclusive_slots    -> the proposer's
                                                               receipt if held,
                                                               else none (rule W)
  else if R is empty                                        -> none
  else any r in R                                           -> r        (rule L)
```

The proposer's receipt is the one whose `prover_address` equals the block's
`proposer_address`, the withdrawal account of the proposing seat. It counts as
the proposer's whoever computed it: a proposer may have a proving pool prove
for it, and a stranger who attributes a receipt to the proposer only pays the
proposer.

- **Rule P.** The proposer's receipt wins while it has priority: the node first
  verified it within the lease, `proof_exclusive_slots / 2` slots after the
  block's slot, or no later than every other receipt held for the block. A
  leader applies the comparison exactly; a voter allows two slots of tolerance
  for clock differences. The proposer is the only party that executed the
  block and the only one holding the witness at publication, so its receipt is
  the cheapest proof the network can get. A faster third-party receipt inside
  the lease marks the block proven but does not cancel the proposer's proof:
  the proposer keeps proving, stores its receipt as the preferred one and
  publishes it, and peers relay it as the proposer's receipt of a block another
  receipt proved first, so a third party cannot front-run the proposer's
  payment or hold the chunk until the window closes. After the lease, rescuers
  prove the block, and a proposer receipt arriving after theirs does not win.
- **Rule W.** During the exclusive window only the proposer's receipt is
  selectable. A third-party receipt that arrives inside the window still keeps
  the block from going stale and becomes selectable when the window closes, so
  completing a range waits at most for the window of its youngest block.
- **Rule L.** After the window the leader names any valid receipt it holds: the
  one attributed to its own node's `prover_address` when it holds one,
  otherwise the one it verified first. Voters do not rank third-party receipts
  against each other. There is no key order, lottery or settle time, so a
  receipt that reaches a voter late can never invalidate a proposal, and a
  second complete proof of a block that already has one earns nothing.

The node's `[proving] prover_address` defaults to the validator's withdrawal
credentials; with neither, its receipts credit the block's proposer.

## Voter refusals

A voter refuses to prevote and precommit a proposal that breaks one of these
rules (`check_receipt_selection`):

1. A named receipt the voter does not hold is unavailable, and staying
   unavailable through the phase deadline is a nil vote. A choice whose
   `prover_address` differs from the attribution of the held receipt with that
   key is invalid. A voter lacking a named receipt keeps the proposal, requests
   `ReceiptsByHash` for those blocks from the peer that relayed it (which holds
   what it relayed) and retries.
2. A third-party receipt named for a block whose proposer receipt the voter
   held before the proposal arrived, with priority over the named receipt, is
   invalid under rule P.
3. A third-party receipt named inside the exclusive window is invalid under rule
   W, measured on the lower of the signed `proposal_slot` and the voter's own
   slot at arrival, so the drift allowance on `proposal_slot` cannot shorten
   the proposer's window.
4. A ratification entry naming a chunk proof the voter does not hold is
   unavailable, a nil vote if it stays so through the phase deadline; an entry
   whose prover or certificate commitment differs from the held proof with that
   key is invalid. The voter fetches a missing proof with `ChunkProofById {
   chunk_ids, statement_keys }`, whose keys select the retained proof of each
   chunk with that key, canonical or alternative; empty keys request the
   canonical proofs.

The timing qualifier in refusal 2 keeps a late receipt from invalidating a
proposal made in good faith. "Held before" is measured on the voter's clock: a
node records the local slot at which it first verified each receipt and chunk
proof, and a proposal's arrival slot is local too, so the offset between clocks
cancels. A proposal deferred under refusal 1 or 4 keeps the slot it first
arrived in, and its retry is judged as of that slot.

A justified re-proposal (one carrying a valid quorum) reproduces the selection
its quorum signed. Voters apply availability, attribution, rule W and the exact
ratification check to it, all of which the signed values decide, but not
refusal 2: that compares against holdings that may have changed since the
quorum formed, and refusing on it could stall a round the protocol must be able
to finish.

A leader can still omit a proposer receipt it claims never to have seen.
Refusal 2 makes that costly only when the leader can also keep two thirds of
the voters from seeing the proposer's receipt, which is the standard
assumption. Leadership rotates every round, so a persistent omission requires a
persistent collusion of the quorum.

## Votes sign the selection

A value vote signs `FinalityVoteData { chunk_id, round, chunk_hash, selection,
phase }`, where `selection` is the commitment of the proposal's
`proposal_slot`, `receipts` and `ratified_chunk_proofs` under
`DOMAIN_SELECTION`. The BFT value is the chunk with its selection: a vote for
the same chunk with another selection is a vote for another value, so locks,
unlocks, valid values, the double-vote rule and the round-change rank compare
both. Two certificates of one chunk from different rounds cannot reuse one
quorum for different payment choices, and a leader that signs two proposals
for one round splits its voters between two values instead of letting a
carrier pick a proposal they never saw.

A node signs no value before the round's proposal fixes the selection; without
one it signs nil. Peer value votes that arrive first are authenticated once and
held per selection, at most four selections per phase
(`MAX_PENDING_SELECTIONS`). A full set yields its weakest selection to a
verified vote that outweighs it, so a few colluding signers voting bogus
selections cannot crowd out honest votes that arrive before the proposal is
validated, and one signer behind several selections double-votes, which is
slashable. When the proposal arrives only the votes for its selection count and
the rest are discarded; a prevote quorum among held votes is lock evidence all
the same. Nodes keep the selection with every retained valid value and pass it
in availability hints next to the justification, which must commit to it.
Long-range fork evidence stays chunk-based, since it concerns finalized chunks,
not payment.

## Chunk Guest checks

The Chunk Guest verifies every receipt the certificate names and checks every
selection rule its inputs decide: each choice names the verified receipt of its
height with that statement key and a runtime-account prover; rule W holds from
`proposal_slot`, the block slots and `proof_exclusive_slots`; `proposal_slot`
is not below the range's last slot; and the ratification is exactly the
previous chunk's proof. Rule P compares the named receipt against receipts the
certificate does not carry, so the voters enforce it under the two-thirds
assumption; rule L leaves the choice to the leader. A leader naming a
third-party receipt inside the window produces a certificate the Guest refuses,
so the chunk cannot finalize under it; that is a round liveness failure handled
by round change, not a slashable offence.

## Proving report

A chunk derives the previous chunk's `ProvingReport` from the certificate it
carries, exactly where it derives the previous chunk's `ParticipationReport`:

```rust
pub struct ProvingReport {
    pub chunk_id: u64,
    pub entries: Vec<ProvingEntry>,       // one per height, in order
    pub committee: Vec<(Hash, u128)>,     // withdrawal account and effective
                                          // stake of every positively weighted
                                          // validator of that chunk
    pub chunk_provers: Vec<(u64, Hash)>,  // the chunk proof the certificate ratified
}
pub struct ProvingEntry { pub height: u64, pub prover: Hash }
```

A report cannot be emitted by the chunk it describes. Two certificates of one
chunk may differ in their signers, and every node must derive the same boundary
and History whichever certificate it finalized with. The report is therefore
fixed where a later block selects one certificate in committed data. The carrier
lane holds:

```rust
pub struct CarriedCertificate {
    pub quorum: QuorumCertificate,  // the precommit quorum
    pub proposal: CompactProposal,  // the certificate's leader proposal
}
pub struct CompactProposal {
    pub round: u32,
    pub proposer_index: u32,
    pub valid_quorum: Option<Hash>,             // commitments, not the bodies
    pub round_change_certificate: Option<Hash>,
    pub proposal_slot: u64,
    pub receipts: Vec<ReceiptChoice>,
    pub ratified_chunk_proofs: Vec<ChunkRatification>,
    pub signature: BlsSignature,
}
```

The compact proposal omits the chunk, which the previous chunk's History record
supplies, and replaces the valid quorum and round-change certificate by the
commitments the proposal signature covers, so the leader's signature verifies
over the same bytes. The Guest checks the quorum against that History record,
checks that the proposal names the quorum's round, that its selection
commitment is the one the quorum signed and that the round's designated leader
of the recorded committee signed it, and derives the report: `entries` from the
receipt choices in height order, `committee` from the recorded validators, and
`chunk_provers` from the ratification. Derivation fails unless the choices
cover every height. For a hard fork's first chunk, which ratifies nothing,
`chunk_provers` names the predecessor's endpoint prover the specification pins
([upgrades and forks](20-upgrades-and-forks.md)). The proposer needs no entry:
it keeps its block's tips at execution and is owed nothing at settlement.

The quorum's signatures bind the carried choices, since every vote signed the
selection the Guest recomputes from the compact proposal. A leader that signs
two proposals for one round with the same chunk still commits a
`DoubleBftProposal` offence, but at most one of the two values gathers a quorum,
and the carried proposal is the one that quorum signed. The report names the
whole committee; the runtime pays the committee share only to members whose
precommit the carried certificate holds, which the participation report of the
same certificate lists.

The report's commitment travels in the outgoing `ConsensusBoundary` as
`proving`, next to `participation`, with the same meaning: the latest report
consumed by the chunk ending there. The boundary carries no ratification count
and no link to the previous boundary: which proof a certificate ratifies
follows from its chunk id and the specification's first chunk, and recursion
places a ratified proof's start. The boundary is 409 Borsh bytes, 449 while it
carries a scheduled hard fork.

## Chunk proof ratification

A chunk proof's content is fixed by its certificate, so delegating it changes
nothing about safety. The Chunk Guest commits `ChunkReceiptStatement {
statement, chunk_prover_address }`, reading the address from its input after
the witness, so `chunk_prover_address` is a public value outside the
`ConsensusStatement`. The `ChunkProof` names the address so a receiver can
rebuild the public values. The address is not part of the chunk hash, the end
boundary or the History leaf: two proofs of one certificate with different
provers finalize the same chunk, prove the same History and leave every node
with the same boundary. Only payment needs one of them chosen.

Payment is settled by ratification in a later certificate. A chunk proof's
statement key is the commitment of its complete public values, prover address
included. There is no designated chunk prover and no ranking: the leader of
chunk `N` names any valid proof of `N - 1` it holds, its own node's whenever it
holds one and otherwise the one it verified first.

```text
select_chunk_proof(N, P):
  any p in P                                                  (rule L')
```

Every proposal carries `ratified_chunk_proofs`: empty for the specification's
first chunk (genesis or a hard fork's start), and for any later chunk `N`
exactly one `ChunkRatification { chunk_id: N - 1, prover_address,
finality_cert_hash, statement_key }`. Nodes may finalize a chunk under different
valid certificates, and a chunk proof's statement names the one it was proven
under; the entry carries that certificate's commitment so every node rebuilds
the exact statement from its stored boundaries and the chunk commitment and
checks it against the key. A proposal of chunk `N` whose ratification is not
exactly chunk `N - 1` is refused by the voters and by the Chunk Guest. A session
for chunk `N` opens only once `N - 1` has finalized, and finality takes a chunk
proof, so every honest leader and voter already holds one: ratification adds no
wait.

The Chunk Guest of `N` verifies the ratified proof itself. Its witness carries
the proof's `ChunkReceiptStatement`, which must have the entry's statement key
and prover, name this chain and chunk `N - 1` and end exactly at `N`'s incoming
boundary; the guest program then verifies the proof recursively under the
specification's Chunk Guest, after the block and fact receipts. The ratified
proof verified its own predecessor the same way, back to the specification's
first boundary, so a valid proof ending at `N`'s start proves that start, and
the verification rules out a statement key no proof has. A leader naming a
fabricated key or another chunk's proof cannot get its certificate proven.
Because the first chunk starts at the specification's first boundary, every
chunk receipt proves the whole chain from there: the latest finalized receipt
is the History proof, and the work the market pays for is the chain's only
History proving ([recursive history](13-recursive-history.md)).

For the carried certificate of the previous chunk, the Guest checks the same
exact shape from that certificate's chunk id and copies the entry's `(chunk_id,
prover_address)` into the derived report's `chunk_provers`. The prover of chunk
`N - 1` is paid at the carrier of chunk `N + 1`, which settles chunk `N`'s
report.

Ratification never changes a chunk's finality, boundary or History; it only
decides who is paid. A proof that is never ratified finalizes the chunk all the
same. Nodes retain valid proofs of a finalized chunk made under any valid
certificate of it, so a voter that finalized under another certificate can
still hold, fetch and check the named proof; it fetches the proof by key before
voting and before proving. A proof of an already finalized chunk that arrives
on the `chunk_proofs` topic, or that a local prover completes after another
proof finalized the chunk, is verified against the node's stored boundaries
under the certificate it names (whose quorum must be authentic for the chunk's
committee), retained within the per-chunk bound and propagated on the
`chunk_proofs` topic. Proofs of chunks whose ratification has already passed
(below the finalized chunk minus one) are ignored, and each peer has a bounded
number of such verifications per chunk. A snapshot carries the provider's History proof of
its anchor, whose statement holds the start boundary of the anchor's last chunk,
so a freshly bootstrapped node rebuilds the first ratified statement as well.

Chunk proving is a validator duty with a default. The node of the round-0
leader of chunk `N + 1`, under the committee `N`'s certificate seats, starts the
proof of chunk `N` as soon as the certificate exists, since it will name a proof
of `N` and names its own first. Every other validator proves after
`[proving] chunk_proof_fallback_secs` (default 180 s) from the durable round
start, and any node may publish a chunk proof. If round 0 of `N + 1` fails, the
later round's leader names whatever valid proof it holds. Validators need no
hardware beyond verification.

## Carrier rule

The successor's execution context does not need chunk `N`'s certificate. Its
finalized boundary is a function of chunk `N`'s blocks and end state alone:
`validate_candidate` derives the next seed by folding the chunk's VRF proofs,
the next committee from the rotation records, the program set from the
scheduled-upgrade record, the identity-sanctions root from the chunk, the
History root by appending the chunk's `EvidenceContext` (chunk hash, committee,
seed, programs and start boundary, no certificate) to the frontier, and
`participation` and `proving` from what the chunk's carrier consumed. The
certificate enters chunk `N + 1` through one channel, the body lane
`participation: Option<CarriedCertificate>`, verified against chunk `N`'s
History record. Only the lane's position within the chunk is free, and the
carrier rule fixes it.

**Carrier rule.** In every chunk after chunk 0, exactly one block carries the
previous chunk's compact precommit certificate; a hard fork's first chunk
carries its predecessor's last, whose proof it does not ratify. The carrier is
the first block its proposer produces while holding the certificate; blocks
before it carry none. The chunk's last height is the objective deadline: a last
block without a carrier when none preceded it is invalid, a second carrier is
invalid, and a range without a carrier is refused by the Chunk Guest. Carrying
is not rewarded; withholding gains nothing and costs the last proposer its slot.

Runtime binding. Blocks before the carrier execute with no carried report:
`apply_participation` and `apply_proving` leave the stored reports unchanged,
and the block commits the commitments of the latest reports in state, which are
the start boundary's `participation` and `proving`. The carrier and every block
after it commit the commitments of the newly consumed reports, and the carrier
settles the proving report. The boundary fields `participation` and `proving`
are read from the carrier's output. The runtime receives both reports
(`RuntimeBlockInput.proving` for the proving report); they are
consensus-authenticated data, and the economics that consume them live in the
runtime.

Participation selection. An honest producer carries the precommit quorum of the
certificate in its finalized record of the previous chunk; any quorum of the
committee that signed the certified selection is valid, and the participation
report lists exactly the signers of the carried quorum, which alone share the
committee fee (case 28). A precommit the carried quorum omits can still
acknowledge its signer through the vote lane: a block's participation
acknowledgements ([block format](05-block-format.md)) are authenticated against
their historical source chunk, at most once per seat per chunk, enter the
block's execution inputs through `inputs_root`, and record the identity as
acknowledged for that chunk, which keeps it clear of an inactivity sanction but
earns no committee share. Inactivity evidence is in [evidence
proofs](16-evidence-proofs.md).

Chunk Guest. The Guest checks that exactly one body in the range carries a
certificate (none in chunk 0), that the carried quorum and proposal verify
against the previous chunk's History record and chunk hash, that every block
before the carrier commits the start boundary's `participation` and `proving`
and the carrier and every later block the commitments derived from the carried
certificate, and that the end boundary carries the derived commitments.

Engine. Production of a chunk's first height does not require the previous
chunk's record. The engine builds a projected boundary for the successor from
the predecessor's blocks (`validate_candidate`'s next context without the
certificate, in `projected.rs`) and signs successor headers under it exactly as
it signs them under the certified boundary
([certified execution](11-certified-execution.md)). If the certificate
finalizes a different branch of the predecessor, successor blocks built on the
losing branch are orphaned by ordinary reorganization and the engine rebuilds
the projection from the certified end. The producer attaches the certificate to
the first block it produces after holding it and refuses to sign a chunk's last
block without one when none was carried.

The projection needs the predecessor's block outputs, since the
identity-sanctions root and the reports its carrier selected come from them and
not from headers or diffs. A proof-following node holds those outputs only
through receipts, so it projects when its BFT session for the predecessor
opens, once every receipt of the range is held, and the producer retries the
projection each slot. The projection follows the session's candidate; a move to
another candidate, a certificate or finality replaces it, and production only
extends the head the projected boundary ends in. A header that fails
authentication against a projected context is ignored, not rejected
([proof-following nodes](07-proof-following-nodes.md)).

What waits for what. Production of `N + 1` starts when `N`'s last receipt is
held; an executing producer could start at `N`'s last block, but its successor
is admitted by proof-following nodes only once they project. Block proofs of
`N + 1` start when the diffs are known. `N + 1`'s BFT waits for `N`'s finality,
as finality is sequential. Settlement of `N`'s proving report and the
inactivity accounting of `N`'s participation report wait for the carrier, at
most one chunk of blocks. The liveness evidence schedule reserves two chunks
after a report's chunk for signature challenges and admits at the third, and a
report consumed by the end of the following chunk precedes that admission
([evidence proofs](16-evidence-proofs.md)). Committee, seed, programs,
sanctions, randomness exposure and History are not delayed by a single slot.

Carrier cases:

- The certificate is available when the first block is produced: the first
  block carries it.
- The certificate arrives mid-chunk: the next produced block carries it;
  earlier blocks are unaffected.
- The certificate is still absent at the chunk's last height: the last block
  waits for it, moving the pause from the start of the chunk to its end, where
  it is normally zero because `N + 1`'s own BFT needs `N` finalized anyway.
- A proposer carries a wrong or foreign certificate: block admission refuses
  it, and the height is produced again.
- A second block carries a certificate on the same branch: block admission
  refuses it.
- Chunk 1 carries chunk 0's certificate under the same rule; chunk 0 carries
  none.

## Economics

Every amount below is runtime policy under `runtime:policy`, seeded from the
chain specification and changed only by governance after the policy delay
([upgrades and forks](20-upgrades-and-forks.md)). The consensus Guests carry
attribution and never compute a payment.

### Sources and recipients

| Source | Amount | Recipient |
| --- | --- | --- |
| Priority fees | Every tip the block's transactions paid | The block's proposer, at execution |
| Base fees | Every base fee the block's transactions paid | `chunk_prover_fee_bps` to the prover of the block's chunk; the rest to the chunk's participating committee by stake |
| Issuance | `annual_issuance_bps` of total stake per year, accrued per block over the time since the previous block | Half to the prover of the block's selected receipt, half to the prover of its chunk |

The proposer keeps the tips, as an Ethereum proposer does, and nothing else.
The tip is what senders offer for inclusion, and it pays the proposer for
building and, by default, proving its own block. The base fee is not burned but
leaves the proposer entirely, so a proposer that pays base fee on its own
transactions to move the market recovers none of it, and the fee market stays
incentive-compatible as under EIP-1559. The base fee pays the verification
every block needs, the chunk proof covering it and the committee certifying it,
and both shares grow with load. Issuance is a yearly staking yield paid for
proving: the same total per year whatever the slot length, chunk size or load,
and nothing is minted in proportion to gas. Half pays block provers, so a block
without fees is still worth proving.

### Escrow at execution

`COINBASE` is the proposer and receives each transaction's tip during
execution. At block end the runtime records under `escrow:fees:<height>` what
the block owes, under the policy in force when it executes:

```text
elapsed      = timestamp - previous block's timestamp        (0 for the first block)
               if more than MAX_ACCRUAL_SLOTS slots passed:
               elapsed / slots * MAX_ACCRUAL_SLOTS
issued       = total_stake * annual_issuance_bps / 10_000
               * min(elapsed, one year) / one year           (one year = 365.25 days)
chunk_fees   = base_fees * chunk_prover_fee_bps / 10_000
block_prover = issued / 2
chunk_prover = chunk_fees + (issued - block_prover)
committee    = base_fees - chunk_fees
```

`total_stake` is the sum of the stakes in the runtime's consensus-candidate
record. The base fee leaves the senders at execution and nothing is minted
then; the amounts exist again only at settlement. A later policy change never
reprices a block that has executed.

### Settlement

At the consuming block of chunk `N`'s reports (its carrier in chunk `N + 1`),
the mandatory phase settles the certified report:

```text
for entry in report.entries:
    (committee, chunk_prover, block_prover) = escrow:fees:<entry.height>
    pay block_prover to entry.prover
    committee_total += committee
    chunk_total     += chunk_prover
    delete escrow:fees:<entry.height>
present = precommit signers of the same certificate (its ParticipationReport)
pay committee_total to report.committee ∩ present, pro rata by stake
add chunk_total to escrow:chunk:<N>
for (chunk, prover) in report.chunk_provers:
    pay escrow:chunk:<chunk> to prover
    delete escrow:chunk:<chunk>
```

A report ratifies the chunk before its own, so the escrow of every ratified
chunk exists when it is paid: chunk `N - 1`'s share is escrowed at the
consuming block of `N - 1`'s report and paid at the consuming block of `N`'s.
Only the first block that consumes a report settles it, and each payment costs
mandatory gas.

The committee is paid for signing. A member whose precommit the carried
certificate does not hold receives nothing for the chunk, and its share is
divided among the signers by stake rather than burned; with no signer in the
committee the share is not issued. The carrier chooses which quorum of the
signatures it holds to carry, so it can leave out signers beyond the two thirds
it needs and raise the others' shares; it gains only its own stake's part of
that redistribution and cannot exclude a quorum. Weighting by stake rather than
by seat removes any reason to split stake across seats.

An abandoned block never finalizes, so neither its tips nor its escrow exists
in finalized state and there is nothing to settle.

### Who is paid, and why there is no bid

A bid would hand the proof market to seat holders: if each receipt offered a
share of its reward to the chunk and the highest offer won, a validator that
also proves would recover its own weight's share of whatever it offers while an
outside prover recovers nothing, so it could always outbid an outsider at no
cost. A lottery over statement keys pays provers to duplicate work, since every
extra complete proof buys another ticket, and needs a settle window in which a
late ticket can stall a round. Selection therefore has no price and no ticket:

- Rule P comes first. The proposer executed the block and holds the witness; if
  it proves within its priority, nobody else is named.
- After the window the leader names any valid receipt and prefers its own
  node's. A third party is paid exactly when neither the proposer nor the
  leader's prover proved the block in time, and a second proof earns nothing.
  Leadership is drawn by stake every round, so the leader's preference spreads
  the unproven blocks' block-prover issuance among proving validators in
  proportion to the rounds they lead.
- The committee share comes from the base fee, not from any prover's reward, so
  no member gains from the selection, and a prover that holds a seat keeps
  exactly what an outside prover keeps for the same proof.

Chunk proofs follow the same shape: the next chunk's round-0 leader proves by
default and names its own proof, so a seat earns chunk-prover pay in proportion
to the round-0 leaderships it holds, which follow stake, as long as it proves;
another validator or an outside prover earns it when that duty is neglected.
What remains is rule P and the leader's preference for its own proofs after the
window, both bounded by the window, and economies of scale in proving hardware,
which the protocol does not create.

### Why the proposer proves its own blocks

The proposer has the witness and starts first. When rule P selects its receipt
it earns the block-prover half of the block's issuance on top of its tips. If
it is slow past its lease, a rescuer's receipt may be named and that prover
takes the issuance while the proposer keeps its tips. If the block is never
proven it goes stale and the proposer keeps nothing, tips included. Losing the
tips alone would leave abandonment free: a proposer could hold a height for a
whole window and have every honest block built on it discarded. The absence of
a receipt cannot be proven, but its consequence can, which the abandonment
penalty charges.

### Inflation control

Issuance over any period is `annual_issuance_bps` of total stake per year,
accrued between consecutive block timestamps of the finalized chain over at
most `MAX_ACCRUAL_SLOTS` slots per block. It accrues by time, not by block
count, so a short run of missed slots neither loses nor duplicates issuance,
and an abandoned block's accrual never reaches finalized state. Every policy
field, the proof-market shares included, is set by governance through the Borsh
or tuple form of `proposePolicy` and read back by `policy()`. Governance may set
the rate to zero or raise it. Fees are redistributed, never created.

The `ProvingReport` makes the share of heights proven by third parties and the
ratified chunk provers finalized state, so governance tunes the shares against
an on-chain quantity. There is deliberately no automatic feedback from stale
rates to amounts: an adaptive schedule would give provers a reason to withhold
proofs, and the stale rule already bounds the damage of an underpriced reward.

## Invalid execution claim

A header can commit a state root, receipts root, runtime commitment or gas that
no correct execution produces. The proof of that is a correct execution: a valid
receipt of the same block whose result fields differ from the header. This is a
`SanctionKind::Slash` offence:

```rust
InvalidExecutionClaim {
    proposer_index: u32,
    header: Header,          // signed by the offender
    parent: Option<Header>,  // binds parent_hash to the claimed pre-state root;
                             // None exactly when the parent is the
                             // specification's first boundary, which binds it
    receipt: BlockProof,     // valid under the chunk's program set
}
// offence_id = penalty_id(9, proposer, height, 0)
```

Execution consumes inputs no other header field names: the execution context
with its incoming boundary, the participation and proving reports inherited
along the branch, the acknowledgements derived from the vote lane, the program
pieces and the evidence anchor. A reporter that proved the block with other
inputs would obtain other results and could frame an honest proposer, so the
header commits them: `Header.inputs_root` is the `DOMAIN_EXECUTION_INPUTS`
commitment of the output's `(context, participation, participation_acks,
proving, program_pieces, accountability.anchor)`, the producer sets it from its
execution, and `BlockProofPublicInputs.inputs_root` repeats it, so every
receipt's output must reproduce it. Every node, executing or not, derives the
same commitment from its branch when it admits a block, without the runtime
artifact, and refuses a header that declares other inputs. Such a header could
never be proven and would escape this claim, since no receipt of the honest
inputs matches it; refused at admission, nothing builds on it.

An executing node proves the honest execution of a divergent candidate, and any
node that receives a valid receipt verifying under the header's inputs with
other results keeps the claim that receipt supports without executing. Either
way the claim persists as evidence in node-local metadata until the header's
chunk finalizes and the claim reaches the slashing pool. The node forgets it
only on a positive determination: the pool holds it, or a successful read shows
it can never be pooled because the offender is tombstoned or, on a reporter,
untracked or unresolvable once the chunk's record has left the retained window.
Anything undetermined (a pending bootstrap, an unresolved offender, a storage
error) keeps the claim for the next finalization; like every safety offence it
has no age limit. One claim per offender and chunk suffices, so a further claim
against the same proposer in that chunk is not stored. At most 64 proven claims
are persisted and 16 unproven ones held in memory with their witnesses; held
claims are never evicted for another offender's, and at the bound a new claim
is refused.

The claim needs no body and no boundary. Its context is the chunk whose range
contains the header's height, authenticated from that chunk's History record,
so it is admissible once that chunk has finalized; the abandoned candidates it
targets belong to chunks that finalize on another branch. The Evidence Guest
checks the proposer signature under the record's committee,
`parent.hash() == header.parent_hash`, and that the receipt's inputs equal
those derived from the header: height, block and parent hashes, chain id,
transactions root, gas limit, `inputs_root`, `state_root_before =
parent.state_root`, the record's runtime and Block program, the proposer's
withdrawal account, and an execution context whose header fields match and
whose boundary names the record's chunk, committee, seed and programs. Only the
result fields `(state_root_after, receipt_root, runtime_extra, gas_used)` may
differ, and at least one must. The rest of the boundary is whatever the header
declared through `inputs_root`: a wrong declaration is the proposer's own input,
and the receipt shows the claimed results false even under it. The Fact Guest
establishes that the receipt verifies under the record's Block program. The
admission is a safety offence with the reporter reward of [reporter
nodes](18-reporter-nodes.md); the deduction and permanent tombstone follow
[evidence proofs](16-evidence-proofs.md). Whether the parent itself was valid
is irrelevant: the header claimed an execution from that pre-state.

The runtime's block transition is total. An undecodable user transaction, one
whose gas allowance exceeds the remaining block gas, or one the EVM refuses
(nonce, balance, fee cap, signature) is skipped with no effects and no receipt,
in verification and proving exactly as producer selection skips it. Every
signed block therefore has one correct execution and a receipt, and a proposer
that claims forged writes for a body holding such a transaction is contradicted
by that receipt and slashed instead of costing the chain
`proof_exclusive_slots` of honest work at no risk. Indexers and RPC treat a
skipped envelope as not executed, and the artifacts' transaction index names
only executed ones.

The offence follows the safety window: no age limit, once per identity,
provided the reporter retained the headers within the signed-artifact retention
of [evidence availability](17-evidence-availability.md). An executing node that
imports a divergent candidate proves the honest execution itself and is the
natural reporter.

### Other offences and what is not punished

Two candidates by the same proposer for the same slot are a double proposal.
Equivocating receipts are impossible: a receipt verifies or it does not. Not
proving a block, proving late, and building on a candidate that later turns out
to be invalid (the descendant goes stale with it) are not punished; there is no
objective offence for the absence of a proof beyond the abandonment penalty's
replaced height.

## Parameters

| Parameter | Location | Default | Meaning |
| --- | --- | --- | --- |
| `proof_exclusive_slots` | `ConsensusParams` | 32 | Proposer-only selection window after a block's slot; also the age at which an unproven candidate is stale |
| `proof_orphan_slots` | `ConsensusParams` | 8 | Retention of receipts for unknown blocks |
| `max_receipts_per_block` | `ConsensusParams` | 4 | Distinct valid statements retained per block, and proofs per finalized chunk |
| `chunk_prover_fee_bps` | `RuntimePolicy` | 5,000 | Share of every block's base fee escrowed for the prover of its chunk; the rest pays the chunk's participating committee |
| `annual_issuance_bps` | `RuntimePolicy` | 200 | Yearly issuance as a share of total stake, half to the block's prover and half to its chunk's prover |
| `abandonment_penalty_amount` | `RuntimePolicy` | 1 token | Deduction for a signed block the canonical chain replaced after its window; zero disables the offence |
| `MAX_ACCRUAL_SLOTS` | runtime constant | 8 | Slots of issuance one block may accrue |
| `[proving] prove_foreign_blocks` | node | false | Prove candidates this node did not produce; requires `mode = "execute"` |
| `[proving] rescue_unproven_blocks` | node | on for CUDA, off for CPU | Prove head-branch blocks whose proposer published no receipt after its lease |
| `[proving] prioritize_block_proofs` | node | true | Start a chunk proof only with no block proof pending, waiting at most one slot |
| `[proving] chunk_proof_fallback_secs` | node | 180 | Delay before validators other than the next round-0 leader prove a chunk |
| `[proving] prover_address` | node | the validator's withdrawal credentials | Runtime account credited by this node's receipts |

Slot defaults assume the 4 s slot. Thirty-two slots are 128 s, which must cover
a full block's proof latency on the expected prover hardware with margin for
publication and verification. The slot parameters are consensus parameters
because they shape the certificate; the amounts are runtime policy because they
never enter a Guest. Policy validation rejects a bps field above 10,000. A zero
issuance rate is legal and leaves block provers unpaid beyond the proposer's
tips.

The pending-chain bound `2 * chunk_size` is derived, not configured; with the
default 128-block chunk it is 256 blocks, about 17 minutes of production. The
stale rule produces heights again, so heights alone do not bound candidates;
three rules do. A node keeps the first unproven candidate a proposer signed for
a slot and admits a second only with a receipt; it keeps at most
`2 * chunk_size` unproven candidates above finality (production pauses at the
same bound, and peers ignore candidates beyond it without judgement); and it
deletes stale candidates one window after they went stale. A long finality
stall therefore holds a bounded set of candidates in memory and on disk; the
free-space quota of [state and storage](04-state-and-storage.md) is a separate
backstop.

## Cases

Each case names the rule that decides it.

1. **Proposer publishes a candidate and proves it in time.** Rule P selects its
   receipt; it keeps its tips and earns the block-prover issuance.
2. **Proposer publishes and goes offline.** Candidates and their state remain
   available. After the exclusive window the leader names any valid receipt
   under rule L; the proposer keeps its tips if anyone proves the block.
3. **Nobody proves the block within the window.** Rescuers with GPU backends
   prove it after the proposer's lease. If none does, the block goes stale, its
   height is produced again and its transactions return to the mempool; nothing
   is paid, and once the replacement finalizes the proposer is charged the
   abandonment penalty.
4. **Writes do not reproduce the header root.** The candidate is rejected at
   admission; no state is applied and the source is penalized. No offence,
   because nothing shows the proposer sent them.
5. **Writes reproduce the root, but the root is wrong.** Every follower holds a
   wrong candidate state. The honest receipt proves the mismatch; the block is
   never proven, so it goes stale under case 3, and the proposer is slashed for
   an invalid execution claim.
6. **A proposer builds on a wrong candidate.** Its block is a correct execution
   over a wrong pre-state. It goes stale with its parent and earns nothing; the
   proposer is not at fault and not punished.
7. **Two valid third-party receipts.** Rule P if one is the proposer's;
   otherwise after the window the leader names one, its own node's if it is
   either, and the other earns nothing.
8. **The proposer's receipt arrives after the proposal.** The proposal stands;
   refusal 2 applies only to receipts a voter held when the proposal arrived.
9. **The leader names a third-party receipt while holding the proposer's.**
   Voters that held the proposer's receipt refuse under refusal 2; the round
   times out and the next leader proposes.
10. **A receipt arrives before its candidate.** It waits in the orphan buffer
    for `proof_orphan_slots`, then is dropped.
11. **A receipt for a stale block arrives late.** Before the block is deleted
    the valid receipt restores it to `Proven` and fork choice judges its branch
    again; after deletion the block returns only through complete-chunk sync.
12. **Proof spam.** Receipts are deduplicated per statement key, bounded per
    block by `max_receipts_per_block` in first-verified order after the
    proposer's, verified before relay and charged to per-peer budgets. A
    receipt has exactly one accepted encoding ([proof
    system](06-proof-system.md)), so a signed acceptance of another encoding is
    objectively malformed everywhere. A receipt of a proven block whose claimed
    statement key is already held is answered as already proven without being
    verified, earns no verdict and is not retained, so new bytes for one
    statement never buy another STARK verification under the engine lock; a
    new statement costs a new proof.
13. **Candidate spam.** Candidates are VRF-gated per slot and signed; a second
    candidate per slot is a double proposal. Nodes keep the first, record the
    double proposal and admit the second only with a valid receipt, whose
    proving cost bounds it.
14. **Program switch at a chunk boundary.** Receipts are verified under the
    program set of the block's chunk start boundary; a receipt under another
    program is invalid.
15. **The next chunk's round-0 leader never publishes a chunk proof.** Other
    validators prove after `chunk_proof_fallback_secs` and any node may; the
    first proof finalizes the chunk, and the next chunk's leader ratifies a
    proof it holds under rule L′.
16. **Two chunk proofs for one certificate.** The leader names one, its own
    node's if it is either; one prover is paid, and both proofs finalize the
    same chunk.
17. **Reorganization to a competing candidate chain.** Candidate fork choice
    ranks the branches and the chunk certificate decides. A node whose pending
    chain lost replays the certified range from retained diffs and receipts.
18. **Bootstrap and snapshots.** Only finalized state is installed; candidates
    are rebuilt from publications. Pending state is never served to light
    clients.
19. **Reporter nodes.** They retain signed headers, bodies and receipts within
    the evidence window and may report invalid execution claims ([reporter
    nodes](18-reporter-nodes.md)).
20. **Archive nodes.** They execute candidates themselves, retain witnesses and
    are natural provers.
21. **An unprovable block in the middle of a chunk.** Proposers stop building on
    it after `proof_exclusive_slots` under the stale rule; at most that many
    slots of other work are abandoned; the height is produced again and the
    chunk closes once the range is complete.
22. **A receipt attributed to the proposer by someone else.** Rule P selects it
    and the proposer is paid; the submitter donated a proof.
23. **Validators run their own provers.** Allowed; after the window a leader
    names its own node's receipts, and the committee share does not depend on
    who proved.
24. **Duplicate proofs of one block.** A second complete proof under another
    `prover_address` buys nothing: after the window the leader names one
    receipt, and the rest are discarded beyond `max_receipts_per_block`.
25. **No chunk proof exists when the next chunk's range is complete.** The
    previous chunk has not finalized, so the next session has not opened; the
    first proof finalizes it and the next proposal ratifies it.
26. **A leader ratifies anything but a held proof of the previous chunk.** An
    empty ratification, an older chunk or a second entry is refused by the
    voters and by the Chunk Guest. A statement key no proof has, or a proof
    over another start, leaves the certificate unprovable, because the Guest
    verifies the named proof against the chained boundary.
27. **Two valid chunk proofs of chunk N finalize N on different nodes.** Both
    nodes hold the same boundary and History; the quorum of N + 1 signs the
    paid prover.
28. **A carrier attaches another two-thirds subset of the precommit quorum.**
    The proving report is identical, since every subset signed the same
    selection; the participation report lists the carried signers, so the
    committee share follows them, and an omitted signer's share is divided
    among the carried ones by stake.
29. **A certificate of another round of the same chunk with other payment
    choices.** Its votes signed another selection, so it is another value: the
    lock rules decide between the two exactly as between two chunks, and no
    quorum can be reused for choices it did not sign.
30. **Clock skew.** `proposal_slot` is bounded by the header drift rule; the
    Guest evaluates windows against the signed proposal slot, never wall time,
    and voters also apply rule W on their own arrival slot, so a leader signing
    a slot ahead of its clock cannot open a window early.
31. **Proving capacity below production.** Unproven blocks go stale, heights
    are produced again, and the pending bound stalls production once two chunks
    are outstanding, the backpressure of [certified
    execution](11-certified-execution.md). The schedule must be sized to the
    proving throughput the network actually has.

## Assumptions

The design inherits the protocol's assumptions and adds none about hardware:

- fewer than one third of the active weight is Byzantine and the BFT network is
  partially synchronous, which rule P rests on; the existence and binding of
  the ratified chunk proof do not, since the Chunk Guest verifies it;
- candidates and receipts reach honest nodes within a bounded delay that is
  small against the windows, which are sized in slots;
- at least one party is willing to prove each block for its issuance share
  within the window, otherwise the block goes stale and its height is produced
  again; validators are not required to prove anything;
- the local clock is within the header drift bound, which `proposal_slot`
  reuses;
- gas prices every operation within a bounded multiple of its proving cost, so
  a legal block is provable within the window; where that fails, the stale rule
  contains the damage and the fix is in gas pricing.

Nothing here relies on provers being honest, on the proposer being online after
publication, or on any node holding a GPU.

## Invariants

1. The write set is never a consensus commitment, never enters a Guest and
   never authorizes finality; it is checked only by reproducing a signed root.
2. Only a verified complete chunk proof finalizes a chunk; a chunk certificate
   covers the chunk's complete fixed height range, names exactly one receipt
   per height, and the Chunk Guest verifies all of them.
3. A receipt's attribution is inside its public values; relaying cannot change
   it, and its statement key is a function of the same values.
4. Rules P and W are pure functions of the receipts voters hold, the block
   slots and the signed proposal slot; the Chunk Guest checks every clause its
   inputs decide and the voters enforce the rest. Among receipts both rules
   allow, the leader chooses.
5. Selection has no price dimension, and the committee share comes from the
   base fee and follows the certificate's signers whoever proved, so a seat
   confers no advantage in the proof market beyond rule P and the leader's
   preference for its own proofs after the window.
6. Every payment is computed by the runtime from a certified report after the
   fact; no Guest and no engine rule contains an amount.
7. A block that is not finalized pays nothing to anyone.
8. Issuance depends only on total stake and the time between finalized block
   timestamps; fees are redistributed, never minted.
9. There is no objective offence for the absence of a proof.
10. Candidates, receipts, reports and policy fields have one format, with no
    compatibility variants.
11. A certificate of any chunk `N` after the specification's first ratifies
    exactly one valid proof of chunk `N - 1`, chosen by its leader; the Chunk
    Guest verifies that proof recursively against the chained boundary, and
    ratification never changes finality, a boundary or History.
12. Every value vote signs the payment selection with the chunk, so a quorum
    authorizes exactly one set of payment choices, and the carried proposal is
    the one the quorum signed.
