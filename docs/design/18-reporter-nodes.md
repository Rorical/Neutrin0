# Reporter nodes and runtime rewards

A reporter node (`role = "reporter"`) follows the chain without proposing or
voting and keeps the signed material needed to prove misconduct by identities
that can still be punished. Ordinary nodes keep sources only for the eight-chunk
window ([evidence availability](17-evidence-availability.md)), while safety
evidence has no age window; the reporter closes that gap for every identity that
still holds slashable funds, and is paid from the deductions it causes. Its
storage grows with the accountable committee's signing history, never with what
peers send and never with transaction bodies.

A reporter advances state from verified receipts and state diffs like a full
node ([proof-following nodes](07-proof-following-nodes.md)) and executes only
with `[execution] mode = "execute"`. It prunes transaction bodies, execution
witnesses and old state as a full node does and keeps no complete History tree.

## Configuration

```toml
role = "reporter"
data_dir = "./data/reporter"

[reporter]
reward_address_hex = "0000000000000000000000001111111111111111111111111111111111111111"
```

The reward address is a runtime account: twelve zero bytes, then the 20-byte
Ethereum address of an account whose key the operator controls. The runtime pays
nothing to any other value, so the node refuses one at startup and the Evidence
Guest refuses a statement naming one. A missing, malformed or zero address, or a
`[reporter]` section on another role, rejects startup. The reporter needs no
validator BLS key and no account signing key. Without `data_dir` the node uses
the in-memory backend and loses its observations on exit.

```sh
neutrin0-cli node-config --spec chain-spec.toml --out reporter.toml \
  --role reporter --data-dir ./data/reporter \
  --reporter-reward-address <64 hex digits>
neutrin0-node --config reporter.toml
```

## Starting observation

A reporter starts from genesis or from an authenticated full-node bootstrap
([recursive history](13-recursive-history.md)). The bootstrap supplies a frontier
whose count and root match the verified endpoint, so observation needs no
historical tree download. The initial bootstrap atomically retains the supplied
recent certificate records and their openings. A later old-source observation
promotes any available authenticated ordinary record into reporter retention
before saving its signatures. Each source uses its own chunk's validator
indices; missing authenticated context prevents retention, and the current
validator vector never stands in for a past or future chunk. A historical root
cannot recover signatures that nobody retained.

## Selective retention

The reporter retains, while a relevant identity remains accountable:

- signed consensus sources and signed proposer headers;
- exact proof-envelope dependencies;
- historical chunk records (chunk, validator vector, effective seed and
  certificate; no transaction bodies), each immutable and stored with its leaf;
- the complete History subtree roots that open those records.

A record's 64-level opening is built on demand from the bounded frontier and the
complete subtrees it needs (each a 32-byte root under its level and start), and
is verified against the finalized root before use. A complete subtree never
changes, so nothing watched is rewritten as the chain grows: a finalized append
keeps each right child it completes whose left neighbour holds a watched chunk,
at most one per tree level and about two per append on average, found by one
ordered index seek each. Releasing a chunk deletes exactly the subtrees no other
watched chunk still pairs with. Finalization work therefore does not grow with
the number of watched chunks. The shared frontier stays at most 64 hashes.

A finalized chunk's canonical block receipts are never copied: the Chunk Guest
verified every one, so accepting one is never an offence. A vote's receipt
dependency is copied when the vote is observed, because its canonicity is not
yet known, and finalizing the vote's chunk releases every copy that is exactly a
retained, verified receipt of one of that chunk's canonical blocks. Each
canonical header is kept for its proposer as one side of a possible double
proposal.

Value votes and certificates retain full distinct proof manifests shared by the
individual signed count/root commitments; dependency indexing follows those
manifests and keeps what an exact receipt's Merkle opening needs. Quorum
dictionaries share each certificate within a signed envelope and retain the
source signatures and complete signer subsets behind its hash references. Thin
proving-time `HistoricalContext` objects and compact participation votes do not
replace these sources; finality certificates stay in `HistoricalOpening` for
source recovery and bootstrap. Sources shared by several identities stay until
every one of them can be released.

The historical context commits the Block program and runtime artifact hash at
the chunk's start boundary, and rejection evidence for an old receipt uses that
identity even when newer programs govern admission. A reporter lacking those old
program bytes fetches them from peers by identity through the `StateByRoot`
program namespaces and keeps them while a retained record names them
([upgrades and forks](20-upgrades-and-forks.md)).

Retention is bounded per identity and chunk. Each owner keeps at most two
differing signed statements per chunk, round and step (prevote, precommit, nil
prevote, nil precommit, proposal, round change, and a header's slot) and at most
256 per chunk. Re-bundled copies of one statement count once, and a full owner
gives up its highest-round statement only for a lower one, because honest rounds
are few and low. Canonical headers are exempt. Per watched chunk the reporter
adds its record, its 32-byte leaf and on average about two subtree roots. Startup
index scans, eligibility cleanup and inventory rebuilds read the columns a page
at a time.

Old source observations are forensic inputs: they never authorize old votes in
live BFT or widen its eight-chunk reference window, and reporter history and the
ordinary recent-history caches have separate lifetimes. A validator that stays
bonded indefinitely generates an indefinitely growing signing history; releasing
exited identities stops obsolete lifetimes from accumulating but does not make
active validators' histories constant-size.

## Eligibility and release

Eligibility comes from the installed runtime's `reporter_status` query against
authenticated finalized state. The request lists up to 256 BLS identities with
their withdrawal accounts; each reply gives the slashable balance (active stake
plus funds still in the withdrawal queue, including matured funds not yet
withdrawn, matching the mandatory deduction), the safety tombstone and whether a
sanction is pending. An unfinalized withdrawal never deletes evidence, and
unavailable or malformed query results preserve local evidence.

The eligibility cache binds the finalized boundary and the tracked
identity/account generation, so a late authenticated context can trigger a
refresh without new finality. Both bindings are checked again before cleanup,
and concurrent changes keep all sources until a new query succeeds. Signature
arrivals and path updates do not invalidate the cache.

Collateral belongs to the withdrawal account, so several historical identities
sharing it stay accountable while it holds deductible funds, and replacing a
registered key does not release the former key's observations. An identity that
later seats under another account keeps every previously observed account in its
query, and eligibility is their union. Withdrawing and restaking between two
finalized observations creates no observed zero-balance boundary.

Once finalized state shows that an identity has no deductible funds, or already
carries its safety sanction, and nothing is pending against it, its discovery
material and unprovable raw reports are released, keeping dependencies another
accountable identity still needs. A pending sanction keeps its own runtime
obligation and recipient. If a retired identity funds stake again, observation
restarts; cleanup cannot restore earlier signing material.

## Snapshot jumps and hard forks

A reporter that falls behind may snapshot-bootstrap like a full node, keeping
everything it retained. A jump skips the appends whose completed subtrees its
openings would have kept, so the bootstrap stores the subtrees the snapshot's
recent openings reveal for watched chunks and marks dormant each watched chunk
that still cannot be opened under the new count, reading every watched chunk
once. A dormant record still identifies its historical validators, but nothing
can be proven from it until its path is refreshed: the reporter asks peers,
archives first, for an `AnchorOpening` of that chunk under its own latest
finalized endpoint, accepts one whose leaf matches the stored record and keeps
its complete siblings. Full nodes open chunks within one unbonding delay; older
ones need an archive.

The range between the reporter's previous finalized count and the first chunk
the snapshot covers is recorded durably as a gap (`reporter_gaps`) and logged.
Signatures from those chunks were never observed here, so offences signed only
there need another reporter or an archive. The gauges
`neutrin0_reporter_gap_chunks` and `neutrin0_reporter_dormant_paths` report both.

A hard fork moves a reporter to a new data directory started at the fork. At the
endpoint the predecessor node writes its reporter columns, raw offence pool and
gaps into the endpoint bundle's carry file, and the successor (`[bootstrap]
fork_from`) imports them once, keeping rows it already holds and merging each
tracked identity's withdrawal accounts. History continues across the fork, so
the import reopens every watched chunk under the successor's frontier as a
snapshot jump does and records any chunks between the predecessor's finality and
the successor's retained records as a gap. Carried sources verify under the
predecessor's domain, so offences signed before the fork stay reportable.

## Discovery, proof and publication

Authenticated observations feed objective offence detection, including late
conflicting messages against retained contexts. A detected claim enters the
durable raw-evidence pool. The background evidence worker supplies its
historical record to the Evidence Guest, proves the offence, attaches the
retained current History opening and publishes an `EvidenceReport` on the
`evidence_proofs` topic ([evidence proofs](16-evidence-proofs.md)). A reporter
keeps raw claims local until a proof-bound report is ready, while ordinary
signed-source publication continues; failed jobs keep their inputs for retry.
Receivers authenticate the report normally and admit it through the mandatory
FIFO.

The reporter account is an optional field of the Evidence Guest witness and
public statement, authenticated by the batch commitment and the recursive proof,
so relaying a receipt or refreshing its path cannot change the destination.
Offence IDs exclude the reporter, so a different destination cannot bypass the
identity tombstone or earn a second reward. Anyone may prove an independently
observed offence again; the first canonical admission selects the recipient.

An `InvalidExecutionClaim` needs a valid receipt of the honest execution of the
offending candidate. An executing node finds the divergence itself: it
re-executes a candidate whose results differ from its header and proves the
honest execution. Any node, executing or not, keeps the claim a received receipt
supports when that receipt verifies under the header's inputs but commits other
results. Proven claims persist in node-local metadata and are pooled once the
candidate's chunk is in History; only an executing node's unproven divergences
are held in memory and lost on restart.

## Runtime economic interface

`RuntimePolicy.reporter_reward_bps` sets the safety-report reward: default 1,000
basis points (10%), range 0 to 10,000, changed only through governance. Admission
fixes the proven destination and the current percentage in the pending sanction,
so later governance cannot rewrite an admitted obligation.

At mandatory execution the runtime deducts the actual available collateral,
credits `floor(actual_deduction * reporter_reward_bps / 10_000)` to the
reporter's spendable account and burns the remainder. A claim with no actual
deduction, a `None` destination and the liveness kinds (inactivity and
abandonment) pay nothing. A destination at its balance limit receives only what
it can represent, and the residue burns. Rewards come from the deduction and
never mint supply. Consensus and the Chunk Guest consume the proven sanction and
never read reporter records or implement the reward rule.

The runtime keeps one fixed-size cumulative record under
`accountability:settlement_totals`. For each sanction kind (safety, inactivity,
abandonment) it counts admitted and executed obligations, executions with zero
deduction, funds deducted, reporter credits and funds burned, updated in the same
execution as the sanction and account writes and proven by the Block Guest.
Shared withdrawal accounts contribute only what each FIFO operation actually
removes, so several identities on one account do not multiply recorded
collateral. The totals are authenticated state and survive restart and snapshot
installation without replaying old bodies.

The read-only `accountability_metrics` query takes empty arguments and returns a
borsh `neutrin0_runtime_abi::operational::SettlementSnapshot`: the cumulative
`totals` and the `pending_slash`, `pending_inactivity` and `pending_abandonment`
counts of the FIFO. Pending counts are obligations, not estimated deductions or
promised rewards. Each cumulative value uses checked `u128` arithmetic; a total
that exceeds the representation stays at `u128::MAX` with its `overflowed` flag
set. This observational loss of precision never blocks mandatory execution or
changes a transfer.

Nodes run the query through the installed runtime against authenticated
finalized state, with the program that produced that state, and publish a result
only if the finalized boundary still matches after the query; an unchanged
boundary reuses the last result. Speculative head execution never advances the
exported counters. Missing state, query errors and runtimes without the interface
expose an unavailable observation that keeps the last successful values and
their finalized height. Light clients expose economics as unavailable, since a
state root alone does not supply the records. The totals describe chain state
and must not be summed across observing nodes.
