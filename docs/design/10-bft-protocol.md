# BFT protocol

Each chunk is decided by one instance of a Tendermint-style protocol among the
validators of the chunk's incoming boundary. A stake-weighted leader proposes a
proven candidate, validators prevote and precommit, explicit nil votes close
phases that produced nothing usable, and signed round-change certificates move
everyone into the next round together. Every rule that decides validity
(leadership, round entry, quorums, attestations) is checked natively and again
in the Chunk Guest, so host-side pacing alone can never authorize a
certificate. Only a verified complete Chunk proof finalizes a chunk
([chunk proofs](12-chunk-proofs.md)); the BFT certificate is one of its inputs.

The native state machine is `neutrin0-consensus-chunk-bft`; the engine side
(sessions, persistence, candidate retrieval) is
`crates/consensus-engine/src/bft_loop/`; the Guest-side verification shared
with native code is `crates/prover-chunk/src/bft.rs` and
`crates/prover-chunk/src/finality.rs`. The chunk's incoming finalized context,
active set, seed and program identities stay fixed through all its rounds.

## Messages

| Type | Content |
| --- | --- |
| `BftProposal` | Chunk, round, leader index, optional earlier valid prevote QC, optional `RoundChangeCertificate`, `proposal_slot`, one `ReceiptChoice` per height, `ratified_chunk_proofs`, leader signature |
| `BftVote::Value(FinalityVote)` | `FinalityVoteData { chunk_id, round, chunk_hash, selection, phase }`, signer bitmap, aggregate signature, `VoteAttestation`s, proof manifests |
| `BftVote::Nil(NilVote)` | `NilVoteData { chunk_id, round, phase }`, bitmap, aggregate signature, `NilVoteAttestation`s |
| `RoundChange` | Chunk, requested round, validator index, optional highest known value prevote QC, signature |
| `RoundChangeCertificate` | Chunk, round, unique `RoundChange` reports carrying a quorum |
| `FinalityCert` | The exact signed `BftProposal`, both aggregates, complete prevote and precommit attestations, proof manifests, active validator-set root |

Nil is its own variant, never a sentinel chunk hash. Each message kind has its
own domain tag (`DOMAIN_BFT_PROPOSAL`, `DOMAIN_PREVOTE`, `DOMAIN_PRECOMMIT`,
`DOMAIN_VOTE_ATTESTATION`, `DOMAIN_BFT_NIL`, `DOMAIN_BFT_NIL_ATTESTATION`,
`DOMAIN_BFT_ROUND_CHANGE`) under the specification-bound signing prefix of
[consensus](09-consensus.md#signing-domain).

## Round leaders

`bft_leader` (`crates/consensus-types/src/bft/leader.rs`) orders the chunk's
validators with positive effective stake by stake-weighted draws without
replacement and gives round `r` to the validator at position `r mod n` of that
order, where `n` is the number of such validators. Draw `d` hashes

```text
DOMAIN_LEADER_DRAW || chain_id LE8 || chunk_id LE8 || validators_root || seed || d LE8
```

with BLAKE3, where `seed` is the chunk's incoming seed. The whole digest, read
as a big-endian 256-bit integer, is reduced modulo the remaining total stake
(a checked `u128` sum), and the draw picks the remaining validator whose
cumulative stake interval contains the result. Reducing all 256 bits leaves no
measurable modulo bias at any total stake.

Round 0, which decides most chunks, therefore falls to a validator with
probability proportional to its stake, so splitting stake across seats gains no
leadership. Every eligible validator leads once within any `n` consecutive
rounds, so a large balance cannot monopolize successive rounds and an offline
leader is not revisited before every other validator had a turn. The seed
folds the previous chunk's block VRF outputs, so a validator that shapes the
set's encoding through a top-up or a fresh registration cannot also choose
which leader it yields; only the proposer-withholding bias of the seed itself
remains ([randomness](15-randomness.md)). The native engine and the Chunk Guest
run the same function.

A leader only chooses among independently proven candidates, so a faulty
leader costs a timed-out round, never safety. Leadership pays: the round-0
leader of chunk `N + 1` proves chunk `N` by default, and a leader prefers its
own node's receipts after the exclusive window ([proof market](08-proof-market.md)).

## Proposals and the BFT value

A `BftProposal` signs its complete compact chunk, round, leader index,
optional valid QC, optional round-change certificate (by commitment),
`proposal_slot`, receipt choices and ratified chunk proofs. Nodes check the
designated leader and the signature before allocating any branch download.
They then check the receipt selection and validate the exact branch, the named
block receipts and the complete candidate under the current backend before
choosing a value vote. Opening a session or receiving an unsigned
`BftCandidate` does not authorize a prevote.

The BFT value is the chunk together with the proposal's payment selection.
`selection` commits the proposal slot, the receipt choices and the
ratification (`DOMAIN_SELECTION`), and every value vote signs it next to the
chunk hash. Locks, unlocks, valid values, double votes and QC ranking compare
`(round, chunk_hash, selection)`, so a vote for the same chunk with another
selection is a vote for another value. A node signs no value before the
round's proposal fixes the selection and signs nil instead. Peer value votes
that arrive before the proposal are held per selection, at most
`MAX_PENDING_SELECTIONS` (4) per phase (a full set yields its weakest selection
to a verified vote that outweighs it), persisted with the session, and counted
only if the proposal names their selection. A retained valid value keeps its
selection, and a leader re-proposing it reproduces that selection exactly.

The receipt-selection rules (rule P, rule W, rule L), the conditions under
which a leader may propose and a session opens, voter refusals 1 to 4 and the
exact ratification of chunk `N - 1` are specified in
[proof market](08-proof-market.md). The receipts a proposal names are the
round's attested proof manifest ([chunk proofs](12-chunk-proofs.md#shared-proof-acceptance-manifests)).
A justified re-proposal is checked only for availability, attribution, rule W
and the exact ratification.

## Phases and deadlines

The persistent pacemaker (`crates/consensus-chunk-bft/src/pacemaker.rs`) has
`Propose`, `Prevote`, `Precommit` and `AwaitRound` steps. Each phase has its own
deadline, `bft_round_timeout_base_secs + round × bft_round_timeout_step_secs`
(defaults 8 s and 4 s; both must be positive), reset on entering the phase.

| Step | Leaves on | Signs |
| --- | --- | --- |
| `Propose` | A timely, valid, available, lock-compatible proposal | Value prevote |
| `Propose` | Deadline, or a missing, invalid, unavailable or lock-incompatible proposal | Nil prevote |
| `Prevote` | A current-round value prevote QC | Value precommit, retaining the lock |
| `Prevote` | A nil prevote QC, or the deadline without a usable value QC | Nil precommit |
| `Precommit` | Deadline without a value precommit quorum, or a nil precommit quorum | `RoundChange` for `round + 1`, entering `AwaitRound` |
| `AwaitRound` | A verified `RoundChangeCertificate` for a later round | Retransmits its report at each deadline until then |

A nil precommit quorum triggers the report immediately, first persisting
`AwaitRound` so a later proposal or QC cannot cause another old-round value
vote. Duplicate nil quorum observations do not postpone the retransmission
deadline, and the exact signed report is retransmitted on each deadline, so a
lost first publication cannot leave the session waiting forever. A
current-target, current-round prevote quorum keeps its pending precommit phase
until the local timeout; availability advertisements cannot skip that phase.
A current value precommit quorum pauses round advancement while its complete
proof is prepared, verified and committed.

## Nil votes

Explicit nil votes finish phases that have no usable proposal or value quorum.
They never finalize a chunk, never erase a retained value lock, and never
authorize a value vote. A nil vote retains complete `NilVoteAttestation`
coverage with each signer's individual vote signature, under its own domain
that includes the phase.

## Certified round changes

A `RoundChange` signs the chunk, the requested round, the validator index and
the commitment of its optional highest known value prevote QC. Each carried QC
independently binds the chunk, authenticated members, stake, phase, target and
an earlier round. A `RoundChangeCertificate` holds unique reports for one exact
chunk and round whose stake meets the prevote quorum fraction; its highest QC
is the carried QC with the largest `(round, chunk_hash, selection)`.

Local timeout alone never enters a higher round, and a bare report cannot
advance a session. A verified certificate can move a session directly to its
round, however far ahead. Report collection keeps only the two nearest future
rounds; complete certificates authorize catch-up to any later round without a
minority-report advancement rule.

Round zero has no entry certificate. Every nonzero proposal must carry a valid
certificate for exactly its chunk and round, bound into the leader signature.
If the certificate carries a highest QC, the proposal's valid QC may not be
lower, and at an equal round it must name the same value. The proposal's valid
QC must itself authenticate this candidate and selection and strictly predate
the proposal's round. Native admission and the Chunk Guest both run these
checks (`verify_proposal_with` in `crates/prover-chunk/src/bft.rs`).

## Locks and valid values

The driver keeps three things apart: the candidate selected for the current
round, its retained signing lock, and the highest observed valid value with the
selection its QC signed. A leader proposes the highest known valid value with
that selection and its QC; availability hints carry the selection next to their
justification. If a round-change certificate refers to a higher QC whose
candidate is not held locally, the leader fetches that exact branch before
proposing. A signed higher-round proposal can carry its own certified entry for
a node that missed earlier rounds, and accepting it does not first sign a
throwaway round-zero vote.

A locked validator may prevote its lock target. That prevote declares the QC
that established the lock, or a newer QC for the same target, so no earlier
conflicting precommit of the signer can be cited against it. A prevote for a
different target needs an independently verified QC with

```text
retained_lock.round < justification.round < new_prevote.round
```

A precommit still requires the current target's current-round prevote quorum
and may declare that quorum as its unlock. Current-round prevotes cannot justify
the conflicting prevotes that created them, and receiving a QC cannot overwrite
the old lock before signing authorization is checked. The strict earlier-round
rule follows the
[Tendermint lock-change specification](https://github.com/tendermint/spec/blob/master/spec/consensus/consensus.md).

"Highest known" is a local rule for honest nodes. Certificates do not prove that
a signer never saw an unpublished QC or held an undisclosed lock; an offence
always needs the actual signed messages and their authenticated source context.

## Signatures and accountability

Both value phases retain complete, unique `VoteAttestation` coverage. A prevote
attestation signs the signer's exact individual vote and its optional unlock QC
commitment, including an explicit `None`, and carries no proof-acceptance
commitment. A precommit attestation also signs a counted Merkle commitment to
the exact ordered block-proof envelope hashes it accepted
([manifests](12-chunk-proofs.md#shared-proof-acceptance-manifests)).

QC commitments bind the exact vote data, signer bitmap and aggregate signature
under a separate domain. Votes, certificates, proposals and round-change
certificates carry sorted unique QC dictionaries; optional hash references
preserve `None`, decoders reject missing, duplicate or unused entries before
accepting an envelope, and nested reports share the outer dictionary. Proposal
and round-change signatures bind the optional QC commitments, and a proposal
binds its complete round-entry certificate commitment. Dictionary positions are
never signing authority.

Vote accumulation unions verified individual signers even when incoming
aggregate bitmaps overlap. Each validator contributes its stake and vote
signature once, the first accepted signed attestation is kept unchanged, and
the aggregate is recomputed from those unique signatures, so ignoring a smaller
overlapping aggregate cannot lose progress. Identical QCs carried by proposals,
reports and unlock claims share one aggregate-signature and quorum check within
a certificate; every claim still receives its individual signature, policy,
membership and stake checks. Fork choice counts the same signers
([consensus](09-consensus.md#fork-choice)).

The protocol's objective offences, verified by the Fact and Evidence Guests and
admitted by blocks ([evidence proofs](16-evidence-proofs.md)):

| Offence | Signed facts |
| --- | --- |
| `DoublePrevote`, `DoublePrecommit` | Two distinct value prevotes (or precommits) of one signer for one chunk and round |
| `ConflictingNilVote` | A value vote and a nil vote of one signer in one chunk, round and phase; shares the double-vote penalty identity, so presenting both forms cannot deduct twice |
| `DoubleBftProposal` | Two proposals of distinct values (chunk or selection) by the designated leader of one chunk and round; an invalid attached QC or certificate does not excuse it |
| `LockViolation` | An earlier value precommit with its locking QC, then a conflicting value prevote or precommit whose signed unlock declaration is invalid under the rule above |
| `InvalidProofSigning` | A precommit attestation whose acceptance commitment opens to a block-proof envelope the verifier rejects ([chunk proofs](12-chunk-proofs.md#shared-proof-acceptance-manifests)) |

## Durable recovery

Before signing any new message, the engine synchronizes the session's
candidate, step, deadlines, retained lock, valid value, report collection and
certified round entry. The signing journal (`crates/consensus-engine/src/signing.rs`)
then reserves the exact proposal, value or nil vote, attestation or round
report. It binds the specification, the BLS public key, chunk, round, phase and
complete payload; it decodes only the current 56-byte domain prefix. Identical
retries reproduce the original deterministic signature. A conflicting value or
nil reservation, a changed proposal or a regressing round is refused. Entries
are keyed by public key, so validator-index changes cannot erase a key's
history. A reservation failure publishes nothing. Durable signing retains the
exact unsigned carrier next to its reserved message, so restart cannot
substitute other sources.

Journal retention is bounded per identity and chunk. An atomic reservation
keeps the current value and nil intents and the original precommit that
established the retained lock, while monotonic proposal and report watermarks
replace superseded positions, including skipped rounds that never produced a
vote. Compaction and the new reservation synchronize together; a failed write
neither authorizes a signature nor erases the prior lock, and removed positions
stay forbidden. Entries below durable finality are reclaimed; proposer slot
watermarks never expire. Key sources, remote signers, doppelganger protection
and moving a journal between data directories are in
[validator keys](19-validator-keys.md).

Restart reauthenticates the saved reports, proposal and certificates, vote
declarations and the original candidate branch under the current backend; it
never substitutes the current fork-choice head, erases an unfinalized lock, or
lets a journal entry manufacture an absent higher-round entry. It does not
compare saved proof hashes with the receipts held at restart, because preferred
receipts legitimately change and nothing was signed over them. A precommit
derives its manifest from the proposal's named receipts as held at signing,
abstains if any is missing, and persists the manifest before the signature, so
a reserved or saved local precommit still matches it exactly. An open value
that does not validate yet on restart waits for the round clock instead of
stopping the node. Accepting an independently verified leader proposal keeps
its exact entry certificate without discarding a higher valid value or lock;
different valid signer subsets of a round-change certificate are allowed.

Before any local signature the open value's complete candidate must validate
under the running backend, including the Guest's own limits
([chunk proofs](12-chunk-proofs.md#provability-before-voting)). The verdict is
reused while its inputs are unchanged: the session's chunk hash, branch end and
named receipts, the backend's Guest programs and the incoming boundary. The
node gathers the witness under the engine lock and validates it outside; a new
proposal selection validates again, installing a boundary discards every
verdict, and whether the backend can still prove under the boundary's programs
is checked on every use.

The node keeps its first verified receipt for a block. Another valid encoding
of the same statement cannot replace bytes already signed locally, and a
rejected alternative cannot demote a proven block or remove an invalid envelope
needed for accountability. Different validators may accept different valid
encodings; the chunk commits block statements, never one chosen encoding.

The first complete authenticated proposal with both value quorums freezes its
exact certificate. Later signed sources remain available to accountability but
cannot change the in-flight proof identity. Proof work is fenced by the exact
chunk, hash, round and certificate identity at preparation, launch and commit,
so a stale completion cannot commit another session or clear another task's
state. The quorum-ready clock retries failed proof work under the same
identity, restart restores the frozen certificate, and completion notifications
release the next ready quorum. The BFT clock runs independently of the producer
and does not poll proof completion.

## Transport

`BftMessage` on the `bft_messages` topic carries proposals, nil votes, round
reports and certificates; value votes travel on the prevote and precommit
topics and the aggregate-vote subnets ([networking](21-networking.md)). The
`bft_round_by_chunk` RPC returns the current proposal and certified entry when
gossip was missed. An empty or failed response stays eligible for bounded
retries after a network cooldown even if the local round has not advanced, so a
lagging node can recover the entry certificate after peers moved beyond the
round its own reports could help.

`BftCandidate` gossip, candidate inventory and `candidate_by_chunk` are
availability hints. `Engine::offer_bft_candidate` fully authenticates an offered
branch but never treats its advertised round or QC as signing authority.
Payload retrieval pins an exact branch endpoint, so moving peer heads do not
redirect a backfill, and a branch whose endpoint is already held as proven is
offered without downloading its range again. Exact-hash candidate retrieval
also serves retained non-current proven branches after reauthenticating their
receipts and candidate. An immutable signed report can reference an older QC
target after its signer's valid value or head changed, so that target must stay
retrievable: the candidate cache holds `MAX_BFT_CANDIDATES` (8) branches per
session, and eviction protects the current target, highest valid value,
retained lock, the current entry certificate's highest QC and the local
next-round report's highest QC, at most five distinct pins.

Transport decoders bound bitmap sizes, signer and report counts, proof-hash
counts and message sizes before allocation; these are resource limits, never a
substitute for core validation. Report collection, candidate discovery and
fixed-branch payload queues are bounded and scheduled fairly, and payload
scheduling rotates targets after each attempt so one failing target cannot
starve an obtainable highest-QC candidate.

## Liveness assumptions

Under eventual synchrony, bounded honest clock skew, an obtainable valid
candidate and responsive stake meeting both quorum fractions, growing phase
deadlines eventually let a complete round communicate. The leader order visits
every eligible validator once per cycle, so an honest leader gets a turn.
Proposing the highest known valid value lets validators with older conflicting
locks follow its independently verified QC, and nil phases with certified
reports continue through missing or malicious leaders. At the default 2/3
fractions, fewer than one third faulty or unresponsive active stake satisfies
the quorum assumption; higher configured fractions need correspondingly more
responsive stake. Progress also requires the active set, certificates and
candidate to fit the supported resource budgets.

The protocol does not promise progress through a permanent partition, a failed
proof backend, an unavailable candidate, exhausted storage or arbitrary denial
of service. There is no configurable round cutoff. Checked `u32` round
exhaustion is an explicit failure, never a wraparound or a reason to reset
signing history. Safety rests on the active-stake fault assumption and the
signing rules above.

Committee handoff is part of the decided value: the next validator vector and
identity-sanctions root are fields of the chunk, bounded and derived as in
[consensus](09-consensus.md#validator-set-rotation). These rules live in the
Chunk Guest, so changing them is a hard fork
([upgrades and forks](20-upgrades-and-forks.md)), never a governed runtime
change.
