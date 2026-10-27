# Consensus

Neutrin0 separates block production from finality. In every slot, validators
whose BLS-VRF output falls below a stake-weighted threshold may propose a
block; fork choice picks the head among the proposed branches. Every
`chunk_size` blocks form a chunk, and a chunk becomes final only when a
three-phase BFT committee has certified it and a recursive Chunk proof has
verified that certificate together with every block proof in the range. A
fast probabilistic head for execution and an expensive proven finality
step then never wait on each other: production continues while the previous
chunk is decided and proven ([certified execution](11-certified-execution.md)).

## Parameters

`ConsensusParams` (`crates/primitives/src/params.rs`) is part of the chain
specification and covered by its hash. `chain-spec.toml` sets
`slot_duration_secs` and `chunk_size`; every other field takes its default.
Changing any of them is a hard fork ([upgrades and forks](20-upgrades-and-forks.md)).

| Field | Default | Meaning |
| --- | --- | --- |
| `slot_duration_secs` | 4 | Slot length |
| `chunk_size` | 128 | Blocks per chunk |
| `expected_proposers_per_slot` | 1.0 (Q64.64) | Mean number of eligible proposers per slot |
| `bft_prevote_quorum_numerator` / `_denominator` | 2 / 3 | Prevote quorum fraction |
| `bft_precommit_quorum_numerator` / `_denominator` | 2 / 3 | Precommit quorum fraction |
| `bft_round_timeout_base_secs` | 8 | Round-zero phase deadline |
| `bft_round_timeout_step_secs` | 4 | Deadline added per round |
| `expected_aggregators_per_round` | 4.0 (Q64.64) | Vote aggregators per chunk and round ([networking](21-networking.md)) |
| `vote_subnets` | 16 | Aggregate-vote gossip subnets |
| `epoch_length_in_chunks` | 1 | Chunks per epoch |
| `activation_delay_epochs` | 2 | Epochs before a new seat carries weight |
| `exit_delay_epochs` | 2 | Epochs a leaving seat keeps its weight |
| `proof_exclusive_slots`, `proof_orphan_slots`, `max_receipts_per_block` | 32, 8, 4 | Proof market ([design 08](08-proof-market.md)) |

Validation (`ConsensusParams::validate`) refuses a zero slot duration, chunk
size, timeout, subnet count, epoch length or delay, a zero fixed-point
parameter, and a quorum fraction below 2/3 or above 1. The runtime's
`unbonding_delay_blocks` (default 302,400 blocks, fourteen days of 4-second
slots) lives in `RuntimeParams` but is checked against these parameters; see
[exit accountability](#exits-and-accountability).

## Slots and proposers

Slot `s` starts at `genesis_time + s × slot_duration_secs`. A header's
timestamp must equal its slot's start exactly, and slots strictly increase
along a branch. Chain time is therefore the slot schedule, and no proposer can
postdate a block to make the runtime's increasing-time rule refuse every honest
block after it. Native import (`check_header_timing` in
`crates/consensus-engine/src/import/admission.rs`) and the Chunk Guest both
check the schedule. Native import also defers, without penalty, a header whose
slot starts more than `MAX_CLOCK_DRIFT_SECS` (60) after the local clock: a
proposer that ground a far-future slot cannot move the head there and stall
honest production, and a lagging local clock sees honest blocks the same way,
so the block is imported again once its slot has started.

A header's `gas_limit` must equal the specification's `genesis_gas_limit`. The
runtime executes under the header's limit and the block proof binds whatever
it names, so only consensus can stop a proposer from raising it; native import
and the Chunk Guest both enforce it.

Proposer eligibility is a BLS-VRF over

```text
DOMAIN_VRF || chain_id LE8 || ChainSpecHash32 || seed || slot LE8
```

where `seed` is the seed of the block's incoming boundary (finalized, certified
or projected; [design 08](08-proof-market.md)). The VRF proof is a
deterministic BLS signature, its output the SHA-256 of the proof, and the
proposer is eligible when the output, read as a big-endian 256-bit integer,
lies below `(2^256 - 1) × expected_proposers_per_slot × stake / total_stake`.
The threshold arithmetic and the seed's evolution are specified in
[randomness](15-randomness.md). A slot can have zero or several eligible
proposers; fork choice resolves the competition.

Each header carries the proposer's BLS signature. Native import verifies the
signature first and retains the signed header for accountability even when the
VRF claim then fails, because a signed header is double-proposal evidence
either way. A failed VRF claim is refused and is not an offence. Such a header
can never become canonical, and an honest producer signs one whenever it built
on a projected successor that another candidate of the open chunk later
replaced, because the finalized seed then differs from the projected one. A
header that fails only against a context the node had projected is ignored
rather than penalized. A header is slashable only for a second signed proposal
in the same slot, for an execution claim a valid receipt contradicts
(`InvalidExecutionClaim`, [design 08](08-proof-market.md)) or for a DA
publication that does not match its commitment.

## Chunks and boundaries

Chunk `n` covers heights `n × chunk_size + 1` through `(n + 1) × chunk_size`;
genesis is height 0. A `Chunk` (`crates/consensus-types/src/chunk.rs`) commits
the height range, start and end state roots and block hashes, Merkle roots over
the block hashes, block-proof public inputs, VRF proofs and DA roots, the active
validator-set root, and the next validator-set and identity-sanctions roots.
Its hash is the value BFT decides.

A `ConsensusBoundary` (`crates/primitives/src/boundary.rs`) is the state
between two chunks: next chunk id, height, block hash, state root, slot,
validator-set root, identity-sanctions root, seed, History root, the governed
`ProgramSet`, the participation and proving report commitments, and an optional
scheduled fork. The validator set, seed and programs of a chunk's incoming
boundary stay fixed for all of its slots and BFT rounds. The specification's
first boundary (`ConsensusBoundary::first`) is genesis, or a hard fork's pinned
start; chunk proofs, recursion and History are described in
[chunk proofs](12-chunk-proofs.md) and [recursive history](13-recursive-history.md).

## Fork choice

`neutrin0-consensus-fork-choice` selects the head among known blocks that
descend from the finalized block, or from the certified boundary's block while
a [certified execution dependency](11-certified-execution.md) exists. A branch
containing a block that went stale (`Stale`, [design 08](08-proof-market.md)) is
excluded together with its descendants; blocks still waiting for proofs take
part. An invalid receipt is rejected on import and never marks a block.

Candidates are ranked lexicographically by:

1. Score: the summed stake of validators whose latest value vote (prevote or
   precommit) names a chunk whose end block lies on the candidate's ancestry.
   Each validator counts once, by its latest vote; sums are checked `u128`.
2. Proven prefix: the height of the highest block below which every block down
   to finality is proven.
3. Height.
4. The smaller header VRF-proof hash, then the smaller block hash, as
   deterministic tie-breakers.

There is no proposer boost. Materializing the chosen branch applies its
authenticated write sets, or re-executes it on an executing node
([proof-following nodes](07-proof-following-nodes.md)).

## Finality

A chunk is final only through a verified complete Chunk proof; no certificate,
vote count or execution result finalizes on its own.

Each chunk runs one BFT instance among the validators of its incoming boundary.
A stake-weighted leader proposes the chunk together with a payment selection of
block receipts ([design 08](08-proof-market.md)); validators prevote and
precommit with stake-weighted quorums, finish failed phases with explicit nil
votes, and enter later rounds only through signed round-change certificates.
Locks follow the Tendermint rules and are never cleared by nil votes or
timeouts. The full protocol is in [BFT protocol](10-bft-protocol.md).

A vote set is a quorum when its stake is strictly more than two thirds of the
active stake and at least the configured fraction
(`neutrin0_primitives::quorum_reached`). Two quorums therefore overlap in
strictly more than one third of the stake, including at exactly the 2/3
default, so two conflicting certificates require more than one third of the
stake to sign both. Products are exact 256-bit comparisons.

The Chunk proof establishes, for the whole range, block-proof composition,
proposer signatures and VRF eligibility, both BFT quorums with their
attestations, the signed leader proposal and its certified round entry,
continuity from the previous chunk's receipt, participation acknowledgements,
the validator transition and the next seed ([chunk proofs](12-chunk-proofs.md)).
Only the next unfinalized chunk runs BFT and finalizes; at most one successor
chunk executes ahead of it ([certified execution](11-certified-execution.md)).

## Signing domain

Every consensus BLS signature signs

```text
tag || chain_id LE8 || ChainSpecHash32 || payload
```

with the 16-byte `DOMAIN_*` tag from `crates/primitives/src/lib.rs` and a
`ConsensusDomain` derived from the complete authenticated specification
(`ChainSpec::consensus_domain`). Proposer signatures and VRF, value and nil
votes and their attestations, leader proposals, round-change reports and DA
publications all use it. Two specifications with the same numeric chain id
cannot replay each other's signatures; there is no signing interface keyed by
the numeric id alone. After a hard fork the domain also carries its
predecessors' domains, and a signature on chunk `c` verifies under the domain
in force at `c` (`ConsensusDomain::at_chunk`, `at_height` for headers); see
[upgrades and forks](20-upgrades-and-forks.md).

## Validator set rotation

The Chunk Guest derives the next committee from the previous one and the
runtime's authenticated `consensus:candidates` record
(`derive_next_validators` in `crates/prover-chunk/src/rotation/transition.rs`).
Runtime stakes become consensus weights unchanged: both are `u128` wei.

### Committee bounds

A committee holds at most `MAX_CONSENSUS_VALIDATORS` (256) seats, counting
activation-pending ones, and `seats × chunk_size` may not exceed
`MAX_CONSENSUS_COMMITTEE_BLOCKS` (16,384), which keeps accountable certificates
and eight retained historical records bounded. At the default chunk size the
committee holds at most 128 seats. Genesis refuses duplicate BLS identities and
every seated key has a verified registration proof of possession
([validator keys](19-validator-keys.md)). A transition must leave positive
active weight; a candidate yielding a zero-weight successor is invalid whatever
the runtime state says. Weight totals stay within `MAX_TOTAL_STAKE`.

### Activation and seats by stake

The epoch at the boundary entering chunk `n + 1` is
`(n + 1) / epoch_length_in_chunks`. A seat created at epoch `e` activates at
`e + activation_delay_epochs` and carries zero weight until then, which
excludes it from VRF eligibility, leadership and quorums.

Seats go by stake, never arrival. A full committee does not refuse a
registration; the registrant waits. At each boundary, waiting candidates take
free seats highest stake first, then lowest address, as long as the committee
bound leaves room and neither the address nor the BLS key is already seated.
Once per chunk, when the highest waiting candidate not already matched to a
leaving seat stakes strictly more than the lowest active runtime-backed seat,
that seat begins an exit handoff, provided another open seat remains. It keeps
its stake bonded and its weight until its exit epoch, then waits like any
candidate. The handoff is rechecked at every boundary and cancelled once no
waiting candidate still outranks the seat, so a challenger that unstakes again
evicts nobody. Only when the candidate record itself is full (256 entries) does
a registration staking strictly more than the lowest waiting, unseated
candidate displace it, and that candidate's stake leaves as a voluntary exit
would. A cheap early registration therefore cannot squat a seat, and no
registration can force a seated validator's stake out. A key with a safety
tombstone cannot register.

Genesis validators the runtime has never recorded keep their specification
weight until a candidate entry for them appears.

### Exits and accountability

A seat whose candidate stake reaches zero is scheduled to exit at
`epoch + exit_delay_epochs`, keeps its last authenticated weight until then,
and leaves the committee vector at that epoch, so expired seats do not consume
capacity. The runtime refuses a full voluntary exit unless another funded,
currently active, non-exiting identity remains; a registration awaiting
activation does not count.

The unbonding delay must cover the exit handoff and two more chunks,
`ConsensusParams::exit_accountability_blocks()`:

```text
(exit_delay_epochs × epoch_length_in_chunks + 2) × chunk_size ≤ unbonding_delay_blocks
```

A stake unstaken in a chunk's first block is seen at the next boundary; its
seat signs the last chunk before its exit epoch during the chunk after, and
evidence of that signature can be admitted only once that chunk finalizes. The
withdrawn collateral therefore stays slashable through the handoff, and what
the delay adds beyond the bound is the window for proving and admitting
evidence of the last signatures. Specification validation
(`ExitDelayOutlivesCollateral`) and the rotation itself refuse parameters that
violate the bound.

### Key rotation

A validator replaces its BLS key without leaving its seat through `rotateKey`
([validator keys](19-validator-keys.md)). The runtime records the new key,
proven for the validator's address, in its registration and candidate entry;
the next boundary gives the seat that key, keeping stake, weight and position,
when the possession proof binds the seat's address and no seat already holds
the key. A leaving seat keeps the key it is accountable under. The old key's
signatures stay punishable: sanctions deduct from the address the offence
names, and a safety admission ejects the seat and candidate at that address
whatever key they hold.

### Identity sanctions

Proven safety admissions append a permanent BLS-identity ban to an
independent, consensus-owned Poseidon2 trie
(`crates/prover-chunk/src/identity_sanctions.rs`). Its root is part of the
signed chunk and of every boundary. A banned identity leaves the committee at
the next boundary together with any seat or candidate at the offender's
address, so a key rotated after the offence shelters nothing, and it can never
return through a new account, registration or governed runtime change. The
runtime keeps its own sanction and withdrawal records for economics; neither
they nor committee retention substitute for the ban root.

## Accountability

Objective offences are proven by the Evidence Guest and admitted through
`SubmitEvidence` transactions; the block's runtime performs the mandatory
deductions and the chunk applies the block-proven identity sanctions to
rotation ([evidence proofs](16-evidence-proofs.md)). Safety offences
(`SlashingEvidence`) are double proposals, double prevotes and precommits, a
value and a nil vote in one phase, conflicting leader proposals, lock
violations, accepting an invalid block proof, an execution claim a valid
receipt contradicts and DA commitment fraud. The liveness sanctions are
inactivity and abandonment. Inactivity means absence from the previous
chunk's certificate as selected by the next chunk's carrier block and recorded
in its participation report; it does not claim the validator was silent on
the network. Abandonment is defined in [proof market](08-proof-market.md).
Signed consensus records stay retrievable within the evidence window
([evidence availability](17-evidence-availability.md)).
