# Upgrades and hard forks

Neutrin0 replaces its runtime and its Evidence and Block Guests by on-chain
governance, without a new chain and without a new node binary. Proofs bind
program identities, so a new runtime means a new Block Guest with a new
verifying key, and a receipt only means something under the key that produced
it. Program identities therefore travel inside every consensus boundary, a switch
takes effect at a chunk boundary the runtime schedules, and the Chunk Guest that
recursively proves History carries the switch forward without any list of
historical keys. The Fact Guest, the Chunk Guest and the SP1 version are fixed for
the life of a chain. Replacing one of them is a hard fork, which governance also
schedules: the chain ends at a chosen chunk count and a successor specification
starts from that endpoint, keeping its predecessors' signing domains.

## What governance can and cannot change

Governance can switch the execution program set (the runtime WASM, the Evidence
Guest and the Block Guest), replace the governable runtime policy and end the
chain at a hard fork. Everything else the chain specification fixes: chain
identity and genesis commitments, the Fact and Chunk Guests, every
`ConsensusParams` field ([consensus](09-consensus.md#parameters)),
`ProofParams`, `LightClientParams`, the block gas limit and
`unbonding_delay_blocks`. Changing any of them is a new specification, which on a
live chain is a hard fork.

Because the consensus Guests never change within a chain, the economic model
lives entirely in the runtime, and runtime and consensus meet through a narrow,
fixed interface:

| Direction | Item | Owner |
| --- | --- | --- |
| Runtime to consensus | `consensus:candidates` (`ConsensusCandidates`, sorted by address: address, `u128` stake, optional BLS identity with its registration proof of possession) | [consensus](09-consensus.md#validator-set-rotation), [validator keys](19-validator-keys.md) |
| Runtime to consensus | `upgrade:scheduled` (`ScheduledUpgrade`) | [switching rule](#switching-rule) |
| Runtime to consensus | `fork:scheduled` (`ScheduledFork`) | [scheduled forks](#scheduled-forks) |
| Consensus to runtime | `ParticipationReport` of the previous chunk's carried certificate | [runtime interface](02-runtime-interface.md) |
| Consensus to runtime | `ProvingReport` of the same certificate | [proof market](08-proof-market.md) |

The Chunk Guest reads exactly these three records from the authenticated
post-state witness and nothing else, so how the runtime stores accounts, stake,
delegation or registrations is invisible to consensus. An entry of the candidate
record exists while the runtime holds a validator record or a registration for
the address, so a zero stake is authenticated and a missing entry means the
validator fully withdrew. Rotation rules (activation and exit delays,
retirement, removal of a tombstoned identity's seat) stay consensus semantics
inside the Chunk Guest. Each boundary commits the reports the chunk ending there
consumed (`participation`, `proving`), and the runtime keeps the latest
participation report under `consensus:participation`; reward, delegation and
liveness economics read it without reading a certificate.

## Program sets, the chain binding and boundaries

```rust
pub struct ExecutionPrograms { pub fact: [u32; 8], pub evidence: [u32; 8], pub block: [u32; 8] }
pub struct ProgramSet { pub runtime_code_hash: Hash, pub execution: ExecutionPrograms }
pub struct ChainBinding { pub chain_spec_hash: Hash }
pub struct ConsensusBoundary {
    pub next_chunk_id: u64, pub height: u64, pub block_hash: Hash, pub state_root: Hash,
    pub slot: u64, pub validators_root: Hash, pub identity_sanctions_root: Hash,
    pub seed: Seed, pub history_root: Hash,
    pub programs: ProgramSet,            // programs that execute and prove the next chunk
    pub participation: Hash, pub proving: Hash,
    pub fork: Option<ScheduledFork>,     // see "Scheduled forks"
}
pub struct ProofDomain { pub chain: ChainBinding, pub chunk: VkDigest, pub programs: ProgramSet }
```

`ChainBinding` is the chain-specification hash alone
(`BLAKE3(DOMAIN_CHAIN_SPEC || borsh(spec))`). The specification fields it commits
include the chain id, the chunk size, the Fact identity
(`genesis_execution.fact`) and the Chunk Guest identity (`genesis_chunk`), so a
consumer holding the specification reads them from it and compares only the
hash; `ChainBinding::new(spec)` takes nothing from the node binary.

A `ProgramSet` is complete when no Guest identity is zero. Every boundary's
`programs.execution.fact` must equal the specification's Fact pin
(`ChainSpec::accepts_programs`); its place in `ProgramSet` repeats the execution
ABI and grants no upgrade permission. `ProofDomain` is a verifier's trust
profile: the binding, the specification's Chunk Guest and the program set
trusted at the verifier's anchor. Statements never embed it.

A `ConsensusStatement` carries a start and an end boundary. The chunk's block
receipts are verified under `start.programs.execution.block`, and the chunk
receipt itself under the specification's Chunk Guest. Normally
`end.programs == start.programs`; a switch is a chunk whose end boundary names a
different set. Evidence and Block keys always come from the start boundary,
which the verifier authenticates before trusting anything proven from it, never
from a key a receipt names. The Chunk key is an input the verifier takes from its
specification, so no Guest names its own identity.

Fact receipt caches, Chunk recursion and Evidence recursion use the genesis Fact
identity. Evidence batches bind it to each claim's specification, and
chunk-to-chunk recursion and light-client anchors refuse any boundary whose Fact
identity differs. Pinning the Chunk Guest alone would not suffice: an upgradable
Fact program could substitute false signature verdicts, so a Fact change is a
hard fork too.

## Switching rule

The runtime stores at most one scheduled switch under `upgrade:scheduled`
(`neutrin0_consensus_types::runtime::UPGRADE_KEY`):

```rust
pub struct ScheduledUpgrade {
    pub activate_at_chunk: u64,       // first chunk executed under `programs`
    pub programs: ProgramSet,
    pub artifacts: ProgramArtifacts,  // content hashes: runtime, fact, evidence, block
    pub available: bool,              // see "Artifact availability"
}
```

The Chunk Guest reads the record from the post-state witness of the chunk's last
block. The end boundary entering chunk `next` adopts `upgrade.programs` only if
`activate_at_chunk == next`, `available` is set, the set is complete and its Fact
identity equals the incoming one; otherwise the end boundary repeats the start
set. A record that is stale, not yet due, unavailable, incomplete, names another
Fact identity or does not decode is void. Governance never writes an incomplete,
Fact-changing or malformed record, but a replacement runtime could, and runtime
state is something no Guest can correct: refusing such a record would leave
every later chunk unprovable after its certificate, while voiding it keeps the
chain under programs it already trusts.

The engine and the Chunk Guest apply one shared function
(`neutrin0_prover_chunk::rotation::programs_entering`), and voters run the Guest's
whole successor derivation, this rule included, before voting. The record's
Borsh layout is frozen consensus ABI like `consensus:candidates`: the immutable
Chunk Guest decodes it, so a runtime that changes the layout voids every schedule
it writes, and changing the layout is a hard fork.

Finalized boundaries carry their program set. For a block in an unfinalized
chunk the engine derives the set by `programs_entering` from the record in the
post-state of each preceding chunk's last canonical block
(`Engine::programs_at_chunk`), caching records by that block's hash so a
reorganisation never reuses a stale answer. A block's proving public inputs carry
the expected Block Guest digest (`block_program`) beside the runtime hash, so a
receipt is checked under the key the block's boundary names.

## Governance in the runtime

Governance is an ordinary runtime rule (`neutrin0_runtime_system::governance`),
upgradable with the runtime as a Substrate governance pallet dispatching
`set_code` is. Consensus never sees proposals or votes; it consumes only the
records governance writes. The EVM runtime exposes the entry points as system
precompile calls from the validator's own account, which pay gas
([EVM runtime](03-evm-runtime.md)):

| Call | Slot | Effect on quorum |
| --- | --- | --- |
| `proposeUpgrade(programs, artifacts, activate_at_chunk)` | program | writes `upgrade:scheduled` |
| `cancelUpgrade(programs, activate_at_chunk)` | program | deletes `upgrade:scheduled` |
| `proposePolicy(policy)` | policy | writes `runtime:policy:pending` |
| `proposeFork(count, successor)` | fork | writes `fork:scheduled` |
| `cancelFork(count, successor)` | fork | deletes `fork:scheduled` |
| `vote(proposal_id)` | the slot holding the id | enacts when it reaches quorum |

```rust
pub enum ProposalAction {
    Programs { programs: ProgramSet, artifacts: ProgramArtifacts, activate_at_chunk: u64 },
    Policy(RuntimePolicy),
    Cancel { programs: ProgramSet, activate_at_chunk: u64 },
    Fork(ScheduledFork),
    CancelFork(ScheduledFork),
}
pub struct UpgradeProposal {
    pub proposer: Address, pub action: ProposalAction,
    pub proposed_at_chunk: u64, pub voters: Vec<Address>,   // sorted
}
// proposal id = BLAKE3(DOMAIN_UPGRADE_PROPOSAL_ID || proposer || borsh(action))
```

The slots live under `upgrade:proposals`, `policy:proposals` and
`fork:proposals`. A proposal costs 100,000 gas and a vote 40,000. Failures return
`Unauthorized`, `UpgradeConflict`, `InvalidUpgrade` or `AlreadyVoted` receipts.

Eligibility:

- Only runtime validators that hold a seat with positive weight in the block's
  authenticated consensus set may propose or vote, and only they count in the
  quorum denominator. Runtime stake consensus has not seated (pending
  activation, a banned identity, a completed exit) answers to no consensus
  offence and cannot decide the program set.
- A registration counts only once it is `UPGRADE_VOTER_MIN_AGE_BLOCKS` (1,024)
  blocks old, so freshly registered stake cannot decide a switch before
  consensus would seat it. Genesis validators have no registration record and
  count at once. Stake added later shares one per-validator `bond:` record whose
  clock restarts with each addition; it is excluded from the voter's weight and
  the denominator until it has aged the same 1,024 blocks. A later unstake or
  deduction is charged against counted stake first, which only undercounts.

Slots and support:

- Programs, policy and forks have separate slots, so no decision of one kind
  waits for another. Each slot holds every live proposal of its kind, at most one
  per proposer; a new proposal replaces the proposer's previous one in that slot.
  Accumulated support decides, never the proposer's own stake, so no validator can
  occupy a slot.
- A validator supports at most one proposal per slot. Its vote, or its own new
  proposal, moves its support; the proposer's stake counts as a vote. Proposing
  an id already in the slot is a conflict.
- A slot holds at most `MAX_SLOT_PROPOSALS` (256, the seat bound). Since every
  seat has room, only proposals of departed proposers can fill it; then the least
  supported proposal yields to a newcomer whose stake exceeds that support.
- While an enacted switch awaits its activation chunk the program slot admits
  only its cancellation, and while an enacted fork awaits its count the fork slot
  admits only its cancellation. The policy slot is never blocked.

Quorum and enactment:

- Weights are the voters' counted stake at tally time. A proposal is enacted in
  the transaction that brings its supporters to two thirds of the counted stake
  (`UPGRADE_QUORUM`); a validator holding that much alone enacts at proposal
  time. Supporters are disjoint within a slot, so at most one proposal per slot
  can reach quorum. Enactment closes the slot with every competing proposal.
- A cancellation must name the current schedule exactly (program set and
  activation chunk, or the fork record), checked at proposal and at every vote,
  and on quorum deletes it. A program switch can be cancelled until its
  activation chunk and a fork until its count.

Timing:

- A switch or a fork can rewrite every rule, so dissenters must be able to leave
  first. The minimum lead is
  `L = 1 + ceil((unbonding_delay_blocks + 1) / chunk_size)` chunks
  (`upgrade_min_lead_chunks`, from the block's authenticated evidence anchor;
  2,364 chunks at the defaults): stake unbonded in the block after enactment
  matures and is withdrawn under the current programs even when enactment falls in
  the last block of its chunk.
- `activate_at_chunk`, or a fork's `count`, must lie in
  `[current + L, current + L + UPGRADE_ACTIVATION_WINDOW_CHUNKS − 1]`
  (window 1,024 chunks) at proposal, and every vote, the enacting one included,
  requires it to remain at least `L` chunks ahead.
- A proposal without quorum expires `UPGRADE_VOTING_PERIOD_CHUNKS` (64) chunks
  after its proposal chunk. Votes and views ignore it at once; it leaves the slot
  on the slot's next write.

Content of proposals:

- A program proposal names a complete set whose Fact identity equals the pinned
  one (checked at proposal and at every vote) and the program-lane content
  hashes of its artifacts (`ProgramArtifacts`: runtime, fact, evidence, block).
  Every program the switch changes must name a nonzero artifact hash. A proposal
  may distribute the unchanged Fact artifact but never replaces its key.
- A fork proposal names the count and the nonzero commitment of the successor's
  pinned programs, which `neutrin0-cli fork programs` prints for a binary.
- The runtime cannot run SP1 setup, so it cannot check that named digests or a
  successor commitment match any code. Voters are accountable for the pairing:
  builds are reproducible (the Guest ELFs and the WASM are built with the
  workspace root and the Cargo home remapped to fixed prefixes, so content hashes
  depend only on the code and the toolchain), and voters rebuild and audit before
  voting.

Block-start housekeeping deletes a schedule whose activation chunk has been
reached (the Chunk Guest consumed it at the boundary entering that chunk, or
found it void), and at or beyond a fork's count deletes the fork record together
with any remaining schedule, which was enacted for the predecessor's programs. It
reads no proposal slot, and a block without program-lane pieces reads neither the
slots nor the piece record. The Chunk Guest ignores stale and malformed records
regardless, so housekeeping is tidiness, not safety.

Mempool admission has no chunk context and checks signature, nonce, fee,
membership and structure; chunk-relative rules are enforced at execution. The
`upgrade_status` runtime query returns every slot's stored proposals, the pending
schedule with its availability, the pending policy and the scheduled fork.
`neutrin0-cli governance` builds proposals: `propose-upgrade` from a
`runtime-package` file with the activation window checked locally,
`cancel-upgrade` against the enacted switch, `propose-policy` changing named
fields of the policy in force, `propose-fork`, `cancel-fork` and `vote`.

### Governable runtime policy

`RuntimePolicy` lives in runtime state under `runtime:policy`. Genesis seeds it
from the specification's `[runtime]` values, except the reporter reward, which
starts at 1,000 bps. The STF, mempool admission and the node's evidence selection
all read it from state, so a policy change needs no new programs.

| Field | Default | Stake risk |
| --- | --- | --- |
| `min_validator_stake` | 32 tokens | no |
| `evidence_max_age_blocks` | 1,024 | yes |
| `evidence_max_pending` | 1,024 | no |
| `evidence_admissions_per_block` | 16 | no |
| `evidence_executions_per_block` | 16 | no |
| `inactivity_leak_amount` | 0 | yes |
| `reporter_reward_bps` | 1,000 | yes |
| `chunk_prover_fee_bps` | 5,000 | no |
| `annual_issuance_bps` | 200 | no |
| `abandonment_penalty_amount` | 1 token | yes |

The evidence fields and deductions are specified in
[evidence proofs](16-evidence-proofs.md#parameters), the fee share and issuance
in the [proof market](08-proof-market.md). The minimum stake is always positive;
registration and stake must reach it and a partial unstake may not leave a
validator below it, while a full exit to zero is always allowed. A safety slash
always takes the whole slashable balance and has no governed amount. Transaction
fees are the EVM runtime's EIP-1559 fees, not a policy field.

A policy is valid when its counts are positive and within the queue bounds, its
basis-point fields are at most 10,000, `evidence_max_age_blocks` is strictly
below the genesis-fixed unbonding delay, a nonzero inactivity leak comes with a
window of at least three chunks, and its mandatory per-block gas fits the block
gas limit. The STF receives the unbonding delay and chunk size through the
evidence anchor for this check. Liveness offence markers are retained for the
unbonding delay, independent of the governable window, so widening the window
never resurrects a swept offence.

`proposePolicy` opens a `ProposalAction::Policy` proposal; quorum writes it as
the `PendingPolicy { policy, effective_height }` under `runtime:policy:pending`,
replacing any pending one. It takes effect at block start of its effective
height:

- a change of a stake-risk field waits one unbonding delay plus two blocks, so
  stake a dissenter unbonds in the block after enactment matures and is
  withdrawn under the old policy;
- any other change waits `POLICY_DELAY_CHUNKS` (64) chunks.

The STF treats a mandatory sanction queue longer than `evidence_max_pending` as
an invariant violation. A policy whose bound is below the live queue therefore
cannot be proposed, the vote that would enact it fails and leaves the proposal
open, and a pending policy waits at its effective height until the queue fits.
Payments are never repriced: each block records what it owes the proof market
under the policy in force when it executes, and settlement pays exactly that
([proof market](08-proof-market.md)). Neither the chain binding nor block public
inputs carry a fee rate; fees follow from authenticated state.

## On-chain program distribution

Program bytes travel in the block body's program lane, never read by the STF and
never stored in the state trie ([block format](05-block-format.md#body)):

```rust
pub struct ProgramPiece { pub root: Hash, pub total_len: u32, pub offset: u32,
                          pub bytes: Vec<u8>, pub opening: MerkleOpening }
pub struct ProgramPieceDescriptor { pub root: Hash, pub total_len: u32, pub offset: u32,
                                    pub bytes_hash: Hash, pub opening: MerkleOpening }
pub struct ProgramPieceRef { pub artifact: Hash, pub index: u64, pub count: u64 }
// content_hash = tagged_commitment("neutrin0-program-artifact", (total_len, root))
// root = Merkle root of BLAKE3(piece_i); the opening proves BLAKE3(bytes) at index offset / 512 KiB
```

| Bound | Value |
| --- | --- |
| Piece size (all but the last) | 512 KiB (`MAX_PROGRAM_PIECE_BYTES`) |
| Pieces per block | 2 (`MAX_PROGRAM_PIECES_PER_BLOCK`) |
| Artifact size | 16 MiB (`MAX_PROGRAM_BYTES`) |

Every piece authenticates on its own against its artifact's content hash, so a
forged piece is dropped on arrival and never spoils the reassembly of an honest
artifact. The header's DA root commits the lane through the descriptors, which
bind each piece's bytes by their BLAKE3 hash; the Chunk Guest sees the
descriptors (`ConsensusBody::program_pieces`) and never the bytes. Block import
refuses bodies with unauthenticated pieces or more than two.

Package integrity checksums use raw BLAKE3, and the runtime code identity is the
raw BLAKE3 of the WASM. Governance names artifacts by the program-lane content
hash above, which `RuntimePackage::distribution_artifacts()` returns and
`neutrin0-cli runtime-package` prints.

### Artifact availability

A switch activates only if the network can obtain its programs. The executing
node hands the runtime the block's `ProgramPieceRef`s as
`RuntimeBlockInput.program_pieces`, and the block output commits them. The Chunk
Guest requires every descriptor to authenticate against its artifact and the
output's commitment to equal the descriptors' references, so the runtime's view
of the lane is proven. At block start the
runtime records, under `upgrade:pieces`, which pieces have appeared of each
artifact named by a stored program proposal or by an unavailable schedule (as a
bitmap, so an artifact may have at most 64 pieces). Pieces of an artifact nothing
names are ignored, and the record is deleted once nothing names an artifact.

A schedule becomes `available` once the artifact of every program it changes
(runtime, Evidence or Block Guest) has been published completely, counting pieces
published while its proposal was still open; enactment checks this immediately.
An artifact named only for distribution, such as the unchanged Fact program's, is
not required. At the boundary entering `activate_at_chunk` the Chunk Guest
switches only an available schedule. An unavailable one is void: the chain keeps
its programs, no node is asked to execute or prove under programs it cannot
install, and governance may propose the switch again.

### Installation

Nodes assemble only artifacts that the runtime's stored proposals or enacted
schedule name, read through `upgrade_status`. Partial artifacts are counted by
their declared lengths against a 128 MiB budget, and at most eight complete
artifacts (64 MiB) wait in memory for installation. A completed artifact is
installed only if it produces exactly the identity governance declared: a
runtime's BLAKE3 must equal the set's runtime code hash before the module is
compiled, and SP1 setup of a Guest must derive the named digest. Only then is it
persisted under `<data_dir>/programs/<content hash>.bin`, so a restart
reinstalls exactly the approved set.

WASM artifacts are compiled into the executor, which holds one runtime per code
hash and executes each block under the runtime its chunk boundary names. ELF
artifacts go through SP1 setup once and enter the proof backend's program
registry, keyed by the derived verifying-key digest. A node proves and fully
verifies under any installed set and verifies other sets by digest; without the
active artifacts it can verify and follow but cannot prove.

An operator publishes artifacts by dropping files into
`<data_dir>/programs/publish`; the node's producer streams them two pieces per
block. The `programs_status` RPC reports assembly, installation and publication
state, and which programs of the enacted switch the node has not installed
(`scheduled_missing`, also the `neutrin0_upgrade_missing_programs` gauge). A
node missing one at activation cannot execute or verify under it. No switch of
the runtime or execution Guests needs a new node binary.

### Fetching programs from peers

A running node fetches any program the chain names, or the specification pins,
whose bytes it lacks through the `StateByRoot` `Runtime` and `Guest` namespaces
([networking](21-networking.md#requestresponse-protocols)), by identity and with
no state root. Runtime requests name the raw BLAKE3 code hash; Guest requests
name the eight little-endian verifying-key words. Fragments are at most 64 KiB
and an artifact at most 16 MiB. The node checks the content hash the
specification or an enacted switch pins before any SP1 setup, then the identity,
and indexes the bytes in its program store; providers serve from the same store.
Each fragment goes to the fastest provider not backed off, a peer never asked
first. Bytes that do not reproduce the identity are dropped at once and every
provider that served them backs off, so the artifact comes from others; an
assembled artifact that has not installed within ten minutes is fetched again.
Archives and reporters recover the old Block Guests and runtimes their retained
records name this way.

Snapshot bootstrap past a switch uses the same namespaces
([recursive history](13-recursive-history.md)). The requirements come from the
authenticated endpoint `ProgramSet` and the preceding eight historical contexts,
never from a peer-supplied manifest, and partial program downloads share the
durable snapshot journal. A Guest is authenticated when its last fragment
arrives, while the provider that sent every byte is known: a genesis Guest must
first match the specification's content pin, then SP1 setup under the proving
budget must derive the requested identity. A failure resets that artifact only,
rejects the response and backs the provider off; authenticated trie progress is
kept. A Guest a past switch activated has no content pin left in state, so setup
alone authenticates it. Installation repeats setup from the verifying-key cache
before registry insertion, and code bytes reach the program directory before
registry exposure and the atomic state installation. The runtime that produced
the endpoint state is retained even when the next chunk switches, and current,
recent historical and reporter-retained programs are restored under their
authenticated identities on restart.

## Chain identity

The chain specification pins every genesis program identity:
`runtime_code_hash`, `genesis_execution { fact, evidence, block }` and
`genesis_chunk`, plus the program-lane content hashes of the five artifacts
(`genesis_artifacts`). The genesis boundary's program set and the chain binding
come from it; a node binary only supplies bytes, and accepts them only when they
reproduce the pins: the WASM's BLAKE3 must equal `runtime_code_hash` and SP1
setup run locally must derive each pinned key. For each artifact a node uses its
embedded bytes when they reproduce the pin and otherwise reads
`<data_dir>/programs/<content hash>.bin`, which it can also fetch from peers. The
proof backend is built from exactly those bytes and refuses to start if its keys
differ; the engine enables chunk consensus only under a backend whose Chunk key
is the pinned one.

In `chain-spec.toml` the pins form a required `[programs]` table:
`runtime_code_hash`, `fact_vk`, `evidence_vk`, `block_vk` and `chunk_vk` (keys as
32-byte hex of eight little-endian words) and the optional
`runtime_artifact`, `fact_artifact`, `evidence_artifact`, `block_artifact` and
`chunk_artifact` content hashes (zero or absent where an artifact is not
distributed). A file without the table derives no specification and a node
refuses to start from it. Pinning is the explicit authoring step
(`ChainSpecFile::pin_embedded_programs`), which `neutrin0-cli genesis` runs
when the table is absent and `--write` appends; nothing falls back to whatever
programs a binary embeds. The genesis Fact program's correctness is a fixed
trust assumption of the chain: governance cannot later replace its BLS, VRF, POP
or proof-verdict semantics while keeping the chain identity.

## Scheduled forks

The runtime stores at most one enacted hard fork under `fork:scheduled`
(`neutrin0_consensus_types::runtime::FORK_KEY`):

```rust
pub struct ScheduledFork { pub count: u64, pub successor: Hash }  // first chunk the successor proves
pub struct PinnedPrograms { pub programs: ProgramSet, pub chunk: [u32; 8], pub artifacts: GenesisArtifacts }
// successor = tagged_commitment(DOMAIN_PINNED_PROGRAMS, pinned_programs)
```

`successor` commits what the successor specification pins at its start: its
runtime and execution Guests, its Chunk Guest and the content hashes of all five
artifacts, so it names one exact build. The Chunk Guest reads the record from the
same post-state witness as the candidate record and the upgrade
(`rotation::fork_entering`): the boundary entering chunk `c` carries the fork
while `count >= c`, so every boundary from the enacting chunk's end to the count
names it, and a record that does not decode schedules nothing. Its layout is
frozen consensus ABI like the upgrade record's.

The boundary entering `count` is the chain's endpoint. The Chunk Guest refuses
every chunk at or beyond the count of the fork its start boundary carries
(`ConsensusBoundary::proves`), so no chunk of this chain from `count` on can be
proven, whoever runs which binary. The engine signs and produces nothing for
those chunks (`SigningViolation::Halted`, judged from the latest certified,
projected or finalized boundary). The predecessor's last finalized chunk is
therefore `count − 1` by consensus rule: validators that never upgraded halt at
the same place, and no stake can finalize a predecessor chunk at or beyond the
count, so a predecessor and its successor never both finalize one chunk number.
The first block of chunk `count` belongs to the successor, whose block-start
housekeeping deletes the fork record and any remaining switch.

Forks exist only by governance: a chain that cannot finalize cannot
schedule one, and its operators can only restart it from a new genesis.

## Hard fork handoff

A successor specification carries a `ForkAnchor` under `[fork]`:

```rust
pub struct ForkAnchor {
    pub predecessor: Hash,              // complete hash of the specification it replaces
    pub count: u64,                     // first chunk it proves
    pub endpoint_programs: ProgramSet,  // predecessor's programs at its endpoint
    pub start: ConsensusBoundary,       // fork_start of the endpoint
    pub endpoint_prover: Hash,          // runtime account that proved chunk count - 1
    pub prior_domains: Vec<PriorDomain>,// every predecessor's domain, oldest first, at most 4
}
pub struct PriorDomain { pub chain_spec_hash: Hash, pub end_chunk: u64, pub end_height: u64 }
```

`start` is the predecessor's endpoint with the successor's starting programs and
without the fork (`ConsensusBoundary::fork_start`). `ChainSpec::fork_endpoint`
rebuilds the endpoint whole: `start` with `endpoint_programs` and the fork,
scheduled for the commitment of this specification's own pinned programs. The
specification therefore pins the exact boundary the predecessor's History proof
of chunk `count − 1` must end at. A successor whose programs differ from the ones
governance scheduled names an endpoint the predecessor never had, so no
specification derives from it and no endpoint snapshot installs under it.
Validation requires `count > 0`, a nonzero predecessor, complete program sets,
a runtime-account endpoint prover, `start.next_chunk_id == count` with matching
height, `start.programs` equal to the specification's starting programs, no fork
in `start`, and a last prior domain naming the predecessor and ending at `count`.

A fork keeps the chain identifier, the chunk size and the genesis fields
(genesis time, block hash and state root), so the original genesis stays a
boundary without a header: evidence against block 1 names no parent there, as
evidence against the fork's first block does at `start`. The successor's first
chunk is `count`, which ratifies nothing. History restarts there: the Chunk Guest
proves no chunk below `count`, and its first chunk must start exactly at `start`,
as chunk 0 starts at genesis. Light clients, bootstrap and the engine trust
`ConsensusBoundary::first(spec)`, genesis or `start`, exactly as they trust
genesis.

The first chunk still carries chunk `count − 1`'s certificate
(`ChainSpec::carried_chunk`), verified under the predecessor's domain and judged
by the predecessor's ratification rule (`ConsensusDomain::previous_chunk`), so the
predecessor's last reports settle and its block provers, committee and the chunk
prover it ratified are paid. The first chunk's Guest cannot verify chunk
`count − 1`'s proof, so instead of ratifying it the report credits
`endpoint_prover` with that chunk's escrowed prover share
(`ChainSpec::pinned_chunk_prover`).

Signatures follow the Ethereum fork-version model. The successor's
`ConsensusDomain` carries the prior domains, and a signature on chunk `c`
verifies under the domain in force at `c` (`ConsensusDomain::at_chunk`, and
`at_height` for headers, where a prior domain covers heights up to its
`end_height = end_chunk × chunk_size`), natively and in the Chunk and Evidence
Guests, so pre-fork safety evidence stays punishable. The exception is
`InvalidProofSigning`: a proof's rejection is relative to the verifier that
judges it, which the fork may replace, so proof acceptances signed before the
fork lapse with it ([evidence proofs](16-evidence-proofs.md#invalid-proof-acceptance)).
Everything signed after the fork binds the new specification, and the signing
journal refuses any chunk below `count` (`SigningViolation::PriorDomain`). The
fork tooling refuses a successor that would carry a fifth prior domain.

### Producing a fork

No database is rewritten in place: every successor node starts in a new data
directory, and the predecessor's directory stays as it was.

1. Governance schedules the fork on the predecessor with
   `proposeFork(F, successor)`, where `successor` is what
   `neutrin0-cli fork programs` prints for the successor's binary. Its lead lets
   dissenters withdraw first and every operator install the successor's binary
   beside the running one.
2. Consensus ends the chain: the boundary entering `F` is the endpoint, nothing
   from `F` on is signed, produced or provable, and chunk `F − 1` is the
   predecessor's last finalized chunk.
3. Once a node's finality reaches the endpoint (a node that was down catches up
   first), it writes the endpoint bundle into `<data_dir>/fork-endpoint`, staged
   in a sibling directory and renamed into place so a bundle that exists is
   complete, and exits with status 10 (`fork::EXIT_FORK_ENDPOINT`; supervisors
   should not restart it on that status). Restarting the predecessor's binary
   keeps the bundle and stops again. The bundle holds:
   - `successor.toml`: the predecessor's file with its genesis state root pinned
     (the successor's programs would derive another), without its `[programs]`
     table and with the `[fork]` table (predecessor hash, endpoint boundary,
     endpoint prover from the endpoint receipt, every prior domain with the
     predecessor's appended);
   - `snapshot.bin`: the endpoint snapshot file;
   - `carry.bin`: what the directory retained beyond the endpoint;
   - `signing.bin`: its signing protection.
4. The operator starts the successor's binary with a new `data_dir` and
   `[bootstrap] fork_from` naming the predecessor's, leaving `chain_spec_path`
   and `snapshot_path` unset. On first start the node completes `successor.toml`
   with its own `[programs]` table, derives the specification (which fails for
   programs the endpoint did not schedule) and writes it to
   `<data_dir>/chain-spec.toml`; later starts read that file. Before its engine
   opens it imports the signing protection, keeping only the proposer slot
   watermarks rebound to the successor (`SigningTransfer::for_successor`): slots
   run on across the fork, so no slot a validator proposed at can carry a second
   header, while votes, messages and sessions stay behind, since the successor
   signs no chunk below `F` and later chunks only under its own domain. A
   directory that already records its chain is not imported into again
   ([validator keys](19-validator-keys.md)).
5. It installs the endpoint snapshot as its start (`Engine::install_fork_start`).
   A forked node never materialises the original genesis state. The snapshot's
   header, validators, History frontier and recent records (whose certificates
   verify under the predecessor's domain) must reproduce `start`, and its state
   and sanctions tries must hash to the roots `start` names. Its History proof is
   not verified: the start is trusted as genesis is, and that proof may need the
   predecessor's SP1 version. The successor's History proof is its own first chunk
   receipt. An archive starts there too; the sources below the fork stay in the
   predecessor's directory.
6. It imports the carry once (`ChainStore::export_fork_carry`,
   `Engine::import_fork_carry`). The History tree continues across the fork and
   old signatures verify under the predecessor's domain, so what the predecessor
   retained stays valid. Pooled raw offences go into every node (pooled evidence
   receipts stay behind and their raw reports are proven again under the
   successor's programs), a reporter's retention into a reporter, and an
   archive's complete History tree and records into an archive, only from an
   archive. Rows the successor already holds stay as they are, and a tracked
   identity keeps every withdrawal account either side knew. A reporter's watched
   chunks are then reopened under the successor's frontier as after a snapshot
   jump, and the chunks between the predecessor's finality and the successor's
   first retained record are recorded as a gap
   ([reporter nodes](18-reporter-nodes.md)). The bundle is the operator's own
   data, trusted as a signing transfer is; tree nodes are still checked against
   their hashes whenever they are read. An archive that starts at the fork stores
   the tree nodes on its recent records' paths, so it opens those and every later
   chunk on its own; older pre-fork chunks need the carry.

Each of steps 4 to 6 is skipped once done, so a restart resumes the handoff, and
once the carry is imported the predecessor's directory is not read again.

Nodes that join later take the successor's `chain-spec.toml` from any successor
node, compare its hash out of band as they would a genesis, and bootstrap from
the successor's History proofs, or from an endpoint snapshot file
(`[bootstrap] snapshot_path`) before the successor finalizes a chunk of its own.
Without a carry, a pruned successor opens pre-fork chunks only within its eight
retained records, so for one unbonding delay after the fork older pre-fork
openings come from carried reporters and archives. A light client of the
predecessor stops at the endpoint, where no further proof can exist, and is
reconfigured with the successor's specification, whose start it trusts as it
trusted genesis ([light clients](14-light-clients.md)).

## History recursion across program sets

There is no History Guest ([recursive history](13-recursive-history.md)). Chunk
`N` after the first verifies chunk `N − 1`'s receipt under the specification's
`genesis_chunk` and requires its end boundary to equal this chunk's start,
execution program set and report commitments included; the first chunk starts at
`ConsensusBoundary::first(spec)`. Every receipt of a chain therefore carries the
same binding, and the latest one proves the whole chain across every
execution-program switch. No Guest embeds a verifying key: the Chunk identity is
an input read from the specification the binding commits, and each switch's
legitimacy was proven inside the chunk that performed it.

Because the Chunk Guest never changes within a chain, verifiers anchored at any
boundary trust the same key and there is no cross-Guest composition. A new Chunk
Guest is a new chain binding, and receipts of the old binding do not verify under
the new one.

## Verifiers

- Nodes verify block receipts under the execution program set of the start
  boundary, which they authenticate against their canonical store, and chunk
  receipts, History proofs included, under the Chunk Guest of their own
  specification. Installed programs verify with the full SP1 verifying key
  through an independent light verifier; other identities are verified by
  digest. Neither path accepts mock receipts, and the key never comes from the
  receipt.
- Light clients anchor on a `Checkpoint` whose binding pins the Fact and Chunk
  Guests and whose boundary carries an execution program set. They verify each
  History proof under the binding's Chunk Guest from the specification's start,
  for an endpoint a quorum of sampled peers advertise, and adopt the proven end
  boundary, programs included, as the new endpoint. Program identity comes from
  the genesis pins plus proven governance decisions, never from local
  configuration: the same trust model as the validator set.
- Bootstrap verifies the History proof under its own chain binding and the anchor
  opening of its local trust boundary, program sets included.

## SP1 version upgrades

The recursion precompile verifies only receipts of its own SP1 version, so a
toolchain upgrade breaks chunk-to-chunk recursion: the first chunk under the new
version cannot verify the last receipt of the old one. An SP1 upgrade also
changes the Fact and Chunk identities and therefore the chain binding. Neutrin0
treats it as a hard fork: the successor's `ForkAnchor` pins the switch boundary
as a weak-subjectivity checkpoint, as bootstrap and light clients already do for
their anchors, and History restarts there. There is no Groth16 bridge Guest
that would wrap the last old receipt for verification under the new version.

## Installed-program resource lifetime

Open proposals distribute and persist bounded content only. They trigger no WASM
compilation, SP1 setup or CUDA session; Guest identities are derived and checked
locally before an enacted or current artifact is installed. Replaced proposals
release their partial and completed buffers and unreferenced source material
during reconciliation.

The node derives program retention from the current and head programs, enacted
schedules, authenticated retained consensus, reporter and History records, and
temporarily pinned snapshot dependencies. Snapshot targets are pinned before
their first artifact installation and stay protected through state validation and
durable admission or cancellation. Artifact indices bind a locally checked
identity to its content hash; a cold read loads one file, checks its size and
content hash, and for a runtime its exact WASM hash. Historical runtime queries
never substitute the current runtime.

| Resource | Bound | Notes |
| --- | --- | --- |
| Compiled WASM modules | 8 live, 512 MiB total, 128 MiB per image | Counts evicted modules still leased by running work; accounts retained WASM bytes and Wasmtime image ranges, not compiler allocations, per-call stores or allocator overhead. One compilation runs at a time. Current and scheduled modules stay protected; historical ones reload from authenticated disk sources. |
| SP1 proving keys / CUDA sessions | 16 live (`MAX_RESIDENT_GUESTS`) | Counts evicted keys retained by running or queued work. Each job holds explicit leases before admission; an evicted live key stays resolvable until its last lease drops. Cold key acquisition happens before device admission, without engine or registry locks during SDK setup. Exhaustion keeps sources for retry and never evicts a protected job. |
| CUDA setup attempts | 64 per device per process (`MAX_CUDA_SETUP_ATTEMPTS`) | Counted before each SDK call, failures included. SP1 destroys server sessions asynchronously after the last key reference drops and acknowledges nothing to the registry, so the 16-session bound is a local handle bound. Exhaustion fails closed and keeps authenticated sources. |
| Memory-mode cold sources | 32 artifacts, 256 MiB | Only without a data directory; no restart durability. Protected sources are never displaced; insufficient capacity is an operational error, and chains whose retained dependencies exceed it need disk-backed storage. |

These are local process bounds, not consensus or upgrade parameters, and they do
not bound RSS or VRAM, which depend on the deployment. Recovering from exhausted
CUDA setup attempts needs an operator-confirmed server cleanup or a fresh server
before the node restarts; restarting the node alone does not reclaim remote
sessions. Same-key ELF packaging changes reuse the resident program.

Verification of a historical source key does not need a heavyweight session:
cached verifier material stays on disk, and old receipts verify against their
authenticated key digest without allocating a CUDA session. Missing source bytes
or operational setup failures never become proof-rejection evidence.
