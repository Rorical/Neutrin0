# Proof system

Every proof in the chain is an SP1 6.10.0 Compressed STARK. Four Guest programs
compose by SP1's optimized recursive verification, so a single chunk receipt
covers execution, evidence, consensus and the whole chain before it, and a
verifier checks one proof with a key it already trusts. The split keeps each
Guest small enough to change on its own schedule: execution programs are
governable, while the cryptographic Fact Guest and the Chunk Guest are pinned
by the chain specification.

## Proof stages

| Proof | Establishes | Consumed by |
| --- | --- | --- |
| Fact proof | An exact signature or aggregate-signature verdict, or the rejection of a block receipt | Evidence Guest, by recursion |
| Evidence proof | A batch of objective offences and their historical membership | Block Guest, by recursion |
| Block proof (receipt) | The state transition over authenticated state, its execution commitments and admitted sanctions | Chunk Guest, by recursion |
| Chunk proof | Block composition and continuity, BFT finality, VRF eligibility, validator rotation, the compact next boundary and the previous chunk's receipt | Node finalization and import, and the next Chunk Guest |
| History proof | The latest finalized chunk proof: the chain from the specification's start under one chain binding, across program switches | Light clients and snapshot bootstrap |

Transactions are checked inside the block state transition; there is no
separate transaction proof. Fact-to-evidence, evidence-to-block,
block-to-chunk and chunk-to-chunk composition all use SP1's optimized recursive
verification syscall.

There is no History Guest. Each Chunk Guest after the specification's first
chunk verifies the previous chunk's receipt and requires it to end exactly at
its own start boundary, and the first chunk starts at the specification's first
boundary (genesis, or a hard fork's start), so the latest finalized receipt
proves the chain from there. Boundaries carry no link to their predecessors.
See [recursive history](13-recursive-history.md).

Evidence transactions commit statements and historical openings; evidence
receipts are interchangeable witnesses outside transaction and DA commitments,
and ordinary execution verifies the actual attachments under the pinned
Evidence program. The deterministic exact-byte receipt verifier runs in the
Fact Guest only to establish that a block receipt is rejected, for signed
acceptance of an invalid receipt. A receipt an offence needs valid is verified
by recursion in the Evidence Guest under its source Block program, so no Guest
proves acceptance with a software verifier. See [evidence
proofs](16-evidence-proofs.md).

## Program identities and trust

The Fact Guest is immutable per chain. The specification pins it as
`ChainSpec.genesis_execution.fact`, the chain binding commits the
specification, and the Fact key repeated in every boundary must equal it. Chunk
signature checks reuse Fact verdicts without recomputing their equations, so a
governable Fact Guest would move the cryptographic trust boundary even with an
immutable Chunk Guest. The correctness of the pinned Fact program is a genesis
trust assumption; changing it, the Chunk Guest or the SP1 version is a hard
fork ([upgrades and forks](20-upgrades-and-forks.md)).

The runtime, Evidence and Block programs are governable. Their artifact checks
establish which code ran, not that newly approved code is correct. A receipt is
verified under the program set of its chunk's start boundary, never one the
receipt names.

## Verification

`ProofSystem` (in `neutrin0-proof-system`) exposes block, evidence and
complete consensus operations: `prove_block`, `verify_block`,
`classify_block_rejection`, `prove_evidence_batch`, `verify_evidence`,
`prove_consensus_chunk`, `verify_consensus_chunk` and `verify_history`. A
verifier pins the program identity, the chain specification and the incoming
context; SP1 verifies the compressed receipt and the caller compares its
committed public values with the expected statement. A nonzero Guest exit, a
malformed proof or a mismatched statement is rejected.

A receipt has exactly one accepted encoding. The host decodes it, refuses a TEE
attestation (which verification would ignore) and requires the bytes to equal
their canonical re-encoding, because SP1 release builds decode a field element
from any `u32` modulo the field prime. The Fact and Evidence Guests decode by
the same rule, so a signed acceptance of another encoding is objectively
malformed everywhere.

History verification and the chunk and block adapters accept only real
compressed receipts, even when a caller configures the SP1 mock prover; mock
output never verifies under a pinned key. `MockProofSystem` supplies
deterministic block fixtures for isolated consensus tests and cannot finalize a
chunk or produce History acceptance.

The host decodes a block receipt once per verification and keeps a bounded
cache (64 entries, 32 MiB) of authenticated typed receipts for chunk preparation
and proving. Entries bind the exact receipt bytes and the adapter's program
identity, and every call still checks the expected public inputs. Fresh
evidence receipts are verified as typed objects before encoding and flow
directly into local publication and storage; external inputs are verified
independently. Distinct evidence envelopes are each verified even when they
declare the same batch root; identical bytes share one verification and one
recursive stream entry per batch.

## Keys and backends

The host caches verifying keys on disk by SP1 circuit version and ELF hash.
Changing a Guest changes its identity, and incompatible artifacts are never
accepted through another aggregation API.

The node selects CPU or CUDA at startup for all four proof stages
(`[proving] backend`). CUDA needs the `cuda` build feature, Linux x86-64 and an
NVIDIA GPU; an unsupported build or platform, or an initialization failure,
refuses startup with no CPU fallback. `ProgramProver` keeps CPU's disk-cached
preprocessing and CUDA's live server session keys, every CUDA setup compares
the returned verifying key with the locally derived one. Every program's keys,
the Chunk Guest's included, live in one in-process registry that block, chunk
and history proving and verification share; each is set up once, from the
on-disk verifying-key cache when it holds the ELF. Receipt formats, Guest ELFs, recursive
verification and consensus rules are identical on both backends. Operation is
described in [GPU proving](../gpu-proving.md).

## Block proving pipeline

Block proving snapshots its immutable input under the engine lock, proves and
verifies outside it, then rechecks the stored header and witness and commits
the proof and block state atomically, so concurrent imports or finalization
never regress state. The node queues block hashes rather than witnesses,
deduplicates work, recovers pending canonical witnesses after a restart and
handles completions in any order. Each completion checks whether its chunk can
open a BFT session.

| `[proving]` key | Default | Meaning |
| --- | --- | --- |
| `backend` | `cpu` | `cpu` or `cuda` for every stage |
| `concurrency` | 2 | Simultaneous proving calls across all stages (1 to 64) |
| `capacity` | 16 | Queued plus running block jobs (at least `concurrency`, at most 1024) |

A full queue pauses production, and a producing validator keeps one queue slot
for its own next block. A failed job retries on a later slot. Which blocks a
node proves and when it starts a chunk proof are set by the proof market's
scheduling keys ([proof market](08-proof-market.md)).

## Block proving input envelope

`ProofParams.max_block_proving_input_bytes` is an immutable chain-spec
parameter: 32 MiB by default, positive and at most the 128 MiB absolute
ceiling `MAX_BLOCK_PROVING_INPUT_BYTES`. Every block's evidence anchor echoes
it, and the Chunk Guest rebuilds the anchor from the locally authenticated
specification.

The envelope covers the persisted `BlockWitness`: execution input, state
openings and ordered evidence attachments. Ordinary execution rejects an
oversized witness before publishing its post-state. Production drops user
transactions before signing while keeping the mandatory system and evidence
work. Host serialization refuses a write that would grow past the envelope,
host decoding checks the absolute ceiling before decoding and the anchor's
ceiling after, and each Block Guest checks its input blob against both before
execution. The recursive proof stream keeps its own receipt size and count
limits.

These checks bound encoded inputs only, not SDK allocations, compiler memory,
instruction counts or proof latency. An authorized runtime upgrade must still
keep mandatory work affordable and provable within the network's schedule; a
gas ceiling alone does not establish that for Osaka's software precompiles.

## Verifying real composition

Workspace tests run native and Guest execution and mock recursion. Real
compressed composition is a separate gate, run by the ignored tests in
`crates/runtime-host/tests`: `evidence_block_chunk_real_compressed_recursion`
(EvidenceProof to block to chunk), `history_real_compressed_chunk_recursion`
(chunk to chunk) and their CUDA variants. A result holds only for the ELFs it
ran; any Guest change requires running them again.
