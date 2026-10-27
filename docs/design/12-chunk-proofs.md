# Chunk proofs

The Chunk Guest turns a decided chunk into a single SP1 receipt. It
recursively verifies every compressed block proof of the range against the
pinned Block Guest key and exact public values, verifies the BFT certificate
and the complete consensus transition, and recursively verifies the previous
chunk's receipt. A verified Chunk receipt is the only way a chunk finalizes.
Blocks already proved the state transition, transaction commitments and
accountability effects, so the Guest never serializes transactions or
re-executes them; it checks the consensus facts around them. Native validation
and the Guest share the same code in `neutrin0-prover-chunk`
(`validate_consensus`, `validate_candidate`), so a node knows before voting
exactly what the Guest will accept.

## Trust inputs and recursion

The verifier supplies the trusted chain specification. The incoming context
(parent hash and state, active validators, seed, History root) is not trusted
as given: the specification's first chunk (0, or a hard fork's pinned count)
must start at `ConsensusBoundary::first`, and every later chunk must start
exactly where the recursively verified receipt of the previous chunk ends. A
valid Chunk receipt therefore proves the chain from the specification's start,
and the latest finalized receipt is the
[History proof](13-recursive-history.md); no further Guest consumes Chunk
statements.

Every consensus signature the Guest checks derives `ConsensusDomain` from the
complete supplied specification, exactly as native verification does
([signing domain](09-consensus.md#signing-domain)). A signature on chunk `c`
verifies under the domain in force at `c`, so after a fork the Guest still
checks a predecessor-era certificate or vote under its predecessor's domain.
Recursively authenticated Fact verdicts bind these exact bytes, so a valid
verdict from another specification cannot answer this Guest's request even
when chain id and keys are equal.

The Guest commits

```rust
pub struct ChunkReceiptStatement {
    pub statement: ConsensusStatement, // chain, start, end, chunk, finality_cert_hash
    pub chunk_prover_address: Hash,
}
```

The credited prover account lies outside the consensus statement and must be a
runtime account ([proof market](08-proof-market.md)). `end` is the outgoing
`ConsensusBoundary`: next validator root, identity-sanctions root, seed,
History root, programs and the participation and proving commitments this
chunk consumed.

## Blocks

For each block the Guest authenticates the header projection through the
block's public output, binds the proposer signature and canonical hash, checks
parent, height, slot and state continuity, the slot-start timestamp and the
specification's gas limit ([consensus](09-consensus.md#slots-and-proposers)),
binds the chain, runtime, gas, transaction and receipt commitments, and
verifies the proposer's BLS signature and VRF eligibility.

Compact consensus bodies (`ConsensusBody` in `crates/prover-chunk/src/body.rs`)
keep only what consensus consumes: the participation acknowledgements, the
carried certificate and bytes-free program-piece descriptors. The counted
transaction, vote, program and carried-certificate lanes committed by the
header authenticate those contents without the transaction bytes
([block format](05-block-format.md)). Chunk roots use canonical ordered block,
public-input, VRF and DA leaves. A DA commitment does not prove physical
availability.

## Leader proposal and quorums

The Guest verifies the mandatory signed `BftProposal` against the
authenticated incoming validator set: the designated stake-weighted leader,
the signature, and for a nonzero round a valid weighted round-change
certificate bound into the signature that the proposal's valid QC does not
ignore or downgrade. The proposal's exact chunk and round must match the
finality certificate. These are recursive consensus rules, not host-only
pacemaker assertions ([BFT protocol](10-bft-protocol.md#certified-round-changes)).

It then verifies both value quorum certificates: stake weights, signer
membership, domain, chain, round and chunk binding, and complete attestation
coverage for both phases. Attestations keep individually signed votes and
signed unlock claims; precommits add the counted proof-acceptance commitment.
Each distinct complete manifest appears once in the certificate's dictionary,
and every reference, count, canonical order and exact coverage is checked
before a signature is accepted. Carried QCs are checked independently against
the active set and the configured fraction. A prevote cannot carry its own
round's quorum as an unlock; a precommit may. Earlier locks are proven by
objective evidence, never inferred from missing observations. Nil and
conflicting-proposal offences go through the Evidence Guest
([evidence proofs](16-evidence-proofs.md)). `FinalityCert` is mandatory in the
Chunk proof wire format.

## Committee transition

The Guest derives activations, exits, stake changes and key rotations from the
runtime's authenticated `consensus:candidates` record, the only runtime state
it reads besides the scheduled upgrade and the scheduled fork
([consensus](09-consensus.md#validator-set-rotation)). It verifies the
possession proofs of new and rotated keys; genesis keys carry theirs in the
specification, checked whenever a node loads it, so every seated key has a
verified proof and aggregate-only quorum checks cannot meet a rogue key. It
consumes the block-proven sanctions: safety admissions append permanent bans
to the identity-sanctions trie, and the Guest authenticates every previous,
candidate and offender lookup, absence included, before applying the
transition. Banned and expired seats leave the vector, so dead seats do not
consume its capacity. The node keeps the live sanctions trie and persists it
atomically with finality. Economic replay markers belong to the block runtime;
the consensus trie owns permanent seating exclusion.

## Carried certificate and reports

In every chunk after the specification's first, exactly one block, the carrier
([proof market](08-proof-market.md)), holds the previous chunk's
`CarriedCertificate { quorum, proposal: CompactProposal }`; a hard fork's first
chunk carries its predecessor's last chunk. The Guest opens the previous
chunk's validator set and finalized target from History, verifies the selected
precommit quorum (target, signer membership, signature and stake) and the
compact leader proposal under the domain in force at that chunk, and derives
the `ParticipationReport` and `ProvingReport`. Blocks before the carrier must
consume the start boundary's reports, and the carrier and every later block the
derived ones; the specification's first chunk consumes none. The compact
selection carries the signed vote payload, bitmap and aggregate signature only,
without the earlier proposal's prevote proof, attestations or the complete
finality proof.

The outgoing participation commitment never depends on the current finality
certificate's signer subset: the next chunk makes its own selection before
execution and agreement. History leaves and outgoing boundaries exclude
certificate signer subsets, so alternative valid certificates for one value
produce the same History root and boundary. The block-proof root commits
canonical public inputs, not receipt bytes, so different valid receipt
encodings cannot change the chunk hash.

## Participation acknowledgements

Positive acknowledgements carry an exact precommit vote, its validator index
and individual vote signature, checked against an authenticated historical
target and key. They share the counted vote lane with full vote leaves, at most
`MAX_PARTICIPATION_ACKS` (512) per block and `MAX_PARTICIPATION_VOTE_BYTES`
(2 MiB) per block and per chunk. Within one chunk each source seat (source chunk
and validator index) appears at most once across every block: a precommit of
the same seat in another round or with another selection adds no
acknowledgement, only work, so the Guest and block import refuse it. An
acknowledgement neither claims proof acceptance nor replaces the signed source
used for offences; the inactivity rules are in
[evidence proofs](16-evidence-proofs.md).

## Fact statements

The witness may carry up to `MAX_CONSENSUS_FACT_STATEMENTS` (64) Fact
statements. The Guest verifies each receipt under the pinned Fact key and
answers the signature checks they cover from them; uncovered checks fall back
to the batched in-circuit path, so Chunk proving never waits for the Fact
worker and the committed statement is identical either way. The host selects
receipts from its verified cache after recording the exact requests the chunk
performs. Evidence validity is proven by the Evidence Guest and reaches the
chunk through block recursion; the chunk never reverifies an evidence receipt
or the underlying offence.

## History witnesses

Chunk witnesses contain only the `HistoricalContext` records actually
referenced, fixed 64-level membership paths and an append frontier; they never
enumerate earlier chunks. For incoming chunk `n` only indices
`[n.saturating_sub(8), n)` are admissible. Reads are capped at
`MAX_HISTORY_READS` (8) records and `MAX_HISTORY_CONTEXT_BYTES` (256 KiB) of
encoded context, with `MAX_HISTORY_CONTEXT_RECORD_BYTES` (32 KiB) per record
enforced while decoding. The frontier proves the old-root to new-root append
inside the Guest without a complete tree.

A `HistoricalContext` holds the chunk, its validator vector and seed, its
source program identities (Block Guest key digest and runtime code hash) and
the commitment of its start boundary, which lets a History leaf place that
boundary on any later chain as a light-client or bootstrap anchor. It omits
the chunk's finality certificate, which complete verification already
authenticated before appending the leaf. How ordinary and archive nodes obtain
paths, and the full `HistoricalChunk` and `HistoricalOpening` objects used by
bootstrap, reporters and offences, are in
[recursive history](13-recursive-history.md).

## Provability before voting

Finality waits for the Chunk proof and a certificate is never withdrawn, so a
certified chunk the Guest could not prove would halt the chain. Voters
therefore run the Guest's own rules before voting: `validate_candidate`, the
code the Guest runs up to finality, including the successor derivation that
reads the authenticated upgrade record and builds the outgoing boundary, and
`provable_candidate`, which applies the Guest's one input bound,
`MAX_CHUNK_WITNESS_BYTES` (64 MiB) on the encoded witness, keeping room for the
certificate, Fact statements and ratified statement attached after the vote. A
candidate outside either is refused as a conflict. The Guest asserts the same
bound and the host refuses to prove past it. A chunk that native validation
accepts and the Guest refuses is an implementation bug, repaired by hard fork;
no protocol path abandons a certificate.

## Finalization

The node validates the candidate before BFT, obtains the certificate, proves
outside the engine lock and verifies the receipt before atomically persisting
finality and the next context. Gossip and RPC imports go through the same
checks. There is no proofless or execution-only finalization path. Before the
proof finishes, verified block receipts and full native validation can
authorize execution of one successor chunk; the eventual proof must reproduce
that exact outgoing boundary
([certified execution](11-certified-execution.md)).

## Shared proof-acceptance manifests

A precommit attestation's `ProofAcceptanceCommitment { count, root }` commits
the exact ordered block-proof envelopes the signer accepted. Leaf `i` is
`BLAKE3(DOMAIN_BLOCK_PROOF || borsh(BlockProof))`, covering the complete proof
bytes, the receipt's attribution and its statement key
([proof market](08-proof-market.md)), placed in a canonical counted tree under
its own leaf, node and root domains. The leaves are the receipts the round's
accepted proposal names, one per height; before a proposal a session carries
its locally preferred receipts, and accepting a proposal replaces them. The
signed vote and the specification domain scope the commitment to its chain,
chunk and target. The semantic `block_proof_root` is a public-input commitment
and cannot substitute for this exact-byte tree.

Votes and certificates carry each distinct ordered `ProofManifest` once,
sorted by commitment. Every precommit must resolve a manifest and every
dictionary entry must be used; prevotes have neither commitments nor
manifests. Distinct valid receipt encodings stay distinct manifests. The
dictionary's usual size is proportional to signers plus blocks, its worst case
one manifest per signer, within the committee bounds and decoding limits.

An `InvalidProofSigning` report supplies the exact rejected envelope and one
position- and count-bound opening under the individually signed commitment;
changing its position, count, siblings or bytes cannot establish acceptance.
Rejection is checked under the source Block key and runtime taken from
authenticated history, never from a trust profile the signer chose. Missing
sources or a failed local verification never establish misconduct.

## Guest signature work

Candidate and certificate verification share a checked public-key cache and a
bounded BLS equation batch (`crates/prover-chunk/src/bls/`). Signatures,
aggregates, attestation votes and signatures, and proposer and VRF signatures
use the same verifier. Curve, subgroup and non-identity checks precede
batching; membership, stake thresholds, possession-proof provenance and domain
bindings stay mandatory. Exact duplicate equations are checked once. A single
equation is verified directly; larger groups share one final exponentiation and
group equal messages into one Miller-loop term.

Validation-local caches bound repeated signature decoding, aggregate-key
construction and prepared message points; only checked points enter a cache,
and eviction changes work, never validity. MSM windows reuse bounded bucket
workspaces. Fact preparation groups equivalent message and cipher-suite work
before packing 64-item batches, keeping canonical statement order and exact
request identities. Host-side discovery uses native BLST; the Guest uses the
portable, SP1-patched equations.

Batch coefficients are nonzero full-field scalars derived with SHA-512 from a
length-framed transcript of every key, message, signature and cipher-suite DST,
the batch length and the equation index. They are deterministic Fiat-Shamir
challenges, never prover-chosen weights; the security argument is in the
random-oracle model, and unweighted summation would let invalid signatures
cancel. At most `MAX_BATCH_EQUATIONS` (64) are pending, and the final batch
must succeed before a consensus statement is committed. Negative decisions (a
dishonest unlock, a rejected proof) use individual checks or proven Fact
verdicts, never a pending positive batch. Registration possession proofs keep
their immediate verdict, because the rotation rule ignores invalid
registrations. See [fast verification of multiple BLS signatures](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407)
and [its security conditions](https://ethresear.ch/t/security-of-bls-batch-verification/10748).

## Real-proof verification

Native tests cover adversarial boundaries, signatures and quorums, proof keys,
rotation and accountability. Real compressed composition is a separate gate for
each set of programs: the ignored test `consensus_guest_real_compressed_recursion`
in `crates/runtime-host/tests/consensus_chunk.rs` proves blocks and a Chunk with
the CPU prover, and the evidence-to-chunk path is covered in
[evidence proofs](16-evidence-proofs.md).
