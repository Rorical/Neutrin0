# Block and proof formats

This document fixes the wire and hashing layout of blocks, block receipts,
chunks, chunk proofs and the consensus messages that travel with them. Every
canonical object is Borsh, and every commitment is BLAKE3 over a type-specific
domain tag followed by the encoding, so one hash names exactly one value of one
type. The authoritative field layouts are `neutrin0-consensus-types` and
`neutrin0-primitives`; this document states the rules those layouts implement.

## Encoding and hashing

- The wire codec is Borsh. Types, fields, protocol paths and stored metadata
  carry no format version; an incompatible change replaces the format.
- The chain hash is BLAKE3 (`primitives::blake3_256`). SHA-256 and Keccak-256
  appear only on compatibility surfaces such as the EVM.
- Every hash of a Borsh value prepends a 16-byte domain tag naming its type: the
  header hash (`DOMAIN_HEADER`), the chunk hash (`DOMAIN_CHUNK`), the
  chain-spec hash (`DOMAIN_CHAIN_SPEC`), the validator-set root
  (`DOMAIN_VALIDATORS`) and every value that `evidence::commitment` covers,
  through its type's `Committed::COMMITMENT_TAG`. Separation between committed
  types never rests on their encodings having different lengths.
- Domain tags are prepended by callers; the crypto crate signs and hashes the
  bytes it is given. The `DOMAIN_*` constants live in
  `crates/primitives/src/lib.rs`.
- Program and configuration identities are content hashes, which authenticate
  them without a version field.

## Header

| Field | Meaning |
| --- | --- |
| `height`, `slot`, `parent_hash` | Position on the chain; `timestamp` equals the slot start |
| `proposer_index`, `vrf_proof` | Proposer seat in the active set and its slot-eligibility VRF proof |
| `state_root` | Post-execution state root |
| `transactions_root` | Counted, tagged root of the transaction lane |
| `votes_root` | Root of the participation-acknowledgement lane |
| `da_root` | Counted commitment of all four body lanes |
| `runtime_extra` | Runtime commitment: the post-block validator-set root |
| `inputs_root` | Commitment of the execution inputs the block consumed ([proof market](08-proof-market.md)) |
| `receipts_root` | `body.artifacts.commitment()`: the runtime's receipts, transaction ids and metadata |
| `gas_used`, `gas_limit` | Gas consumed and the block ceiling |
| `timestamp` | Slot start in seconds since the UNIX epoch |
| `signature` | Proposer BLS signature |

`Header::hash` is `BLAKE3(DOMAIN_HEADER || borsh(header without signature))`.
That hash is also the payload the proposer signs under `DOMAIN_PROPOSER_SIG`,
so the block hash binds every field the signature covers and nothing else.

## Body

```rust
pub struct Body {
    pub artifacts: ExecutionArtifacts,          // committed by receipts_root
    pub transactions: Vec<Vec<u8>>,             // lane 0
    pub participation_acks: Vec<ParticipationVote>, // lane 1, at most 512
    pub participation: Option<CarriedCertificate>,  // lane 3, the carrier only
    pub evidence_proofs: Vec<EvidenceArtifact>, // outside every header root
    pub programs: Vec<ProgramPiece>,            // lane 2
}
```

Four lanes are committed by the DA root. Each lane contributes a leaf
`BLAKE3(DOMAIN_DA_LANE || lane index || u32 LE count || lane root)`, and the DA
root is the Merkle root of the four leaves. Counts prevent ambiguous tree
shapes. The lanes are:

| Lane | Contents | Root |
| --- | --- | --- |
| 0 | Runtime transaction blobs | `transactions_root` |
| 1 | Compact participation acknowledgements | `votes_root` |
| 2 | Program-artifact pieces ([upgrades](20-upgrades-and-forks.md)) | Merkle root of the bytes-free piece descriptors |
| 3 | The previous chunk's carried certificate | Merkle root of zero or one entry |

The transaction root is counted and tagged on its own: leaves are
`BLAKE3(DOMAIN_TX_LEAF || u32 LE len || blob)`, inner nodes use
`DOMAIN_TX_NODE`, an odd node is promoted, and the root is
`BLAKE3(DOMAIN_TX_ROOT || u32 LE count || top)`. Block receipts bind the
transaction root without the DA root, so this root alone must name exactly one
transaction list; a valid receipt can never be presented for a different list
behind an honest header. These commitments establish contents. They do not
establish physical availability or erasure-code correctness.

Validator operations and `SubmitEvidence` admissions are runtime transactions;
there is no separate sanction or validator-operation lane. Evidence proofs are
interchangeable witnesses carried beside the transactions they serve, outside
every header commitment, so proof encoding never changes transaction identity
([evidence proofs](16-evidence-proofs.md)).

The program lane carries upgrade artifact bytes; the state transition never
reads it, and the Chunk Guest commits only the piece descriptors.

### Participation acknowledgements

A `ParticipationVote` is an exact precommit payload (`FinalityVoteData`), the
signer's index in the historical source committee and its individual
signature, never an aggregate. Its authenticated historical target and
challenge timing are checked before execution input records are derived from
it. Each source seat is acknowledged at most once per chunk, so a repeated
precommit of the same seat adds signature work and no acknowledgement. The
lane holds acknowledgements only; live BFT votes travel on their own topics and
are never embedded in a body. Complete attested sources stay in the
availability and reporter stores for accountability
([evidence availability](17-evidence-availability.md)).

### Carried certificate

Exactly one block of every chunk after the specification's first holds the
previous chunk's `CarriedCertificate { quorum, proposal: CompactProposal }`,
the precommit quorum and the compact leader proposal. The carrier rule, the
reports derived from the certificate and the `inputs_root` binding are
specified in [the proof market](08-proof-market.md). The carried quorum
authenticates participation in the previous chunk through the block's incoming
boundary; it authorizes no finalization and unlocks no vote.

## Block receipt

A `BlockProof` is the retained form of a receipt: height and hash, the
`BlockProofPublicInputs` the node derives from the header, the parent's state
root and the program set of the block's chunk, the backend proof bytes, and the
`prover_address` and `statement_key` read from the verified public values.

| Public input | Bound to |
| --- | --- |
| `context` | The consensus execution context of the block's chunk |
| `chain_id`, `height`, `parent_block_hash`, `block_hash` | The header |
| `state_root_before`, `state_root_after` | Parent state root, `header.state_root` |
| `transactions_root`, `receipt_root`, `da_root` | The header's roots |
| `vm_code_hash`, `block_program` | Runtime and Block Guest of the chunk's start boundary |
| `gas_used`, `gas_limit` | The header |
| `proposer_address` | Withdrawal account of `header.proposer_index` |
| `runtime_extra`, `inputs_root` | The header |

The receipt bytes travel alone (`BlockReceipt { block_hash, proof_bytes }`);
every receiver derives the envelope itself ([proof-following
nodes](07-proof-following-nodes.md)). A receipt has exactly one accepted byte
encoding ([proof system](06-proof-system.md)). A node keeps the first verified
bytes of each statement and up to `max_receipts_per_block` statements per
block ([proof market](08-proof-market.md)); validators may hold different
proof bytes of one statement, and each precommit names the exact bytes its
signer accepted.

Rejecting receipt bytes rejects that receipt and its source. It does not
invalidate the block or change fork choice. Ordinary execution saves its
proving witness atomically with the block and state, and replay saves missing
witnesses with its head commit, so another node can prove a block whose
producer withholds its receipt.

## Chunk and chunk proof

A `Chunk` commits a fixed height range (`chunk_id`, `start_height`,
`end_height`), its start and end state roots and block hashes, four Merkle
roots in height order (block hashes, block-proof leaves, VRF proofs and block
DA roots), the active and next validator-set roots and the identity-sanctions
root after the chunk. A block-proof leaf is the Borsh encoding of the block's
canonical `BlockProofPublicInputs`, so alternative receipt bytes for the same
statement cannot split the chunk a BFT round votes on. `Chunk::hash` is
`BLAKE3(DOMAIN_CHUNK || borsh(chunk))`.

A `ChunkProof` carries the mandatory `FinalityCert`, the chunk id and hash,
the chunk's public inputs, the `prover_address` it credits (outside the
consensus statement) and opaque proof bytes. Complete chunk proofs are the only
finalization path ([chunk proofs](12-chunk-proofs.md)).

### Finality certificate

`FinalityCert` holds the exact signed `BftProposal`, both aggregate signatures,
separate complete prevote and precommit attestation lists, the canonical proof
manifests, and the chunk id, round, chunk hash and active validator-set root.
The proposal binds the chunk, round, designated leader, an optional earlier
valid prevote quorum, the round-entry certificate and the payment selection
(`proposal_slot`, one `ReceiptChoice` per height, `ratified_chunk_proofs`).
Round zero carries no entry certificate; every later round carries one for that
chunk and round, and cannot downgrade its highest quorum
([BFT protocol](10-bft-protocol.md)).

A value vote signs `FinalityVoteData { chunk_id, round, chunk_hash, selection,
phase }` under `DOMAIN_PREVOTE` or `DOMAIN_PRECOMMIT`. A `VoteAttestation`
binds the individual vote signature and the signer's unlock declaration.
Precommit attestations also bind a `ProofAcceptanceCommitment`, a counted
Merkle commitment to the ordered exact block-proof envelope hashes the signer
accepted; prevotes carry none. The distinct `ProofManifest`s live once in a
canonical dictionary shared by the attestations: it is sorted by commitment,
every precommit's declared count and root resolve to exactly one entry, and
missing, duplicate or unused entries are rejected.

Two certificates of one chunk that differ only in their signers derive the
same next boundary: the boundary's participation field names the report the
chunk consumed from its own carrier, not the signer bitmap of the certificate
it finalized under.

### Quorum dictionaries

A `QuorumCertificate` is a `FinalityVoteData`, a signer bitmap and an aggregate
signature, with a domain-separated commitment over all three. Value votes,
finality certificates, proposals and round-change certificates encode each
exact quorum once in a canonical sorted dictionary; nested fields refer to it
by optional content hash. Decoders reject missing, duplicate and unused
entries and bound both the wire bytes and the expanded carriers. Signatures
bind the content hashes, never a dictionary position, so every source stays
independently attributable.

### Nil votes and round changes

`BftVote` distinguishes a value vote from a `NilVote`. A nil vote signs its
chunk, round and phase under `DOMAIN_BFT_NIL` with complete individual
attestations; it never masquerades as a vote for a zero chunk hash, and a nil
quorum synchronizes phases without ever appearing as a value certificate. A
`RoundChange` signs the requested next round and an optional exact highest
known prevote quorum; a `RoundChangeCertificate` holds unique authenticated
reports with enough prevote stake. `BftMessage` carries proposals, value and
nil votes, round changes and round-change certificates under bounded decoding.

## Evidence submissions

An `EvidenceSubmission` carries an `EvidenceStatement` and the `HistoryPath`
that opens its source chunk in the block's incoming History root. Compressed
evidence receipts travel as separate `EvidenceArtifact` attachments. Offence
identities (`penalty_id`) depend on the offence scope and never on the evidence
encoding, so aliases and re-encodings cannot buy a second deduction, and the
historical context excludes certificate signer subsets.
`ConflictingNilVote` carries a value vote and a nil vote of one signer for one
chunk, round and phase and shares the double-vote identity of that phase.
`DoubleBftProposal` carries two signed proposals by the designated leader of
one chunk and round whose chunks or payment selections differ; its identity is
separate from block-proposer slot equivocation. The offence catalogue is
[evidence proofs](16-evidence-proofs.md).

## History proof and checkpoint

A `HistoryProof` is a finalized chunk receipt without its certificate: its
`ChunkReceiptStatement` and the compressed STARK receipt bytes, at most
`MAX_HISTORY_RECEIPT_BYTES` (8 MiB). A `Checkpoint` is a chain binding and an
endpoint boundary, hashed under `DOMAIN_CHECKPOINT`; it is derived from a
History proof and never an independent network assertion. See [recursive
history](13-recursive-history.md).

## Size bounds

| Object | Bound |
| --- | --- |
| Block on the wire (`MAX_GOSSIP_BLOCK_BYTES`) | 8 MiB |
| State diff of one block (`MAX_STATE_DIFF_BYTES`) | 8 MiB |
| `ProvenBlock` or `CandidateBlock` publication (`MAX_PROVEN_BLOCK_BYTES`) | 18 MiB |
| Receipt on the `receipts` topic | 2 MiB |
| Evidence receipt (`MAX_EVIDENCE_PROOF_BYTES`) | 2 MiB |
| History receipt (`MAX_HISTORY_RECEIPT_BYTES`) | 8 MiB |
| Participation acknowledgements per block | 512, at most 2 MiB |
| Block proving input (`max_block_proving_input_bytes`) | 32 MiB default, at most 128 MiB ([proof system](06-proof-system.md)) |
