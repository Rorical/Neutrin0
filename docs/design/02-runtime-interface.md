# Runtime interface

The runtime is the state-transition function: it decodes user transactions,
executes them, applies staking, governance and accountability rules, and
reports a fixed public statement. The node, the WASM host, the Block Guest and
the Chunk Guest share one unversioned execution contract built from common
types, so none of them decodes the runtime's own transaction format or economic
records. One `no_std` core compiles to native code, to 32-bit WASM for ordinary
execution and to the 64-bit SP1 Block Guest for receipts; any divergence between
those builds would let a valid receipt contradict an honest header, so every
untrusted value is bounded as a fixed-width integer before it becomes a `usize`.
The only runtime is the Osaka EVM described in [EVM runtime](03-evm-runtime.md).

## Wire contract

`neutrin0-runtime-abi` owns `RuntimeTransaction`, `RuntimeBlockInput`,
`RuntimeBlockOutput`, `BlockReceiptStatement`, `TransactionSummary`,
`StateWitness`, the call, query and admission envelopes, the WASM entry-point
names, the operational query contracts (`operational`) and the Ethereum query
and artifact types (`ethereum`). `neutrin0-consensus-types::runtime` owns the
records consensus reads (`ConsensusCandidates`, the scheduled-upgrade and
scheduled-fork keys), `ConsensusExecutionContext`, `ExecutionArtifacts` and the
proven accountability types `Sanction` and `AccountabilityOutput`.

### Transaction envelope

Each body transaction blob is the exact Borsh encoding of:

```rust
pub enum RuntimeTransaction {
    User(Vec<u8>),                            // runtime-defined payload
    SubmitEvidence(Box<EvidenceSubmission>),  // framework evidence admission
}
```

The envelope is mandatory. A user payload is opaque to the host, the mempool,
the network and consensus; the runtime defines its encoding, signatures,
accounts and rules. The EVM runtime carries one EIP-2718 Ethereum transaction
per `User` payload, and staking and governance are ordinary calls to its system
precompiles, so there is no second user format. Evidence admissions form a
prefix of the body: no `SubmitEvidence` may follow a `User` envelope, each must
bind the chain, height and incoming anchor, and a block carries at most
`MAX_EVIDENCE_ADMISSIONS` (4096) of them. The proof bytes of each admission
travel separately in `Body.evidence_proofs`, exactly one correctly bound
attachment per submission, and never enter the STF input or the transaction
commitments ([evidence proofs](16-evidence-proofs.md)).

### Block input

`RuntimeBlockInput` is the complete input of one block execution:

| Field | Meaning |
| --- | --- |
| `context` | `ConsensusExecutionContext`: slot, header timestamp, native parent hash, the SHA-256 output of the proposer's verified BLS-VRF proof, and the complete incoming finalized `ConsensusBoundary` |
| `active_validators` | Incoming committee; its commitment must equal `context.finalized.validators_root` and it holds at most `MAX_CONSENSUS_VALIDATORS` (256) entries |
| `evidence_anchor` | Authenticated incoming consensus and program context that evidence admissions bind |
| `chain_id`, `block_height`, `block_gas_limit` | Header-authenticated chain identity, height and gas ceiling |
| `proposer_address` | Proposer's withdrawal account, which receives runtime-defined proposer fees |
| `participation`, `proving` | The preceding chunk's certified `ParticipationReport` and `ProvingReport`, present from the chunk's carrier block on and absent before it |
| `participation_acks` | Positive participation records derived from historical precommits in the body's vote lane |
| `program_pieces` | References of the body's program-lane pieces, from which the runtime tracks artifact availability ([upgrades and forks](20-upgrades-and-forks.md)) |
| `transactions` | Exact ordered transaction envelopes |

The ordinary host derives every field from local consensus; the Chunk Guest
checks the same values against its authenticated start boundary and the signed
headers ([chunk proofs](12-chunk-proofs.md)). The runtime never consults a host
clock, host randomness or an RPC argument for these facts.

Exactly one block of every chunk after the specification's first, the carrier,
selects the previous chunk's compact certificate; the Chunk Guest derives the
two reports from it and requires the carrier and every later block of the chunk
to consume them ([proof market](08-proof-market.md)). A block before the carrier
consumes no report and commits the start boundary's commitments instead, so the
outgoing boundary records the report its chunk consumed and never depends on
which signer subset formed that chunk's own finality certificate.

Before any receipt verification or state access, `check_runtime_input` rejects
an input whose committee does not open the boundary root, whose participation
records are unsorted, duplicated, more than `MAX_PARTICIPATION_ACKS` (512) or
more than a committee per source chunk, or outside their challenge window, whose
program-piece references exceed `MAX_PROGRAM_PIECES_PER_BLOCK` (2) or name an
index outside their artifact, whose proving report disagrees with the
participation report's chunk or exceeds the committee, chunk length or
ratification bounds, or whose evidence prefix is malformed. A participation
record for source chunk `s` is accepted only in chunks `s + 1` and `s + 2`
(`PARTICIPATION_CHALLENGE_CHUNKS = 2`). The same function, with the same fixed
diagnostics, runs natively, in WASM and in the Guest.

### Block statement

`RuntimeBlockOutput` is the common statement every block proves:

| Field | Binding |
| --- | --- |
| `context` | Equal to the input context |
| `accountability` | `AccountabilityOutput`: the input's evidence anchor, newly admitted sanctions, sanctions executed from the mandatory queue and the queue commitment before and after |
| `chain_id`, `block_height`, `block_gas_limit`, `proposer_address` | Equal to the input |
| `participation`, `proving` | Commitment of the consumed report, or the start boundary's commitment when none was consumed |
| `participation_acks`, `program_pieces` | Commitments of the consumed records |
| `transactions_root`, `transaction_summary` | Root and count over every input envelope |
| `pre_state_root`, `post_state_root` | Actual state roots before and after |
| `applied`, `failed` | Included Ethereum transactions that succeeded, and that reverted or halted |
| `consensus_candidates_root` | Commitment of the `consensus:candidates` record after execution |
| `gas_used` | All gas consumed, mandatory work included; at most `block_gas_limit` |
| `receipts_root` | Commitment of the block's `ExecutionArtifacts` |

The Block Guest commits `BlockReceiptStatement { output, prover_address }`. The
prover chooses `prover_address`; every verifier accepts any value, and it only
attributes payment ([proof market](08-proof-market.md)). The header commits
`inputs_root` over the context, the report, acknowledgement and program-piece
commitments and the anchor, which the output reproduces
([block format](05-block-format.md)). Fee policy, receipt contents and account
layouts stay in the runtime; the statement has no runtime-specific fields.

`runtime-core::execution::transaction_commitments` computes
`transactions_root` with the same length-framed leaves as the body's
transaction lane, and the count covers every envelope, including transactions
the runtime skipped. Chunks reuse that block-proven count instead of decoding
user payloads again.

### Execution artifacts

`ExecutionArtifacts { transaction_ids, receipts, metadata }` holds runtime
transaction identifiers with their envelope positions, opaque receipts in
execution order (system work included) and opaque block metadata. Its
commitment, BLAKE3 of the canonical Borsh encoding under
`NTRO/execution-artifacts`, is `receipts_root`; WASM execution recomputes it, the
Block Guest derives it from execution and the header binds it. Artifacts travel
in the body and persist with the header, state and witness. The Ethereum
transaction index (the `ExecutionTransactions` column) is written in the same
durable batch, resolved against the canonical height mapping after a
reorganization and removed with pruned bodies. Decoding a historical artifact
uses the runtime installed at that block.

## Consensus-facing records

Consensus reads exactly three runtime records and writes none:

| Key | Record |
| --- | --- |
| `consensus:candidates` | `ConsensusCandidates`: every validator the runtime knows, sorted by address, with stake and optional BLS identity and registration proof; consumed by chunk rotation |
| `upgrade:scheduled` | The enacted program switch, consumed at its activation boundary |
| `fork:scheduled` | The enacted hard fork, consumed at its count |

The runtime receives the two certified reports as inputs and records the latest
under `consensus:participation` and `consensus:proving`; reward, liveness and
proving economics are runtime rules that never enter a consensus Guest. A safety
slash always takes the whole slashable balance. The inactivity deduction, the
reporter reward share, the proof-market shares and the issuance rate are
governed `runtime:policy` fields ([upgrades and forks](20-upgrades-and-forks.md)).

Inactivity deductions are disabled by default (`inactivity_leak_amount = 0`).
An enabled policy leaves the two chunks after a source chunk for signature
challenges and admits the deduction from the third. A missing signature does not
prove that a validator was silent, and censorship or delayed delivery can defeat
a challenge window, which is why the default is off. A positive signature clears
only its own source and identity; another identity sharing the same account
earns no credit from it ([evidence proofs](16-evidence-proofs.md)).

### System layer

`neutrin0-runtime-system` holds the staking, governance, accountability and
proving-settlement rules. It acts for a caller the execution engine has already
authenticated (`StateBackend::authenticated_caller`) and has no transaction
format or signature scheme of its own. Its actions are stake, unstake,
voluntary exit, withdrawal, BLS validator registration and key rotation,
governance proposals and votes, proof-backed evidence admission and the
mandatory sanction FIFO, which every block executes before ordinary
transactions with reserved gas. Deductions are internal operations, never
unsigned user transactions. Registration verifies the BLS proof of possession
bound to the withdrawal account; genesis keys carry the same proof (`pop_hex`).
Registration and validator records are keyed per address only, so no global
index grows with every registrant. A validator that has fully withdrawn loses
its records, and consensus drops the exited identity after the retirement delay.

Every transaction that executes consumes block gas, failures included, so gas
bounds the checks a block can carry. A transaction its sender authorized
(signature verifies, next nonce, balance covers the fee) pays its fee and spends
its nonce whether it succeeds or reverts; a forgery, a replay or an unaffordable
fee charges nobody and is skipped. A transaction that does not fit the remaining
block gas is skipped before any check runs.

## WASM host ABI

The runtime master is a `wasm32-unknown-unknown` cdylib loaded by wasmtime
(`runtime-host::wasm::WasmRuntime`). Inputs and outputs are Borsh envelopes from
`runtime-abi`; this ABI is separate from SP1's Guest stdin and public values.

### Exports

| Export | Signature | Input | Output |
| --- | --- | --- | --- |
| `memory` | unshared 32-bit memory | | |
| `neutrin0_allocate` | `(i32) -> i32` | length | pointer to a zeroed buffer |
| `neutrin0_deallocate` | `(i32, i32) -> ()` | pointer, length | |
| `apply_block` | `(i32, i32) -> i64` | `borsh(RuntimeCallInput)` | `borsh(RuntimeCallOutput)` |
| `_neutrin0_validate_tx` | `(i32, i32) -> i64` | `chain_id LE8 \|\| block_gas_limit LE8 \|\| borsh(RuntimeTransaction)` | `TxValidity` encoding |
| `_neutrin0_query` | `(i32, i32) -> i64` | `borsh(QueryRequest)` | `borsh(QueryResponse)` |

A call allocates an input buffer, copies the input, calls the entry point,
splits the returned `i64` into `pointer << 32 | length`, checks that range
against linear memory before copying, and deallocates both buffers. Installation
rejects an empty artifact or one larger than `MAX_PROGRAM_BYTES` (16 MiB), a
compiled image above 128 MiB, and any missing or mistyped export; a trap during
deallocation fails the call.

### Imports

The `neutrin0` import module supplies six state operations. Each validates its
guest-supplied ranges and traps on violation.

| Import | Signature | Effect |
| --- | --- | --- |
| `state_read_len` | `(key_ptr, key_len) -> i32` | Length of the value, or `-1` if absent; records the read and stashes the value |
| `state_read_into` | `(value_ptr)` | Copies the stashed value into guest memory |
| `state_write` | `(key_ptr, key_len, value_ptr, value_len)` | Writes into the call's scratch trie |
| `state_delete` | `(key_ptr, key_len)` | Deletes from the scratch trie |
| `pre_state_root` | `(out_ptr)` | Writes the 32-byte root before the call |
| `post_state_root` | `(out_ptr)` | Writes the scratch trie's current root |

Validation and query calls run read-only: a write or delete is dropped and
flagged, and the host then replaces a query's response with
`QueryStatus::PermissionDenied` and an admission verdict with
`TxValidationCode::Unauthorized`. A path whose trie node the host does not hold
fails the call as unavailable state ([state and storage](04-state-and-storage.md)).

### Limits

Fuel counts executed WASM instructions, so the bound is deterministic and
independent of host speed. Every call runs in a fresh store with one memory and
one table.

| Call | Fuel | Memory |
| --- | --- | --- |
| `apply_block` and `runtime:select_transactions` | 10^12 | 512 MiB |
| `_neutrin0_query` | 2 × 10^9 | 64 MiB |
| `_neutrin0_validate_tx` | 10^8 | 64 MiB |

The block budget is far above what any block within the gossip limit needs, so
it never rejects a block the Guest would prove; it only stops a runtime that
never returns. A node keeps at most eight compiled runtimes resident, 512 MiB in
total.

### Admission verdict

`TxValidity` encodes as `code u32 LE || priority u64 LE ||
borsh(Option<TransactionDependency>)`, at least 13 bytes. `TxValidationCode` is
`Valid` (0), `Malformed`, `BadSignature`, `NonceMismatch`,
`InsufficientBalance`, `Unauthorized`, `UnknownType` or `StateReadFailed` (7).
`TransactionDependency` carries the runtime's transaction identifier, account,
nonce, the account's current nonce, fee and tip caps and gas limit, from which
the pool applies sequence and replacement rules without decoding payloads.
`SubmitEvidence` never enters through admission; evidence reaches blocks only
through the verified evidence path.

## Execution and proving

`apply_block` takes `RuntimeCallInput::Genesis(RuntimeGenesisInput)` or
`RuntimeCallInput::Block(RuntimeBlockInput)` and returns the matching
`RuntimeCallOutput`; block execution returns `RuntimeBlockResult { output,
artifacts }`. The runtime core exposes `prepare_block`, which runs
`check_runtime_input` and decodes every user payload before any state access,
and `apply_prepared_block`, which executes the prepared block. Native, WASM and
Guest execution share both.

The block transition is total. An undecodable payload, a transaction that does
not fit the remaining gas and one the EVM refuses are each skipped with no
effects and no receipt, in verification and proving exactly as producer
selection skips them, so every signed block has exactly one correct execution
and a receipt. A state fault is never a transaction verdict: it aborts
execution.

### Ordinary execution

`WasmRuntime::dry_run` first verifies every evidence attachment
(`verify_input_receipts`: input checks, one attachment per submission, binding
to the anchor's Evidence and Fact keys, and SP1 verification of each distinct
proof envelope), then invokes `apply_block` against a tracing view of the parent
state. It accepts the result only if `receipts_root` equals the artifacts'
commitment and the output binds the exact input, the actual pre-state and
scratch roots and the gas ceiling (`output_binds_input`). A rejected output never
reaches the live state. The executor (`WasmExecutor`) then records the witness,
the write set that proof-following nodes import as the block's diff
([proof-following nodes](07-proof-following-nodes.md)) and applies the writes.

Proving requires the persisted `BlockWitness { input, state, evidence_proofs }`:
the block input, its `StateWitness` and the ordered evidence proof attachments.
The executor identity of a runtime is the BLAKE3 hash of its exact WASM bytes.

### Block Guest

The Block Guest reads one Borsh blob `(RuntimeBlockInput, StateWitness,
Vec<EvidenceMembership>, prover_address)`, bounded by the absolute
`MAX_BLOCK_PROVING_INPUT_BYTES` (128 MiB) and then by the anchor's
specification-pinned `max_block_proving_input_bytes` (32 MiB by default). It runs
`prepare_block`, checks one membership per submission bound to the anchor's
Fact key, recursively verifies each distinct evidence batch under the anchor's
Evidence key, builds a `WitnessState`, runs `apply_prepared_block` and commits
the `BlockReceiptStatement`. Verification decodes the committed statement and
compares it with the expected output. Receipts are verified under the program
set of their chunk's start boundary, never under one the receipt names
([proof system](06-proof-system.md)).

## Witness

`StateWitness { pre_state_root, nodes, values, witnessed_keys }` carries the
trie nodes and values on every path the block reads or writes and the sorted raw
keys it may read. `WitnessState` authenticates a witness before execution: every
node and value must hash to its claimed Poseidon2 hash, a non-empty pre-state
root must be among the nodes, and every witnessed key must resolve completely
from the supplied entries, which proves absence as well as membership. Reading a
key outside `witnessed_keys` aborts the Guest; writes and deletes witness their
key implicitly, and the post-state root is the partial trie's root after
execution.

On the host, `TracingState` and the WASM host state record every touched key and
build the witness from the authenticated paths in the parent trie. A path the
store cannot supply stops the run with no witness, diff or post-state
([state and storage](04-state-and-storage.md)).

## Verification and parity

The host checks every WASM result against its input before use; the Block Guest
proves the same statement independently; the Chunk Guest binds each statement
to its canonical header and checks continuity
([chunk proofs](12-chunk-proofs.md)). Because producers execute in 32-bit WASM
and receipts come from the 64-bit Guest, a new decoder must be covered by the
non-ignored native-versus-WASM case in `crates/runtime-host/tests/evm_parity.rs`;
the `#[ignore]` cases in that file execute the final Block Guest ELF in the SP1
executor and compare its public values with WASM.

## Runtime genesis

Every node initializes genesis through the selected runtime's `apply_block`
with `RuntimeGenesisInput`: the block-proving input bound, chain ID, genesis
timestamp and seed, synthetic genesis block hash, chunk size, the locally
authenticated program set, block gas limit, the genesis runtime parameters, the
initial validators with their withdrawal credentials, and an opaque
runtime-specific configuration. The runtime builds its state from an empty trie
and returns `RuntimeGenesisOutput { state_root, consensus_candidates_root }`.

The host requires the returned root to equal the trie it built, the candidates
to be strictly sorted by address and their commitment to match. The node then
requires every candidate to have a nonzero address and a verifying registration
proof, and every genesis validator to appear among the candidates with equal
stake and identity. The resulting root is the specification's
`genesis_state_root`, so the chain-spec hash binds the allocation; a declared
`genesis_state_root_hex` must equal it, and `neutrin0-cli genesis` prints it.
`ChainSpec::genesis_execution` pins the Fact, Evidence and Block keys next to
the runtime code hash, and genesis boundaries derive the program set from the
local specification, never from a prover's claim. The Chunk key stays in the
immutable chain binding.

### Runtime packages

`RuntimePackage` bundles the WASM, the Fact, Evidence and Block ELFs, their
`ProgramSet` (runtime code hash and locally derived SP1 keys), the BLAKE3
integrity hashes of all four artifacts and the opaque genesis configuration, up
to 128 MiB encoded. Decoding checks the artifact kinds, the hashes, the
complete WASM ABI and, before use as a proof system, that the locally derived
keys equal the declared ones. Governance proposals name a different hash per
artifact, the program-lane content hash, which also binds the artifact's length
and piece layout ([upgrades and forks](20-upgrades-and-forks.md)).
`neutrin0-cli runtime-package` builds a package from supplied artifacts;
`RuntimePackage::embedded` builds the one the node binary embeds.

## Operational queries

Queries use `QueryRequest { method, args }` and return `QueryResponse { code,
payload }`, where code 0 is success and codes below 1024 are reserved
(`UnknownMethod` 1, `InvalidArguments` 2, `MethodError` 3,
`PermissionDenied` 4). Ordinary application queries carry no state proofs;
their authenticity comes from the state root the node selected.

`runtime-abi::operational` defines the queries the node itself depends on,
answered by the installed runtime instead of node code that decodes
application state:

| Method | Arguments | Result |
| --- | --- | --- |
| `runtime:programs` | next block's `EvidenceAnchor` | `Vec<ProgramDistribution>`: proposed or enacted program sets and artifact hashes to warm or archive |
| `runtime:evidence_policy` | none | `EvidencePolicy`: liveness age, queue and per-block bounds, reserved gas, abandonment penalty |
| `runtime:evidence_coverage` | `Vec<EvidenceCoverageRequest>` | one `EvidenceCoverage` per request: participated, tombstoned, admitted, liveness-eligible |
| `runtime:select_transactions` | `RuntimeBlockInput` | user-envelope indexes in execution order |
| `reporter_status` | `ReporterStatusRequest` (at most 256 identities) | `Vec<ReporterStatus>`: slashable balance, tombstone and pending status |
| `accountability_metrics` | none | `SettlementSnapshot`: cumulative admitted, executed, deducted, rewarded and burned totals per sanction kind and current queue counts |

A missing or malformed response never authorizes an admission or a deletion;
retained evidence stays available for retry. Reporter cleanup queries finalized
state ([reporter nodes](18-reporter-nodes.md)), and snapshot installation queries
the runtime that produced the authenticated endpoint state and stages the
deletion of covered reports in the same durable installation batch.

### Transaction selection

Production asks the runtime which pooled user transactions to include through
`runtime:select_transactions`, which runs with the block's fuel and memory
budget. The runtime executes candidates against a disposable journal after
mandatory work, repeating passes until none makes progress so that later nonces
follow earlier ones, and returns their indexes. The engine keeps the evidence
prefix and rejects a duplicate, out-of-range or evidence index; block execution
then validates the selected inputs. JSON-RPC refuses `runtime:select_transactions`
and `evm:pending` through `runtime_call`, so no client can supply a block
context.

Candidates stay pooled until block persistence succeeds. Admission validates
each new transaction against the current head. When the head or the runtime
changes, one pass revalidates the pool on a blocking worker that holds neither
the head-update fence nor the pool while transactions execute, and its verdicts
apply only if the head has not moved; RPC pending reads answer from the last
validated pool, and production brings it up to date first.

### Historical queries

RPC `runtime_call` resolves `latest`, `safe`, `finalized`, a hash or a height to
one block and reads its committed state root; `finalized` is the latest verified
chunk boundary, or the trusted genesis before any chunk finalizes. The program
history of the selected height names the runtime code hash, and the node queries
that exact installed WASM artifact, including runtimes restored from consensus
or reporter boundaries on restart. Missing blocks or state return explicit
errors and never fall back to the head. Queries run in a fixed number of slots
(half the cores, rounded up); a slot is taken before the query starts and held
until it returns, even after the RPC deadline has answered the caller.
`runtime_call` returns `-32010` without a runtime, `-32013` for an undecodable
response, `-32014` for a runtime failure and `-32012` only when its wall-clock
budget expires ([consensus RPC](../consensus-rpc.md)).
