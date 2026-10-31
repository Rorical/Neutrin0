# GPU proving

The node supports SP1 6.10.0 CPU and local NVIDIA CUDA backends. One selection
routes Fact, Evidence, Block and Chunk proving through the same prover; the latest
finalized Chunk receipt is the History proof, so there is no separate History
stage. CUDA does not change the Guest programs, proof format, recursive checks or
chain identity. Proof verification and WASM execution stay on the host CPU.

Ordinary full, archive and light-client nodes initialize a verification-only
backend. Selecting a proving backend does not give those roles proving duties.
Validators and reporters initialize the configured prover; reporters generate
Evidence proofs and obtain missing Facts on demand. A non-light node with
`prove_foreign_blocks = true` also initializes the prover, precomputes consensus
Facts and runs fallback Chunk and Evidence jobs. That opt-in requires executing
mode. Archive execution alone does not enable proving.

## Build and configure

CPU is the default, including on macOS. CUDA execution requires Linux x86-64,
an NVIDIA GPU and a driver compatible with the pinned SP1 GPU server. Apple
Silicon/Metal is not supported. The optional CUDA client compiles on a Mac for
integration checks but cannot run GPU proofs there.

Install the normal [build prerequisites](../README.md#prerequisites), then build:

```sh
cargo build --locked --release -p neutrin0-node --features cuda
```

Add this section to the node's TOML configuration (or pass `--proving cuda` to
`neutrin0-cli node-config`):

```toml
[proving]
backend = "cuda"
cuda_device = 0
concurrency = 1
capacity = 16
chunk_proof_fallback_secs = 180
prove_foreign_blocks = false
prioritize_block_proofs = true
# rescue_unproven_blocks = true
# prover_address = "0x…32 bytes…"
```

```sh
./target/release/neutrin0-node --config /path/to/node.toml
```

| Key | Default | Meaning |
| --- | --- | --- |
| `backend` | `"cpu"` | `"cpu"` or `"cuda"` for every proof stage. |
| `cuda_device` | 0 | CUDA ordinal; refused with the CPU backend. |
| `concurrency` | 2 | Simultaneous native proving and setup calls, 1 to 64. CUDA submits one call per device regardless. |
| `capacity` | 16 | Queued plus running Block jobs, including restart recovery; at least `concurrency`, at most 1024. |
| `chunk_proof_fallback_secs` | 180 | How long a validator other than the next chunk's round-0 leader waits, from the persisted round start, before proving the chunk itself. At most 3600; zero disables the delay. |
| `prioritize_block_proofs` | true | A chunk proof waits, for at most one slot after the certificate, while this node still has block proofs pending. |
| `prove_foreign_blocks` | false | Prove candidates this node did not produce and publish their receipts. Requires `[execution] mode = "execute"`; also opts a non-validator into proactive Fact caching and fallback Chunk and Evidence proving. |
| `rescue_unproven_blocks` | on for CUDA, off for CPU | Prove head-branch blocks whose proposer published no receipt once the proposer's lease has passed. |
| `prover_address` | withdrawal credentials | Runtime account (twelve zero bytes, then the 20-byte address) every receipt this node proves names for its reward. |

The next chunk's round-0 leader starts a chunk proof as soon as the certificate
exists, since that leader names the proof it is paid for and prefers its own. A
running chunk proof cannot be preempted and takes minutes, while production waits
on block proofs that take seconds, which is why block proofs go first by default.
A backward clock or a future round start triggers the fallback at once. A receipt
arriving before admission cancels queued work, with readiness rechecked within
250 ms; running native proofs finish normally. Every result still passes
independent receipt verification and the canonical and quorum checks. These local
choices do not change BFT deadlines, signing authority or the finalization rule
(design 08).

A node proves the blocks it produces. It proves other blocks only with
`prove_foreign_blocks`, which keeps one queue slot for the node's own next block,
or through `rescue_unproven_blocks` once a proposer's lease has expired. A node
with neither a `prover_address` nor a validator key credits each block's proposer,
so a node without a validator key should set `prover_address` to be paid for the
receipts it proves. Anything other than a runtime account is refused at startup.

## Scheduling and device sharing

A shared priority gate orders Block and Chunk work first, then Fact, Evidence and
program setup. Optional early Fact work also waits for the producer's whole
Block proof queue to drain, including the handoff between native calls, before
coalescing queued requests. This check precedes device admission; a Fact call
already waiting at the device gate keeps its admission priority, and a running
native call completes normally. Missing
Fact receipts retain the existing in-circuit Chunk verification and on-demand
Evidence proving paths. Fact and Evidence batches carry a priority scope instead
of a device lease: each compressed call releases the gate before the next, so queued
Block or Chunk work enters between fact groups. No GPU lease is held while waiting
on the fact cache's single-flight lock. On CPU, Fact and Evidence composites take
a fresh lease for each compressed call. Program installation takes capacity only
at cold native setup, after its installation and cache single-flight checks; warm
setup holds no permit. Native CPU hooks reuse an admitted synchronous call through
nested wrappers, restoring their scope after return or panic. Backends without the
native admission hook keep the node's composite resource budget.

Setup and proving use the same gate, and nested synchronous wrappers reuse the
exact device reservation. Independent devices have independent gates; raising the
worker count does not select another GPU. The registry admits at most 64 devices
and 256 known SDK handles. Known factory handles keep their device through SDK
`Arc` clones; foreign SDK or environment CUDA handles share the device-zero gate.

These gates are local to one process. Each validator process starts its own SP1
GPU server, using the socket for its selected device; separate processes do not
share the queue or a memory budget. The hardware measurements below cover one
CUDA prover process at a time. Reserve a 24 GiB device for one CUDA validator in
an initial deployment. Running two CUDA validators on that device has not been
validated and needs coordination beyond the current in-process gate.

## SP1 GPU server

SP1 starts a local `sp1-gpu-server` and talks to it over a Unix socket. The SDK
installs the matching server in `$HOME/.sp1/bin` when it is absent or mismatched,
which needs release download access and a writable SP1 installation directory. No
Docker is required, and there is no remote endpoint or hosted proving network.
`SP1_PROVER` does not override the node's `backend`.

Unsupported CUDA builds or platforms fail before node services start. Driver,
server or key-setup failures abort startup; the node never switches to CPU.
Startup logs name the backend and device. Each program keeps its backend-specific
proving key; CUDA session handles are never rebuilt from disk VKs, and the
server's program VK is checked against the local ELF and circuit identity. CPU VK
caching remains available. Program setup uses a bounded single-flight lock and
rechecks cached preprocessing before a cold CPU setup.

Library callers use `backend::cuda_prover` inside a multithreaded Tokio runtime
and keep that runtime alive through key and prover cleanup. The node and the ignored GPU
tests provide this runtime.

## GPU tests

Ordinary checks do not need a GPU and never start its server:

```sh
cargo test --locked -p neutrin0-node -p neutrin0-runtime-host --features neutrin0-node/cuda
cargo clippy --locked --all-targets -p neutrin0-node -p neutrin0-runtime-host --features neutrin0-node/cuda -- -D warnings
```

The ignored `evidence_block_chunk_cuda_compressed_recursion` test proves
Fact → Evidence → Block → Chunk → Chunk recursion, checks the final receipt as a
History proof from genesis and verifies every receipt with an independent local
CPU verifier. Real-proof acceptance uses CUDA for all proving stages.
Use fresh checkpoint directories for a first hardware run:

```sh
export NEUTRIN0_CUDA_DEVICE=0
export NEUTRIN0_SP1_CACHE_DIR="$PWD/target/cuda-tests/sp1"
export NEUTRIN0_EVIDENCE_GATE_DIR="$PWD/target/cuda-tests/stages"
cargo test --locked --release -p neutrin0-runtime-host --features cuda \
  --test evidence_pipeline evidence_block_chunk_cuda_compressed_recursion \
  -- --ignored --exact --nocapture
```

Keep those directories to resume an interrupted run; use new ones to measure fresh
proving latency. `history_cuda_compressed_chunk_recursion` proves consecutive
chunk receipts with real recursion and rejects off-chain ratified receipts.

`consensus_guest_cuda_compressed_recursion` proves the two-Block → Chunk fixture
and independently verifies the final Chunk receipt.
`receipt_verdicts_real_compressed` tests both acceptance and rejection of real
Block receipts through Fact and Evidence recursion. These gates and the two
`prove_verify` real-proof cases require `--features cuda` and use
`NEUTRIN0_CUDA_DEVICE` (default 0). CPU proving is excluded from acceptance;
CPU execution, parity checks and independent receipt verification remain.

```sh
cargo test --locked --release -p neutrin0-runtime-host --features cuda \
  --test consensus_chunk consensus_guest_cuda_compressed_recursion \
  -- --ignored --exact --nocapture
NEUTRIN0_HISTORY_GATE_DIR="$PWD/target/cuda-tests/history" \
  cargo test --locked --release -p neutrin0-runtime-host --features cuda \
  --test history_recursion history_cuda_compressed_chunk_recursion \
  -- --ignored --exact --nocapture
NEUTRIN0_EVIDENCE_GATE_DIR="$PWD/target/cuda-tests/receipt-verdicts" \
  cargo test --locked --release -p neutrin0-runtime-host --features cuda \
  --test evidence_pipeline receipt_verdicts_real_compressed \
  -- --ignored --exact --nocapture
```

Plan for a high-memory host: CPU-side traces and recursion need well over 12 GiB
of RAM. A result applies only to the Guest ELFs it ran on.

## Validated hardware and results

Validation used Linux x86-64, one NVIDIA RTX 4090 D with 24,564 MiB of device
memory, 16 allocated CPUs and a 62 GiB host-memory limit.
Rust 1.99.0 and SP1 6.10.0 were pinned. The locked workspace build passed.
The ordinary workspace suite passed 1,746 tests with no failures. The CUDA
node/runtime-host suite passed 460 tests with no failures. Strict workspace and CUDA Clippy, Rustdoc with warnings
denied, format, monitoring rules and metric-exposition checks passed.

All eight opt-in final-ELF execution/parity cases passed. PostgreSQL integration
passed three cases, Solidity passed three tests, and the Forge/Cast HTTP wallet
flow passed. The wallet fixture covers deployment, transfers, simulation and
receipt queries with mock Block proofs and native consensus validation.
An explicit validator-exit fixture also passed under its fixed committee and
leader sequence, using mock Block proofs and native consensus validation.

All six CUDA real-proof cases passed. The four recursive gates used independent
CPU receipt verification:

| Test | Verified result |
| --- | --- |
| `history_cuda_compressed_chunk_recursion` | Three Blocks and three recursively linked Chunks; false ratified receipts rejected |
| `consensus_guest_cuda_compressed_recursion` | Two Block receipts recursively verified by a Chunk; forged public values and incorrect bindings rejected |
| `evidence_block_chunk_cuda_compressed_recursion` | Objective misconduct, sanctions and reward settlement composed through Evidence → Block → Chunk; Fact coverage 15/15 |
| `receipt_verdicts_real_compressed` | Both verdict polarities for real Block receipts; rejection fixture executed 828,737,469 Fact Guest instructions |
| `real_prover_full_pipeline` | Signed EVM transfer proved as a compressed Block receipt and verified |
| `real_prover_demonstration` | Signed EVM transfer proved and verified; altered public output rejected |

A release-built single-validator network finalized Chunk 0 at height 1 and
then Chunk 1 at height 2 with real compressed proofs. Its first History proof
was exported successfully (1,275,157 bytes). The validator resumed its existing
database, key and signing journals before finalizing. This run used one-block
chunks and no peers.

A separate release-built single-validator network finalized two consecutive
64-block chunks at heights 64 and 128 with a 10-second slot interval. Its first
History proof was exported successfully (1,275,157 bytes). The second chunk
finalized after a host scheduling update and a restart on the same database and
signing journals; all Guest and WASM fingerprints remained unchanged. These
first two chunks had no peers or injected user transactions; they establish
real 64-block composition and recursive finalization.

The same network subsequently finalized eight EIP-1559 transactions at height
256: funding two wallets, transfers in both directions, `WalletFixture`
deployment, state updates from both wallets and a call that reverted as expected.
Seven receipts succeeded and one reverted. Exact balances after gas charges,
nonces, deployed bytecode, event identities and historical storage all matched.
Block and receipt projections agreed on transaction order, cumulative and system
gas, effective EIP-1559 fees and canonical inclusion. The creation address matched
the sender and nonce. Read-only calls left state and nonces unchanged; a reverting
simulation returned standard ABI revert data. The History proof covering all
eight transactions was exported successfully (1,275,157 bytes).

The Evidence pipeline resumed previously generated CUDA checkpoints and verified
them again before completing the remaining stages. Device memory samples reached
21,192 MiB (about 20.7 GiB). Sampling can miss shorter peaks. These fixture
measurements do not establish throughput or memory bounds for full-gas blocks,
128-block chunks or a sustained multi-host network.

The tested GPU server required `libcudart.so.12`. An image with only CUDA 13 needed
an additional CUDA 12 runtime library; the driver was unchanged. After one test
exited, a stale device socket refused connections. Before retrying, the server
was confirmed stopped and only the refused socket was removed. Never unlink a
live server's socket.

The SHA-256 fingerprints below identify the tested build artifacts. Chain
specifications continue to use their protocol program identities. A changed
artifact requires new proof results.

| Artifact | SHA-256 |
| --- | --- |
| Block Guest | `1e0fc7976b12e9d4f11a76dee4d350808c9f156e4206a5db08d4e6167eccd037` |
| Chunk Guest | `a41acc41ec54fd997ecc89b326ab44e9342b3a67e1678b25b8ae09eaa251eefd` |
| Evidence Guest | `a7dc8c7c90767d123c37c183cc469d89c0cf97304f006cbc1e3e5412814083af` |
| Fact Guest | `cfa996d304631d7f003fd4c6d24fb468419fbfb00a5aff283ef96b6616093f26` |
| WASM runtime | `3e14d83234dfb985a8e65180e8c27725016e71c941df9e90f7672730d7fab5b7` |
