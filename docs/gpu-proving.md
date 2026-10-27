# GPU proving

The node supports SP1 6.10.0 CPU and local NVIDIA CUDA backends. One selection
routes Fact, Evidence, Block and Chunk proving through the same prover; the latest
finalized Chunk receipt is the History proof, so there is no separate History
stage. CUDA does not change the Guest programs, proof format, recursive checks or
chain identity. Proof verification and WASM execution stay on the host CPU.

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
| `prove_foreign_blocks` | false | Prove candidates this node did not produce and publish their receipts. Requires `[execution] mode = "execute"`. |
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
program setup. Fact and Evidence batches carry a priority scope instead of a
device lease: each compressed call releases the gate before the next, so queued
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
CPU verifier. It uses the same fixture and stage checkpoints as the CPU gate
`evidence_block_chunk_real_compressed_recursion`. Use fresh directories for a
first hardware run so cached CPU proofs cannot stand in for CUDA proving:

```sh
export NEUTRIN0_CUDA_DEVICE=0
export NEUTRIN0_SP1_CACHE_DIR="$PWD/target/cuda-tests/sp1"
export NEUTRIN0_EVIDENCE_GATE_DIR="$PWD/target/cuda-tests/stages"
cargo test --locked --release -p neutrin0-runtime-host --features cuda \
  --test evidence_pipeline evidence_block_chunk_cuda_compressed_recursion \
  -- --ignored --exact --nocapture
```

Keep those directories to resume an interrupted run; use new ones to measure fresh
proving latency. The ignored `history_recursion` gates
(`history_real_compressed_chunk_recursion` on CPU,
`history_cuda_compressed_chunk_recursion` on CUDA) prove consecutive chunk
receipts with real recursion and reject off-chain ratified receipts.

Plan for a high-memory host: CPU-side traces and recursion need well over 12 GiB
of RAM. A result applies only to the Guest ELFs it ran on.
