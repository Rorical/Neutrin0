# AGENTS.md

Guide for coding agents and contributors. The design documents in `docs/design/`
own the protocol rules; this file lists the environment, the checks, the source
rules and the invariants that changes most often break, each with the document
that owns it. Read `README.md` and `docs/design/00-overview.md` first.

## Environment

- Rust is pinned by `rust-toolchain.toml` to 1.99.0, with the
  `wasm32-unknown-unknown` target. Do not switch the default toolchain.
- The workspace uses `edition = "2024"` and `resolver = "3"`. Edition 2024
  reserves `gen`, so use names such as `gen_sk()` in tests.
- `Cargo.lock` is committed. Build and test with `--locked`; do not run
  `cargo update` as part of an unrelated change.
- SP1 6.10.0 is a hard build dependency. `runtime-host`'s build script always
  compiles the Guest ELFs and embeds them, so the `succinct` toolchain and
  `cargo-prove` must be installed first:
  `curl -fsSL https://sp1up.succinct.xyz | bash && "$HOME/.sp1/bin/sp1up" --version 6.10.0`.
- Linux builds need `protobuf-compiler` and `libclang-dev`.

## Build, test, lint

CI runs:

```text
cargo build  --locked
cargo test   --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt    --all -- --check
```

Do not claim the workspace is green unless these have passed. Real compressed
recursion (Fact/Evidence → Block → Chunk → Chunk) runs only in `#[ignore]`d tests
(`docs/gpu-proving.md`), and their results never carry over to changed ELFs.

## Lint posture

- The workspace enables clippy `all`, `pedantic`, `nursery` and `cargo` at warn,
  plus `unsafe_op_in_unsafe_fn = deny`, `missing_docs = warn` and
  `unused_must_use = deny`. CI promotes warnings to errors.
- Every crate has `#![deny(unsafe_code)]` except the WASM master
  (`crates/runtimes/neutrin0-evm/master`), whose FFI exports need it. Do not
  introduce `unsafe`.
- Runtime crates run as 32-bit WASM for producers and as the 64-bit SP1 Block
  Guest for receipts. A divergence lets a receipt contradict an honest header
  (`InvalidExecutionClaim`). Bound every untrusted value as a fixed-width integer
  before converting it to `usize`, and extend the non-ignored native-vs-WASM case
  in `crates/runtime-host/tests/evm_parity.rs` to cover every new decoder.
- Foundational and protocol crates are `no_std + alloc` where practical. Keep that
  shape unless a crate must be host-only.

## Source layout

- One responsibility per file and no production file over about 400 non-test
  lines; functions stay short enough to read in one pass (about 80 lines; a flat
  dispatch or renderer may be longer). A module root `foo.rs` keeps the type and
  its `mod` declarations and re-exports from private children in `foo/`; public
  paths never move. Inline tests live in `foo/tests.rs`. Do not use `#[path]` for
  source modules; it remains only where integration tests share support files.
- A refactor is behavior-preserving only: no signature, error text or order,
  Borsh layout, lock scope, `.await` or I/O order changes, and per-crate test
  counts match before and after.
- Guest-side crates (`primitives`, `consensus-types`, `runtime-*`,
  `prover-chunk`, `vrf`, `crypto`, `trie`, `runtimes/neutrin0-evm/*`) are compiled
  into the Guest ELFs. Any change to them, even moving files, changes every pinned
  program identity; say so in the change description.
- There is one current protocol format with unversioned types, fields and paths.
  An incompatible change replaces the format directly. Do not add deprecated
  variants, compatibility shims, migrations, fake recursive proofs or empty-proof
  finalization paths.

### Runtime crates

- `crates/runtime-abi/`: Borsh wire types shared by the runtime and its hosts
  (`RuntimeTransaction`, `RuntimeBlockInput`, `RuntimeBlockOutput`,
  `StateWitness`, query types, `TxValidity`) and the WASM entry-point names. No
  logic.
- `crates/runtime-core/`: the `StateBackend` trait, guest-side `WitnessState`
  and, behind the `host` feature, `LiveTrie` and `TracingState`. `no_std + alloc`.
- `crates/runtime-host/`: the SP1 prover/verifier host, the wasmtime runtime host
  and `Sp1ProofSystem`, the `proof-system::ProofSystem` implementation the node
  uses. Embeds the four Guest ELFs (Block, Chunk, Evidence, Fact) and the WASM
  master built by `build.rs`, and
  caches verifying keys on disk by `(SP1_CIRCUIT_VERSION, BLAKE3(elf))`.
  `build.rs` remaps the workspace root and `CARGO_HOME` to fixed prefixes so ELF
  and WASM content hashes do not depend on the build location.
- `crates/runtime-system/`: staking, governance, accountability and
  consensus-candidate rules. `no_std + alloc`. Actions run for a caller the
  execution engine already authenticated (`StateBackend::authenticated_caller`);
  the crate has no transaction format or signature scheme of its own.
- `crates/runtimes/neutrin0-evm/core/`: the only runtime, Osaka EVM over
  `RuntimeBlockInput` with system interfaces as precompiles at reserved
  addresses. Compiles to native, wasm32 and the SP1 Guest target.
- `crates/runtimes/neutrin0-evm/master/`: `cdylib + rlib`. The rlib
  (`apply_block_with_witness`) serves native parity tests; the wasm32 cdylib
  imports state operations from the host's `neutrin0` module and exports
  `apply_block`, `neutrin0_allocate`, `neutrin0_deallocate`,
  `_neutrin0_validate_tx` and `_neutrin0_query`. Uses `dlmalloc` on wasm32.
- `crates/runtimes/neutrin0-evm/guest/`: the SP1 Block Guest. Not a workspace
  member; `runtime-host/build.rs` builds it with `sp1-build`. The consensus Guests
  (chunk, evidence, fact) live in `crates/prover-chunk/guest/`.

## Protocol facts

- The native token has 18 decimals. Every amount (stake, consensus weight
  `Validator::effective_stake`, fee, reward, issuance, deduction, withdrawal, EVM
  balance) is `u128`/U256 wei; nothing converts between units. Consensus totals
  are checked `u128` sums, quorum, VRF and pro-rata arithmetic is exact over wide
  products, and total stake stays within `MAX_TOTAL_STAKE`. Chain-spec TOML
  amounts above `i64` are decimal strings.
- The wire codec is Borsh. The chain hash is BLAKE3 (`primitives::blake3_256`);
  SHA-256 and Keccak-256 exist for compatibility surfaces only.
- Consensus BLS and VRF signatures sign
  `tag || chain_id LE8 || ChainSpecHash32 || payload` under a `ConsensusDomain`
  derived from the complete chain specification, so equal chain IDs do not allow
  cross-spec replay. Callers prepend the 16-byte `DOMAIN_*` tags from
  `crates/primitives/src/lib.rs`; the crypto crate does not. After a hard fork a
  signature on chunk `c` verifies under the domain in force at `c` (design 20).
- BLS is min-pk with proof of possession. Every seated key has a verified
  registration POP; genesis keys carry `pop_hex`, checked whenever a node loads
  the spec.
- secp256k1 signatures are 65 bytes `r || s || v`, recoverable, low-S.

## Invariants that changes break

Read the owning document before changing its area.

| Invariant | Design |
| --- | --- |
| One STF core compiles to WASM and the SP1 Block Guest. The block transition is total: an undecodable, over-gas or EVM-invalid transaction is skipped with no effects, so every signed block has one correct execution and a receipt. | [02](docs/design/02-runtime-interface.md), [03](docs/design/03-evm-runtime.md) |
| Complete chunk proofs are the only finalization path. Certificates keep the exact signed proposal and both attestation quorums. | [12](docs/design/12-chunk-proofs.md) |
| Chunk `N` recursively verifies chunk `N - 1`'s receipt and the first chunk starts at `ConsensusBoundary::first` (genesis or a fork start), so the latest finalized chunk receipt is the History proof. There is no separate History prover. | [13](docs/design/13-recursive-history.md) |
| The chain spec pins every genesis program and the Fact and Chunk keys; its hash is the `ChainBinding`. Changing the Chunk or Fact Guest or the SP1 version is a hard fork. A node uses embedded program bytes only when they reproduce a pin. | [20](docs/design/20-upgrades-and-forks.md) |
| Receipts are verified under the program set of their start boundary, never one the receipt names. Old receipt rejection uses the source Block Guest key its historical context binds; never reinterpret an old receipt under a new key. | [16](docs/design/16-evidence-proofs.md), [20](docs/design/20-upgrades-and-forks.md) |
| Consensus reads exactly three runtime records (`consensus:candidates`, the scheduled upgrade, the scheduled fork) and passes the runtime the participation and proving reports. Economic rules never enter the Guests. | [20](docs/design/20-upgrades-and-forks.md), [08](docs/design/08-proof-market.md) |
| BFT: timeout alone cannot authorize a higher round, nil votes cannot clear a value lock, a conflicting prevote needs a quorum strictly between the lock round and the new round, and there is no configurable round cutoff. The BFT value is the chunk plus its payment selection. | [10](docs/design/10-bft-protocol.md), [08](docs/design/08-proof-market.md) |
| Signing journals reserve every message before it is signed. Never bypass a reservation or discard unfinalized locks during bootstrap. A validator key has exactly one source, and production signs only typed `SignRequest`s. | [10](docs/design/10-bft-protocol.md), [19](docs/design/19-validator-keys.md) |
| A state diff is a transport artifact authenticated by reproducing the header's state root. It is never a consensus commitment and never enters a Guest. | [07](docs/design/07-proof-following-nodes.md) |
| State is never held in memory whole. Stored trie nodes are reference counted (`StateRefs`, `StatePins`, `StateReleases`) and pruning runs in bounded slices. | [04](docs/design/04-state-and-storage.md) |
| Consensus references and liveness evidence are limited to the preceding eight finalized chunks. Safety evidence has no age window and is admitted once per identity. `evidence_max_age_blocks < unbonding_delay_blocks > chunk_size`. | [16](docs/design/16-evidence-proofs.md), [17](docs/design/17-evidence-availability.md) |
| Prover and reporter accounts must be runtime accounts (twelve zero bytes, then the 20-byte address); every verifier refuses any other. | [08](docs/design/08-proof-market.md) |
| Signed consensus artifacts are retained and exchanged within the current plus eight-chunk evidence window; archive retention does not extend admissible consensus history. | [17](docs/design/17-evidence-availability.md), [18](docs/design/18-reporter-nodes.md) |

## Architecture changes

- When a request describes how the system works, check the description against
  the code first and report any mismatch before changing anything.
- Report a change that alters what a component guarantees or depends on by its
  system-level consequence. Follow the chain transitively and name every
  component it makes redundant, obsolete or contradictory. For example, because
  chunk `N` verifies chunk `N - 1`'s receipt and chunk 0 starts at genesis, every
  chunk receipt proves the chain from genesis, so a separate History prover
  duplicates it.
- Update every design document the consequence touches in the same change, and
  report any two documents, or a document and the code, that disagree.
