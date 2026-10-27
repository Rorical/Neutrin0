# Crate layout

The repository is one Cargo workspace of 28 member crates plus two SP1 Guest
packages that the workspace builds but does not contain. Crates are split so
that everything a proof depends on compiles into the Guests without the node's
networking, storage or async runtime: protocol and runtime crates are
`no_std + alloc` where practical, and host-only crates sit above them.

## Workspace members

Every member is named `neutrin0-<directory>`, except the EVM runtime crates,
which are named `neutrin0-evm-runtime-core` and `neutrin0-evm-runtime-master`.

| Crate | Responsibility |
| --- | --- |
| `crates/primitives` | Shared protocol types and constants: hashes, domain tags, accounts, programs, consensus and runtime parameters, the chain specification and wide-integer arithmetic |
| `crates/crypto` | BLAKE3, SHA-256 and Keccak-256 hashing, secp256k1 recoverable signatures and min-pk BLS12-381 with proof of possession |
| `crates/vrf` | BLS-VRF evaluation and verification, the stake-weighted eligibility threshold and the finalized-seed fold ([randomness](15-randomness.md)) |
| `crates/trie` | Binary sparse Merkle trie with prefix compression, Poseidon2 and BLAKE3 hashers, inclusion and exclusion proofs ([state and storage](04-state-and-storage.md)) |
| `crates/storage` | Column-family `Database` trait, atomic batches, an in-memory backend and the RocksDB backend |
| `crates/consensus-types` | Consensus wire types shared by the engine, network and proof crates: blocks, chunks, boundaries, BFT messages, evidence, participation, proving reports, history and runtime-facing records |
| `crates/consensus-vrf` | Consensus use of the VRF: header proposer claims, validator-set indexing and vote-aggregator selection |
| `crates/consensus-fork-choice` | Fork choice over the candidate DAG above finality ([consensus](09-consensus.md)) |
| `crates/consensus-chunk-bft` | Chunk-level BFT: leaders, rounds, vote accumulation, pacing and certificate verification ([BFT protocol](10-bft-protocol.md)) |
| `crates/proof-system` | The `ProofSystem` and `BlockExecutor` traits, History proof verification and a block-only mock that never authorizes chunk finality ([proof system](06-proof-system.md)) |
| `crates/prover-chunk` | Deterministic consensus validation shared by the native node and the Chunk, Evidence and Fact Guests, including recursive verification of the previous chunk receipt and exact signed-proof rejection |
| `crates/consensus-engine` | Production, proof-following import, witnesses, proof jobs, chunk BFT, complete chunk finalization, history, retention, bootstrap and signing journals |
| `crates/network` | libp2p transport: discovery, gossip topics with size caps, request/response protocols and the sync state machine ([networking](21-networking.md)) |
| `crates/sync` | Sync driver that turns network events into state-machine input and delegates verification to a host backend |
| `crates/mempool` | Bounded transaction pool, opaque to payloads, ordered by the runtime's verdicts |
| `crates/light-client` | Trust origin, latest-proof acceptance, peer-sampling decisions and durable light-client state ([light clients](14-light-clients.md)) |
| `crates/rpc` | JSON-RPC server and client: native `chain_*`, `state_*`, `mempool_*`, `history_*` and `runtime_call` methods and the Ethereum facade |
| `crates/node` | Node assembly and the `neutrin0-node` binary: configuration, chain-spec loading, genesis, `ChainBackend`, metrics and supervision |
| `crates/cli` | The `neutrin0-cli` binary: `keygen`, `genesis`, `node-config`, `program-hash`, `runtime-package`, key and signing-journal management, fork programs, typed RPC queries and signed transactions ([operator tooling](../operator-tooling.md)) |
| `crates/indexer` | The `neutrin0-indexer` binary and library: PostgreSQL ingestion over a node's public RPC and a GraphQL API ([indexer](../indexer.md)) |
| `crates/runtime-abi` | Borsh wire types shared by the runtime and its hosts (`RuntimeTransaction`, `RuntimeBlockInput`, `RuntimeBlockOutput`, `StateWitness`, queries, `TxValidity`) and the WASM entry-point names ([runtime interface](02-runtime-interface.md)) |
| `crates/runtime-core` | The `StateBackend` trait, the Guest-side `WitnessState`, the host-side `TracingState` and runtime-independent execution commitments ([runtime interface](02-runtime-interface.md)) |
| `crates/runtime-system` | Staking, governance, accountability, proving settlement and consensus-candidate rules, acting for a caller the execution engine authenticated |
| `crates/runtimes/neutrin0-evm/core` | The Osaka EVM STF with system precompiles and the mandatory accountability queue ([EVM runtime](03-evm-runtime.md)) |
| `crates/runtimes/neutrin0-evm/master` | WASM exports of the runtime (`cdylib`) and a native witness adapter for parity tests (`rlib`) |
| `crates/runtime-host` | Embedded WASM and Guest artifacts, runtime packages, wasmtime execution, SP1 proving and verification, and the verifying-key cache |
| `crates/keystore` | EIP-2335 encrypted BLS keystores ([validator keys](19-validator-keys.md)) |
| `crates/signer` | `neutrin0-signer`, the remote BLS signer with its own slashing-protection journal |

## Guest packages

Two packages are excluded from the workspace (each declares an empty
`[workspace]`) because they build for the SP1 `succinct` target with their own
lockfiles and cryptographic patches. `runtime-host/build.rs` builds both with
`sp1-build`.

| Package | Binaries | Contents |
| --- | --- | --- |
| `crates/runtimes/neutrin0-evm/guest` (`neutrin0-evm-runtime-guest`) | `neutrin0-evm-runtime-guest` | The Block Guest: shared EVM STF over a `WitnessState`, recursive evidence verification, committing a `BlockReceiptStatement` |
| `crates/prover-chunk/guest` (`neutrin0-chunk-guest`) | `neutrin0-consensus-chunk-guest`, `neutrin0-evidence-guest`, `neutrin0-fact-guest` | The Chunk, Evidence and Fact Guests over `prover-chunk` |

The same build script compiles the master crate to `wasm32-unknown-unknown`
under the `runtime-artifact` profile and remaps the checkout and `CARGO_HOME`
paths to fixed prefixes in every ELF and in the WASM, so the content hashes a
chain specification pins depend only on the source.

## What compiles into a Guest

The Block Guest links `neutrin0-evm-runtime-core`, `runtime-system`,
`runtime-core`, `runtime-abi`, `prover-chunk`, `consensus-types`, `vrf`,
`crypto`, `trie` and `primitives`; the consensus Guests link `prover-chunk` and
its dependencies. A change to any of these crates, including moving files,
changes the affected Guest ELFs and therefore every program identity a
specification or governance proposal pins ([upgrades and forks](20-upgrades-and-forks.md)).
Host crates (`storage`, `network`, `sync`, `rpc`, `consensus-engine`, `node`,
`runtime-host` and the binaries) never enter a Guest.
