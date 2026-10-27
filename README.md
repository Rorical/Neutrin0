# Neutrin0

[![ci](https://github.com/Rorical/Neutrin0/actions/workflows/ci.yml/badge.svg)](https://github.com/Rorical/Neutrin0/actions/workflows/ci.yml)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

Neutrin0 is a proof-aware layer-1 blockchain written in Rust. It runs Osaka EVM
execution, proves every block with SP1, and finalizes a chunk of blocks only when
a recursive chunk proof verifies its BFT certificate and the previous chunk's
proof, so the latest finalized chunk proof covers the whole chain.

**Status:** experimental development protocol. There is no public network, and
wire, database and proof formats change incompatibly between versions without
migration. See the [roadmap](docs/design/22-roadmap.md) for what is implemented
and which acceptance gates are open.

## Architecture

- **One state-transition core.** The same runtime code compiles to WASM for
  ordinary execution, RPC and witness generation, and to an SP1 Block Guest for
  proofs, so the two cannot drift apart. Staking, governance and accountability
  are EVM precompiles at reserved addresses
  ([EVM runtime](docs/design/03-evm-runtime.md)).
- **Execute once, follow everywhere.** A producer publishes its block with its
  write set, then a receipt proving it. Other nodes apply the writes against the
  header's state root and verify the receipt instead of re-executing
  ([proof-following nodes](docs/design/07-proof-following-nodes.md)).
- **Chunk finality.** Validators run stake-weighted BFT over chunks of blocks
  (128 by default). A Chunk Guest verifies the signed proposal, both quorums, the
  consensus transition and the previous chunk's receipt. Complete chunk proofs are
  the only finalization path ([complete chunk proofs](docs/design/12-chunk-proofs.md),
  [BFT protocol](docs/design/10-bft-protocol.md)).
- **History is finality.** Because each chunk proof recursively verifies its
  predecessor, the latest finalized chunk receipt proves the chain from genesis.
  Light clients and bootstrapping nodes trust that one proof
  ([recursive history](docs/design/13-recursive-history.md)).
- **Proof-authorized sanctions.** A Fact Guest and an Evidence Guest prove
  objective offences; blocks verify those proofs and execute sanctions
  ([evidence proofs](docs/design/16-evidence-proofs.md)).
- **Paid proving.** Block and chunk provers are paid from base fees and a yearly
  issuance on total stake (2% by default)
  ([proof market](docs/design/08-proof-market.md)).
- **Governed programs.** Runtime and execution Guest upgrades are scheduled by
  stake-weighted governance and distributed on chain. Changing the Chunk or Fact
  Guest is a governance-scheduled hard fork ([runtime upgrades](docs/design/20-upgrades-and-forks.md)).
- **One unit.** The native token has 18 decimals; stakes, fees, rewards and EVM
  balances are all wei. The default minimum validator stake is 32 tokens.

Solidity interfaces for the system precompiles are in [contracts](contracts/).

## Prerequisites

- Rust 1.99.0, pinned in `rust-toolchain.toml` together with the
  `wasm32-unknown-unknown` target; rustup installs both on first use.
- SP1 6.10.0. The build compiles the Guest ELFs, so `sp1up` must install the
  `succinct` toolchain and `cargo-prove` before any build:

  ```sh
  curl -fsSL https://sp1up.succinct.xyz | bash
  export PATH="$HOME/.sp1/bin:$PATH"
  sp1up --version 6.10.0
  ```

- On Linux, `protobuf-compiler` and `libclang-dev` for the networking and
  RocksDB dependencies.

## Build and test

CI runs:

```sh
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

CPU proving is the default. NVIDIA proving needs the `cuda` feature on Linux
x86-64; see [GPU proving](docs/gpu-proving.md). Tests that run real SP1 recursion
are `#[ignore]`d and run separately from CI.

## Run a local network

A single validator on CPU proving. Block and chunk proofs must keep up with the
slot schedule and CPU proving is slow, so the specification below uses long
slots and one-block chunks; raise `slot_duration_secs` if finality falls behind.

```sh
cargo build --locked --release -p neutrin0-cli -p neutrin0-node
export PATH="$PWD/target/release:$PATH"

cat > chain-spec.toml <<EOF
name = "local"
chain_id = 1337
genesis_time = $(( $(date +%s) + 300 ))
genesis_gas_limit = 30000000
slot_duration_secs = 60
chunk_size = 1
EOF

# keygen prints the [[validators]] and [[accounts]] entries for the spec;
# amounts are wei, and 32 tokens is the minimum stake.
neutrin0-cli keygen --out keys --name v0 \
  | sed -n '/^# chain-spec.toml entries/,$p' \
  | sed 's/<stake>/32000000000000000000/; s/<balance>/1000000000000000000000/' \
  >> chain-spec.toml

neutrin0-cli genesis --spec chain-spec.toml --write
neutrin0-cli node-config --spec chain-spec.toml --out node.toml --role validator \
  --data-dir data --ikm-path keys/v0.ikm --network-key-path keys/v0.p2p \
  --listen /ip4/127.0.0.1/tcp/30303 --rpc 127.0.0.1:9933
neutrin0-node --config node.toml
```

In another shell, `neutrin0-cli node status` and `neutrin0-cli chunk get` show
the head and finalized chunks. The [operator runbook](docs/operator-runbook.md)
covers multi-host networks, monitoring, bootstrap, upgrades and hard forks.

## Documentation

Operating a node:

| Document | Topic |
| --- | --- |
| [Operator runbook](docs/operator-runbook.md) | Keys, genesis, configuration, health, monitoring, storage, bootstrap, upgrades, hard forks, public RPC |
| [Operator tooling](docs/operator-tooling.md) | `neutrin0-cli` commands, local management socket, transactions, exit codes |
| [Consensus RPC](docs/consensus-rpc.md) | Chunk, certificate and proof queries; durable chain events |
| [Indexer](docs/indexer.md) | PostgreSQL ingestion and GraphQL queries |
| [GPU proving](docs/gpu-proving.md) | CUDA build, configuration and GPU tests |
| [Monitoring](ops/monitoring/README.md) | Prometheus scrape configuration, alert rules and dashboard |

Design: start with the [overview](docs/design/00-overview.md), whose reading map
lists the 23 design documents in order.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and checks, and
[AGENTS.md](AGENTS.md) for the source rules and invariants that changes must
keep. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Participation follows the [code of conduct](CODE_OF_CONDUCT.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions submitted for
inclusion in the work shall be dual-licensed as above, without any additional
terms or conditions.
