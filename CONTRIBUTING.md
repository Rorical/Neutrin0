# Contributing to Neutrin0

Neutrin0 is an experimental protocol. Formats change incompatibly between
versions, and there is no migration path to keep, so a change can replace a type,
field or wire layout directly instead of adding a versioned variant.

Participation follows the [code of conduct](CODE_OF_CONDUCT.md).

## Setting up

Install the toolchains listed under prerequisites in the [README](README.md):
the pinned Rust toolchain (`rust-toolchain.toml`), SP1 6.10.0 through `sp1up`, the
`wasm32-unknown-unknown` target, and on Linux `protobuf-compiler` and
`libclang-dev`. The build compiles the SP1 Guest ELFs and the WASM runtime, so a
first build takes a while.

## Before opening a pull request

Run the same checks as CI:

```text
cargo build  --locked
cargo test   --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt    --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --workspace
cargo deny check     # licenses, bans, sources and advisories (cargo install cargo-deny)
```

`Cargo.lock` and the two Guest lockfiles are committed. Do not run
`cargo update` as part of an unrelated change.

Tests that run real SP1 recursion (EvidenceProof, block, chunk and
chunk-to-chunk) are `#[ignore]`d; run them with `--ignored` when a change touches
proving (see [GPU proving](docs/gpu-proving.md)). A change to a Guest-side crate
changes every pinned program identity, so say in the pull request whether it
touches one.

## Code and design

[AGENTS.md](AGENTS.md) holds the source layout rules, lint posture and the
protocol invariants that are easiest to break. Read the design document it points
to before changing that area. A change that alters what a component guarantees
updates the design documents it affects in the same pull request.

## License

By contributing you agree that your contribution is dual-licensed under the
[Apache License, Version 2.0](LICENSE-APACHE) and the [MIT license](LICENSE-MIT),
without additional terms or conditions.
