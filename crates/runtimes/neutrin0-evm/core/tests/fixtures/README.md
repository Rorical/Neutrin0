These are application-state projections of the official Ethereum EEST v5.4.0
`fixtures_develop.tar.gz` release:
https://github.com/ethereum/execution-spec-tests/releases/tag/v5.4.0

`osaka.json` contains 22 deterministic samples filled for Osaka, including CLZ,
CREATE/CREATE2, nested calls, transient storage, EIP-7702 and maximum refunds.
Each entry records its upstream test identity, file and SHA-256 digest. Raw signed
transaction bytes are extracted directly from the fixture's block RLP.
Application account balances, nonces, code, storage and total EVM gas are preserved.

Ethereum beacon-root, withdrawal/consolidation-request, deposit and historical-block
system accounts are omitted. Neutrin0 supplies its own consensus context and native
block-hash history; it does not execute Ethereum consensus system-block operations
or compare Ethereum MPT roots. This sample suite does not claim full EEST coverage.

Regenerate from an extracted official release with:

```sh
python3 scripts/fixtures/import-evm-fixtures.py target/fixtures crates/runtimes/neutrin0-evm/core/tests/fixtures/osaka.json
cargo test --locked -p neutrin0-evm-runtime-core --test osaka_fixtures
```
