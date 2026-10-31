# EVM runtime

`neutrin0-evm-runtime-core` is the chain's only runtime: an Osaka EVM on REVM
43.0.0 with the fork selected explicitly (`EVM_SPEC = OSAKA`) and REVM's native
crypto defaults disabled. One `no_std` crate serves native execution, the WASM
master and the SP1 Block Guest, behind the [runtime interface](02-runtime-interface.md).
Ethereum semantics are kept wherever a wallet, contract or tool can observe
them; Neutrin0's own commitments (Poseidon2 state, BLAKE3 blocks) replace
Ethereum's where the proof system needs them. Changing the EVM rules means
installing a new runtime artifact through governance
([upgrades and forks](20-upgrades-and-forks.md)).

## Transactions

Each `RuntimeTransaction::User` payload is one exact EIP-2718 envelope with no
trailing bytes. Supported types are chain-protected legacy (0), EIP-2930 (1),
EIP-1559 (2) and EIP-7702 (4); unprotected legacy transactions, blob
transactions (3) and any chain ID other than the chain's are rejected, as are
high-s signatures. The sender is recovered from the signature, and the
transaction identifier is the Keccak hash of the exact envelope. EIP-7702
delegation uses the Osaka interpreter's authorization processing.

The block transition is total. Every payload is decoded before state access;
an undecodable one, a transaction whose gas limit exceeds the remaining block
gas and one REVM refuses (nonce, balance, fee, intrinsic gas) are skipped with
no effects and no receipt. Reverts and halts stay included and consume the
nonce and the charged gas. A state fault aborts the block instead of skipping,
so withheld or corrupt state can never pass for a skip. Nested EVM state, logs,
collateral and governance effects share one transaction journal, and a block
runs through a disposable overlay that is flushed only once the whole block
has executed.

Every build of the runtime (native, WASM and both SP1 Guests) has overflow
checks on, so an unchecked overflow traps identically everywhere. Genesis and
checked arithmetic reject overflow instead of wrapping.

## Gas and fees

Mandatory participation, evidence and sanction work runs before Ethereum
transactions. Block metadata records system gas and EVM gas separately; their
sum is the block's `gas_used` and drives the next base fee, while Ethereum
receipts' cumulative gas covers Ethereum execution only. The base fee starts at
the specification's positive `initial_base_fee`, targets half the block gas
limit and moves by at most one eighth per block (EIP-1559 with elasticity two
and denominator eight), with a minimum increase of one above target. REVM and
Alloy represent fee caps as `u128` and the block base fee as `u64`; balances and
values are `U256`.

The proposer receives the priority fees during execution, and that is its whole
payment. The base fee is escrowed at block end under `escrow:fees:<height>`
together with the issuance accrued since the previous block, and the next
chunk's carrier settles it to the chunk prover and the participating committee
through the certified proving report, so the base fee is redistributed instead
of burned ([proof market](08-proof-market.md)). Unrewarded sanction deductions
are burned.

## State and commitments

Accounts use 20-byte addresses, `U256` balances, `u64` nonces, Keccak code
hashes, bytecode and 32-byte storage words, stored through `StateBackend` under
`evm:account:`, `evm:code:` and storage keys. Solidity's Keccak storage layout
and Ethereum address derivation are unchanged. The authenticated state trie is
Poseidon2 and native block, body and protocol commitments are BLAKE3
([state and storage](04-state-and-storage.md)), so native block identifiers and
roots are not Ethereum RLP header hashes or MPT roots, and MPT storage proofs
(`eth_getProof`) are not available.

The native token has 18 decimals, and stake, consensus weight, fees, rewards and
EVM balances are all wei with no conversion between them. The staking escrow
(`0x0805`) holds the same token as account balances and gas. Staking amounts
are `u128`: an overflowing Solidity conversion reverts; a bond that would lift
the total stakes, plus the weight consensus seats keep beyond their stake, above
`MAX_TOTAL_STAKE` (`u128::MAX / 2`) fails with `Overflow`; and one validator
account's active stake plus all unclaimed withdrawals must fit `u128` even when
its spendable `U256` balance is larger. Consensus withdrawal credentials are the
Ethereum address left-padded with twelve zero bytes.

## Execution environment

| EVM value | Source |
| --- | --- |
| `NUMBER`, `TIMESTAMP`, `CHAINID` | Authenticated block input |
| `COINBASE` | Proposer's withdrawal address |
| `BASEFEE` | Base fee recorded by the previous block |
| `BLOCKHASH` | Witnessed ring of the last 256 native block hashes (`evm:block_hash:`); zero outside that range |
| `PREVRANDAO` | Incoming finalized chunk seed |

`PREVRANDAO` is the same in every block of a chunk and known before the chunk
begins, so contracts must not use it as randomness. Each block requires a slot
and timestamp strictly greater than the previous block's. Two records keep the
last executed block's environment for historical simulation so that light
blocks stay light: `evm:environment` holds the per-block facts and is rewritten
every block, while `evm:environment:chunk` holds the committee and carried
reports and is rewritten only when the chunk or its carried-report state
changes.

## System interfaces

`contracts/INeutrin0System.sol` specifies the runtime-owned interfaces at
reserved addresses:

| Address | Interface |
| --- | --- |
| `0x0800` | Staking: `registerValidator`, `rotateKey`, `stake`, `unstake`, `exit`, `withdraw`, views `validator` and `withdrawalStatus` |
| `0x0801` | Governance: program, policy and fork proposals, cancellations, `vote`, and views of the policy, live proposals, pending policy, scheduled upgrade and scheduled fork |
| `0x0802` | Consensus: `finalizedSeed`, `producerVrf`, `chunkId`, `finalizedHeight`, `validatorsRoot`, `historyRoot`, `slot`, `nativeParentHash` |
| `0x0803` | Randomness: `randomness(sourceChunk)` |
| `0x0804` | Journal projection of native system records; never user-programmable |
| `0x0805` | Token escrow of active and unbonding collateral |

None of the six can be a genesis allocation or a genesis validator's
withdrawal account, and a system credit or issuance addressed to one pays
nothing. A system call must be a `CALL` or `STATICCALL` to the interface's
own address with zero value; delegate and callcode dispatch, nonzero value and
state-changing calls under `STATICCALL` revert. Amounts debit the caller's
balance explicitly. Each call costs 500 gas, plus 100 per system-record word or
balance read and 1,000 per word written or balance transfer (a record's length
word included), plus the action's own system gas (for example 225,000 for registration and key rotation, which verify a
proof of possession). State-changing calls emit `SystemOperation(address,uint8)`,
proposals also emit `ProposalSubmitted(address,bytes32)` and return their ID,
and an enclosing revert rolls back state and logs alike.

Registration takes a 48-byte BLS public key and a 96-byte proof of possession
bound to the caller's canonical withdrawal account. Only a validator's own
account adds stake; there is no deposit into another validator. Added stake
keeps stake aging, withdrawal holds, permanent identity sanctions and mandatory
FIFO settlement. `rotateKey` replaces the caller's consensus key at the next
chunk boundary ([validator keys](19-validator-keys.md)). `withdrawalStatus`
reports queued and matured funds, whether a pending sanction holds them, and
the next maturity height.

Upgrade proposals name the runtime code hash, the Fact, Evidence and Block keys
(each eight little-endian `u32` words packed into `bytes32`), the four artifact
content hashes and the activation chunk; `factVk` must equal the chain's Fact
key. `cancelUpgrade` names the scheduled program set and activation chunk.
`proposePolicy` accepts the `RuntimePolicy` tuple or its canonical Borsh bytes
(at most 1,024). `proposeFork(uint64,bytes32)` names a hard fork's count and the
commitment of its successor's pinned programs, and `cancelFork` the scheduled
fork. Proposal views list the live proposals of each slot by index, at most one
per proposer; `hasVoted` reports whether an account supports a live proposal.
Eligible aged stake decides by a two-thirds quorum, and an enacted policy takes
effect only after its delay, never within the enacting block
([upgrades and forks](20-upgrades-and-forks.md)).

`producerVrf` returns the producer's VRF output; it has different adversarial
properties from the finalized seed and is unavailable in pending simulations,
where no proposer has signed. `randomness(s)` returns the finalized seed
generated by chunk `s`, with `commitBeforeChunk = s - 1` and
`availableFromChunk = s + 1`; the runtime keeps the eight most recent source
seeds and reverts for a source that has not finalized or has left that window.
The genesis seed has no source-chunk record. `contracts/DelayedRandomness.sol`
fixes participants and inputs in chunk `k`, targets source `k + 2`, settles from
`k + 3` and stores the consumed result. Delay limits adaptive participation but
does not remove withholding bias; applications that need trusted randomness use
an external VRF oracle ([randomness](15-randomness.md#application-randomness)).

## Admission and the pool

`validate_tx` admits only `RuntimeTransaction::User` envelopes and requires a
supported, chain-protected transaction from a sender without code other than an
EIP-7702 delegation designator. The nonce may run at most 64 ahead of the
account's. The gas limit must be between 21,000 and the smaller of the block gas
limit and 2^24, init code at most 49,152 bytes, a type-4 transaction must carry
authorizations, the tip may not exceed the fee cap, and the balance must cover
`fee_cap × gas_limit + value`. A fee cap below the current base fee stays queued
and is never included while underpriced. The priority is the effective tip at
the current base fee.

The pool requires a same-nonce replacement to raise both the fee cap and the tip
cap by ten percent, rounded up with a minimum of one. Queued (future-nonce)
entries share a separate byte reserve and displace only other queued entries.
Inclusion removes only transactions actually persisted on the canonical chain,
and after a reorganization the node re-admits at most 32 MiB of orphaned user
envelopes through ordinary admission.

## Ethereum RPC facade

The facade serves `eth_chainId`, `net_version`, `web3_clientVersion`, balances,
nonces, code and storage, `eth_sendRawTransaction`, `eth_call`,
`eth_estimateGas`, gas price and tip suggestions, `eth_feeHistory`, block,
transaction and receipt lookups (including `eth_getBlockReceipts`), `eth_getLogs`,
polling filters (block, pending-transaction and log) and WebSocket `newHeads`
and `logs` subscriptions. Receipts and logs are projections of authenticated
execution artifacts, decoded by the runtime installed at the selected block.
Native block hashes appear consistently in RPC and `BLOCKHASH`; transaction
hashes are Keccak.

Zero-argument methods accept omitted `params`, `null` and `[]`. Methods validate
positional parameter shapes and argument counts.

Block tags follow Ethereum: `latest` is the executed candidate head, `safe` the
proven head, whose blocks since finality all have verified receipts,
`finalized` the chunk-finalized boundary, and `pending` a simulated next block.
Hash and height selectors use that exact block's state, environment and
historical runtime; unknown, unavailable and pruned data never read the head
instead. EIP-1898 `requireCanonical` checks the hash against the canonical
height mapping. Compatibility indexes follow reorganizations atomically, and
filters emit removed logs.

Pending views execute local candidates in a disposable journal, either as a next
block under its authenticated boundary or, when that boundary is not yet known,
over the head's environment. Their block hash and state root are null, the
hypothetical fee recipient is zero, the next timestamp is slot-derived and the
producer VRF is unavailable. No client-supplied context or state override can
change these facts. Gas estimation pins the context, candidates and scratch
state across all allowance trials in one runtime query.

| Bound | Value |
| --- | --- |
| Log query range | 1,024 blocks, 10,000 results, 2 MiB |
| Polling filters | 128 in total, 16 per client, expired after five minutes idle |
| Filter replay window | 1,024 unfinalized blocks, 2 MiB per filter |
| `eth_feeHistory` | 1 to 1,024 blocks |
| Block bodies read per log or fee-history call | 64 MiB, after which a narrower range is required |

Block reads check the header under the engine lock and read and verify the
body outside it, so RPC traffic never holds the engine while it hashes bodies.
Synchronous database reads, state snapshots, pending preparation and WASM queries
run on a bounded blocking pool. A request timeout cancels the wait; running work
keeps its concurrency slot until it exits. Block rendering projects artifacts
once per response. Subscription polling includes header rendering in its deadline
and advances its cursor only after the whole poll renders successfully; a poll
timeout retries from the same anchor.
Simulations run under the node's query fuel, memory and slot limits and the RPC
request and time limits ([runtime interface](02-runtime-interface.md#historical-queries)).

Blob transport, the Engine API, tracing APIs and MPT proofs are not provided.

## SP1 acceleration

Inside the Block Guest, EVM instructions are interpreted as RISC-V, where
Keccak, signature recovery, modular exponentiation and pairings are expensive.
SP1 has constrained circuits for these operations, distinct from the EVM's
address-based precompiles. Guest-only library patches route the same operations
to those circuits without changing EVM outputs, gas charges or native and WASM
execution; the circuit proves each result, so a host-supplied answer alone is
never trusted. Adding a new SP1 syscall would require coordinated executor,
constraint, prover and verifier changes, so a runtime cannot extend the pinned
SP1 circuits by declaring a host callback; these optimizations use existing
circuits only.

The standalone Guest manifest and lockfile pin the official patches by
immutable commit:

| Guest dependency | SP1 patch | Operations |
| --- | --- | --- |
| `sha3` 0.11 | `patch-sha3-0.11.0-sp1-6.0.0` | Alloy Keccak: `KECCAK256`, code and transaction hashes, address derivation |
| `sha2` 0.11 | `patch-sha2-0.11.0-sp1-6.2.0` | SHA-256 precompile and evidence public-value hashing |
| `sha2` 0.10 | `patch-sha2-0.10.9-sp1-6.2.0` | SP1 public-value hashing and older transitive SHA-256 users |
| `k256` 0.13.4 | `patch-k256-13.4-sp1-6.0.0` | Transaction and EIP-7702 authority recovery, `ECRECOVER` |
| `p256` 0.13.2 | `patch-p256-13.2-sp1-6.0.0` | Osaka P-256 verification precompile |
| `substrate-bn` 0.6 | `patch-0.6.0-sp1-6.0.0-substrate-bn` | BN254 add, multiply and pairing |
| `bls12_381` 0.8 | `patch-0.8.0-sp1-6.0.0` | BLS12-381 operations and KZG |
| `crypto-bigint` 0.5.5 | `patch-0.5.5-sp1-6.0.0` | 256-bit modular multiplication in modexp |

Alloy resolves Keccak through `sha3`, so patching only `tiny-keccak` would
accelerate nothing. K256 and P256 resolve to commits `476243d` and `9237941` of
`sp1-patches/elliptic-curves`, use the secp256k1 and secp256r1 circuits through
`sp1-lib` 6.10.0 and share `elliptic-curve` 0.13.8; K256's ECDSA 0.16.9 is the
`sp1-patches/signatures` commit `1880299`, while P256 keeps registry ECDSA
0.16.9. Low-s and recovered-point checks stay enforced, and REVM keeps Osaka's
input parsing, failure behavior and gas schedule. The host's `k256` 0.14 is a
separate dependency graph. Poseidon2 trie hashing already uses SP1's KoalaBear
permutation.

The Guest enables the core's `sp1-crypto` feature, which installs a Guest-only
REVM crypto provider. BN254 uses the patched `substrate-bn`. BLS12-381 adapts
Ethereum's encodings to the patched `bls12_381`, keeping canonical field, curve
and subgroup checks, infinity rules and REVM's KZG setup; G1 addition and
doubling use curve circuits, multi-scalar multiplication shares Pippenger
windows, and pairing products share one Miller loop and final exponentiation.
Modexp uses constrained 256-bit modular multiplication when base and modulus
fit 256 bits, including even moduli and padded operands, with a four-bit sliding
window for long dense exponents and binary exponentiation otherwise; wider
operands use REVM's portable implementation, so the accepted input domain is
unchanged and exponents keep Osaka's 8,192-byte bound. Native and WASM builds
keep the portable upstream libraries, and a Guest built with
`--no-default-features` is the portable baseline.

The `#[ignore]` test `every_osaka_precompile_executes_in_sp1` in
`crates/runtime-host/tests/evm_runtime.rs` runs every Osaka precompile in the
real SP1 executor, compares public values with WASM and requires the matching
syscall counters (`KECCAK_PERMUTE`, `SECP256K1_ADD`, `SHA_EXTEND`,
`SHA_COMPRESS`, `SECP256R1_ADD`, `UINT256_MUL`, `BN254_FP_MUL`,
`BLS12381_FP2_MUL`, `BLS12381_DOUBLE`) to be nonzero. A rebuilt Guest ELF has a
new key, so its results never carry over from another build.

## Genesis

The chain specification's allocation becomes the runtime's opaque genesis
configuration (`EvmGenesisConfig`). `initial_base_fee` must be positive and
defaults to 1 gwei. Each `[[accounts]]` entry has `address_hex`, a 20-byte
address or canonically padded 32-byte credentials, and either `balance`, a
`u128` wei amount, or `balance_hex`, a 32-byte `U256`. TOML integers stop at
`i64::MAX` (about 9.2 tokens), so `balance`, `effective_stake`,
`min_validator_stake`, `inactivity_leak_amount` and
`abandonment_penalty_amount` also accept decimal strings such as
`"32000000000000000000"`. Validator credentials must be padded Ethereum
addresses. Genesis rejects duplicate accounts, reserved addresses, invalid
bytecode and storage on accounts without code, and records the genesis supply.
`neutrin0-cli genesis --spec <file> --write` derives and pins the state root
and programs, and `neutrin0-cli keygen` writes a validator's key files and
prints their `[[validators]]` and `[[accounts]]` entries; neither funds an
account the specification does not allocate
([operator tooling](../operator-tooling.md)).
