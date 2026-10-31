# Roadmap

Neutrin0 is an experimental development protocol with no public network. Wire,
database and proof formats change incompatibly between versions, no migration path
is maintained, and every network built from the current sources must be
resettable. This document lists what the sources implement, the bounds they
enforce, the security model they assume, what is missing, and the stages a network
passes through before launch.

## Implemented

Execution and proofs:

- One state-transition core compiled into a WASM runtime (ordinary execution, RPC,
  witness generation) and an SP1 Block Guest proved as a Compressed STARK. The
  runtime is Osaka EVM with staking, governance and accountability exposed as
  precompiles ([runtime interface](02-runtime-interface.md),
  [EVM runtime](03-evm-runtime.md)).
- A complete consensus Chunk Guest that verifies the signed leader proposal,
  certified round entry, both attestation quorums and the consensus transition, and
  recursively verifies the previous chunk's receipt. The latest finalized chunk
  receipt is the History proof from the specification's start
  ([chunk proofs](12-chunk-proofs.md), [recursive history](13-recursive-history.md)).
- A Fact Guest for exact cryptographic verdicts and a batch Evidence Guest for
  objective offences; blocks recursively verify evidence statements and execute
  mandatory sanctions in FIFO order ([evidence proofs](16-evidence-proofs.md)).
- CPU and local CUDA proving for all four proof stages
  ([GPU proving](../gpu-proving.md)).

Consensus and finality:

- Chunk BFT with stake-weighted round leaders, signed proposals, explicit nil
  phases, growing deadlines, authenticated round-change quorums, retained value
  locks and durable session recovery ([BFT protocol](10-bft-protocol.md)).
- Complete chunk proofs as the only finalization path, with a bounded execution
  pipeline that lets one successor chunk proceed while its predecessor's proof is
  pending ([certified execution](11-certified-execution.md)).
- A proof market: candidate and receipt publication, receipt attribution and
  selection, fee escrow and settlement, the invalid execution claim, the carrier
  block and a projected successor boundary
  ([proof-following nodes](07-proof-following-nodes.md),
  [proof market](08-proof-market.md)).
- Runtime governance of execution programs, policy and hard forks, with program
  artifacts distributed in the block body's program lane and an automatic handoff
  from a predecessor chain's endpoint to its successor
  ([upgrades and forks](20-upgrades-and-forks.md)).

Nodes and storage:

- Validators, full and reporter nodes import blocks from receipts and state diffs
  without executing; archives execute by default and `[execution] mode` overrides
  ([proof-following nodes](07-proof-following-nodes.md)).
- Full and validator nodes prune below the eight-chunk finalized window and keep
  bounded historical paths; archives keep the full tree; reporters keep the
  evidence of identities that remain slashable
  ([recursive history](13-recursive-history.md),
  [evidence availability](17-evidence-availability.md),
  [reporter nodes](18-reporter-nodes.md)).
- Authenticated snapshot bootstrap from a peer's latest finalized receipt, in
  resumable bounded slices, and offline snapshot files
  ([recursive history](13-recursive-history.md#snapshot-bootstrap)).
- Proof-only light clients that sample peers and halt on conflicting verified
  History proofs ([light clients](14-light-clients.md)).
- Validator keys from an IKM, an EIP-2335 keystore or a separate `neutrin0-signer`,
  with signing journals, doppelganger protection and on-chain key rotation
  ([validator keys](19-validator-keys.md)).
- Operator tooling, a free-space quota, health endpoints, Prometheus metrics with
  promtool-checked alert rules, and a PostgreSQL/GraphQL indexer
  ([operator runbook](../operator-runbook.md), [indexer](../indexer.md)).

## Bounds and safeguards

| Area | Behavior |
| --- | --- |
| Committee size | At most `MAX_CONSENSUS_VALIDATORS` (256) active and activation-pending seats, and at most `MAX_CONSENSUS_COMMITTEE_BLOCKS` (16,384) seats times blocks per chunk, so 128 seats at the default 128-block chunk. |
| Historical contexts | A thin historical context is `508 + 112N` bytes; eight maximum contexts fit the 256 KiB context budget. Full `HistoricalOpening` carriers keep a separate 8 MiB record limit ([recursive history](13-recursive-history.md#bounded-historical-access)). |
| Vote bytes | Historical participation votes share a 2 MiB budget per chunk. |
| Block size | Local production checks the complete serialized block against the 8 MiB gossip envelope before signing; bounded retries drop only user transactions. |
| Proving input | Block proving envelopes have a chain-spec allocation limit, 32 MiB by default. |
| Exits | A full exit requires another authenticated active, funded, non-exiting member. Retiring seats keep their weight until their exit epoch; the kernel rejects an unusable next committee. |
| Safety bans | A consensus-owned trie permanently bans BLS identities. Chunk values and boundaries bind its root; restart, pruning and snapshot bootstrap retain it, and execution upgrades cannot erase it. |
| Inactivity deductions | Disabled by default. A positive policy reserves a two-chunk window for an omitted signer to publish its precommit, so admission for chunk `k` starts at `k + 3` ([evidence proofs](16-evidence-proofs.md)). |
| Historical membership | Header verification, seed selection, fee escrow and execution inputs use the block's authenticated incoming committee; missing historical context fails closed. |
| Receipt context | Peer import, local proof completion and durable commit bind the evidence anchor, consumed participation report and signed acknowledgements to the retained block body. A mismatch leaves execution pending without manufacturing invalid-proof evidence. |
| Pending views | Query-only head-local simulation uses the stored head environment until the next finalized boundary exists. The pending nonce follows the full contiguous revalidated pool queue, independently of one scratch block's capacity. |
| Durable publication | A head change writes its complete batch (execution state, consensus boundary, identity sanctions) before the head is published. |
| Program sources | Pending manifests and in-flight pins keep the source artifacts a bootstrap needs; installation rechecks the manifest generation before publication. |

## Security model

Chunk safety relies on sound recursive proofs, the immutable chain specification
and Fact and chunk programs, less than one third Byzantine active stake, and honest
validators preserving their durable signing locks. Execution programs are
governable: governance can change application behavior, but not consensus-owned
identity bans or the fixed consensus verification rules.

Progress also needs eventual synchrony, responsive honest stake meeting both quorum
thresholds, a fully available valid candidate and enough proving capacity. Finite
wire and allocation bounds do not establish a wall-clock deadline, and
nonpreemptible native proving calls and CUDA contention affect the schedule.

An unfinalized head is an optimistic view and can reorganize. The BFT finality
checks establish no common-prefix, chain-growth or chain-quality property for it.
Applications that need settled results use `finalized`; `safe` is the proven head.
Execution proofs and recursion give no data-availability sampling guarantee.

An enabled inactivity policy is conditional economics: a valid signature is
positive evidence, a missing one does not prove silence, and censorship or delayed
delivery can defeat the challenge window. Safety evidence stays enforceable at any
age while slashable collateral remains.

The finalized seed folds published proposer VRF proofs into the incoming seed, so a
proposer can bias it by withholding an eligible block. The bias moves who proposes
and who leads BFT rounds, not chunk safety. Applications that need trusted
randomness use an external VRF oracle, and `PREVRANDAO` is fixed for a whole chunk
and known in advance ([randomness](15-randomness.md)).

## Not implemented

- Erasure-coded data availability and sampling.
- Authenticated state, header and transaction query proofs for light clients, and
  a browser or mobile verifier distribution ([light clients](14-light-clients.md)).
- Sustained proving-cost bounds for full-gas blocks, default 128-block chunks,
  larger validator sets and broader rejection inputs. Single-GPU fixture
  measurements are available in [GPU proving](../gpu-proving.md#validated-hardware-and-results).
- A real-proof test of an execution-program switch and of upgrade with snapshot
  bootstrap; only a native preflight covers the switch
  (`governed_upgrade_native_preflight_checks_waiting_chunks` in
  [`evm_composition.rs`](../../crates/runtime-host/tests/evm_composition.rs)).
- Verification of an external VRF oracle on a multi-node network, and the oracle
  network's support for production use
  ([randomness](15-randomness.md#application-randomness)).
- Signing diagnostics (journal contents, refused signatures), a connected-peer
  inventory and native receipt interpretation in the CLI.
- A block explorer frontend over the indexer.

## Verification evidence

The RTX 4090 D run passed all six real-proof cases:
recursive History, two-Block consensus recursion, Evidence/Fact composition with
monetary and consensus effects, and both verdict polarities for real Block
receipts, plus both signed-transfer Block proving cases. The four recursive
gates passed independent CPU receipt verification. The locked workspace
build passed, with 1,746 ordinary tests passing and no failures. The GPU-enabled
node/runtime-host suite passed 460 tests with no failures. Strict Clippy for both
build configurations, Rustdoc with warnings denied, format and monitoring checks
passed.
All eight opt-in final-ELF execution/parity cases, three PostgreSQL integration
cases, three Solidity tests and the Forge/Cast HTTP wallet fixture passed.
An explicit `registered_validator_exits_after_unstake` run passed with mock Block
proofs and native consensus validation. This fixture covers the exit epoch
transition under its fixed committee and leader sequence. The tested artifact
fingerprints and measurement scope are recorded in
[GPU proving](../gpu-proving.md#validated-hardware-and-results).

A single-validator release network also finalized two consecutive chunks with
real proofs after resuming its existing database and signing journals.
A separate single-validator release network finalized two consecutive 64-block
chunks, using 10-second slots and no injected user transactions. The second
chunk finalized after a host scheduling update and a restart with the same
database, signing journals and Guest fingerprints.
Eight EIP-1559 transactions on that network covered wallet funding, transfers,
contract deployment, state updates from both wallets and an expected revert.
All eight reached real-proof finality. Balance and gas accounting, nonces,
bytecode, event logs, historical state queries and block/receipt consistency
checks passed.

Further real-network application tests finalized 52 additional transactions,
including OpenZeppelin ERC-20/ERC-721 behavior, contract rollback and storage
semantics, ethers/viem interoperability, ERC-2612 permits and all 18 Osaka
precompiles. Expected reverts, exact fee accounting, canonical projections and
historical state checks passed. The application and wallet groups finalized at
height 832, the precompile group at height 896 and a zero-amount transfer with
WebSocket and polling-filter checks at height 960. Each group exported its
covering History proof. These functional results and their scope are recorded in
[GPU proving](../gpu-proving.md#validated-hardware-and-results).

The RPC and consensus-lock repair passed the locked workspace build, ordinary
suite (1,758 passed, no failures, 13 ignored), strict all-target Clippy and format
checks on macOS ARM64, plus the Linux CUDA release build. On the same running
network, four HTTP clients completed 1,140 mixed batches with 4,560 successful
responses and no failures across execution certification and real Chunk finality
at height 1,536. A real ERC-20 transfer passed canonical header/log subscriptions,
polling filters, exact fee and nonce accounting, and covering History export.
Database, signing journals and Guest/WASM fingerprints were preserved. These
results cover the tested load and finalization boundary.

## Open verification work

A real-proof result applies only to the Guest ELFs it ran on, and any change to a
Guest-side crate changes every pinned program identity, so each check below must
pass on the final sources.

- The locked workspace build, tests, strict Clippy and format checks that CI runs.
- The ignored real-proof tests in `neutrin0-runtime-host`: recursive History,
  Block-to-Chunk composition, Evidence/Fact composition, receipt verdicts and
  signed-transfer Block proofs. [Proving acceptance](../gpu-proving.md#gpu-tests)
  lists the test names, commands and hardware requirements. CPU execution,
  parity checks and independent receipt verification remain.
  The other ignored tests in `evm_runtime.rs` and `evm_parity.rs` execute the final
  Block ELF without proving and compare it with native and WASM execution.
- Multi-validator restart, partitions, delayed signed-source retrieval,
  omitted-signer acknowledgement, committee churn and upgrade or snapshot recovery.
- An independent review of the BFT safety and liveness model, proposer withholding
  and optimistic fork properties.

## Launch stages

Each stage starts only after the previous stage's exit criteria hold on the same
sources and ELFs. Any Guest, wire or chain-specification change returns to stage 1.

1. Real-proof checks. Run the real-proof acceptance suite on the final sources. Exit:
   every test passes and every receipt verifies under the independent verifier.
2. Closed devnet. Four to seven team-operated validators on separate GPU hosts in
   at least two networks, using the default specification (128-block chunks), with
   a full node, an archive node, a reporter and a light client. Run for at least
   seven days and exercise process and host restarts, a minority partition, a
   quorum-blocking partition, validator registration and exit, an
   execution-program switch through governance, a snapshot-bootstrapped full node
   and the disk-pressure halt. Exit: finality resumes after every fault without
   manual state edits; proof latency, queue waits, RSS, accelerator memory and disk
   growth are recorded; every alert that fired is explained.
3. Public resettable testnet. Requires stage 2 and the independent BFT review.
   Publish the chain specification, bootstrap peers, a faucet and the operator
   documentation, and state that the network resets on incompatible upgrades. Admit
   external validators once someone outside the team has followed the
   [operator runbook](../operator-runbook.md) end to end.
4. Incentivized network. Requires an external security audit of the Guests, the
   runtime system and the node, a decision on erasure-coded data availability, and
   a rehearsed hard fork on a multi-node network.
