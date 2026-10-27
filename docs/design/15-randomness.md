# Randomness

Consensus randomness has two parts: a BLS-VRF that makes each validator's
proposer eligibility per slot private until it publishes, and a public seed that
folds the published VRF proofs of each chunk and drives the next chunk's proposer
draws and BFT round leaders. Both are deterministic and verified identically by
native nodes and the Chunk Guest. The seed is public and biasable by withholding,
which consensus safety does not depend on; applications that need trusted
randomness take it from an external VRF oracle.

## Canonical domain tags

Every consensus signature, VRF proof included, signs

```text
tag (16) || chain_id LE8 || chain_spec_hash (32) || payload
```

(`ConsensusDomain::signing_message`). The 16-byte `DOMAIN_*` tags are constants in
[`primitives`](../../crates/primitives/src/lib.rs) and callers prepend them; the
crypto crate exposes only raw primitives. The consensus domain comes from the
complete locally authenticated `ChainSpec`, so equal numeric chain ids and
identical validator keys cannot replay a proof under another specification. How
the domain extends across a hard fork is in
[upgrades and forks](20-upgrades-and-forks.md).

## Proposer VRF

The VRF input for a slot ([`vrf::eval`](../../crates/vrf/src/eval.rs)) is

```text
DOMAIN_VRF (16) || chain_id (8) || chain_spec_hash (32) || finalized_seed (32) || slot (8)
```

The proof is a deterministic min-pk BLS12-381 signature over that message, so BLS
uniqueness makes it a VRF; the output is `SHA-256(proof)`. Each
`(validator, slot)` has exactly one output per seed.

A validator is eligible when

```text
threshold = floor((2^256 - 1) * E * stake / total_stake)
eligible  = U256(output) < threshold
```

with `U256(output)` the big-endian output and
`E = expected_proposers_per_slot / 2^64` (Q64.64, default 1.0). When
`E * stake / total_stake >= 1` the threshold saturates at `2^256 - 1`; zero stake or
zero total stake is never eligible. Stakes are `u128` wei, and
[`is_eligible`](../../crates/vrf/src/threshold.rs) evaluates the equivalent
`(U256(output) + 1) * d <= (2^256 - 1) * n` exactly in eight 64-bit limbs.
Native header validation and the Chunk Guest check the same identity, signature
and eligibility rules against the block's authenticated incoming committee.

## Public seed: mix of finalized VRF outputs

The next seed folds the chunk's block VRF proofs, in block-height order, into the
incoming seed ([`vrf::seed`](../../crates/vrf/src/seed.rs)):

```text
seed_next = SHA-256(prev_seed || proof_0 || ... || proof_n)
```

Each proof enters as its 96-byte compressed G2 encoding; reordering the inputs
yields a different seed. The Chunk Guest derives it and it travels in the outgoing
`ConsensusBoundary` with the next validator set. Besides proposer eligibility it
draws the next chunk's BFT round leaders ([BFT protocol](10-bft-protocol.md)), so
leader order follows the seed rather than a validator-set encoding a staker could
grind with a top-up or a fresh registration.

Successor blocks may be produced under a certified or projected boundary before
the chunk proof exists ([certified execution](11-certified-execution.md),
[proof market](08-proof-market.md)). A header that fails against a projection that
is later replaced is ignored, never punished, and a failed VRF claim is no offence.
Only complete chunk finalization installs the seed as finalized. Historical
evidence authenticates the seed that applied to its source chunk. History
recursion plays no part in seed advancement.

## Bias

The seed is not a VDF or unbiased private randomness. A proposer that publishes an
eligible final block or withholds it produces different valid inputs to the fold;
chunk BFT fixes the chosen sequence but does not prove the choice was unbiased.
Withholding, reordering and adversarial stake therefore remain protocol
assumptions, and no chain-quality guarantee holds for the unfinalized head. The
protocol adds no stronger beacon, because the bias only moves who proposes and who
leads BFT rounds, which chunk safety does not depend on.

## Application randomness

Contracts see three sources, none of them trusted randomness:

- `PREVRANDAO` returns the seed of the boundary entering the executing chunk. It is
  the same in every block of the chunk, and anyone can compute it from the previous
  chunk's blocks before the chunk begins, so a contract must never treat it as
  unpredictable.
- `producerVrf()` on the consensus interface (`0x…0802`) returns the block
  proposer's VRF output, which the proposer sees before publishing and may withhold.
  A simulated pending block has none.
- `randomness(uint64 source)` on the randomness interface (`0x…0803`) returns the
  seed chunk `source` produced, with `source`, `commitBefore = source − 1` and
  `availableFrom = source + 1`. The runtime keeps the last eight such seeds; an
  older or not yet produced source reverts.

[`contracts/DelayedRandomness.sol`](../../contracts/DelayedRandomness.sol) freezes
participants and inputs in chunk `k`, consumes the seed chunk `k + 2` produces from
chunk `k + 3` on, and stores the result so a pruned source cannot change it. That
removes adaptive participation but keeps the withholding bias, so it suits only
low-value uses.

Applications that need randomness nobody on the chain can bias or predict use an
external VRF oracle such as Chainlink VRF. The oracle signs a VRF over the request
and the request block's hash, and the consumer contract verifies it. Neither the
proposer nor the oracle can choose the output; the oracle can only refuse to
answer. The trust comes from the oracle's operator network, so production use
needs that network to serve Neutrin0, which is an integration rather than protocol
code. A self-operated oracle node checks interface compatibility only; its
randomness is no stronger than its operator's key.

An oracle integration must account for these chain properties:

- `BLOCKHASH` reads a 256-block ring of native BLAKE3 block hashes; older request
  blocks need the oracle's blockhash store.
- The head reorganizes (competing eligible proposers, stale candidates), and a
  reorganized request block changes the VRF input, which gives its proposer
  another draw. The oracle's confirmation count must cover finalization of the
  request block: Chainlink VRF allows at most 200 confirmations, and a chunk is
  `chunk_size` heights (128 by default) plus the blocks produced while its proof
  runs.
- The oracle node relies on logs, new-head subscriptions, the `finalized` tag, fee
  estimation and raw submission through the Ethereum-compatible RPC.
- Payment in the native token avoids bridging an oracle token.
