# Light clients

A light client follows finality by verifying History proofs: a finalized chunk
receipt, a Compressed STARK that proves the chain from the specification's start
because every chunk Guest verifies its predecessor's receipt
([recursive history](13-recursive-history.md)). It replays no blocks and needs no
WASM executor, BFT voter or prover, and it stores only the latest proof it
accepted. A receipt proves a rules-valid chain, not the chain the network follows,
so the client also decides which endpoint to accept by sampling peers, requires
each new chain to contain its current endpoint, and halts on verified
disagreement. The policy lives in
[`neutrin0-light-client`](../../crates/light-client/src/lib.rs); the node's
`light-client` role persists it.

## Trust model

Recursion from the start proves a rules-valid history. It does not prove
latestness or remove the proof-of-stake long-range problem: validators that have
withdrawn could sign an alternative history. Three mechanisms bound that risk.

- Sampling: accepting an endpoint requires that a quorum of sampled peers
  advertise it identically.
- Anchor openings: every update past the trusted start needs an opening of the
  client's current endpoint under the new one, so a chain forking below the
  client's endpoint cannot be adopted.
- Weak subjectivity: the trust window bounds how far back such a fork can start.
  `ChainSpec::validate` rejects a `weak_subjectivity_period_secs` longer than
  `unbonding_delay_blocks * slot_duration_secs`.

The window is bounded by accountability. A fork signed by validators accountable
at an anchor may surface at any time while the anchor is trusted. Safety evidence
has no age window: a signature is admissible once per identity at any time and
the deduction takes whatever the signer still has at stake
([evidence proofs](16-evidence-proofs.md)), so a signer escapes economically only
by withdrawing fully, which takes one unbonding delay. A chain that wants a longer
trust window lengthens the unbonding delay.

## Endpoint sampling

A peer advertises its finalized endpoint (chunk count and checkpoint hash) in
`Status` and refreshes it with each `CheckpointAnnouncement`; the light role
subscribes only to the checkpoint topic. The client keeps the latest advertisement
of the last `sample_peers` distinct peers, one per host group (an IPv4 /24 or IPv6
/48 prefix), so identities run from one machine or network cannot form a quorum
between them. An advertisement at chunk count zero is never a sample, since the
start is part of the trusted specification.

`sampling::decide(current, samples, quorum)`
([`sampling.rs`](../../crates/light-client/src/sampling.rs)) returns:

- `Advance(endpoint)`: the highest endpoint above the current one that at least
  `sample_quorum` samples advertise identically;
- `Conflict { chunks, first, second }`: two endpoints at one count, or one that
  differs from the current endpoint at its own count, where the disagreeing side
  is advertised by at least two samples; a backed conflict wins over any
  advancement;
- `Wait`: no endpoint above the current one has a quorum yet.

A single advertisement is a hint. Requests pin the endpoint's count and
checkpoint hash, name the client's current count as the anchor, and reject
mismatched replies. A provider that cannot open the anchor reports the request
unavailable, and the client tries the other peers advertising that endpoint.

## Anchor openings

`check_anchor` ([recursive history](13-recursive-history.md#anchors-and-anchor-openings))
decides each update:

| Outcome | Effect |
| --- | --- |
| `Extends` | The new chain contains the client's endpoint; the update proceeds |
| `Invalid` | The path does not verify, or an opening came where none belongs: rejected as the provider's fault; nothing moves or halts |
| `Unopened` | The provider omitted the opening: rejected as the provider's fault (`MissingOpening`) and retried elsewhere; nothing moves or halts |
| `Conflicts` | The new chain does not contain the client's endpoint: the client halts as on a conflict, storing its current proof, the new proof and the opening as evidence |

Every honest full node that has run for one unbonding delay can open any anchor a
live client holds, because its record window covers the weak-subjectivity period.

## Conflicts and the halt

Two sampled endpoints with one count but different checkpoint hashes, or one that
contradicts the client's own endpoint at its count, are a conflict. The client
fetches each side from a peer advertising it and verifies it without accepting it.
A side whose peer cannot back its advertisement with a valid proof stops counting.
An endpoint advertised by a single peer does not hold the client back: it is
checked alongside while a quorum-backed endpoint still advances the client, so one
peer stalling its side cannot delay every update, yet it still halts the client if
its side verifies.

Two verified proofs that disagree at one count take more than a third of the stake
signing both. The client then halts: it durably stores both proofs (or the
configured origin as one side) and any opening as evidence, refuses every further
update, logs an error, reports `history_conflict` in RPC diagnostics and as a
readiness reason, sets the `neutrin0_light_history_conflict` gauge, and stays
halted across restarts. Configuring a new trusted checkpoint (a different origin or
`trusted_at`) is the only way to clear it, and it replaces the halted state with
the new origin.

## Acceptance

`LightClient::accept(proof, opening, expected_endpoint, now, verifier)` completes
every check before changing state:

1. `now` is before the current anchor's expiry.
2. The proof names the client's chain binding, and its end is well formed and
   counts at least one chunk.
3. The end's checkpoint hash is `expected_endpoint`, the endpoint sampling chose.
4. The verifier authenticates the receipt under the specification's chunk Guest.
5. An identical endpoint returns `AlreadyCurrent` without touching trust or
   freshness, so replay never extends the window; a different endpoint at the
   current count is a conflict and a lower one is refused, since trust never moves
   backwards.
6. `check_anchor` relates the current endpoint to the new chain.
7. The endpoint's slot time is at most `max_future_drift_secs` ahead of `now` and
   at most `stale_threshold_secs` behind it.
8. The new expiry is `min(endpoint time, now) + weak_subjectivity_period_secs`.

The node verifies the receipt outside its lock, then compares the client snapshot
and commits the new state and proof in one atomic batch, so concurrent updates
cannot race or leave a partial write.

## Trust configuration

```toml
role = "light-client"

[light_client]
trusted_checkpoint_path = "trusted-checkpoint.borsh"
trusted_at = 1791028800
max_future_drift_secs = 30
sample_peers = 5
sample_quorum = 3
```

| Key | Default | Meaning |
| --- | --- | --- |
| `trusted_checkpoint_path` | none | Borsh `Checkpoint` obtained through an independent trust decision, at most 1 KiB |
| `trusted_at` | none | Unix time of that decision; required with the path |
| `max_future_drift_secs` | 30 | Largest accepted future endpoint time |
| `sample_peers` | 5 | Distinct sampled peers, at most 64 (`MAX_SAMPLE_PEERS`) |
| `sample_quorum` | 3 | Identical advertisements needed; `1 <= sample_quorum <= sample_peers` |

The specification's `[light_client]` parameters are covered by its hash:

| Parameter | Default |
| --- | --- |
| `weak_subjectivity_period_secs` | one unbonding delay of slots, 1,209,600 s (14 days) |
| `stale_threshold_secs` | four chunks of slots, 2,048 s |

Without a checkpoint, genesis at the specification's `genesis_time` is the trust
origin. The weak-subjectivity period runs from the earlier of `trusted_at` and the
checkpoint block's slot time, as for every later endpoint, so trusting an old
boundary late does not make it recent. `neutrin0-cli history checkpoint --out FILE`
writes the latest proven endpoint and reports its block time as `trusted_at`.
Startup time never refreshes trust: restart checks the persisted origin and time
and restores the original expiry. An expired client needs a new trusted bootstrap
in a fresh local database, never an arbitrary peer checkpoint; a client halted on
a conflict is the one case where a newly configured origin replaces its state in
place.

## Node role

`role = "light-client"` runs independently of the full engine's canonical block
index. The node keeps its trust origin, current boundary, expiry and latest
accepted proof, replacing the state and proof together; it does not accumulate
earlier proofs. RPC head and finalized report the accepted boundary,
`history_getLatest` returns the accepted proof, and state and runtime queries
return unavailable. The protocol sync machine has only light-client states besides
`Init` and `Following` ([networking](21-networking.md)).

The persisted state is trusted local storage. The newest receipt proves its
endpoint from the start, but not that the stored origin, anchor and expiry are the
ones the operator configured: replacing the whole database replaces them together.
Recovery from untrusted storage needs authenticated storage or a fresh trust
decision, and peer snapshots cannot serve as trusted local state.

A compact proof cannot reconstruct deleted votes, transactions or state. State,
header and transaction query proofs and browser or mobile verifier distribution
are not implemented ([roadmap](22-roadmap.md#not-implemented)).
