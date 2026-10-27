# Operator runbook

Procedures for running a team-operated devnet or a public resettable testnet
(stages 2 and 3 of the [launch stages](design/22-roadmap.md#launch-stages)).
Command details are in [operator tooling](operator-tooling.md) and metric
semantics in the [monitoring package](../ops/monitoring/README.md). The protocol
has no migration path: an incompatible change means a new chain specification and
fresh data directories, so announce every network as resettable.

## Hosts

Validators prove: each needs an NVIDIA GPU, a Linux x86-64 host and a node
built with `--features cuda` ([GPU proving](gpu-proving.md)). Full, archive and reporter nodes can run on CPU. Give every
host a dedicated data filesystem with room for the eight-chunk retention window
plus the storage quota below; archives keep all history and grow without bound.
Use fixed listening ports so bootnode addresses stay valid.

## Keys

```sh
neutrin0-cli keygen --out keys --name v0
```

writes three owner-only files and prints their public identities:

| File | Used by | Purpose |
| --- | --- | --- |
| `v0.ikm` | node (`proposer_ikm_path` or `NEUTRIN0_PROPOSER_IKM_HEX`) | BLS consensus key; also the VRF key |
| `v0.secp256k1` | `neutrin0-cli --key-file` only | account that stakes, votes and receives withdrawals and rewards |
| `v0.p2p` | node (`network_key_path`) | libp2p identity; its peer ID goes into other nodes' bootnode lists |

`neutrin0-cli keys inspect --ikm-path keys/v0.ikm --key-file keys/v0.secp256k1
--network-key keys/v0.p2p` prints the BLS public key, the account address and
withdrawal credentials, and the peer ID without exposing secrets. Keep the IKM and
account key offline except where the node or the CLI reads them; those files are
plain hex.

The validator key comes from exactly one source: a remote signer, an EIP-2335
keystore, `NEUTRIN0_PROPOSER_IKM_HEX` or an owner-only IKM file. An inline
`proposer_ikm_hex` in the configuration is for tests; the node warns when it reads
one. The `validator` role requires a key; use `role = "full"` for a node that
follows the chain without signing or producing blocks.

The node's libp2p identity lives in `<data_dir>/p2p-key`, or in the file
`network_key_path` names. The node creates an owner-only key atomically on first
start and reuses it on restart; a corrupt or loosely permissioned key fails
startup, and with neither path configured the identity is temporary. A running
node logs its peer ID at startup and reports it in `system_diagnostics`.
Configured `bootnodes` are retried with bounded exponential backoff and jitter,
including after disconnection.

To replace the BLS key without exiting, make the new key (`keygen
--keystore-password-file`, or a key in the remote signer), give the node it as
`proposer_next_keystore_path` (or `[remote_signer] next_public_key_hex`) and
restart it, then `neutrin0-cli validator rotate-key --key-file keys/account.secp256k1
--keystore keys/next.keystore.json --password-file keys/password --submit`. At the
next chunk boundary the seat takes the new key and the node signs with it; then
make it `proposer_keystore_path` and drop the old key. The old key stays
accountable for what it signed (design 19).

To keep the BLS key encrypted at rest, write an owner-only password file and use
an EIP-2335 keystore instead of the IKM (design 19):

```sh
neutrin0-cli keygen --out keys --name v0 --keystore-password-file keys/password
# or convert an existing IKM:
neutrin0-cli keys encrypt --ikm-path keys/v0.ikm --password-file keys/password \
  --out keys/v0.keystore.json
```

The node then takes `proposer_keystore_path = "keys/v0.keystore.json"` and the
password from `NEUTRIN0_KEYSTORE_PASSWORD` or `proposer_keystore_password_path`.
A node configured with more than one key source refuses to start.

To hold the key apart from the node, run `neutrin0-signer --config signer.toml`
(`chain_id`, `chain_spec_hash_hex`, `data_dir`, `keystores`, `password_path`,
`unix_socket` in a directory of mode 700, and/or a `[tcp]` table with `listen`,
`cert_path`, `key_path`, `client_ca_path` and one `[[tcp.clients]]` entry per node
certificate: its `certificate_sha256` (`openssl x509 -noout -fingerprint -sha256`)
and the `public_keys_hex` it may use) and give the node a `[remote_signer]` table:
`unix_socket`, or
`address`, `server_name`, `ca_path`, `cert_path` and `key_path` for mutually
authenticated TLS, plus `public_key_hex` when the signer holds several keys. The
signer keeps its own slashing-protection journal and the node checks every
signature it returns. The signer checks lock quorums by shape only, since it
holds no validator sets: against a compromised node it still refuses double
signing, but the lock rule rests on the node's own journal. It refuses a request
further ahead of the highest slot or chunk it signed than one per elapsed second
allows (`ahead of the pace`), so a node asking for a far-future chunk cannot
push its window past the chain.

Never run one BLS key in two places. The signing journals (the node's, and a
remote signer's) are the protection against signing two conflicting messages,
and a safety slash takes the whole slashable balance. As a last line, a validator
signs nothing for `[doppelganger] quiet_chunks` chunks (2) after it starts, and a
message signed by its key that its journal did not reserve pauses signing and
production durably (`Neutrin0Doppelganger`): stop the other instance, then
`validator resume-signing` and `resume-production`.

## Genesis

1. Collect each validator's `[[validators]]` and `[[accounts]]` entries from
   `keygen` into `chain-spec.toml`, together with the faucet account and the
   consensus parameters. Each validator entry carries `pop_hex`, the key's proof
   of possession for its withdrawal credentials; every node verifies it when it
   loads the specification, so a key nobody holds cannot enter genesis. Changing
   the credentials needs a new proof from the key's holder. Keep the default 128-block chunks unless measurements
   justify another size.
2. `neutrin0-cli genesis --spec chain-spec.toml --write` pins the genesis state root
   and the `[programs]` table. Every operator runs it on the same file and compares
   the printed chain-spec hash; that hash is the network's identity.
3. Publish the pinned specification together with the bootnode addresses
   `/ip4/<host>/tcp/<port>/p2p/<peer id>`.

The specification, not the binary, defines the chain. A node uses its embedded
programs only when they reproduce the `[programs]` pins and otherwise reads
`<data_dir>/programs/<content hash>.bin`; programs it needs later are fetched from
peers by identity and checked the same way.

## Node configuration

```sh
neutrin0-cli node-config --spec chain-spec.toml --out v0.toml --role validator \
  --data-dir /srv/neutrin0 --ikm-path keys/v0.ikm --network-key-path keys/v0.p2p \
  --listen /ip4/0.0.0.0/tcp/30303 --bootnode /ip4/10.0.0.2/tcp/30303/p2p/12D3Koo... \
  --metrics 127.0.0.1:9615 --management-socket /run/neutrin0/control/node.sock \
  --proving cuda
```

Prover rewards go to the validator's withdrawal account unless `--prover-address`
names another runtime account. Validators, full and reporter nodes import peer
blocks from receipts and state diffs; archives execute every block, and
`[execution] mode = "execute"` makes any node do so. Add `--rpc` only on nodes that serve RPC (see
below). Run each node under a service manager that restarts it on failure: a failed
critical worker exits the process with the worker's name in the error.

SIGINT and SIGTERM perform a bounded normal shutdown. Startup listener failures
are fatal.

After start, `neutrin0-cli node doctor` must pass, `node status` must show rising
finalized chunks, and `node control-status` (the management socket) must show the
expected peer ID (`local_peer_id`) and committee membership. Public RPC never
reports the local validator's identity, seat or votes.

## Health and metrics

A `[metrics]` listener serves Prometheus text at `GET /metrics`: chain and finality
progress, eligible validators, BFT session stake and events, proof generation,
verification and queue waits, network RPC and bootnode retries, sync progress,
runtime execution and transaction admission, reporter retention, finalized
economic settlements, process resources and RocksDB operations. Labels are finite;
chunk identities are values, and unknown observations carry availability flags.

The same listener serves `GET /health` and `/ready`. They return HTTP 200 when
startup, authenticated bootstrap and sync have completed, any proof-only trust
anchor is still valid, the data filesystem is above its quota, enough peers are
connected and finality has not stalled; otherwise HTTP 503 with a short reason.
`GET /live` checks only the lifecycle and the sampler heartbeat. Health is sampled
once per second whether or not anything polls it. In `[health]`, `min_peers`
defaults to 1 (zero for an intentionally isolated node, which also permits the
initial wait for a first peer; a known unfinished backfill still fails readiness) and
`finality_stall_timeout_secs` defaults to the larger of 1800 seconds and three
nominal chunk durations; set it above the proving latency you measure. These checks
report local state, not agreement among validators.

## Monitoring

Deploy Prometheus with `ops/monitoring`: list every node with its real role in
`targets.json` and `expected-targets.yml`, run `ops/monitoring/check.sh` with
promtool (CI runs it with `install-promtool.sh`), import the dashboard and route
the alerts to a receiver. Critical alerts need a human: a node that is down or
not ready, stalled finality, storage pressure, storage errors, a light-client
History conflict and an expired trust anchor.

## Storage quota

Pruning follows finality, so unfinalized candidates accumulate while chunk proofs
stall. Below `[storage] min_free_bytes` (default 10 GiB) a node stops producing and
ignores new candidates; finality and pruning continue and the pause clears a tenth
above the threshold. Below `halt_free_bytes` (default 2 GiB) the node stops. On
`Neutrin0StoragePressure` or `Neutrin0DiskFillingUp`, first check finality, then
add space. Unfinalized candidates are bounded on their own (`2 * chunk_size`
unproven ones, stale ones deleted after a window), and execution state is read
from disk on demand behind fixed caches, so memory does not grow with the state
or with a finality stall. SP1 verifying-key and fact-receipt caches live in
`<data_dir>/sp1-cache` and are trimmed at start. Back up a full or archive node by
stopping it and copying its data directory; never start a copy of a validator's
data directory while the original can still run.

## Adding a node to a running network

Full nodes, validators and reporters bootstrap from a peer's latest finalized
state. Within the weak-subjectivity period of genesis (14 days by default) no
anchor is needed. Later, take a checkpoint from a node you trust:

```sh
neutrin0-cli history checkpoint --out checkpoint.borsh --rpc http://trusted-node:9933
```

and pass the printed `--trusted-checkpoint checkpoint.borsh --trusted-at <secs>`
to `node-config`; `trusted_at` is the endpoint block's own time, so check
`age_secs` before using it. The checkpoint is only as trustworthy as the node it came from;
the bootstrapping node still verifies a History proof from genesis that contains
it. Archives replay from genesis and take no checkpoint.

Without reachable peers, a node can bootstrap from a snapshot file instead. On a
running full node:

```sh
neutrin0-cli node export-snapshot --out /var/backups/neutrin0.snap \
  --management-socket <socket> [--anchor-chunks N]
```

writes its latest finalized endpoint: the History proof, the manifest a peer would
serve and every program, state and sanctions object, each checked against its
hash on import. `--anchor-chunks` adds the opening an importer whose trust boundary
is at that chunk count needs; a fresh node within the weak-subjectivity period, or
one that trusts exactly the file's endpoint, needs none. Copy the file and set
`[bootstrap] snapshot_path` on the new node: it installs the snapshot before
contacting peers, authenticates it exactly as a network bootstrap (the file is
not judged stale, but its trust anchor must not have expired) and then syncs
forward. An endpoint local finality already reached is skipped.

## Moving a validator

1. Stop the old node and make sure it cannot restart.
2. `neutrin0-cli signing export --data-dir /srv/neutrin0 --out signing.borsh`.
3. Copy the keys and `signing.borsh` to the new host.
4. `neutrin0-cli signing import --data-dir /srv/neutrin0 --file signing.borsh`
   before the node first starts there. Import refuses a data directory of another
   chain or one that already holds a journal; a fresh directory records the
   source chain, and the first start refuses any other specification.
5. Start the new node; it bootstraps state from peers and keeps the imported
   journal and pause policy. A BFT session for a chunk the new node has not
   reached yet waits, survives restarts and a snapshot to that chunk, and
   resumes when the chunk opens.

## Program and policy upgrades

1. Build the runtime WASM and Guest ELFs reproducibly and package them:
   `neutrin0-cli runtime-package --wasm runtime.wasm --block block.elf
   --evidence evidence.elf --genesis genesis.borsh --out upgrade.pkg`.
2. `neutrin0-cli governance status` prints the upgrade window. Choose an
   activation chunk inside it with room for voting: a proposal dies once its
   activation is closer than the lead.
3. `neutrin0-cli governance propose-upgrade --package upgrade.pkg
   --activate-at-chunk N --key-file keys/v0.secp256k1 --submit`; other validators
   run `governance vote --proposal-id 0x...`.
4. After enactment, a producing validator copies the changed artifacts into
   `<data_dir>/programs/publish`; it streams them two pieces per block. The switch
   is void unless `governance status` shows `available` before activation.
5. Every node installs the enacted programs itself. Check `programs status`
   (`scheduled_missing` must be empty) or `Neutrin0UpgradeNotReady` on every node
   before activation.
6. `governance cancel-upgrade` proposes cancelling the enacted switch; it needs two
   thirds of the stake.

Policy changes use `governance propose-policy --chunk-prover-fee-bps 4000 ...`;
unnamed fields keep the policy in force. They take effect after one unbonding delay
plus two blocks for stake-risk fields and 64 chunks otherwise.

## Hard forks

A changed Chunk or Fact Guest or SP1 version needs a successor specification that
continues the chain from a chunk count `F` (design 20). Governance schedules it,
the chain stops itself at `F`, and every node hands over to the successor's binary
from a bundle it writes. Nothing is re-proved and no data directory is edited in
place.

1. With the successor's binary, print the commitment of the programs it pins:

   ```sh
   neutrin0-cli fork programs --spec chain-spec.toml
   ```

   Voters build the release themselves and compare the commitment; the Guest
   builds remap their source paths, so it does not depend on where they build.
2. A validator proposes the fork; the others vote for its proposal id. `F` must
   obey the same lead as a program switch (the CLI prints the window), which gives
   dissenters time to withdraw and every operator time to install the successor's
   binary next to the running one:

   ```sh
   neutrin0-cli governance propose-fork --fork-chunk F --successor 0x<commitment> \
     --key-file account.key --submit
   neutrin0-cli governance vote --proposal-id 0x<id> --key-file account.key --submit
   ```

   Two thirds of the counted stake enact it; `governance cancel-fork` asks the same
   quorum to cancel it before `F`. `governance status` shows the scheduled fork.
3. Nothing else is needed before `F`. From `F` on no node signs, produces or proves
   a chunk of this chain. Once chunk `F − 1` finalizes, every node, validator, full,
   reporter or archive, writes `<data_dir>/fork-endpoint/` (the successor's
   specification without its programs, the endpoint snapshot, the carry of what the
   directory retained and the signing protection) and exits with status 10. Make the
   service manager leave it stopped on that status (systemd:
   `RestartPreventExitStatus=10`). A node that was down catches up first and stops
   at the same place; restarting the old binary only stops it again.
4. Start the successor's binary with the same configuration except a new `data_dir`
   and `[bootstrap] fork_from` naming the old one, and without `chain_spec_path` or
   `snapshot_path`:

   ```toml
   data_dir = "/srv/neutrin0-successor"

   [bootstrap]
   fork_from = "/srv/neutrin0"
   ```

   It derives the successor's specification from the bundle and its own programs,
   refusing programs governance did not schedule, writes it to
   `<data_dir>/chain-spec.toml`, imports the signing protection (proposer slot
   watermarks only), installs the endpoint snapshot as its start and imports the
   carry. Each step runs once, so a restart resumes; the log reports when the
   handoff is complete.

The predecessor's data directory stays intact; keep it until nothing needs its
history (an archive's sources below the fork stay there). Nodes joining later take
`chain-spec.toml` from any successor node, compare its hash out of band as they
would a genesis, and bootstrap from the successor's peers as usual.

## Public RPC

Serve public RPC from full nodes, never from validators, behind a reverse proxy
that terminates TLS and sets CORS. The node limits connections, request and
response sizes, concurrent requests, batch size, call time, subscriptions (16 per
connection, 64 of each kind in total) and concurrent WASM queries, which run
under fuel and memory budgets (`[rpc]` and `[execution]`), and identifies
each client by its address (an IPv4 address, or an IPv6 /64): one client holds at
most `max_connections_per_client` of the `max_connections` connections (16 of 200)
and draws one `requests_per_second_per_client` budget (50 per second, bursts of
100) across all of them. WebSocket sessions take one of `max_ws_connections` slots (32) for their
lifetime and buffer at most four responses for a slow reader.

Behind a proxy every request arrives from the proxy's address. List the proxy in
`[rpc] trusted_proxies`; the node then takes the client from the last entry of
`X-Forwarded-For` on that proxy's connections (the address the proxy itself
received the request from) and exempts the proxy from the per-client connection
bound. Configure the proxy to append the client address and never forward a
client-supplied header unchanged. Keep `/metrics` and the management socket private.

## Resetting the network

Announce the reset and the new specification, stop every node, delete the data
directories (keys and the `.p2p` identities can stay), set a new `genesis_time`,
re-run `genesis --write` and start again. A changed Chunk or Fact Guest or SP1
version needs a new specification: a hard fork (above) or a reset.

## Not provided

Erasure-coded data availability is undefined.
