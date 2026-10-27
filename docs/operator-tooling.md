# Operator tooling

`neutrin0-cli` has two kinds of commands. Offline commands (`keygen`, `keys`,
`genesis`, `node-config`, `runtime-package`, `program-hash`, `signing`, `fork`)
work on local files. Operator commands connect to a running node through the typed
client in `neutrin0-rpc::client`, or to its local management socket.

## Connecting and scripting

```sh
neutrin0-cli node status --rpc http://127.0.0.1:9933 --json
neutrin0-cli node watch --interval-secs 2 --count 5 --json
neutrin0-cli node doctor --json
neutrin0-cli chain genesis --json
neutrin0-cli chain head --json
neutrin0-cli chain finalized --json
neutrin0-cli chain validators --json
neutrin0-cli block header --at 100 --json
neutrin0-cli block get --at finalized --json
```

Endpoint selection is `--rpc`, then `NEUTRIN0_RPC_URL`, then
`http://127.0.0.1:9933`. HTTP(S) requests default to a ten-second deadline,
overridden by `--timeout-secs`. Transactions are never implicitly retransmitted.
`--help` on an RPC command prints the command reference.

`--json` prints one JSON result. Watch emits newline-delimited JSON. Failures
appear on stderr, including RPC error codes and structured retention data.
Submission progress also uses newline-delimited JSON on stderr, preserving the
transaction identifier when a transport error or confirmation timeout occurs.
Exit codes are 0 for successful commands, 1 for transport/runtime/local failures,
2 for invalid arguments, and 3 for failed diagnostic checks or a confirmed EVM
transaction whose execution reverted or halted. Ctrl-C stops watch normally;
interrupting transaction confirmation reports the submitted identifier.

Operator status preserves separate head and complete-chunk finality observations;
History coverage is the finalized chunk count, since the latest finalized chunk
receipt is the History proof. Its constituent queries and live counters are
sampled independently. RPC observations trust the selected provider; they are
not independent light-client proof verification.

`node doctor` diagnoses bootstrap, synchronization, trust-anchor expiry, runtime
availability, storage pressure and a scheduled program switch this node has not
installed. It is not the HTTP `/ready`
verdict: HTTP readiness additionally applies the configured peer policy,
lifecycle, sampler freshness and finality-stall timeout.

## Selected-state views

```sh
neutrin0-cli account get --address 0x... --at finalized --json
neutrin0-cli validator list --json
neutrin0-cli validator status --json
neutrin0-cli validator status --address 0x... --at finalized --json
neutrin0-cli governance policy --at finalized --json
neutrin0-cli governance status --at finalized --json
neutrin0-cli programs status --json
neutrin0-cli proving status --json
neutrin0-cli runtime call --method runtime_info --at finalized --json
```

State views default to `finalized`; block selectors use Ethereum's tags: `latest`
(the candidate head the node follows, which may still reorganize; a following node
has checked only that its published writes reproduce the signed root, so balances
there are a proposer's claim until proven), `safe`
(the proven head: the highest block whose every ancestor since finality has a
verified receipt), `finalized`, decimal/hex heights on the latest head's chain and
32-byte hashes. Multi-query state views resolve the
selector once and query that exact hash. Unknown, unavailable and pruned state
remain distinct errors; there is no fallback to head state. Genesis selectors use
immutable chain-spec facts even when no genesis header is stored.

Account and signing commands address the EVM runtime and check the installed
runtime metadata. `runtime call` reaches any query method with Borsh arguments.
Ethereum addresses are 20 bytes or canonical zero-padded 32-byte withdrawal
credentials.
Large balances, stake amounts and fees are decimal strings in JSON.

## Local node management

The management service is opt-in and separate from public HTTP/WebSocket RPC.
It uses a Unix socket authenticated by filesystem ownership and peer UID; all
processes running as the node's Unix user are trusted operators. Enable it in
the node configuration, or pass `--management-socket` to `node-config`:

```toml
[management]
socket = "/absolute/path/to/private-control/node.sock"
```

The socket's immediate directory must be canonical, owned by the node user and
have mode `0700`. The node creates that leaf directory with mode `0700` if its
parent already exists. It refuses symlink components and existing socket/file
paths, and sets the socket to `0600`. Normal shutdown removes the socket. After
an abrupt process death the next start removes the stale socket only when it is
a socket of the node user that refuses connections, so no process listens on it;
a socket another process still serves, or any other file, is refused. The signer
treats its `unix_socket` the same way. Management is
available on Unix platforms only and does not require public RPC to be enabled.

```sh
export NEUTRIN0_MANAGEMENT_SOCKET=/absolute/path/to/private-control/node.sock
neutrin0-cli node control-status --json
neutrin0-cli validator pause-signing --json
neutrin0-cli validator resume-signing --json
neutrin0-cli validator pause-production --json
neutrin0-cli validator resume-production --json
neutrin0-cli node shutdown --json
```

Use `--management-socket PATH` to override the environment variable. There is no
implicit socket default. Local controls accept `--json` and `--timeout-secs`
(default ten seconds) and refuse `--rpc`. The protocol permits only these fixed
operations, with one bounded request per authenticated connection; it never
exports keys or signs caller-supplied consensus messages.

`pause-signing` closes every local consensus signing path, including block VRF,
header sealing, value/nil votes, round changes and leader proposals. It also
prevents production. `pause-production` prevents new blocks while permitting
votes. The two policies are independent: resuming production leaves a signing
pause in force, and resuming signing leaves a production pause in force.
Neither operation exits a validator or changes its on-chain stake.

Controls serialize with all engine signing and production. A successful pause
response means prior signatures finished and the policy was durably saved
before returning. Previously signed messages can still be broadcast or replayed;
pausing cannot retract published votes or cancel existing proof jobs. Sync,
proof verification and peer-quorum processing continue. Keys, exact signing
reservations, proposer watermarks, BFT locks and original deadlines are retained.
Resume uses the existing BFT recovery path and remains subject to bootstrap,
authenticated committee membership, anti-equivocation and proof gates.
It does not guarantee immediate slot eligibility or node readiness.

Policies persist in local database metadata and load before BFT recovery or
signing on restart, even when the management listener is disabled. Persistence
across process restarts requires `data_dir`; in-memory nodes retain policy only
for their current lifetime. A failed policy write returns an error and closes
both local gates in the running process (`persistence_fault = true`). Repair
storage and successfully write the desired policy before resuming. A failed
write does not acknowledge a durable pause across restart. Corrupt saved policy
refuses startup. A client timeout/disconnect can leave a mutation completed;
query `control-status` before retrying. Mutations are never retried automatically.

`shutdown` closes the signer irreversibly for this process, acknowledges the
request, then enters the same bounded worker shutdown as SIGINT/SIGTERM. Its
response acknowledges shutdown initiation, not completed process exit. It does
not alter the policy saved for the next start. Check process termination before
key or database maintenance. The status result carries the full chain-spec hash,
public validator identity, independent policy flags, storage fault, shutdown,
bootstrap and current membership observations.

Validator address views show runtime stake, withdrawals, maturity and mandatory
sanction holds at the selected state. Current committee seats and local signer
information are independent present-time observations. Queue maturity alone does
not authorize withdrawing held collateral. Registration records omit already
retired registrations and do not enumerate genesis registrations.

## Preparing and submitting transactions

Amounts and fees are integer wei: the native token has 18 decimals, so
`--amount 32000000000000000000` is 32 tokens. The CLI does no decimal conversion.
Keys stay local. Key files must be regular files containing a 32-byte hex seed;
Unix files require mode 600. Key bytes and their textual encoding are zeroized
after use. Existing output files are never overwritten.

```sh
# Prepare and inspect an EIP-1559 transfer without broadcasting.
neutrin0-cli tx transfer --key-file keys/account.secp256k1 \
  --to 0x... --amount 100 --out transfer.bin --json

# Submit previously prepared exact signed bytes.
neutrin0-cli tx submit --file transfer.bin --wait finalized --json

# Arbitrary Solidity/system call, with locally signed EIP-1559 bytes.
neutrin0-cli tx send --key-file keys/account.secp256k1 \
  --to 0x... --data 0x... --submit --wait finalized --json
```

Named transfer, Validator and governance-vote commands prepare by default;
`--submit` explicitly broadcasts. Preparation prints the identifier, operation,
signer, nonce, fee allowance and signed bytes. `--out` writes binary signed bytes,
matching `tx submit --file`. `tx submit` always broadcasts, accepts exactly one of
`--bytes` or `--file`, and checks envelope format and Ethereum chain ID.

Preparation uses the pending nonce, fee suggestions and pending simulation.
It estimates gas unless `--gas-limit` is supplied, then simulates the selected
allowance before signing. Fee caps can be set with `--max-fee-per-gas` and
`--max-priority-fee-per-gas`, and `--nonce` overrides the pending nonce; the node
still performs authoritative transaction admission. `--chain-id`, when supplied,
must equal the connected node's numeric chain ID.

Transactions are standard Ethereum envelopes with Ethereum replay protection.
Consensus identities, which the CLI never signs for, bind the complete chain
specification.

## Validator and governance transactions

```sh
neutrin0-cli validator register --key-file keys/account.secp256k1 \
  --ikm-path keys/validator.ikm --amount 100000 --json
neutrin0-cli validator stake --key-file keys/account.secp256k1 --amount 100 --json
neutrin0-cli validator unstake --key-file keys/account.secp256k1 --amount 100 --json
neutrin0-cli validator exit --key-file keys/account.secp256k1 --json
neutrin0-cli validator withdraw --key-file keys/account.secp256k1 --json
neutrin0-cli validator rotate-key --key-file keys/account.secp256k1 \
  --keystore keys/next.keystore.json --password-file keys/password --json
neutrin0-cli governance vote --key-file keys/account.secp256k1 \
  --proposal-id 0x... --json
neutrin0-cli governance propose-upgrade --key-file keys/account.secp256k1 \
  --package upgrade.pkg --activate-at-chunk 5000 --json
neutrin0-cli governance cancel-upgrade --key-file keys/account.secp256k1 --json
neutrin0-cli governance propose-policy --key-file keys/account.secp256k1 \
  --chunk-prover-fee-bps 4000 --json
neutrin0-cli governance propose-fork --key-file keys/account.secp256k1 \
  --fork-chunk 9000 --successor 0x... --json
neutrin0-cli governance cancel-fork --key-file keys/account.secp256k1 --json
```

These commands call the EVM runtime's staking and governance system
interfaces. Registration binds the BLS proof to the signer's withdrawal account;
only that account adds stake to its validator. `rotate-key` replaces that
account's consensus key with the one in `--keystore` (or `--ikm-path`), proven for
the account; consensus seats it at the next chunk boundary (design 19). `governance status` shows the
open proposals of every slot (program, policy and fork), the scheduled upgrade with
its artifact availability, the enacted policy waiting for its effective height, the
scheduled hard fork and the upgrade window: the chunk the next block executes in, the lead the unbonding delay
requires and the earliest and latest activation chunk a new proposal may name.
VKs print as the little-endian `bytes32` values the interface takes.

`propose-upgrade` proposes the programs and program-lane artifact hashes of a
`runtime-package` file and refuses an activation chunk outside the window before
signing. Choose one with room for voting: a proposal dies once its activation is
closer than the lead. `cancel-upgrade` proposes cancelling the switch scheduled at
the latest head. `propose-policy` starts from the policy in force at the latest
head, replaces the fields given as flags (`--min-validator-stake`,
`--evidence-max-age-blocks`, `--evidence-max-pending`,
`--evidence-admissions-per-block`, `--evidence-executions-per-block`,
`--inactivity-leak-amount`, `--reporter-reward-bps`, `--chunk-prover-fee-bps`,
`--annual-issuance-bps`, `--abandonment-penalty-amount`) and refuses an unchanged
policy. `propose-fork` proposes
ending the chain at `--fork-chunk`, which must lie in the same window, for the
successor whose programs `--successor` commits (see "Hard forks");
`cancel-fork` proposes cancelling the fork scheduled at the latest head. Every
proposal counts the proposer's stake as its first vote.

Exiting is an on-chain operation with the chain's activation/retirement and
unbonding rules. Stopping a process is separate and does not exit a validator.

## Transaction confirmation

```sh
neutrin0-cli tx get --hash 0x... --json
neutrin0-cli tx receipt --hash 0x... --json
neutrin0-cli tx wait --hash 0x... --wait finalized --json
```

Submission, canonical inclusion, execution outcome and finality are separate.
`--wait included` waits for canonical inclusion; `--wait finalized` also checks
the complete-chunk finalized height. Ethereum receipt block hashes are checked
against the canonical height mapping. Orphaned receipts do not confirm a
transaction. Reverted/failed execution remains explicit even after finality.

Confirmation defaults to a 1,800-second overall deadline and one-second polling,
overridden by `--wait-timeout-secs` and `--poll-secs`. Before waiting, submission
prints its identifier to stderr so interruption or timeout does not hide it.
A transport error during submission does not establish rejection; reconcile the
known signed transaction identifier before manually retrying.

## History

```sh
neutrin0-cli history retention --json
neutrin0-cli history latest --out latest-history.borsh --json
neutrin0-cli history checkpoint --out checkpoint.borsh --json
```

`history latest` downloads the latest finalized chunk receipt as a `HistoryProof`,
which proves the chain from genesis; there is nothing to request or schedule.
Downloads preserve the exact Borsh bytes; this command does not claim to
independently verify them.

`history checkpoint` writes that proof's endpoint as a Borsh `Checkpoint`, the
trusted anchor `[bootstrap]` and `[light_client]` read, and prints the
`--trusted-checkpoint` and `--trusted-at` arguments for `node-config`. `trusted_at`
is the endpoint block's own time and `age_secs` its age: weak subjectivity runs
from when the boundary was produced, so a stale provider's old endpoint is not
trusted as fresh. It trusts the
queried node; a bootstrapping node still verifies a History proof from the
specification's start that contains the anchor.

```sh
neutrin0-cli node export-snapshot --out /var/backups/neutrin0.snap \
  --management-socket /run/neutrin0/management.sock [--anchor-chunks N]
```

`node export-snapshot` asks a running full node, over its management socket, to
write its latest finalized endpoint to a new file: the manifest a bootstrap peer
serves (History proof, header, validators, frontier, recent records and, with
`--anchor-chunks`, the opening of that trust boundary) followed by every program,
state and sanctions object, each under its content key. It reports the endpoint,
chunk count, object count and size, and refuses an existing file. A node with
`[bootstrap] snapshot_path` set installs it at startup before contacting peers.

## Keys and validator migration

```sh
neutrin0-cli keygen --out keys --name v0
neutrin0-cli keys inspect --ikm-path keys/v0.ikm --key-file keys/v0.secp256k1 \
  --network-key keys/v0.p2p
neutrin0-cli signing export --data-dir /srv/neutrin0 --out signing.borsh
neutrin0-cli signing import --data-dir /srv/new --file signing.borsh
```

`keygen` also writes the libp2p identity `<name>.p2p` and prints its peer ID, so
bootnode addresses are known before the first start. With
`--keystore-password-file <file>` it writes the BLS key as an EIP-2335 keystore
`<name>.keystore.json` instead of `<name>.ikm`; `keys encrypt --ikm-path <file>
--password-file <file> --out <keystore.json>` converts an existing IKM. `keys
inspect` prints the BLS public key (`--ikm-path`, or `--keystore` without its
password), account address, withdrawal credentials and peer ID of existing files
without printing secrets. Password files must be owner-only regular files.

`signing export` reads a stopped validator's signing journal, unfinalized BFT
sessions and local pause policy; RocksDB's lock refuses a running node. `signing
import` writes them into another data directory in one durable batch before the
validator first starts there. It refuses a directory initialized for another chain
specification and one that already holds journal or session entries, so two
histories of one key are never merged. Never start the old node again. A hard
fork's successor moves its protection itself (see "Hard forks").

## Hard forks

```sh
neutrin0-cli fork programs --spec chain-spec.toml
```

`fork programs`, run with a successor's binary, prints the `[programs]` table that
binary pins as a hard fork's successor and its commitment, the `--successor` value
of `governance propose-fork` (design 20). `--spec` names any specification file of
the chain; only its program pins are replaced. Voters run it on their own build of
the release and compare.

Once the chain finalizes up to an enacted fork, every node writes its endpoint
bundle into `<data_dir>/fork-endpoint/` and exits with status 10; the successor's
binary, started with a new `data_dir` and `[bootstrap] fork_from` naming the old
one, derives its specification and takes over from the bundle. The operator
runbook gives the whole procedure.

## Read-only operational RPC

`system_diagnostics` exposes the chain-spec hash, chunk size, unbonding delay,
proof-only/bootstrap flags, storage pressure, the local libp2p peer ID, sync
phase/cursors, public local signer identity, current committee index,
bounded live BFT observations and proof scheduler occupancy. Local membership is
resolved by BLS identity rather than a configured genesis index. Unavailable
committee observations are explicit; membership does not certify slot eligibility,
signing permission, readiness or global agreement. `chain_getGenesis` exposes
immutable genesis facts.

## Consensus artifacts and chain events

Chunk, certificate and proof inspection, hash-pinned Borsh downloads, HTTP cursor
replay and WebSocket event subscriptions are described in
[consensus RPC](consensus-rpc.md). Use `chunk get|certificate|proof`, `proof get`,
`chain events` and `chain watch-events`. Recovery cursors survive ordinary node
restart; retention expiry explicitly requires snapshot/backfill reconciliation.
