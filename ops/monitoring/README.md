# Node monitoring

Run Prometheus from this directory with `--config.file=prometheus.yml`.
Set `listen` in each node's `[metrics]` section and replace `targets.json` addresses/roles
with your nodes. Scrape `role` labels must match the
actual configured node role: `role="reporter"` enables reporter-only unavailable
alerts; full and light nodes do not receive them. Update `expected-targets.yml` to the
same desired node names and roles, so losing one service-discovery entry raises
an alert even while the other nodes remain visible. The five loopback entries are an
example; they do not start validators. Keep the endpoint on the private network.
Import `dashboard.json` into Grafana and select the Prometheus datasource.
Prometheus stores alerts locally; configure an Alertmanager receiver in your own
infrastructure to deliver them. No notification destination is configured here.

Validate before deploying:

```sh
PROMTOOL=/path/to/promtool ./check.sh
./check.sh http://127.0.0.1:9615
```

On Linux x86-64, `PROMTOOL="$(./install-promtool.sh DIR)" ./check.sh` installs the
checksum-verified promtool release the artifacts are validated with. CI runs this
check and lints the node's complete metric exposition with `promtool check metrics`.

The script checks scrape configuration, PromQL/rules, alert firing tests,
actual dashboard proof-failure queries with all stages present, unknown/disabled
sync and stale inventory queries, JSON artifacts and, when an endpoint is supplied,
actual metric exposition.
The syntax follows the official [scrape configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
and [alert rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/).
The artifacts were validated with promtool 3.5.0. Tune alert durations for actual
CPU/GPU proving times; a fifteen-minute lack of admitted proof work is a warning,
not evidence of validator misconduct.

`Neutrin0NodeDown` watches Prometheus `up`, because fatal worker supervision stops
the metrics listener. A final `neutrin0_live=0` scrape is not guaranteed. Inspect
service-manager exit codes and the named worker error in node logs. Restart alerts
use changes in process start time and can miss a restart wholly between scrapes.
Enable service-manager restart/failure monitoring as well. Host-wide CPU, memory,
filesystem and other process load can be supplied by node_exporter; the node
exports its own RSS, process CPU usage and I/O, and the data filesystem space.

The node samples operational state once per second independently of requests;
filesystem capacity refreshes every thirty seconds. Unknown observations are
marked by `*_available=0`; economic and filesystem amounts are omitted until
known, rather than exposing a fabricated zero. On a runtime-query failure, the
last successful economic totals remain visible with availability zero and a
last-success height. Alert on availability and query failures before interpreting
those totals.
Sync progress and authenticated full-chunk target availability are separate flags;
an unknown target keeps the node syncing. Peer height hints describe download
goals and do not certify local completion.
The dashboard names unknown progress/targets explicitly and marks full-chunk sync
Disabled when that mode is off. Full-chunk cursors require enabled mode plus known
local progress and target; unknown cursors do not appear as completed progress.

Process counters reset at restart. Runtime `neutrin0_accountability_*_total`
counters are authenticated cumulative chain state: they survive restart and
snapshot installation. Do not sum them across nodes, which would count the same
settlement multiple times. The dashboard uses a maximum across current snapshots.
Amounts are integer wei (18 decimals), not token display units. Prometheus stores
floating-point samples, so totals above 2^53 wei (about 0.009 tokens) lose integer
precision; use the runtime query for exact values. Counter overflow is explicit and never
halts mandatory economic execution.

Execution gas/transaction counters include ordinary dry-run and branch replay;
they measure execution load, not unique canonical chain TPS. Import histograms
include receipt verification, dependency checks and state import. Fact coverage
counts unique requested checks answered by the actual attached receipts in the
latest successfully locally proven chunk, not repeated cryptographic invocations.
The `last_chunk` gauges are not process cumulative counters. Actual proving
inflight requires a global capacity permit; launched block workers may be waiting
for that permit. Wait histograms capture that distinction.
Histogram quantiles estimate bucket ranges. Attempts longer than the final finite
1800-second bucket fall in `+Inf`; the stage last/max gauges retain their actual
durations, so inspect those when CPU proving exceeds that range.
The `neutrin0_local_proof_failures_15m` recording rule computes each stage's
increase separately and preserves a fixed `stage` label before combining them.
The alert sums these stage values per node; the dashboard shows all five stages
(block, chunk, fact and evidence proofs, and program setup).

BFT `slot` labels are bounded to 64 positions in the current session snapshot.
The chunk identity and round are values, never labels; omitted sessions are
explicit in `neutrin0_bft_sessions_unexposed`. BFT action counters include
retransmissions, and deadline actions may request a higher round but do not imply
it was authorized. Stake gauges describe the current round's value/nil aggregates, in wei.
Active validators count positive-weight seats (an ejected identity has zero weight);
total seats are separate.
Proof-only and pending-bootstrap nodes omit validator counts and export
`neutrin0_validator_set_available=0` until they hold the authenticated list.

Reporter retention inventories use durable aggregate metadata, updated with
storage mutations. They do not enumerate historical signatures on every scrape.
Reporter detection counters count fresh successful raw-pool insertions; an offence
reinserted after a drain can increment them again. Lifetime admissions and economic
effects come from the finalized runtime counters.
The proven pool is bounded, so its active/dormant classification can be refreshed
when the inventory revision or finalized boundary changes. An active opening
matches the current finalized history root; admission still checks programs and
runtime state. Cleanup failures never authorize deletion. Retained byte metrics
count serialized keys and values, not filesystem allocation or RocksDB overhead.
Inventory plots and capacity-pressure alerts use only current available samples;
the availability panel shows Unknown instead of stale or fabricated zero inventory.
Reporter-mode inventory remaining unknown for ten minutes raises a separate alert.
Contexts, subtrees and signatures are overlapping breakdowns of their parent
columns; do not add these subcategories to history/indexes/sources/headers or sum
every kind.
Use newly observed finalized transaction counters for per-node TPS; bootstrap
prefixes are excluded, and finalized observation failures indicate incomplete
local source statistics.

No dynamic identity, account, peer address, hash, height, round or error string is
used as a metric label. Method families, protocols, outcomes, phases and priorities
are finite enums. Keep per-peer and per-validator forensic detail in RPC/logs.

`neutrin0_storage_pressure=1` means free space on the data filesystem is below
`[storage] min_free_bytes`: production and new candidate imports pause until
finality prunes or the operator adds space; below `halt_free_bytes` the node stops
and `Neutrin0NodeDown` follows. `Neutrin0DiskFillingUp` extrapolates six hours of
free-space samples a day ahead. `neutrin0_upgrade_missing_programs` counts the
programs of an enacted, not yet activated switch this node has not installed;
`Neutrin0UpgradeNotReady` fires after thirty minutes so operators can act before
activation. `Neutrin0LightHistoryConflict` means two verified History proofs
disagree at one chunk count: treat it as a possible safety failure, not a node fault.
`neutrin0_doppelganger_detected=1` (`Neutrin0Doppelganger`) means the node saw a
message signed by its validator key that its own journal did not reserve, so
another process holds the key; the node paused signing and production durably and
stays paused across restarts until the operator resumes both.
