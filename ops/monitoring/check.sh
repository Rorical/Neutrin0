#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
monitoring_promtool="${PROMTOOL:-promtool}"
"$monitoring_promtool" check config prometheus.yml
"$monitoring_promtool" check rules alerts.yml expected-targets.yml
"$monitoring_promtool" test rules alerts.test.yml
python3 -m json.tool targets.json >/dev/null
python3 -m json.tool dashboard.json >/dev/null
monitoring_query_rules="$(mktemp "${TMPDIR:-/tmp}/neutrin0-dashboard-rules.XXXXXX")"
monitoring_query_tests="$(mktemp "${TMPDIR:-/tmp}/neutrin0-dashboard-tests.XXXXXX")"
trap 'rm -f "$monitoring_query_rules" "$monitoring_query_tests"' EXIT
python3 - "$monitoring_query_rules" "$monitoring_query_tests" <<'PY'
import json
import sys

with open("dashboard.json", encoding="utf-8") as source:
    dashboard = json.load(source)
rules = []
for panel in dashboard["panels"]:
    for index, target in enumerate(panel.get("targets", [])):
        expression = target.get("expr")
        if expression:
            expression = expression.replace("${instance:regex}", ".*")
            assert "$" not in expression, "unhandled Grafana variable"
            rules.append({"record": f"neutrin0_dashboard_check_{panel['id']}_{index}",
                          "expr": expression})
with open(sys.argv[1], "w", encoding="utf-8") as destination:
    json.dump({"groups": [{"name": "dashboard-check", "rules": rules}]}, destination)

# Evaluate the actual dashboard expressions with every proof stage present.
# A syntax-only check misses collisions when rate/increase remove __name__.
proof_stages = {
    "neutrin0_block_proof_total": 1,
    "neutrin0_chunk_proof_total": 2,
    "neutrin0_fact_proof_total": 3,
    "neutrin0_evidence_proof_total": 4,
    "neutrin0_program_setup_total": 5,
}
proof_panel = next(panel for panel in dashboard["panels"] if panel["id"] == 11)
labels = 'instance="node:9615",job="neutrin0",node="validator-1",outcome="failed"'
expressions = []
tested_stages = set()
for target in proof_panel["targets"]:
    expression = target["expr"].replace("${instance:regex}", ".*")
    counters = [counter for counter in proof_stages if counter in expression]
    assert len(counters) == 1, "each proof target must retain one stage"
    counter = counters[0]
    tested_stages.add(counter)
    expressions.append({"expr": expression, "eval_time": "15m",
                        "exp_samples": [{"labels": "{" + labels + "}",
                                         "value": 15 * proof_stages[counter]}]})
assert len(expressions) == len(proof_stages) and tested_stages == set(proof_stages)
tests = {"evaluation_interval": "1m", "tests": [{
    "interval": "1m",
    "input_series": [{"series": counter + "{" + labels + "}",
                      "values": f"0+{slope}x15"}
                     for counter, slope in proof_stages.items()],
    "promql_expr_test": expressions,
}]}

def metric_labels(node, role, **extra):
    labels = {"instance": f"{node}:9615", "job": "neutrin0", "node": node,
              "role": role, **extra}
    return "{" + ",".join(f'{key}="{value}"' for key, value in labels.items()) + "}"

def sample(metric, node, role, value, **extra):
    return {"labels": metric + metric_labels(node, role, **extra), "value": value}

def series(metric, node, role, value, **extra):
    return {"series": metric + metric_labels(node, role, **extra),
            "values": f"{value}+0x15"}

def dashboard_test(panel_id, expected):
    panel = next(panel for panel in dashboard["panels"] if panel["id"] == panel_id)
    assert len(panel["targets"]) == 1
    return {"expr": panel["targets"][0]["expr"].replace("${instance:regex}", ".*"),
            "eval_time": "15m", "exp_samples": expected}

# Exercise enabled, unknown local progress, unknown target and disabled sync.
sync_nodes = [
    ("known", "full", 1, 1, 1, 4),
    ("progress_unknown", "full", 1, 0, 1, 99),
    ("target_unknown", "full", 1, 1, 0, 99),
    ("disabled", "light", 0, 1, 0, 0),
]
sync_series = []
for node, role, enabled, progress, target, cursor in sync_nodes:
    for metric, value in [
        ("neutrin0_sync_full_chunk_enabled", enabled),
        ("neutrin0_sync_progress_available", progress),
        ("neutrin0_sync_full_chunk_target_available", target),
    ]:
        sync_series.append(series(metric, node, role, value))
    sync_series.append(series("neutrin0_sync_full_chunk_cursor", node, role, cursor,
                              kind="next_block"))
    sync_series.append(series("neutrin0_sync_fsm_progress", node, role, cursor,
                              kind="head_height"))
tests["tests"].append({"interval": "1m", "input_series": sync_series,
    "promql_expr_test": [
        dashboard_test(16, [sample("neutrin0_sync_full_chunk_cursor", "known", "full", 4,
                                   kind="next_block")]),
        dashboard_test(30, [sample("neutrin0_sync_progress_available", node, role, progress)
                            for node, role, _, progress, _, _ in sync_nodes]),
        dashboard_test(31, [sample("", node, role, target + 2 * (1 - enabled))
                            for node, role, enabled, _, target, _ in sync_nodes]),
        dashboard_test(33, [sample("neutrin0_sync_fsm_progress", node, role, cursor,
                                   kind="head_height")
                            for node, role, _, progress, _, cursor in sync_nodes if progress]),
    ]})

# Stale nonzero values must disappear; role full does not enable reporter alerts.
inventory_nodes = [("current", "reporter", 1), ("stale", "reporter", 0),
                   ("disabled", "full", 0)]
inventory_series = []
for node, role, available in inventory_nodes:
    inventory_series.extend([
        series("neutrin0_reporter_inventory_available", node, role, available),
        series("neutrin0_reporter_retained_bytes", node, role, 32768, kind="history"),
        series("neutrin0_evidence_pool_bytes", node, role, 33554432, state="active"),
    ])
tests["tests"].append({"interval": "1m", "input_series": inventory_series,
    "promql_expr_test": [
        dashboard_test(20, [sample("neutrin0_reporter_retained_bytes", "current", "reporter",
                                   32768, kind="history")]),
        dashboard_test(21, [sample("neutrin0_evidence_pool_bytes", "current", "reporter",
                                   33554432, state="active")]),
        dashboard_test(32, [sample("neutrin0_reporter_inventory_available", node, role, available)
                            for node, role, available in inventory_nodes]),
    ]})
with open(sys.argv[2], "w", encoding="utf-8") as destination:
    json.dump(tests, destination)
PY
"$monitoring_promtool" check rules "$monitoring_query_rules"
"$monitoring_promtool" test rules "$monitoring_query_tests"
if [[ $# -gt 0 ]]; then
  curl --fail --silent --show-error --max-time 5 "$1/metrics" | "$monitoring_promtool" check metrics
fi
