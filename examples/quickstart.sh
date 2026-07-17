#!/usr/bin/env bash
# mcp-contract quickstart: the infer -> approve -> verify loop on the bundled
# fixtures. Run from the repo root after `pip install -e .`:
#
#   bash examples/quickstart.sh
set -euo pipefail

MCP="python3 -m mcp_contract.cli"
MANIFEST=tests/fixtures/manifests/filesystem.json
CLEAN=tests/fixtures/events/filesystem-clean.jsonl
EXFIL=tests/fixtures/events/filesystem-exfil.jsonl

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
POLICY="$WORK/filesystem.policy.yaml"

echo "== 1/5 infer: manifest -> least-privilege policy (fs caps land as needs_review)"
$MCP infer "$MANIFEST" -o "$POLICY"

echo
echo "== 2/5 approve: a human narrows scope and flips needs_review -> inferred"
python3 - "$POLICY" <<'PY'
import sys

import yaml

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    doc = yaml.safe_load(f)
for cap in doc["x-mcp-contract"]["caps"]:
    if cap["id"] in ("fs.read", "fs.write"):
        cap["status"] = "inferred"
        cap["values"] = ["/data"]
with open(path, "w", encoding="utf-8") as f:
    yaml.safe_dump(doc, f, sort_keys=False)
print("granted: fs.read + fs.write under /data")
PY

echo
echo "== 3/5 verify: a clean recorded run passes the CI gate (exit 0)"
$MCP verify "$MANIFEST" --policy "$POLICY" --events "$CLEAN"

echo
echo "== 4/5 verify: an exfiltration run fails the gate (exit 1)"
set +e
$MCP verify "$MANIFEST" --policy "$POLICY" --events "$EXFIL"
rc=$?
set -e
if [ "$rc" -ne 1 ]; then
  echo "expected exit code 1 from verify, got $rc" >&2
  exit 1
fi
echo "caught: read_file triggered a net.connect to evil.example.com -> outside_contract"

echo
echo "== 5/5 run: replay the exfil trace through the live monitor (mock backend)"
set +e
$MCP run "$MANIFEST" --policy "$POLICY" --backend mock --mode observe \
  --events-in "$EXFIL" --report-out "$WORK/report.json"
rc=$?
set -e
if [ "$rc" -ne 1 ]; then
  echo "expected exit code 1 from run, got $rc" >&2
  exit 1
fi
echo "report written to $WORK/report.json (severity: critical)"
echo
echo "quickstart complete."
