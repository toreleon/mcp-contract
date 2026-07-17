#!/usr/bin/env bash
# End-to-end mcp-contract demo with REAL MCP servers and a REAL MCP client
# (the official `mcp` SDK) — no LLM, no docker required.
#
#   Act 1: the official `mcp-server-fetch` reference server, put under
#          hostname-level egress enforcement on real internet traffic.
#   Act 2: a malicious MCP server that DECLARES a file-reading tool but
#          SECRETLY exfiltrates the file — caught by mcp-contract.
#
# Prereqs (demo-only, not framework deps):
#   pip install -e '.[dev]' mcp mcp-server-fetch
# Run from the repo root:
#   PYTHON=.venv/bin/python bash demo/run_demo.sh
set -u
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-.venv/bin/python}"
BIN="$PYTHON -m mcp_contract.cli"
ART=demo/artifacts
mkdir -p "$ART"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

free_port() { $PYTHON -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()"; }
wait_line() { for _ in $(seq 1 60); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
rule() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ─────────────────────────────────────────────────────────────────────────
rule "ACT 1 — real off-the-shelf server: mcp-server-fetch"

rule "1/4  capture the REAL manifest (via the real MCP client)"
$PYTHON demo/mcp_client.py list -- $PYTHON -m mcp_server_fetch 2>/dev/null > "$ART/fetch.manifest.json"
$PYTHON -c "import json;m=json.load(open('$ART/fetch.manifest.json'));print(' tools:',[t['name'] for t in m['tools']])"

rule "2/4  infer a least-privilege policy (deny-by-default)"
$BIN infer "$ART/fetch.manifest.json" --server-id fetch -o "$ART/fetch.policy.yaml"

rule "3/4  operator approves a narrow allowlist: example.com only"
$PYTHON - <<PY
import yaml
p="$ART/fetch.policy.yaml"; d=yaml.safe_load(open(p))
for c in d["x-mcp-contract"]["caps"]:
    if c["id"]=="net.http": c["status"]="inferred"; c["values"]=["example.com"]
yaml.safe_dump(d,open(p,"w"),sort_keys=False); print(" net.http -> inferred [example.com]")
PY

rule "4/4  run the server through the enforcing proxy (needs internet)"
rm -f "$ART/fetch.events.jsonl"
$BIN proxy --policy "$ART/fetch.policy.yaml" --host 127.0.0.1 --port 0 \
    --events-out "$ART/fetch.events.jsonl" > "$ART/fetch.proxy.log" 2>&1 &
PIDS+=($!)
wait_line "$ART/fetch.proxy.log" "listening on" || { echo "proxy failed"; cat "$ART/fetch.proxy.log"; exit 1; }
PORT=$(sed -n 's/.*listening on 127.0.0.1:\([0-9]*\).*/\1/p' "$ART/fetch.proxy.log" | head -1)
export HTTP_PROXY="http://127.0.0.1:$PORT" HTTPS_PROXY="http://127.0.0.1:$PORT"
echo " ALLOWED  fetch https://example.com (raw):"
$PYTHON demo/mcp_client.py call fetch '{"url":"https://example.com/","raw":true,"max_length":120}' \
    -- $PYTHON -m mcp_server_fetch 2>/dev/null | $PYTHON -c "import sys,json;d=json.load(sys.stdin);print('   isError=',d['isError'],'| first bytes:',(d['content'][0][:90] if d['content'] else '').replace(chr(10),' '))"
echo " DENIED   fetch https://www.iana.org:"
$PYTHON demo/mcp_client.py call fetch '{"url":"https://www.iana.org/","raw":true}' \
    -- $PYTHON -m mcp_server_fetch 2>/dev/null | $PYTHON -c "import sys,json;d=json.load(sys.stdin);print('   isError=',d.get('isError'),'|',(d.get('content') or [d.get('error')])[0][:80])"
unset HTTP_PROXY HTTPS_PROXY
echo " proxy egress events:"; sed 's/^/   /' "$ART/fetch.events.jsonl"

# ─────────────────────────────────────────────────────────────────────────
rule "ACT 2 — malicious server: declares file-read, secretly exfiltrates"

rule "1/4  infer a policy from its honest-LOOKING manifest"
$PYTHON demo/mcp_client.py list -- $PYTHON demo/malicious_server.py 2>/dev/null > "$ART/notes.manifest.json"
$BIN infer "$ART/notes.manifest.json" --server-id notes -o "$ART/notes.policy.yaml" 2>/dev/null
$PYTHON - <<PY
from pathlib import Path
from mcp_contract.policy import load_policy
for c in load_policy(Path("$ART/notes.policy.yaml")).caps:
    print(f"   {c.id.value:10} {c.status.value:12} {c.values}")
print("   -> declares filesystem only; NET IS DENIED")
PY

AP=$(free_port)
rule "2/4  BASELINE (no mcp-contract): the exfil succeeds"
rm -f "$ART/recv_baseline.log"
$PYTHON demo/attacker_sink.py "$AP" "$ART/recv_baseline.log" > "$ART/sink1.log" 2>&1 & PIDS+=($!)
sleep 0.4
env EXFIL_IP=127.0.0.1 EXFIL_PORT="$AP" C2_HOST=drop.exfil.zone \
  $PYTHON demo/mcp_client.py call read_note '{"filename":"secrets.txt"}' \
    -- $PYTHON demo/malicious_server.py 2>/dev/null >/dev/null
sleep 0.4
echo "   attacker C2 received:"; sed 's/^/     /' "$ART/recv_baseline.log" 2>/dev/null || echo "     (nothing)"

rule "3/4  ENFORCED (under mcp-contract): the exfil is blocked"
rm -f "$ART/recv_enforced.log" "$ART/notes.events.jsonl"
AP2=$(free_port)
$PYTHON demo/attacker_sink.py "$AP2" "$ART/recv_enforced.log" > "$ART/sink2.log" 2>&1 & PIDS+=($!)
$BIN proxy --policy "$ART/notes.policy.yaml" --host 127.0.0.1 --port 0 \
    --events-out "$ART/notes.events.jsonl" > "$ART/notes.proxy.log" 2>&1 & PIDS+=($!)
wait_line "$ART/notes.proxy.log" "listening on" || { echo "proxy failed"; cat "$ART/notes.proxy.log"; exit 1; }
NPORT=$(sed -n 's/.*listening on 127.0.0.1:\([0-9]*\).*/\1/p' "$ART/notes.proxy.log" | head -1)
sleep 0.3
env EXFIL_IP=127.0.0.1 EXFIL_PORT="$AP2" C2_HOST=drop.exfil.zone \
    HTTP_PROXY="http://127.0.0.1:$NPORT" HTTPS_PROXY="http://127.0.0.1:$NPORT" \
  $PYTHON demo/mcp_client.py call read_note '{"filename":"secrets.txt"}' \
    -- $PYTHON demo/malicious_server.py 2>/dev/null >/dev/null
sleep 0.5
if [ -s "$ART/recv_enforced.log" ]; then echo "   attacker C2 received: $(cat "$ART/recv_enforced.log")";
else echo "   attacker C2 received: NOTHING (0 bytes) — exfil blocked"; fi
echo "   proxy logged:"; sed 's/^/     /' "$ART/notes.events.jsonl"

rule "4/4  BCM verdict — verify against the declared contract"
$BIN verify "$ART/notes.manifest.json" --policy "$ART/notes.policy.yaml" \
    --events "$ART/notes.events.jsonl"; rc=$?
echo "   verify exit=$rc  (0=clean, 1=CONTRACT VIOLATION, 2=rug-pull)"
rule "DEMO COMPLETE"
