#!/usr/bin/env bash
# mcp-contract against REAL PUBLIC MCP servers pulled from npm / PyPI.
# No LLM, no docker. A real MCP client (the `mcp` SDK) drives them.
#
#   Part A: least-privilege inference for the flagship public filesystem server.
#   Part B: a least-privilege table across six public servers (the "wedge").
#   Part C: live hostname egress enforcement on the public fetch server against
#           the real GitHub API.
#
# Prereqs (demo-only): node/npx, outbound internet, and
#   .venv/bin/pip install -e '.[dev]' mcp mcp-server-fetch mcp-server-time
# Run from repo root:
#   PYTHON=.venv/bin/python bash demo/run_public_demo.sh
set -u
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-.venv/bin/python}"
BIN="$PYTHON -m mcp_contract.cli"
ART=demo/artifacts; mkdir -p "$ART"
PIDS=(); cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; }; trap cleanup EXIT
rule(){ printf '\n\033[1m== %s\033[0m\n' "$*"; }
free_port(){ $PYTHON -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()"; }
wait_line(){ for _ in $(seq 1 90); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 1; done; return 1; }

# capture a server's real tools/list into a file (best-effort; slow npx tolerated)
grab(){ local out="$1"; shift; $PYTHON demo/mcp_client.py list -- "$@" 2>/dev/null > "$out"; }

rule "PART A — public filesystem server (@modelcontextprotocol/server-filesystem, npm)"
grab "$ART/pub_filesystem.json" npx -y @modelcontextprotocol/server-filesystem /tmp
$PYTHON -c "import json;m=json.load(open('$ART/pub_filesystem.json'));print(' declares',len(m['tools']),'tools:',', '.join(t['name'] for t in m['tools'][:6])+', ...')"
$BIN infer "$ART/pub_filesystem.json" --server-id filesystem -o "$ART/filesystem.policy.yaml" 2>/dev/null
$PYTHON - <<PY
from pathlib import Path
from mcp_contract.policy import load_policy
print(" inferred least-privilege:")
for c in load_policy(Path("$ART/filesystem.policy.yaml")).caps:
    print(f"   {c.id.value:10} {c.status.value}")
print(" -> filesystem only; network/exec/env denied.")
PY

rule "PART B — least-privilege across six public servers (the wedge)"
grab "$ART/pub_memory.json"     npx -y @modelcontextprotocol/server-memory
grab "$ART/pub_everything.json" npx -y @modelcontextprotocol/server-everything
grab "$ART/pub_sequential.json" npx -y @modelcontextprotocol/server-sequential-thinking
$PYTHON -m mcp_server_fetch --help >/dev/null 2>&1 && grab "$ART/pub_fetch.json" $PYTHON -m mcp_server_fetch >/dev/null 2>&1 || true
grab "$ART/pub_fetch.json" $PYTHON -m mcp_server_fetch
grab "$ART/pub_time.json"  $PYTHON -m mcp_server_time
$PYTHON - <<PY
from pathlib import Path
from mcp_contract.manifest import load_manifest
from mcp_contract.pie import infer_policy
from mcp_contract.models import CapabilityId, CapabilityStatus as S
servers={"filesystem(npm)":"pub_filesystem","fetch(PyPI)":"pub_fetch","memory(npm)":"pub_memory",
         "everything(npm)":"pub_everything","sequential(npm)":"pub_sequential","time(PyPI)":"pub_time"}
sym={S.INFERRED:"GRANT",S.NEEDS_REVIEW:"review",S.DENIED:"deny"}
order=[CapabilityId.NET_HTTP,CapabilityId.FS_READ,CapabilityId.FS_WRITE,CapabilityId.PROC_EXEC,CapabilityId.ENV]
hdr=["server","tools"]+[c.value for c in order]; rows=[]
for name,stem in servers.items():
    p=Path(f"$ART/{stem}.json")
    if not p.exists() or not p.read_text().strip(): continue
    try:
        man=load_manifest(p); pol=infer_policy(man)
        rows.append([name,str(len(man.tools))]+[sym[pol.cap(c).status] for c in order])
    except Exception as e: rows.append([name,"ERR",str(e)[:20],"","","",""])
w=[max(len(str(r[i])) for r in [hdr]+rows) for i in range(len(hdr))]
pr=lambda r: print("  "+"  ".join(str(c).ljust(w[i]) for i,c in enumerate(r)))
pr(hdr); pr(["-"*x for x in w]); [pr(r) for r in rows]
print("\n  GRANT=auto-inferred  review=class known/scope needs human  deny=not implied")
print("  Note: memory persists a JSON file but never declares it -> fs denied;")
print("  a real disk write would be flagged outside_contract at runtime.")
PY

rule "PART C — live egress enforcement: public fetch server -> real GitHub API"
cp "$ART/pub_fetch.json" "$ART/pubfetch.manifest.json"
$BIN infer "$ART/pubfetch.manifest.json" --server-id fetch -o "$ART/pubfetch.policy.yaml" 2>/dev/null
$PYTHON - <<PY
import yaml
p="$ART/pubfetch.policy.yaml"; d=yaml.safe_load(open(p))
for c in d["x-mcp-contract"]["caps"]:
    if c["id"]=="net.http": c["status"]="inferred"; c["values"]=["api.github.com"]
yaml.safe_dump(d,open(p,"w"),sort_keys=False); print(" operator approved allowlist: [api.github.com]")
PY
rm -f "$ART/pubfetch.events.jsonl"
$BIN proxy --policy "$ART/pubfetch.policy.yaml" --host 127.0.0.1 --port 0 \
    --events-out "$ART/pubfetch.events.jsonl" > "$ART/pubfetch.proxy.log" 2>&1 & PIDS+=($!)
wait_line "$ART/pubfetch.proxy.log" "listening on" || { echo "proxy failed"; cat "$ART/pubfetch.proxy.log"; exit 1; }
PORT=$(sed -n 's/.*listening on 127.0.0.1:\([0-9]*\).*/\1/p' "$ART/pubfetch.proxy.log" | head -1)
export HTTP_PROXY="http://127.0.0.1:$PORT" HTTPS_PROXY="http://127.0.0.1:$PORT"
echo " ALLOWED  fetch https://api.github.com/zen:"
$PYTHON demo/mcp_client.py call fetch '{"url":"https://api.github.com/zen","raw":true,"max_length":120}' \
    -- $PYTHON -m mcp_server_fetch 2>/dev/null | $PYTHON -c "import sys,json;d=json.load(sys.stdin);print('   isError=',d['isError'])"
echo " DENIED   fetch https://example.com:"
$PYTHON demo/mcp_client.py call fetch '{"url":"https://example.com/","raw":true}' \
    -- $PYTHON -m mcp_server_fetch 2>/dev/null | $PYTHON -c "import sys,json;d=json.load(sys.stdin);print('   isError=',d.get('isError'),'(blocked)')"
unset HTTP_PROXY HTTPS_PROXY
echo " proxy egress events:"; sed 's/^/   /' "$ART/pubfetch.events.jsonl"
rule "PUBLIC DEMO COMPLETE"
