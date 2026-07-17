#!/usr/bin/env bash
# mcp-contract egress-proxy demo: hostname-level net.http enforcement, with
# NO docker and NO real network. It starts a local sentinel "upstream", runs
# the enforcing proxy in front of it (allowlist = 127.0.0.1 only), and shows:
#
#   * an ALLOWED host tunnelling through and getting a 200
#   * a DENIED host getting a 403 from the proxy — never dialled upstream
#   * the per-attempt net.connect events the proxy emits (JSONL)
#
# Run from the repo root (after `pip install -e .`, or as-is — we add src/ to
# PYTHONPATH so it works either way):
#
#   bash examples/egress-proxy-demo.sh
set -euo pipefail

# Make the package importable whether or not it was pip-installed.
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}src"
# Unbuffered so the "listening on ..." lines reach their log files promptly
# (Python block-buffers stdout when it is redirected to a file, not a TTY).
export PYTHONUNBUFFERED=1
PY="${PYTHON:-python3}"

WORK="$(mktemp -d)"
SENTINEL_PID=""
PROXY_PID=""

cleanup() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
  [ -n "$SENTINEL_PID" ] && kill "$SENTINEL_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

wait_for() {  # wait_for <logfile> <sed-extract-expr> -> echoes captured value
  local log="$1" expr="$2" val="" i
  for i in $(seq 1 100); do
    val="$(sed -n "$expr" "$log" 2>/dev/null | head -n1)"
    [ -n "$val" ] && { echo "$val"; return 0; }
    sleep 0.1
  done
  return 1
}

echo "== 1/4 start a local sentinel upstream on 127.0.0.1 (an ephemeral port)"
"$PY" -m http.server 0 --bind 127.0.0.1 >"$WORK/sentinel.log" 2>&1 &
SENTINEL_PID=$!
SENTINEL_PORT="$(wait_for "$WORK/sentinel.log" 's/.*port \([0-9]*\).*/\1/p')" \
  || { echo "sentinel did not start" >&2; cat "$WORK/sentinel.log" >&2; exit 1; }
echo "   sentinel listening on 127.0.0.1:$SENTINEL_PORT"

echo
echo "== 2/4 start the enforcing egress proxy (allowlist: 127.0.0.1 only)"
EVENTS="$WORK/events.jsonl"
"$PY" -m mcp_contract.cli proxy \
  --allow 127.0.0.1 \
  --host 127.0.0.1 --port 0 \
  --events-out "$EVENTS" \
  >"$WORK/proxy.out" 2>"$WORK/proxy.err" &
PROXY_PID=$!
PROXY_PORT="$(wait_for "$WORK/proxy.err" 's/.*listening on 127.0.0.1:\([0-9]*\).*/\1/p')" \
  || { echo "proxy did not start" >&2; cat "$WORK/proxy.err" >&2; exit 1; }
echo "   proxy listening on 127.0.0.1:$PROXY_PORT"

echo
echo "== 3/4 ALLOWED: CONNECT to 127.0.0.1 (on the allowlist) -> tunnels, 200"
if curl -sS --proxytunnel \
    -x "http://127.0.0.1:$PROXY_PORT" \
    -o /dev/null -w "   allowed request HTTP status: %{http_code}\n" \
    "http://127.0.0.1:$SENTINEL_PORT/"; then
  echo "   -> allowed host reached the sentinel"
else
  echo "   unexpected: allowed request failed" >&2
  exit 1
fi

echo
echo "== DENIED: CONNECT to blocked.example (NOT on the allowlist) -> 403"
set +e
DENIED_OUT="$(curl -sS -v --proxytunnel \
  -x "http://127.0.0.1:$PROXY_PORT" \
  "http://blocked.example:$SENTINEL_PORT/" 2>&1)"
DENIED_RC=$?
set -e
if [ "$DENIED_RC" -eq 0 ]; then
  echo "SECURITY FAILURE: denied host was allowed through" >&2
  exit 1
fi
if echo "$DENIED_OUT" | grep -q "403"; then
  echo "   -> proxy returned 403 Forbidden and never dialled blocked.example"
else
  echo "   -> proxy refused the tunnel (curl exit $DENIED_RC):"
  echo "$DENIED_OUT" | sed -n 's/^/      /p' | tail -3
fi

echo
echo "== 4/4 the events the proxy emitted (one net.connect per attempt):"
if [ -s "$EVENTS" ]; then
  sed 's/^/   /' "$EVENTS"
else
  # Fall back to the proxy's stdout stream if the file lagged.
  sed 's/^/   /' "$WORK/proxy.out"
fi

echo
echo "demo complete: hostname-level egress enforcement without docker."
echo "note: MCP traffic is overwhelmingly HTTPS, which uses exactly this"
echo "CONNECT path; point a server at the proxy with HTTPS_PROXY=http://HOST:PORT."
