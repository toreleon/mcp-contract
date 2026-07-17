# Phase: Egress-Proxy Network Enforcement — build contract

Companion to `DESIGN.md`. This phase makes `net.http` **enforceable at the
hostname level** and gives BCM hostname-level network events (today the docker
adapter only sees raw IPs from `/proc/net/tcp`, so a granted
`net.http: [api.github.com]` can never match an observed connection). It is the
M2 reference architecture from `docs/OPEN-QUESTIONS.md` (egress proxy +
default-deny, portable across macOS dev / Linux CI / Docker / gVisor).

The v0 core is unchanged and still frozen: `models.py`, `ral/base.py`,
`ral/__init__.py`, `__init__.py`. **Reuse — do not reimplement —
`mcp_contract.bcm.diff.host_matches(host, patterns)`** for every allowlist
decision, so proxy enforcement and BCM classification share one matching rule.

## Why it composes (state this in README)

With the proxy in place, sanctioned egress flows *through* it: the proxy
resolves the **hostname** (from the `CONNECT` target or the request URL),
enforces the allowlist (deny-by-default, 403 on miss), and emits a
`net.connect` event carrying `detail["host"]`. Meanwhile the existing
`/proc/net/tcp` poller still runs: any **direct** connection to a raw IP that
did *not* go through the proxy is itself the drift signal BCM flags
`outside_contract`. Two observation sources, one contract.

## Layout & ownership

| Path | Owner |
|---|---|
| `src/mcp_contract/proxy/__init__.py`, `proxy/plan.py`, `proxy/server.py`, `tests/test_proxy.py` | Module P (proxy core) |
| `src/mcp_contract/ral/docker.py` (network additions only), `tests/test_ral.py` (additions) | Module DK (docker wiring) |
| `src/mcp_contract/cli.py` (additions), `tests/test_cli.py` (additions), `README.md`, `examples/egress-proxy-demo.sh`, `DESIGN.md` (backend matrix + net.http enforcement note) | Module UI |

Module P has no dependency on DK/UI. DK and UI code against Module P's and the
docker adapter's signatures below (built in parallel; the integration step
reconciles). Do not change files outside your row; if you must deviate from a
signature, record it in `api_notes`.

## Module P — proxy core (the security-critical, fully unit-testable part)

`src/mcp_contract/proxy/plan.py`:
```python
@dataclass
class EgressPlan:
    mode: str          # "deny" | "allowlist" | "open"
    hosts: list[str]   # allowlist patterns; [] for deny and open

def egress_plan(policy: Policy) -> EgressPlan
```
Rules (deny-by-default):
- `policy.granted(NET_HTTP)` is `None` → `EgressPlan("deny", [])`.
- granted, values contain `"*"` → `EgressPlan("open", [])` (allow all, still
  observe/log — the operator explicitly widened it).
- granted with concrete host patterns (no `"*"`) →
  `EgressPlan("allowlist", sorted(set(values)))`.
- granted but empty values → `EgressPlan("deny", [])` (empty = grant nothing,
  matches BCM bucket-1 semantics; fail closed).

`src/mcp_contract/proxy/server.py`:
```python
class EgressProxy:
    def __init__(self, allow: EgressPlan | list[str], *,
                 on_event: Callable[[BehaviorEvent], None] | None = None,
                 host: str = "127.0.0.1", port: int = 0,
                 connect_timeout: float = 10.0): ...
    port: int                       # actual bound port, valid after start()
    address: tuple[str, int]
    events: list[BehaviorEvent]     # every emitted event, thread-safe append
    def allowed(self, host: str) -> bool
    def start(self) -> None         # binds + serves in a background daemon thread; returns once bound
    def stop(self) -> None          # idempotent; joins the thread
    def __enter__(self) -> "EgressProxy"
    def __exit__(self, *exc) -> None
```
A bare `list[str]` is wrapped as `EgressPlan("allowlist", list)` (deny-by-default).
Implementation: stdlib only (`http.server`/`socketserver`/`socket`/`ssl` not
required for tunneling — a raw socket relay is enough; `selectors` or two
relay threads are both fine). Threaded so concurrent tunnels don't block.

Request handling:
- **`CONNECT host:port`** (HTTPS and any TLS/TCP tunnel): parse the target
  host (strip the port; lowercase; strip brackets from IPv6). Check
  `self.allowed(host)`.
  - allowed → reply `HTTP/1.1 200 Connection Established\r\n\r\n`, open a TCP
    socket to `(host, port)` with `connect_timeout`, relay bytes both
    directions until either side closes. Emit event `allowed=True`.
  - denied → reply `HTTP/1.1 403 Forbidden\r\n` + short body, **never** open
    the upstream socket. Emit event `allowed=False`.
- **absolute-form HTTP** (`GET http://host/path ...`): host from the request
  line URL (fall back to `Host` header). Same allow check; if allowed, forward
  the request upstream and relay the response; if denied, 403. (A minimal
  forward is acceptable — the CONNECT path is the load-bearing one since MCP
  traffic is overwhelmingly HTTPS; keep the HTTP path correct but simple.)
- **`mode == "open"`**: `allowed()` returns True for every host (still emits
  events). **`mode == "deny"`**: `allowed()` returns False for every host
  (403 everything, emit `allowed=False`). **`allowlist`**: `host_matches`.

Event shape (every connection attempt, allowed or not):
```python
BehaviorEvent(ts=time.time(), kind=EventKind.NET_CONNECT,
    detail={"host": host, "port": port, "allowed": bool, "via": "proxy"},
    backend="egress-proxy")
```
`on_event` is called synchronously from the handler thread; guard `self.events`
and the callback with a lock. The proxy must never crash the process on a
malformed client request or an upstream connection failure — catch per
connection, emit `allowed` accordingly (upstream failure while allowed → still
emit `allowed=True` with `detail["error"]` set), and close the socket.

**Security invariants (tests must pin all of these):**
1. A denied host is **never** connected to upstream (assert with a host pointing
   at a local sentinel server that records hits — it must receive zero).
2. Deny-by-default: an empty allowlist (`EgressPlan("allowlist", [])`) denies
   everything.
3. `host_matches` semantics hold end-to-end: `*.example.com` allows
   `api.example.com`, denies `example.com` and `evil.com`.
4. Every attempt (allow and deny) produces exactly one event with the right
   `host`/`allowed`.
5. Case-insensitive host matching; `CONNECT` with an uppercase host is matched.

`tests/test_proxy.py`: drive the proxy in-process with `http.client`
(`set_tunnel` for CONNECT) and a local `ThreadingHTTPServer` sentinel as the
"upstream". No docker, no external network — bind everything to `127.0.0.1`.
Cover the five invariants + `egress_plan` for all four policy cases + context
manager + `stop()` idempotency.

## Module DK — docker adapter network wiring

Add to `src/mcp_contract/ral/docker.py` (network only; leave the existing
`/proc/net/tcp` and `docker top` polling intact — both event sources coexist):

```python
def translate_network_args(plan: EgressPlan, proxy_endpoint: str | None,
                           spec: ServerSpec) -> list[str]
```
Pure function (unit-test without docker):
- `proxy_endpoint` set (proxy in use) → emit `-e HTTP_PROXY=<ep>`,
  `-e HTTPS_PROXY=<ep>`, plus lowercase `http_proxy`/`https_proxy`, and
  `--add-host=host.docker.internal:host-gateway`; do **not** emit
  `--network none` (the container needs the bridge to reach the proxy).
- no proxy, `plan.mode == "deny"` → `["--network", "none"]` (fail closed).
- no proxy, `plan.mode in ("open","allowlist")` → `[]` (default bridge,
  observe-only; note that without the proxy, allowlist can't be enforced at the
  hostname level — that's the whole reason for the proxy).

`DockerAdapter(..., egress_proxy: bool = False)`:
- On `start`: compute `plan = egress_plan(policy)`. If `egress_proxy` and
  `plan.mode in ("allowlist","open")`: construct an `EgressProxy(plan,
  on_event=<enqueue>, host="0.0.0.0", port=0)`, `start()` it, set
  `proxy_endpoint = f"http://host.docker.internal:{proxy.port}"`; else
  `proxy_endpoint=None`. Feed `translate_network_args(plan, proxy_endpoint,
  spec)` into the `docker run` argv (compose with the existing hardening flags;
  ensure you don't double-add a network flag). Keep the proxy handle on the
  `ServerHandle.native` (or the adapter) so `event_stream` can drain it and
  `stop` can close it.
- `event_stream`: in each poll cycle, also drain the proxy's queued events and
  yield them (hostname-level `net.connect`, `via="proxy"`) alongside the
  `/proc/net/tcp` (IP-level) and `docker top` events. On container exit, stop
  the proxy.
- `stop`: `proxy.stop()` (best-effort) then the existing `docker rm -f`.
- `capabilities()`: `network = ENFORCE` when `egress_proxy` else the existing
  `OBSERVE`.

`tests/test_ral.py` additions: unit-test `translate_network_args` for all three
branches (proxy endpoint present; deny no-proxy → `--network none`; open/allowlist
no-proxy → no network flag; proxy env vars present and no `--network none` when
proxy set). The full docker+proxy path stays behind the existing double gate
(`shutil.which("docker")` and `MCP_CONTRACT_DOCKER_TESTS=1`).

## Module UI — CLI, demo, docs

`src/mcp_contract/cli.py`:
- New subcommand `proxy` — run the enforcing proxy standalone (backend-agnostic;
  point any MCP server or client at it):
  `proxy [--allow HOST ...] [--policy FILE] [--host H] [--port N] [--events-out FILE]`
  Build the allowlist from `--allow` hosts or, with `--policy`, from
  `egress_plan(load_policy(Path(...)))`. Start `EgressProxy`, print each event
  as one JSON line to stdout (and append to `--events-out` if given), run until
  SIGINT; on exit print a one-line summary to stderr. Exit 0 on clean shutdown.
- `run` gains `--egress-proxy` (docker backend only): pass `egress_proxy=True`
  to `get_adapter("docker", egress_proxy=True)`. If used with `--backend mock`,
  print a one-line note to stderr that it has no effect (mock replays events)
  and continue.

`examples/egress-proxy-demo.sh`: runnable from repo root **without docker** —
start `mcp-contract proxy --allow api.github.com` in the background (or drive
the in-process demo), show a curl/python request to an allowed host succeeding
and a denied host getting 403, print the emitted events, then stop. Keep it
robust (kill the bg proxy in a trap).

`README.md`: document the network-enforcement path, resolve the "docker sees
IPs not hostnames" gap for the proxy path, and update the **backend capability
matrix** (docker `network` becomes `ENFORCE` with `--egress-proxy`; note the
residual limitation that a server which ignores `HTTP_PROXY` and dials a raw IP
directly is not *blocked* in v0 but *is* flagged `outside_contract` by the
`/proc/net/tcp` poller — airtight blocking needs the internal-network+iptables
follow-on). `DESIGN.md`: one line in the backend matrix + a note under the
`net.http` semantics that hostname-level enforcement is via the egress proxy.

`tests/test_cli.py` additions: `main(["proxy","--allow","api.github.com",...])`
starts and enforces in-process (allowed vs denied host, event JSONL on stdout),
using an ephemeral port and a local sentinel — no docker, no external network.

## Style
Same as `DESIGN.md`: Python ≥3.11, stdlib + PyYAML only, `from __future__
import annotations`, full type hints, no `shell=True`, tests bind only to
`127.0.0.1` and never reach the real network. Syntax-check every file
(`python3 -m py_compile`). The integration step owns making the whole suite
green.
