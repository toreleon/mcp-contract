# mcp-contract

A runtime-agnostic engine that treats an MCP server's tool manifest as an
**enforceable contract**: it reads the manifest, infers the minimal sandbox
policy the declared tools actually need, and monitors the server's real
runtime behavior — network, filesystem, process — for drift from what it
declared. A server that says it reads files but opens a socket to
`evil.example.com` is caught not by scanning its description, but by watching
it run.

Full product spec: [SPEC.md](SPEC.md) · module contract: [DESIGN.md](DESIGN.md)
· policy schema research notes: [docs/policy-mcp-notes.md](docs/policy-mcp-notes.md)

## Architecture

```
                 +--------------------------------------+
 MCP manifest -->| PIE - Policy Inference Engine        |
 (tools/list)    | parse -> classify tools -> infer caps|--> policy.yaml
                 +--------------------------------------+    (policy-mcp compatible
                                                              + x-mcp-contract block)
                 +--------------------------------------+       |
                 | RAL - Runtime Adapter Layer          |<------+
                 | policy -> backend-native rules       |
                 | backends: docker | mock (| gvisor...)|
                 +------------------+-------------------+
                                    | boot w/ policy applied; emit events
                                    v
                 +--------------------------------------+
                 | BCM - Behavioral Consistency Monitor |
                 | each event -> within_policy          |
                 |            |  within_manifest_not_policy
                 |            |  outside_contract  <- the alarm
                 +--------------------------------------+
```

Every capability has one of three statuses: `inferred` (confidently derived,
granted at runtime), `needs_review` (class implied but scope unconfirmed —
**not** granted until a human approves), `denied` (no signal — never granted).
Approval in v0 is deliberately low-tech: edit the policy YAML and flip
`needs_review` to `inferred`, narrowing `values` as you go.

A violation means *deviation from the declared contract*, not *dangerous
behavior*. A shell server that declared (and got approved for) `proc.exec`
is fine; a filesystem server opening a socket is not — even though running
commands is "scarier" than opening sockets.

## Quickstart

```bash
pip install -e ".[dev]"

# 1. infer a least-privilege policy from a manifest
mcp-contract infer tests/fixtures/manifests/filesystem.json -o filesystem.policy.yaml
# stderr: 2 caps need review: fs.read, fs.write

# 2. approve: edit filesystem.policy.yaml, flip needs_review -> inferred,
#    narrow values (e.g. ["/data"])

# 3. gate in CI: verify recorded behavior against the contract
mcp-contract verify tests/fixtures/manifests/filesystem.json \
    --policy filesystem.policy.yaml \
    --events tests/fixtures/events/filesystem-exfil.jsonl
# exit 1: net.connect to evil.example.com is outside the declared contract
```

The whole loop is scripted in [examples/quickstart.sh](examples/quickstart.sh);
a CI-gate sketch lives in [examples/github-action.yml](examples/github-action.yml).

### CLI

| Command | What it does | Exit codes |
|---|---|---|
| `infer MANIFEST [-o FILE] [--json]` | manifest → policy YAML; `needs_review` summary on stderr | 0 |
| `run MANIFEST --policy P --backend {docker,mock} --mode {observe,alert,enforce} [--egress-proxy]` | start (or replay) the server, monitor live, optionally write events/report; `--egress-proxy` (docker only) turns on hostname-level network **enforcement** | 0 ok/warning, 1 critical, 3 manifest drift, 4 missing/corrupt input |
| `audit --events E --policy P --manifest M [--json]` | offline classification report | 0 (it reports, it never gates); 4 missing/corrupt input |
| `verify MANIFEST --policy P --events E [--allow-empty]` | the CI gate | 0 clean, 1 outside-contract event, 2 manifest hash mismatch (rug-pull), 4 inconclusive (missing/corrupt input, or zero events observed — never a security signal) |
| `proxy [--allow HOST ...] [--policy P] [--host H] [--port N] [--events-out FILE]` | run the enforcing egress proxy standalone (deny-by-default); logs every allowed/denied attempt as JSONL to stdout; runs until Ctrl-C | 0 clean shutdown |

Machine output (YAML/JSON) goes to stdout, human chatter to stderr.

## Network enforcement: the egress proxy

`net.http` is the one capability whose *values* are hostnames, but the docker
backend only ever sees raw IPs: it discovers connections by polling
`/proc/net/tcp` inside the container, so a policy that grants
`net.http: [api.github.com]` can never be matched against — let alone
enforced on — an observed connection. That is the "docker sees IPs, not
hostnames" gap.

The **egress proxy** closes it. Sanctioned egress is routed *through* a small
stdlib proxy (`mcp_contract.proxy.EgressProxy`) that resolves the hostname
from the `CONNECT` target (or the request URL), checks it against the
allowlist with the **same** `host_matches` rule BCM uses, and:

- **allows** → opens the upstream socket, relays bytes, and emits a
  `net.connect` event carrying `detail["host"]` (`via: "proxy"`);
- **denies** → replies `403 Forbidden` and **never opens the upstream
  socket** (deny-by-default; a denied host never reaches the network).

The allowlist is derived from the policy by `egress_plan`, deny-by-default:
no `net.http` grant → deny all; `["*"]` → open (allow all, still logged);
concrete hosts → allowlist; empty values → deny all (fail closed).

```bash
# Run the enforcing proxy standalone and point any MCP server/client at it:
mcp-contract proxy --allow api.github.com --allow '*.githubusercontent.com'
# … then in the server's environment:
#   HTTPS_PROXY=http://127.0.0.1:<port> HTTP_PROXY=http://127.0.0.1:<port>

# Or derive the allowlist straight from an approved policy:
mcp-contract proxy --policy github.policy.yaml
```

A runnable, docker-free walkthrough (allowed host succeeds, denied host gets
403, emitted events) is in
[examples/egress-proxy-demo.sh](examples/egress-proxy-demo.sh).

**Why it composes — two observation sources, one contract.** With the proxy in
front, hostname-level egress is *enforced*, while the existing
`/proc/net/tcp` poller keeps running. Any **direct** connection to a raw IP
that bypassed the proxy (a server that ignores `HTTP_PROXY` and dials an IP
itself) is exactly the drift the poller catches: it surfaces as an IP-valued
`net.connect` that matches no granted host and lands in `outside_contract`.
So in v0 the raw-IP bypass is **flagged, not blocked** — airtight blocking
needs the internal-network + iptables follow-on (M-series). The proxy makes
the common, well-behaved path enforceable; the poller makes the misbehaving
path *visible*.

Run it under docker with `mcp-contract run … --backend docker --egress-proxy`:
the adapter starts the proxy, injects `HTTP(S)_PROXY` into the container, and
drains the proxy's hostname-level events alongside the IP-level poller events.

## Honest status: v0 vs the roadmap

| Milestone (SPEC §11) | v0 status |
|---|---|
| **M1** PIE + Docker adapter (observe) | **Partial.** Rule-based PIE only — no static analysis of server source; LLM-assist is a guarded protocol (`LLMAssist`) with a `NullLLM` default. The docker adapter observes by polling (not eBPF); hostname-level network *enforcement* now ships via the egress proxy (`--egress-proxy`). |
| **M2** BCM diffing + `verify` CI gate | **Shipped.** Three-bucket classification, `verify` exit codes, GitHub Action sketch, fixture-backed e2e tests. |
| **M3** `policy-mcp` upstream PR + gVisor adapter | **Not started.** Upstream-PR material is collected in `docs/policy-mcp-notes.md`; no gVisor adapter yet. |
| **M4** enforce mode + rug-pull detection | **Partial.** Rug-pull gate is real (`verify` exit 2, `ManifestDriftError` at monitor start). Enforce mode exists; docker per-event "block" is coarse (kill the container), but hostname-level egress is enforced deny-by-default by the egress proxy (`--egress-proxy`). Raw-IP bypass is still only flagged, not blocked (needs internal-network + iptables). |
| **M5** report/SIEM export + fleet API | **Partial.** Per-run JSON report export only; no fleet API. |
| **M6** v1.0 + infra-team pilot | **Not started.** |

## Backend capability matrix

From the `BackendCaps` each adapter declares (`none` / `observe` / `enforce`):

| Axis | mock | docker |
|---|---|---|
| network | enforce | observe · **enforce** w/ `--egress-proxy` [1] |
| filesystem | enforce | enforce [2] |
| process | enforce | observe [3] |
| syscall | enforce | none |
| boot-time policy | yes | yes |
| runtime block | yes | yes (coarse: `docker kill`) |

Known docker gaps in v0, on purpose and documented rather than papered over:

1. **Network: IP-level observe by default, hostname-level enforce with
   `--egress-proxy`.** Without the proxy, connections are discovered by
   polling `/proc/net/tcp` inside the container, so events carry remote IPs
   and per-host egress is only *observed*; `--network none` is applied at
   boot when the policy grants no `net.http` at all. With `--egress-proxy`
   (see [Network enforcement](#network-enforcement-the-egress-proxy)) the
   container's egress is routed through the proxy, which enforces the
   allowlist by hostname (deny-by-default, 403 on miss) and emits
   hostname-level `net.connect` events. Residual v0 limitation: a server that
   ignores `HTTP_PROXY` and dials a raw IP directly is **not blocked**, but
   the `/proc/net/tcp` poller still observes the connection and BCM flags it
   `outside_contract` — airtight blocking needs the internal-network +
   iptables follow-on.
2. **No per-open filesystem events.** Filesystem scope is enforced at boot
   via ro/rw bind mounts derived from granted `fs.read`/`fs.write` values;
   docker emits no per-open events, so runtime fs activity is invisible to
   BCM on this backend.
3. **Process events come from polling `docker top`**, so short-lived
   processes can be missed.

The `mock` backend replays recorded JSONL event streams deterministically —
it is the test/CI backend and the reference for what a full-fidelity adapter
should provide.

## Library usage

```python
from mcp_contract.manifest import load_manifest
from mcp_contract.pie.inference import infer_policy
from mcp_contract.policy import dump_policy
from mcp_contract.bcm.report import classify_events, load_events_jsonl

manifest = load_manifest("tests/fixtures/manifests/filesystem.json")
policy = infer_policy(manifest)
print(dump_policy(policy))            # policy-mcp compatible YAML

events = load_events_jsonl("tests/fixtures/events/filesystem-exfil.jsonl")
report = classify_events(events, policy, manifest)
print(report.severity.value)          # "critical"
for event in report.violations:
    print(event.kind.value, event.detail, "during", event.tool_ctx)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

Docker integration tests are double-gated: they run only when a `docker`
binary is present **and** `MCP_CONTRACT_DOCKER_TESTS=1` is set.
