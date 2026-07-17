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
| `run MANIFEST --policy P --backend {docker,mock} --mode {observe,alert,enforce}` | start (or replay) the server, monitor live, optionally write events/report | 0 ok/warning, 1 critical, 3 manifest drift, 4 missing/corrupt input |
| `audit --events E --policy P --manifest M [--json]` | offline classification report | 0 (it reports, it never gates); 4 missing/corrupt input |
| `verify MANIFEST --policy P --events E [--allow-empty]` | the CI gate | 0 clean, 1 outside-contract event, 2 manifest hash mismatch (rug-pull), 4 inconclusive (missing/corrupt input, or zero events observed — never a security signal) |

Machine output (YAML/JSON) goes to stdout, human chatter to stderr.

## Honest status: v0 vs the roadmap

| Milestone (SPEC §11) | v0 status |
|---|---|
| **M1** PIE + Docker adapter (observe) | **Partial.** Rule-based PIE only — no static analysis of server source; LLM-assist is a guarded protocol (`LLMAssist`) with a `NullLLM` default. Docker adapter observes by polling, not eBPF/proxy. |
| **M2** BCM diffing + `verify` CI gate | **Shipped.** Three-bucket classification, `verify` exit codes, GitHub Action sketch, fixture-backed e2e tests. |
| **M3** `policy-mcp` upstream PR + gVisor adapter | **Not started.** Upstream-PR material is collected in `docs/policy-mcp-notes.md`; no gVisor adapter yet. |
| **M4** enforce mode + rug-pull detection | **Partial.** Rug-pull gate is real (`verify` exit 2, `ManifestDriftError` at monitor start). Enforce mode exists, but docker "block" is coarse: kill the container. |
| **M5** report/SIEM export + fleet API | **Partial.** Per-run JSON report export only; no fleet API. |
| **M6** v1.0 + infra-team pilot | **Not started.** |

## Backend capability matrix

From the `BackendCaps` each adapter declares (`none` / `observe` / `enforce`):

| Axis | mock | docker |
|---|---|---|
| network | enforce | observe [1] |
| filesystem | enforce | enforce [2] |
| process | enforce | observe [3] |
| syscall | enforce | none |
| boot-time policy | yes | yes |
| runtime block | yes | yes (coarse: `docker kill`) |

Known docker gaps in v0, on purpose and documented rather than papered over:

1. **Network events are IPs, not hostnames.** Connections are discovered by
   polling `/proc/net/tcp` inside the container, so events carry remote IPs;
   hostname-level matching (and per-host egress *enforcement*) needs an
   egress proxy, which v0 does not ship. `--network none` is applied at boot
   when the policy grants no `net.http` at all.
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
