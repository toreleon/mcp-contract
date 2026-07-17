# mcp-contract — v0 build contract (DESIGN)

Companion to `SPEC.md` (product spec). **This file is the source of truth for
module boundaries and public signatures.** The shared core is already written
and frozen: `src/mcp_contract/models.py` and `src/mcp_contract/ral/base.py`
(+ `ral/__init__.py`, `__init__.py`, `pyproject.toml`). Do not modify frozen
files. If you must deviate from a signature below, record it in your result's
`api_notes`.

## Layout & ownership

| Path | Owner |
|---|---|
| `src/mcp_contract/manifest.py`, `src/mcp_contract/pie/*` , `tests/test_manifest.py`, `tests/test_pie.py` | Module A |
| `src/mcp_contract/policy/*`, `tests/test_policy_io.py`, `docs/policy-mcp-notes.md` | Module B |
| `src/mcp_contract/bcm/*`, `tests/test_bcm.py` | Module C |
| `src/mcp_contract/ral/docker.py`, `src/mcp_contract/ral/mock.py`, `tests/test_ral.py` | Module D |
| `src/mcp_contract/cli.py`, `tests/fixtures/**`, `tests/test_cli.py`, `examples/*`, `README.md` | Module E |
| `docs/OPEN-QUESTIONS.md` | Module F (research) |

Modules A–D unit tests use **inline dicts/objects**, not `tests/fixtures/`
(Module E owns that dir; parallel builds must not collide).

## Shared semantics (all modules)

**Capability statuses.** `inferred` = granted at runtime. `needs_review` =
class implied by the manifest but scope unconfirmed — **not** granted.
`denied` = not implied — never granted. An emitted policy always lists all
five capability classes so deny-by-default is explicit. Approval flow v0: a
human edits the policy YAML and flips `needs_review` → `inferred` (optionally
narrowing `values`). There is no separate "approved" status.

**Host matching** (`net.http` values): exact match (case-insensitive),
global wildcard `"*"`, suffix wildcard `"*.github.com"` (matches any
subdomain, **not** `github.com` itself). Values may be hostnames or IPs.
Port is ignored in v0. Hostname-level `net.http` *enforcement*
(deny-by-default, 403 on miss) is delivered by the egress proxy — see
`docs/DESIGN-egress-proxy.md` — which reuses this same `host_matches` rule;
the docker `/proc/net/tcp` poller only ever sees IPs, so the proxy is what
makes a granted hostname enforceable at runtime.

**Path matching** (`fs.read`/`fs.write` values): values are path prefixes
(absolute or `./`-relative). Normalize both sides with
`posixpath.normpath` before comparing; `/data` matches `/data` and
`/data/x` but **not** `/database` (prefix must end at a path separator).

**Proc matching** (`proc.exec` values): values are allowed program
basenames; empty values = class-level (any program).

**Event → capability mapping** (used by BCM):
- `net.connect` → (`net.http`, `detail["host"]` or `detail["ip"]`)
- `fs.open` mode `r` → (`fs.read`, `detail["path"]`); modes `w`/`a`/`rw` → `fs.write`;
  any other or unknown mode (`r+`, `x`, ...) fails closed to `fs.write`
- `proc.spawn` → (`proc.exec`, basename of `detail["argv"][0]` or `detail["cmd"]` first token)
- `env.read` → (`env`, `detail["var"]`)
- `mcp.call` → context marker only: updates current `tool_ctx`, never a violation
- `syscall` and unknown kinds → informational in v0, classify `within_policy`

**BCM classification** (spec §5.3). Given event `e` mapping to `(cap_id, value)`:
1. If policy has `cap_id` with status `inferred` and `value` matches its
   values (empty values on `proc.exec` = class-level match; `net`/`fs`/`env`
   with empty values match nothing; a class-level `env` grant is written
   `values: ["*"]`) → `within_policy`.
2. Else if the **manifest-implied capability set** (union of PIE
   classification over all tools, any status) contains `cap_id` and the
   value matches the implied values — where implied values `[]` or `["*"]`
   (class-level / unknown scope) match anything → `within_manifest_not_policy`.
3. Else → `outside_contract`.

Rationale: a `needs_review` cap is manifest-implied, so its events land in
bucket 2 (nudge to approve), not bucket 3. A fs-server suddenly opening a
socket lands in bucket 3 even though `net.connect` is a "normal" thing to do
— violation means *deviation from the declared contract*, not *dangerous*.

## Module A — manifest parsing + PIE

`src/mcp_contract/manifest.py`:
```python
def load_manifest(source: str | Path | dict) -> Manifest
```
Accepts a path to a JSON or YAML file, or an already-parsed dict. Supported
shapes: `{"tools": [...]}` (MCP `tools/list` result), `{"result": {"tools":
[...]}}` (full JSON-RPC response), `{"name": ..., "tools": [...]}`.
`server_name` from `"name"`/`"serverInfo".name` if present, else file stem,
else `"unknown"`. Each tool → `ToolIR` (accept both `inputSchema` and
`input_schema` keys). Raise `ValueError` with a clear message on
unrecognized shapes.

`src/mcp_contract/pie/classifier.py`:
```python
def classify_tool(tool: ToolIR) -> list[Capability]
```
Rule-based, conservative. Starting rule set (extend if useful, keep each
rule producing `Evidence(tool=name, source=..., detail=...)`):
- **net.http**: URL literal in description (`https?://host`) → host,
  `inferred`. Bare hostname literal in description (e.g. `api.github.com`)
  → `inferred` only when its final label is on a conservative known-TLD
  allowlist (file-extension lookalikes like `*.json`, `.py`, `.md` are
  dropped outright; anything else — `data.parquet`, `model.pt`, `os.path` —
  is ambiguous and clamps to `needs_review` with the literal kept for the
  reviewer: an extension denylist can never be complete, so ambiguity
  fails closed). Param named/containing
  `url|uri|link|endpoint|host|domain|address` or JSON-Schema `format: uri`
  → net class, scope-unknown: `needs_review` with `"*"` unioned into the
  values **even when a host literal (e.g. an example URL) is present** —
  the endpoint is a caller-supplied runtime value (spec §4.4), so the
  literal never absorbs the param signal. Description verbs
  `fetch|download|http|api|request|webhook|scrape|crawl|post to` →
  net class; alone → `needs_review` `["*"]`; alongside unambiguous host
  literals they are confirmation only.
- **fs.read / fs.write**: param named/containing
  `path|file|filename|filepath|dir|directory|folder|dest|destination` →
  fs class. Direction from tool name/description verbs: read-ish
  (`read|get|list|view|cat|open|stat|search|glob|load`) → `fs.read`;
  write-ish (`write|create|save|delete|remove|move|copy|append|edit|mkdir|rename`)
  → `fs.write` (move/copy also implies `fs.read`). Literal path in
  description → `inferred` with that prefix; otherwise `needs_review`
  with values `[]` (class-level). Exception (fail closed): when the tool
  carries any network signal (URL/hostname literal, net verb, url-ish
  param), a "path" param and `/...` literals are likely URL routes, so fs
  is clamped to `needs_review` (harvested values kept for the reviewer);
  route templates (`/repos/{owner}/...`) are never harvested as prefixes.
- **proc.exec**: name/description matching
  `exec|execute|shell|bash|command|cmd|terminal|subprocess|spawn|script`
  (require word-ish matches; bare "run" alone is too broad — accept
  `run_command`, "run a shell command", not "run analysis") →
  **always `needs_review`, never auto-`inferred`** (red flag per spec §4.3;
  a human must approve exec).
- **env**: description mentioning `api key|token|credential|secret|
  environment variable` → `env` `needs_review`; ALL_CAPS identifiers that
  look like env vars (`[A-Z][A-Z0-9_]{2,}` with suffix `_TOKEN|_KEY|_SECRET`
  or prefix `API_`) → include as values.
- No signals → pure → `[]`.

`src/mcp_contract/pie/inference.py`:
```python
def infer_policy(
    manifest: Manifest,
    *,
    server_id: str | None = None,      # default manifest.server_name
    overrides: list[Capability] | None = None,
    llm: LLMAssist | None = None,
) -> Policy
```
Aggregation: one `Capability` per class in the final policy. Merge rule for
a class with multiple signals: values = union of concrete values, plus `"*"`
(net) or `[]` (fs/proc/env) if any signal was scope-unknown; status =
`inferred` only if **all** signals were inferred, else `needs_review`;
evidence = union. Classes with no signal at all → present with status
`denied`, empty values/evidence (deny-by-default made explicit — all five
`CapabilityId` classes appear in every policy). `proc.exec` never ends up
`inferred` from rules alone. Overrides applied last: an override capability
replaces the merged one for its class wholesale (evidence gets
`source="override"` appended). `Policy.manifest_hash = manifest.hash()`.

`src/mcp_contract/pie/llm.py`:
```python
class LLMAssist(Protocol):
    def suggest(self, tool: ToolIR) -> list[Capability]: ...

class NullLLM:  # default; returns []
```
Guardrails in `infer_policy` (spec §4.5): LLM suggestions may only **add**
capability classes, always clamped to `needs_review` regardless of what the
LLM claims; they never raise a rule-derived status, never touch a
rule-`inferred` cap's values, and their evidence is tagged `source="llm"`.
Rules win every conflict.

## Module B — policy I/O (`policy-mcp`-compatible)

**First**, do a short web research pass (WebSearch/WebFetch): find the actual
Wassette policy schema (`policy-mcp` — check github.com/microsoft/wassette,
its crates and docs). Align the emitted top-level document with the real
schema as far as it can express (network hosts, storage paths+access, env
keys). Write what you learned (with URLs, and the gap list for the upstream
PR) to `docs/policy-mcp-notes.md`. If the network or repo is unreachable,
say so in that file and use the fallback shape below.

`src/mcp_contract/policy/io.py`:
```python
def policy_to_dict(policy: Policy) -> dict
def dump_policy(policy: Policy, path: str | Path | None = None) -> str  # YAML; writes file if path
def load_policy(source: str | Path | dict) -> Policy
def verify_manifest_hash(policy: Policy, manifest: Manifest) -> bool
```
Fallback emitted document (adjust base `permissions` block to the real
policy-mcp schema if research succeeds; keep `x-mcp-contract` as ours):
```yaml
version: "1.0"
description: "Least-privilege policy for <server_id>, generated by mcp-contract"
permissions:            # ONLY inferred (granted) caps appear here
  network:
    allow: [{host: "api.github.com"}]
  storage:
    allow: [{uri: "fs:///data", access: ["read"]}]
  environment:
    allow: [{key: "GITHUB_TOKEN"}]
x-mcp-contract:         # full three-status picture, ours (spec §7)
  schema: policy-mcp/v1
  server_id: github
  source_manifest_hash: "sha256:..."
  generated_by: mcp-contract/0.1
  backend_hint: null
  caps:
    - {id: net.http, status: inferred, values: [api.github.com], evidence: [{tool: ..., source: ..., detail: ...}]}
    - {id: proc.exec, status: denied, values: [], evidence: []}
```
`load_policy` treats `x-mcp-contract.caps` as the source of truth; for a
foreign policy-mcp file without that block, synthesize `inferred` caps from
`permissions` (evidence `source="override"`, detail "imported from
policy-mcp permissions") and mark absent classes `denied`. Round-trip
(`load_policy(dump_policy(p))`) must preserve caps, statuses, values,
hash. `proc.exec` has no policy-mcp permissions analog — it lives only in
`x-mcp-contract` (note this in the docs file as upstream-PR material).
`src/mcp_contract/policy/__init__.py` re-exports the four functions.

## Module C — BCM (diffing + monitor + report)

`src/mcp_contract/bcm/diff.py`:
```python
def event_capability(event: BehaviorEvent) -> tuple[CapabilityId, str] | None
def host_matches(host: str, patterns: list[str]) -> bool
def path_matches(path: str, prefixes: list[str]) -> bool
def classify_event(
    event: BehaviorEvent,
    policy: Policy,
    manifest_caps: list[Capability],
) -> EventClass
```
Implements the mapping + 3-bucket classification from *Shared semantics*
exactly. `manifest_caps` is the manifest-implied union (see below).

`src/mcp_contract/bcm/contract.py`:
```python
def manifest_implied_caps(manifest: Manifest) -> list[Capability]
```
Union of `pie.classifier.classify_tool` over all tools, merged per class
(same merge rule as inference, statuses irrelevant here beyond existence).

`src/mcp_contract/bcm/monitor.py`:
```python
class ManifestDriftError(Exception): ...  # carries expected/actual hashes

class Monitor:
    def __init__(self, adapter, handle, policy, manifest, mode: Mode,
                 *, on_alert=None, allow_drift: bool = False): ...
    def run(self, *, max_events: int | None = None,
            duration: float | None = None) -> ViolationReport: ...
```
Constructor raises `ManifestDriftError` if `policy.manifest_hash !=
manifest.hash()` unless `allow_drift` (rug-pull gate, spec §9). `run`
iterates `adapter.event_stream(handle)`, classifies each event in place
(sets `event.classification`), tracks `tool_ctx` from `mcp.call` events and
stamps it onto subsequent events that lack one, appends to the report.
`alert` mode: call `on_alert(event)` (default: one-line print to stderr) for
every `outside_contract` event. `enforce` mode: additionally call
`adapter.block(handle, event)`. Stop after `max_events`, after `duration`
seconds (`time.monotonic`), or when the stream ends.

`src/mcp_contract/bcm/report.py`:
```python
def load_events_jsonl(path: str | Path) -> list[BehaviorEvent]
def dump_events_jsonl(events: list[BehaviorEvent], path: str | Path) -> None
def classify_events(events, policy, manifest) -> ViolationReport  # offline path (audit/verify)
```
`classify_events` computes `manifest_implied_caps` itself, classifies every
event (including `tool_ctx` tracking), and returns a `ViolationReport` with
`mode=Mode.OBSERVE`. `bcm/__init__.py` re-exports the public names.

## Module D — RAL adapters (mock + docker)

`src/mcp_contract/ral/mock.py`:
```python
class MockAdapter:
    name = "mock"
    def __init__(self, events: Sequence[BehaviorEvent] | str | Path = ()): ...
```
Accepts events directly or a path to a JSONL file (same format as
`bcm.report`; parse here without importing bcm to avoid a cycle — it's
`BehaviorEvent.from_dict` per line). `capabilities()`: everything
`ENFORCE`, `boot_time_policy=True`, `runtime_block=True`. `start` records
the spec+policy and returns a handle; `event_stream` yields the injected
events; `block` appends to a public `blocked: list[BehaviorEvent]`;
`stop` is a no-op. This is the test/CI backend.

`src/mcp_contract/ral/docker.py`:
```python
def translate_policy_args(policy: Policy, spec: ServerSpec) -> list[str]

class DockerAdapter:
    name = "docker"
    def __init__(self, docker_bin: str = "docker", poll_interval: float = 1.0): ...
```
`translate_policy_args` is a **pure function** (unit-testable without
docker) producing `docker run` arguments: `--rm -d --cap-drop ALL
--security-opt no-new-privileges --pids-limit 64`; `--network none` when
`policy.granted(NET_HTTP)` is None, else default network (per-host egress
enforcement needs a proxy — v0 gap, documented); `-v host:ctr:ro` /`:rw`
mounts from granted `fs.read`/`fs.write` values (skip non-absolute values);
`-e VAR` passthrough only for granted `env` values present in `spec.env`.
`capabilities()`: network `OBSERVE`, filesystem `ENFORCE` (boot-time mounts,
no per-open events → document), process `OBSERVE`, syscall `NONE`,
`boot_time_policy=True`, `runtime_block=True` (block = `docker kill`,
coarse). Backend matrix note: with `DockerAdapter(egress_proxy=True)` / CLI
`--egress-proxy`, network becomes `ENFORCE` at the hostname level via the
egress proxy (`docs/DESIGN-egress-proxy.md`); the raw-IP bypass remains
`outside_contract`-flagged by the poller, not blocked, in v0. `start` shells
out to the docker CLI via `subprocess` (no
docker-py). `event_stream` polls every `poll_interval`: `docker exec <id>
cat /proc/net/tcp /proc/net/tcp6` → parse remote endpoints, emit
`net.connect` for new ones (value is the IP — document that hostname-level
matching needs the proxy); `docker top <id> -eo pid,comm` (fall back to
plain `docker top`) → emit `proc.spawn` for new pids. Ends when the
container exits. `stop` = `docker rm -f`. Every subprocess call:
`check=False`, capture output, no `shell=True`.

`tests/test_ral.py`: MockAdapter fully; docker = unit tests of
`translate_policy_args` + parsing helpers only, plus an integration test
gated `@pytest.mark.skipif(shutil.which("docker") is None or
os.environ.get("MCP_CONTRACT_DOCKER_TESTS") != "1", ...)`.

## Module E — CLI + fixtures + docs + e2e

`src/mcp_contract/cli.py`: argparse, prog `mcp-contract`.
`main(argv: list[str] | None = None) -> int`; module-level
`if __name__ == "__main__": raise SystemExit(main())`. Human-facing chatter
→ stderr; machine output (YAML/JSON) → stdout.

- `infer MANIFEST [-o FILE] [--server-id ID] [--json]` — load manifest,
  `infer_policy`, print policy YAML to stdout (or write FILE). Print a
  `needs_review` summary table to stderr ("N caps need review: ...").
  Exit 0.
- `run MANIFEST --policy FILE --backend {docker,mock} --mode
  {observe,alert,enforce} [--image IMG] [--cmd ...] [--events-in FILE]
  [--events-out FILE] [--report-out FILE] [--duration SEC]
  [--max-events N] [--allow-drift]` — build `ServerSpec` (mock backend
  requires `--events-in`, replayed), `get_adapter`, start, `Monitor.run`,
  write events JSONL / report JSON if asked, print report summary to
  stderr. Exit 0 if severity info/warning, 1 if critical,
  3 on `ManifestDriftError`.
- `audit --events FILE --policy FILE --manifest FILE [--json]` — offline:
  `classify_events`, print human report (stderr) + JSON report (stdout when
  `--json`). Always exit 0 (reporting command).
- `verify MANIFEST --policy FILE --events FILE [--allow-empty]` — the CI
  gate: exit **2** if `verify_manifest_hash` fails (rug-pull: manifest
  changed since the policy was generated), exit **1** if any
  `outside_contract` event, exit **4** if an input file is missing/corrupt
  or the events stream contains zero events (inconclusive — a monitor that
  observed nothing must not read as clean; `--allow-empty` accepts it),
  else **0**. Exit 4 is operational, never a security signal — it must not
  collide with 1 or 2. One-line verdict on stderr; counts on stdout.

`tests/fixtures/manifests/`: realistic `tools/list`-shaped JSON for six
servers: `github.json` (descriptions mention `api.github.com` → net
inferred), `filesystem.json` (read_file/write_file/list_directory → fs),
`fetch.json` (fetch(url) → net needs_review `["*"]`), `shell.json`
(run_command → proc.exec needs_review), `sqlite.json` (query/execute on a
db file path → fs), `slack.json` (net + SLACK_BOT_TOKEN env).
`tests/fixtures/events/`: `filesystem-clean.jsonl` (mcp.call + fs.open
events under the granted path), `filesystem-exfil.jsonl` (same plus a
`net.connect` to `evil.example.com` with `tool_ctx: read_file` →
outside_contract).

`tests/test_cli.py`: end-to-end through `main([...])` (no subprocess
needed): infer fetch → stdout YAML contains net.http needs_review; infer
filesystem → write policy to tmp_path, hand-approve (flip fs caps to
inferred with path `/data`) by editing the YAML, then `verify` with clean
events → exit 0, with exfil events → exit 1; tampered manifest → exit 2.

`examples/`: `quickstart.sh` (the infer→approve→verify loop on the
fixtures, runnable from repo root) + `github-action.yml` (sketch of the CI
gate from spec §8.2).

`README.md`: what it is (one paragraph, from SPEC one-liner), architecture
diagram (ASCII, PIE/RAL/BCM), quickstart (pip install -e ., the CLI loop),
honest status table: what v0 really does vs. spec roadmap (M1–M6), backend
capability matrix (from `BackendCaps` declared by the two adapters —
including the docker gaps: IP-not-hostname events, no per-open fs events,
egress enforcement needs proxy), library usage snippet (infer_policy +
classify_events), link to SPEC.md/DESIGN.md.

## Style rules (all modules)

- Python ≥ 3.11, stdlib + PyYAML only; tests use pytest only.
- `from __future__ import annotations`; full type hints; docstrings on
  public functions. Comments only for non-obvious constraints.
- No network access in unit tests; no `shell=True`; docker integration
  tests double-gated (binary present AND `MCP_CONTRACT_DOCKER_TESTS=1`).
- Do not create or modify files outside your ownership row.
- Syntax-check your files (`python3 -m py_compile ...`). Running your own
  tests is optional (a dedicated venv under the scratchpad dir is fine);
  the integration agent owns making the full suite green.
