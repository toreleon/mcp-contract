# GO-FORWARD — mcp-contract v0.1.0 build plan

Author: synthesis lead · Date: 2026-07-18 · Status: **decisive build spec** (build directly from this)

This folds the four research docs (`reporting-formats.md`, `policy-mcp-schema.md`,
`fleet-config.md`, `phase-recommendation.md`) into one implementable plan. It is
grounded in the current source read this session: `models.py`, `cli.py`,
`policy/io.py`, `bcm/{report,diff,contract}.py`, `ral/base.py`, `pie/inference.py`,
`manifest.py`, the 6 fixture manifests, and the 2 event fixtures.

**Hard rule honored throughout:** frozen files are **not modified** —
`src/mcp_contract/models.py`, `src/mcp_contract/ral/base.py`. Every new field
(`policy_hash`, env redaction, fleet metadata) lives in *new* modules or in
`policy/io.py` as free functions, never as new dataclass fields on the frozen types.
The single-server CLI exit-code contract (0/1/2/3/4) and its precedence are
preserved byte-for-byte; fleet/report are additive.

---

## 1. Phase scope for 0.1.0 (one paragraph)

Ship **Phase (A): the Fleet API + standardized reporting** as the sole headline of
v0.1.0, plus one cheap **policy-mcp conformance rider** from (D). Concretely: a new
`fleet` CLI command group (`fleet infer`, `fleet verify`, `fleet audit`, `fleet run`)
backed by an importable `mcp_contract.fleet` module (`Fleet`, `FleetServer`,
`FleetServerReport`, `FleetReport`); a new `mcp_contract.report.export` module with
stdlib-only **SARIF 2.1.0** (CI / GitHub code-scanning) and **ECS-aligned flat NDJSON**
(SIEM) emitters sharing one `violation_identity`; a `policy_to_policy_mcp_base`
projection plus a stdlib structural conformance check pinned to the real
`microsoft/policy-mcp` `schema/v1.json`@`186e5812`; and two small correctness guards in
`policy/io.py` (CIDR-vs-host, env-key `*`). All of it is exercised **here** with the 6
fixture manifests + the mock backend — no docker, no gVisor, no network. Explicitly
**defer** (B) airtight egress, (C) gVisor, (E) static-hints, and the upstream (D) PR;
(B)/(C) are security-critical enforcement paths that cannot be validated in this
docker-less/gVisor-less environment and must not ship as unexercised "airtight" claims.

---

## 2. New modules / files + public signatures

### 2.1 `src/mcp_contract/report/export.py` (NEW)

Imports only `json`, `hashlib`, `datetime` (+ project models). No SARIF/ECS/OCSF package.

```python
from mcp_contract import __version__
from mcp_contract.models import BehaviorEvent, EventClass, EventKind, ViolationReport

# --- shared identity (feeds SARIF fingerprint AND future OCSF finding_info.uid) ---
def event_target(event: BehaviorEvent) -> str:
    """Scope-defining value per kind (excludes ts/port/argv-tail noise):
    net.connect -> detail['host'] or detail['ip'];
    fs.open     -> f"{detail['path']}:{detail['mode']}";
    proc.spawn  -> posixpath.basename(argv[0] or first token of cmd);
    env.read    -> detail['var'];
    else        -> "" ."""

def violation_identity(server_id: str, classification: str, kind: str, target: str) -> str:
    """sha256 hex of '\\x00'.join([server_id, classification, kind, target]).
    Deliberately EXCLUDES ts and manifest_hash so one misbehavior == one alert
    across runs and manifest edits."""

# --- SARIF 2.1.0 (CI / GitHub code-scanning) ---
def to_sarif(reports: list[ViolationReport], *,
             manifest_uri: str | None = None,
             include_within_manifest: bool = True,
             tool_version: str = __version__) -> dict:
    """One SARIF 2.1.0 sarifLog dict, one run. json.dumps-ready.
    Emits a result per outside_contract event (level error) and, when
    include_within_manifest, per within_manifest_not_policy event (level note).
    within_policy is NEVER a result. Empty results:[] is valid."""

def to_sarif_json(reports: list[ViolationReport], *, indent: int | None = 2, **kw) -> str:
    """json.dumps(to_sarif(...), indent=indent, sort_keys=False) + trailing '\\n'."""

# --- ECS-aligned flat JSON (SIEM), NDJSON ---
def to_siem_json(reports: list[ViolationReport], *,
                 include_within_policy: bool = False) -> list[dict]:
    """One flat ECS dict per NOTABLE event (outside_contract + within_manifest_not_policy;
    within_policy only when include_within_policy). mcp.call events are skipped
    (context marker, not a system action)."""

def to_siem_ndjson(reports: list[ViolationReport], **kw) -> str:
    """'\\n'.join(json.dumps(d, sort_keys=True) for d in to_siem_json(...)) + '\\n'."""

# --- deferred past v0.1.0, DOCUMENTED not implemented ---
# def to_ocsf(reports) -> list[dict]: ...   # Detection Finding class_uid 2004 (see §4.4)
```

Determinism: results/rows are emitted in report order, then event order; SARIF `rules[]`
is built in first-seen `(classification, kind)` order and each result's `ruleIndex`
points at it. `sort_keys=True` on SIEM rows; SARIF keeps insertion order (stable because
inputs are ordered). No wall-clock reads inside the exporters — `@timestamp` comes from
`event.ts`, `tool.driver.version` from `tool_version`.

### 2.2 `src/mcp_contract/report/__init__.py` (NEW)

Re-export `to_sarif, to_sarif_json, to_siem_json, to_siem_ndjson, violation_identity,
event_target`.

### 2.3 `src/mcp_contract/policy/io.py` (EXTEND — not frozen)

Add three free functions + two guards. **`policy_to_dict` output stays byte-identical
for the existing golden/round-trip tests** (no new keys emitted by default).

```python
def policy_to_policy_mcp_base(policy: Policy) -> dict:
    """Projection to a strict policy-mcp/v1 document: ONLY
    {version, description, permissions} — the x-mcp-contract key stripped.
    Reuses _permissions_block. This is the byte-for-byte schema/v1.json-valid form."""

def policy_hash(policy: Policy) -> str:
    """'sha256:<hex>' over a canonical dict of {permissions_block, caps} —
    the policy-side analog of manifest_hash so a SIEM can detect a widened policy
    even when the manifest is unchanged. Computed over base permissions + the full
    caps list (json.dumps sort_keys, separators=(',',':')); EXCLUDES generated_by/
    generated_at so it is stable. NOT embedded in policy_to_dict in v0.1.0
    (would churn goldens); consumed by FleetServerReport. Threading it into
    x-mcp-contract is a deferred Track-B item."""
```

Guards inside `_permissions_block` (from policy-mcp-schema.md §5 / §8):
- **CIDR-vs-host**: for each granted `net.http` value, emit `{"cidr": v}` when `v`
  matches `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$` (IPv4 CIDR), else `{"host": v}`.
  Today io.py emits every value as `host`.
- **env `*` guard**: before emitting `{"key": k}`, assert `"*" not in k` (schema pattern
  `^[^*]*$`); raise `ValueError` if violated (env var names never contain `*`; fail loud).

`policy/__init__.py`: add `policy_to_policy_mcp_base`, `policy_hash` to exports.

### 2.4 `src/mcp_contract/policy/conformance.py` (NEW, stdlib-only)

```python
POLICY_MCP_SCHEMA_COMMIT = "186e58128fa38da3df6ae2636782e820fe5d3da6"  # microsoft/policy-mcp schema/v1.json
POLICY_MCP_SCHEMA_URL = ("https://raw.githubusercontent.com/microsoft/policy-mcp/"
                         "186e58128fa38da3df6ae2636782e820fe5d3da6/schema/v1.json")

def policy_mcp_base_conforms(doc: dict) -> list[str]:
    """Hand-rolled structural conformance to policy-mcp/v1 (zero deps).
    Returns [] when doc conforms, else a list of human-readable problems.
    Checks: root keys ⊆ {version,description,permissions}; version matches ^1\\.;
    permissions subkeys ⊆ {storage,network,environment,runtime,resources,ipc};
    network.allow[] each oneOf {host}|{cidr IPv4}|{defaults:true};
    storage.allow[] each {uri:non-empty, access:non-empty ⊆ {read,write}};
    environment.allow[] each {key: non-empty, no '*'}. Mirrors §2 of
    policy-mcp-schema.md. The FULL x-mcp-contract-bearing doc is expected to FAIL
    (root additionalProperties:false) — that gap is asserted, not hidden."""
```

Rationale for stdlib structural check instead of `jsonschema`: keeps **runtime deps at
stdlib+PyYAML** and makes A6 pass with no new dependency. A vendored copy of the real
`schema/v1.json` snapshot is added under `tests/fixtures/policy-mcp/v1.json` (with the
commit sha in a header comment / adjacent README) so a *dev-only* test can additionally
cross-check with `jsonschema` if desired (add `jsonschema` to the `dev` extra only — never
to `dependencies`). The structural check is the release gate; jsonschema is optional belt-and-suspenders.

### 2.5 `src/mcp_contract/fleet.py` (NEW)

Nothing frozen touched. Imports `load_manifest`, `load_policy`, `dump_policy`,
`policy_to_dict`, `policy_hash`, `verify_manifest_hash`, `infer_policy`,
`classify_events`, `load_events_jsonl`, `get_adapter`, `Monitor`, and the frozen
`ServerSpec`, `Mode`, `Severity`, `BackendCaps`, `Policy`, `ViolationReport`.

```python
@dataclass
class FleetServer:
    id: str
    launch: dict = field(default_factory=dict)   # verbatim mcpServers/server.json entry
    backend: str = "docker"                       # -> get_adapter
    mode: Mode = Mode.OBSERVE
    image: str | None = None
    manifest_path: str | None = None
    policy_path: str | None = None
    events_path: str | None = None
    egress_proxy: bool = False
    labels: dict[str, str] = field(default_factory=dict)
    source: str | None = None                     # provenance: fleet-file path or client

    @property
    def transport(self) -> str: ...               # launch['transport'] | 'stdio' if command | else error
    def resolved_env(self) -> dict[str, str]: ...  # ${VAR}/${VAR:-default} expansion; raises _UnresolvedVar
    def launch_fingerprint(self) -> dict: ...      # {image?, command?, args?, env_keys:[...]} — VALUES REDACTED
    def to_server_spec(self, policy: Policy) -> ServerSpec: ...
        # id->server_id, image->image, launch.command+args->command,
        # resolved env filtered to policy.granted(ENV).values -> env,
        # extra={source, transport, labels, launch_fingerprint}

@dataclass
class FleetServerReport:                           # the SIEM envelope (fleet-config.md Part 5)
    server_id: str
    status: str                                    # "ok"|"violation"|"rug_pull"|"skipped"|"error"
    exit_code: int                                 # per-server: 0|1|2|4 (see §6 precedence)
    report: ViolationReport | None = None          # None if skipped/errored
    manifest_hash: str = ""
    policy_hash: str = ""
    backend: str = ""
    mode: str = ""
    transport: str = "stdio"
    labels: dict[str, str] = field(default_factory=dict)
    source: str | None = None
    launch_fingerprint: dict = field(default_factory=dict)   # env values already redacted
    error: str | None = None
    def to_dict(self) -> dict: ...                 # NDJSON row; envelope + (report.to_dict() if any)

@dataclass
class FleetReport:
    runs: list[FleetServerReport]
    started_at: float                              # caller-injected (byte-stability); no wall-clock inside
    engine_version: str = __version__
    def exit_code(self) -> int: ...                # aggregate precedence 2 > 1 > 4 > 0 (§6)
    def severity(self) -> Severity: ...            # critical if any outside_contract, warning if any within_manifest, else info
    def totals(self) -> dict[str, int]: ...        # summed per-EventClass counts + servers/violations/rug_pulls/skipped
    def to_dict(self) -> dict: ...                 # {generated_at, tool_version, totals, exit_code, severity, runs:[...]}, sorted keys
    def to_json(self, indent: int | None = 2) -> str: ...
    def to_ndjson(self) -> str: ...                # one FleetServerReport.to_dict() per line
    def to_sarif(self, **kw) -> dict: ...          # report.export.to_sarif over all non-None reports
    def to_siem_ndjson(self, **kw) -> str: ...     # report.export.to_siem_ndjson over all non-None reports

class Fleet:
    servers: list[FleetServer]

    # construction
    @classmethod
    def from_config(cls, path: str | Path) -> "Fleet": ...        # native fleet.yaml (§5)
    @classmethod
    def from_mcp_servers(cls, path: str | Path, *,
                         backend: str = "docker", mode: Mode = Mode.OBSERVE) -> "Fleet": ...
        # ingest mcpServers (Claude/.mcp.json/Cursor) OR VS Code top-level `servers`
    @classmethod
    def from_manifests(cls, paths: list[str | Path]) -> "Fleet": ...
        # zero-config onboarding: one FleetServer per manifest file (id=file stem,
        # manifest_path set, no policy) — backs `fleet infer <dir|glob>`

    # selection
    def select(self, **labels: str) -> "Fleet": ...               # slice by labels, e.g. select(env="prod")

    # batch verbs -> FleetReport (started_at defaults to time.time(); pass explicit for determinism)
    def infer_all(self, *, llm=None, write: bool = True,
                  started_at: float | None = None) -> FleetReport: ...
        # per server: load_manifest -> infer_policy -> (dump_policy to policy_path if write);
        # status "ok"; aggregate needs_review; NEVER gates (bad input -> "skipped"/4)
    def audit_all(self, *, started_at: float | None = None) -> FleetReport: ...
        # per server: load_events_jsonl(events_path) -> classify_events; reports only, exit 0
    def verify_all(self, *, allow_empty: bool = False,
                   started_at: float | None = None) -> FleetReport: ...
        # per server: verify_manifest_hash (mismatch -> rug_pull/2) -> classify ->
        # violations (1) / empty (4) / clean (0). THE CI GATE.
    def run_all(self, *, max_events=None, duration=None, sequential: bool = True,
                started_at: float | None = None) -> FleetReport: ...
        # per server: get_adapter -> start -> Monitor.run -> stop. sequential only in v0;
        # docstring points production users at the per-server sidecar pattern.
```

Env expansion + redaction rules (fleet-config.md §3/§4):
- `${VAR}` and `${VAR:-default}` expanded from host env on load. A referenced `${VAR}`
  with no value and no default → that server is marked `status="skipped"`, `exit_code=4`,
  never launched.
- Reports carry env **key names only, never values**; `launch_fingerprint` redacts `env`
  to its key set. Redaction is baked into the serializer so it cannot be forgotten.

### 2.6 `src/mcp_contract/cli.py` (EXTEND — not frozen in the model sense)

Add a `fleet` subparser group + export flags on existing subcommands. Reuse
`EXIT_OK/EXIT_VIOLATION/EXIT_HASH_MISMATCH/EXIT_BAD_INPUT`. Human chatter → stderr,
machine output → stdout/file (existing convention).

New `fleet` group (dispatch to `_cmd_fleet_*`):

```
mcp-contract fleet infer  (<DIR|GLOB> | --config FLEET | --from-mcp FILE)
                          [-o OUTDIR] [--report FILE] [--format json|ndjson|sarif]
                          [--emit base|full]
mcp-contract fleet audit  --config FLEET [--select K=V ...]
                          [--report FILE] [--format json|ndjson|sarif]
mcp-contract fleet verify --config FLEET [--select K=V ...] [--allow-empty]
                          [--report FILE] [--format json|ndjson|sarif]
                          [--sarif PATH] [--siem PATH]        # CI gate: aggregate exit code
mcp-contract fleet run    --config FLEET [--select K=V ...]
                          [--report-out FILE] [--max-events N] [--duration S] [--siem PATH]
```

`--format` controls what is written to `--report FILE` (or stdout): `json` →
`FleetReport.to_json()`, `ndjson` → `FleetReport.to_ndjson()`, `sarif` →
`to_sarif_json(all reports)`. `fleet verify` returns `FleetReport.exit_code()` (2>1>4>0).
`fleet infer`/`fleet audit` return 0 unless bad input (4). `fleet run` returns the
aggregate (drift/rug_pull → 2, violation → 1).

New export flags on the **single-server** subcommands (reporting-formats.md §1.5/§3),
all additive, **exit codes unchanged**:
- `audit  ... [--sarif PATH] [--siem PATH]`
- `verify ... [--sarif PATH] [--siem PATH]`   (verify still prints counts JSON to stdout)
- `run    ... [--sarif PATH] [--siem PATH]`

Each writes `to_sarif_json([report], manifest_uri=<manifest arg>)` / `to_siem_ndjson([report])`
to the given path as an additional artifact. `--emit base` on single-server `infer`
writes the strict `policy_to_policy_mcp_base(policy)` projection instead of the full doc.

---

## 3. Report formats — field by field

### 3.1 SARIF 2.1.0 (`to_sarif`)

Top-level:
```
$schema:  "https://json.schemastore.org/sarif-2.1.0.json"
version:  "2.1.0"
runs:     [ <one run> ]
```
`runs[0].tool.driver`:
```
name:            "mcp-contract"
version:         tool_version           # default __version__ == "0.1.0"
semanticVersion: tool_version
informationUri:  "https://github.com/…/mcp-contract"   # project URL constant
rules:           [ <one reportingDescriptor per (classification, kind) present> ]
```
**Rule** = a `(classification, kind)` pair (stable across servers/runs):
| field | value |
|---|---|
| `id` | `f"{classification}/{kind}"` e.g. `"outside_contract/net.connect"` |
| `name` | PascalCase, e.g. `"OutsideContractNetConnect"` |
| `shortDescription.text` | e.g. `"Network connection outside the declared contract"` |
| `fullDescription.text` | one sentence naming the deviation (see doc for per-kind text) |
| `defaultConfiguration.level` | `"error"` for `outside_contract`, `"note"` for `within_manifest_not_policy` |
| `properties.tags` | `["security","mcp","runtime-behavior", kind]` |
| `properties.security-severity` | `"9.0"` (`outside_contract`→GitHub critical) / `"4.0"` (`within_manifest`→medium) |

**Result** = one `BehaviorEvent`:
| field | value |
|---|---|
| `ruleId` / `ruleIndex` | its `(classification, kind)` rule + index into `rules[]` |
| `level` | `"error"` (`outside_contract`) / `"note"` (`within_manifest_not_policy`) |
| `message.text` | human line naming `server_id`, target, `tool_ctx`, e.g. `"MCP server 'github' connected to unlisted host evil.example.com:443 during tool 'read_file' — outside its declared contract."` |
| `locations[0].physicalLocation.artifactLocation.uri` | `manifest_uri` or fallback `f"{server_id}.manifest.json"` |
| `locations[0].physicalLocation.region.startLine` | `1` |
| `partialFingerprints.primaryLocationLineHash` | `violation_identity(server_id, classification, kind, event_target(event))` |
| `properties` | `{server_id, manifest_hash, classification, kind, tool_ctx, backend, detail:{...}, ts}` |

Rules: emit results for `outside_contract` always; `within_manifest_not_policy` only when
`include_within_manifest=True`; **never** `within_policy`; empty `results: []` is valid
(GitHub reads it as "resolved"). Self-computed `primaryLocationLineHash` is **mandatory**
(there is no source line for GitHub to hash) and **excludes `ts`/`manifest_hash`** so one
misbehavior stays one alert across runs and manifest edits. Limits: ≤25,000 results/run.
CI upload: `github/codeql-action/upload-sarif@v3`; `verify` exit contract unchanged.

### 3.2 SIEM ECS-aligned flat NDJSON (`to_siem_json` → one dict per notable event)

Flat dotted keys, string/number/array values, no nesting:
| field | derivation |
|---|---|
| `@timestamp` | `datetime.fromtimestamp(event.ts, timezone.utc).isoformat()` → ISO-8601 UTC (…`+00:00`) |
| `event.kind` | `"alert"` if `outside_contract` else `"event"` |
| `event.category` / `event.type` | from `EventKind`: `net.connect`→`["network"]`/`["connection","allowed"|"denied"]`; `fs.open`→`["file"]`/`["access"]`(r) or `["change"]`(w); `proc.spawn`→`["process"]`/`["start"]`; `env.read`→`["configuration"]`/`["access"]`; `syscall`→`["process"]`/`["info"]`; `mcp.call`→**skipped** |
| `event.action` | `event.kind.value` (e.g. `"net.connect"`) |
| `event.outcome` | `"failure"` if the action was denied/blocked (enforce or proxy-403; `detail.get("allowed") is False`), else `"success"` |
| `event.severity` | `9` (`outside_contract`) / `4` (`within_manifest`) / `1` (`within_policy`) |
| `event.reason` | short human sentence (same content as SARIF message, no server prefix) |
| `event.dataset` | `"mcp_contract.behavior"` |
| `event.module` / `event.provider` | `"mcp_contract"` / `"mcp-contract"` |
| `rule.id` / `rule.name` | same `(classification, kind)` vocabulary as SARIF |
| observables (ECS-native) | `net.connect`→`destination.address`(host)/`destination.ip`(ip)/`destination.port`; `fs.open`→`file.path`; `proc.spawn`→`process.command_line`+`process.args`; `env.read`→`mcp_contract.env_var` (no ECS home) |
| `mcp_contract.*` | `server_id, manifest_hash, classification, mode, backend, tool_ctx, event_kind` |

Emit `outside_contract` + `within_manifest_not_policy` by default; `within_policy` only
when `include_within_policy=True`. `to_siem_ndjson` joins with `\n`, `sort_keys=True`.
Why ECS over OCSF: ECS is flat string dicts with zero integer-enum bookkeeping and reaches
the same SIEMs (Elastic/Splunk/Datadog/Sentinel); OCSF's only edge is AWS Security Lake.

### 3.3 One shared violation identity

`violation_identity(server_id, classification, kind, target)` feeds SARIF
`primaryLocationLineHash` today and (deferred) OCSF `finding_info.uid` later — one
violation, one id, every format. `target = event_target(event)` per §2.1.

---

## 4. Fleet-config schema to accept (`fleet.yaml`, JSON also accepted)

```yaml
version: "0.1"                     # fleet-config schema version (distinct from policy version)

defaults:                          # merged under each server; server wins
  backend: docker                  # docker | mock
  mode: observe                    # observe | alert | enforce
  egress_proxy: true               # docker only
  manifest_dir: manifests/         # resolves per-server `manifest:` relative to here
  policy_dir:  policies/           # resolves per-server `policy:`   relative to here

servers:
  github:                          # map key == server id
    launch:                        # verbatim mcpServers / server.json entry
      transport: stdio             # stdio | http | sse (streamable-http aliases http)
      command: docker
      args: ["run", "-i", "--rm", "mcp/github"]
      env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" }   # ${VAR}/${VAR:-default} expansion
    image: "mcp/github@sha256:…"   # REQUIRED when backend==docker (pin @sha256)
    manifest: github.tools.json    # pinned tools/list (rug-pull baseline)
    policy:   github.policy.yaml   # pre-approved policy (optional for infer)
    backend:  docker
    mode:     enforce
    egress_proxy: true
    events:   events/github.jsonl  # mock replay source
    labels: { team: platform, env: prod, data_class: source-code, owner: alice@corp }
```

Per-server fields: `launch` (required; stdio `command`/`args`/`env`/`cwd` or remote
`url`/`headers`), `image`, `manifest`, `policy`, `backend`, `mode`, `egress_proxy`,
`events`, `labels` (free-form; reserved keys `team`/`env`/`owner`/`data_class`).

**Fail-closed validation (loader):**
1. `backend: docker` ⇒ `image` present (do NOT parse it out of `docker run` args).
2. `launch.transport: http|sse` ⇒ `mode` forced to `observe` in v0 (can't process-sandbox
   a remote; egress-proxy observe only) — warn+downgrade.
3. `url` present but no `transport` ⇒ error (ecosystem parity).
4. `verify`/`run` selected but a server has no `policy` ⇒ that server errors (never gate
   without a contract).
5. Unresolved `${VAR}` (no value, no default) ⇒ server marked `skipped` (exit 4), not launched.

**Ingest adapter** `Fleet.from_mcp_servers(path)`: read top-level `mcpServers`
(Claude/.mcp.json/Cursor) OR `servers` (VS Code); `id = map key`, `launch = entry` as-is,
`backend`/`mode` from call, `labels = {source: <file>, client: <detected>}`. Manifests are
absent from these files — pair with a future `discover` step that fetches `tools/list`
**inside the sandbox** (untrusted code), never on the host (out of v0 scope; note the caveat).

---

## 5. Testable acceptance checklist for 0.1.0

All exercisable **here** with fixtures + mock backend — no docker/gVisor/network.
New fixtures to add: `tests/fixtures/fleet/fleet.yaml` (mock backend, references the 6
manifests + per-server event JSONL), a `*-tampered` policy whose `source_manifest_hash`
no longer matches its manifest, and a truncated/corrupt events file; vendored
`tests/fixtures/policy-mcp/v1.json` (schema snapshot @186e5812).

- **A1 — `fleet infer`.** `Fleet.from_manifests(glob(tests/fixtures/manifests/*.json))`
  (6 servers) → 6 policies written + one `FleetReport`; rows carry `server_id`,
  `manifest_hash`, per-EventClass counts, `needs_review` tally matching known fixtures;
  exit 0. Also via CLI `fleet infer tests/fixtures/manifests/`.
- **A2 — `fleet verify` aggregation.** Mixed clean+exfil → aggregate `severity=critical`,
  exit **1**; a tampered-manifest server in the set → exit **2**; a corrupt/missing input
  → exit **4**; assert precedence 2 > 1 > 4 > 0 with no code collision (rug-pull+violation
  together → 2; violation+corrupt → 1).
- **A3 — determinism.** `FleetReport.to_json()` byte-stable for identical input with a
  fixed `started_at`; sorted keys; runs sorted by `server_id`.
- **A4 — export formats.** `to_sarif([report])`: `version=="2.1.0"`, `$schema` present,
  ≥1 rule, `results[].level` mapping (`error` for outside_contract, `note` for
  within_manifest), `partialFingerprints.primaryLocationLineHash` present and equal to
  `violation_identity(...)`; `to_siem_json`: `event.kind=="alert"` for outside_contract,
  `event.category/type` per-kind correct, `destination.address=="evil.example.com"` for
  the exfil event, flat keys only. Export never changes any exit code.
- **A5 — exports diff-clean.** SARIF and SIEM output stable across two runs of the same
  input (fingerprints exclude ts; no wall-clock in exporters).
- **A6 — policy-mcp conformance.** `policy_mcp_base_conforms(policy_to_policy_mcp_base(p))
  == []` for every fixture server; `policy_mcp_base_conforms(policy_to_dict(p)) != []`
  (full doc fails on the x- key — the known gap, asserted). Schema snapshot pinned by
  commit sha. CIDR value → `{cidr}`; host value → `{host}`; env key with `*` → raises.
- **A7 — demo Part B.** A pytest runs `fleet infer` over the fixture manifests and matches
  the six-server least-privilege table documented in `demo/README.md` (regenerated by
  `fleet infer`, not the hand-rolled shell loop).
- **A8 — docs.** README status table flips **M5 → Shipped**; CLI table gains `fleet` rows +
  the `--sarif/--siem` flags; library-usage snippet gains `FleetReport`.
- **A9 — release hygiene.** `CHANGELOG.md` created with the `0.1.0` entry (§7); `v0.1.0`
  git tag cut once the suite is green.
- **A10 — suite green.** `pytest` all-green with new fleet/report/conformance tests; runtime
  deps unchanged (stdlib + PyYAML); the 2 docker tests remain skip-gated (currently 215
  passed / 2 skipped → target ~+40 new tests, still 2 skipped).

---

## 6. Exit-code aggregation (the one non-trivial correctness point)

Per-server `FleetServerReport.exit_code`: `rug_pull → 2`, `violation → 1`,
`error|skipped|bad-input|empty → 4`, `clean → 0` (mirrors single-server `cli.py`).

`FleetReport.exit_code()` aggregates by **security-first precedence**, NOT numeric max:
```
if any server rug_pull:                 return 2
elif any server violation:              return 1
elif any server error/skipped/bad-input:return 4
else:                                   return 0
```
Rug-pull outranks a plain violation (a changed manifest invalidates the whole comparison);
`4` stays last so a broken pipeline never *looks* clean and never trips a gate keyed on
1/2. `fleet run`'s live `ManifestDriftError` maps to `rug_pull` (2) at the aggregate; the
single-server `run`-only exit 3 (drift) is not produced by the fleet aggregate.

---

## 7. Explicit DEFER list + why

| Deferred | Target | Why not 0.1.0 |
|---|---|---|
| **(B) Airtight egress** (internal docker net + iptables) | 0.2.0 / M4 | **Fails the validatability gate.** The blocking boundary can only be exercised against a running docker daemon (absent here). Shipping unexercised *enforcement* in a first release is a false "airtight" promise. Current honest posture — proxy enforces the well-behaved path, raw-IP bypass **flagged, not blocked**, documented — stays. |
| **(C) gVisor adapter** | 0.2.0 / M3 | **Fails validatability.** `event_stream`/enforce need gVisor installed; would ship half-exercised. Runtime-agnosticism already proven by mock+docker. |
| **(E) Static-hints analyzer** | 0.2.0 headline | Validatable but it **auto-widens grants** (`needs_review → inferred`), against PIE's fail-closed stance (§4.5). Needs a labeled corpus — which (A)'s fleet output supplies. Sequence (A)→(E) deliberately. |
| **(D) upstream policy-mcp PR** (Track A `patternProperties {"^x-":{}}`, Track B native `metadata`/`evidence`/`review`/`process`) | M3 | External artifact, cannot merge from here. **Draft** it; the *conformance code* slice (A6) is folded in. |
| **`to_ocsf`** | post-0.1.0 | Documented mapping (Detection Finding 2004) in reporting-formats.md §2.4; nested + integer-enum bookkeeping the flat ECS shape avoids. Not release-blocking; ECS reaches the same SIEMs. |
| **x-mcp-contract additions** (`ext_version`, `generated_at`, `behavior_expectations`, embedded `policy_hash`) | post-0.1.0 | Schema churn with no consumer today; would break existing goldens/round-trip. BCM derives matchers from `caps` directly; `policy_hash` ships as a free function consumed by reports, not embedded in the YAML. |
| **`Fleet.discover()`** (scan well-known client paths) + live in-sandbox `tools/list` discovery | post-0.1.0 | Discovery runs untrusted code — must launch inside the sandbox backend; per-OS paths unverified. Note the supply-chain caveat. |
| **Parallel/orchestrated `run_all`** | post-0.1.0 | `sequential=True` only in v0; production monitoring is the per-server sidecar + NDJSON serializer, documented as such. |

Also **update, not defer** (cheap doc corrections riding along): `docs/policy-mcp-notes.md`
resources shape → flat cpu(0–100%)/memory(MB)/io(IOPS); SPEC Wassette reference v0.3.4 →
v0.4.0.

---

## 8. Version / CHANGELOG

`pyproject` already declares `0.1.0`, no tags, no CHANGELOG — completing Phase (A) **is the
first tagged release cut**, not a bump. Keep the number at **`0.1.0`**; `__version__` stays
`"0.1.0"`. Runtime deps unchanged (`PyYAML>=6.0`); optionally add `jsonschema` to the `dev`
extra only (belt-and-suspenders conformance cross-check).

**Create `CHANGELOG.md`** (Keep-a-Changelog), `## [0.1.0] — 2026-07-…`:
- **Added**
  - `mcp-contract fleet infer|audit|verify|run` — batch inference/verification across a
    fleet; per-server policies + one aggregate `FleetReport`.
  - `mcp_contract.fleet` library API: `Fleet` (`from_config`/`from_mcp_servers`/
    `from_manifests`/`select`/`infer_all`/`audit_all`/`verify_all`/`run_all`),
    `FleetServer`, `FleetServerReport`, `FleetReport` (deterministic `to_dict`/`to_json`/
    `to_ndjson`).
  - `mcp_contract.report.export`: **SARIF 2.1.0** (`to_sarif`/`to_sarif_json`) for CI
    code-scanning, **ECS-aligned NDJSON** (`to_siem_json`/`to_siem_ndjson`) for SIEM, shared
    `violation_identity`. New `--sarif PATH`/`--siem PATH` on `audit`/`verify`/`run`;
    `--format {json,ndjson,sarif}` on the `fleet` group.
  - policy-mcp conformance: `policy_to_policy_mcp_base`, `policy_hash`, and
    `policy_mcp_base_conforms` (schema pinned to `microsoft/policy-mcp`@`186e5812`);
    `infer --emit base` strict projection; CIDR-vs-host and env-key `*` emit guards.
- **Changed**
  - README status table **M5 → Shipped**; CLI reference gains the `fleet` group and export
    flags; public-demo Part B now driven by `fleet infer`.
  - Doc fixes: policy-mcp resources shape (flat percent/MB/IOPS); Wassette ref v0.3.4→v0.4.0.
- **Unchanged / preserved**
  - Single-server exit-code contract (0/1/2/3/4) and precedence; frozen `models.py` /
    `ral/base.py`; runtime deps stdlib + `PyYAML`.
- **Known limitations (ship honest, SPEC §13)**
  - Network enforcement covers the proxy (well-behaved) path; raw-IP bypass **flagged, not
    blocked** (airtight blocking deferred, M4).
  - Backends `mock` + `docker` only; gVisor deferred (M3).
  - PIE rule-based (manifest-only); static hints deferred (0.2.0).
  - Full x-mcp-contract policy is Wassette-runtime-valid but not schema-valid against the
    published `schema/v1.json` (root `additionalProperties:false`); use `--emit base` for a
    strict-schema document. Upstream Track-A PR closes this.

**Tag** `v0.1.0` once §5 is green.

---

## 9. Build order (suggested, each step independently testable)

1. `report/export.py` + `report/__init__.py` + `test_report_export.py` (pure functions over
   existing `ViolationReport`; uses the exfil fixture). — unblocks A4/A5.
2. `policy/io.py` guards + `policy_to_policy_mcp_base` + `policy_hash` +
   `policy/conformance.py` + vendored schema snapshot + `test_policy_conformance.py`. — A6.
3. `fleet.py` (dataclasses + `from_config`/`from_manifests`/`from_mcp_servers` +
   `infer_all`/`audit_all`/`verify_all`) + `tests/fixtures/fleet/*` + `test_fleet.py`. — A1/A2/A3.
4. `run_all` (mock backend replay path) — A2 live variant.
5. `cli.py` `fleet` group + single-server `--sarif/--siem` + `test_cli.py` additions. — A4 via CLI.
6. Docs: README M5→Shipped + CLI rows + library snippet; demo Part B regen test (A7);
   `CHANGELOG.md`; doc corrections. — A8/A9.
7. Full `pytest`; cut `v0.1.0` tag. — A10.
