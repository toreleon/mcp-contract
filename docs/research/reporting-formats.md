# Reporting formats for mcp-contract's ViolationReport export

Research date: 2026-07-18. Method: web search + primary-source fetch (OASIS SARIF
spec, GitHub code-scanning docs, OCSF schema browser, Elastic ECS reference).
Every claim is tagged **[VERIFIED]** (read in a primary/vendor source) or
**[INFERRED]** (reasoned design decision for this codebase). Scope: what
standardized format(s) mcp-contract should emit so a `ViolationReport` ingests
cleanly into (a) CI / GitHub code-scanning and (b) SIEM/security pipelines
(SPEC §8.3), and the exact stdlib-only emitter functions to expose.

Grounding is the real data model in `src/mcp_contract/models.py`:
`ViolationReport{server_id, manifest_hash, mode, events[]}` with derived
`severity` (info/warning/critical), `counts()`, `violations` (the
`outside_contract` events), and `suggested_action`; each `BehaviorEvent{ts,
kind, detail, tool_ctx, classification, backend}` where `kind in {net.connect,
fs.open, proc.spawn, env.read, mcp.call, syscall}` and `classification in
{within_policy, within_manifest_not_policy, outside_contract}`.

---

## TL;DR recommendation

| Consumer | Format | Emitter | Dependency |
|---|---|---|---|
| **CI / GitHub code-scanning** | **SARIF 2.1.0** | `to_sarif(reports, *, manifest_uri=None, include_within_manifest=True) -> dict` | stdlib `json`/`hashlib` only |
| **SIEM / security pipeline** | **ECS-aligned flat JSON (NDJSON)** | `to_siem_json(reports, *, include_within_policy=False) -> list[dict]` | stdlib only |
| (optional, Security-Lake shops) | OCSF Detection Finding 2004 | `to_ocsf(reports) -> list[dict]` | stdlib only; defer past v0.1.0 |

**Minimal set for v0.1.0: SARIF for CI, ECS-flat-JSON for SIEM.** Both are
hand-rollable from `dict`/`json`/`hashlib` — no SARIF library, no `ecs`/`ocsf`
package. OCSF is documented below as a mapping table so a `to_ocsf` can be added
later without re-research, but it should **not** block the release: its nested
objects and integer-enum bookkeeping are maintenance the flat ECS shape avoids
while ingesting into the same SIEMs.

Why two formats, not one: SARIF is the *transport GitHub code-scanning speaks*
(the CI half of §8.3) and nothing else ingests it well; ECS/OCSF are the
*transports SIEMs speak* and GitHub does not ingest them. There is no single
format that covers both consumers, so the minimal honest answer is one each.

---

## 1. SARIF 2.1.0 for CI / GitHub code-scanning

### 1.1 Is SARIF appropriate for a *runtime behavioral* finding?

SARIF's name is "**Static** Analysis Results Interchange Format" and its data
model centers on a physical file + text region [VERIFIED — OASIS spec]. An
`outside_contract` egress event has **no source line**. So the honest answer is:
SARIF is appropriate *as the CI transport*, with three caveats, and there is
strong precedent for non-source findings riding it:

- **Precedent.** GitHub code-scanning already ingests SARIF from tools whose
  findings are not source lines: Trivy (container images, "by target image"),
  Checkov (IaC), and SCA tools ("by package") all emit SARIF and upload it
  [VERIFIED — Trivy/Checkov SARIF docs; boostsecurity.io teardown]. The format
  is used well beyond classic linters.
- **Caveat 1 — location is a proxy, not a code line.** GitHub *requires* every
  result to carry `locations[].physicalLocation.artifactLocation.uri` +
  `region.startLine` [VERIFIED — GitHub SARIF support]. Map it to the **manifest
  file** the CI job is scanning (a real committed artifact, `region.startLine:
  1`); the finding then annotates *"this server's declared contract"*, which is
  semantically exactly right — the violation is a gap between manifest and
  behavior. When no repo-relative manifest path is known, fall back to a stable
  synthetic uri (`f"{server_id}.manifest.json"`).
- **Caveat 2 — you must supply your own fingerprints.** GitHub computes
  `partialFingerprints` from *source files* when the field is missing; with no
  source line there is nothing to hash, so **mcp-contract must populate
  `partialFingerprints.primaryLocationLineHash` itself** (§1.4). This is the
  single most important correctness detail for stable alerts.
- **Caveat 3 — severity mapping is a fit, not a stretch.** SARIF's three
  `level`s (`error`/`warning`/`note`) map cleanly onto our
  `critical`/`warning`/`info`, and GitHub's `security-severity` numeric band
  reproduces the same ordering (§1.3).

Verdict: **use SARIF for CI.** It is the only format GitHub code-scanning
accepts, the file-less-finding pattern is well-trodden, and the one real
obligation (self-computed `partialFingerprints`) is cheap.

### 1.2 Structure GitHub requires [VERIFIED — GitHub SARIF support]

- Top level: `$schema` (`https://json.schemastore.org/sarif-2.1.0.json`),
  `version` (`"2.1.0"` exactly), `runs[]` (>=1).
- `runs[].tool.driver` (a `toolComponent`): `name` (required),
  `rules[]` (array of `reportingDescriptor`), plus `version`, `informationUri`,
  `semanticVersion`.
- Each rule (`reportingDescriptor`): `id` (required, referenced by results),
  `name`, `shortDescription.text` (<=1024), `fullDescription.text` (<=1024),
  `help.text`/`help.markdown`, `defaultConfiguration.level`
  (`note`/`warning`/`error`), `properties.tags[]` (<=20; `"security"` enables the
  security view), `properties.security-severity` (`"0.1"`–`"10.0"` string),
  `properties.precision`.
- Each `result`: `message.text` (required), `locations[]` (>=1, required),
  `partialFingerprints` (required for dedup — must include
  `primaryLocationLineHash`), `ruleId`, `ruleIndex`, `level` (overrides rule
  default). `locations[0].physicalLocation` needs `artifactLocation.uri`
  (repo-relative) + `region.startLine`.
- Limits per file: 20 runs, 25,000 results/run (5,000 displayed), 10 MB gzip.

### 1.3 ViolationReport → SARIF field mapping

Emit **one SARIF run per `to_sarif` call** (batch of reports). Emit a `result`
for every `outside_contract` event (`level: error`) and, when
`include_within_manifest`, every `within_manifest_not_policy` event
(`level: note`). **`within_policy` events are never results** — they are the
"all clear" baseline, not findings. If no findings survive, still emit a valid
run with an empty `results: []` (GitHub reads it as "resolved").

| SARIF construct | Source in mcp-contract |
|---|---|
| `run.tool.driver.name` | `"mcp-contract"` |
| `run.tool.driver.version` / `.semanticVersion` | `Policy.generated_by` → `"0.1.0"` |
| `run.tool.driver.informationUri` | project URL |
| **`rule`** (one per `(classification, kind)` pair present) | see below |
| **`result`** (one per notable `BehaviorEvent`) | see below |

**A rule is a `(classification, kind)` pair** — the *type* of contract deviation,
which is stable across servers and runs (so alerts group and rules are reusable):

- `rule.id` = `f"{classification}/{kind}"`, e.g. `outside_contract/net.connect`,
  `outside_contract/fs.open`, `outside_contract/proc.spawn`,
  `outside_contract/env.read`, `within_manifest_not_policy/net.connect`.
- `rule.name` = PascalCase, e.g. `OutsideContractNetConnect`.
- `rule.shortDescription.text` = e.g. *"Network connection outside the declared
  contract"*.
- `rule.fullDescription.text` = e.g. *"The MCP server opened a network
  connection to a host that is neither granted by the policy nor implied by its
  tool manifest. This is behavior the server never declared."*
- `rule.defaultConfiguration.level` = `error` for `outside_contract`, `note`
  for `within_manifest_not_policy`.
- `rule.properties.tags` = `["security", "mcp", "runtime-behavior", kind]`.
- `rule.properties.security-severity` = `"9.0"` for `outside_contract`
  (GitHub → *critical*, since 9.0 sits at the critical band), `"4.0"` for
  `within_manifest_not_policy` (→ *medium*). GitHub bands: >9.0 critical,
  7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low [VERIFIED].

**A result is one `BehaviorEvent`:**

- `result.ruleId` / `result.ruleIndex` → the rule for its
  `(classification, kind)`.
- `result.level` → `error` (`outside_contract`) / `note`
  (`within_manifest_not_policy`).
- `result.message.text` → human line built from the event, e.g.
  *"MCP server `github-mcp` connected to unlisted host `evil.example.com:443`
  during tool `read_file` — outside its declared contract."*
- `result.locations[0].physicalLocation.artifactLocation.uri` → `manifest_uri`
  (repo-relative) or `f"{server_id}.manifest.json"` fallback;
  `region.startLine: 1`.
- `result.partialFingerprints.primaryLocationLineHash` → **stable semantic hash**
  (§1.4).
- `result.properties` → carry the raw event for humans/tools:
  `{ "server_id", "manifest_hash", "classification", "kind", "tool_ctx",
  "backend", "detail": {...}, "ts" }`. GitHub ignores unknown `properties` but
  preserves them.

### 1.4 Concrete: a `net.connect`-to-unlisted-host violation, and stable fingerprints

Given `BehaviorEvent(ts=…, kind=net.connect, detail={"host":"evil.example.com",
"port":443}, tool_ctx="read_file", classification=outside_contract)` on server
`github-mcp`:

```json
{
  "ruleId": "outside_contract/net.connect",
  "ruleIndex": 0,
  "level": "error",
  "message": {
    "text": "MCP server 'github-mcp' connected to unlisted host evil.example.com:443 during tool 'read_file' — outside its declared contract (net.http grants: api.github.com)."
  },
  "locations": [
    { "physicalLocation": {
        "artifactLocation": { "uri": "servers/github-mcp/manifest.json" },
        "region": { "startLine": 1 } } }
  ],
  "partialFingerprints": {
    "primaryLocationLineHash": "b91e0c…",
    "mcpContract/violationIdentity/v1": "b91e0c…"
  },
  "properties": {
    "server_id": "github-mcp",
    "manifest_hash": "sha256:…",
    "classification": "outside_contract",
    "kind": "net.connect",
    "tool_ctx": "read_file",
    "backend": "docker",
    "detail": { "host": "evil.example.com", "port": 443 }
  }
}
```

**Stability across runs — the fingerprint recipe.** GitHub dedups on
`primaryLocationLineHash` only, and uses *ours* when we provide it [VERIFIED].
Compute it from the **semantic identity** of the violation, deliberately
**excluding** `ts` (and connection `port`/argv-tail noise) so the same egress on
every CI run collapses to one alert:

```
identity = "\x00".join([server_id, classification, kind, target])
primaryLocationLineHash = sha256(identity.encode()).hexdigest()
```

where `target` is the *scope-defining* value per kind:
`net.connect` → `detail["host"]` (else `detail["ip"]`); `fs.open` →
`f'{detail["path"]}:{detail["mode"]}'`; `proc.spawn` → `argv[0]`/`cmd` basename;
`env.read` → `detail["var"]`. [INFERRED — design]

Deliberately **omit `manifest_hash`** from the identity: a rug-pull (manifest
change) is surfaced on its own channel (`verify` exit 2 / `ManifestDriftError`),
and keeping it out means the *same misbehavior* stays *one* alert across manifest
edits rather than churning open/closed. [INFERRED — design; consistent with
GitHub's "ruleId + filepath must be stable" guidance]

### 1.5 Wiring into CI

Add `--sarif PATH` to `verify` (and `audit`/`run`). The GitHub Action uploads
`PATH` via `github/codeql-action/upload-sarif@v3`; findings land in the repo's
Security → Code scanning tab, deduped by our fingerprints. `verify`'s exit-code
contract (0/1/2/4) is unchanged — SARIF is an *additional* artifact, and the
gate still fails the job on exit 1/2. GitHub also computes fingerprints itself
only when the SARIF file **and** the analyzed source are both in the repo; since
our "source" is behavior, self-computed fingerprints are mandatory, not
optional. [VERIFIED — GitHub SARIF support]

---

## 2. SIEM: OCSF vs Elastic ECS, and the flat shape to emit

### 2.1 The two candidates (primary-source facts)

**Elastic ECS** — a flat, dotted-key field dictionary. The categorization
quartet [VERIFIED — Elastic ECS reference]:

- `event.kind`: 8 values; **`alert`** = "an event such as an alert or notable
  event, triggered by a detection rule executing externally to the Elastic
  Stack" — firewalls/IDS/EDR. (`event` = generic something-happened.) This is
  the correct `kind` for an `outside_contract` finding.
- `event.category` (big buckets) with expected `event.type` per bucket:
  `network` → `access, allowed, connection, denied, end, info, protocol,
  start`; `process` → `access, change, end, info, start`; `file` → `access,
  change, creation, deletion, info`; `configuration` → `access, change,
  creation, deletion, info`; `intrusion_detection` → `allowed, denied, info`;
  `threat` → `indicator`.
- `event.outcome`: `success | failure | unknown`.
- Related fields used below all exist in ECS: `event.action`, `event.reason`,
  `event.severity` (numeric), `event.dataset`, `event.module`, `event.provider`,
  `rule.id`, `rule.name`, `rule.category`, and the network/file/process object
  fields `destination.address`, `destination.ip`, `destination.port`,
  `file.path`, `process.command_line`, `process.args`.

**OCSF** — a nested schema with integer enums. **Detection Finding, class_uid
`2004`, category_uid `2`** is the right class for a "detection/alert from a
security product" [VERIFIED — schema.ocsf.io/1.4.0]. Required/notable fields:
`class_uid=2004`, `category_uid=2`, `activity_id` (0 Unknown / **1 Create** / 2
Update / 3 Close / 99), `type_uid` (200400–200499), `time`, `severity_id` (0
Unknown / 1 Informational / 2 Low / 3 Medium / 4 High / **5 Critical** / 99),
`status_id`, `message`, `finding_info{uid,title,desc,types}` (required),
`metadata{product,version}` (required), `confidence_id` (0–3), `risk_level_id`,
and an `observables[]` array of `{name, type, type_id, value}`. Observable
`type_id`s [VERIFIED]: **1 Hostname, 2 IP Address, 4 User Name, 6 URL String,
7 File Name, 9 Process Name, 11 Port, 13 Command Line, 15 Process ID**.

### 2.2 Recommendation: emit ECS-aligned flat JSON

**Emit ECS-flavored flat JSON (one object per notable event), as NDJSON.**
Reasons [INFERRED — design, from the verified shapes]:

1. **Zero dependency, zero enum bookkeeping.** ECS is *flat dotted keys with
   string values* — a plain `dict` literal. OCSF requires nesting
   (`finding_info`, `metadata`, `observables[]`) and a table of **integer**
   enums (`activity_id`, `severity_id`, `type_uid`, observable `type_id`) that
   must be kept correct as the schema versions. The task's constraint is
   "SIEM-friendly without a heavy dependency"; flat ECS is the lighter of the
   two by a wide margin.
2. **Same ingestion reach.** Elastic/OpenSearch/Splunk/Datadog/Sentinel all
   ingest ECS-shaped JSON directly; OCSF's differentiator is AWS Security Lake
   and a handful of OCSF-native pipelines — a narrower default.
3. **Natural fit for our event.** A `BehaviorEvent` *is* a categorized
   network/file/process action, which is exactly what ECS's
   `event.category`/`event.type` quartet describes; the `outside_contract`
   verdict maps to `event.kind: alert`.

Keep OCSF as a **documented optional `to_ocsf`** (mapping in §2.4) for Security
Lake shops, added post-v0.1.0.

### 2.3 The concrete flat shape (`to_siem_json` → one dict per event)

Emit one object per **notable** event (`outside_contract` and
`within_manifest_not_policy`; `within_policy` only when
`include_within_policy=True`, for baselining). Dotted keys, string/number/array
values — flat, no nesting required:

```json
{
  "@timestamp": "2026-07-18T12:34:56.000Z",
  "event.kind": "alert",
  "event.category": ["network"],
  "event.type": ["connection", "denied"],
  "event.action": "net.connect",
  "event.outcome": "failure",
  "event.severity": 9,
  "event.reason": "connect to unlisted host evil.example.com:443 — outside declared contract",
  "event.dataset": "mcp_contract.behavior",
  "event.module": "mcp_contract",
  "event.provider": "mcp-contract",
  "rule.id": "outside_contract/net.connect",
  "rule.name": "Network connection outside the declared contract",
  "rule.category": "mcp-contract-behavioral",
  "destination.address": "evil.example.com",
  "destination.port": 443,
  "mcp_contract.server_id": "github-mcp",
  "mcp_contract.manifest_hash": "sha256:…",
  "mcp_contract.classification": "outside_contract",
  "mcp_contract.mode": "observe",
  "mcp_contract.backend": "docker",
  "mcp_contract.tool_ctx": "read_file",
  "mcp_contract.event_kind": "net.connect"
}
```

Field-derivation rules [INFERRED — from verified ECS allowed values]:

- **`@timestamp`** ← `BehaviorEvent.ts` (epoch float) → ISO-8601 UTC
  (`datetime.fromtimestamp(ts, timezone.utc).isoformat()`).
- **`event.kind`** ← `outside_contract → "alert"`; everything else `"event"`.
- **`event.category` / `event.type`** ← from `EventKind`:
  `net.connect → ["network"]`, type `["connection","allowed"]` normally or
  `["connection","denied"]` when the action was blocked (enforce/proxy-403);
  `fs.open → ["file"]`, type `["access"]` (read) / `["change"]` (write);
  `proc.spawn → ["process"]`, type `["start"]`; `env.read → ["configuration"]`,
  type `["access"]`; `syscall → ["process"]`, type `["info"]`;
  `mcp.call` is context-only → **skip** (not a system action).
- **`event.outcome`** ← `"failure"` if the action was denied/blocked (enforce
  mode or egress-proxy 403), else `"success"` (observe: the action happened).
  This is the *action* outcome; the *policy verdict* lives in
  `mcp_contract.classification`, not here.
- **`event.severity`** (numeric) ← report/event severity: `outside_contract → 9`,
  `within_manifest_not_policy → 4`, `within_policy → 1`.
- **`rule.id` / `rule.name`** ← same `(classification, kind)` rule identity as
  SARIF (one vocabulary across both formats).
- **observable fields** ← from `detail`, using ECS-native homes so SIEM
  correlation/dashboards work out of the box: `net.connect` →
  `destination.address` (host) / `destination.ip` (ip) / `destination.port`;
  `fs.open` → `file.path`; `proc.spawn` → `process.command_line` +
  `process.args`; `env.read` → `mcp_contract.env_var` (no standard ECS home).
- **`mcp_contract.*`** namespace ← everything product-specific that has no ECS
  field (`server_id`, `manifest_hash`, `classification`, `mode`, `backend`,
  `tool_ctx`, raw `event_kind`). Custom top-level namespaces are the ECS-endorsed
  way to carry non-standard fields.

### 2.4 OCSF Detection Finding mapping (for the optional `to_ocsf`)

| OCSF field | Value from mcp-contract |
|---|---|
| `class_uid`, `category_uid` | `2004`, `2` |
| `activity_id`, `type_uid` | `1` (Create), `200401` |
| `time` | `int(ts * 1000)` (ms) |
| `severity_id` | `outside_contract → 5` (Critical), `within_manifest → 3` (Medium), else `1` |
| `status_id` | `1` (New) |
| `message` | same human line as SARIF `message.text` |
| `finding_info.uid` | the §1.4 `primaryLocationLineHash` (shared identity) |
| `finding_info.title` / `.desc` | rule name / full description |
| `finding_info.types` | `["MCP contract violation", kind]` |
| `metadata.product.name` / `.version` | `"mcp-contract"` / `"0.1.0"` |
| `metadata.product.vendor_name` | `"mcp-contract"` |
| `confidence_id` | `3` (High) for `outside_contract` |
| `observables[]` | `net.connect` → `{type_id:1,"Hostname",host}` or `{type_id:2,"IP Address",ip}` + `{type_id:11,"Port",port}`; `fs.open` → `{type_id:7,"File Name",path}`; `proc.spawn` → `{type_id:13,"Command Line",cmd}`; `env.read` → `{name:"env_var",value:var}` |
| `unmapped` / custom | `{server_id, manifest_hash, classification, tool_ctx, backend}` |

The shared `finding_info.uid` = SARIF `primaryLocationLineHash` = a single stable
violation identity across all three formats — one violation, one id, everywhere.
[INFERRED — design]

---

## 3. Emitter functions to expose (stdlib-only)

New module `src/mcp_contract/report/export.py` (or `bcm/export.py`), importing
only `json`, `hashlib`, `datetime`:

```python
def violation_identity(server_id: str, classification: str, kind: str,
                       target: str) -> str: ...
    # sha256 hex of the §1.4 semantic identity; the one id shared by all formats.

def to_sarif(reports: list[ViolationReport], *,
             manifest_uri: str | None = None,
             include_within_manifest: bool = True) -> dict: ...
    # -> a SARIF 2.1.0 sarifLog dict (one run). json.dumps-ready.

def to_sarif_json(reports, **kw) -> str: ...          # thin json.dumps wrapper

def to_siem_json(reports: list[ViolationReport], *,
                 include_within_policy: bool = False) -> list[dict]: ...
    # -> ECS-aligned flat dicts, one per notable BehaviorEvent.

def to_siem_ndjson(reports, **kw) -> str: ...         # "\n".join(json.dumps(d))

# optional, post-v0.1.0:
def to_ocsf(reports: list[ViolationReport]) -> list[dict]: ...
```

Both required emitters take `list[ViolationReport]` so a fleet run serializes in
one call (SPEC §8.3 "xuất report cho nhiều server một lượt"). CLI surface:
`verify --sarif PATH`, `audit --sarif PATH --siem PATH`, `run … --siem PATH`;
machine artifacts to files, human chatter to stderr (matching the existing CLI
contract). No third-party SARIF/ECS/OCSF package is pulled in — every structure
above is a literal `dict`.

---

## Sources

Primary / vendor:
- OASIS SARIF 2.1.0 spec — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- SARIF 2.1.0 JSON schema — https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json
- GitHub — SARIF support for code scanning — https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
- GitHub — Uploading a SARIF file — https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github
- GitHub — codeql-action fingerprints.ts — https://github.com/github/codeql-action/blob/main/src/fingerprints.ts
- OCSF Detection Finding (2004), v1.4.0 — https://schema.ocsf.io/1.4.0/classes/detection_finding
- OCSF Observable object — https://schema.ocsf.io/1.4.0/objects/observable
- Elastic ECS — event.kind allowed values — https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind
- Elastic ECS — event.category allowed values — https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-category
- Elastic ECS — event.type allowed values — https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-type
- Elastic ECS — using categorization fields — https://www.elastic.co/docs/reference/ecs/ecs-using-categorization-fields
- Elastic ECS — Event fields — https://www.elastic.co/docs/reference/ecs/ecs-event

Secondary / context:
- Trivy SARIF output — https://deepwiki.com/aquasecurity/trivy/7.2-sarif-output-for-security-tools
- Checkov SARIF output — https://www.checkov.io/8.Outputs/SARIF.html
- BoostSecurity — SARIF limitations for non-source findings — https://boostsecurity.io/blog/sarif-cant-save-you-now
- Trivy discussion — partialFingerprints for de-duplication — https://github.com/aquasecurity/trivy/discussions/9070
- Splunk — What is OCSF — https://www.splunk.com/en_us/blog/learn/open-cybersecurity-schema-framework-ocsf.html
