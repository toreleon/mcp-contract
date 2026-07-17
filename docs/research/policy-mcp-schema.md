# policy-mcp schema — exact state, "emit exactly this" spec, and the upstream-PR proposal

Research pass: **2026-07-18**. Method: GitHub REST API + raw file reads of primary
sources (schema JSON, Rust source, examples), cross-checked against the local
implementation. Every schema claim below is read from a **pinned commit**, not a
rendered summary. Facts are tagged **[PRIMARY]** (read verbatim in the source) or
**[INFERRED]** (reasoned). This file supersedes the schema half of
`docs/policy-mcp-notes.md` where they disagree (see §3).

---

## 0. TL;DR (the three decisions this unblocks)

1. **The authoritative schema is `microsoft/policy-mcp` → `schema/v1.json`**, a
   JSON-Schema draft 2020-12 document. It is stricter than the Wassette Rust
   crate: **`additionalProperties: false` at the document root** and at every
   nested object. Root allows **exactly three keys**: `version`, `description`,
   `permissions`. [PRIMARY]

2. **A top-level `x-mcp-contract` key gives two different answers depending on
   who validates.** A Wassette-*runtime* consumer **accepts** it (the `policy`
   crate deserializes with serde and sets **no** `deny_unknown_fields`, so unknown
   keys are silently dropped). A **JSON-Schema validator** running the published
   `schema/v1.json` (e.g. the `yaml-language-server` directive the project ships in
   its own examples, or any CI `ajv`/`jsonschema` lint) **rejects** it, because
   root `additionalProperties: false` has no `x-` escape hatch. Both verified in
   primary source. **Our current single-file output is serde-valid but
   schema-invalid.** This is the one thing to fix/frame for v0.1.0.

3. **What `x-mcp-contract` must still carry is unchanged and confirmed:** per-cap
   `status`, `evidence`, `source_manifest_hash`, and (proposed) `behavior_expectations`,
   plus the three cap classes policy-mcp cannot express at all — `proc.exec`,
   `syscall`, resource limits with provenance. policy-mcp is still **unreleased**
   (0 tags, 0 releases), which keeps the §7 upstream contribution live and cheap.

---

## 1. Pinned current state (primary source)

| Fact | Value | Source |
|---|---|---|
| Repo | `github.com/microsoft/policy-mcp` | API |
| Description | "a specification for a policy format for MCP servers" | repo metadata |
| Default branch | `main` | repo metadata |
| **Latest commit (pin this)** | **`186e58128fa38da3df6ae2636782e820fe5d3da6`** | commits API |
| Latest commit date | **2026-01-13T07:47:59Z** | commits API |
| Latest commit | "Merge PR #7 … Add WASM/WASI runtime schema support with V8 and Wasmtime policy examples" | commits API |
| Commits total | 37 (stated on repo card) | repo README card |
| **Tags** | **none** | tags API (empty) |
| **Releases** | **none** | releases API (empty) |
| License | MIT | repo metadata |
| Created / last push | 2025-08-01 / **2026-01-13** (unchanged since Jan) | repo metadata |
| Authoritative schema file | `schema/v1.json` | git tree |
| Schema `$id` | `https://raw.githubusercontent.com/microsoft/policy-mcp/main/schema/v1.json` | schema |
| Schema dialect | `https://json-schema.org/draft/2020-12/schema` | schema |

Repo layout at the pinned commit (git tree, `recursive=1`):

```
README.md  DEFAULTS.md  LICENSE  SECURITY.md  SUPPORT.md  CONTRIBUTING.md  CODE_OF_CONDUCT.md
schema/v1.json                        <- the authority
Examples/minimal.yaml
Examples/network-only.yaml  Examples/storage-only.yaml  Examples/environment-only.yaml
Examples/defaults-http.yaml  Examples/development-with-defaults.yaml
Examples/Container/{comprehensive,development,docker,docker-privileged,restricted,web-service}.yaml
Examples/Wasm/{v8-wasi,wasmtime-wasi}.yaml
Examples/gVisor/{sandbox-minimal,web-service-gvisor}.yaml
```

There are **no Rust source files** in `microsoft/policy-mcp` — it is a spec repo
(schema + examples + docs). The Rust *implementation* lives in **`microsoft/wassette`
→ `crates/policy`** (`lib.rs`, `parser.rs`, `types.rs`), whose latest release tag is
now **v0.4.0** (SPEC still cites v0.3.4 — update that reference).

---

## 2. The exact `schema/v1.json` (read verbatim, pinned commit)

### 2.1 Document root

```jsonc
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://raw.githubusercontent.com/microsoft/policy-mcp/main/schema/v1.json",
  "title": "MCP Policy Document",
  "type": "object",
  "required": ["version", "permissions"],
  "properties": {
    "version":     { "type": "string", "pattern": "^1\\." },   // "1.x" only; "1.0" ok
    "description": { "type": "string" },
    "permissions": { "type": "object", "additionalProperties": false, "properties": {
        "storage": {"$ref":"#/$defs/PermissionList"},
        "network": {"$ref":"#/$defs/NetworkPermissionList"},
        "environment": {"$ref":"#/$defs/EnvironmentPermissions"},
        "runtime": {"$ref":"#/$defs/Runtime"},
        "resources": {"$ref":"#/$defs/ResourceLimits"},
        "ipc": {"$ref":"#/$defs/IpcPermissionList"} } }
  },
  "additionalProperties": false          // <-- ROOT is closed: only version|description|permissions
}
```

Load-bearing facts:
- **Root `additionalProperties: false`.** Only `version`, `description`, `permissions`
  are legal top-level keys. **No `$schema` field, no `x-*` extension key is
  schema-valid.** (The examples reference the schema via a YAML *comment* line —
  `# yaml-language-server: $schema=…/schema/v1.json` — which is not a document key,
  so it does not trip `additionalProperties`.)
- `permissions` itself is **also** `additionalProperties: false`, and it has **no
  required sub-keys** → an empty `permissions: {}` is valid.
- `version` must match `^1\.` (Wassette's `PolicyDocument::validate` enforces the
  same `starts_with("1.")`).

### 2.2 Permission families (all `$defs`, all `additionalProperties: false`)

**storage** — `PermissionList` = `{ allow?: StoragePermission[] | null, deny?: … }`
```
StoragePermission  (required: uri, access)
  uri:    string, minLength 1               # e.g. "fs://work/agent/**"
  access: AccessType[]  (minItems 1, uniqueItems)   AccessType = "read" | "write"
```

**network** — `NetworkPermissionList` = `{ allow?: NetworkPermission[] | null, deny?: … }`
`NetworkPermission` is a **oneOf** of exactly three item shapes:
```
NetworkHostPermission     { host: string, minLength 1 }        # "api.openai.com", "*.internal.company.com"
NetworkCidrPermission     { cidr: string, pattern ^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$ }  # IPv4 only
NetworkDefaultsPermission { defaults: boolean, const true }    # curated bundle (see §2.3)
```

**environment** — `EnvironmentPermissions` = `{ allow?: EnvironmentPermission[] | null }`
(note: **no `deny`** on environment — asymmetric with storage/network/ipc)
```
EnvironmentPermission  (required: key)
  key: string, minLength 1, pattern "^[^*]*$"   # NO wildcards allowed in env keys
```

**runtime** — `Runtime = { docker?: DockerRuntime|null, wasm?: WasmRuntime|null, hyperlight?: HyperlightRuntime|null }`
```
DockerRuntime.security = { privileged?: bool, no_new_privileges?: bool, capabilities?: {drop?: [], add?: []} }
CapabilityAction enum = ["ALL", "NET_BIND_SERVICE", "SYS_ADMIN", "SYS_TIME"]   # <-- only 4 values, coarse
WasmRuntime (required: engine)  engine ∈ {"v8","wasmtime"}; module?; wasi?{inherit_env,args,preopens[]}  # NEW (PR #7, Jan 2026)
HyperlightRuntime = additionalProperties: true   # placeholder, "future/TODO"
```

**resources** — `ResourceLimits` (**flat**, `additionalProperties: false`):
```
cpu:    number, 0..100     # PERCENT (not millicores)
memory: integer, >= 0      # MB
io:     integer, >= 0      # IOPS
```

**ipc** — `IpcPermissionList` = `{ allow?: IpcPermission[]|null, deny?: … }`,
`IpcPermission = { uri: string, minLength 1 }` (e.g. `pipe://…`, `socket://unix:/…`).

### 2.3 The `defaults` network bundle (from `DEFAULTS.md`)

Syntax is a boolean toggle item, **not** named bundles:
```yaml
network:
  allow:
    - defaults: true            # const true
    - host: "internal.mycompany.com"
```
`defaults: true` expands to a curated allowlist across ~7 categories: package
registries (npm/PyPI/crates/…), version control (GitHub/GitLab/Bitbucket), cloud
(AWS/GCP/Azure/Cloudflare), container registries, AI/ML APIs (OpenAI/Anthropic/
Cohere/HuggingFace), CDNs, and docs/CI-CD. **PIE must never emit `defaults: true`** —
it is the antithesis of least-privilege inference and the exact anti-pattern the
project exists to replace. (Good demo material: `defaults:true` vs a PIE-inferred
concrete host list.)

---

## 3. Reconciliation with `docs/policy-mcp-notes.md` (what changed / was wrong)

The prior notes were largely correct but read the **Wassette `policy` crate** rather
than the standalone spec. Corrections:

1. **Resources shape changed / diverged.** notes.md documents Kubernetes-style
   `resources.limits: { cpu: "500m", memory: "512Mi" }` (that is the Wassette
   `types.rs` `ResourceLimits.limits` shape). The **authoritative `schema/v1.json`
   uses a flat, different-units form**: `resources: { cpu: <0-100 percent>,
   memory: <int MB>, io: <int IOPS> }` — confirmed by `Examples/Container/comprehensive.yaml`
   (`cpu: 50.0, memory: 1024, io: 1000`). If we ever emit resources, follow the
   **schema** (flat percent/MB/IOPS), not the K8s strings. [PRIMARY, changed]
2. **`runtime.wasm` is new** (PR #7, merged 2026-01-13): `engine: v8|wasmtime` +
   WASI `preopens`. Not in the old notes. `runtime` now = docker | wasm | hyperlight.
3. **Docker capability enum is tiny and fixed**: only `ALL, NET_BIND_SERVICE,
   SYS_ADMIN, SYS_TIME`. This is the *entire* "syscall-ish" surface of policy-mcp —
   it is not seccomp and not the full Linux-cap set. [PRIMARY]
4. **notes.md gap #8 ("unknown-field tolerance unverified") is now resolved — and
   it splits two ways** (see §4). serde: tolerant. JSON-Schema: strict/rejecting.
5. **Still true:** no releases/tags (verified empty), MIT, deny-by-default,
   `defaults` bundle exists, no `proc.exec`, no `status/evidence/hash`. The
   `cidr` regex is **IPv4-only** (no IPv6) — worth noting for the import path.
6. **Wassette moved to v0.4.0** since the SPEC's v0.3.4 citation.

---

## 4. The unknown-field question, resolved (the pivotal finding)

**Q: Will a top-level `x-mcp-contract` key be rejected?** — It depends on the
validator, and the two disagree.

**(a) Wassette runtime consumer → ACCEPTS.** [PRIMARY]
`crates/policy/src/parser.rs`:
```rust
pub fn parse_str(content: impl AsRef<str>) -> PolicyResult<PolicyDocument> {
    let document: PolicyDocument = serde_yaml::from_str(content.as_ref())?;  // (1)
    document.validate()?;                                                    // (2)
    Ok(document)
}
```
- (1) `PolicyDocument` (`lib.rs`) = `{ version: String, description: Option<String>,
  permissions: Permissions }`. It derives `Deserialize` with **no
  `#[serde(deny_unknown_fields)]`**; `Permissions` (`types.rs`) likewise has **no**
  `deny_unknown_fields`. serde's default is to **silently ignore** unknown fields.
  So `x-mcp-contract` (and any `$schema:` field) is dropped on the floor and the
  document parses.
- (2) `validate()` only checks `version.starts_with("1.")` and recurses into
  permission validation. **It never runs `schema/v1.json`.**
- Caveat: `serde_yaml::from_str` reads a **single** YAML document. A `---`
  multi-document sidecar would make Wassette **error** ("more than one document"),
  so the "second YAML doc in the same file" trick is **not** safe. [PRIMARY/INFERRED]

**(b) JSON-Schema validator (`schema/v1.json`) → REJECTS.** [PRIMARY]
Root `additionalProperties: false` + `properties: {version, description, permissions}`
means any other top-level key (including `x-mcp-contract`) fails validation. This is
the validator behind the `# yaml-language-server: $schema=…` directive the project
ships in its own examples, and behind any CI `ajv --strict` / Python `jsonschema`
lint a consumer might run.

**Net:** our current emitted file (top-level `x-mcp-contract`) is **accepted by the
real Wassette runtime** but **fails the published JSON schema**. For the literal task
question — "so a Wassette-style *consumer* accepts it" — **yes, it does**. For "is it
a valid policy-mcp/v1 *document*" — **no, not against `schema/v1.json`**.

---

## 5. Emit exactly this — the schema-valid base `permissions` block

This is what `policy/io.py::_permissions_block` must produce so the base document
(with the extension key stripped) validates against `schema/v1.json` **and** parses
in Wassette. The current code already produces a schema-clean base block; the
findings below are the exact constraints plus small guards.

**Base document skeleton (only these three top-level keys are schema-legal):**
```yaml
version: "1.0"                                   # must match ^1\.
description: "Least-privilege policy for <server_id>, generated by mcp-contract"
permissions:
  network:
    allow:
      - host: "api.github.com"                   # NetworkHostPermission: {host}
      - host: "*.githubusercontent.com"          # wildcard host is a valid string
  storage:
    allow:
      - uri: "fs:///data"                        # StoragePermission: {uri, access}
        access: ["read", "write"]                # non-empty, unique, ⊆ {read,write}
  environment:
    allow:
      - key: "GITHUB_TOKEN"                       # EnvironmentPermission: {key}, no "*"
```

**Rules PIE/io.py must honour for the base block to stay valid:**

1. **Only `inferred` caps appear in `permissions`.** `needs_review` and `denied`
   are *not* grants and must never be written into `allow` (there is no policy-mcp
   list for "unconfirmed"). Current code does this correctly (`_granted_values`
   uses `Policy.granted`, which is INFERRED-only). An empty result → `permissions: {}`,
   which is schema-valid.
2. **network:** one `{host: <value>}` item per `net.http` value. Raw IPs and
   wildcard hosts (`*`, `*.example.com`) are legal `host` strings. **Do not** emit
   a bare `"*"` as anything other than a `host` string — there is no "allow all"
   primitive except the risky `defaults: true`, which we never emit. Values that are
   CIDR blocks should be emitted as `{cidr: <value>}` (IPv4 only per the regex);
   today io.py stores imported CIDRs as `net.http` values and would re-emit them as
   `host:` — **guard:** if a `net.http` value matches the CIDR regex, emit `{cidr}`,
   else `{host}`. [gap in current emit]
3. **storage:** merge `fs.read`/`fs.write` on the same prefix into one item with
   `access: ["read","write"]` (current code does this). `uri` must be non-empty;
   our absolute prefix `/data` → `fs:///data` (triple slash = empty authority) is a
   valid string. Semantic caveat: a real consumer parses `fs://<authority>/<path>`,
   so `fs:///data` (authority="") vs the examples' `fs://work/agent/**`
   (authority="work") differ in *matching* semantics — fine for validity, worth a
   note for interop.
4. **environment:** one `{key: <name>}` per `env` value. **Guard:** the schema
   forbids `*` in keys (`pattern ^[^*]*$`); assert no env value contains `*` before
   emit (env var names never do, but fail loud if one slips through).
5. **Never emit** `runtime`, `resources`, `ipc`, or `defaults:true` in v0 — we have
   no inferred content for them and `defaults` is anti-least-privilege.

**Handling the top-level extension key — recommendation for v0.1.0:**

Keep the **single self-describing file** with an inline top-level `x-mcp-contract`
block (it is what the SPEC/README/loader commit to, and the real Wassette runtime
accepts it), but make three honesty/forward-compat changes:

- **A. Do not ship a `# yaml-language-server: $schema=…/policy-mcp/…/v1.json`
  directive on our own files.** It would paint every mcp-contract policy red in an
  IDE, because the extension key violates `additionalProperties:false`. (Point the
  directive at *our* extended schema if/when we publish one — a superset that adds
  the `x-mcp-contract` def.)
- **B. Add a strict/base export path** (`mcp-contract infer --emit base` or a
  `policy_to_policy_mcp_base(policy)` that returns only `{version, description,
  permissions}`). This hands a **byte-for-byte `schema/v1.json`-valid** document to
  a strict consumer or a CI schema-lint. The base block we already build is exactly
  this once the extension key is dropped — so it is a projection, not new logic.
- **C. Land the upstream PR (§6)** so the single-file form becomes schema-valid and
  the whole question disappears.

Rationale for not defaulting to a two-file sidecar: (i) Wassette can't read a `---`
multi-doc, so "one file, two docs" is out; (ii) a separate `.mcp-contract.yaml`
sidecar doubles the artifacts and breaks the "the policy file *is* the contract"
story; (iii) the real runtime consumer already accepts the inline form. The base
export (B) covers the strict-validator case without giving up the single file.

---

## 6. The `x-mcp-contract` extension — finalized fields + upstream-PR proposal

### 6.1 What we emit today (from `io.py::policy_to_dict`, verified)
```yaml
x-mcp-contract:
  schema: "policy-mcp/v1"            # self-identifier string
  server_id: <string>
  source_manifest_hash: "sha256:<hex>"
  generated_by: "mcp-contract/0.1"
  backend_hint: <string|null>
  caps:
    - id: "net.http"                 # ∈ {net.http, fs.read, fs.write, proc.exec, env}
      status: "inferred"             # ∈ {inferred, needs_review, denied}
      values: ["*"]
      evidence:
        - { tool: "fetch", source: "param", detail: "parameter 'url' suggests a network endpoint" }
```
`evidence.source` ∈ `{name, description, param, static, override, llm}`.

### 6.2 Finalized field names (freeze these for v0.1.0 + the PR)

Keep the current names (they are already good and stable). Two additions, both
**optional** so they don't churn existing files:

```yaml
x-mcp-contract:
  ext_version: "1"                   # NEW (optional): version the EXTENSION independently
                                     #   of policy-mcp's own version. Rename target for the
                                     #   ambiguous 'schema' key; keep 'schema' as an alias in v0.
  server_id: <string>
  source_manifest_hash: "sha256:<hex>"   # binds policy to manifest version (rug-pull)
  generated_by: "mcp-contract/<ver>"
  generated_at: "<RFC3339>"          # NEW (optional): audit timestamp
  backend_hint: <string|null>
  caps:
    - id: <cap-class>                # see §7 for the expanded class set
      status: inferred|needs_review|denied
      values: [ ... ]
      evidence:
        - { tool: <str>, source: <enum>, detail: <str> }
      behavior_expectations:         # NEW (optional; SPEC §7) — see §6.3
        - kind: net.connect|fs.open|proc.spawn|env.read|syscall
          match: { host?: <pat>, path?: <prefix>, mode?: r|w|rw, argv?: [<glob>], group?: <str> }
```

- **Freeze**: `server_id`, `source_manifest_hash`, `generated_by`, `backend_hint`,
  `caps[].{id,status,values,evidence}`, `evidence[].{tool,source,detail}`. These are
  the load-bearing names the loader already treats as source-of-truth.
- **`ext_version`** disambiguates the current `schema: "policy-mcp/v1"` marker (which
  reads like it points at policy-mcp's version but is really our extension's). Emit
  both in v0.1.0 (accept `schema` on load), prefer `ext_version` going forward.

### 6.3 `behavior_expectations` — recommend defining but **not emitting** in v0.1.0

BCM already derives its event matchers directly from `caps` (net.http values → host
allowlist, fs.read/write prefixes → path matchers, etc.), so an explicit
`behavior_expectations` block is redundant *today*. Reserve the field name and shape
(above) for when an expectation must diverge from a cap's raw `values` (e.g. a cap
grants a broad host but the expectation pins a path+method). Emitting it now would be
schema churn with no consumer. **Decision: specify it in the extension schema, leave
it unemitted in v0.1.0, derive-on-the-fly in BCM.**

### 6.4 Upstream PR — two-track proposal

**Track A — the wedge PR (small, non-controversial, land first): reserve an `x-`
extension namespace in `schema/v1.json`.** Add, at the document root:
```jsonc
"patternProperties": { "^x-": {} },    // allow vendor extension keys (OpenAPI / k8s convention)
"additionalProperties": false          // keep the root otherwise closed
```
This makes **any** `x-*` sidecar (ours included) schema-valid without policy-mcp
having to bless our semantics. Framing for the PR: *"policy-mcp's own examples ship a
`$schema` IDE directive, yet the root is closed to the standard `x-` vendor-extension
convention; tools layering provenance/audit metadata on top of a policy currently
have to choose between a valid document and a self-describing one."* This is the
cheapest possible "insider flag-plant" and directly unblocks our single-file form.

**Track B — the native fields RFC (larger, propose as a discussion):** add
first-class provenance + review state to the base spec.
- **Provenance** — optional root `metadata` object: `{ source_manifest_hash,
  generated_by, generated_at }`. (Root, not per-item; it describes the whole policy.)
- **Per-grant `evidence`** — optional `evidence: [{tool, source, detail}]` on each
  permission item.
- **Review state** — this is the hard one, because policy-mcp is binary allow/deny
  and `needs_review` is **neither** (not granted, not forbidden). Propose an optional
  **third list** parallel to `allow`/`deny`: `review: [ …items… ]` on each
  `PermissionList`, meaning "implied but not granted; a human must confirm scope."
  This lets the three-status model live natively instead of in a sidecar. Expect
  this to be contentious (it changes the enforcement contract) — lead with Track A,
  offer Track B as the direction of travel.

---

## 7. proc.exec, syscall, and resource-limit caps — how to represent each

policy-mcp cannot express two of these at all and expresses the third only coarsely.
Recommendations, per class:

**`proc.exec` — extension-only in v0; propose a native `process` family upstream.**
- policy-mcp has **no** subprocess/exec primitive (`runtime` is container config,
  `ipc` is pipes/sockets, docker caps are Linux capabilities — none gate exec).
- v0: represent solely as an `x-mcp-contract` cap `id: proc.exec`, `values:
  [<program-basenames>]` (empty list = class-level "any exec"); it **never** appears
  in `permissions`. A foreign policy-mcp import always yields `proc.exec: denied`
  (current behaviour — keep).
- Upstream (Track B follow-on): propose `permissions.process.allow: [{ exec:
  "<basename-or-glob>" }]`. This is the single biggest coverage gap vs comparable
  systems (AgentBound covers fs/net/env but process-exec is the notable hole), so it
  is a credible, useful addition rather than a bespoke ask.

**`syscall` — extension-only; do NOT try to map onto docker capabilities.**
- policy-mcp's only syscall-adjacent surface is `runtime.docker.security.capabilities.
  {drop,add}` over a **4-value enum** (`ALL, NET_BIND_SERVICE, SYS_ADMIN, SYS_TIME`).
  That is Linux *capabilities*, not seccomp syscall groups, and the enum is far too
  small to represent BCM's `syscall`/`{group}` events. Do **not** lossily coerce our
  syscall caps into it.
- v0: represent as `x-mcp-contract` cap `id: syscall`, `values: [<group-names>]`,
  typically `status: needs_review` or `denied` (no backend except `mock` enforces
  syscalls; docker `syscall` capability is `none` per the BackendCaps matrix).
  `EventKind.SYSCALL` stays informational, matching the model.
- Optional least-privilege *enhancement* (schema-valid, high signal): when a policy
  grants **no** syscall/proc caps, emit a conservative hardening block into the base
  document —
  ```yaml
  runtime:
    docker:
      security: { privileged: false, no_new_privileges: true, capabilities: { drop: ["ALL"] } }
  ```
  This is valid against `schema/v1.json`, communicates least-privilege to a Wassette
  consumer, and costs nothing. Recommend as an opt-in emit flag, not default, for
  v0.1.0 (keep the base minimal until we can test a real Wassette consumer honours it).

**Resource limits — NOT a Capability; emit natively if/when modelled.**
- policy-mcp already models this: `permissions.resources: { cpu: <0-100 percent>,
  memory: <int MB>, io: <int IOPS> }` (flat — see §3.1). There is no `status`/
  `evidence` story needed for a scalar limit.
- v0: mcp-contract has no `resource` cap in `CapabilityId` and should keep it out of
  scope (a RAL concern, per the SPEC). If added later, write straight into the
  schema-valid `permissions.resources` block using the **flat percent/MB/IOPS** form
  (not K8s `500m`/`512Mi` strings, and not a nested `limits:` object). Only lift it
  into `x-mcp-contract` as `id: resource` if we ever need provenance/status on a
  limit — unlikely.

**Summary table:**

| Cap class | policy-mcp native? | v0 representation | Upstream ask |
|---|---|---|---|
| `net.http` | ✅ `network.allow[].host`/`.cidr` | base `permissions` (inferred) + ext caps | — (fits) |
| `fs.read`/`fs.write` | ✅ `storage.allow[].{uri,access}` | base `permissions` (inferred) + ext caps | — (fits) |
| `env` | ✅ `environment.allow[].key` (no `*`) | base `permissions` (inferred) + ext caps | — (fits) |
| `proc.exec` | ❌ none | `x-mcp-contract` cap only | new `permissions.process.allow[].exec` |
| `syscall` | ⚠️ only 4 coarse docker caps | `x-mcp-contract` cap only (+ optional `drop:[ALL]` hardening) | out of scope for policy-mcp |
| resource limits | ✅ `resources.{cpu,memory,io}` (flat) | out of scope in v0; emit native later | — (fits) |
| per-cap `status`/`evidence`/`hash`/`behavior_expectations` | ❌ | `x-mcp-contract` | Track A (`x-` namespace) then Track B (native) |

---

## 8. Concrete action items for v0.1.0

1. **Emit guard (network):** classify each `net.http` value — CIDR regex → `{cidr}`,
   else `{host}` (io.py currently emits everything as `host`). [correctness]
2. **Emit guard (environment):** assert no `env` value contains `*` before writing
   (schema `^[^*]*$`); fail loud otherwise. [validity]
3. **Add a base-only projection** (`--emit base` / `policy_to_policy_mcp_base`) that
   outputs `{version, description, permissions}` and validates against `schema/v1.json`.
   Add a test that pins `schema/v1.json` (commit `186e5812…`) and asserts the base
   output validates and the full output does **not** (documents the known gap). [interop]
4. **Do not ship the `yaml-language-server` directive** on full (extension-bearing)
   files; only on base-only output (or our own extended schema).
5. **Rename `x-mcp-contract.schema` → `ext_version`** (keep `schema` as an accepted
   alias on load); add optional `generated_at`. [clarity]
6. **Update `docs/policy-mcp-notes.md` §resources** (flat percent/MB/IOPS, not K8s)
   and the SPEC's Wassette version reference (v0.3.4 → v0.4.0).
7. **File the Track-A upstream PR** (`patternProperties: {"^x-": {}}` at root) while
   policy-mcp is still unreleased. Open the Track-B RFC (native `metadata` +
   per-grant `evidence` + `review:` list + `process` family) as a discussion.

---

## Sources (all primary, pinned where possible)

- policy-mcp schema (verbatim, pinned): `https://raw.githubusercontent.com/microsoft/policy-mcp/186e58128fa38da3df6ae2636782e820fe5d3da6/schema/v1.json`
- policy-mcp README: `https://raw.githubusercontent.com/microsoft/policy-mcp/186e58128fa38da3df6ae2636782e820fe5d3da6/README.md`
- policy-mcp DEFAULTS.md: `https://raw.githubusercontent.com/microsoft/policy-mcp/186e58128fa38da3df6ae2636782e820fe5d3da6/DEFAULTS.md`
- policy-mcp comprehensive example: `https://raw.githubusercontent.com/microsoft/policy-mcp/186e58128fa38da3df6ae2636782e820fe5d3da6/Examples/Container/comprehensive.yaml`
- policy-mcp repo / commits / tags / releases APIs: `https://api.github.com/repos/microsoft/policy-mcp` · `/commits?per_page=1` · `/tags` (empty) · `/releases` (empty) · `/git/trees/main?recursive=1`
- Wassette policy crate — top-level struct & parser (serde, no `deny_unknown_fields`): `https://github.com/microsoft/wassette/blob/main/crates/policy/src/lib.rs` · `.../parser.rs` · `.../types.rs`
- Wassette tags (latest v0.4.0): `https://api.github.com/repos/microsoft/wassette/tags`
- Local cross-refs: `src/mcp_contract/policy/io.py`, `src/mcp_contract/models.py`, `docs/policy-mcp-notes.md`, `SPEC.md` §7
</content>
</invoke>
