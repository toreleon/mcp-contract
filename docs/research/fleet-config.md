# Fleet config & embeddable SDK surface (SPEC §8.3)

Research date: 2026-07-18. Method: web search + primary-source fetch (vendor
docs, GitHub, the official MCP registry spec). Every config-format claim is
tagged **[VERIFIED]** (read in a primary source) or **[INFERRED]** (reasoned
from secondary sources or absence of evidence). The recommendation and API
sketch are **[DESIGN]** — my proposal, grounded in the verified facts and in
the frozen types in `src/mcp_contract/models.py` / `ral/base.py`.

Owner of the eventual code: whoever builds M5 (`report/SIEM export + fleet
API`). This file is the research input; it does not modify frozen files.

---

## TL;DR

1. **There is one de-facto config shape and it is not a formal spec — it is the
   `mcpServers` JSON object** that Claude Desktop, Claude Code (`.mcp.json`),
   and Cursor all use, with VS Code as the one deliberate deviation (top-level
   `servers`, not `mcpServers`). A server entry is either **stdio**
   (`command` + `args` + `env`) or **remote** (`type` + `url` + `headers`,
   where `type` ∈ `http`/`streamable-http`/`sse`/`ws`). [VERIFIED]

2. **Reuse the shape, don't adopt it as the source of truth.** Point
   mcp-contract at an existing `.mcp.json`/Cursor/VS Code file as a first-class
   *ingest* path (this is exactly what mcp-scan, dr-mcp, mcp-doctor already do —
   strong adoption precedent [VERIFIED]), but the fleet's source of truth is
   mcp-contract's own `fleet.yaml`, whose per-server `launch` block is a
   copy-paste-compatible superset of an `mcpServers` entry plus the operational
   fields the ecosystem shape lacks: `backend`, `mode`, `image`, `manifest`,
   `policy`, `labels`. [DESIGN]

3. **The report needs a stable per-server identity triple** the ecosystem
   configs don't carry: `manifest_hash` (have it), `policy_hash` (must add), and
   a `source`/launch fingerprint — plus `labels` for SIEM slicing. [DESIGN]

4. **What an infra team actually calls** is `infer_all()` once at onboarding and
   `verify_all()` in CI; `run_all()` is a convenience for single-host/test use.
   Live fleet monitoring in production is realistically *one monitor process per
   server* (sidecar), all emitting into one report sink — not one Python process
   babysitting the whole fleet. The embeddable API should optimize for the
   batch/CI calls and be honest that `run_all` is the convenience case. [DESIGN]

---

## Part 1 — The de-facto MCP server config formats (concrete shapes)

### 1.1 The `mcpServers` block (Claude Desktop, Claude Code, Cursor)

The canonical shape. Top-level key `mcpServers`, a map of *server-name → entry*.
The map key is the server's identity. [VERIFIED — FastMCP, Claude Code docs]

**stdio entry** (local process, spawned over stdin/stdout — the default and most
common):

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" }
    }
  }
}
```

- `command` (required): executable, absolute path or on `PATH`.
- `args` (optional): ordered argv array.
- `env` (optional): string→string env map.
[VERIFIED — gofastmcp.com/integrations/mcp-json-configuration]

**remote entry** (HTTP/SSE/WebSocket): the entry carries a `url` and no
`command`. Claude Code keys the transport off the `type` field:

```json
{
  "mcpServers": {
    "stripe": { "type": "http", "url": "https://mcp.stripe.com" },
    "sentry": {
      "type": "http",
      "url": "${API_BASE_URL:-https://api.example.com}/mcp",
      "headers": { "Authorization": "Bearer ${API_KEY}" }
    }
  }
}
```

Verified details that matter for parsing [VERIFIED — code.claude.com/docs/en/mcp]:
- `type` accepts `stdio`, `http`, `streamable-http` (an alias for `http` — the
  MCP spec's own name for the transport), `sse` (deprecated), and `ws`.
- **An entry with a `url` but no `type` is a hard error**; Claude Code reads a
  typeless entry as stdio and refuses it. So a robust parser treats "has
  `command`" ⇒ stdio and "has `url`" ⇒ must-have-explicit-`type`.
- `ws` entries accept the same `url`, `headers`, `headersHelper`, `timeout`,
  `alwaysLoad` fields as `http`.
- Per-server `timeout` (ms) and an `oauth` object (`clientId`, `callbackPort`,
  `authServerMetadataUrl`) may appear on remote entries.

**Environment-variable expansion** inside `.mcp.json` (and `~/.claude.json`):
`${VAR}` and `${VAR:-default}`, expanded in `command`, `args`, `env`, `url`, and
`headers`. Path placeholders `${CLAUDE_PROJECT_DIR}`, `${CLAUDE_PLUGIN_ROOT}`
also exist. [VERIFIED]

### 1.2 The `.mcp.json` convention (Claude Code, project scope)

`.mcp.json` at the project root is the committed-to-git, team-shared file; it is
literally an `mcpServers` block (§1.1) at the top level. Written by
`claude mcp add --scope project`. Project-scoped servers require an approval step
before use (trust gate). [VERIFIED — code.claude.com/docs/en/mcp]

```json
{
  "mcpServers": {
    "myserver": { "command": "/path/to/server", "args": [], "env": {} }
  }
}
```

This is the single most important file for mcp-contract to ingest: it is the
one a team already curates, version-controls, and shares — the natural anchor
for "point the tool at what you already run."

### 1.3 VS Code `mcp.json` — the deliberate deviation (+ a sandbox precedent)

VS Code uses **`servers`** as the top-level key, not `mcpServers`
(`.vscode/mcp.json` in a workspace, or user profile). [VERIFIED —
code.visualstudio.com/docs/agents/reference/mcp-configuration]

```json
{
  "servers": {
    "memory": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"] },
    "context7": { "type": "http", "url": "https://mcp.context7.com/mcp" }
  },
  "inputs": [
    { "type": "promptString", "id": "perplexity-key", "description": "API Key", "password": true }
  ]
}
```

- stdio fields: `type: "stdio"`, `command`, `args`, `cwd`, `env`, `envFile`,
  `dev` (`{ watch, debug }`), `sandboxEnabled`.
- http fields: `type: "http"` (or `sse`), `url`, `headers`, `oauth`.
- `inputs[]`: top-level prompted variables (`${input:id}`), for secrets.

**Most relevant finding for this project:** VS Code already ships a top-level
`sandbox` object — the industry is converging on exactly mcp-contract's
vocabulary inside the config file [VERIFIED]:

```json
{
  "sandbox": {
    "filesystem": { "allowWrite": ["${workspaceFolder}"], "denyRead": ["${userHome}/.ssh"] },
    "network": { "allowedDomains": ["api.example.com"] }
  }
}
```

This is hand-written, not inferred, and it is client-level not per-server — but
it validates the premise (`fs allow/deny` + `network allowedDomains` is the unit
teams reach for) and gives mcp-contract a natural *export* target: a PIE-inferred
policy could be rendered as a VS Code `sandbox` block, not only as policy-mcp.

### 1.4 The official MCP registry `server.json`

The registry (`registry.modelcontextprotocol.io`, schema
`2025-12-11/server.schema.json`) is a *publish/discovery* format, not a runtime
launcher, but it is where an image digest + argument metadata live. [VERIFIED —
modelcontextprotocol/registry generic-server-json.md]

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "io.modelcontextprotocol/filesystem",
  "description": "...",
  "version": "1.0.2",
  "packages": [
    {
      "registryType": "oci",
      "identifier": "mcp/filesystem",
      "version": "1.0.2",
      "runtimeHint": "docker",
      "transport": { "type": "stdio" },
      "runtimeArguments": [],
      "packageArguments": [],
      "environmentVariables": [
        { "name": "LOG_LEVEL", "description": "...", "isRequired": false, "isSecret": false }
      ]
    }
  ],
  "remotes": [
    { "type": "streamable-http", "url": "https://mcp-fs.example.io/http",
      "headers": [ { "name": "X-API-Key", "isRequired": true, "isSecret": true } ] }
  ]
}
```

- `packages[]`: `registryType` ∈ `npm|pypi|cargo|nuget|oci|mcpb`, `identifier`,
  `version`, `runtimeHint` (`npx|uvx|dnx|docker`), `transport: { type }`,
  and typed argument arrays. `oci` packages carry the container image — the
  cleanest source of a **pinned image digest** for the docker backend.
- `remotes[]`: `type` (`streamable-http`|`sse`), `url`, `headers[]`.
- `environmentVariables[]` and `headers[]` carry `isSecret` — a signal
  mcp-contract can lift straight into policy `env` grants and report redaction.

mcp-contract should treat `server.json` as an *optional enrichment* source
(resolve `identifier`+`version` → pinned digest, harvest `isSecret` env names),
not a primary fleet config.

### 1.5 Docker MCP Gateway / Catalog

A YAML catalog of container-packaged servers, referenced by URI. Files:
`/mcp/catalogs/docker-mcp.yaml`, `/mcp/config.yaml`, `/mcp/registry.yaml`.
[VERIFIED existence — docs.docker.com/ai/mcp-catalog-and-toolkit; exact YAML
field set INFERRED — the rendered pages show fields but not a full verbatim
schema]. A catalog server entry carries `title`, `description`, `image` (pinned
by digest, e.g. `mcp/duckduckgo@sha256:…`), `type: server`, `tools`, and
`secrets` mapped to env vars. Servers are addressed by reference:

```
catalog://mcp/docker-mcp-catalog/github
docker://my-server:latest
https://registry.modelcontextprotocol.io/v0/servers/<id>
file://./server.yaml
```

The gateway CLI takes `--catalog`, `--config`, `--registry`, `--secrets`,
`--transport`, `--port`. [VERIFIED — CLI flags]

Relevance: the Docker catalog is the best real-world source of **pinned image
digests** for the docker backend, and its `secrets → env` mapping mirrors what
PIE's `env` capability wants. mcp-contract's docker backend and this catalog are
complementary: the catalog says *what image*, mcp-contract says *what that image
is allowed to do*.

### 1.6 Precedent: security tools already ingest `mcpServers`

Every MCP-hygiene tool discovered auto-discovers the same config files:
- **mcp-scan** (Invariant/Snyk): "searches through your configuration files to
  find MCP server configurations… automatically discover… Claude, Cursor and
  Windsurf… Gemini CLI"; it reads the `mcpServers` entries and *runs the
  commands* to fetch `tools/list`. [VERIFIED — mcp-scan README]
- **dr-mcp**, **mcp-doctor**: audit/repair across "Claude Code, Codex, Cursor,
  Windsurf, GitHub Copilot, VS Code, Cline, Roo Code, Continue, Zed, and
  `.mcp.json`" at their standard locations. [VERIFIED — repos]

**Takeaway:** "point it at your existing config" is the established zero-friction
adoption pattern for this exact category. mcp-contract should match it, then add
the operational layer nobody else has (backend/mode/policy binding).

---

## Part 2 — Recommendation: reuse the shape, own the config

**Do both, with a clear split of roles:**

- **Ingest adapter (reuse).** `Fleet.from_mcp_servers(path)` accepts any
  `mcpServers`/`servers` file (Claude Desktop, `.mcp.json`, Cursor, VS Code) and
  synthesizes a fleet with sane defaults. This is the demo/onboarding path:
  *"you already have a `.mcp.json`; run `mcp-contract fleet infer --from-mcp
  .mcp.json` and get least-privilege policies for every server in it."* Matches
  mcp-scan/dr-mcp precedent; near-zero adoption cost.

- **Native fleet config (own).** `fleet.yaml` is the source of truth for a team
  that has moved past the demo. Its per-server `launch` block is a
  **copy-paste-compatible superset of an `mcpServers` entry** (same
  `command`/`args`/`env` for stdio, same `type`/`url`/`headers` for remote), so
  a user pastes the block they already know and only adds the operational
  fields. It exists because the `mcpServers` shape structurally cannot express
  what the engine needs:

| mcp-contract needs | in `mcpServers`? |
|---|---|
| which **sandbox backend** (docker/mock/…) | ✗ |
| which **mode** (observe/alert/enforce) | ✗ |
| the **OCI image** to sandbox in (stdio entry is a host command) | ✗ (only in registry/catalog) |
| the **pinned manifest** to infer/verify against (rug-pull binding) | ✗ |
| the **pre-approved policy** path | ✗ |
| **labels** for SIEM slicing (team/env/data-class) | ✗ |
| stable **id** | ~ (map key doubles as id — reuse it) |

Trying to overload `mcpServers` with these (e.g. an `x-mcp-contract` sidecar per
entry) would fight every client that validates the file. Keep the ingest shape
pristine; put mcp-contract's fields in mcp-contract's file. [DESIGN]

**One structural nuance to call out** (drives the schema below): an `mcpServers`
stdio entry describes a **host process** (`npx …`), while mcp-contract's docker
backend needs an **image**. These are different things. The fleet config keeps
both: `launch` records how the server is normally started (provenance + the
mock/host run path), and `image` names what the docker backend sandboxes. For a
Docker-catalog server the two coincide (`command: docker, args: [run, …, mcp/x]`
and `image: mcp/x@sha256:…`); parsing the image out of `docker run` args is
fragile, so require `image` explicitly when `backend: docker`. Remote (`http`)
servers can't be process-sandboxed at all — mcp-contract can only observe/enforce
their **egress via the proxy**, so they're `mode: observe` + egress-proxy only in
v0 (flag this in validation). [DESIGN]

---

## Part 3 — The exact fleet-config schema

`fleet.yaml` (YAML preferred for comments/secrets ergonomics; the loader also
accepts `fleet.json`). Reuses the same loaders the engine already has
(`load_manifest`, `load_policy` accept path/dict).

```yaml
version: "0.1"                    # fleet-config schema version (not policy version)

defaults:                         # applied to every server unless overridden
  backend: docker                 # docker | mock
  mode: observe                   # observe | alert | enforce
  egress_proxy: true              # docker only; hostname-level net.http enforce
  manifest_dir: manifests/        # resolve per-server `manifest:` relative to here
  policy_dir:  policies/          # resolve per-server `policy:`   relative to here

servers:
  github:                         # map key == server id (matches mcpServers)
    launch:                       # <-- verbatim mcpServers/​server.json entry shape
      transport: stdio            # stdio | http | sse  (mirrors ecosystem `type`)
      command: docker
      args: ["run", "-i", "--rm", "mcp/github"]
      env:
        GITHUB_TOKEN: "${GITHUB_TOKEN}"   # ${VAR} / ${VAR:-default} expansion
    image: "mcp/github@sha256:abc…"       # OCI image for backend=docker (pinned)
    manifest: github.tools.json           # pinned tools/list (rug-pull baseline)
    policy:   github.policy.yaml          # pre-approved policy (optional for infer)
    backend:  docker                      # overrides defaults.backend
    mode:     enforce                     # overrides defaults.mode
    egress_proxy: true
    labels:                               # free-form; surfaced in every report row
      team: platform
      env: prod
      data_class: source-code
      owner: alice@corp

  notion-remote:
    launch:
      transport: http
      url: "https://mcp.notion.com/mcp"
      headers: { Authorization: "Bearer ${NOTION_TOKEN}" }
    manifest: notion.tools.json
    policy:   notion.policy.yaml
    backend:  docker
    mode:     observe                     # remote => observe + egress-proxy only in v0
    labels: { team: docs, env: prod, data_class: internal-docs }

  local-fs:
    launch:
      transport: stdio
      command: npx
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    backend: mock                         # replay recorded events (CI)
    mode:    observe
    events:  events/local-fs.jsonl        # mock backend replay source
    manifest: filesystem.tools.json
    policy:   filesystem.policy.yaml
    labels: { team: data, env: ci }
```

### Field reference

**Top level**
- `version` (str, required): fleet-config schema version. Distinct from
  policy-mcp `version` and from `manifest_hash`.
- `defaults` (map, optional): any per-server field except `launch`/`image`/
  `manifest`/`policy`/`labels`/`id`; merged under each server (server wins).
- `servers` (map, required): server-id → server entry.

**Per-server entry**
- `launch` (map, required): the ecosystem entry, verbatim.
  - `transport`: `stdio` | `http` | `sse` (accept `streamable-http` as an alias
    for `http`, matching Claude Code). Defaults to `stdio` when `command` is
    present, and is **required** when only `url` is present (mirrors the
    ecosystem's "url without type is an error" rule).
  - stdio: `command` (str), `args` (list[str]), `env` (map[str,str]), `cwd`.
  - remote: `url` (str), `headers` (map[str,str]).
  - `${VAR}` / `${VAR:-default}` expansion applied on load (host env), matching
    `.mcp.json`. **Values are never persisted post-expansion into reports** —
    only the *keys* are (redaction; see Part 4).
- `image` (str): OCI image for `backend: docker`; **required** when
  `backend == docker`. Recommend a pinned `@sha256:` digest.
- `manifest` (path|inline): a saved `tools/list` (resolved via
  `defaults.manifest_dir`). Required for `infer`/`verify` — it is the rug-pull
  baseline the `manifest_hash` is computed from. If omitted, engine may
  live-discover by launching the server (see `fleet discover`), but a pinned
  file is the reproducible, CI-safe choice.
- `policy` (path): pre-approved policy YAML (resolved via `defaults.policy_dir`).
  Optional for `infer_all` (it writes one), required for `verify_all`/`run_all`.
- `backend` (str): `docker` | `mock`. Passed straight to `get_adapter`.
- `mode` (str): `observe` | `alert` | `enforce` → `models.Mode`.
- `egress_proxy` (bool): docker only; enables hostname-level `net.http` enforce.
- `events` (path): mock-backend replay source (and the default `--events-out`
  location for audit/verify).
- `labels` (map[str,str]): free-form, echoed into every report row; the SIEM
  slice dimension. Reserved-but-optional keys the report understands specially:
  `team`, `env`, `owner`, `data_class`.

### Validation rules the loader must enforce (fail closed)
1. `backend: docker` ⇒ `image` present (don't parse it out of `docker run`).
2. `launch.transport: http|sse` ⇒ `mode` must be `observe` (v0: can't
   process-sandbox a remote; egress-proxy observe only) — warn+downgrade or
   reject.
3. `url` present but no `transport` ⇒ error (ecosystem parity).
4. `verify`/`run` selected but no `policy` for a server ⇒ error (never gate
   without a contract).
5. A referenced `${VAR}` with no value and no default ⇒ warn per server, keep
   `${VAR}` literal (ecosystem parity), and mark that server `skipped` in the
   report rather than silently launching with a broken env.

---

## Part 4 — The `mcpServers` ingest adapter

`Fleet.from_mcp_servers(path, *, backend="docker", mode="observe")` normalizes
any of these into the native model:

- top-level `mcpServers` (Claude Desktop / `.mcp.json` / Cursor) **or**
  top-level `servers` (VS Code) — try both keys.
- each entry → a `FleetServer` with `id = map key`, `launch = entry` (as-is),
  `backend`/`mode` from the call defaults, `labels = {source: "<file>",
  client: "claude-code|vscode|cursor|unknown"}`.
- stdio entries get `backend` per the argument; remote entries are forced to
  `mode: observe` (Part 3 rule 2) and get an egress-proxy plan.
- manifests are **not** in these files, so the ingest path pairs with a
  `discover` step: launch each server, call `tools/list`, write
  `manifests/<id>.tools.json`, then infer. (This is precisely mcp-scan's
  "execute the command to fetch tool descriptions" step — call it out as a
  supply-chain caveat: discovery *runs untrusted code*, so do it inside the
  sandbox backend, not on the host.)

A `Fleet.discover()` convenience may scan the well-known client paths
(`~/Library/Application Support/Claude/claude_desktop_config.json`,
`./.mcp.json`, `~/.cursor/mcp.json`, `./.vscode/mcp.json`, …) and union them —
matching dr-mcp/mcp-doctor behavior. Nice-to-have, not v0-critical. [DESIGN;
well-known paths INFERRED from secondary tool docs — verify exact paths per OS
before shipping discovery.]

---

## Part 5 — Per-server identity/metadata a SIEM/fleet report needs

A SIEM row must let an operator answer "*which* server, running *what*, under
*which* contract, owned by *whom*, did *what*." The current `ViolationReport`
already carries `server_id`, `manifest_hash`, `mode`, `counts`, `severity`,
`suggested_action`, and per-event detail. Wrap each per-server report in a
metadata envelope with the fields below; **bold = not currently emitted, add it.**

| Field | Source | Why the SIEM needs it |
|---|---|---|
| `server_id` | fleet key | primary correlation key |
| **`source`** | fleet-file path + `labels.client` | provenance: which config declared this server |
| **`launch_fingerprint`** | `image@digest` **or** `command`+`args` (env **keys only**) | *what actually ran*; digest catches image swaps |
| **`transport`** | `launch.transport` | stdio vs remote changes the threat surface |
| `manifest_hash` | `Manifest.hash()` (have it) | binds behavior to the declared tool surface; rug-pull key |
| **`policy_hash`** | sha256 of canonical policy dict (**add**) | *which exact contract was in force*; correlate policy changes to behavior changes |
| `policy.generated_by` | `Policy.generated_by` | engine/provenance (`mcp-contract/0.1`) |
| **`backend` + `backend_caps`** | adapter `capabilities()` | tells the analyst what could/couldn't be enforced (e.g. docker fs = boot-time only) |
| `mode` | `ViolationReport.mode` | observe vs enforce changes how to read a violation |
| **`labels`** | fleet `labels` | the slice dimensions: team, env, data_class, owner |
| **`run_id` / `started_at` / `ended_at`** | monitor run | dedupe + timeline |
| **`engine_version`** | `mcp_contract.__version__` | reproducibility |
| `severity` / `suggested_action` / `counts` | `ViolationReport` (have it) | triage |
| `events[]` | `ViolationReport.events` | the evidence, each already classified + `tool_ctx` |

**Two concrete additions to make in the model layer:**

1. **`policy_hash`** — compute sha256 over the canonical `policy_to_dict` output
   at load/emit time; store it beside `manifest_hash`. Without it a SIEM can see
   "the manifest is unchanged" but not "someone widened the policy." This is the
   policy-side analog of the rug-pull hash and belongs in `x-mcp-contract`
   alongside `source_manifest_hash` (feeds the §7 upstream contribution).

2. **Secret hygiene** — reports carry env **key names, never values**; the
   launch fingerprint redacts `env` to its key set. `isSecret` from
   `server.json`/catalog `secrets` marks which keys to also drop from the
   fingerprint entirely. Bake redaction into the metadata serializer so it can't
   be forgotten at a call site.

**Serialization for SIEM:** emit **NDJSON — one JSON object per server per run**
(not one giant array). SIEM/log pipelines (Splunk, Elastic, Loki) ingest
line-delimited JSON natively, it streams, and a single server's failure doesn't
corrupt the batch. Reuse the existing `ViolationReport.to_dict()` as the `report`
sub-object inside each envelope.

---

## Part 6 — The embeddable Fleet API surface

Design goals: mirror the existing free-function engine (`infer_policy`,
`classify_events`, `get_adapter`, `Monitor`) rather than reinvent it; make the
batch/CI calls first-class; keep `run_all` honest about being the single-host
convenience. All names are `[DESIGN]`.

```python
# mcp_contract/fleet.py  (new module; nothing frozen is touched)

@dataclass
class FleetServer:
    id: str
    launch: dict                       # verbatim mcpServers/​server.json entry
    backend: str = "docker"            # -> get_adapter
    mode: Mode = Mode.OBSERVE
    image: str | None = None
    manifest_path: str | None = None
    policy_path: str | None = None
    events_path: str | None = None
    egress_proxy: bool = False
    labels: dict[str, str] = field(default_factory=dict)

    def to_server_spec(self, policy: Policy) -> ServerSpec: ...
        # id->server_id, image->image, launch.command+args->command,
        # expanded+policy-filtered env->env, labels/source/hashes->extra

@dataclass
class FleetServerReport:                # the SIEM envelope (Part 5)
    server: FleetServer
    report: ViolationReport | None      # None if skipped/errored
    manifest_hash: str
    policy_hash: str
    backend_caps: BackendCaps
    status: str                         # "ok" | "violation" | "rug_pull"
                                        #  | "skipped" | "error"
    exit_code: int                      # per-server CLI-contract code
    error: str | None = None
    def to_dict(self) -> dict: ...      # redacts env values; NDJSON row

@dataclass
class FleetReport:
    runs: list[FleetServerReport]
    started_at: float
    engine_version: str
    def exit_code(self) -> int: ...     # aggregate: max-precedence over runs
    def severity(self) -> Severity: ...
    def to_ndjson(self) -> str: ...     # one FleetServerReport per line
    def to_dict(self) -> dict: ...      # summary + runs (for a single-blob sink)

class Fleet:
    servers: list[FleetServer]

    # --- construction ---
    @classmethod
    def from_config(cls, path: str | Path) -> "Fleet": ...          # native fleet.yaml
    @classmethod
    def from_mcp_servers(cls, path, *, backend="docker",
                         mode=Mode.OBSERVE) -> "Fleet": ...          # ingest .mcp.json/VS Code/Cursor
    @classmethod
    def discover(cls) -> "Fleet": ...                               # scan well-known client paths (optional)

    # --- selection (run a slice) ---
    def select(self, **labels: str) -> "Fleet": ...                # e.g. select(env="prod", team="platform")

    # --- the three batch verbs ---
    def infer_all(self, *, llm=None, write=True) -> FleetReport: ...
        # per server: load_manifest -> infer_policy -> (write policy_path);
        # aggregate needs_review counts; never gates (exit 0 unless bad input=4)
    def audit_all(self) -> FleetReport: ...
        # per server: load events (events_path) -> classify_events;
        # reports only, always exit 0 (matches `audit`)
    def verify_all(self, *, allow_empty=False) -> FleetReport: ...
        # per server: verify_manifest_hash (2) -> classify -> violations (1);
        # aggregate exit code with the CLI precedence below. THE CI GATE.

    # --- live convenience (single host / tests) ---
    def run_all(self, *, max_events=None, duration=None,
                sequential=True) -> FleetReport: ...
        # per server: get_adapter -> start -> Monitor.run -> stop.
        # Honest default sequential=True; parallelism is opt-in and out of v0 scope.
```

**Aggregate exit-code precedence** (preserves the CLI contract in
`cli.py`: 0 clean, 1 violation, 2 rug-pull, 4 bad-input). The fleet code is the
*most severe security signal first*, with bad-input never masking or faking a
security verdict:

```
if any server rug_pull        -> 2
elif any server violation     -> 1
elif any server error/bad-input/skipped -> 4
else                          -> 0
```

(Rug-pull outranks a plain violation because a changed manifest invalidates the
whole comparison; `4` stays last so a broken pipeline never *looks* clean and
never trips a gate keyed on 1/2. This matches the single-server rationale in
`cli.py`.)

**CLI surface** (thin wrapper, mirrors the existing subcommands):

```
mcp-contract fleet infer   --config fleet.yaml [--from-mcp .mcp.json]
mcp-contract fleet audit   --config fleet.yaml [--json|--ndjson]
mcp-contract fleet verify  --config fleet.yaml [--select env=prod]   # CI gate, aggregate exit code
mcp-contract fleet run     --config fleet.yaml --report-out fleet.ndjson
```

---

## Part 7 — What an infra team actually calls

The realistic lifecycle, and which surface serves each step:

1. **Onboard (once, human-in-loop).** `Fleet.from_mcp_servers(".mcp.json")` or
   `from_config`, then `infer_all()`. Output: a policy per server + an aggregated
   `needs_review` list. A human approves by editing the policy YAMLs (the
   existing low-tech flow). This is the demo *and* the real first step.

2. **Gate (every CI run, unattended).** `Fleet.from_config("fleet.yaml")
   .select(env="ci").verify_all()` → **one aggregate exit code** gates the merge.
   This is the single most-called surface. It needs recorded event streams
   (mock backend replays `events_path`, or a prior `run` produced them). The
   GitHub Action sketch in `examples/` generalizes to "verify the whole fleet."

3. **Monitor (production).** Here the honest answer diverges from a tidy
   `run_all()`: production fleets run **one monitor per server as a sidecar**
   (each server already runs as its own container/service), every sidecar
   emitting `FleetServerReport` NDJSON to a shared sink (SIEM/S3/Kafka). So the
   heavily-used production surface is actually the **per-server** `Monitor` +
   the **serializer** (`FleetServerReport.to_dict`), not a single Python process
   looping the fleet. `run_all(sequential=True)` is the right tool for a
   single-host fleet, a smoke test, or a nightly batch — say so, don't oversell
   it. Parallel/orchestrated live monitoring is explicitly beyond v0.

4. **Slice & report (on demand).** `select(**labels)` + `FleetReport.to_ndjson`
   answers "show me every prod server that went outside contract this week,
   grouped by team." Labels are what make this cheap — which is why they're
   required in the schema even though the engine ignores them.

**Net:** optimize the embeddable API for `infer_all`/`verify_all`/`audit_all`
(batch, deterministic, CI-shaped, mock-backend-friendly) and the NDJSON
serializer. Ship `run_all` as a labeled-convenience with `sequential=True`
default and a docstring that points production users at the per-server sidecar
pattern.

---

## Open questions / caveats before building M5

- **Live discovery runs untrusted code.** `from_mcp_servers` + `discover` must
  fetch `tools/list` by *launching the server inside the sandbox backend*, never
  on the host — otherwise the fleet tool becomes the attack vector (mcp-scan
  carries the same caveat). Gate discovery behind an explicit flag.
- **Well-known client config paths** (§4) are from secondary tool docs
  [INFERRED]; enumerate and verify the exact per-OS paths (macOS/Linux/Windows)
  against each client's own docs before shipping `discover()`.
- **Docker catalog YAML** exact field set is [INFERRED] from rendered docs; if
  mcp-contract wants to ingest a Docker catalog directly, clone
  `docker/mcp-gateway` and pin the schema.
- **`policy_hash` + secret redaction** are new model-layer work (Part 5); they
  touch the serializer, not the frozen dataclasses, but the `policy_hash` field
  should be threaded into `x-mcp-contract` for the §7 upstream story.
- **Parallel `run_all`** (thread/async orchestration, backpressure, partial
  failure) is deliberately out of v0 scope; note it so a reviewer doesn't expect
  it.

---

## Sources

Config formats (primary):
- https://gofastmcp.com/integrations/mcp-json-configuration
- https://code.claude.com/docs/en/mcp
- https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- https://code.visualstudio.com/docs/agent-customization/mcp-servers
- https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md
- https://modelcontextprotocol.io/registry/remote-servers

Registry / gateway / catalog:
- https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/
- https://docs.docker.com/ai/mcp-catalog-and-toolkit/catalog/
- https://www.docker.com/blog/build-custom-mcp-catalog/
- https://github.com/docker/mcp-gateway
- https://registry.modelcontextprotocol.io/docs

Ingest precedent (tools that read `mcpServers`):
- https://github.com/invariantlabs-ai/mcp-scan/blob/main/README.md
- https://invariantlabs-ai.github.io/docs/mcp-scan/
- https://github.com/Inferensys/dr-mcp
- https://github.com/realwigu/mcp-doctor

Internal (this repo, frozen types the API must reuse):
- src/mcp_contract/models.py — Policy, Manifest, ViolationReport, Mode, Severity
- src/mcp_contract/ral/base.py — ServerSpec, ServerHandle, BackendCaps
- src/mcp_contract/ral/__init__.py — get_adapter
- src/mcp_contract/cli.py — exit-code contract (0/1/2/4) the fleet aggregate mirrors
```
