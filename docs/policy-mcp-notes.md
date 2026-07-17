# policy-mcp compatibility notes (research pass, 2026-07-17)

Findings from a short web research pass on the real Wassette policy schema
("policy-mcp"), and the alignment/gap decisions baked into
`src/mcp_contract/policy/io.py`.

## What was found

Network access worked; the sources below were reachable.

- Wassette repo: <https://github.com/microsoft/wassette> — workspace crates:
  `component2json`, `mcp-server`, `policy`, `wassette`. There is no crate
  literally named `policy-mcp` in the tree; the schema SPEC.md calls
  "policy-mcp (Wassette v0.3.4)" is implemented by the **`policy` crate**
  (<https://github.com/microsoft/wassette/tree/main/crates/policy>), whose
  README describes it as a "Rust library for parsing and validating
  capability-based security policies for Model Context Protocol (MCP)
  servers" and says it is "implemented by policy-mcp and Wassette".
- Concepts doc: <https://microsoft.github.io/wassette/latest/concepts.html> —
  deny-by-default capability model; permissions are granted per component via
  YAML policy files, MCP grant tools, or the CLI.
- Type definitions: `crates/policy/src/types.rs`
  (<https://github.com/microsoft/wassette/blob/main/crates/policy/src/types.rs>)
  — exact serde field names confirmed below.
- Release cited by SPEC: <https://github.com/microsoft/wassette/releases/tag/v0.3.4>

### The real schema (as of this pass)

Top level: `version: "1.0"`, optional `description`, and `permissions`.
Each permission section is a `PermissionList` with optional `allow` and
`deny` arrays. Sections and grant shapes:

```yaml
version: "1.0"
permissions:
  storage:
    allow:
      - uri: "fs://workspace/**"        # URI patterns, glob wildcards ** and *
        access: ["read", "write"]       # AccessType: "read" | "write"
  network:
    allow:
      - host: "api.openai.com"          # host patterns (wildcards supported)
      - cidr: "10.0.0.0/8"              # CIDR ranges
  environment:
    allow:
      - key: "PATH"                     # env var names
  resources:
    limits:
      cpu: "500m"                       # Kubernetes-style resource notation
      memory: "512Mi"
```

`types.rs` additionally defines `runtime` and `ipc` permission sections
(runtime configuration and IPC grants, not modeled here).

## Alignment decisions in `policy/io.py`

- The emitted base document uses the real schema where it can express our
  capabilities: `version: "1.0"`, `description`, and `permissions` with
  `network.allow: [{host: ...}]`, `storage.allow: [{uri: "fs://<prefix>",
  access: [...]}]`, `environment.allow: [{key: ...}]`.
- **Only `inferred` (granted) capabilities appear in `permissions`**;
  `needs_review` and `denied` live only in the `x-mcp-contract` extension
  block, which carries the full three-status picture (status, values,
  evidence, `source_manifest_hash`) and is the source of truth on load.
- `fs.read`/`fs.write` grants on the same path are merged into one storage
  entry with `access: ["read", "write"]`. Our values are path *prefixes*,
  not globs, so they are emitted as plain `fs://` URIs without wildcards
  (an absolute `/data` becomes `fs:///data`).
- Importing a foreign policy-mcp file (no `x-mcp-contract`): `allow` grants
  are synthesized as `inferred` capabilities with evidence
  `source="override"`; absent classes become `denied` (deny-by-default made
  explicit). Trailing glob segments on storage URIs (`/**`, `/*`) are
  stripped down to the enclosing prefix, since our matcher is prefix-based.
- `deny` lists are ignored on import: our model is deny-by-default, so an
  explicit deny adds no grant information in v0.
- Storage entries without an `access` list are skipped on import
  (direction unknown; least-privilege says do not guess).

## Gaps — upstream PR material (spec §7 contribution surface)

1. **No `proc.exec` analog.** Nothing in `permissions` can express
   subprocess/exec allowlisting (`runtime` is runtime configuration, `ipc`
   is not exec). `proc.exec` therefore lives only in `x-mcp-contract`, and
   a foreign policy-mcp file always imports with `proc.exec: denied`.
2. **No per-capability `status`.** policy-mcp is binary allow/deny; there is
   no way to express `inferred` vs `needs_review` vs `denied` upstream —
   the entire human-approval workflow needs the extension block.
3. **No `evidence`.** No audit trail for *why* a grant exists.
4. **No `source_manifest_hash`.** Policies are not bound to a manifest
   version, so rug-pull detection (manifest changed → re-infer) has no
   upstream expression.
5. **No generator provenance** (`generated_by`).
6. **`cidr` grants have no analog in our host matching** (exact/suffix
   wildcard hostnames or IPs). On import they are preserved as opaque
   `net.http` values but will not match hostname events in v0; real CIDR
   egress control needs the proxy backend.
7. **`resources`, `runtime`, `ipc` sections are not modeled** in v0
   (resource limits are a RAL concern later).
8. **Unknown-field tolerance unverified.** serde ignores unknown fields by
   default, so `x-mcp-contract` should be tolerated by the Rust parser
   unless `deny_unknown_fields` is set — not verified against the crate;
   worth confirming as part of the upstream PR.
