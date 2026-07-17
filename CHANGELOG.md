# Changelog

All notable changes to **mcp-contract** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-18

First tagged release: completing the **Fleet API + standardized reporting**
phase. Runtime dependencies stay stdlib + `PyYAML`.

### Added

- `mcp-contract fleet infer|audit|verify|run` — batch inference/verification
  across a fleet; per-server policies plus one aggregate `FleetReport`.
  `fleet verify` is the fleet CI gate, returning the aggregate exit code with
  security-first precedence **2 > 1 > 4 > 0** (rug-pull outranks a plain
  violation; the operational `4` stays last so a broken pipeline never reads as
  clean). `--select K=V` slices the fleet by label; `--format {json,ndjson,sarif}`
  selects the aggregate report shape.
- `mcp_contract.fleet` library API: `Fleet`
  (`from_config` / `from_mcp_servers` / `from_manifests` / `select` /
  `infer_all` / `audit_all` / `verify_all` / `run_all`), `FleetServer`,
  `FleetServerReport`, and `FleetReport` with deterministic
  `to_dict` / `to_json` / `to_ndjson` (timestamps come from an injected
  `started_at`, never a wall-clock read inside serializers).
- `mcp_contract.report`: **SARIF 2.1.0** (`to_sarif` / `to_sarif_json`) for CI
  code-scanning and **ECS-aligned NDJSON** (`to_siem_json` / `to_siem_ndjson`)
  for SIEM, sharing one `violation_identity` (the SARIF
  `primaryLocationLineHash`, deliberately excluding `ts`/`manifest_hash` so one
  misbehavior stays one alert across runs and manifest edits). New
  `--sarif PATH` / `--siem PATH` on `audit` / `verify` / `run` (additive — the
  exit code is unchanged).
- policy-mcp conformance: `policy_to_policy_mcp_base`, `policy_hash`, and
  `policy_mcp_base_conforms` (schema pinned to `microsoft/policy-mcp`@`186e5812`);
  `infer --emit base` writes the strict policy-mcp/v1 projection; CIDR-vs-host
  and env-key `*` emit guards.

### Changed

- README status table **M5 → Shipped**; CLI reference gains the `fleet` group
  and the `--sarif` / `--siem` export flags; public-demo Part B is now driven by
  `fleet infer` rather than a hand-rolled shell loop.
- Doc fixes: policy-mcp resources shape (flat percent / MB / IOPS); Wassette
  reference v0.3.4 → v0.4.0.

### Unchanged / preserved

- The single-server exit-code contract (0 / 1 / 2 / 3 / 4) and its precedence,
  byte-for-byte.
- Frozen `models.py` / `ral/base.py`; runtime deps stdlib + `PyYAML`.

### Known limitations (ship honest)

- Network enforcement covers the proxy (well-behaved) path; a raw-IP bypass is
  **flagged, not blocked** — airtight blocking is deferred (M4).
- Backends `mock` + `docker` only; the gVisor adapter is deferred (M3).
- PIE is rule-based (manifest-only); static hints are deferred (0.2.0).
- The full `x-mcp-contract` policy is Wassette-runtime-valid but not schema-valid
  against the published `schema/v1.json` (root `additionalProperties: false`);
  use `--emit base` for a strict-schema document. The upstream Track-A PR closes
  this gap.

[0.1.0]: https://github.com/anthropics/mcp-contract/releases/tag/v0.1.0
