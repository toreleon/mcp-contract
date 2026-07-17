# Phase recommendation for a credible v0.1.0

Author: scoping lead · Date: 2026-07-18 · Status: decision doc (this file is mine alone)

> **Decision in one line:** ship **Phase (A) — Fleet API + standardized reporting
> (batch infer/verify + JSON / NDJSON / SARIF export)** as the sole headline of
> v0.1.0, fold in one cheap policy-mcp *conformance* rider from (D), and
> explicitly **defer (B) airtight egress, (C) gVisor, (E) static-hints, and the
> upstream (D) PR**. (A) is the only candidate that is simultaneously the
> product-defining surface, fully buildable-and-validatable in *this*
> docker-less / gVisor-less environment, and the phase most de-risked by the
> parallel reporting/fleet research.

Every claim below is tagged **[VERIFIED]** (read in this repo's source/tests/docs
this session) or **[INFERRED]** (reasoned judgement). The ranking rests on two
hard gates the task imposes — *coherence of a first release* and *validatability
here* — applied adversarially.

---

## 1. Where the code actually is today (baseline I'm scoping against)

Read this session, primary source (the repo itself):

- **PIE** — rule-based classifier (`pie/classifier.py`, 501 LoC), `infer_policy`
  aggregation, `LLMAssist` protocol defaulting to `NullLLM`. No static source
  analysis. [VERIFIED]
- **Policy I/O** — `policy-mcp`-compatible emit + `x-mcp-contract` extension,
  round-trip, `source_manifest_hash` binding. Foreign-policy import synthesizes
  `inferred` caps. [VERIFIED — `policy/io.py`, `docs/policy-mcp-notes.md`]
- **BCM** — three-bucket classification (`within_policy` /
  `within_manifest_not_policy` / `outside_contract`), `Monitor`, `ViolationReport`
  with `counts/severity/suggested_action/to_dict/to_json`. [VERIFIED — `bcm/*`,
  `models.py`]
- **RAL** — `mock` (replay) + `docker` (subprocess poller) adapters, `BackendCaps`
  matrix, `translate_policy_args` as a pure unit-testable function. [VERIFIED]
- **Egress proxy** — stdlib deny-by-default hostname enforcement, reuses BCM's
  `host_matches`; works on the **dockerless** path. [VERIFIED — `proxy/*`,
  `docs/DESIGN-egress-proxy.md`]
- **CLI** — `infer / run / audit / verify / proxy` with the exit-code contract
  (0 clean · 1 violation · 2 rug-pull · 3 drift-at-run · 4 bad-input/inconclusive).
  [VERIFIED — `cli.py`]
- **Demos** — controlled (fetch + a real malicious exfil server) and public (real
  npm/PyPI servers, incl. a hand-rolled **six-server least-privilege table**).
  [VERIFIED — `demo/README.md`]
- **Tests** — `215 passed, 2 skipped` (the 2 are docker-gated). [VERIFIED — ran
  `pytest` this session]
- **Version** — `pyproject` already declares `0.1.0`; **no git tags, no
  CHANGELOG.** So this phase *is* the cut of the first tagged release, not a bump
  from a prior one. [VERIFIED]

**What is conspicuously missing for a *product* story:** everything is
**single-server**. `run`/`audit`/`verify` each take one manifest, one policy, one
event stream, and emit one report to stderr + optional per-run JSON. There is no
batch surface, no fleet-level aggregate, and no export format a security team's
existing tooling (CI code-scanning, SIEM) actually ingests. SPEC §8.3 calls the
fleet/SDK surface "the surface that becomes a paid product"; the README status
table marks **M5 "Partial — per-run JSON only, no fleet API."** [VERIFIED]

**Environment facts that gate the ranking:** no `docker` daemon and no gVisor are
available here (the 2 skipped tests are exactly the docker-gated ones). The task
states validatability is a *hard constraint*: do not recommend building
security-critical code that cannot be exercised here. [VERIFIED — task + skip
behavior]

---

## 2. The two gates, applied to all five candidates

| Phase | Coherent headline for a *first* release? | Buildable **and validatable** here? | Verdict |
|---|---|---|---|
| **(A)** Fleet API + SIEM/SARIF export, batch | **Yes** — turns a single-server CLI into the fleet product SPEC §8.3 promises | **Yes** — pure Python over proven primitives (`infer_policy`, `classify_events`, `ViolationReport`); mock backend + fixtures exercise all of it | **SHIP as 0.1.0** |
| **(B)** Airtight egress (internal net + iptables) | No — it's *hardening* of one backend, not a release theme | **No** — the enforcement boundary can only be validated against a running docker daemon; unavailable here | **DEFER** |
| **(C)** gVisor adapter | Partial — proves runtime-agnostic, but that's already shown by 2 backends | **No** — `event_stream`/enforce paths need gVisor installed; would ship half-exercised | **DEFER** |
| **(D)** policy-mcp upstream PR | No — an external research/PR artifact, belongs to M3 | **Split** — the *conformance code* is validatable here; the *PR* cannot be merged from here | **Fold in the code slice; defer the PR** |
| **(E)** Static-hints analyzer | Partial — an *accuracy* theme, strong for 0.2.0 | **Yes** — pure source scan, fixture-testable | **DEFER to 0.2.0** |

The gates do most of the work: **(B) and (C) fail the hard validatability
constraint outright.** They are security-critical (B is the actual blocking
boundary; C is a sandbox backend) and can only be exercised with infrastructure
this environment lacks. Shipping an *unexercised* enforcement path in a **first**
release is the specific anti-pattern the task warns against — worse than a gap,
it is a false promise ("airtight blocking") that was never observed to block.
That is a credibility liability, not an asset. [INFERRED, high confidence]

---

## 3. Why (A) is the right headline (positive case)

1. **It is the product surface, not a feature.** SPEC §8.3 names the fleet/SDK
   layer as "the surface that becomes a paid product"; M5 is exactly
   "report/SIEM export + fleet API." A credible *first release* needs the breadth
   that the pitch (heterogeneous MCP fleets — the wedge Anthropic's managed
   sandbox explicitly does *not* serve, per `OPEN-QUESTIONS.md` Q1) already
   promises. More depth on one server does not make the pitch true; a fleet
   surface does. [VERIFIED — SPEC §8.3/§11, OPEN-QUESTIONS Q1]

2. **It is the lowest-risk large deliverable.** Batch is a thin
   orchestration + aggregation + serialization layer over primitives that are
   *already proven and tested*: `infer_policy`, `classify_events`,
   `ViolationReport`, the exit-code precedence. No new trust boundary, no new
   inference heuristic that could silently widen a grant. [INFERRED, high —
   grounded in the models/BCM I read]

3. **The demo already exists in prototype form.** Public-demo **Part B** is a
   hand-rolled shell loop that prints a six-server least-privilege table. (A)
   productizes that exact artifact into `mcp-contract fleet infer` + a real
   report object. The most persuasive 0.1.0 demo is one that already works and
   just needs to be spoken through the product surface. [VERIFIED — `demo/README.md`]

4. **Standardized export is what makes the CI gate *credible to buyers*.** The
   `verify` exit-code gate already exists, but a security team consumes findings
   through **SARIF** (drops straight into GitHub/GitLab code-scanning, where the
   CI-gate audience lives) and **NDJSON** (SIEM ingestion). Emitting those turns
   an exit code into an auditable artifact. This is inside (A) as the task frames
   it ("SIEM/SARIF export"). [INFERRED, high — SARIF 2.1.0 is the de-facto
   code-scanning interchange format]

5. **It is the phase the *parallel* research most de-risks.** The task notes
   earlier reporting/policy-mcp/fleet research. Those reduce build risk for (A)
   specifically — SARIF result shape, SIEM field expectations, fleet-report
   ergonomics — whereas (B)/(C) are blocked by *environment* (docker/gVisor) that
   no amount of research removes here. Spend the de-risking where it converts to
   shippable code. [INFERRED]

6. **No new dependencies.** SARIF and NDJSON are just `json`; the repo stays
   stdlib + PyYAML (a stated style rule). A first release with a clean dep
   surface is more credible. [VERIFIED — `pyproject` deps = `PyYAML>=6.0`]

### Should (A) be combined with anything?

- **Fold in a small (D) *conformance* rider — yes.** Because (A)'s export claims
  the policies are "policy-mcp compatible," 0.1.0 should *pin the real
  `microsoft/policy-mcp` schema by commit hash* (it has no releases —
  `OPEN-QUESTIONS.md` Q4) and add a lightweight self-check that emitted policies
  structurally conform. Cheap, validatable, and it makes the compatibility claim
  honest. The **upstream PR itself is deferred** (external artifact, M3, needs a
  live upstream; draft it, don't gate the release on it). [VERIFIED — Q4 + notes]
- **Do NOT fold in (E).** It is a *net-new inference subsystem* whose whole job is
  to promote `needs_review → inferred` — i.e., to **auto-widen grants**, the exact
  opposite of PIE's fail-closed stance (§4.5, the VIPER-MCP false-positive lesson).
  It needs a labeled corpus to tune precision before it can be trusted, and it
  dilutes a 0.1.0 whose story is "productize the proven loop." It is the right
  *0.2.0* headline — and the fleet corpus (A) produces is exactly the evaluation
  set (E) needs. Sequencing (A) → (E) is deliberate, not accidental.
  [INFERRED, high — grounded in SPEC §4.4/§4.5]

---

## 4. Acceptance checklist for v0.1.0 (crisp, all validatable *here*)

Every item below is exercisable with fixtures + the mock backend — no docker, no
gVisor, no network. "Green" = a pytest asserts it.

**Fleet batch surface (new `fleet` subcommand group + library types)**

- [ ] **A1.** `mcp-contract fleet infer <dir|glob> [-o OUTDIR] [--report FILE]
      [--format json|ndjson|sarif]` infers one policy per manifest, writes each
      policy, and emits **one** aggregate `FleetReport`. *Test:* point at
      `tests/fixtures/manifests/` (6 servers) → 6 policy files + a report whose
      rows carry `server_id`, `manifest_hash`, per-class status counts, and a
      `needs_review` tally matching the known fixtures. Exit 0.
- [ ] **A2.** `mcp-contract fleet verify <config>` (batch of
      `(manifest, policy, events)` triples) aggregates `ViolationReport`s into a
      `FleetReport` and returns the **worst** per-server exit code under the
      existing precedence **2 (rug-pull) > 1 (violation) > 4 (bad-input/empty) >
      0 (clean)**. *Test:* mixed clean+exfil fixtures → aggregate severity
      `critical`, exit 1; one tampered manifest in the set → exit 2; one
      missing/corrupt input → exit 4; no collision between codes.
- [ ] **A3.** `FleetReport` is a library-importable dataclass
      (`server summaries + totals + generated_at + tool_version`) with a
      deterministic `to_dict`/`to_json` (sorted keys), mirroring
      `ViolationReport` ergonomics. *Test:* byte-stable output for identical
      input.

**Standardized export (new, shared by fleet *and* single-server `audit`)**

- [ ] **A4.** `--format json` emits the report dict; `--format ndjson` emits one
      finding per line (SIEM-ingestable); `--format sarif` emits valid **SARIF
      2.1.0** — one `run`, `tool.driver.name = "mcp-contract"`, a `rule` per
      `EventClass`, one `result` per flagged event with
      `level = error` (`outside_contract`) / `warning`
      (`within_manifest_not_policy`), `ruleId`, message, and properties
      (`server_id`, `tool_ctx`, host/path). *Test:* output parses as JSON;
      structural SARIF checks (`version == "2.1.0"`, `$schema` present,
      `runs[0].results[].level` mapping correct); export format never changes the
      exit code.
- [ ] **A5.** Exports are deterministic and diff-clean in CI (stable ordering).

**policy-mcp conformance rider (the folded-in (D) slice)**

- [ ] **A6.** The real `microsoft/policy-mcp` schema is pinned by commit hash in
      `docs/policy-mcp-notes.md`, and a test asserts every emitted policy's base
      `permissions` block structurally conforms (network/storage/environment
      shapes) — the "policy-mcp compatible" claim is now checked, not asserted.

**Docs / demo / release hygiene**

- [ ] **A7.** Public-demo **Part B** (six-server table) is regenerated **by
      `fleet infer`** instead of the hand-rolled shell loop. *Test:* a pytest runs
      `fleet infer` over the fixture manifests and matches the documented table.
- [ ] **A8.** README status table flips **M5 → "Shipped"** (batch infer/verify +
      JSON/NDJSON/SARIF); CLI table gains the `fleet` rows; library-usage snippet
      gains `FleetReport`.
- [ ] **A9.** `CHANGELOG.md` created with a `0.1.0` entry (see §6); a `v0.1.0`
      git tag is cut once the suite is green.
- [ ] **A10.** Full suite green (`pytest`), new fleet+export tests included; deps
      unchanged (stdlib + PyYAML); the 2 docker tests remain skip-gated.

---

## 5. Explicit DEFER list (with why)

| Deferred | Target | Why it is not 0.1.0 |
|---|---|---|
| **(B) Airtight egress — internal docker network + iptables** | 0.2.0 / M4-hardening | **Fails the hard validatability gate.** The blocking boundary can only be exercised against a running docker daemon (absent here). Shipping unexercised *enforcement* in a first release is a false "airtight" promise. The current honest posture — proxy enforces the well-behaved path, raw-IP bypass is **flagged, not blocked**, and documented as such (`demo/README.md`, README §Backend gaps) — is defensible and already shipped. Keep it honest. |
| **(C) gVisor adapter** | 0.2.0 / M3 | **Fails validatability.** `event_stream` + enforce need gVisor installed; a third backend would ship half-exercised. Runtime-agnosticism is **already demonstrated** by two working backends implementing the RAL Protocol (mock + docker) — the abstraction is proven; a third *unexercisable* one adds claim-surface without validation. |
| **(E) Static-hints analyzer** | **0.2.0 headline** | Validatable, but it is a correctness-sensitive new subsystem that **auto-widens grants** (`needs_review → inferred`), against PIE's fail-closed design (§4.5). Needs a labeled corpus to tune precision — which (A)'s fleet output supplies. Right *next* theme; wrong to bundle into a "productize the loop" release. |
| **(D) upstream policy-mcp PR** (the `status`/`evidence`/`hash` proposal + submission) | M3 | External artifact that cannot be merged from here; depends on a live, unfrozen upstream. **Draft** the proposal from `docs/policy-mcp-notes.md` gap list; do not gate the release on it. The *conformance code* slice is folded into 0.1.0 (A6). |

---

## 6. Version bump + CHANGELOG items

`pyproject` is already at `0.1.0` and there are no tags/CHANGELOG — so completing
Phase (A) *is* the first release cut, not a bump. Keep the number at **`0.1.0`**;
add the release scaffolding.

**Create `CHANGELOG.md`** (Keep-a-Changelog style), `## [0.1.0] — 2026-…`:

- **Added**
  - `mcp-contract fleet infer` — batch least-privilege inference across a
    directory/glob of manifests; per-server policies + one aggregate `FleetReport`.
  - `mcp-contract fleet verify` — batch contract verification; aggregate exit
    code under the existing 2 > 1 > 4 > 0 precedence.
  - `FleetReport` library type (deterministic `to_dict`/`to_json`).
  - Standardized reporting: `--format {json,ndjson,sarif}` on fleet reports and
    single-server `audit`; **SARIF 2.1.0** for CI code-scanning, **NDJSON** for
    SIEM ingestion.
  - policy-mcp schema pinned by commit hash + a conformance self-check on emitted
    policies.
- **Changed**
  - README status table: **M5 → Shipped**; CLI reference gains the `fleet`
    command group; public-demo Part B now driven by `fleet infer`.
- **Unchanged / preserved (call out for credibility)**
  - Single-server exit-code contract (0/1/2/3/4) and its precedence.
  - Runtime deps: stdlib + `PyYAML` only.
- **Known limitations (ship honest, per SPEC §13)**
  - Network enforcement covers the proxy (well-behaved) path; raw-IP bypass is
    **flagged, not blocked** (airtight blocking = deferred M4).
  - Backends: `mock` + `docker` only; gVisor deferred (M3).
  - PIE is rule-based (manifest-only); static hints deferred (0.2.0).

**Tag** `v0.1.0` once §4 is green.

---

## 7. Adversarial caveats on my own recommendation

- **"Fleet is just a for-loop"** — partly true, and that is the *point*: low risk
  is a feature for a first release. The non-trivial parts are the **exit-code
  aggregation precedence** (get 2 > 1 > 4 > 0 wrong and the CI gate lies) and
  **SARIF structural validity** (a malformed `run` is silently dropped by code-
  scanning UIs). Both are covered by A2/A4 and both are fully testable here.
- **"SARIF may need a real code-scanning UI to validate"** — I only claim
  *structural* validity (schema-shape + level mapping), which is asserted in-repo
  without external services. True end-to-end rendering in GitHub is a
  post-release nicety, not a 0.1.0 gate. [INFERRED]
- **"Deferring (B) leaves a security hole in a security tool"** — the hole is
  already **disclosed** (flagged-not-blocked is in the README and demo). A first
  release that is honest about a documented boundary beats one that ships an
  unvalidated blocking claim. This is consistent with SPEC §13's own caveat
  posture.
- **Negative-claim caution** — "no product closes the infer→observe→diff→enforce
  loop" (from `OPEN-QUESTIONS.md`) is a fast-moving, secondary-sourced claim;
  0.1.0 should not lean its marketing on it beyond what that doc already hedges.

---

## Sources (this session, primary = the repo)

- `SPEC.md` §4.2/§4.4/§4.5 (PIE + static hints), §7 (policy-mcp extension), §8.3
  (fleet/SDK product surface), §11 (M1–M6), §13 (caveat posture). [VERIFIED]
- `DESIGN.md` (module boundaries, exit-code contract, backend matrix). [VERIFIED]
- `docs/OPEN-QUESTIONS.md` Q1 (Anthropic sandbox = manual egress, fleet wedge
  intact), Q4 (`microsoft/policy-mcp` v1.0, no releases → pin a commit).
  [VERIFIED]
- `docs/policy-mcp-notes.md` (real schema shape + the upstream-PR gap list).
  [VERIFIED]
- `docs/DESIGN-egress-proxy.md`, `README.md` status table + backend gaps,
  `demo/README.md` (the six-server table that (A) productizes). [VERIFIED]
- `src/mcp_contract/models.py`, `cli.py`, `bcm/*`, `pie/*`, `ral/*`, `proxy/*`
  (current surface). [VERIFIED]
- `pytest` run this session: `215 passed, 2 skipped`. [VERIFIED]

Upstream references worth pinning during A6 (from the research docs, not
re-fetched this session): `https://github.com/microsoft/policy-mcp`,
`https://github.com/microsoft/wassette/releases/tag/v0.3.4`,
SARIF 2.1.0 OASIS spec (`https://docs.oasis-open.org/sarif/sarif/v2.1.0/`).
