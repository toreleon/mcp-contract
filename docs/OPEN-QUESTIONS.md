# SPEC §12 Open Questions — Landscape Verification (July 2026)

Research date: 2026-07-17. Method: web search + primary-source fetch (vendor docs,
GitHub repos, arXiv). Every claim below is tagged **[VERIFIED]** (read in a primary
source) or **[INFERRED]** (reasoned from secondary sources or absence of evidence).
Negative claims ("nobody has shipped X") are inherently weaker than positive ones
and are tagged accordingly.

## TL;DR scorecard

| §12 question | Verdict | Confidence |
|---|---|---|
| Q1: Anthropic sandbox auto-generates egress policy? | **No — manual, customer/provider-owned.** Anthropic explicitly disclaims per-tool isolation inside the sandbox. | High |
| Q2: Consistency-check wired into runtime enforcement? | **Not shipped as a combined loop — but both halves now exist separately in fresh academic work (AgentBound, SandScope). Gap is real but closing.** | Medium-high |
| Q3: eBPF vs egress-proxy for M2 | **Proxy-first; eBPF as Linux-only enrichment later.** | High (platform facts verified) |
| Q4: policy-mcp schema exists as assumed? | **Yes, and better than assumed: standalone repo `microsoft/policy-mcp`, spec v1.0. Covers fs/network/env/docker-runtime. No syscall caps, no status/evidence fields.** | High |

**One-line takeaway:** the SPEC's core wedge — *manifest-as-contract: infer policy
from the manifest, observe real behavior, diff against what was declared, enforce
the diff* — is still unoccupied. But AgentBound (FSE 2026) has shipped the
"infer→enforce" half as an academic artifact, and SandScope has shipped the
"observe→compare-with-declared" half as an audit tool. The window for claiming the
combined loop is open, and shrinking.

---

## Q1. Does Anthropic's self-hosted sandbox / MCP tunnels auto-generate egress policy per MCP server?

**Answer: No. Egress/network policy is manual and customer- or provider-owned.
There is no per-MCP-server policy inference anywhere in the offering.**

Facts, from primary sources:

- The offering ("Claude Managed Agents: self-hosted sandboxes and MCP tunnels")
  was announced **May 19, 2026**. Orchestration stays on Anthropic's side; tool
  execution moves into customer infrastructure. [VERIFIED — claude.com blog]
- The official **security model doc** (shared-responsibility page) puts network
  egress squarely on the customer: *"Network egress controls. Your sandbox's
  network access is determined by your VPC and firewall rules. Without egress
  restrictions, a compromised tool execution can reach arbitrary external hosts.
  Restrict outbound traffic to only the endpoints your tools require."*
  [VERIFIED — platform.claude.com docs]
- For Anthropic-hosted cloud environments, the `networking` field takes a manual,
  static `allowed_hosts` list (bare hostnames or wildcards). Docs *recommend* the
  customer route traffic through their own egress proxy for allowlisting,
  credential injection, and logging. No generation step. [VERIFIED — platform docs]
- MCP tunnels are a connectivity feature (outbound-only gateway to private MCP
  servers, no inbound firewall rules), not a policy feature. The operator manually
  points the gateway at an internal URL. [VERIFIED — blog + setup guides]
- Sandbox providers (Cloudflare, Daytona, Modal, Vercel) each bring their own
  egress controls (e.g. Cloudflare's "customizable proxies to audit, reroute, or
  modify egress") — configured by the operator, varying per provider.
  [VERIFIED — blog; provider-level detail INFERRED from secondary writeups]

**The strongest finding for this project** — Anthropic states, verbatim, in "What
Anthropic cannot do for you":

> *"Isolate tools inside your sandbox. Anthropic's security boundary stops at the
> sandbox. How you isolate individual tool executions from each other inside that
> boundary is entirely your responsibility."*

That is a primary-source confirmation that per-tool/per-server least-privilege —
exactly what PIE+BCM does — is explicitly **out of scope** for Anthropic's managed
offering, not merely unaddressed. The SPEC's positioning ("avoid head-on collision;
serve the heterogeneous fleet") holds, and is arguably stronger than the SPEC
assumed: mcp-contract is complementary *even inside* Anthropic's own perimeter
story, not only outside it.

Adversarial caveats: (a) absence of a feature in docs as of 2026-07-17 does not
prove Anthropic isn't building it — policy inference is an obvious roadmap item
for them; (b) some third-party writeups loosely say "sandboxes include network
egress control", which could be misread as auto-policy — the primary docs show it
means "egress is controllable *by you*".

Sources:
- https://claude.com/blog/claude-managed-agents-updates
- https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes-security
- https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes
- https://platform.claude.com/docs/en/managed-agents/environments
- https://dev.to/akaranjkar08/claude-managed-agents-self-hosted-sandboxes-and-mcp-tunnels-setup-guide-4ha4
- https://thenewstack.io/anthropic-mcp-tunnels-sandboxes/

---

## Q2. Has anyone connected manifest/description-vs-behavior consistency checking to RUNTIME enforcement?

**Answer: No shipped system closes the full loop (declaration → inferred policy →
runtime behavior diff → enforcement). But the loop's components now each exist,
and two academic systems come close from opposite directions.** The SPEC §0 claim
"no top runtime auto-generates policy" needs revision: it's still true of
*products*, no longer true of *research artifacts*.

### The two near-misses (most important findings)

**AgentBound** (Bühler, Biagiola, Di Grazia, Salvaneschi — Univ. of St. Gallen;
arXiv 2510.21236, v3 Apr 2026, accepted FSE 2026, ACM DOI 10.1145/3808103):
- First access-control framework for MCP servers: declarative manifest (Android-
  permission-style vocabulary) + enforcement engine ("AgentBox"). [VERIFIED — abstract + full text]
- **Auto-generates policies** with a two-stage LLM pipeline (gpt-4-mini manifest
  creators × 5 runs → gpt-4 consolidator) reading the server's **source code**.
  80.9% of generated manifests correct without modification, on 296 popular MCP
  servers; developers confirmed the vocabulary covers 100% of needed permissions.
  [VERIFIED — full text]
- **Enforces at runtime** via Docker: fs mounts (ro/rw scoping), network via
  iptables rules resolving allowed hostnames to IP allowlists, env-var
  whitelisting. [VERIFIED — full text]
- **Does NOT do drift/consistency detection**: no comparison of observed behavior
  vs tool descriptions, no observe mode, no violation taxonomy. Enforce-only.
  [VERIFIED — full text states no such component]
- Admitted limits: over/under-approximation in generation; all-or-nothing device
  access; attacks that never touch OS resources (tool poisoning / prompt
  injection at the LLM layer) bypass it entirely; Docker-only.
- Artifact released on Zenodo (DOI 10.5281/zenodo.19571298); research prototype,
  not a product. [VERIFIED]

**SandScope / "MCP-SandboxScan"** (Tan et al., arXiv 2601.01241, Jan 2026, rev.
June 2026):
- Executes MCP tools in controlled environments (WASI for portable tools, stdio
  for unmodified servers), observes runtime behavior, and **compares observed
  capabilities against declared capabilities from `tools/list` metadata** —
  producing "source-to-sink witnesses" as auditable evidence. [VERIFIED — abstract]
- This IS declaration-vs-behavior consistency checking at runtime — but it is
  **analysis/audit only**. No enforcement, no blocking, not a persistent monitor.
  [VERIFIED — abstract]

So: AgentBound = infer + enforce, no diff. SandScope = observe + diff, no enforce.
**Nobody = infer + observe + diff + enforce.** That combination — plus the
three-way classification (within-policy / within-manifest-not-policy /
outside-contract) and treating the manifest as the per-server contract — remains
the SPEC's defensible novelty. [INFERRED — negative claim; survey below]

### Everyone else, by category

**Static-only consistency checkers** (confirm the SPEC's "already crowded" call):
- **DCIChecker** (arXiv 2606.04769, June 2026): description-code inconsistency at
  scale — 19,200 pairs / 2,214 servers, 9.93% inconsistent. Static + LLM
  cross-validation ("Direct-Reverse-Arbitration"); detection only. [VERIFIED — abstract]
- **"Don't believe everything you read"** (arXiv 2602.03580, Feb 2026): ~13% of
  10,240 servers show substantial description/behavior mismatch enabling
  undocumented privileged operations; static semantic consistency analysis,
  pre-deployment. [VERIFIED — abstract]
- **Cisco MCP Scanner** (open source, cisco-ai-defense/mcp-scanner): YARA +
  LLM-as-judge + AI Defense API; pre-deployment scanning. [VERIFIED — repo/blog]

**Runtime enforcement at the MCP-message layer, without manifest-consistency:**
- **Invariant Labs mcp-scan proxy** (now under Snyk): dynamic proxy injecting an
  Invariant Gateway into MCP configs; real-time guardrails (PII, secrets, tool
  restrictions, custom policies) on tool-call traffic. Also tool pinning /
  rug-pull hash detection. Operates on MCP messages, not system behavior
  (network/fs/syscall), and doesn't diff behavior vs manifest. [VERIFIED — docs]
- **Toxic Flow Analysis** (Invariant/Snyk Labs): hybrid static (config, toolsets)
  + runtime data building a flow graph, scoring dangerous tool *sequences*
  (untrusted input → sensitive data → exfil sink). Closest *conceptual* neighbor
  on the "static+dynamic hybrid" axis, but it scores flow risk; it does not treat
  the manifest as an enforceable contract. [VERIFIED — Snyk Labs writeup]
- **Snyk Evo / Agent Guard** (announced Jun 23, 2026; private preview): "enforces
  policies in real time, monitoring agent behavior and blocking unsafe actions."
  Marketing-level detail only; no evidence of manifest-vs-behavior consistency or
  syscall-level enforcement. Watch it. [VERIFIED announcement; capability scope INFERRED]
- **Cisco AI Defense runtime**: commercial MCP gateway intercepting agent↔server
  calls (tool misuse, privilege escalation, deceptive behavior detections).
  Message-layer, closed-source; no manifest-contract diffing evidenced.
  [VERIFIED existence; scope INFERRED from datasheet language]
- **Docker MCP Gateway / Toolkit**: containerized servers with restricted
  privileges/network/resources + pluggable interceptors (secrets blocking, call
  logging, signature checks). Static hand-set restrictions; no inference from
  manifest, no behavior-vs-manifest diff. [VERIFIED — docs/blog/repo]
- **eqtylab/mcp-guardian**: proxy with real-time human approval per tool call;
  manual, message-layer. [VERIFIED — repo]
- **LlamaFirewall** (Meta): PromptGuard/AlignmentCheck/CodeShield — alignment and
  prompt-layer guardrails, not system-behavior-vs-manifest. [VERIFIED — docs/paper]

**Syscall-level runtime enforcement, hand-written policy (no inference, no diff):**
- **MCPGuard** (github.com/facebook/mcpguard-dynamic): transparent proxy treating
  MCP servers as untrusted; per-server capability policy + argument validation +
  BPF LSM programs (file/net/proc/fork guards) at the syscall boundary. Policies
  are **hand-written JSON** (defaults + overrides); no manifest inference; no
  description-vs-behavior comparison. Linux 6.x + CONFIG_BPF_LSM only; research
  artifact for an unpublished paper, 5 commits, MIT. Proves BPF-LSM enforce-mode
  viability (relevant to §12 Q5 / BackendCaps), and its existence under a
  Meta-affiliated org means big players are circling this layer. [VERIFIED — repo]
- Adjacent eBPF agent-sandboxing projects on the awesome-agent-runtime-security
  list: AgentSentinel, AgentSight, ActPlane, membrane, agentsh, syva, Prempti
  (Falco-rules for tool calls), SentinelGate (CEL/RBAC userspace firewall),
  brood-box (libkrun µVM + Cedar authz). None compare declarations to behavior;
  none infer policy. The curator's list has **no entries** in either category.
  [VERIFIED — list contents as of July 2026]

**Wassette** (Microsoft, the SPEC's reference point): still a manual per-grant
model — "tools must declare capabilities, users or host systems must explicitly
grant them"; deny-by-default. No inference step has appeared through v0.3.4.
[VERIFIED — docs + release notes]

Adversarial caveats: (a) this is a negative claim over a fast-moving space —
MCPGuard's unpublished paper could add consistency checking; Snyk Agent Guard is
in private preview and opaque; (b) commercial closed-source products (Cisco AI
Defense, Akto, etc.) could do more than their marketing says, though vendors
usually overclaim rather than underclaim; (c) I did not find, but cannot rule
out, unlisted internal tools at hyperscalers.

Sources:
- https://arxiv.org/abs/2510.21236 (+ https://arxiv.org/html/2510.21236v1, https://dl.acm.org/doi/10.1145/3808103, https://zenodo.org/records/19571298)
- https://arxiv.org/abs/2601.01241
- https://arxiv.org/abs/2606.04769 · https://arxiv.org/abs/2602.03580
- https://invariantlabs-ai.github.io/docs/mcp-scan/ · https://explorer.invariantlabs.ai/docs/mcp-scan/guardrails/
- https://labs.snyk.io/resources/toxic-flow-analysis/ · https://snyk.io/blog/introducing-agent-security/
- https://github.com/facebook/mcpguard-dynamic
- https://github.com/bureado/awesome-agent-runtime-security
- https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/ · https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/
- https://github.com/eqtylab/mcp-guardian
- https://meta-llama.github.io/PurpleLlama/LlamaFirewall/
- https://blogs.cisco.com/ai/securing-the-ai-agent-supply-chain-with-ciscos-open-source-mcp-scanner · https://www.cisco.com/c/en/us/products/collateral/security/ai-defense/ai-defense-ds.html
- https://microsoft.github.io/wassette/latest/concepts.html

---

## Q3. eBPF vs egress-proxy for per-container network observation (M2 recommendation)

**Recommendation: proxy-first for M2; eBPF as an optional Linux-only enrichment
adapter at M3+.** On Linux with plain Docker (runc), eBPF gives the richest
signal — cgroup-scoped, per-process `connect()`/DNS attribution with no traffic
redirection — but it demands a modern kernel (BPF LSM for enforce mode needs
`CONFIG_BPF_LSM=y`, cf. MCPGuard's Linux 6.x requirement), a privileged agent, and
per-kernel fragility. On **gVisor** host-side eBPF largely observes the Sentry,
not the application: gVisor runs its own userspace netstack, so app-level socket
semantics are invisible to host tracing; the right integration there is gVisor's
native trace points (`runsc` seccheck) consumed via the RAL, not eBPF [INFERRED —
gVisor architecture; verify at implementation]. On **macOS dev machines** — the
decisive constraint — eBPF does not exist on the macOS host at all (Linux-only),
and Docker Desktop runs containers inside a LinuxKit VM under Virtualization.framework;
loading eBPF means privileged containers against the VM's kernel, which is
version-dependent and fragile, and community writeups confirm host-level detail is
simply not exposed [VERIFIED — petermalmgren.com, hemslo.io, blog.pocok.dev]. An
egress proxy (default-deny + allowlist + log, per-server proxy container or
transparent redirect) behaves **identically** on Linux CI, macOS dev, Docker,
and gVisor, gives host/SNI-level allow/deny — the granularity `policy-mcp`'s
network permissions actually express — and is the only enforce-capable option that
works everywhere M2 targets. It costs you: no syscall visibility, blind to
non-proxied protocols unless you also default-deny at the network level (do both:
proxy + `iptables`/Docker network with only-proxy egress, the same pattern
AgentBound validated). BCM's event model should treat eBPF as an *additional
event source* behind the RAL, never the foundation.

Sources:
- https://petermalmgren.com/docker-mac-bpf-perf/
- https://hemslo.io/run-ebpf-programs-in-docker-using-docker-bpf/
- https://blog.pocok.dev/articles/ebpf-containers
- https://github.com/facebook/mcpguard-dynamic (kernel requirements)
- https://arxiv.org/html/2510.21236v1 (iptables + hostname-resolution enforcement pattern)

---

## Q4. Does the `policy-mcp` schema exist as SPEC assumes, and what does it cover?

**Answer: Yes — and it's more real than the SPEC assumed. It is now a standalone
spec repo, `github.com/microsoft/policy-mcp`, spec version "1.0", not just a field
inside Wassette.**

- **Wassette v0.3.4** added a `$schema` field to all policy YAML files
  "referencing the policy-mcp schema for better IDE support and validation
  (#331)", and stated the policy crate "is now ready to be published as a
  standalone library for other projects like policy-mcp (#427)". [VERIFIED — release notes]
- **`microsoft/policy-mcp`** defines a YAML policy spec (version "1.0") with four
  permission families [VERIFIED — repo README]:
  - `storage`: fs URIs with glob patterns (`fs://work/agent/**`) + `access: [read, write]`
  - `network`: allowed hosts, **host patterns, and CIDR blocks**, plus a
    `defaults` keyword bundling common destinations (package registries, cloud
    services, AI/ML APIs)
  - `environment`: env-var allowlist
  - `docker` runtime: privilege level and **Linux capabilities** config
- Status: MIT, 37 commits, **no releases published** — young and unfrozen, which
  is exactly the right moment for the §7 upstream contribution. [VERIFIED]
- Wassette's own docs confirm deny-by-default and note resource limits
  (memory/CPU/time) are "future versions". [VERIFIED — concepts page]

**Coverage vs the SPEC's needs (what `x-mcp-contract` must still add):**

| SPEC capability | policy-mcp v1.0? |
|---|---|
| `net.http(host)` egress | ✅ hosts + patterns + CIDR (+ risky `defaults` bundles) |
| `fs.read/write(path)` | ✅ URI globs + access modes |
| `env(var)` | ✅ allowlist |
| Syscall groups / seccomp | ❌ (nearest: Docker Linux-capabilities config — coarse) |
| `proc.exec` as first-class cap | ❌ |
| Resource limits | ❌ (declared future work by Wassette) |
| `status` (inferred/needs_review/denied) | ❌ — ours to add |
| `evidence`, `source_manifest_hash`, `behavior_expectations` | ❌ — ours to add |

Adversarial caveats: read via rendered README summaries, not a clone — before M1,
clone the repo and pin the exact JSON-schema revision (no releases means the
schema can move under you; pin a commit hash). Also note the `defaults` network
bundles are philosophically opposed to least-privilege inference — PIE should
never emit them, and the diff between "policy uses defaults" vs "policy lists
inferred hosts" is itself a nice demo of PIE's value.

Sources:
- https://github.com/microsoft/policy-mcp
- https://github.com/microsoft/wassette/releases/tag/v0.3.4
- https://microsoft.github.io/wassette/latest/concepts.html

---

## What this means for the roadmap

1. **The wedge survives — sharpen the pitch with Anthropic's own words.** Quote
   the security-model line ("Anthropic's security boundary stops at the sandbox…
   entirely your responsibility") in the README/pitch: mcp-contract is the layer
   Anthropic tells customers to build themselves. Position as complementary to
   managed sandboxes, not only for heterogeneous fleets.
2. **Rewrite SPEC §0 claim 1.** "No runtime auto-generates policy" is stale.
   Accurate version: *no product* infers policy, and *no system anywhere* closes
   the manifest→infer→observe→diff→enforce loop. Cite AgentBound and SandScope as
   the two half-loops. Novelty now rests on (a) manifest-first inference (no
   source required — AgentBound needs source code), (b) the BCM three-way diff
   with the manifest as contract, (c) runtime-agnostic RAL, (d) CI/fleet
   productization. Move fast: FSE 2026 publication + Zenodo artifact means
   followers have a recipe.
3. **Steal AgentBound's validated pieces instead of re-deriving them:** the
   permission vocabulary (developer-confirmed 100% coverage), the multi-run
   LLM-generate + consolidate pattern for PIE's LLM-assist, and the
   iptables-hostname-resolution enforcement trick for the Docker adapter. Its
   80.9% correct-manifest rate is the number PIE must beat (or beat on
   *cheaper input* — manifest-only vs full source) — make the week-1 wedge demo
   report this comparison explicitly.
4. **M2 architecture decided:** egress-proxy + default-deny network as the
   reference observation/enforcement path (works on macOS dev, Linux CI, Docker,
   gVisor); eBPF demoted to optional Linux-only adapter at M3+, gVisor via native
   trace points. BackendCaps (§12 Q5) gains hard data: BPF-LSM enforce is proven
   (MCPGuard, Linux 6.x) but hand-written; Docker boot-time network enforce is
   proven (AgentBound).
5. **§7 contribution path confirmed and urgent:** policy-mcp v1.0 exists, is
   active, and has no releases — propose `status`/`evidence`/`manifest_hash`
   upstream now, while the schema is young; pin a commit hash until releases
   exist. `x-mcp-contract` must carry syscall/proc.exec/resource caps, which
   policy-mcp lacks.
6. **New watch-list for the competitive brief:** Snyk Evo Agent Guard (private
   preview, runtime enforcement — opaque), MCPGuard's unpublished paper (could add
   consistency checking; Meta-affiliated org), Cisco AI Defense runtime gateway,
   and any move by Anthropic to add egress inference to managed sandboxes (the
   docs' manual `allowed_hosts` is an obvious thing for them to automate).
