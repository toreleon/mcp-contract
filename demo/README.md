# mcp-contract end-to-end demo

Real MCP servers, a real MCP client (the official `mcp` SDK), **no LLM and no
docker**. mcp-contract observes the *server*, not the agent — so the LLM that
would normally choose which tools to call is replaced here by scripted
`tools/call` requests. The enforcement point is the egress proxy (the
dockerless path).

```
PYTHON=.venv/bin/python bash demo/run_demo.sh          # controlled: fetch + a malicious server
PYTHON=.venv/bin/python bash demo/run_public_demo.sh   # REAL public servers from npm/PyPI
```

## Public-server demo (`run_public_demo.sh`)

Runs mcp-contract against real, widely-used MCP servers pulled straight from the
public registries (needs `node`/`npx` + internet):

- **Part A** — the flagship `@modelcontextprotocol/server-filesystem` (npm, 14
  tools): inferred to filesystem-only, network/exec/env denied.
- **Part B** — a least-privilege table across six public servers (filesystem,
  fetch, memory, everything, sequential-thinking, time). Pure tools (memory,
  sequential, time) get **everything denied**; each server is pinned to exactly
  the capability classes its declared surface implies. The `memory` server
  actually persists a JSON file it never declares — so `fs.write` is denied and
  a real disk write would be flagged `outside_contract` at runtime.
- **Part C** — live hostname egress enforcement on the public fetch server
  against the **real** GitHub API: `api.github.com` allowed, `example.com` blocked.

Prereqs (demo-only, not framework dependencies):

```
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]' mcp mcp-server-fetch
```

Act 1 needs outbound internet (it fetches example.com). Act 2 is fully local.

## Act 1 — a real off-the-shelf server (`mcp-server-fetch`)

The official reference fetch server, put under hostname-level egress control.

1. **Capture** its real manifest with the MCP client (`tools/list`).
2. **Infer** a policy: PIE flags `net.http` **needs_review** (the URL is a
   runtime param, so it won't auto-grant *which* host) and **denies**
   filesystem/exec/env — deny-by-default.
3. **Approve** a narrow allowlist (`example.com` only) — the one human decision.
4. **Run** the server through the enforcing proxy: `example.com` is tunnelled
   (real 200), `www.iana.org` is **blocked** (403), and the server's own
   surprise attempt to reach `registry.npmjs.org` (it shells out to `npm` for
   HTML→markdown) is **blocked deny-by-default** — a real unexpected-egress catch.

## Act 2 — a malicious server (the core thesis)

`malicious_server.py` is a real `mcp` SDK server. Its manifest declares one
tool, `read_note`, described purely as reading a local file — nothing about the
network. Its *implementation* secretly ships the file it reads to an external
C2 host. This "declares X, does Y" gap is invisible to static manifest review.

1. **Infer**: PIE grants `fs.read ./notes`, **denies `net.http`** — the server's
   declared contract is filesystem-only.
2. **Baseline** (no mcp-contract): `read_note("secrets.txt")` returns the note
   *and* the attacker's C2 receives the stolen bytes. The caller sees nothing wrong.
3. **Enforced** (under mcp-contract): the same call — the note still returns
   (the implant hides its failure) but the C2 receives **zero bytes**; the proxy
   logs a denied `net.connect` to `drop.exfil.zone`.
4. **Verdict**: `mcp-contract verify` classifies that connection
   `outside_contract` (the manifest declared no network) and **exits 1** — the
   CI gate fails and the lying server is caught.

## Files

| File | What it is |
|---|---|
| `mcp_client.py` | Real MCP stdio client (SDK): `initialize` → `tools/list` / `tools/call`. No LLM. |
| `malicious_server.py` | Real MCP server that declares file-read, secretly exfiltrates. |
| `attacker_sink.py` | Stand-in C2 drop server; records stolen bytes. |
| `notes/secrets.txt` | The sensitive file the malicious server reads and leaks. |
| `run_demo.sh` | One-command runner for both acts. |
| `artifacts/` | Generated at runtime (manifests, policies, event logs); git-ignored. |

## What this demonstrates about the design

- **No LLM is in the trust boundary.** mcp-contract watches server behavior;
  the model only decides *which* tool to call.
- **Deny-by-default from the manifest.** A real server gets only what its
  declared surface implies, and network scope always needs human approval.
- **Behavior is the source of truth.** The malicious server's manifest is a
  lie; only observing real egress catches it — which is precisely what a static
  scanner cannot do.

## Residual limitation (honest)

A maximally-evasive server that ignores `HTTP_PROXY` and opens a raw socket to a
raw IP is not *blocked* on this dockerless path — it is *flagged*
`outside_contract` by the docker adapter's `/proc/net/tcp` poller (needs the
docker backend). Airtight blocking of raw sockets is the internal-network +
iptables follow-on.
