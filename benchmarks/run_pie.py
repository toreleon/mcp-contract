#!/usr/bin/env python3
"""Phase-3 static benchmark: PIE coverage + a tool-poisoning tripwire.

Two parts, both offline and deterministic:

  Part A — PIE coverage on REAL public MCP servers. Runs the shipped policy
    inference over the real manifests vendored in demo/artifacts/pub_*.json
    (filesystem, fetch, memory, time, sequential-thinking, everything) and
    reports the inferred least-privilege surface and the needs_review rate.

  Part B — Tool-poisoning tripwire on MCPTox. For each poisoned tool, infer a
    policy from (a) the bare tool NAME only and (b) the name PLUS the poisoned
    description. Any capability class the description ADDS is a capability the
    poisoning injected into an otherwise innocuous-looking tool — the tripwire
    fires. Reports the fire rate and a breakdown by capability and paradigm.

    Data source, in order of preference:
      benchmarks/data/mcptox_pure_tool.json   (real corpus; run fetch_mcptox.sh)
      benchmarks/poison_samples.jsonl          (committed synthetic fallback)

The tripwire is a STATIC complement to the runtime monitor: it flags a poisoned
description before the server ever runs. It is honest about its reach — a
payload that abuses only already-declared tools (e.g. write_file to ~/.ssh on a
filesystem server) injects no new capability CLASS and is left to the runtime
arm (BCM scope check) instead. See the README.

    python benchmarks/run_pie.py
"""
from __future__ import annotations

import collections
import json
from pathlib import Path

from mcp_contract.manifest import load_manifest
from mcp_contract.models import CapabilityStatus, Manifest, ToolIR
from mcp_contract.pie.inference import infer_policy

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent

REAL_MANIFESTS = {
    "filesystem": "demo/artifacts/pub_filesystem.json",
    "fetch": "demo/artifacts/pub_fetch.json",
    "memory": "demo/artifacts/pub_memory.json",
    "time": "demo/artifacts/pub_time.json",
    "sequential": "demo/artifacts/pub_sequential.json",
    "everything": "demo/artifacts/pub_everything.json",
}


def _active(policy) -> dict[str, str]:
    """capability id -> status, excluding denied."""
    return {
        c.id.value: c.status.value
        for c in policy.caps
        if c.status is not CapabilityStatus.DENIED
    }


def part_a() -> None:
    print("=" * 68)
    print("Part A — PIE coverage on real public MCP servers")
    print("=" * 68)
    total_tools = review = granted = 0
    w = max(len(k) for k in REAL_MANIFESTS)
    print(f"{'server':<{w}}  tools  inferred / needs_review")
    print("-" * (w + 40))
    for name, rel in REAL_MANIFESTS.items():
        path = REPO / rel
        if not path.exists():
            print(f"{name:<{w}}  (missing {rel})")
            continue
        manifest = load_manifest(str(path))
        policy = infer_policy(manifest)
        active = _active(policy)
        inferred = [c for c, s in active.items() if s == "inferred"]
        needs = [c for c, s in active.items() if s == "needs_review"]
        total_tools += len(manifest.tools)
        review += len(needs)
        granted += len(inferred)
        cell = ", ".join(f"{c}={s}" for c, s in sorted(active.items())) or "(none)"
        print(f"{name:<{w}}  {len(manifest.tools):>5}  {cell}")
    print("-" * (w + 40))
    print(f"{len(REAL_MANIFESTS)} servers, {total_tools} real tools; "
          f"{granted} caps inferred, {review} need review (human gate).")


def _caps(name: str, desc: str) -> set[str]:
    m = Manifest(server_name="probe", tools=[ToolIR(name=name, description=desc, input_schema={})])
    return {c.id.value for c in infer_policy(m).caps if c.status is not CapabilityStatus.DENIED}


def _load_poison() -> tuple[str, list[dict]]:
    real = ROOT / "data" / "mcptox_pure_tool.json"
    if real.exists():
        raw = json.loads(real.read_text(encoding="utf-8"))
        cases = []
        for item in raw:
            for _key, v in item.items():
                cases.append({
                    "server_name": v.get("server_name", "?"),
                    "tool_name": v.get("tool_name", "?"),
                    "tool_content": v.get("tool_content", ""),
                    "paradigm": v.get("paradigm", "?"),
                    "risk": v.get("security risk", v.get("security_risk", "?")),
                })
        return f"MCPTox real corpus ({real.relative_to(REPO)})", cases
    jl = ROOT / "poison_samples.jsonl"
    cases = [json.loads(ln) for ln in jl.read_text(encoding="utf-8").splitlines() if ln.strip()]
    for c in cases:
        c["risk"] = c.get("security_risk", "?")
    return f"synthetic sample ({jl.relative_to(REPO)}; run fetch_mcptox.sh for the real corpus)", cases


def part_b() -> None:
    print("\n" + "=" * 68)
    print("Part B — tool-poisoning tripwire (PIE name-only vs poisoned-desc)")
    print("=" * 68)
    source, cases = _load_poison()
    print(f"source: {source}")
    print(f"cases : {len(cases)}\n")

    fires = 0
    by_cap: collections.Counter = collections.Counter()
    by_para: collections.Counter = collections.Counter()
    examples: list[str] = []
    for c in cases:
        base = _caps(c["tool_name"], "")
        pois = _caps(c["tool_name"], c["tool_content"])
        injected = pois - base
        if injected:
            fires += 1
            by_cap.update(injected)
            by_para[c["paradigm"]] += 1
            if len(examples) < 4:
                examples.append(
                    f"  [{c['server_name']}/{c['tool_name']}] +{sorted(injected)}  "
                    f"({c['risk']})"
                )

    pct = 100 * fires / len(cases) if cases else 0
    print(f"tripwire FIRES (poisoned description injects >=1 capability class): "
          f"{fires}/{len(cases)} = {pct:.1f}%")
    print(f"injected capability breakdown : {dict(by_cap)}")
    print(f"fires by attack paradigm      : {dict(by_para)}")
    if examples:
        print("examples:")
        print("\n".join(examples))
    print("\nnote: the tripwire only catches poisoning that injects a new capability")
    print("CLASS into the description. Payloads that reuse an already-declared tool")
    print("(e.g. write_file to ~/.ssh on a filesystem server) inject no new class and")
    print("are left to the RUNTIME arm (BCM scope check) — see Phase 1 `soft` cases.")


def main() -> int:
    part_a()
    part_b()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
