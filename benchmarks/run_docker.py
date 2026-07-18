#!/usr/bin/env python3
"""Phase-2 docker benchmark for mcp-contract: real containers, real enforcement.

Unlike Phase 1 (which replays hand-authored event traces through `verify`),
this boots real Docker containers through the SHIPPED
`mcp-contract run --backend docker [--egress-proxy]` path and asserts on the
events the adapter actually observed/enforced. It exercises the docker
backend's genuine strength — **network enforcement** — two ways:

  * egress-allowlist : with --egress-proxy, an allowlisted host tunnels
                       (net.connect allowed=true -> within_policy) and a blocked
                       host is 403'd by the proxy before any socket opens
                       (allowed=false -> within_manifest_not_policy).
  * boot-network-none: a server that declared no net.http is booted with
                       --network none; egress is refused by the kernel, so the
                       poller observes no outbound connection at all.

Honest caveat surfaced by this harness: the docker `proc.spawn` poller
(`docker top`) is COARSE — it flags the container's OWN processes (sh/curl/...)
as proc.exec drift unless the policy grants proc.exec. These scenarios grant
proc.exec (a real server runs its own process) so the report isolates the
network verdict; the assertions below only inspect net.connect events.

Requires Docker + MCP_CONTRACT_DOCKER_TESTS=1 (same gate as the docker
integration tests). No LLM.

    MCP_CONTRACT_DOCKER_TESTS=1 python benchmarks/run_docker.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp_contract.manifest import load_manifest
from mcp_contract.models import CapabilityId, CapabilityStatus
from mcp_contract.pie.inference import infer_policy
from mcp_contract.policy import dump_policy

ROOT = Path(__file__).resolve().parent
IMAGE = "mcp-contract-bench:probe"

# Each scenario: id, source, manifest, grants (capid -> values), the in-image
# command, whether the egress proxy is enabled, and a predicate over the
# observed net.connect events.
SCENARIOS = [
    {
        "id": "egress-allowlist",
        "source": "MCPSecBench: MITM / egress redirect (hostname enforce)",
        "manifest": "fetch.json",
        "grants": {"net.http": ["example.com"], "proc.exec": []},
        "cmd": ["sh", "/scenarios/egress-proxy.sh"],
        "egress_proxy": True,
        "expect": {
            "allowed_within_policy": ("example.com", True, "within_policy"),
            "denied_blocked": ("blocked.invalid", False, "within_manifest_not_policy"),
        },
    },
    {
        "id": "boot-network-none",
        "source": "MCPSecBench: Data Exfiltration (boot-time --network none)",
        "manifest": "arith.json",
        "grants": {"proc.exec": []},  # no net.http -> --network none at boot
        "cmd": ["sh", "/scenarios/exfil-nonet.sh"],
        "egress_proxy": False,
        "expect": {"no_successful_egress": True},
    },
]


def ensure_image() -> None:
    subprocess.run(
        ["docker", "build", "-q", "-t", IMAGE, "-f",
         str(ROOT / "docker" / "Dockerfile.probe"), str(ROOT / "docker")],
        check=True, capture_output=True, text=True,
    )


def build_policy(scenario: dict, dst: Path) -> None:
    policy = infer_policy(load_manifest(str(ROOT / "manifests" / scenario["manifest"])))
    grants = {CapabilityId(k): list(v) for k, v in scenario["grants"].items()}
    for cap in policy.caps:
        if cap.id in grants:
            cap.status = CapabilityStatus.INFERRED
            cap.values = grants[cap.id]
    dst.write_text(dump_policy(policy), encoding="utf-8")


def net_events(events_path: Path) -> list[dict]:
    out = []
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("kind") == "net.connect":
            out.append(e)
    return out


def check(scenario: dict, nets: list[dict]) -> tuple[bool, list[str]]:
    notes: list[str] = []
    exp = scenario["expect"]
    ok = True
    if exp.get("no_successful_egress"):
        egressed = [e for e in nets if e["detail"].get("allowed") is True]
        if egressed:
            ok = False
            notes.append(f"expected no egress, saw {egressed}")
        else:
            notes.append(f"no outbound connection observed ({len(nets)} net events) — blocked at boot")
        return ok, notes
    for label, (host, allowed, klass) in exp.items():
        hit = next(
            (e for e in nets
             if e["detail"].get("host") == host
             and e["detail"].get("allowed") is allowed
             and e.get("classification") == klass),
            None,
        )
        if hit:
            verb = "tunneled" if allowed else "403'd by proxy"
            notes.append(f"{host}: {verb} -> {klass}")
        else:
            ok = False
            notes.append(f"MISSING {label}: {host} allowed={allowed} {klass}")
    return ok, notes


def run_scenario(scenario: dict, workdir: Path) -> dict:
    policy = workdir / f"{scenario['id']}.policy.yaml"
    build_policy(scenario, policy)
    events = workdir / f"{scenario['id']}.events.jsonl"
    cmd = [
        sys.executable, "-m", "mcp_contract.cli", "run",
        str(ROOT / "manifests" / scenario["manifest"]),
        "--policy", str(policy),
        "--backend", "docker", "--mode", "observe",
        "--image", IMAGE, "--events-out", str(events),
        "--duration", "12",
    ]
    if scenario["egress_proxy"]:
        cmd.append("--egress-proxy")
    cmd += ["--cmd", *scenario["cmd"]]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not events.exists():
        return {"id": scenario["id"], "source": scenario["source"], "ok": False,
                "notes": [f"run produced no events (exit {proc.returncode}): {proc.stderr.strip()[:200]}"]}
    ok, notes = check(scenario, net_events(events))
    return {"id": scenario["id"], "source": scenario["source"], "ok": ok, "notes": notes}


def main() -> int:
    if shutil.which("docker") is None or os.environ.get("MCP_CONTRACT_DOCKER_TESTS") != "1":
        print("SKIP: needs the docker binary and MCP_CONTRACT_DOCKER_TESTS=1")
        return 0
    ensure_image()
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        results = [run_scenario(s, workdir) for s in SCENARIOS]

    w = max(len(r["id"]) for r in results)
    print(f"{'scenario':<{w}}  result  detail")
    print("-" * (w + 40))
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"{r['id']:<{w}}  {mark:<6}  {r['source']}")
        for n in r["notes"]:
            print(f"{'':<{w}}          - {n}")
    passed = sum(r["ok"] for r in results)
    print("-" * (w + 40))
    print(f"{passed}/{len(results)} docker scenarios enforced as expected.")
    print("\nnote: docker proc.spawn observation is coarse (flags the server's own\n"
          "processes); these scenarios grant proc.exec and assert only on net.connect.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
