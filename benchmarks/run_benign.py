#!/usr/bin/env python3
"""Phase-4 benign-workflow benchmark: false-positive / specificity measurement.

Phases 1-3 measured detection (recall) and static poisoning signal. This one
measures the other half of a usable monitor: does it stay SILENT on legitimate
traffic? It runs real multi-step workflows on real MCP servers through the
shipped `verify` gate (single-server) and `fleet verify` (multi-server) and
reports the false-positive rate.

  hard false-positive : benign workflow -> verify exit 1/2. MUST be 0.
  soft flag           : benign action within the declared class but outside the
                        approved policy scope -> within_manifest_not_policy.
                        Not a gate failure; reported as policy-tuning noise.

Offline, deterministic. Workflow shapes are modelled on mcpuniverse benign
tasks (MCP-SafetyBench, arXiv:2512.15163); 4 of the 5 server manifests are the
real public servers in demo/artifacts/pub_*.json.

    python benchmarks/run_benign.py

Exit 0 iff every benign workflow matched its expected verdict AND the hard
false-positive count is 0.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

from mcp_contract.manifest import load_manifest
from mcp_contract.models import CapabilityId, CapabilityStatus
from mcp_contract.pie.inference import infer_policy
from mcp_contract.policy import dump_policy

ROOT = Path(__file__).resolve().parent
BENIGN = ROOT / "benign"
POLICIES = BENIGN / "policies"
_COUNTS_RE = re.compile(r'\{[^{}]*"within_policy"[^{}]*\}')


def build_policy(case: dict, dst: Path) -> None:
    policy = infer_policy(load_manifest(str(BENIGN / "manifests" / case["manifest"])))
    grants = {CapabilityId(k): list(v) for k, v in (case.get("approve") or {}).items()}
    for cap in policy.caps:
        if cap.id in grants:
            cap.status = CapabilityStatus.INFERRED
            cap.values = grants[cap.id]
    dst.write_text(dump_policy(policy), encoding="utf-8")


def verify_case(case: dict) -> dict:
    POLICIES.mkdir(exist_ok=True)
    policy = POLICIES / f"{case['id']}.policy.yaml"
    build_policy(case, policy)
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_contract.cli", "verify",
         str(BENIGN / "manifests" / case["manifest"]),
         "--policy", str(policy),
         "--events", str(BENIGN / "events" / case["events"])],
        capture_output=True, text=True,
    )
    counts = {}
    blob = _COUNTS_RE.search(proc.stdout or "")
    if blob:
        try:
            counts = json.loads(blob.group(0))
        except json.JSONDecodeError:
            counts = {}
    soft = counts.get("within_manifest_not_policy", 0)
    got = proc.returncode
    hard_fp = got in (1, 2)
    ok = got == case["expect_exit"] and soft == case["expect_soft"]
    return {"id": case["id"], "source": case["source"], "got_exit": got,
            "soft": soft, "hard_fp": hard_fp, "ok": ok,
            "expect_exit": case["expect_exit"], "expect_soft": case["expect_soft"]}


def fleet_verify() -> tuple[int, str]:
    """Regenerate fleet policies, then run the shipped `fleet verify`."""
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_contract.cli", "fleet", "verify",
         "--config", str(BENIGN / "fleet.yaml")],
        capture_output=True, text=True,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip().splitlines()[-1] if (proc.stdout or proc.stderr) else ""


def main() -> int:
    cases = yaml.safe_load((BENIGN / "benign_cases.yaml").read_text(encoding="utf-8"))["cases"]
    results = [verify_case(c) for c in cases]

    w = max(len(r["id"]) for r in results)
    print("Phase 4 — benign-workflow false-positive / specificity matrix")
    print(f"{'workflow':<{w}}  exit  soft  verdict  source")
    print("-" * (w + 52))
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        flag = "  <- hard FP" if r["hard_fp"] else (f"  ({r['soft']} soft)" if r["soft"] else "")
        print(f"{r['id']:<{w}}  {r['got_exit']:>4}  {r['soft']:>4}  {mark:<7}  {r['source']}{flag}")
    print("-" * (w + 52))

    n = len(results)
    hard = sum(r["hard_fp"] for r in results)
    soft = sum(1 for r in results if r["soft"])
    matched = sum(r["ok"] for r in results)
    print(f"hard false-positives : {hard}/{n}  (target 0)")
    print(f"soft-flag (noise)    : {soft}/{n}  (policy-tuning, not gate failures)")
    print(f"matched expected     : {matched}/{n}")

    # Regenerate policies were written per-case above; fleet.yaml reuses them.
    fleet_rc, fleet_last = fleet_verify()
    print(f"\nmulti-server `fleet verify` (4 benign servers): exit {fleet_rc}  "
          f"({'clean' if fleet_rc == 0 else 'NON-CLEAN'})")
    if fleet_last:
        print(f"  {fleet_last}")

    ok = hard == 0 and matched == n and fleet_rc == 0
    print(f"\n{'PASS' if ok else 'FAIL'}: benign traffic "
          f"{'produced no hard false-positives' if ok else 'FALSE-POSITIVED'}.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
