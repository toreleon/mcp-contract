#!/usr/bin/env python3
"""Phase-1 detection-matrix runner for mcp-contract.

For every case in cases.yaml this:
  1. infers a least-privilege policy from the declared manifest,
  2. applies the case's `approve:` block (flip caps to inferred + narrow values),
     writing the approved policy to policies/<id>.policy.yaml,
  3. runs the SHIPPED `mcp-contract verify` gate on the (verify) manifest,
     policy and event trace,
  4. scores the real process exit code against `expect_exit`.

No Docker, no LLM, no network — pure replay through the mock/verify path.
Exit 0 iff every case matches its expected verdict (CI-able).

    python benchmarks/run.py            # run the matrix
    python benchmarks/run.py --json     # also dump machine-readable results
"""
from __future__ import annotations

import argparse
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
POLICIES = ROOT / "policies"

EXIT_LABEL = {
    0: "clean",
    1: "outside_contract",
    2: "rug-pull",
    4: "inconclusive",
}
_COUNTS_RE = re.compile(r'\{[^{}]*"within_policy"[^{}]*\}')


def build_policy(case: dict) -> Path:
    """Infer + approve -> write policies/<id>.policy.yaml, return its path."""
    manifest = load_manifest(str(ROOT / "manifests" / case["manifest"]))
    policy = infer_policy(manifest)
    approve = case.get("approve") or {}
    granted = {CapabilityId(k): list(v) for k, v in approve.items()}
    for cap in policy.caps:
        if cap.id in granted:
            cap.status = CapabilityStatus.INFERRED
            cap.values = granted[cap.id]
    POLICIES.mkdir(exist_ok=True)
    out = POLICIES / f"{case['id']}.policy.yaml"
    out.write_text(dump_policy(policy), encoding="utf-8")
    return out


def run_case(case: dict) -> dict:
    policy = build_policy(case)
    verify_manifest = ROOT / "manifests" / case.get("verify_manifest", case["manifest"])
    events = ROOT / "events" / case["events"]
    cmd = [
        sys.executable, "-m", "mcp_contract.cli", "verify",
        str(verify_manifest), "--policy", str(policy), "--events", str(events),
    ]
    if case.get("allow_empty"):
        cmd.append("--allow-empty")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    counts = {}
    blob = _COUNTS_RE.search(proc.stdout or "")
    if blob:
        try:
            counts = json.loads(blob.group(0))
        except json.JSONDecodeError:
            counts = {}
    got = proc.returncode
    return {
        "id": case["id"],
        "partition": case["partition"],
        "source": case["source"],
        "expect_exit": case["expect_exit"],
        "got_exit": got,
        "ok": got == case["expect_exit"],
        "counts": counts,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="dump results.json alongside the table")
    args = ap.parse_args()

    cases = yaml.safe_load((ROOT / "cases.yaml").read_text(encoding="utf-8"))["cases"]
    results = [run_case(c) for c in cases]

    w_id = max(len(r["id"]) for r in results)
    w_part = max(len(r["partition"]) for r in results)
    header = f"{'case':<{w_id}}  {'partition':<{w_part}}  exp  got  verdict            result"
    print(header)
    print("-" * len(header))
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        label = EXIT_LABEL.get(r["got_exit"], f"exit {r['got_exit']}")
        soft = r["counts"].get("within_manifest_not_policy", 0)
        soft_note = f"  (+{soft} soft-flag)" if soft and r["got_exit"] == 0 else ""
        print(
            f"{r['id']:<{w_id}}  {r['partition']:<{w_part}}"
            f"  {r['expect_exit']:>3}  {r['got_exit']:>3}"
            f"  {label:<17}  {mark}{soft_note}"
        )

    n = len(results)
    passed = sum(r["ok"] for r in results)
    print("-" * len(header))
    # per-partition tally
    parts: dict[str, list[dict]] = {}
    for r in results:
        parts.setdefault(r["partition"], []).append(r)
    for part, rs in parts.items():
        print(f"  {part:<16} {sum(x['ok'] for x in rs)}/{len(rs)} as expected")
    print(f"\n{passed}/{n} cases matched their expected verdict.")

    if args.json:
        out = ROOT / "results.json"
        out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out.relative_to(ROOT.parent)}")

    return 0 if passed == n else 1


if __name__ == "__main__":
    raise SystemExit(main())
