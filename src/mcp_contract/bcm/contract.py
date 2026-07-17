"""The "contract" side of BCM diffing: what the manifest implies.

A needs_review capability is not granted, but it *is* manifest-implied —
its events belong in bucket 2 (within_manifest_not_policy), not bucket 3.
This module computes that implied union from PIE's per-tool classifier.
"""
from __future__ import annotations

from mcp_contract.models import (
    Capability,
    CapabilityId,
    CapabilityStatus,
    Evidence,
    Manifest,
)
from mcp_contract.pie.classifier import classify_tool


def manifest_implied_caps(manifest: Manifest) -> list[Capability]:
    """Union of PIE classification over all tools, merged per class.

    Same merge rule as policy inference: values are the union of concrete
    values, plus "*" for net.http when any signal was scope-unknown
    (empty values or a "*" value) — for fs/proc/env a scope-unknown signal
    collapses the implied values to [] (class-level, matches anything in
    bucket 2); status is inferred only when every signal was inferred,
    else needs_review; evidence is the union. Classes with no signal at
    all are absent (unlike an emitted policy, which lists them explicitly
    as denied).
    """
    buckets: dict[CapabilityId, list[Capability]] = {}
    for tool in manifest.tools:
        for cap in classify_tool(tool):
            buckets.setdefault(cap.id, []).append(cap)

    merged: list[Capability] = []
    for cap_id in CapabilityId:
        signals = buckets.get(cap_id)
        if not signals:
            continue
        values: list[str] = []
        scope_unknown = False
        for sig in signals:
            if not sig.values or "*" in sig.values:
                scope_unknown = True
            for v in sig.values:
                if v != "*" and v not in values:
                    values.append(v)
        if scope_unknown:
            if cap_id is CapabilityId.NET_HTTP:
                values.append("*")
            else:
                # Class-level marker for fs/proc/env: empty implied values
                # match anything in bucket 2, so events from a scope-unknown
                # tool stay within_manifest_not_policy instead of falling to
                # outside_contract just because another tool contributed
                # concrete values.
                values = []
        status = (
            CapabilityStatus.INFERRED
            if all(s.status is CapabilityStatus.INFERRED for s in signals)
            else CapabilityStatus.NEEDS_REVIEW
        )
        evidence: list[Evidence] = []
        seen: set[tuple[str, str, str]] = set()
        for sig in signals:
            for ev in sig.evidence:
                key = (ev.tool, ev.source, ev.detail)
                if key not in seen:
                    seen.add(key)
                    evidence.append(ev)
        merged.append(
            Capability(id=cap_id, status=status, values=values, evidence=evidence)
        )
    return merged
