"""Policy inference: aggregate per-tool capability signals into one policy.

The emitted `Policy` always lists all five capability classes so
deny-by-default is explicit: classes with no signal appear as `denied`.
Merging is conservative — a class is `inferred` only when every signal was,
and `proc.exec` can never become `inferred` from rules or LLM suggestions
(only an explicit user override can grant it).
"""
from __future__ import annotations

from mcp_contract.models import (
    Capability,
    CapabilityId,
    CapabilityStatus,
    Evidence,
    Manifest,
    Policy,
    ToolIR,
)
from mcp_contract.pie.classifier import classify_tool
from mcp_contract.pie.llm import LLMAssist


def infer_policy(
    manifest: Manifest,
    *,
    server_id: str | None = None,
    overrides: list[Capability] | None = None,
    llm: LLMAssist | None = None,
) -> Policy:
    """Infer a least-privilege policy from a manifest.

    - Rules (`classify_tool`) run over every tool; signals merge per class
      (see `merge_class_signals`).
    - LLM suggestions (spec §4.5) may only *add* classes the rules did not
      flag, are always clamped to `needs_review`, and get ``source="llm"``
      evidence. Rules win every conflict.
    - `overrides` apply last: an override replaces the merged capability for
      its class wholesale (with ``source="override"`` evidence appended).
    - Classes with no signal at all are emitted as `denied` with empty
      values/evidence, so every policy carries all five classes.
    """
    signals: dict[CapabilityId, list[Capability]] = {cid: [] for cid in CapabilityId}
    for tool in manifest.tools:
        for cap in classify_tool(tool):
            signals[cap.id].append(cap)
    rule_classes = {cid for cid, caps in signals.items() if caps}

    if llm is not None:
        for tool in manifest.tools:
            for suggestion in llm.suggest(tool):
                if suggestion.id in rule_classes:
                    continue  # rules win: LLM may only add new classes
                signals[suggestion.id].append(_clamp_llm(suggestion, tool))

    caps: list[Capability] = []
    for cap_id in CapabilityId:
        if signals[cap_id]:
            merged = merge_class_signals(cap_id, signals[cap_id])
            if (
                cap_id == CapabilityId.PROC_EXEC
                and merged.status == CapabilityStatus.INFERRED
            ):
                # Unreachable via the shipped rules, but the invariant is
                # load-bearing: exec is only granted by explicit override.
                merged.status = CapabilityStatus.NEEDS_REVIEW
            caps.append(merged)
        else:
            caps.append(Capability(cap_id, CapabilityStatus.DENIED))

    if overrides:
        by_id = {c.id: c for c in caps}
        for override in overrides:
            by_id[override.id] = Capability(
                id=override.id,
                status=override.status,
                values=list(override.values),
                evidence=list(override.evidence)
                + [
                    Evidence(
                        "",
                        "override",
                        "user override replaced the inferred capability",
                    )
                ],
            )
        caps = [by_id[cap_id] for cap_id in CapabilityId]

    return Policy(
        server_id=server_id or manifest.server_name,
        manifest_hash=manifest.hash(),
        caps=caps,
    )


def merge_class_signals(
    cap_id: CapabilityId, signals: list[Capability]
) -> Capability:
    """Merge multiple signals for one class into a single capability.

    values = union of concrete values, plus ``"*"`` (net) or ``[]``
    (fs/proc/env — a no-op on the union) if any signal was scope-unknown;
    status = `inferred` only if **all** signals were, else `needs_review`;
    evidence = deduplicated union. An empty signal list means the class is
    not implied at all and is DENIED — never granted by vacuous truth.
    """
    if not signals:
        # Deny-by-default: no signal means no grant (mirrors infer_policy's
        # own no-signal branch). Without this guard, all_inferred would be
        # vacuously true and an empty list would come back INFERRED.
        return Capability(cap_id, CapabilityStatus.DENIED)

    values: list[str] = []
    evidence: list[Evidence] = []
    seen_evidence: set[tuple[str, str, str]] = set()
    scope_unknown = False
    all_inferred = True

    for signal in signals:
        if signal.status != CapabilityStatus.INFERRED:
            all_inferred = False
        concrete = [v for v in signal.values if v != "*"]
        if not concrete:
            scope_unknown = True
        if cap_id == CapabilityId.NET_HTTP and "*" in signal.values:
            scope_unknown = True
        for value in concrete:
            if value not in values:
                values.append(value)
        for ev in signal.evidence:
            key = (ev.tool, ev.source, ev.detail)
            if key not in seen_evidence:
                seen_evidence.add(key)
                evidence.append(ev)

    if cap_id == CapabilityId.NET_HTTP and scope_unknown and "*" not in values:
        values.append("*")

    status = (
        CapabilityStatus.INFERRED if all_inferred else CapabilityStatus.NEEDS_REVIEW
    )
    return Capability(cap_id, status, values=values, evidence=evidence)


def _clamp_llm(suggestion: Capability, tool: ToolIR) -> Capability:
    """Apply the LLM guardrails: needs_review always, evidence tagged llm."""
    evidence = [
        Evidence(ev.tool or tool.name, "llm", ev.detail) for ev in suggestion.evidence
    ]
    if not evidence:
        evidence = [
            Evidence(tool.name, "llm", f"LLM suggested {suggestion.id.value}")
        ]
    return Capability(
        id=suggestion.id,
        status=CapabilityStatus.NEEDS_REVIEW,
        values=list(suggestion.values),
        evidence=evidence,
    )
