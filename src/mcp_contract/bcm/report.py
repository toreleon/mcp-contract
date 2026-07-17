"""Offline BCM path: event (de)serialization and batch classification.

Used by `audit` and `verify` — classify a recorded event stream against
a contract without a live backend.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable

from mcp_contract.bcm.contract import manifest_implied_caps
from mcp_contract.bcm.diff import classify_event, track_tool_ctx
from mcp_contract.models import (
    BehaviorEvent,
    EventKind,
    Manifest,
    Mode,
    Policy,
    ViolationReport,
)

_KNOWN_KINDS = frozenset(k.value for k in EventKind)


def _remap_unknown_kind(d: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Map a forward-compatible/foreign event kind to the informational bucket.

    DESIGN shared semantics: unknown kinds are informational in v0 and
    classify within_policy. The original kind is preserved in
    detail["group"] (the syscall detail vocabulary). A missing or
    non-string kind is still an error (malformed, not merely foreign).
    """
    kind = d.get("kind")
    if not isinstance(kind, str) or not kind:
        raise ValueError(f"event has no usable 'kind': {kind!r}")
    if kind in _KNOWN_KINDS:
        return d, False
    detail = d.get("detail")
    detail = dict(detail) if isinstance(detail, dict) else {}
    detail.setdefault("group", kind)
    return {**d, "kind": EventKind.SYSCALL.value, "detail": detail}, True


def load_events_jsonl(path: str | Path) -> list[BehaviorEvent]:
    """Read one BehaviorEvent per non-blank line of a JSONL file.

    Unknown event kinds are remapped to informational syscall events (the
    original kind kept in detail["group"], one warning to stderr); a
    malformed line raises ValueError with file:line context instead of
    letting a raw traceback escape.
    """
    events: list[BehaviorEvent] = []
    warned = False
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if not isinstance(d, dict):
                    raise ValueError("event line is not a JSON object")
                d, remapped = _remap_unknown_kind(d)
                events.append(BehaviorEvent.from_dict(d))
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"{path}:{lineno}: bad event: {exc}") from exc
            if remapped and not warned:
                warned = True
                print(
                    f"[mcp-contract] warning: {path}:{lineno}: unknown event "
                    "kind(s) treated as informational (within_policy)",
                    file=sys.stderr,
                )
    return events


def dump_events_jsonl(events: list[BehaviorEvent], path: str | Path) -> None:
    """Write events as one JSON object per line."""
    with open(path, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event.to_dict(), sort_keys=True))
            fh.write("\n")


def classify_events(
    events: Iterable[BehaviorEvent],
    policy: Policy,
    manifest: Manifest,
) -> ViolationReport:
    """Classify recorded events against the contract (audit/verify path).

    Computes the manifest-implied capability union itself, tracks
    tool_ctx from mcp.call events, sets each event's classification in
    place, and returns an OBSERVE-mode report.
    """
    manifest_caps = manifest_implied_caps(manifest)
    report = ViolationReport(
        server_id=policy.server_id,
        manifest_hash=policy.manifest_hash,
        mode=Mode.OBSERVE,
    )
    tool_ctx: str | None = None
    for event in events:
        tool_ctx = track_tool_ctx(event, tool_ctx)
        event.classification = classify_event(event, policy, manifest_caps)
        report.events.append(event)
    return report
