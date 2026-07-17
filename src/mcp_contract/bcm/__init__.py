"""BCM — Behavioral Consistency Monitor.

Diff runtime behavior against the contract (manifest + policy): event →
capability mapping, three-bucket classification, live monitoring with
alert/enforce hooks, and offline report/audit helpers.
"""
from __future__ import annotations

from mcp_contract.bcm.contract import manifest_implied_caps
from mcp_contract.bcm.diff import (
    classify_event,
    event_capability,
    host_matches,
    path_matches,
    track_tool_ctx,
)
from mcp_contract.bcm.monitor import ManifestDriftError, Monitor
from mcp_contract.bcm.report import (
    classify_events,
    dump_events_jsonl,
    load_events_jsonl,
)

__all__ = [
    "ManifestDriftError",
    "Monitor",
    "classify_event",
    "classify_events",
    "dump_events_jsonl",
    "event_capability",
    "host_matches",
    "load_events_jsonl",
    "manifest_implied_caps",
    "path_matches",
    "track_tool_ctx",
]
