"""BCM diffing: map runtime events to capabilities and classify them.

Implements the three-bucket classification from SPEC §5.3. Every event is
within_policy (granted), within_manifest_not_policy (implied by the
declared tool surface but not granted — likely PIE under-granted), or
outside_contract (the server did something it never declared — the
primary violation signal).
"""
from __future__ import annotations

import posixpath

from mcp_contract.models import (
    BehaviorEvent,
    Capability,
    CapabilityId,
    EventClass,
    EventKind,
    Policy,
)


def event_capability(event: BehaviorEvent) -> tuple[CapabilityId, str] | None:
    """Map an event to the (capability class, observed value) it exercises.

    Returns None for events that never count against the contract:
    mcp.call (context marker only), syscall, and unknown kinds
    (informational in v0).
    """
    kind = event.kind
    detail = event.detail
    if kind is EventKind.NET_CONNECT:
        value = detail.get("host") or detail.get("ip") or ""
        return (CapabilityId.NET_HTTP, str(value))
    if kind is EventKind.FS_OPEN:
        mode = str(detail.get("mode", "r")).lower()
        # Fail closed: only pure read modes ('r' plus optional 'b'/'t') map
        # to fs.read; anything write-capable ('w', 'a', '+', 'x') or
        # unrecognized maps to fs.write, the strongest classification.
        read_only = "r" in mode and set(mode) <= {"r", "b", "t"}
        cap_id = CapabilityId.FS_READ if read_only else CapabilityId.FS_WRITE
        return (cap_id, str(detail.get("path", "")))
    if kind is EventKind.PROC_SPAWN:
        argv = detail.get("argv")
        if isinstance(argv, list) and argv:
            program = str(argv[0])
        else:
            tokens = str(detail.get("cmd", "")).split()
            program = tokens[0] if tokens else ""
        return (CapabilityId.PROC_EXEC, posixpath.basename(program))
    if kind is EventKind.ENV_READ:
        return (CapabilityId.ENV, str(detail.get("var", "")))
    return None


def host_matches(host: str, patterns: list[str]) -> bool:
    """True if `host` matches any pattern (exact, "*", or "*.suffix").

    Case-insensitive. The suffix wildcard "*.github.com" matches any
    subdomain (api.github.com, a.b.github.com) but not "github.com"
    itself. Values may be hostnames or IPs; port is ignored in v0.
    """
    h = host.lower()
    for pattern in patterns:
        p = pattern.lower()
        if p == "*":
            return True
        if p.startswith("*."):
            suffix = p[1:]  # ".github.com"
            if len(h) > len(suffix) and h.endswith(suffix):
                return True
        elif h == p:
            return True
    return False


def path_matches(path: str, prefixes: list[str]) -> bool:
    """True if the normalized `path` sits under any normalized prefix.

    Prefix boundaries are path components: "/data" matches "/data" and
    "/data/x" but not "/database". Both sides are normalized with
    posixpath.normpath first.
    """
    npath = posixpath.normpath(path)
    for prefix in prefixes:
        npfx = posixpath.normpath(prefix)
        if npath == npfx:
            return True
        if npfx == "/":
            if npath.startswith("/"):
                return True
        elif npath.startswith(npfx + "/"):
            return True
    return False


def track_tool_ctx(event: BehaviorEvent, current: str | None) -> str | None:
    """Advance the mcp.call-driven tool context and stamp it on `event`.

    An mcp.call event updates the current context to its tool name; any
    event arriving without a tool_ctx gets the current one stamped on
    (events that already carry one keep it). Returns the possibly
    updated current context.
    """
    if event.kind is EventKind.MCP_CALL:
        tool = event.detail.get("tool")
        if isinstance(tool, str) and tool:
            current = tool
    if event.tool_ctx is None and current is not None:
        event.tool_ctx = current
    return current


def _value_matches(cap_id: CapabilityId, value: str, values: list[str]) -> bool:
    """Per-class value matching against a non-empty value list."""
    if cap_id is CapabilityId.NET_HTTP:
        return host_matches(value, values)
    if cap_id in (CapabilityId.FS_READ, CapabilityId.FS_WRITE):
        return path_matches(value, values)
    if cap_id is CapabilityId.ENV:
        # A class-level env grant is written values: ["*"] (empty values on
        # env grant nothing; proc.exec keeps its empty-values class form).
        return "*" in values or value in values
    # proc.exec: allowed program basenames.
    return value in values


def classify_event(
    event: BehaviorEvent,
    policy: Policy,
    manifest_caps: list[Capability],
) -> EventClass:
    """Three-bucket classification (SPEC §5.3) of one event.

    `manifest_caps` is the manifest-implied capability union (see
    bcm.contract.manifest_implied_caps); statuses there are irrelevant
    beyond existence.
    """
    mapped = event_capability(event)
    if mapped is None:
        return EventClass.WITHIN_POLICY
    cap_id, value = mapped

    granted = policy.granted(cap_id)
    if granted is not None:
        if granted.values:
            if _value_matches(cap_id, value, granted.values):
                return EventClass.WITHIN_POLICY
        elif cap_id is CapabilityId.PROC_EXEC:
            # Empty values on proc.exec = class-level grant (any program);
            # empty values on net/fs/env grant nothing.
            return EventClass.WITHIN_POLICY

    for cap in manifest_caps:
        if cap.id is not cap_id:
            continue
        # Implied values [] or ["*"] mean class-level / unknown scope:
        # they match anything for the manifest (bucket 2) check.
        if (
            not cap.values
            or "*" in cap.values
            or _value_matches(cap_id, value, cap.values)
        ):
            return EventClass.WITHIN_MANIFEST

    return EventClass.OUTSIDE_CONTRACT
