"""Standardized report exporters for mcp-contract ViolationReports.

Two hand-rolled, stdlib-only emitters share one violation identity:

* :func:`to_sarif` / :func:`to_sarif_json` — SARIF 2.1.0 for CI / GitHub
  code-scanning. One ``sarifLog`` dict, one run; a result per notable
  ``BehaviorEvent``; a reportingDescriptor per ``(classification, kind)`` pair.
* :func:`to_siem_json` / :func:`to_siem_ndjson` — ECS-aligned flat NDJSON for
  SIEM pipelines (Elastic/Splunk/Datadog/Sentinel). One flat dict per notable
  event.

Both are **deterministic**: results/rows are emitted in report order then event
order, and there are no wall-clock or random reads inside the exporters —
``@timestamp`` comes from ``event.ts`` and ``tool.driver.version`` from the
injected ``tool_version``. The shared :func:`violation_identity` feeds SARIF's
``partialFingerprints.primaryLocationLineHash`` and, deliberately, EXCLUDES
``ts`` and ``manifest_hash`` so one misbehavior stays one alert across runs and
manifest edits.

Imports only ``json``/``hashlib``/``datetime`` beyond the project models — no
SARIF/ECS/OCSF package.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
from datetime import datetime, timezone

from mcp_contract import __version__
from mcp_contract.models import (
    BehaviorEvent,
    EventClass,
    EventKind,
    ViolationReport,
)

# --- constants -------------------------------------------------------------

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "mcp-contract"
PROJECT_URL = "https://github.com/mcp-contract/mcp-contract"
SARIF_MAX_RESULTS = 25000  # GitHub code-scanning per-run hard limit (GO-FORWARD §3.1)

# ECS event.severity per classification.
_ECS_SEVERITY = {
    EventClass.OUTSIDE_CONTRACT.value: 9,
    EventClass.WITHIN_MANIFEST.value: 4,
    EventClass.WITHIN_POLICY.value: 1,
}

# SARIF security-severity band (GitHub): >=9.0 critical, 4.0-6.9 medium.
_SARIF_SECURITY_SEVERITY = {
    EventClass.OUTSIDE_CONTRACT.value: "9.0",
    EventClass.WITHIN_MANIFEST.value: "4.0",
}

# The two notable classes that ever become SARIF results.
_SARIF_NOTABLE = (EventClass.OUTSIDE_CONTRACT, EventClass.WITHIN_MANIFEST)


# --- shared identity -------------------------------------------------------


def event_target(event: BehaviorEvent) -> str:
    """Scope-defining value per kind (excludes ts/port/argv-tail noise).

    ``net.connect`` -> ``detail['host']`` or ``detail['ip']``;
    ``fs.open``     -> ``f"{detail['path']}:{detail['mode']}"``;
    ``proc.spawn``  -> ``posixpath.basename(argv[0] or first token of cmd)``;
    ``env.read``    -> ``detail['var']``;
    else            -> ``""``.
    """
    d = event.detail
    kind = event.kind
    if kind == EventKind.NET_CONNECT:
        return str(d.get("host") or d.get("ip") or "")
    if kind == EventKind.FS_OPEN:
        return f"{d.get('path', '')}:{d.get('mode', '')}"
    if kind == EventKind.PROC_SPAWN:
        return posixpath.basename(_proc_first_token(d))
    if kind == EventKind.ENV_READ:
        return str(d.get("var", ""))
    return ""


def violation_identity(
    server_id: str, classification: str, kind: str, target: str
) -> str:
    """sha256 hex of ``'\\x00'.join([server_id, classification, kind, target])``.

    Deliberately EXCLUDES ``ts`` and ``manifest_hash`` so one misbehavior maps
    to one alert across runs and manifest edits.
    """
    identity = "\x00".join([server_id, classification, kind, target])
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _proc_first_token(detail: dict) -> str:
    """argv[0] if present, else the first whitespace token of ``cmd``."""
    argv = detail.get("argv")
    if isinstance(argv, (list, tuple)) and argv:
        return str(argv[0])
    cmd = detail.get("cmd", "")
    if isinstance(cmd, str) and cmd.split():
        return cmd.split()[0]
    return ""


# --- human phrasing (shared by SARIF message + SIEM reason) ----------------


def _target_phrase(event: BehaviorEvent) -> str:
    """The core '<verb> <target>' clause, no server prefix, no suffix."""
    d = event.detail
    kind = event.kind
    if kind == EventKind.NET_CONNECT:
        host = d.get("host") or d.get("ip") or "?"
        port = d.get("port")
        dest = f"{host}:{port}" if port is not None else str(host)
        return f"connected to host {dest}"
    if kind == EventKind.FS_OPEN:
        return f"accessed file {d.get('path', '?')} (mode {d.get('mode', '?')})"
    if kind == EventKind.PROC_SPAWN:
        return f"spawned process {_proc_first_token(d) or '?'}"
    if kind == EventKind.ENV_READ:
        return f"read environment variable {d.get('var', '?')}"
    if kind == EventKind.SYSCALL:
        return f"made syscall {d.get('group', '?')}"
    if kind == EventKind.MCP_CALL:
        return f"invoked tool {d.get('tool', '?')}"
    return f"performed {kind.value}"


def _class_suffix(classification: str) -> str:
    if classification == EventClass.OUTSIDE_CONTRACT.value:
        return " — outside its declared contract"
    if classification == EventClass.WITHIN_MANIFEST.value:
        return " — implied by the manifest but not granted by policy"
    return ""


def _reason(event: BehaviorEvent, classification: str) -> str:
    """Human sentence WITHOUT the server prefix (SIEM event.reason)."""
    ctx = f" during tool '{event.tool_ctx}'" if event.tool_ctx else ""
    return f"{_target_phrase(event)}{ctx}{_class_suffix(classification)}."


def _sarif_message(server_id: str, event: BehaviorEvent, classification: str) -> str:
    """Human sentence WITH the server prefix (SARIF message.text)."""
    return f"MCP server '{server_id}' {_reason(event, classification)}"


# --- rule (classification, kind) vocabulary --------------------------------

_KIND_NOUN = {
    EventKind.NET_CONNECT.value: "Network connection",
    EventKind.FS_OPEN.value: "Filesystem access",
    EventKind.PROC_SPAWN.value: "Process execution",
    EventKind.ENV_READ.value: "Environment variable access",
    EventKind.SYSCALL.value: "System call",
    EventKind.MCP_CALL.value: "MCP tool call",
}

_KIND_ACTION = {
    EventKind.NET_CONNECT.value: "opened a network connection",
    EventKind.FS_OPEN.value: "accessed a filesystem path",
    EventKind.PROC_SPAWN.value: "spawned a process",
    EventKind.ENV_READ.value: "read an environment variable",
    EventKind.SYSCALL.value: "made a system call",
    EventKind.MCP_CALL.value: "invoked a tool",
}


def _pascal(token: str) -> str:
    """`outside_contract` -> `OutsideContract`, `net.connect` -> `NetConnect`."""
    parts = token.replace(".", "_").split("_")
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def _rule_short_desc(classification: str, kind: str) -> str:
    noun = _KIND_NOUN.get(kind, kind)
    if classification == EventClass.OUTSIDE_CONTRACT.value:
        return f"{noun} outside the declared contract"
    if classification == EventClass.WITHIN_MANIFEST.value:
        return f"{noun} implied by the manifest but not granted by policy"
    return noun


def _rule_full_desc(classification: str, kind: str) -> str:
    action = _KIND_ACTION.get(kind, f"performed a {kind} action")
    if classification == EventClass.OUTSIDE_CONTRACT.value:
        return (
            f"The MCP server {action} that is neither granted by the policy nor "
            f"implied by its tool manifest — behavior it never declared."
        )
    if classification == EventClass.WITHIN_MANIFEST.value:
        return (
            f"The MCP server {action} that its tool manifest implies but the "
            f"approved policy does not grant — likely an under-granted policy."
        )
    return f"The MCP server {action}."


def _build_rule(classification: str, kind: str) -> dict:
    level = "error" if classification == EventClass.OUTSIDE_CONTRACT.value else "note"
    return {
        "id": f"{classification}/{kind}",
        "name": _pascal(classification) + _pascal(kind),
        "shortDescription": {"text": _rule_short_desc(classification, kind)},
        "fullDescription": {"text": _rule_full_desc(classification, kind)},
        "defaultConfiguration": {"level": level},
        "properties": {
            "tags": ["security", "mcp", "runtime-behavior", kind],
            "security-severity": _SARIF_SECURITY_SEVERITY.get(classification, "1.0"),
        },
    }


# --- SARIF 2.1.0 -----------------------------------------------------------


def to_sarif(
    reports: list[ViolationReport],
    *,
    manifest_uri: str | None = None,
    include_within_manifest: bool = True,
    tool_version: str = __version__,
    max_results: int = SARIF_MAX_RESULTS,
) -> dict:
    """One SARIF 2.1.0 ``sarifLog`` dict (one run), ``json.dumps``-ready.

    Emits a result per ``outside_contract`` event (level ``error``) and, when
    ``include_within_manifest``, per ``within_manifest_not_policy`` event
    (level ``note``). ``within_policy`` is NEVER a result. An empty
    ``results: []`` is valid (GitHub reads it as "resolved").

    ``rules[]`` is built in first-seen ``(classification, kind)`` order and each
    result's ``ruleIndex`` points at its rule; results are in report then event
    order — fully deterministic.

    At most ``max_results`` results are emitted (GitHub code-scanning rejects a
    run exceeding 25,000, GO-FORWARD §3.1). Any overflow is dropped
    deterministically (first-seen order is kept) and surfaced in the run's
    ``properties.mcp_contract.truncated_results`` and a warning notification so
    the omission is auditable rather than silently losing the whole upload.
    """
    rules: list[dict] = []
    rule_index: dict[tuple[str, str], int] = {}
    results: list[dict] = []
    truncated = 0

    for report in reports:
        for event in report.events:
            cls = event.classification
            if cls not in _SARIF_NOTABLE:
                continue
            if cls == EventClass.WITHIN_MANIFEST and not include_within_manifest:
                continue
            if len(results) >= max_results:
                # Drop the overflow; build the rule *after* this guard so a kind
                # that only ever appears past the cap adds no orphan rule.
                truncated += 1
                continue
            classification = cls.value
            kind = event.kind.value
            key = (classification, kind)
            idx = rule_index.get(key)
            if idx is None:
                idx = len(rules)
                rule_index[key] = idx
                rules.append(_build_rule(classification, kind))
            results.append(
                _build_result(report, event, idx, classification, kind, manifest_uri)
            )

    driver = {
        "name": TOOL_NAME,
        "version": tool_version,
        "semanticVersion": tool_version,
        "informationUri": PROJECT_URL,
        "rules": rules,
    }
    run: dict = {"tool": {"driver": driver}, "results": results}
    if truncated:
        run["properties"] = {"mcp_contract.truncated_results": truncated}
        run.setdefault("invocations", [{"executionSuccessful": True}])[0][
            "toolExecutionNotifications"
        ] = [
            {
                "level": "warning",
                "message": {
                    "text": (
                        f"{truncated} additional result(s) omitted to stay "
                        f"within the {max_results}-result SARIF/GitHub limit."
                    )
                },
            }
        ]
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def _build_result(
    report: ViolationReport,
    event: BehaviorEvent,
    rule_idx: int,
    classification: str,
    kind: str,
    manifest_uri: str | None,
) -> dict:
    level = "error" if classification == EventClass.OUTSIDE_CONTRACT.value else "note"
    uri = manifest_uri or f"{report.server_id}.manifest.json"
    fingerprint = violation_identity(
        report.server_id, classification, kind, event_target(event)
    )
    return {
        "ruleId": f"{classification}/{kind}",
        "ruleIndex": rule_idx,
        "level": level,
        "message": {"text": _sarif_message(report.server_id, event, classification)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": fingerprint},
        "properties": {
            "server_id": report.server_id,
            "manifest_hash": report.manifest_hash,
            "classification": classification,
            "kind": kind,
            "tool_ctx": event.tool_ctx,
            "backend": event.backend,
            "detail": dict(event.detail),
            "ts": event.ts,
        },
    }


def to_sarif_json(
    reports: list[ViolationReport], *, indent: int | None = 2, **kw
) -> str:
    """``json.dumps(to_sarif(...), indent=indent, sort_keys=False)`` + ``'\\n'``.

    Insertion order is preserved (``sort_keys=False``) — stable because the
    inputs are already deterministically ordered.
    """
    return (
        json.dumps(to_sarif(reports, **kw), indent=indent, sort_keys=False) + "\n"
    )


# --- ECS-aligned flat NDJSON (SIEM) ----------------------------------------


def _ecs_category_type(event: BehaviorEvent) -> tuple[list[str], list[str]]:
    """ECS ``event.category`` / ``event.type`` for one kind."""
    d = event.detail
    kind = event.kind
    if kind == EventKind.NET_CONNECT:
        blocked = d.get("allowed") is False
        return ["network"], ["connection", "denied" if blocked else "allowed"]
    if kind == EventKind.FS_OPEN:
        # Mirror bcm.diff.event_capability's fs.read/fs.write split exactly: a
        # pure read mode is 'r' plus optional 'b'/'t' (case-insensitive); any
        # write-capable or unrecognized mode is a 'change' (fail closed). Using
        # the identical predicate keeps the SIEM read/write split from ever
        # diverging from the capability classification ('rb'/'rt'/'R' are reads).
        mode = str(d.get("mode", "r")).lower()
        read_only = "r" in mode and set(mode) <= {"r", "b", "t"}
        return ["file"], (["access"] if read_only else ["change"])
    if kind == EventKind.PROC_SPAWN:
        return ["process"], ["start"]
    if kind == EventKind.ENV_READ:
        return ["configuration"], ["access"]
    if kind == EventKind.SYSCALL:
        return ["process"], ["info"]
    return [], []


def _add_observables(row: dict, event: BehaviorEvent) -> None:
    """Attach ECS-native observable fields for one kind, in place."""
    d = event.detail
    kind = event.kind
    if kind == EventKind.NET_CONNECT:
        host = d.get("host")
        ip = d.get("ip")
        addr = host or ip
        if addr:
            row["destination.address"] = str(addr)
        if ip:
            row["destination.ip"] = str(ip)
        port = d.get("port")
        if port is not None:
            row["destination.port"] = port
    elif kind == EventKind.FS_OPEN:
        path = d.get("path")
        if path is not None:
            row["file.path"] = str(path)
    elif kind == EventKind.PROC_SPAWN:
        argv = d.get("argv")
        if isinstance(argv, (list, tuple)) and argv:
            args = [str(a) for a in argv]
            row["process.command_line"] = " ".join(args)
            row["process.args"] = args
        else:
            cmd = d.get("cmd")
            if cmd is not None:
                row["process.command_line"] = str(cmd)
                row["process.args"] = str(cmd).split()
    elif kind == EventKind.ENV_READ:
        var = d.get("var")
        if var is not None:
            row["mcp_contract.env_var"] = str(var)


def _siem_row(report: ViolationReport, event: BehaviorEvent) -> dict:
    classification = event.classification.value
    kind = event.kind.value
    category, etype = _ecs_category_type(event)
    outcome = "failure" if event.detail.get("allowed") is False else "success"
    row: dict = {
        "@timestamp": datetime.fromtimestamp(event.ts, timezone.utc).isoformat(),
        "event.kind": (
            "alert"
            if classification == EventClass.OUTSIDE_CONTRACT.value
            else "event"
        ),
        "event.category": category,
        "event.type": etype,
        "event.action": kind,
        "event.outcome": outcome,
        "event.severity": _ECS_SEVERITY.get(classification, 1),
        "event.reason": _reason(event, classification),
        "event.dataset": "mcp_contract.behavior",
        "event.module": "mcp_contract",
        "event.provider": "mcp-contract",
        "rule.id": f"{classification}/{kind}",
        "rule.name": _rule_short_desc(classification, kind),
        "rule.category": "mcp-contract-behavioral",
        "mcp_contract.server_id": report.server_id,
        "mcp_contract.manifest_hash": report.manifest_hash,
        "mcp_contract.classification": classification,
        "mcp_contract.mode": report.mode.value,
        "mcp_contract.event_kind": kind,
    }
    # None-valued optionals are omitted so every value stays a str/number/array.
    if event.backend is not None:
        row["mcp_contract.backend"] = event.backend
    if event.tool_ctx is not None:
        row["mcp_contract.tool_ctx"] = event.tool_ctx
    _add_observables(row, event)
    return row


def to_siem_json(
    reports: list[ViolationReport], *, include_within_policy: bool = False
) -> list[dict]:
    """One flat ECS dict per NOTABLE event.

    Notable = ``outside_contract`` + ``within_manifest_not_policy`` by default;
    ``within_policy`` only when ``include_within_policy``. ``mcp.call`` events
    are always skipped (a context marker, not a system action). Unclassified
    events are skipped (no verdict). Order is report then event order.
    """
    rows: list[dict] = []
    for report in reports:
        for event in report.events:
            if event.kind == EventKind.MCP_CALL:
                continue
            cls = event.classification
            if cls is None:
                continue
            if cls == EventClass.WITHIN_POLICY and not include_within_policy:
                continue
            rows.append(_siem_row(report, event))
    return rows


def to_siem_ndjson(reports: list[ViolationReport], **kw) -> str:
    """NDJSON: one ``json.dumps(row, sort_keys=True)`` per line, each newline-
    terminated. Zero notable events -> ``""`` (an empty, 0-byte document), NOT
    a lone ``"\\n"`` — the all-clean fleet is the common case and a blank line
    breaks a strict JSON-lines forwarder.
    """
    rows = to_siem_json(reports, **kw)
    return "".join(json.dumps(d, sort_keys=True) + "\n" for d in rows)
