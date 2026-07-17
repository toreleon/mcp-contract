"""Core data model for mcp-contract.

Everything here is backend-agnostic and shared by PIE (inference), BCM
(monitoring), and RAL (adapters). Serialization is hand-rolled dict/JSON so
the only runtime dependency stays PyYAML (used by the policy I/O layer).
"""
from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


class CapabilityId(str, enum.Enum):
    """Capability classes a tool can require. Pure tools map to none."""

    NET_HTTP = "net.http"    # values: hostnames/IPs; "*" or "*.example.com" wildcards
    FS_READ = "fs.read"      # values: path prefixes
    FS_WRITE = "fs.write"    # values: path prefixes
    PROC_EXEC = "proc.exec"  # values: allowed program basenames; empty = class-level
    ENV = "env"              # values: environment variable names


class CapabilityStatus(str, enum.Enum):
    INFERRED = "inferred"          # confidently derived; granted at runtime
    NEEDS_REVIEW = "needs_review"  # class implied, scope unconfirmed; NOT granted
    DENIED = "denied"              # no signal it is needed; never granted


@dataclass
class Evidence:
    """One auditable trace of why a capability was inferred."""

    tool: str    # tool name the inference came from ("" for server-level)
    source: str  # "name" | "description" | "param" | "static" | "override" | "llm"
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"tool": self.tool, "source": self.source, "detail": self.detail}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Evidence:
        return cls(
            tool=str(d.get("tool", "")),
            source=str(d.get("source", "")),
            detail=str(d.get("detail", "")),
        )


@dataclass
class Capability:
    id: CapabilityId
    status: CapabilityStatus
    values: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id.value,
            "status": self.status.value,
            "values": list(self.values),
            "evidence": [e.to_dict() for e in self.evidence],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Capability:
        # Fail closed on malformed values: a scalar string (values: /data)
        # would otherwise be iterated char-by-char, and its "/" element
        # matches every absolute path — a filesystem-wide grant.
        vals = d.get("values", [])
        if isinstance(vals, str) or not isinstance(vals, (list, tuple)):
            raise ValueError(
                f"capability {d.get('id', '?')!r}: 'values' must be a list "
                f"(e.g. values: [/data]), got {type(vals).__name__}: {vals!r}"
            )
        return cls(
            id=CapabilityId(d["id"]),
            status=CapabilityStatus(d["status"]),
            values=[str(v) for v in vals],
            evidence=[Evidence.from_dict(e) for e in d.get("evidence", [])],
        )


@dataclass
class ToolIR:
    """One MCP tool, normalized from a manifest."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Manifest:
    """The tool list an MCP server declares — the contract."""

    server_name: str
    tools: list[ToolIR]
    raw: dict[str, Any] = field(default_factory=dict)

    def hash(self) -> str:
        """Stable content hash of the declared tool surface.

        Used to bind a policy to the manifest version it was inferred from
        (rug-pull detection: manifest changes -> hash changes -> re-infer).
        Covers name, description, inputSchema, plus the client-facing
        behavioral declarations `annotations` and `outputSchema` — a server
        flipping e.g. readOnlyHint -> destructiveHint is a rug-pull even
        when the other fields are byte-identical.
        """
        canonical = json.dumps(
            [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                    "annotations": t.raw.get("annotations", {}),
                    "outputSchema": t.raw.get(
                        "outputSchema", t.raw.get("output_schema", {})
                    ),
                }
                for t in sorted(self.tools, key=lambda t: t.name)
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


GENERATOR = "mcp-contract/0.1"


@dataclass
class Policy:
    """Capabilities granted to one server, bound to one manifest version."""

    server_id: str
    manifest_hash: str
    caps: list[Capability] = field(default_factory=list)
    backend_hint: str | None = None
    generated_by: str = GENERATOR

    def cap(self, cap_id: CapabilityId) -> Capability | None:
        for c in self.caps:
            if c.id == cap_id:
                return c
        return None

    def granted(self, cap_id: CapabilityId) -> Capability | None:
        """The capability if actually granted (INFERRED only), else None."""
        c = self.cap(cap_id)
        if c is not None and c.status == CapabilityStatus.INFERRED:
            return c
        return None


class EventKind(str, enum.Enum):
    NET_CONNECT = "net.connect"  # detail: {host?, ip?, port}
    FS_OPEN = "fs.open"          # detail: {path, mode: "r"|"w"|"a"|"rw"}
    PROC_SPAWN = "proc.spawn"    # detail: {argv: [...]} or {cmd: str}
    ENV_READ = "env.read"        # detail: {var}
    MCP_CALL = "mcp.call"        # detail: {tool, params?} — context marker only
    SYSCALL = "syscall"          # detail: {group} — informational in v0


class EventClass(str, enum.Enum):
    WITHIN_POLICY = "within_policy"
    WITHIN_MANIFEST = "within_manifest_not_policy"
    OUTSIDE_CONTRACT = "outside_contract"


@dataclass
class BehaviorEvent:
    """One normalized runtime observation from a backend."""

    ts: float
    kind: EventKind
    detail: dict[str, Any] = field(default_factory=dict)
    tool_ctx: str | None = None
    classification: EventClass | None = None
    backend: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ts": self.ts,
            "kind": self.kind.value,
            "detail": dict(self.detail),
        }
        if self.tool_ctx is not None:
            d["tool_ctx"] = self.tool_ctx
        if self.classification is not None:
            d["classification"] = self.classification.value
        if self.backend is not None:
            d["backend"] = self.backend
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BehaviorEvent:
        return cls(
            ts=float(d.get("ts", 0.0)),
            kind=EventKind(d["kind"]),
            detail=dict(d.get("detail", {})),
            tool_ctx=d.get("tool_ctx"),
            classification=(
                EventClass(d["classification"]) if d.get("classification") else None
            ),
            backend=d.get("backend"),
        )


class Mode(str, enum.Enum):
    OBSERVE = "observe"
    ALERT = "alert"
    ENFORCE = "enforce"


class Severity(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class ViolationReport:
    """Outcome of a monitoring run: every event, classified."""

    server_id: str
    manifest_hash: str
    mode: Mode
    events: list[BehaviorEvent] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {c.value: 0 for c in EventClass}
        out["unclassified"] = 0
        for e in self.events:
            key = e.classification.value if e.classification else "unclassified"
            out[key] += 1
        return out

    @property
    def violations(self) -> list[BehaviorEvent]:
        return [
            e for e in self.events if e.classification == EventClass.OUTSIDE_CONTRACT
        ]

    @property
    def severity(self) -> Severity:
        counts = self.counts()
        if counts[EventClass.OUTSIDE_CONTRACT.value] > 0:
            return Severity.CRITICAL
        if counts[EventClass.WITHIN_MANIFEST.value] > 0:
            return Severity.WARNING
        return Severity.INFO

    @property
    def suggested_action(self) -> str:
        sev = self.severity
        if sev == Severity.CRITICAL:
            return (
                "Server acted outside its declared contract. Quarantine the "
                "server, review the flagged events, and do not grant the "
                "capability unless the manifest is updated and re-approved."
            )
        if sev == Severity.WARNING:
            return (
                "Behavior is implied by the manifest but not granted by the "
                "policy. Review the flagged events and widen the policy "
                "(status inferred) if legitimate — likely PIE under-granted."
            )
        return "All observed behavior is within policy. No action needed."

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "manifest_hash": self.manifest_hash,
            "mode": self.mode.value,
            "severity": self.severity.value,
            "suggested_action": self.suggested_action,
            "counts": self.counts(),
            "events": [e.to_dict() for e in self.events],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
