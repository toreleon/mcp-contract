"""Fleet API — batch inference/verification/monitoring across many servers.

One :class:`Fleet` holds many :class:`FleetServer` descriptions and runs the
same verb over all of them, returning a single deterministic
:class:`FleetReport` whose aggregate exit code is computed by *security-first
precedence* (rug-pull ``2`` > violation ``1`` > error/skipped ``4`` > clean
``0`` — NOT numeric max; GO-FORWARD-0.1.0 §6).

Design constraints honored here:

* Nothing frozen is touched — :mod:`mcp_contract.models` and
  :mod:`mcp_contract.ral.base` are imported, never extended.
* Serializers are deterministic: no wall-clock or randomness inside
  ``to_dict``/``to_json``/``to_ndjson``. The report timestamp comes from an
  injected ``started_at`` (each batch verb reads ``time.time()`` exactly once,
  as the *default* value, and threads it in — pass an explicit ``started_at``
  for byte-stable output).
* Environment **values are never serialized** — reports and
  ``launch_fingerprint`` carry env *key names only*. Redaction is baked into
  the serializer so it cannot be forgotten.
* ``policy_hash`` (Module POLICY) and the SARIF/SIEM exporters (Module REPORT)
  are imported lazily so this module loads even while those land in parallel.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_contract import __version__
from mcp_contract.bcm.monitor import ManifestDriftError, Monitor
from mcp_contract.bcm.report import classify_events, load_events_jsonl
from mcp_contract.manifest import load_manifest
from mcp_contract.models import (
    CapabilityId,
    EventClass,
    Mode,
    Policy,
    Severity,
    ViolationReport,
)
from mcp_contract.pie.inference import infer_policy
from mcp_contract.policy.io import dump_policy, load_policy, verify_manifest_hash
from mcp_contract.ral import ServerSpec, get_adapter

__all__ = [
    "FleetServer",
    "FleetServerReport",
    "FleetReport",
    "Fleet",
]

# Per-server exit codes (mirror the single-server CLI contract, GO-FORWARD §6).
_EXIT_OK = 0
_EXIT_VIOLATION = 1
_EXIT_RUG_PULL = 2
_EXIT_BAD_INPUT = 4

# status -> per-server exit code
_STATUS_EXIT = {
    "ok": _EXIT_OK,
    "violation": _EXIT_VIOLATION,
    "rug_pull": _EXIT_RUG_PULL,
    "skipped": _EXIT_BAD_INPUT,
    "error": _EXIT_BAD_INPUT,
}

# ${VAR} or ${VAR:-default} — bash-style expansion of launch env values.
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

_REMOTE_TRANSPORTS = frozenset({"http", "sse"})
_TRANSPORT_ALIASES = {"streamable-http": "http", "streamablehttp": "http"}


class _UnresolvedVar(Exception):
    """A ``${VAR}`` reference with no host value and no default.

    Raised by :meth:`FleetServer.resolved_env`; caught by the batch verbs,
    which mark the server ``skipped`` (exit 4) and never launch it.
    """

    def __init__(self, var: str) -> None:
        super().__init__(
            f"environment variable ${{{var}}} is unset and has no default; "
            "server cannot be launched (marked skipped)"
        )
        self.var = var


def _policy_hash(policy: Policy) -> str:
    """``policy_hash`` (Module POLICY) if available, else ``""``.

    Imported lazily and defensively so the fleet module works while Module
    POLICY's free function lands in parallel.
    """
    try:  # pragma: no cover - trivial import shim
        from mcp_contract.policy.io import policy_hash as _ph
    except Exception:
        try:
            from mcp_contract.policy import policy_hash as _ph  # type: ignore
        except Exception:
            return ""
    try:
        return _ph(policy)
    except Exception:
        return ""


def _redact_env_keys(env: dict[str, str]) -> list[str]:
    """Env dict -> sorted list of key names (values dropped)."""
    return sorted(env.keys())


@dataclass
class FleetServer:
    """One server in a fleet: how to launch it and where its artifacts live."""

    id: str
    launch: dict = field(default_factory=dict)  # verbatim mcpServers/server.json entry
    backend: str = "docker"                     # -> get_adapter
    mode: Mode = Mode.OBSERVE
    image: str | None = None
    manifest_path: str | None = None
    policy_path: str | None = None
    events_path: str | None = None
    egress_proxy: bool = False
    labels: dict[str, str] = field(default_factory=dict)
    source: str | None = None                   # provenance: fleet-file path or client

    @property
    def transport(self) -> str:
        """Wire transport: explicit ``launch.transport``, else ``stdio`` when a
        ``command`` is present, else a hard error (a ``url`` with no transport
        is ambiguous — GO-FORWARD §4 rule 3)."""
        raw = self.launch.get("transport")
        if raw:
            t = str(raw).lower()
            return _TRANSPORT_ALIASES.get(t, t)
        if self.launch.get("command"):
            return "stdio"
        raise ValueError(
            f"server {self.id!r}: cannot determine transport — launch has no "
            "'transport' and no 'command' (a remote 'url' must declare its "
            "transport explicitly)"
        )

    def resolved_env(self) -> dict[str, str]:
        """Expand ``${VAR}`` / ``${VAR:-default}`` in ``launch.env`` from the
        host environment.

        Raises :class:`_UnresolvedVar` for a bare ``${VAR}`` that is unset and
        has no default (the caller marks the server skipped, exit 4).
        """
        env_raw = self.launch.get("env") or {}
        if not isinstance(env_raw, dict):
            raise ValueError(f"server {self.id!r}: launch.env must be a mapping")
        resolved: dict[str, str] = {}
        for key, value in env_raw.items():
            resolved[str(key)] = _expand_env_value(str(value))
        return resolved

    def env_keys(self) -> list[str]:
        """Sorted env key names from ``launch.env`` (never touches values)."""
        env_raw = self.launch.get("env") or {}
        if not isinstance(env_raw, dict):
            return []
        return sorted(str(k) for k in env_raw.keys())

    def launch_fingerprint(self) -> dict:
        """A redacted, serializable summary of how the server launches.

        ``{image?, command?, args?, env_keys:[...]}`` — env is reduced to its
        key set; **no values ever appear**.
        """
        fp: dict[str, Any] = {}
        if self.image:
            fp["image"] = self.image
        command = self.launch.get("command")
        if command is not None:
            fp["command"] = command
        args = self.launch.get("args")
        if args is not None:
            fp["args"] = list(args) if isinstance(args, (list, tuple)) else args
        url = self.launch.get("url")
        if url is not None:
            fp["url"] = url
        fp["env_keys"] = self.env_keys()
        return fp

    def to_server_spec(self, policy: Policy) -> ServerSpec:
        """Build a backend-neutral :class:`ServerSpec` for this server.

        env is resolved then filtered to the keys the policy actually grants
        (``env`` capability values; ``"*"`` = all keys) so a launched server
        only receives approved secrets. Provenance and the redacted launch
        fingerprint ride along in ``extra``.
        """
        env = self.resolved_env()
        granted = policy.granted(CapabilityId.ENV)
        if granted is None:
            allowed_env: dict[str, str] = {}
        elif "*" in granted.values:
            allowed_env = dict(env)
        else:
            allowed = set(granted.values)
            allowed_env = {k: v for k, v in env.items() if k in allowed}

        command = self.launch.get("command")
        args = self.launch.get("args") or []
        argv: list[str] = []
        if command:
            argv.append(str(command))
        if isinstance(args, (list, tuple)):
            argv.extend(str(a) for a in args)

        return ServerSpec(
            server_id=self.id,
            image=self.image,
            command=argv,
            env=allowed_env,
            workdir=self.launch.get("cwd"),
            extra={
                "source": self.source,
                "transport": self.transport,
                "labels": dict(self.labels),
                "launch_fingerprint": self.launch_fingerprint(),
            },
        )


def _expand_env_value(value: str) -> str:
    """Expand every ``${VAR}`` / ``${VAR:-default}`` occurrence in ``value``."""

    def _sub(match: re.Match[str]) -> str:
        var = match.group(1)
        default = match.group(2)  # None when no ``:-default`` was written
        current = os.environ.get(var)
        if current:
            return current
        if default is not None:
            return default
        # ``:-`` with an empty default (``${VAR:-}``) still resolves to "".
        raise _UnresolvedVar(var)

    return _VAR_RE.sub(_sub, value)


@dataclass
class FleetServerReport:
    """The per-server SIEM envelope: outcome + provenance for one server.

    ``launch_fingerprint`` carries env *key names only* — values are already
    redacted by the time they reach this record.
    """

    server_id: str
    status: str                      # "ok"|"violation"|"rug_pull"|"skipped"|"error"
    exit_code: int                   # per-server: 0|1|2|4 (GO-FORWARD §6)
    report: ViolationReport | None = None   # None when skipped/errored/inferred
    manifest_hash: str = ""
    policy_hash: str = ""
    backend: str = ""
    mode: str = ""
    transport: str = "stdio"
    labels: dict[str, str] = field(default_factory=dict)
    source: str | None = None
    launch_fingerprint: dict = field(default_factory=dict)  # env values redacted
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """One NDJSON row: the envelope, plus the classified report if any."""
        d: dict[str, Any] = {
            "server_id": self.server_id,
            "status": self.status,
            "exit_code": self.exit_code,
            "manifest_hash": self.manifest_hash,
            "policy_hash": self.policy_hash,
            "backend": self.backend,
            "mode": self.mode,
            "transport": self.transport,
            "labels": dict(self.labels),
            "source": self.source,
            "launch_fingerprint": _redacted_fingerprint(self.launch_fingerprint),
        }
        if self.error is not None:
            d["error"] = self.error
        if self.report is not None:
            d["report"] = self.report.to_dict()
        return d


_SECRET_FLAG_RE = re.compile(
    r"(?i)(token|api[-_]?key|secret|passwo?r?d|pwd|access[-_]?token|auth|bearer|"
    r"credential)"
)


def _redact_url(url: str) -> str:
    """Drop credential-bearing parts of a launch ``url`` (keep scheme/host/path).

    A remote (http/sse) MCP server commonly carries its access token in the
    query string (``?access_token=...``) or in ``user:pass@`` userinfo. Those
    are stripped; the scheme/host/path are kept for provenance/identity.
    """
    from urllib.parse import urlsplit, urlunsplit

    try:
        p = urlsplit(url)
    except Exception:
        return "<redacted-url>"
    netloc = p.netloc.rsplit("@", 1)[-1]  # drop any user:pass@ userinfo
    query = "REDACTED" if p.query else ""  # query strings carry access_token=...
    return urlunsplit((p.scheme, netloc, p.path, query, ""))  # drop fragment too


def _redact_args(args: list) -> list:
    """Redact values that follow a secret-looking CLI flag (best-effort).

    Handles both ``--api-key=SECRET`` (inline) and ``--api-key SECRET``
    (separate token) shapes for known secret flag names.
    """
    out: list = []
    redact_next = False
    for a in args:
        s = str(a)
        if redact_next:
            out.append("REDACTED")
            redact_next = False
            continue
        if s.startswith("-") and "=" in s:  # --api-key=SECRET
            flag = s.split("=", 1)[0]
            out.append(f"{flag}=REDACTED" if _SECRET_FLAG_RE.search(flag) else s)
        elif s.startswith("-") and _SECRET_FLAG_RE.search(s):  # --api-key SECRET
            out.append(s)
            redact_next = True
        else:
            out.append(s)
    return out


def _redacted_fingerprint(fp: dict) -> dict:
    """Return ``fp`` with any credential-bearing parts stripped.

    Redaction is baked into the serializer chokepoint so it cannot be
    forgotten: any stray ``env`` mapping is reduced to its key set, a launch
    ``url``'s query string and userinfo (common credential carriers for remote
    MCP servers) are dropped, and values following secret-looking CLI flags in
    ``args`` (``--api-key``/``--token``) are redacted.
    """
    out = dict(fp)
    env = out.pop("env", None)
    if isinstance(env, dict):
        out.setdefault("env_keys", sorted(str(k) for k in env.keys()))
    if isinstance(out.get("url"), str):
        out["url"] = _redact_url(out["url"])
    if isinstance(out.get("args"), list):
        out["args"] = _redact_args(out["args"])
    return out


@dataclass
class FleetReport:
    """Aggregate outcome of one batch verb across the whole fleet."""

    runs: list[FleetServerReport]
    started_at: float                # caller-injected (byte-stability)
    engine_version: str = __version__

    def _sorted_runs(self) -> list[FleetServerReport]:
        """Runs in a deterministic order (by server_id) for every serializer."""
        return sorted(self.runs, key=lambda r: r.server_id)

    def exit_code(self) -> int:
        """Security-first aggregate exit code (GO-FORWARD §6).

        Precedence is ``2 > 1 > 4 > 0`` — NOT numeric max: a rug-pull outranks
        a plain violation (a changed manifest invalidates the whole
        comparison), and ``4`` stays last so a broken pipeline never *looks*
        clean and never trips a gate keyed on 1/2.
        """
        statuses = {r.status for r in self.runs}
        if "rug_pull" in statuses:
            return _EXIT_RUG_PULL
        if "violation" in statuses:
            return _EXIT_VIOLATION
        if statuses & {"error", "skipped"}:
            return _EXIT_BAD_INPUT
        return _EXIT_OK

    def severity(self) -> Severity:
        """critical if any outside_contract event, warning if any within_manifest."""
        totals = self.totals()
        if totals.get(EventClass.OUTSIDE_CONTRACT.value, 0) > 0:
            return Severity.CRITICAL
        if totals.get(EventClass.WITHIN_MANIFEST.value, 0) > 0:
            return Severity.WARNING
        return Severity.INFO

    def totals(self) -> dict[str, int]:
        """Summed per-EventClass counts plus per-status server tallies."""
        totals: dict[str, int] = {c.value: 0 for c in EventClass}
        totals["unclassified"] = 0
        totals["servers"] = len(self.runs)
        totals["ok"] = 0
        totals["violations"] = 0
        totals["rug_pulls"] = 0
        totals["skipped"] = 0
        totals["errors"] = 0
        status_key = {
            "ok": "ok",
            "violation": "violations",
            "rug_pull": "rug_pulls",
            "skipped": "skipped",
            "error": "errors",
        }
        for run in self.runs:
            totals[status_key.get(run.status, "errors")] += 1
            if run.report is not None:
                for key, value in run.report.counts().items():
                    totals[key] = totals.get(key, 0) + value
        return totals

    def to_dict(self) -> dict[str, Any]:
        """Deterministic aggregate document; timestamp from ``started_at``."""
        return {
            "generated_at": datetime.fromtimestamp(
                self.started_at, tz=timezone.utc
            ).isoformat(),
            "tool_version": self.engine_version,
            "totals": self.totals(),
            "exit_code": self.exit_code(),
            "severity": self.severity().value,
            "runs": [r.to_dict() for r in self._sorted_runs()],
        }

    def to_json(self, indent: int | None = 2) -> str:
        """``json.dumps`` of :meth:`to_dict` with sorted keys (byte-stable)."""
        import json

        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_ndjson(self) -> str:
        """One :meth:`FleetServerReport.to_dict` per line, sorted keys."""
        import json

        lines = [
            json.dumps(r.to_dict(), sort_keys=True) for r in self._sorted_runs()
        ]
        return "\n".join(lines) + ("\n" if lines else "")

    def _reports(self) -> list[ViolationReport]:
        return [r.report for r in self._sorted_runs() if r.report is not None]

    def to_sarif(self, **kw: Any) -> dict:
        """SARIF 2.1.0 over all non-None reports (delegates to Module REPORT)."""
        from mcp_contract.report.export import to_sarif

        return to_sarif(self._reports(), **kw)

    def to_siem_ndjson(self, **kw: Any) -> str:
        """ECS NDJSON over all non-None reports (delegates to Module REPORT)."""
        from mcp_contract.report.export import to_siem_ndjson

        return to_siem_ndjson(self._reports(), **kw)


class Fleet:
    """A collection of :class:`FleetServer`s that a verb runs over as a batch."""

    def __init__(self, servers: list[FleetServer] | None = None) -> None:
        self.servers: list[FleetServer] = list(servers or [])

    # ------------------------------------------------------------------ ctors

    @classmethod
    def from_config(cls, path: str | Path) -> "Fleet":
        """Load a native fleet config (``fleet.yaml`` / JSON) — GO-FORWARD §4.

        ``defaults`` are merged under each server (server wins); ``manifest``/
        ``policy`` resolve against ``manifest_dir``/``policy_dir`` (themselves
        relative to the config file); a docker-backed server must declare an
        ``image``; a remote (http/sse) transport downgrades ``mode`` to
        ``observe``.
        """
        import yaml

        cfg_path = Path(path)
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"fleet config {cfg_path}: expected a mapping document")

        base = cfg_path.parent
        defaults = data.get("defaults") or {}
        if not isinstance(defaults, dict):
            raise ValueError("fleet config: 'defaults' must be a mapping")
        servers_raw = data.get("servers") or {}
        if not isinstance(servers_raw, dict):
            raise ValueError("fleet config: 'servers' must be a mapping of id -> spec")

        manifest_dir = _resolve_dir(base, defaults.get("manifest_dir"))
        policy_dir = _resolve_dir(base, defaults.get("policy_dir"))

        servers: list[FleetServer] = []
        for server_id, spec in servers_raw.items():
            if not isinstance(spec, dict):
                raise ValueError(f"fleet config: server {server_id!r} must be a mapping")
            servers.append(
                _build_server(
                    str(server_id), spec, defaults, base, manifest_dir, policy_dir,
                    source=str(cfg_path),
                )
            )
        return cls(servers)

    @classmethod
    def from_mcp_servers(
        cls,
        path: str | Path,
        *,
        backend: str = "docker",
        mode: Mode = Mode.OBSERVE,
    ) -> "Fleet":
        """Ingest an ``mcpServers`` (Claude/.mcp.json/Cursor) or ``servers``
        (VS Code) client config: one server per map entry, ``launch`` verbatim.

        Manifests/policies are absent from these files (they only describe how
        to *launch*); pair with a future in-sandbox ``tools/list`` discovery
        step before verifying.
        """
        import yaml

        cfg_path = Path(path)
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"mcp config {cfg_path}: expected a mapping document")

        if isinstance(data.get("mcpServers"), dict):
            entries = data["mcpServers"]
            client = "mcp"
        elif isinstance(data.get("servers"), dict):
            entries = data["servers"]
            client = "vscode"
        else:
            raise ValueError(
                f"mcp config {cfg_path}: expected a top-level 'mcpServers' "
                "(Claude/.mcp.json/Cursor) or 'servers' (VS Code) mapping"
            )

        servers: list[FleetServer] = []
        for server_id, launch in entries.items():
            if not isinstance(launch, dict):
                raise ValueError(
                    f"mcp config: server {server_id!r} entry must be a mapping"
                )
            server = FleetServer(
                id=str(server_id),
                launch=dict(launch),
                backend=backend,
                mode=mode,
                image=launch.get("image"),
                labels={"source": str(cfg_path), "client": client},
                source=str(cfg_path),
            )
            _apply_transport_downgrade(server)
            servers.append(server)
        return cls(servers)

    @classmethod
    def from_manifests(cls, paths: list[str | Path]) -> "Fleet":
        """Zero-config onboarding: one server per manifest file (id = file stem).

        Sets ``manifest_path`` only; no launch/policy. Backs ``fleet infer
        <dir|glob>``.
        """
        servers: list[FleetServer] = []
        for p in paths:
            path = Path(p)
            servers.append(
                FleetServer(
                    id=path.stem,
                    backend="mock",
                    manifest_path=str(path),
                    source=str(path),
                )
            )
        return cls(servers)

    # -------------------------------------------------------------- selection

    def select(self, **labels: str) -> "Fleet":
        """A sub-fleet of servers whose labels match every ``key=value`` given."""
        matched = [
            s
            for s in self.servers
            if all(s.labels.get(k) == v for k, v in labels.items())
        ]
        return Fleet(matched)

    # ------------------------------------------------------------ batch verbs

    def infer_all(
        self,
        *,
        llm: Any = None,
        write: bool = True,
        started_at: float | None = None,
        out_dir: str | Path | None = None,
    ) -> FleetReport:
        """Infer a least-privilege policy per server from its manifest.

        Writes each policy (when ``write``) to ``out_dir/<id>.policy.yaml`` if
        ``out_dir`` is given, else to the server's ``policy_path``, else next
        to the manifest. Never gates — a bad manifest marks that server
        ``skipped`` (exit 4); everything else is ``ok``.

        ``out_dir`` is an additive convenience over the GO-FORWARD signature so
        the CLI's ``-o OUTDIR`` maps cleanly (see api_notes).
        """
        at = time.time() if started_at is None else started_at
        runs: list[FleetServerReport] = []
        for server in self.servers:
            runs.append(self._infer_one(server, llm=llm, write=write, out_dir=out_dir))
        return FleetReport(runs=runs, started_at=at)

    def audit_all(self, *, started_at: float | None = None) -> FleetReport:
        """Classify each server's recorded events against its contract.

        Reporting only — never gates: even outside_contract events leave the
        server ``ok``. Only a bad input (missing/corrupt events or policy)
        marks that server ``error`` (exit 4).
        """
        at = time.time() if started_at is None else started_at
        runs = [self._audit_one(s) for s in self.servers]
        return FleetReport(runs=runs, started_at=at)

    def verify_all(
        self,
        *,
        allow_empty: bool = False,
        started_at: float | None = None,
    ) -> FleetReport:
        """THE CI gate. Per server: rug-pull check (manifest hash) → classify →
        violation / empty / clean.

        Per-server exit: rug_pull ``2``, any outside_contract ``1``, empty
        events (unless ``allow_empty``) or bad input ``4``, else ``0``. The
        aggregate uses §6 precedence.
        """
        at = time.time() if started_at is None else started_at
        runs = [self._verify_one(s, allow_empty=allow_empty) for s in self.servers]
        return FleetReport(runs=runs, started_at=at)

    def run_all(
        self,
        *,
        max_events: int | None = None,
        duration: float | None = None,
        sequential: bool = True,
        started_at: float | None = None,
    ) -> FleetReport:
        """Launch each server on its backend and monitor it live (mock replay in
        v0).

        Sequential only in v0 — production monitoring is the per-server sidecar
        + NDJSON serializer. Manifest drift maps to ``rug_pull`` (2); any
        outside_contract event to ``violation`` (1).
        """
        at = time.time() if started_at is None else started_at
        runs = [
            self._run_one(s, max_events=max_events, duration=duration)
            for s in self.servers
        ]
        return FleetReport(runs=runs, started_at=at)

    # ----------------------------------------------------------- per-server

    def _envelope(
        self,
        server: FleetServer,
        *,
        status: str,
        report: ViolationReport | None = None,
        manifest_hash: str = "",
        policy_hash: str = "",
        error: str | None = None,
    ) -> FleetServerReport:
        """Assemble a FleetServerReport with provenance + redacted fingerprint."""
        try:
            transport = server.transport
        except ValueError:
            transport = "unknown"
        return FleetServerReport(
            server_id=server.id,
            status=status,
            exit_code=_STATUS_EXIT[status],
            report=report,
            manifest_hash=manifest_hash,
            policy_hash=policy_hash,
            backend=server.backend,
            mode=server.mode.value,
            transport=transport,
            labels=dict(server.labels),
            source=server.source,
            launch_fingerprint=server.launch_fingerprint(),
            error=error,
        )

    def _check_env(self, server: FleetServer) -> str | None:
        """Return a skip reason if any launch env var is unresolved or the env
        block is malformed, else None.

        ``resolved_env`` raises :class:`_UnresolvedVar` for a bare ``${VAR}``
        with no value, and a plain :class:`ValueError` when ``launch.env`` is
        not a mapping. ``_UnresolvedVar`` is not a ``ValueError`` subclass, so
        both are caught: the offending server becomes ``skipped`` (exit 4) and
        every sibling server is still evaluated, rather than one malformed
        ``env:`` aborting the whole batch (GO-FORWARD §2.5/§4.5).
        """
        try:
            server.resolved_env()
        except (_UnresolvedVar, ValueError) as exc:
            return str(exc)
        return None

    def _infer_one(
        self,
        server: FleetServer,
        *,
        llm: Any,
        write: bool,
        out_dir: str | Path | None,
    ) -> FleetServerReport:
        skip = self._check_env(server)
        if skip is not None:
            return self._envelope(server, status="skipped", error=skip)
        if not server.manifest_path:
            return self._envelope(
                server, status="error", error="no manifest to infer from"
            )
        try:
            manifest = load_manifest(server.manifest_path)
            policy = infer_policy(manifest, server_id=server.id, llm=llm)
        except Exception as exc:
            return self._envelope(server, status="skipped", error=str(exc))

        if write:
            target = _policy_out_path(server, out_dir)
            try:
                dump_policy(policy, target)
                server.policy_path = str(target)
            except Exception as exc:
                return self._envelope(
                    server,
                    status="error",
                    manifest_hash=policy.manifest_hash,
                    policy_hash=_policy_hash(policy),
                    error=f"failed to write policy: {exc}",
                )
        return self._envelope(
            server,
            status="ok",
            manifest_hash=policy.manifest_hash,
            policy_hash=_policy_hash(policy),
        )

    def _load_contract(
        self, server: FleetServer, *, need_manifest: bool = True
    ) -> tuple[Policy | None, Any, str | None]:
        """Load (policy, manifest) for a server or return (None, None, reason)."""
        if not server.policy_path:
            return None, None, "no policy — cannot verify without a contract"
        if need_manifest and not server.manifest_path:
            return None, None, "no manifest — cannot verify without a contract"
        try:
            policy = load_policy(server.policy_path)
        except Exception as exc:
            return None, None, f"failed to load policy: {exc}"
        manifest = None
        if need_manifest:
            try:
                manifest = load_manifest(server.manifest_path)
            except Exception as exc:
                return None, None, f"failed to load manifest: {exc}"
        return policy, manifest, None

    def _audit_one(self, server: FleetServer) -> FleetServerReport:
        skip = self._check_env(server)
        if skip is not None:
            return self._envelope(server, status="skipped", error=skip)
        policy, manifest, reason = self._load_contract(server)
        if reason is not None:
            return self._envelope(server, status="error", error=reason)
        if not server.events_path:
            return self._envelope(server, status="error", error="no events to audit")
        try:
            events = load_events_jsonl(server.events_path)
            report = classify_events(events, policy, manifest)
        except Exception as exc:
            return self._envelope(server, status="error", error=str(exc))
        # Audit reports, it never gates — always "ok" (exit 0) regardless of
        # what the classification found.
        return self._envelope(
            server,
            status="ok",
            report=report,
            manifest_hash=policy.manifest_hash,
            policy_hash=_policy_hash(policy),
        )

    def _verify_one(
        self, server: FleetServer, *, allow_empty: bool
    ) -> FleetServerReport:
        skip = self._check_env(server)
        if skip is not None:
            return self._envelope(server, status="skipped", error=skip)
        policy, manifest, reason = self._load_contract(server)
        if reason is not None:
            return self._envelope(server, status="error", error=reason)

        # Rug-pull gate first: a changed manifest invalidates the comparison.
        if not verify_manifest_hash(policy, manifest):
            return self._envelope(
                server,
                status="rug_pull",
                manifest_hash=policy.manifest_hash,
                policy_hash=_policy_hash(policy),
                error=(
                    f"manifest drift: policy bound to {policy.manifest_hash} but "
                    f"manifest now hashes to {manifest.hash()}"
                ),
            )

        if not server.events_path:
            return self._envelope(server, status="error", error="no events to verify")
        try:
            events = load_events_jsonl(server.events_path)
        except Exception as exc:
            return self._envelope(server, status="error", error=str(exc))

        if not events and not allow_empty:
            # A monitor that observed nothing must not read as clean.
            return self._envelope(
                server,
                status="skipped",
                manifest_hash=policy.manifest_hash,
                policy_hash=_policy_hash(policy),
                error="no events observed (inconclusive; pass allow_empty)",
            )

        # Classification (and its manifest-implied-cap computation) is guarded
        # the same way _audit_one guards it, so a classifier failure resolves to
        # this one server's status="error" (exit 4) instead of escaping the
        # verify_all comprehension and aborting the whole batch — which would
        # mask a rug_pull(2)/violation(1) on the sibling servers.
        try:
            report = classify_events(events, policy, manifest)
        except Exception as exc:
            return self._envelope(server, status="error", error=str(exc))
        status = "violation" if report.violations else "ok"
        return self._envelope(
            server,
            status=status,
            report=report,
            manifest_hash=policy.manifest_hash,
            policy_hash=_policy_hash(policy),
        )

    def _run_one(
        self,
        server: FleetServer,
        *,
        max_events: int | None,
        duration: float | None,
    ) -> FleetServerReport:
        skip = self._check_env(server)
        if skip is not None:
            return self._envelope(server, status="skipped", error=skip)
        policy, manifest, reason = self._load_contract(server)
        if reason is not None:
            return self._envelope(server, status="error", error=reason)

        try:
            spec = server.to_server_spec(policy)
        except _UnresolvedVar as exc:
            return self._envelope(server, status="skipped", error=str(exc))
        except Exception as exc:
            return self._envelope(server, status="error", error=str(exc))

        try:
            if server.backend == "mock":
                adapter = get_adapter("mock", events=server.events_path or ())
            else:
                adapter = get_adapter(server.backend)
        except Exception as exc:
            return self._envelope(server, status="error", error=str(exc))

        try:
            handle = adapter.start(spec, policy)
            monitor = Monitor(adapter, handle, policy, manifest, server.mode)
        except ManifestDriftError as exc:
            return self._envelope(
                server,
                status="rug_pull",
                manifest_hash=policy.manifest_hash,
                policy_hash=_policy_hash(policy),
                error=str(exc),
            )
        except Exception as exc:
            return self._envelope(server, status="error", error=str(exc))

        try:
            report = monitor.run(max_events=max_events, duration=duration)
        except Exception as exc:
            return self._envelope(server, status="error", error=str(exc))
        finally:
            try:
                adapter.stop(handle)
            except Exception:
                pass

        status = "violation" if report.violations else "ok"
        return self._envelope(
            server,
            status=status,
            report=report,
            manifest_hash=policy.manifest_hash,
            policy_hash=_policy_hash(policy),
        )


# --------------------------------------------------------------------- helpers


def _resolve_dir(base: Path, value: Any) -> Path:
    """Resolve a config dir (relative to the config file) or default to ``base``."""
    if not value:
        return base
    d = Path(str(value))
    return d if d.is_absolute() else base / d


def _resolve_artifact(directory: Path, base: Path, value: Any) -> str | None:
    """Resolve a manifest/policy path relative to its dir (else the config)."""
    if not value:
        return None
    p = Path(str(value))
    if p.is_absolute():
        return str(p)
    return str(directory / p)


def _build_server(
    server_id: str,
    spec: dict,
    defaults: dict,
    base: Path,
    manifest_dir: Path,
    policy_dir: Path,
    *,
    source: str,
) -> FleetServer:
    """Merge defaults under one server spec and resolve its artifact paths."""
    backend = str(spec.get("backend", defaults.get("backend", "docker")))
    mode = _coerce_mode(spec.get("mode", defaults.get("mode", "observe")))
    egress = bool(spec.get("egress_proxy", defaults.get("egress_proxy", False)))
    launch = spec.get("launch") or {}
    if not isinstance(launch, dict):
        raise ValueError(f"server {server_id!r}: 'launch' must be a mapping")
    image = spec.get("image") or launch.get("image")

    # GO-FORWARD §4 rule 1: a docker-backed server MUST pin an image.
    if backend == "docker" and not image:
        raise ValueError(
            f"server {server_id!r}: backend 'docker' requires an 'image' "
            "(pin @sha256; the image is not parsed out of docker-run args)"
        )

    labels = spec.get("labels") or {}
    if not isinstance(labels, dict):
        raise ValueError(f"server {server_id!r}: 'labels' must be a mapping")

    manifest_path = _resolve_artifact(manifest_dir, base, spec.get("manifest"))
    policy_path = _resolve_artifact(policy_dir, base, spec.get("policy"))
    events_path = _resolve_artifact(base, base, spec.get("events"))

    server = FleetServer(
        id=server_id,
        launch=dict(launch),
        backend=backend,
        mode=mode,
        image=str(image) if image else None,
        manifest_path=manifest_path,
        policy_path=policy_path,
        events_path=events_path,
        egress_proxy=egress,
        labels={str(k): str(v) for k, v in labels.items()},
        source=source,
    )
    _apply_transport_downgrade(server)
    return server


def _coerce_mode(value: Any) -> Mode:
    if isinstance(value, Mode):
        return value
    return Mode(str(value))


def _apply_transport_downgrade(server: FleetServer) -> None:
    """GO-FORWARD §4 rule 2: a remote (http/sse) transport can't be sandboxed in
    v0, so force ``mode=observe`` (warn+downgrade)."""
    try:
        transport = server.transport
    except ValueError:
        return  # transport indeterminate here; surfaced when the server is used
    if transport in _REMOTE_TRANSPORTS and server.mode is not Mode.OBSERVE:
        import sys

        print(
            f"[mcp-contract] warning: server {server.id!r} uses transport "
            f"{transport!r} (remote); forcing mode=observe (cannot sandbox a "
            "remote server in v0)",
            file=sys.stderr,
        )
        server.mode = Mode.OBSERVE


def _policy_out_path(server: FleetServer, out_dir: str | Path | None) -> Path:
    """Where ``infer_all`` writes a server's policy."""
    if out_dir is not None:
        return Path(out_dir) / f"{server.id}.policy.yaml"
    if server.policy_path:
        return Path(server.policy_path)
    if server.manifest_path:
        return Path(server.manifest_path).with_name(f"{server.id}.policy.yaml")
    return Path(f"{server.id}.policy.yaml")
