"""Unit tests for Module C (BCM): diffing, monitor, report.

All inputs are inline objects. pie.classifier (Module A) is stubbed —
either via sys.modules (when the real module is not built yet) or via
monkeypatching bcm.contract.classify_tool — so nothing here depends on
Module A's rule set.
"""
from __future__ import annotations

import sys
import types

import pytest


def _ensure_pie_classifier() -> None:
    """Install a stub mcp_contract.pie.classifier if the real one is absent.

    Module C imports classify_tool at module level; during parallel
    builds Module A's file may not exist yet. Tests below monkeypatch
    bcm.contract.classify_tool anyway, so results never depend on which
    implementation got imported.
    """
    try:
        import mcp_contract.pie.classifier  # noqa: F401

        return
    except ImportError:
        pass
    pie = sys.modules.get("mcp_contract.pie")
    if pie is None:
        pie = types.ModuleType("mcp_contract.pie")
        sys.modules["mcp_contract.pie"] = pie
    classifier = types.ModuleType("mcp_contract.pie.classifier")
    classifier.classify_tool = lambda tool: []  # type: ignore[attr-defined]
    pie.classifier = classifier  # type: ignore[attr-defined]
    sys.modules["mcp_contract.pie.classifier"] = classifier


_ensure_pie_classifier()

from mcp_contract.bcm import contract as bcm_contract  # noqa: E402
from mcp_contract.bcm.contract import manifest_implied_caps  # noqa: E402
from mcp_contract.bcm.diff import (  # noqa: E402
    classify_event,
    event_capability,
    host_matches,
    path_matches,
    track_tool_ctx,
)
from mcp_contract.bcm.monitor import ManifestDriftError, Monitor  # noqa: E402
from mcp_contract.bcm.report import (  # noqa: E402
    classify_events,
    dump_events_jsonl,
    load_events_jsonl,
)
from mcp_contract.models import (  # noqa: E402
    BehaviorEvent,
    Capability,
    CapabilityId,
    CapabilityStatus,
    EventClass,
    EventKind,
    Evidence,
    Manifest,
    Mode,
    Policy,
    Severity,
    ToolIR,
)
from mcp_contract.ral.base import ServerHandle, ServerSpec  # noqa: E402


# ---------------------------------------------------------------- helpers


def ev(kind: EventKind, detail: dict, ts: float = 0.0, **kw) -> BehaviorEvent:
    return BehaviorEvent(ts=ts, kind=kind, detail=detail, **kw)


def cap(
    cap_id: CapabilityId,
    status: CapabilityStatus,
    values: list[str] | None = None,
) -> Capability:
    return Capability(id=cap_id, status=status, values=list(values or []))


def full_policy(
    granted: list[Capability], manifest_hash: str = "sha256:test"
) -> Policy:
    """Policy with the given caps plus explicit denied for the rest."""
    present = {c.id for c in granted}
    caps = list(granted) + [
        Capability(id=cid, status=CapabilityStatus.DENIED)
        for cid in CapabilityId
        if cid not in present
    ]
    return Policy(server_id="test-server", manifest_hash=manifest_hash, caps=caps)


def fs_manifest() -> Manifest:
    return Manifest(
        server_name="filesystem",
        tools=[ToolIR(name="read_file", description="Read a file under /data")],
    )


def fs_stub_classify(tool: ToolIR) -> list[Capability]:
    """Stand-in for pie.classifier.classify_tool: fs-only server."""
    if tool.name == "read_file":
        return [
            Capability(
                id=CapabilityId.FS_READ,
                status=CapabilityStatus.INFERRED,
                values=["/data"],
                evidence=[Evidence(tool="read_file", source="param", detail="path")],
            )
        ]
    return []


class FakeAdapter:
    """Minimal inline adapter; Module D's MockAdapter is not used here."""

    name = "fake"

    def __init__(self, events: list[BehaviorEvent]) -> None:
        self._events = list(events)
        self.blocked: list[BehaviorEvent] = []

    def event_stream(self, handle: ServerHandle):
        yield from self._events

    def block(self, handle: ServerHandle, event: BehaviorEvent) -> None:
        self.blocked.append(event)


def make_handle() -> ServerHandle:
    return ServerHandle(
        id="h1", backend="fake", spec=ServerSpec(server_id="test-server")
    )


def exfil_events() -> list[BehaviorEvent]:
    """mcp.call + in-policy fs.open, then a net.connect exfil attempt."""
    return [
        ev(EventKind.MCP_CALL, {"tool": "read_file"}, ts=1.0),
        ev(EventKind.FS_OPEN, {"path": "/data/notes.txt", "mode": "r"}, ts=2.0),
        ev(EventKind.NET_CONNECT, {"host": "evil.example.com", "port": 443}, ts=3.0),
    ]


# ------------------------------------------------------------ host matching


def test_host_suffix_wildcard_matches_subdomain_not_apex():
    assert host_matches("api.github.com", ["*.github.com"])
    assert host_matches("a.b.github.com", ["*.github.com"])
    assert not host_matches("github.com", ["*.github.com"])
    assert not host_matches("evilgithub.com", ["*.github.com"])


def test_host_exact_case_insensitive_and_global_wildcard():
    assert host_matches("API.GitHub.COM", ["api.github.com"])
    assert host_matches("api.github.com", ["*.GITHUB.com"])
    assert host_matches("anything.example", ["*"])
    assert host_matches("10.0.0.5", ["10.0.0.5"])
    assert not host_matches("api.github.com", [])
    assert not host_matches("api.github.com", ["api.github.io"])


# ------------------------------------------------------------ path matching


def test_path_prefix_trap_data_vs_database():
    assert path_matches("/data", ["/data"])
    assert path_matches("/data/x/y.txt", ["/data"])
    assert not path_matches("/database", ["/data"])
    assert not path_matches("/database/creds.txt", ["/data"])


def test_path_normalization_and_root():
    assert path_matches("/data/./sub/../notes.txt", ["/data"])
    assert not path_matches("/data/../etc/passwd", ["/data"])
    assert path_matches("/tmp/x", ["/tmp/"])
    assert path_matches("./repo/file", ["./repo"])
    assert path_matches("/anything/at/all", ["/"])
    assert not path_matches("/other", [])


# --------------------------------------------------- event -> capability map


def test_event_capability_net_prefers_host_over_ip():
    e = ev(EventKind.NET_CONNECT, {"host": "api.github.com", "ip": "1.2.3.4"})
    assert event_capability(e) == (CapabilityId.NET_HTTP, "api.github.com")
    e = ev(EventKind.NET_CONNECT, {"ip": "1.2.3.4", "port": 443})
    assert event_capability(e) == (CapabilityId.NET_HTTP, "1.2.3.4")


def test_event_capability_fs_modes():
    r = ev(EventKind.FS_OPEN, {"path": "/data/a", "mode": "r"})
    assert event_capability(r) == (CapabilityId.FS_READ, "/data/a")
    for mode in ("w", "a", "rw"):
        e = ev(EventKind.FS_OPEN, {"path": "/data/a", "mode": mode})
        assert event_capability(e) == (CapabilityId.FS_WRITE, "/data/a")


def test_event_capability_fs_unknown_modes_fail_closed_to_write():
    # 'r+'/'x' (and anything unrecognized) permit writing: they must map to
    # fs.write, never sneak in as fs.read.
    for mode in ("r+", "rb+", "r+b", "x", "xb", "w+", ""):
        e = ev(EventKind.FS_OPEN, {"path": "/data/a", "mode": mode})
        assert event_capability(e) == (CapabilityId.FS_WRITE, "/data/a"), mode
    # benign recorder variants of read-only stay reads
    for mode in ("rb", "rt", "R"):
        e = ev(EventKind.FS_OPEN, {"path": "/data/a", "mode": mode})
        assert event_capability(e) == (CapabilityId.FS_READ, "/data/a"), mode


def test_write_capable_mode_under_read_only_grant_is_outside_contract():
    policy = full_policy(
        [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])]
    )
    manifest_caps = [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])]
    for mode in ("r+", "x"):
        e = ev(EventKind.FS_OPEN, {"path": "/data/config", "mode": mode})
        assert (
            classify_event(e, policy, manifest_caps) == EventClass.OUTSIDE_CONTRACT
        ), mode


def test_event_capability_proc_basename():
    e = ev(EventKind.PROC_SPAWN, {"argv": ["/bin/bash", "-c", "ls"]})
    assert event_capability(e) == (CapabilityId.PROC_EXEC, "bash")
    e = ev(EventKind.PROC_SPAWN, {"cmd": "/usr/bin/python3 script.py"})
    assert event_capability(e) == (CapabilityId.PROC_EXEC, "python3")


def test_event_capability_env_and_context_kinds():
    e = ev(EventKind.ENV_READ, {"var": "GITHUB_TOKEN"})
    assert event_capability(e) == (CapabilityId.ENV, "GITHUB_TOKEN")
    assert event_capability(ev(EventKind.MCP_CALL, {"tool": "read_file"})) is None
    assert event_capability(ev(EventKind.SYSCALL, {"group": "io"})) is None


# ------------------------------------------------------------ classification


def test_inferred_cap_event_is_within_policy():
    policy = full_policy(
        [cap(CapabilityId.NET_HTTP, CapabilityStatus.INFERRED, ["api.github.com"])]
    )
    manifest_caps = [
        cap(CapabilityId.NET_HTTP, CapabilityStatus.INFERRED, ["api.github.com"])
    ]
    e = ev(EventKind.NET_CONNECT, {"host": "api.github.com"})
    assert classify_event(e, policy, manifest_caps) == EventClass.WITHIN_POLICY


def test_needs_review_cap_event_is_within_manifest_not_policy():
    # needs_review is manifest-implied but NOT granted -> bucket 2.
    policy = full_policy(
        [cap(CapabilityId.NET_HTTP, CapabilityStatus.NEEDS_REVIEW, ["*"])]
    )
    manifest_caps = [cap(CapabilityId.NET_HTTP, CapabilityStatus.NEEDS_REVIEW, ["*"])]
    e = ev(EventKind.NET_CONNECT, {"host": "api.github.com"})
    assert classify_event(e, policy, manifest_caps) == EventClass.WITHIN_MANIFEST


def test_undeclared_class_is_outside_contract():
    policy = full_policy(
        [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])]
    )
    manifest_caps = [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])]
    e = ev(EventKind.NET_CONNECT, {"host": "evil.example.com"})
    assert classify_event(e, policy, manifest_caps) == EventClass.OUTSIDE_CONTRACT


def test_prefix_trap_classification():
    policy = full_policy(
        [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])]
    )
    manifest_caps = [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])]
    inside = ev(EventKind.FS_OPEN, {"path": "/data/notes.txt", "mode": "r"})
    trap = ev(EventKind.FS_OPEN, {"path": "/database/creds", "mode": "r"})
    assert classify_event(inside, policy, manifest_caps) == EventClass.WITHIN_POLICY
    assert classify_event(trap, policy, manifest_caps) == EventClass.OUTSIDE_CONTRACT


def test_suffix_wildcard_classification():
    policy = full_policy(
        [cap(CapabilityId.NET_HTTP, CapabilityStatus.INFERRED, ["*.github.com"])]
    )
    manifest_caps = [
        cap(CapabilityId.NET_HTTP, CapabilityStatus.INFERRED, ["*.github.com"])
    ]
    sub = ev(EventKind.NET_CONNECT, {"host": "api.github.com"})
    apex = ev(EventKind.NET_CONNECT, {"host": "github.com"})
    assert classify_event(sub, policy, manifest_caps) == EventClass.WITHIN_POLICY
    # apex is not matched by the suffix wildcard; still manifest-implied
    # here because the implied values contain the pattern only -> falls
    # through both value checks -> outside.
    assert classify_event(apex, policy, manifest_caps) == EventClass.OUTSIDE_CONTRACT


def test_proc_exec_empty_values_is_class_level_grant():
    policy = full_policy([cap(CapabilityId.PROC_EXEC, CapabilityStatus.INFERRED, [])])
    e = ev(EventKind.PROC_SPAWN, {"argv": ["/usr/bin/git", "status"]})
    assert classify_event(e, policy, []) == EventClass.WITHIN_POLICY


def test_net_empty_values_grants_nothing():
    policy = full_policy([cap(CapabilityId.NET_HTTP, CapabilityStatus.INFERRED, [])])
    e = ev(EventKind.NET_CONNECT, {"host": "api.github.com"})
    assert classify_event(e, policy, []) == EventClass.OUTSIDE_CONTRACT


def test_manifest_class_level_values_match_anything():
    # Implied values [] (class-level / unknown scope) match any value.
    policy = full_policy([])
    manifest_caps = [cap(CapabilityId.FS_WRITE, CapabilityStatus.NEEDS_REVIEW, [])]
    e = ev(EventKind.FS_OPEN, {"path": "/anywhere/at/all", "mode": "w"})
    assert classify_event(e, policy, manifest_caps) == EventClass.WITHIN_MANIFEST


def test_env_value_matching():
    policy = full_policy(
        [cap(CapabilityId.ENV, CapabilityStatus.INFERRED, ["GITHUB_TOKEN"])]
    )
    manifest_caps = [
        cap(CapabilityId.ENV, CapabilityStatus.INFERRED, ["GITHUB_TOKEN"])
    ]
    ok = ev(EventKind.ENV_READ, {"var": "GITHUB_TOKEN"})
    bad = ev(EventKind.ENV_READ, {"var": "AWS_SECRET_ACCESS_KEY"})
    assert classify_event(ok, policy, manifest_caps) == EventClass.WITHIN_POLICY
    assert classify_event(bad, policy, manifest_caps) == EventClass.OUTSIDE_CONTRACT


def test_env_class_level_grant_is_star_not_empty():
    # values ["*"] is the class-level env grant; empty values grant nothing
    # (fail closed), the event stays manifest-implied at best.
    star = full_policy([cap(CapabilityId.ENV, CapabilityStatus.INFERRED, ["*"])])
    empty = full_policy([cap(CapabilityId.ENV, CapabilityStatus.INFERRED, [])])
    manifest_caps = [cap(CapabilityId.ENV, CapabilityStatus.NEEDS_REVIEW, [])]
    e = ev(EventKind.ENV_READ, {"var": "ANY_VAR_AT_ALL"})
    assert classify_event(e, star, manifest_caps) == EventClass.WITHIN_POLICY
    assert classify_event(e, empty, manifest_caps) == EventClass.WITHIN_MANIFEST


def test_syscall_and_mcp_call_are_within_policy():
    policy = full_policy([])
    assert (
        classify_event(ev(EventKind.SYSCALL, {"group": "io"}), policy, [])
        == EventClass.WITHIN_POLICY
    )
    assert (
        classify_event(ev(EventKind.MCP_CALL, {"tool": "x"}), policy, [])
        == EventClass.WITHIN_POLICY
    )


# ----------------------------------------------------------- tool_ctx track


def test_track_tool_ctx_stamps_and_preserves():
    call = ev(EventKind.MCP_CALL, {"tool": "read_file"})
    plain = ev(EventKind.FS_OPEN, {"path": "/data/a", "mode": "r"})
    explicit = ev(
        EventKind.FS_OPEN, {"path": "/data/b", "mode": "r"}, tool_ctx="other_tool"
    )
    ctx = track_tool_ctx(call, None)
    assert ctx == "read_file" and call.tool_ctx == "read_file"
    ctx = track_tool_ctx(plain, ctx)
    assert plain.tool_ctx == "read_file"
    ctx = track_tool_ctx(explicit, ctx)
    assert explicit.tool_ctx == "other_tool"
    assert ctx == "read_file"


# ------------------------------------------------------ manifest_implied_caps


def test_manifest_implied_caps_merges_per_class(monkeypatch):
    def stub(tool: ToolIR) -> list[Capability]:
        if tool.name == "list_issues":
            return [
                Capability(
                    id=CapabilityId.NET_HTTP,
                    status=CapabilityStatus.INFERRED,
                    values=["api.github.com"],
                    evidence=[Evidence(tool="list_issues", source="description", detail="url")],
                )
            ]
        if tool.name == "fetch":
            return [
                Capability(
                    id=CapabilityId.NET_HTTP,
                    status=CapabilityStatus.NEEDS_REVIEW,
                    values=["*"],
                    evidence=[Evidence(tool="fetch", source="param", detail="url param")],
                )
            ]
        if tool.name == "read_file":
            return [
                Capability(
                    id=CapabilityId.FS_READ,
                    status=CapabilityStatus.NEEDS_REVIEW,
                    values=[],
                )
            ]
        return []

    monkeypatch.setattr(bcm_contract, "classify_tool", stub)
    manifest = Manifest(
        server_name="mixed",
        tools=[ToolIR(name="list_issues"), ToolIR(name="fetch"), ToolIR(name="read_file")],
    )
    caps = manifest_implied_caps(manifest)
    by_id = {c.id: c for c in caps}
    assert set(by_id) == {CapabilityId.NET_HTTP, CapabilityId.FS_READ}

    net = by_id[CapabilityId.NET_HTTP]
    # mixed statuses -> needs_review; concrete union plus "*" for the
    # scope-unknown net signal
    assert net.status == CapabilityStatus.NEEDS_REVIEW
    assert set(net.values) == {"api.github.com", "*"}
    assert len(net.evidence) == 2

    fs = by_id[CapabilityId.FS_READ]
    # scope-unknown fs signal adds no "*": class-level stays empty values
    assert fs.status == CapabilityStatus.NEEDS_REVIEW
    assert fs.values == []


def test_manifest_implied_class_level_survives_merge_with_concrete_values(
    monkeypatch,
):
    """A scope-unknown fs/env signal must not be swallowed by concrete values.

    One tool contributes a concrete fs.read path, another a class-level
    (empty-values) fs.read signal: the merged implied cap must keep the
    class-level marker so events from the class-level tool stay in bucket 2
    (within_manifest_not_policy), not bucket 3 — while an undeclared class
    (net) still lands outside_contract.
    """

    def stub(tool: ToolIR) -> list[Capability]:
        if tool.name == "read_config":
            return [
                Capability(
                    id=CapabilityId.FS_READ,
                    status=CapabilityStatus.INFERRED,
                    values=["/etc/app/config"],
                )
            ]
        if tool.name == "read_file":
            return [
                Capability(
                    id=CapabilityId.FS_READ,
                    status=CapabilityStatus.NEEDS_REVIEW,
                    values=[],
                )
            ]
        return []

    monkeypatch.setattr(bcm_contract, "classify_tool", stub)
    manifest = Manifest(
        server_name="mixed-fs",
        tools=[ToolIR(name="read_config"), ToolIR(name="read_file")],
    )
    caps = manifest_implied_caps(manifest)
    (fs,) = caps
    assert fs.id == CapabilityId.FS_READ
    assert fs.values == []  # class-level marker survives the merge

    policy = full_policy([])
    outside_path = ev(EventKind.FS_OPEN, {"path": "/home/user/notes.txt", "mode": "r"})
    assert classify_event(outside_path, policy, caps) == EventClass.WITHIN_MANIFEST
    net = ev(EventKind.NET_CONNECT, {"host": "evil.example.com"})
    assert classify_event(net, policy, caps) == EventClass.OUTSIDE_CONTRACT


def test_manifest_implied_caps_all_inferred_stays_inferred(monkeypatch):
    def stub(tool: ToolIR) -> list[Capability]:
        return [
            Capability(
                id=CapabilityId.FS_READ,
                status=CapabilityStatus.INFERRED,
                values=["/data"],
            )
        ]

    monkeypatch.setattr(bcm_contract, "classify_tool", stub)
    manifest = Manifest(
        server_name="fs", tools=[ToolIR(name="a"), ToolIR(name="b")]
    )
    caps = manifest_implied_caps(manifest)
    assert len(caps) == 1
    assert caps[0].status == CapabilityStatus.INFERRED
    assert caps[0].values == ["/data"]


# ----------------------------------------------------------------- monitor


def test_monitor_raises_on_manifest_drift(monkeypatch):
    monkeypatch.setattr(bcm_contract, "classify_tool", fs_stub_classify)
    manifest = fs_manifest()
    policy = full_policy([], manifest_hash="sha256:stale")
    with pytest.raises(ManifestDriftError) as excinfo:
        Monitor(FakeAdapter([]), make_handle(), policy, manifest, Mode.OBSERVE)
    assert excinfo.value.expected == "sha256:stale"
    assert excinfo.value.actual == manifest.hash()
    # allow_drift bypasses the rug-pull gate
    Monitor(
        FakeAdapter([]), make_handle(), policy, manifest, Mode.OBSERVE,
        allow_drift=True,
    )


def test_monitor_fs_server_net_event_is_critical(monkeypatch):
    # The core scenario: an fs server's stream contains a net.connect.
    monkeypatch.setattr(bcm_contract, "classify_tool", fs_stub_classify)
    manifest = fs_manifest()
    policy = full_policy(
        [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])],
        manifest_hash=manifest.hash(),
    )
    adapter = FakeAdapter(exfil_events())
    report = Monitor(
        adapter, make_handle(), policy, manifest, Mode.OBSERVE
    ).run()

    assert report.mode == Mode.OBSERVE
    assert report.severity == Severity.CRITICAL
    counts = report.counts()
    assert counts[EventClass.WITHIN_POLICY.value] == 2  # mcp.call + fs.open
    assert counts[EventClass.OUTSIDE_CONTRACT.value] == 1
    (violation,) = report.violations
    assert violation.kind == EventKind.NET_CONNECT
    # tool_ctx tracked from the preceding mcp.call
    assert violation.tool_ctx == "read_file"
    # observe mode never blocks
    assert adapter.blocked == []


def test_monitor_enforce_blocks_only_outside_contract(monkeypatch):
    monkeypatch.setattr(bcm_contract, "classify_tool", fs_stub_classify)
    manifest = fs_manifest()
    policy = full_policy(
        [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])],
        manifest_hash=manifest.hash(),
    )
    adapter = FakeAdapter(exfil_events())
    alerts: list[BehaviorEvent] = []
    report = Monitor(
        adapter, make_handle(), policy, manifest, Mode.ENFORCE,
        on_alert=alerts.append,
    ).run()

    assert len(adapter.blocked) == 1
    assert adapter.blocked[0].kind == EventKind.NET_CONNECT
    assert alerts == adapter.blocked  # enforce also alerts
    assert report.severity == Severity.CRITICAL


def test_monitor_alert_mode_alerts_without_blocking(monkeypatch):
    monkeypatch.setattr(bcm_contract, "classify_tool", fs_stub_classify)
    manifest = fs_manifest()
    policy = full_policy(
        [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])],
        manifest_hash=manifest.hash(),
    )
    adapter = FakeAdapter(exfil_events())
    alerts: list[BehaviorEvent] = []
    Monitor(
        adapter, make_handle(), policy, manifest, Mode.ALERT,
        on_alert=alerts.append,
    ).run()
    assert len(alerts) == 1
    assert alerts[0].kind == EventKind.NET_CONNECT
    assert adapter.blocked == []


def test_monitor_default_alert_prints_to_stderr(monkeypatch, capsys):
    monkeypatch.setattr(bcm_contract, "classify_tool", fs_stub_classify)
    manifest = fs_manifest()
    policy = full_policy([], manifest_hash=manifest.hash())
    adapter = FakeAdapter(
        [ev(EventKind.NET_CONNECT, {"host": "evil.example.com"}, ts=1.0)]
    )
    Monitor(adapter, make_handle(), policy, manifest, Mode.ALERT).run()
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert "outside_contract" in err
    assert "evil.example.com" in err


def test_monitor_max_events_stops_early(monkeypatch):
    monkeypatch.setattr(bcm_contract, "classify_tool", fs_stub_classify)
    manifest = fs_manifest()
    policy = full_policy(
        [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])],
        manifest_hash=manifest.hash(),
    )
    report = Monitor(
        FakeAdapter(exfil_events()), make_handle(), policy, manifest, Mode.OBSERVE
    ).run(max_events=2)
    assert len(report.events) == 2


class BlockingAdapter:
    """Yields one event, then blocks like a quiet-but-alive container."""

    name = "blocking"

    def event_stream(self, handle: ServerHandle):
        import time as _time

        yield ev(EventKind.FS_OPEN, {"path": "/data/a", "mode": "r"}, ts=1.0)
        while True:  # never yields again, never ends
            _time.sleep(0.05)

    def block(self, handle: ServerHandle, event: BehaviorEvent) -> None:
        pass


def test_monitor_duration_returns_even_when_stream_blocks(monkeypatch):
    # The deadline must be enforced while the adapter's generator is
    # blocking, not only after it yields — a silent server must not make
    # run(duration=N) hang forever.
    import time as _time

    monkeypatch.setattr(bcm_contract, "classify_tool", fs_stub_classify)
    manifest = fs_manifest()
    policy = full_policy(
        [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])],
        manifest_hash=manifest.hash(),
    )
    monitor = Monitor(
        BlockingAdapter(), make_handle(), policy, manifest, Mode.OBSERVE
    )
    started = _time.monotonic()
    report = monitor.run(duration=0.2)
    elapsed = _time.monotonic() - started
    assert elapsed < 2.0, f"run() blocked for {elapsed:.1f}s past its deadline"
    assert len(report.events) == 1


# ------------------------------------------------------------------ report


def test_classify_events_offline_matches_monitor(monkeypatch):
    monkeypatch.setattr(bcm_contract, "classify_tool", fs_stub_classify)
    manifest = fs_manifest()
    policy = full_policy(
        [cap(CapabilityId.FS_READ, CapabilityStatus.INFERRED, ["/data"])],
        manifest_hash=manifest.hash(),
    )
    events = exfil_events()
    report = classify_events(events, policy, manifest)

    assert report.mode == Mode.OBSERVE
    assert report.server_id == "test-server"
    assert report.manifest_hash == policy.manifest_hash
    assert report.severity == Severity.CRITICAL
    # classification set in place, tool_ctx tracked
    assert events[1].classification == EventClass.WITHIN_POLICY
    assert events[2].classification == EventClass.OUTSIDE_CONTRACT
    assert events[2].tool_ctx == "read_file"


def test_classify_events_needs_review_is_warning(monkeypatch):
    def stub(tool: ToolIR) -> list[Capability]:
        return [
            Capability(
                id=CapabilityId.NET_HTTP,
                status=CapabilityStatus.NEEDS_REVIEW,
                values=["*"],
            )
        ]

    monkeypatch.setattr(bcm_contract, "classify_tool", stub)
    manifest = Manifest(server_name="fetch", tools=[ToolIR(name="fetch")])
    policy = full_policy(
        [cap(CapabilityId.NET_HTTP, CapabilityStatus.NEEDS_REVIEW, ["*"])],
        manifest_hash=manifest.hash(),
    )
    events = [ev(EventKind.NET_CONNECT, {"host": "example.com"}, ts=1.0)]
    report = classify_events(events, policy, manifest)
    assert events[0].classification == EventClass.WITHIN_MANIFEST
    assert report.severity == Severity.WARNING


def test_events_jsonl_round_trip(tmp_path):
    events = [
        ev(EventKind.MCP_CALL, {"tool": "read_file"}, ts=1.0),
        BehaviorEvent(
            ts=2.5,
            kind=EventKind.NET_CONNECT,
            detail={"host": "evil.example.com", "port": 443},
            tool_ctx="read_file",
            classification=EventClass.OUTSIDE_CONTRACT,
            backend="fake",
        ),
    ]
    path = tmp_path / "events.jsonl"
    dump_events_jsonl(events, path)
    loaded = load_events_jsonl(path)
    assert len(loaded) == 2
    assert loaded[0].kind == EventKind.MCP_CALL
    assert loaded[0].tool_ctx is None
    assert loaded[1].to_dict() == events[1].to_dict()


def test_load_events_jsonl_skips_blank_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"ts": 1.0, "kind": "env.read", "detail": {"var": "HOME"}}\n'
        "\n"
        '{"ts": 2.0, "kind": "syscall", "detail": {"group": "io"}}\n',
        encoding="utf-8",
    )
    loaded = load_events_jsonl(path)
    assert [e.kind for e in loaded] == [EventKind.ENV_READ, EventKind.SYSCALL]


def test_load_events_jsonl_unknown_kind_is_informational(tmp_path, capsys):
    # DESIGN shared semantics: unknown kinds are informational in v0 —
    # a foreign recorder's extra kind must not abort the whole audit.
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"ts": 1.0, "kind": "ptrace.attach", "detail": {"pid": 7}}\n'
        '{"ts": 2.0, "kind": "env.read", "detail": {"var": "HOME"}}\n',
        encoding="utf-8",
    )
    loaded = load_events_jsonl(path)
    assert [e.kind for e in loaded] == [EventKind.SYSCALL, EventKind.ENV_READ]
    assert loaded[0].detail["group"] == "ptrace.attach"  # original kind kept
    assert "unknown event kind" in capsys.readouterr().err
    policy = full_policy([])
    assert classify_event(loaded[0], policy, []) == EventClass.WITHIN_POLICY


def test_load_events_jsonl_malformed_line_raises_with_context(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        '{"ts": 1.0, "kind": "env.read", "detail": {"var": "HOME"}}\n'
        "GARBAGE{{{\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"bad\.jsonl:2"):
        load_events_jsonl(path)
    # missing kind is malformed, not merely foreign
    path.write_text('{"ts": 1.0, "detail": {}}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="kind"):
        load_events_jsonl(path)
