"""Tests for the RAL adapters: MockAdapter fully, DockerAdapter dockerless.

Docker unit tests only exercise the pure pieces (`translate_policy_args`,
the /proc/net/tcp and `docker top` parsers). One integration test actually
talks to docker and is double-gated on the binary being present AND
MCP_CONTRACT_DOCKER_TESTS=1.
"""
from __future__ import annotations

import json
import os
import shutil

import pytest

from mcp_contract.models import (
    BehaviorEvent,
    Capability,
    CapabilityId,
    CapabilityStatus,
    EventKind,
    Policy,
)
from mcp_contract.ral import RuntimeAdapter, ServerSpec, SupportLevel, get_adapter
from mcp_contract.ral.docker import (
    DockerAdapter,
    _decode_proc_addr,
    parse_docker_top,
    parse_proc_net_tcp,
    translate_policy_args,
)
from mcp_contract.ral.mock import MockAdapter

BASE_FLAGS = [
    "--rm",
    "-d",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--pids-limit",
    "64",
]


def _cap(
    cap_id: CapabilityId,
    status: CapabilityStatus = CapabilityStatus.INFERRED,
    values: list[str] | None = None,
) -> Capability:
    return Capability(id=cap_id, status=status, values=list(values or []))


def _policy(*caps: Capability) -> Policy:
    return Policy(server_id="srv", manifest_hash="sha256:0", caps=list(caps))


def _event(kind: EventKind, detail: dict, ts: float = 1.0) -> BehaviorEvent:
    return BehaviorEvent(ts=ts, kind=kind, detail=detail)


def _flag_values(args: list[str], flag: str) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == flag]


# ---------------------------------------------------------------------------
# MockAdapter
# ---------------------------------------------------------------------------


class TestMockAdapter:
    def test_capabilities_everything_enforce(self) -> None:
        caps = MockAdapter().capabilities()
        assert caps.network == SupportLevel.ENFORCE
        assert caps.filesystem == SupportLevel.ENFORCE
        assert caps.process == SupportLevel.ENFORCE
        assert caps.syscall == SupportLevel.ENFORCE
        assert caps.boot_time_policy is True
        assert caps.runtime_block is True

    def test_start_records_spec_and_policy(self) -> None:
        adapter = MockAdapter()
        spec = ServerSpec(server_id="srv")
        policy = _policy()
        handle = adapter.start(spec, policy)
        assert handle.backend == "mock"
        assert handle.spec is spec
        assert adapter.started == [(spec, policy)]
        other = adapter.start(spec, policy)
        assert other.id != handle.id

    def test_event_stream_replays_in_order(self) -> None:
        events = [
            _event(EventKind.MCP_CALL, {"tool": "read_file"}, ts=1.0),
            _event(EventKind.FS_OPEN, {"path": "/data/a", "mode": "r"}, ts=2.0),
            _event(EventKind.NET_CONNECT, {"host": "evil.example.com"}, ts=3.0),
        ]
        adapter = MockAdapter(events)
        handle = adapter.start(ServerSpec(server_id="srv"), _policy())
        assert list(adapter.event_stream(handle)) == events
        # Replay is repeatable — the stream is not consumed.
        assert list(adapter.event_stream(handle)) == events

    def test_events_from_jsonl_path(self, tmp_path) -> None:
        lines = [
            {"ts": 1.0, "kind": "mcp.call", "detail": {"tool": "read_file"}},
            "",  # blank lines are skipped
            {
                "ts": 2.0,
                "kind": "net.connect",
                "detail": {"host": "evil.example.com", "port": 443},
                "tool_ctx": "read_file",
            },
        ]
        path = tmp_path / "events.jsonl"
        path.write_text(
            "\n".join(json.dumps(l) if l else "" for l in lines) + "\n",
            encoding="utf-8",
        )
        adapter = MockAdapter(path)
        assert len(adapter.events) == 2
        assert adapter.events[0].kind == EventKind.MCP_CALL
        assert adapter.events[1].kind == EventKind.NET_CONNECT
        assert adapter.events[1].tool_ctx == "read_file"
        assert adapter.events[1].detail["host"] == "evil.example.com"
        # str path works too
        assert len(MockAdapter(str(path)).events) == 2

    def test_block_collects_events(self) -> None:
        adapter = MockAdapter()
        handle = adapter.start(ServerSpec(server_id="srv"), _policy())
        ev = _event(EventKind.NET_CONNECT, {"host": "evil.example.com"})
        adapter.block(handle, ev)
        assert adapter.blocked == [ev]

    def test_stop_is_noop(self) -> None:
        adapter = MockAdapter()
        handle = adapter.start(ServerSpec(server_id="srv"), _policy())
        adapter.stop(handle)  # must not raise
        assert adapter.stopped == [handle]

    def test_get_adapter_and_protocol(self) -> None:
        adapter = get_adapter("mock", events=[_event(EventKind.SYSCALL, {})])
        assert isinstance(adapter, MockAdapter)
        assert isinstance(adapter, RuntimeAdapter)
        assert len(adapter.events) == 1

    def test_unknown_kind_in_jsonl_is_informational(self, tmp_path, capsys) -> None:
        # Same semantics as bcm.report: a foreign kind must not abort the
        # replay; it becomes an informational syscall event.
        path = tmp_path / "events.jsonl"
        path.write_text(
            '{"ts": 1.0, "kind": "ptrace.attach", "detail": {"pid": 7}}\n'
            '{"ts": 2.0, "kind": "env.read", "detail": {"var": "HOME"}}\n',
            encoding="utf-8",
        )
        adapter = MockAdapter(path)
        assert [e.kind for e in adapter.events] == [
            EventKind.SYSCALL,
            EventKind.ENV_READ,
        ]
        assert adapter.events[0].detail["group"] == "ptrace.attach"
        assert "unknown event kind" in capsys.readouterr().err

    def test_malformed_jsonl_line_raises_with_context(self, tmp_path) -> None:
        path = tmp_path / "bad.jsonl"
        path.write_text("GARBAGE{{{\n", encoding="utf-8")
        with pytest.raises(ValueError, match=r"bad\.jsonl:1"):
            MockAdapter(path)


# ---------------------------------------------------------------------------
# translate_policy_args (pure, no docker needed)
# ---------------------------------------------------------------------------


class TestTranslatePolicyArgs:
    def test_deny_all_policy(self) -> None:
        args = translate_policy_args(_policy(), ServerSpec(server_id="srv"))
        assert args[: len(BASE_FLAGS)] == BASE_FLAGS
        assert _flag_values(args, "--network") == ["none"]
        assert "-v" not in args
        assert "-e" not in args

    def test_granted_net_uses_default_network(self) -> None:
        policy = _policy(_cap(CapabilityId.NET_HTTP, values=["api.github.com"]))
        args = translate_policy_args(policy, ServerSpec(server_id="srv"))
        assert "--network" not in args  # v0 gap: per-host egress needs a proxy

    def test_needs_review_net_is_not_granted(self) -> None:
        policy = _policy(
            _cap(CapabilityId.NET_HTTP, CapabilityStatus.NEEDS_REVIEW, ["*"])
        )
        args = translate_policy_args(policy, ServerSpec(server_id="srv"))
        assert _flag_values(args, "--network") == ["none"]

    def test_fs_mounts_ro_and_rw(self) -> None:
        policy = _policy(
            _cap(CapabilityId.FS_READ, values=["/data"]),
            _cap(CapabilityId.FS_WRITE, values=["/out"]),
        )
        args = translate_policy_args(policy, ServerSpec(server_id="srv"))
        assert _flag_values(args, "-v") == ["/data:/data:ro", "/out:/out:rw"]

    def test_fs_write_wins_over_read_for_same_path(self) -> None:
        policy = _policy(
            _cap(CapabilityId.FS_READ, values=["/data"]),
            _cap(CapabilityId.FS_WRITE, values=["/data/"]),  # normalized to /data
        )
        args = translate_policy_args(policy, ServerSpec(server_id="srv"))
        assert _flag_values(args, "-v") == ["/data:/data:rw"]

    def test_fs_skips_non_absolute_values(self) -> None:
        policy = _policy(
            _cap(CapabilityId.FS_READ, values=["./repo", "relative/x", "/ok"])
        )
        args = translate_policy_args(policy, ServerSpec(server_id="srv"))
        assert _flag_values(args, "-v") == ["/ok:/ok:ro"]

    def test_fs_needs_review_grants_no_mounts(self) -> None:
        policy = _policy(
            _cap(CapabilityId.FS_WRITE, CapabilityStatus.NEEDS_REVIEW, ["/data"])
        )
        args = translate_policy_args(policy, ServerSpec(server_id="srv"))
        assert "-v" not in args

    def test_env_class_level_star_passes_through_all_spec_vars(self) -> None:
        policy = _policy(_cap(CapabilityId.ENV, values=["*"]))
        spec = ServerSpec(server_id="srv", env={"B_VAR": "2", "A_VAR": "1"})
        args = translate_policy_args(policy, spec)
        assert _flag_values(args, "-e") == ["A_VAR", "B_VAR"]

    def test_env_passthrough_only_when_spec_provides_it(self) -> None:
        policy = _policy(
            _cap(CapabilityId.ENV, values=["GITHUB_TOKEN", "MISSING_VAR"])
        )
        spec = ServerSpec(server_id="srv", env={"GITHUB_TOKEN": "t0ken"})
        args = translate_policy_args(policy, spec)
        assert _flag_values(args, "-e") == ["GITHUB_TOKEN"]
        # passthrough form: the secret value never appears in the argv
        assert "t0ken" not in " ".join(args)

    def test_denied_env_not_passed(self) -> None:
        policy = _policy(
            _cap(CapabilityId.ENV, CapabilityStatus.DENIED, ["GITHUB_TOKEN"])
        )
        spec = ServerSpec(server_id="srv", env={"GITHUB_TOKEN": "t"})
        assert "-e" not in translate_policy_args(policy, spec)

    def test_is_deterministic_and_non_mutating(self) -> None:
        policy = _policy(
            _cap(CapabilityId.FS_READ, values=["/b", "/a"]),
            _cap(CapabilityId.ENV, values=["B_VAR", "A_VAR"]),
        )
        spec = ServerSpec(server_id="srv", env={"A_VAR": "1", "B_VAR": "2"})
        first = translate_policy_args(policy, spec)
        assert translate_policy_args(policy, spec) == first
        assert _flag_values(first, "-v") == ["/a:/a:ro", "/b:/b:ro"]
        assert _flag_values(first, "-e") == ["A_VAR", "B_VAR"]
        assert policy.cap(CapabilityId.FS_READ).values == ["/b", "/a"]


# ---------------------------------------------------------------------------
# /proc/net/tcp parsing (pure, no docker needed)
# ---------------------------------------------------------------------------

PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: AB01A8C0:D2C6 5DB8D9AC:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:8124 0100007F:0FA1 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 20 4 30 10 -1
   3: AB01A8C0:D2C7 5DB8D9AC:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 20 4 30 10 -1
"""

PROC_NET_TCP6 = """\
  sl  local_address                         rem_address                         st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22345 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF0000AB01A8C0:9C40 0000000000000000FFFF00005DB8D9AC:0050 01 00000000:00000000 00:00000000 00000000  1000        0 22346 1 0000000000000000 20 4 30 10 -1
   2: B80D012000000000000000000A000000:9C41 B80D012000000000000000000100 0000:1A0A 01 00000000:00000000 00:00000000 00000000  1000        0 22347 1 0000000000000000 20 4 30 10 -1
"""


class TestProcNetTcpParsing:
    def test_decode_ipv4_little_endian(self) -> None:
        assert _decode_proc_addr("0100007F") == "127.0.0.1"
        assert _decode_proc_addr("5DB8D9AC") == "172.217.184.93"

    def test_decode_ipv6_words(self) -> None:
        assert (
            _decode_proc_addr("B80D0120" + "00000000" + "00000000" + "01000000")
            == "2001:db8::1"
        )

    def test_decode_ipv4_mapped_ipv6_collapses(self) -> None:
        assert (
            _decode_proc_addr("00000000" + "00000000" + "FFFF0000" + "5DB8D9AC")
            == "172.217.184.93"
        )

    def test_decode_rejects_garbage(self) -> None:
        assert _decode_proc_addr("XYZ0007F") is None
        assert _decode_proc_addr("0100007") is None
        assert _decode_proc_addr("") is None

    def test_parse_skips_header_listen_loopback_and_dedupes(self) -> None:
        # Only the two identical established remotes survive, deduped to one.
        assert parse_proc_net_tcp(PROC_NET_TCP) == [("172.217.184.93", 443)]

    def test_parse_ipv4_mapped_tcp6(self) -> None:
        endpoints = parse_proc_net_tcp(PROC_NET_TCP6)
        assert ("172.217.184.93", 80) in endpoints
        # the malformed row (split remote address) is skipped, not fatal
        assert len(endpoints) == 1

    def test_parse_concatenated_tcp_and_tcp6(self) -> None:
        endpoints = parse_proc_net_tcp(PROC_NET_TCP + PROC_NET_TCP6)
        assert endpoints == [("172.217.184.93", 443), ("172.217.184.93", 80)]

    def test_parse_empty_and_garbage(self) -> None:
        assert parse_proc_net_tcp("") == []
        assert parse_proc_net_tcp("cat: /proc/net/tcp6: No such file\n") == []

    def test_inbound_connections_to_a_listener_are_not_egress(self) -> None:
        # A serving MCP server: LISTEN on :8080 (row appears AFTER the
        # inbound row — two passes required), one ESTABLISHED inbound
        # client (local port 8080), one ESTABLISHED outbound connection.
        # Only the outbound remote may be reported; reporting the client's
        # address would make every legitimate client a fake violation.
        text = (
            "  sl  local_address rem_address   st junk\n"
            "   0: AB01A8C0:1F90 0F00000A:D2C6 01 0\n"  # inbound (local :8080)
            "   1: 00000000:1F90 00000000:0000 0A 0\n"  # LISTEN :8080
            "   2: AB01A8C0:D2C6 5DB8D9AC:01BB 01 0\n"  # outbound
        )
        assert parse_proc_net_tcp(text) == [("172.217.184.93", 443)]

    def test_short_lived_states_are_still_egress(self) -> None:
        # TIME_WAIT/SYN_SENT/CLOSE_WAIT carry egress evidence of recent or
        # in-flight outbound connections; LISTEN and SYN_RECV do not.
        text = (
            "  sl  local_address rem_address   st junk\n"
            "   0: AB01A8C0:D2C8 04030201:0050 06 0\n"  # TIME_WAIT
            "   1: AB01A8C0:D2C9 08080808:01BB 02 0\n"  # SYN_SENT
            "   2: AB01A8C0:D2CA 07070707:1F40 08 0\n"  # CLOSE_WAIT
            "   3: 00000000:0050 00000000:0000 0A 0\n"  # LISTEN
            "   4: AB01A8C0:1F91 05050505:BEEF 03 0\n"  # SYN_RECV (inbound)
        )
        endpoints = parse_proc_net_tcp(text)
        assert ("1.2.3.4", 80) in endpoints
        assert ("8.8.8.8", 443) in endpoints
        assert ("7.7.7.7", 8000) in endpoints
        assert len(endpoints) == 3


# ---------------------------------------------------------------------------
# docker top parsing (pure, no docker needed)
# ---------------------------------------------------------------------------


class TestDockerTopParsing:
    def test_pid_comm_shape(self) -> None:
        text = "PID                 COMM\n" "4242                node\n" "4300                sh\n"
        assert parse_docker_top(text) == [(4242, "node"), (4300, "sh")]

    def test_default_shape_joins_trailing_cmd(self) -> None:
        text = (
            "UID    PID    PPID   C   STIME   TTY   TIME       CMD\n"
            "root   4242   4200   0   12:00   ?     00:00:00   node server.js --port 80\n"
        )
        assert parse_docker_top(text) == [(4242, "node server.js --port 80")]

    def test_rejects_output_without_pid_column(self) -> None:
        assert parse_docker_top("Error response from daemon: not running\n") == []
        assert parse_docker_top("") == []

    def test_skips_malformed_rows(self) -> None:
        text = "PID   COMM\nnotanumber   node\n77   python\n"
        assert parse_docker_top(text) == [(77, "python")]


# ---------------------------------------------------------------------------
# DockerAdapter — construction only (no docker), plus gated integration
# ---------------------------------------------------------------------------


class TestDockerAdapterUnit:
    def test_get_adapter_docker_construction(self) -> None:
        adapter = get_adapter("docker", poll_interval=0.2)
        assert isinstance(adapter, DockerAdapter)
        assert isinstance(adapter, RuntimeAdapter)
        assert adapter.poll_interval == 0.2
        assert adapter.docker_bin == "docker"

    def test_honest_backend_caps(self) -> None:
        caps = DockerAdapter().capabilities()
        assert caps.network == SupportLevel.OBSERVE  # IPs only; proxy needed
        assert caps.filesystem == SupportLevel.ENFORCE  # boot-time mounts
        assert caps.process == SupportLevel.OBSERVE
        assert caps.syscall == SupportLevel.NONE
        assert caps.boot_time_policy is True
        assert caps.runtime_block is True  # docker kill, coarse

    def test_start_requires_image(self) -> None:
        with pytest.raises(ValueError, match="image"):
            DockerAdapter().start(ServerSpec(server_id="srv"), _policy())

    @staticmethod
    def _result(returncode: int, stdout: str = "", stderr: str = ""):
        import subprocess

        return subprocess.CompletedProcess(
            args=["docker"], returncode=returncode, stdout=stdout, stderr=stderr
        )

    def _handle(self) -> "ServerHandle":
        from mcp_contract.ral.base import ServerHandle

        return ServerHandle(
            id="c0ffee", backend="docker", spec=ServerSpec(server_id="srv")
        )

    def test_running_true_false_from_definitive_inspect(self, monkeypatch) -> None:
        adapter = DockerAdapter(poll_interval=0.01)
        monkeypatch.setattr(
            adapter, "_run", lambda args, env=None: self._result(0, "true\n")
        )
        assert adapter._running("c0ffee") is True
        monkeypatch.setattr(
            adapter, "_run", lambda args, env=None: self._result(0, "false\n")
        )
        assert adapter._running("c0ffee") is False

    def test_running_raises_when_inspect_keeps_failing(self, monkeypatch) -> None:
        # A transient daemon failure must NOT read as "container exited":
        # that would silently end observation of a live server.
        adapter = DockerAdapter(poll_interval=0.01)
        calls: list[list[str]] = []

        def failing(args, env=None):
            calls.append(args)
            return self._result(1, "", "daemon busy")

        monkeypatch.setattr(adapter, "_run", failing)
        with pytest.raises(RuntimeError, match="state unknown"):
            adapter._running("c0ffee")
        assert len(calls) == 3  # retried before giving up loudly

    def test_block_raises_when_kill_fails_and_container_survives(
        self, monkeypatch
    ) -> None:
        adapter = DockerAdapter(poll_interval=0.01)

        def run_stub(args, env=None):
            if args[0] == "kill":
                return self._result(1, "", "transient daemon error")
            assert args[0] == "inspect"
            return self._result(0, "true\n")

        monkeypatch.setattr(adapter, "_run", run_stub)
        with pytest.raises(RuntimeError, match="enforce failed"):
            adapter.block(self._handle(), _event(EventKind.NET_CONNECT, {}))

    def test_block_tolerates_already_exited_container(self, monkeypatch) -> None:
        adapter = DockerAdapter(poll_interval=0.01)

        def run_stub(args, env=None):
            if args[0] == "kill":
                return self._result(1, "", "No such container: c0ffee")
            return self._result(0, "false\n")

        monkeypatch.setattr(adapter, "_run", run_stub)
        adapter.block(self._handle(), _event(EventKind.NET_CONNECT, {}))  # no raise

    def test_stop_raises_after_failed_removal(self, monkeypatch) -> None:
        adapter = DockerAdapter(poll_interval=0.01)
        calls: list[list[str]] = []

        def run_stub(args, env=None):
            calls.append(args)
            return self._result(1, "", "Error response from daemon: busy")

        monkeypatch.setattr(adapter, "_run", run_stub)
        with pytest.raises(RuntimeError, match="rm -f"):
            adapter.stop(self._handle())
        assert len(calls) == 2  # retried once before raising

    def test_stop_tolerates_already_gone_container(self, monkeypatch) -> None:
        adapter = DockerAdapter(poll_interval=0.01)
        monkeypatch.setattr(
            adapter,
            "_run",
            lambda args, env=None: self._result(
                1, "", "Error: No such container: c0ffee"
            ),
        )
        adapter.stop(self._handle())  # no raise


@pytest.mark.skipif(
    shutil.which("docker") is None
    or os.environ.get("MCP_CONTRACT_DOCKER_TESTS") != "1",
    reason="needs the docker binary and MCP_CONTRACT_DOCKER_TESTS=1",
)
def test_docker_adapter_integration_observe_loop() -> None:
    """Start a real container, watch it via the polling loop, tear it down."""
    adapter = DockerAdapter(poll_interval=0.5)
    policy = _policy()  # nothing granted -> --network none, no mounts
    spec = ServerSpec(
        server_id="it", image="alpine:3.20", command=["sleep", "3"]
    )
    handle = adapter.start(spec, policy)
    try:
        assert handle.backend == "docker"
        assert handle.id
        events = list(adapter.event_stream(handle))  # ends when sleep exits
    finally:
        adapter.stop(handle)
    spawns = [e for e in events if e.kind == EventKind.PROC_SPAWN]
    assert spawns, f"expected at least one proc.spawn, got {events!r}"
    assert any("sleep" in str(e.detail.get("cmd", "")) for e in spawns)
    assert all(e.backend == "docker" for e in events)
    # --network none: the polling loop must not report any egress
    assert not [e for e in events if e.kind == EventKind.NET_CONNECT]
