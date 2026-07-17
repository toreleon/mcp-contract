"""End-to-end CLI tests: infer -> approve -> verify on the bundled fixtures.

Everything runs through `mcp_contract.cli.main` in-process (no subprocess).
Stdout carries machine output (YAML/JSON); stderr carries human chatter.
"""
from __future__ import annotations

import http.client
import http.server
import json
import threading
import time
from pathlib import Path

import pytest
import yaml

import mcp_contract.cli as cli_module
from mcp_contract.cli import main
from mcp_contract.models import (
    BehaviorEvent,
    Capability,
    CapabilityId,
    CapabilityStatus,
    Policy,
)
from mcp_contract.policy import dump_policy

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MANIFESTS = FIXTURES / "manifests"
EVENTS = FIXTURES / "events"
FILESYSTEM_MANIFEST = MANIFESTS / "filesystem.json"
CLEAN_EVENTS = EVENTS / "filesystem-clean.jsonl"
EXFIL_EVENTS = EVENTS / "filesystem-exfil.jsonl"


def _caps_by_id(policy_doc: dict) -> dict[str, dict]:
    return {cap["id"]: cap for cap in policy_doc["x-mcp-contract"]["caps"]}


def _approve_filesystem(policy_path: Path) -> None:
    """The v0 human approval step: edit the YAML, flip needs_review -> inferred.

    `x-mcp-contract.caps` is the source of truth for `load_policy`, so only
    that block needs editing.
    """
    doc = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    for cap in doc["x-mcp-contract"]["caps"]:
        if cap["id"] in ("fs.read", "fs.write"):
            cap["status"] = "inferred"
            cap["values"] = ["/data"]
    policy_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _infer_approved_policy(tmp_path: Path) -> Path:
    policy_path = tmp_path / "filesystem.policy.yaml"
    assert main(["infer", str(FILESYSTEM_MANIFEST), "-o", str(policy_path)]) == 0
    _approve_filesystem(policy_path)
    return policy_path


def _tampered_manifest(tmp_path: Path) -> Path:
    """A rug-pull: same server, silently changed tool surface."""
    doc = json.loads(FILESYSTEM_MANIFEST.read_text(encoding="utf-8"))
    doc["tools"][0]["description"] += " Also uploads usage telemetry."
    path = tmp_path / "filesystem-tampered.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# ---------------------------------------------------------------- infer


def test_infer_fetch_reports_net_needs_review(capsys):
    assert main(["infer", str(MANIFESTS / "fetch.json")]) == 0
    out, err = capsys.readouterr()
    net = _caps_by_id(yaml.safe_load(out))["net.http"]
    assert net["status"] == "needs_review"
    assert "*" in net["values"]
    assert "need review" in err
    assert "net.http" in err


def test_infer_lists_all_five_classes_deny_by_default(capsys):
    assert main(["infer", str(MANIFESTS / "fetch.json")]) == 0
    caps = _caps_by_id(yaml.safe_load(capsys.readouterr().out))
    assert set(caps) == {"net.http", "fs.read", "fs.write", "proc.exec", "env"}
    assert caps["proc.exec"]["status"] == "denied"


def test_infer_github_net_inferred(capsys):
    assert main(["infer", str(MANIFESTS / "github.json")]) == 0
    net = _caps_by_id(yaml.safe_load(capsys.readouterr().out))["net.http"]
    assert net["status"] == "inferred"
    assert "api.github.com" in net["values"]


def test_infer_shell_proc_exec_needs_review_never_inferred(capsys):
    assert main(["infer", str(MANIFESTS / "shell.json")]) == 0
    proc = _caps_by_id(yaml.safe_load(capsys.readouterr().out))["proc.exec"]
    assert proc["status"] == "needs_review"


def test_infer_slack_env_token_and_net(capsys):
    assert main(["infer", str(MANIFESTS / "slack.json")]) == 0
    caps = _caps_by_id(yaml.safe_load(capsys.readouterr().out))
    assert caps["net.http"]["status"] != "denied"
    assert "slack.com" in caps["net.http"]["values"]
    assert caps["env"]["status"] == "needs_review"
    assert "SLACK_BOT_TOKEN" in caps["env"]["values"]


def test_infer_writes_policy_file(tmp_path, capsys):
    policy_path = tmp_path / "filesystem.policy.yaml"
    assert main(["infer", str(FILESYSTEM_MANIFEST), "-o", str(policy_path)]) == 0
    out, err = capsys.readouterr()
    assert out == ""  # machine output went to the file, not stdout
    assert policy_path.exists()
    caps = _caps_by_id(yaml.safe_load(policy_path.read_text(encoding="utf-8")))
    assert caps["fs.read"]["status"] == "needs_review"
    assert caps["fs.write"]["status"] == "needs_review"


# ---------------------------------------------------------------- verify


def test_verify_clean_events_pass(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    rc = main(
        ["verify", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--events", str(CLEAN_EVENTS)]
    )
    out, err = capsys.readouterr()
    assert rc == 0
    counts = json.loads(out.strip().splitlines()[-1])
    assert counts["outside_contract"] == 0
    assert "VERIFY OK" in err


def test_verify_exfil_events_fail(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    rc = main(
        ["verify", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--events", str(EXFIL_EVENTS)]
    )
    out, err = capsys.readouterr()
    assert rc == 1
    counts = json.loads(out.strip().splitlines()[-1])
    assert counts["outside_contract"] == 1
    assert "VERIFY FAIL" in err


def test_verify_tampered_manifest_exits_two(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    tampered = _tampered_manifest(tmp_path)
    rc = main(
        ["verify", str(tampered), "--policy", str(policy),
         "--events", str(CLEAN_EVENTS)]
    )
    assert rc == 2
    assert "hash" in capsys.readouterr().err.lower()


def test_verify_missing_events_file_exits_four_not_two(tmp_path, capsys):
    # A typo'd path is an operational error: it must not collide with the
    # rug-pull code (2) or the violation code (1).
    policy = _infer_approved_policy(tmp_path)
    rc = main(
        ["verify", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--events", str(tmp_path / "nope.jsonl")]
    )
    assert rc == 4
    assert "error" in capsys.readouterr().err.lower()


def test_verify_missing_policy_file_exits_four_with_clear_error(tmp_path, capsys):
    # A mistyped --policy must fail as "file not found", not be silently
    # reinterpreted as inline YAML text.
    rc = main(
        ["verify", str(FILESYSTEM_MANIFEST),
         "--policy", str(tmp_path / "polcy.yaml"),
         "--events", str(CLEAN_EVENTS)]
    )
    assert rc == 4
    err = capsys.readouterr().err
    assert "polcy.yaml" in err


def test_verify_corrupt_events_exits_four_not_one(tmp_path, capsys):
    # A garbage JSONL line is a broken pipeline, not a contract violation:
    # it must produce a one-line error and exit 4, never exit 1.
    policy = _infer_approved_policy(tmp_path)
    bad = tmp_path / "bad.jsonl"
    bad.write_text(
        CLEAN_EVENTS.read_text(encoding="utf-8") + "GARBAGE{{{\n",
        encoding="utf-8",
    )
    rc = main(
        ["verify", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--events", str(bad)]
    )
    assert rc == 4
    err = capsys.readouterr().err
    assert "invalid input" in err
    assert "bad.jsonl" in err


def test_verify_scalar_values_policy_fails_closed(tmp_path, capsys):
    # The reviewer wrote `values: /data` (scalar, not a list): loading must
    # fail (exit 4) instead of char-splitting into a filesystem-wide grant
    # that lets /etc/passwd reads verify green.
    policy = _infer_approved_policy(tmp_path)
    doc = yaml.safe_load(policy.read_text(encoding="utf-8"))
    for cap in doc["x-mcp-contract"]["caps"]:
        if cap["id"] in ("fs.read", "fs.write"):
            cap["values"] = "/data"  # the natural-looking scalar mistake
    policy.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    rc = main(
        ["verify", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--events", str(CLEAN_EVENTS)]
    )
    assert rc == 4
    assert "values" in capsys.readouterr().err


def test_verify_empty_events_is_inconclusive_unless_allowed(tmp_path, capsys):
    # A monitor that captured nothing must not certify the server as clean.
    policy = _infer_approved_policy(tmp_path)
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    rc = main(
        ["verify", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--events", str(empty)]
    )
    out, err = capsys.readouterr()
    assert rc == 4
    assert "INCONCLUSIVE" in err
    rc = main(
        ["verify", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--events", str(empty), "--allow-empty"]
    )
    assert rc == 0


# ---------------------------------------------------------------- audit


def test_audit_always_exits_zero_and_emits_json(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    capsys.readouterr()  # drop infer chatter
    rc = main(
        ["audit", "--events", str(EXFIL_EVENTS), "--policy", str(policy),
         "--manifest", str(FILESYSTEM_MANIFEST), "--json"]
    )
    out, err = capsys.readouterr()
    assert rc == 0  # audit reports, it never gates
    report = json.loads(out)
    assert report["severity"] == "critical"
    assert report["counts"]["outside_contract"] == 1
    assert "OUTSIDE CONTRACT" in err


# ---------------------------------------------------------------- run (mock)


def test_run_mock_replays_exfil_and_exits_one(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    events_out = tmp_path / "events.jsonl"
    report_out = tmp_path / "report.json"
    rc = main(
        ["run", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--backend", "mock", "--mode", "observe",
         "--events-in", str(EXFIL_EVENTS),
         "--events-out", str(events_out), "--report-out", str(report_out)]
    )
    assert rc == 1
    report = json.loads(report_out.read_text(encoding="utf-8"))
    assert report["severity"] == "critical"
    lines = [
        json.loads(line)
        for line in events_out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(e.get("classification") == "outside_contract" for e in lines)


def test_run_mock_clean_exits_zero(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    rc = main(
        ["run", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--backend", "mock", "--mode", "observe",
         "--events-in", str(CLEAN_EVENTS)]
    )
    assert rc == 0


def test_run_mock_drift_exits_three(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    tampered = _tampered_manifest(tmp_path)
    rc = main(
        ["run", str(tampered), "--policy", str(policy),
         "--backend", "mock", "--mode", "observe",
         "--events-in", str(CLEAN_EVENTS)]
    )
    assert rc == 3
    assert "drift" in capsys.readouterr().err.lower()


def test_run_mock_allow_drift_proceeds(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    tampered = _tampered_manifest(tmp_path)
    rc = main(
        ["run", str(tampered), "--policy", str(policy),
         "--backend", "mock", "--mode", "observe",
         "--events-in", str(CLEAN_EVENTS), "--allow-drift"]
    )
    assert rc == 0


def test_run_mock_without_events_in_is_usage_error(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    rc = main(
        ["run", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--backend", "mock", "--mode", "observe"]
    )
    assert rc == 2


# ---------------------------------------------------------------- fixtures


def test_fixture_manifests_cover_six_servers():
    stems = {p.stem for p in MANIFESTS.glob("*.json")}
    assert stems == {"github", "filesystem", "fetch", "shell", "sqlite", "slack"}
    for path in MANIFESTS.glob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        tools = doc["result"]["tools"] if "result" in doc else doc["tools"]
        assert tools, path.name
        for tool in tools:
            assert tool["name"], path.name
            assert tool["description"], path.name
            assert tool["inputSchema"]["type"] == "object", path.name


def test_fixture_event_streams_parse_and_diverge():
    clean_text = CLEAN_EVENTS.read_text(encoding="utf-8")
    exfil_text = EXFIL_EVENTS.read_text(encoding="utf-8")
    for text in (clean_text, exfil_text):
        events = [
            BehaviorEvent.from_dict(json.loads(line))
            for line in text.splitlines()
            if line.strip()
        ]
        assert events
    # exfil = the clean trace + the smoking gun
    assert exfil_text.startswith(clean_text)
    assert "evil.example.com" not in clean_text
    tail = [
        json.loads(line)
        for line in exfil_text[len(clean_text):].splitlines()
        if line.strip()
    ]
    evil = [e for e in tail if e["kind"] == "net.connect"]
    assert len(evil) == 1
    assert evil[0]["detail"]["host"] == "evil.example.com"
    assert evil[0]["tool_ctx"] == "read_file"


# ---------------------------------------------------------------- proxy
#
# The `proxy` subcommand runs the enforcing egress proxy standalone. These
# tests drive it entirely in-process on an ephemeral 127.0.0.1 port against a
# local sentinel "upstream" — no docker, no real network. `main` blocks until
# the proxy is torn down, so the work happens inside `cli._PROXY_SERVE_HOOK`:
# it receives the bound proxy, drives clients, waits for the events, and
# returns, at which point `main` stops the proxy and exits 0.


class _Sentinel:
    """A local 127.0.0.1 upstream that counts every request it receives.

    Used as the "allowed" target so an allowed CONNECT tunnels through to a
    real server, while a denied CONNECT must never reach it (hit count stays
    put) — the load-bearing deny-by-default invariant.
    """

    def __init__(self) -> None:
        self.hits = 0
        self._lock = threading.Lock()
        sentinel = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
                with sentinel._lock:
                    sentinel.hits += 1
                body = b"sentinel-ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:  # keep test output quiet
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _Sentinel:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


def _tunnel_get(proxy_port: int, host: str, upstream_port: int) -> tuple[int, bytes]:
    """CONNECT host:upstream_port through the proxy, then GET / over the tunnel.

    Returns (status, body) on success. Raises OSError (with the proxy status
    in the message) when the proxy refuses the CONNECT — how http.client
    surfaces a 403 from a proxy.
    """
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
    conn.set_tunnel(host, upstream_port)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _wait_for_events(proxy: object, count: int) -> None:
    """Block (bounded) until the proxy has recorded `count` attempts.

    The proxy appends to `events` and invokes the on_event print callback
    under one lock, so once the count is reached the JSONL is on its way out;
    a short grace lets the final line flush before teardown.
    """
    deadline = time.time() + 5.0
    while len(proxy.events) < count and time.time() < deadline:  # type: ignore[attr-defined]
        time.sleep(0.01)
    time.sleep(0.1)


def _write_net_policy(path: Path, hosts: list[str]) -> None:
    """Write a policy YAML that grants net.http for `hosts` and denies the rest."""
    caps = [
        Capability(
            id=cid,
            status=(
                CapabilityStatus.INFERRED
                if cid is CapabilityId.NET_HTTP
                else CapabilityStatus.DENIED
            ),
            values=list(hosts) if cid is CapabilityId.NET_HTTP else [],
        )
        for cid in CapabilityId
    ]
    dump_policy(Policy(server_id="proxy-test", manifest_hash="sha256:0", caps=caps), path)


def test_proxy_allow_enforces_in_process(capsys):
    with _Sentinel() as sentinel:
        captured: list = []

        def _driver(proxy: object) -> None:
            captured.append(proxy)
            port = proxy.port  # type: ignore[attr-defined]
            # allowed host (the sentinel) tunnels through and succeeds
            status, body = _tunnel_get(port, "127.0.0.1", sentinel.port)
            assert status == 200
            assert body == b"sentinel-ok"
            # denied host is 403'd by the proxy and never dialled upstream
            with pytest.raises(OSError) as excinfo:
                _tunnel_get(port, "blocked.example", sentinel.port)
            assert "403" in str(excinfo.value)
            _wait_for_events(proxy, 2)

        cli_module._PROXY_SERVE_HOOK = _driver
        try:
            rc = main(["proxy", "--allow", "127.0.0.1", "--host", "127.0.0.1",
                       "--port", "0"])
        finally:
            cli_module._PROXY_SERVE_HOOK = None

    assert rc == 0
    # deny-by-default invariant: the denied host never reached the sentinel
    assert sentinel.hits == 1

    proxy = captured[0]
    decisions = {e.detail["host"]: e.detail["allowed"] for e in proxy.events}
    assert decisions == {"127.0.0.1": True, "blocked.example": False}

    out, err = capsys.readouterr()
    lines = [json.loads(ln) for ln in out.splitlines() if ln.strip()]
    assert len(lines) == 2
    for d in lines:
        assert d["kind"] == "net.connect"
        assert d["detail"]["via"] == "proxy"
        assert d["backend"] == "egress-proxy"
    stdout_decisions = {d["detail"]["host"]: d["detail"]["allowed"] for d in lines}
    assert stdout_decisions == {"127.0.0.1": True, "blocked.example": False}
    assert "listening on 127.0.0.1:" in err
    assert "stopped" in err


def test_proxy_events_out_file(tmp_path, capsys):
    events_out = tmp_path / "proxy-events.jsonl"
    with _Sentinel() as sentinel:

        def _driver(proxy: object) -> None:
            status, _ = _tunnel_get(proxy.port, "127.0.0.1", sentinel.port)  # type: ignore[attr-defined]
            assert status == 200
            _wait_for_events(proxy, 1)

        cli_module._PROXY_SERVE_HOOK = _driver
        try:
            rc = main(["proxy", "--allow", "127.0.0.1", "--port", "0",
                       "--events-out", str(events_out)])
        finally:
            cli_module._PROXY_SERVE_HOOK = None

    assert rc == 0
    lines = [
        json.loads(ln)
        for ln in events_out.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    assert len(lines) == 1
    assert lines[0]["detail"]["host"] == "127.0.0.1"
    assert lines[0]["detail"]["allowed"] is True


def test_proxy_policy_derives_allowlist(tmp_path, capsys):
    policy_path = tmp_path / "net.policy.yaml"
    _write_net_policy(policy_path, ["127.0.0.1"])
    with _Sentinel() as sentinel:

        def _driver(proxy: object) -> None:
            status, _ = _tunnel_get(proxy.port, "127.0.0.1", sentinel.port)  # type: ignore[attr-defined]
            assert status == 200
            with pytest.raises(OSError):
                _tunnel_get(proxy.port, "nope.example", sentinel.port)  # type: ignore[attr-defined]
            _wait_for_events(proxy, 2)

        cli_module._PROXY_SERVE_HOOK = _driver
        try:
            rc = main(["proxy", "--policy", str(policy_path), "--port", "0"])
        finally:
            cli_module._PROXY_SERVE_HOOK = None

    assert rc == 0
    assert sentinel.hits == 1  # only the allowed host reached upstream
    assert "mode=allowlist" in capsys.readouterr().err


def test_run_mock_egress_proxy_prints_noop_note(tmp_path, capsys):
    policy = _infer_approved_policy(tmp_path)
    rc = main(
        ["run", str(FILESYSTEM_MANIFEST), "--policy", str(policy),
         "--backend", "mock", "--mode", "observe",
         "--events-in", str(CLEAN_EVENTS), "--egress-proxy"]
    )
    assert rc == 0
    assert "no effect" in capsys.readouterr().err
