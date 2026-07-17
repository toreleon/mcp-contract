"""Tests for the egress proxy (Module P).

Everything runs in-process on 127.0.0.1 and never touches the real network:
a local ``ThreadingHTTPServer`` sentinel stands in for "upstream", and the
proxy is driven with ``http.client`` (``set_tunnel`` for CONNECT). The five
security invariants from ``docs/DESIGN-egress-proxy.md`` are each pinned.
"""
from __future__ import annotations

import base64
import http.client
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mcp_contract.models import (
    Capability,
    CapabilityId,
    CapabilityStatus,
    EventKind,
    Policy,
)
from mcp_contract.proxy import EgressPlan, EgressProxy, egress_plan
from mcp_contract.proxy import server as proxy_server


# --------------------------------------------------------------------------
# Local sentinel "upstream" — records every request it receives.
# --------------------------------------------------------------------------
class _SentinelHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # close after each response -> clean teardown

    def log_message(self, *args: object) -> None:
        return

    def _serve(self) -> None:
        self.server.hits.append(  # type: ignore[attr-defined]
            (self.command, self.path, self.headers.get("Host"))
        )
        body = b"sentinel-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve
    do_POST = _serve


class _Sentinel(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture()
def sentinel():
    server = _Sentinel(("127.0.0.1", 0), _SentinelHandler)
    server.hits = []  # type: ignore[attr-defined]
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _closed_port() -> int:
    """A 127.0.0.1 port that is bound then released — nothing listens there."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _tunnel_get(proxy_port: int, host: str, port: int, path: str = "/hit"):
    """CONNECT host:port through the proxy, then GET path over the tunnel."""
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
    conn.set_tunnel(host, port)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, data
    finally:
        conn.close()


# --------------------------------------------------------------------------
# egress_plan — the four deny-by-default policy cases
# --------------------------------------------------------------------------
def _policy(cap: Capability | None) -> Policy:
    caps = [cap] if cap is not None else []
    return Policy(server_id="s", manifest_hash="sha256:x", caps=caps)


def test_egress_plan_not_granted_denies():
    # No net.http grant at all -> deny.
    assert egress_plan(_policy(None)) == EgressPlan("deny", [])
    # needs_review is not a grant either -> deny.
    nr = Capability(CapabilityId.NET_HTTP, CapabilityStatus.NEEDS_REVIEW, ["*"])
    assert egress_plan(_policy(nr)) == EgressPlan("deny", [])


def test_egress_plan_empty_values_denies():
    cap = Capability(CapabilityId.NET_HTTP, CapabilityStatus.INFERRED, [])
    assert egress_plan(_policy(cap)) == EgressPlan("deny", [])


def test_egress_plan_star_is_open():
    cap = Capability(
        CapabilityId.NET_HTTP, CapabilityStatus.INFERRED, ["*", "api.example.com"]
    )
    assert egress_plan(_policy(cap)) == EgressPlan("open", [])


def test_egress_plan_concrete_is_sorted_allowlist():
    cap = Capability(
        CapabilityId.NET_HTTP,
        CapabilityStatus.INFERRED,
        ["b.example.com", "a.example.com", "a.example.com"],
    )
    assert egress_plan(_policy(cap)) == EgressPlan(
        "allowlist", ["a.example.com", "b.example.com"]
    )


# --------------------------------------------------------------------------
# allowed() decision logic (unit, no sockets)
# --------------------------------------------------------------------------
def test_allowed_modes():
    assert EgressProxy(EgressPlan("open", [])).allowed("anything.com") is True
    assert EgressProxy(EgressPlan("deny", [])).allowed("anything.com") is False
    p = EgressProxy(EgressPlan("allowlist", ["*.example.com"]))
    assert p.allowed("api.example.com") is True
    assert p.allowed("API.EXAMPLE.COM") is True  # case-insensitive
    assert p.allowed("example.com") is False  # apex not matched by *.example.com
    assert p.allowed("evil.com") is False


def test_bare_list_is_allowlist():
    # A bare list must wrap as an allowlist (deny-by-default), not "open".
    p = EgressProxy(["api.example.com"])
    assert p.plan == EgressPlan("allowlist", ["api.example.com"])
    assert p.allowed("api.example.com") is True
    assert p.allowed("evil.com") is False


# --------------------------------------------------------------------------
# Invariant 1: a denied host is NEVER connected upstream.
# The CONNECT target literally addresses the sentinel (127.0.0.1:sport) but is
# not on the allowlist -> 403, upstream socket never opened, sentinel: 0 hits.
# --------------------------------------------------------------------------
def test_denied_host_never_reaches_upstream(sentinel):
    sport = sentinel.server_address[1]
    with EgressProxy(EgressPlan("allowlist", ["good.example.com"])) as proxy:
        with pytest.raises(OSError):
            _tunnel_get(proxy.port, "127.0.0.1", sport)
    assert sentinel.hits == []  # sentinel never contacted
    assert len(proxy.events) == 1
    ev = proxy.events[0]
    assert ev.kind is EventKind.NET_CONNECT
    assert ev.detail["allowed"] is False
    assert ev.detail["host"] == "127.0.0.1"
    assert ev.detail["port"] == sport
    assert ev.detail["via"] == "proxy"
    assert ev.backend == "egress-proxy"


# --------------------------------------------------------------------------
# Invariant 2: an empty allowlist denies everything (deny-by-default).
# --------------------------------------------------------------------------
def test_empty_allowlist_denies_all(sentinel):
    sport = sentinel.server_address[1]
    with EgressProxy(EgressPlan("allowlist", [])) as proxy:
        with pytest.raises(OSError):
            _tunnel_get(proxy.port, "127.0.0.1", sport)
    assert sentinel.hits == []
    assert len(proxy.events) == 1
    assert proxy.events[0].detail["allowed"] is False


# --------------------------------------------------------------------------
# Allowed host reaches the sentinel end-to-end over a real loopback tunnel
# (no monkeypatch): allowlist contains the loopback IP, CONNECT to it relays
# a plaintext GET straight through to the sentinel.
# --------------------------------------------------------------------------
def test_allowed_host_reaches_upstream(sentinel):
    sport = sentinel.server_address[1]
    with EgressProxy(EgressPlan("allowlist", ["127.0.0.1"])) as proxy:
        status, body = _tunnel_get(proxy.port, "127.0.0.1", sport, path="/ping")
    assert status == 200
    assert body == b"sentinel-ok"
    assert len(sentinel.hits) == 1
    assert sentinel.hits[0][0] == "GET"
    assert sentinel.hits[0][1] == "/ping"
    assert len(proxy.events) == 1
    ev = proxy.events[0]
    assert ev.detail["allowed"] is True
    assert ev.detail["host"] == "127.0.0.1"
    assert ev.detail["port"] == sport
    assert "error" not in ev.detail


# --------------------------------------------------------------------------
# Invariants 3 + 4 + 5: *.example.com wildcard semantics end-to-end, exactly
# one event per attempt with correct host/allowed, case-insensitive matching.
# The upstream seam is redirected to the sentinel so allowed hostnames flow
# through without any real DNS/network; denied ones must never dial it.
# --------------------------------------------------------------------------
def test_wildcard_semantics_end_to_end(sentinel, monkeypatch):
    sport = sentinel.server_address[1]
    dialed: list[str] = []

    def fake_connect(host: str, port: int, timeout: float) -> socket.socket:
        dialed.append(host)
        return socket.create_connection(("127.0.0.1", sport), timeout=timeout)

    monkeypatch.setattr(proxy_server, "_connect_upstream", fake_connect)

    with EgressProxy(EgressPlan("allowlist", ["*.example.com"])) as proxy:
        # allowed subdomains (second one uppercase -> invariant 5)
        for host in ("api.example.com", "API.EXAMPLE.COM"):
            status, body = _tunnel_get(proxy.port, host, 443)
            assert status == 200
            assert body == b"sentinel-ok"
        # denied: the apex and an unrelated host
        for host in ("example.com", "evil.com"):
            with pytest.raises(OSError):
                _tunnel_get(proxy.port, host, 443)

    # Denied hosts never dialed upstream; allowed hosts dialed (lowercased).
    assert dialed == ["api.example.com", "api.example.com"]
    assert "example.com" not in dialed
    assert "evil.com" not in dialed

    # Exactly one event per attempt, correct host + allowed flag, order kept.
    seen = [(e.detail["host"], e.detail["allowed"]) for e in proxy.events]
    assert seen == [
        ("api.example.com", True),
        ("api.example.com", True),  # uppercase normalized to lowercase
        ("example.com", False),
        ("evil.com", False),
    ]


# --------------------------------------------------------------------------
# Allowed host but upstream unreachable: still allowed=True, error recorded,
# exactly one event, 502 back to the client (which surfaces as OSError).
# --------------------------------------------------------------------------
def test_allowed_upstream_failure_still_allowed():
    dead = _closed_port()
    with EgressProxy(EgressPlan("allowlist", ["127.0.0.1"])) as proxy:
        with pytest.raises(OSError):
            _tunnel_get(proxy.port, "127.0.0.1", dead)
    assert len(proxy.events) == 1
    ev = proxy.events[0]
    assert ev.detail["allowed"] is True
    assert "error" in ev.detail


# --------------------------------------------------------------------------
# on_event callback fires synchronously for every attempt, in order.
# --------------------------------------------------------------------------
def test_on_event_callback(sentinel):
    sport = sentinel.server_address[1]
    got: list[tuple[str, bool]] = []
    with EgressProxy(
        EgressPlan("allowlist", ["127.0.0.1"]),
        on_event=lambda e: got.append((e.detail["host"], e.detail["allowed"])),
    ) as proxy:
        _tunnel_get(proxy.port, "127.0.0.1", sport)
    assert got == [("127.0.0.1", True)]
    # Callback list and the proxy's own events list agree.
    assert [(e.detail["host"], e.detail["allowed"]) for e in proxy.events] == got


def test_on_event_exception_does_not_break_enforcement(sentinel):
    sport = sentinel.server_address[1]

    def boom(_e):
        raise RuntimeError("sink is broken")

    with EgressProxy(
        EgressPlan("allowlist", ["127.0.0.1"]), on_event=boom
    ) as proxy:
        status, _ = _tunnel_get(proxy.port, "127.0.0.1", sport, path="/still-works")
    assert status == 200
    assert len(proxy.events) == 1  # event still logged despite callback error


# --------------------------------------------------------------------------
# absolute-form HTTP forward path (allowed + denied), driven with a raw socket.
# --------------------------------------------------------------------------
def _raw_request(proxy_port: int, request_line: str, headers: str = "") -> bytes:
    raw = request_line + "\r\n" + headers + "\r\n"
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    try:
        s.sendall(raw.encode("latin-1"))
        chunks = []
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    finally:
        s.close()


def test_http_forward_allowed(sentinel):
    sport = sentinel.server_address[1]
    with EgressProxy(EgressPlan("allowlist", ["127.0.0.1"])) as proxy:
        resp = _raw_request(
            proxy.port,
            f"GET http://127.0.0.1:{sport}/forward HTTP/1.1",
            f"Host: 127.0.0.1:{sport}\r\n",
        )
    assert b"200" in resp
    assert b"sentinel-ok" in resp
    assert len(sentinel.hits) == 1
    assert sentinel.hits[0][1] == "/forward"
    assert len(proxy.events) == 1
    assert proxy.events[0].detail["allowed"] is True


def test_http_forward_denied(sentinel):
    sport = sentinel.server_address[1]
    with EgressProxy(EgressPlan("allowlist", ["good.example.com"])) as proxy:
        resp = _raw_request(
            proxy.port,
            f"GET http://127.0.0.1:{sport}/forward HTTP/1.1",
            f"Host: 127.0.0.1:{sport}\r\n",
        )
    assert b"403" in resp
    assert sentinel.hits == []
    assert len(proxy.events) == 1
    assert proxy.events[0].detail["allowed"] is False


# --------------------------------------------------------------------------
# open / deny modes exercised through the proxy.
# --------------------------------------------------------------------------
def test_open_mode_allows_but_still_emits(sentinel):
    sport = sentinel.server_address[1]
    with EgressProxy(EgressPlan("open", [])) as proxy:
        status, _ = _tunnel_get(proxy.port, "127.0.0.1", sport)
    assert status == 200
    assert len(proxy.events) == 1
    assert proxy.events[0].detail["allowed"] is True


def test_deny_mode_blocks_everything(sentinel):
    sport = sentinel.server_address[1]
    with EgressProxy(EgressPlan("deny", [])) as proxy:
        with pytest.raises(OSError):
            _tunnel_get(proxy.port, "127.0.0.1", sport)
    assert sentinel.hits == []
    assert proxy.events[0].detail["allowed"] is False


# --------------------------------------------------------------------------
# Lifecycle: context manager binds a real port; stop() is idempotent.
# --------------------------------------------------------------------------
def test_context_manager_binds_port():
    with EgressProxy(EgressPlan("deny", [])) as proxy:
        assert proxy.port > 0
        assert proxy.address == ("127.0.0.1", proxy.port)


def test_stop_is_idempotent():
    proxy = EgressProxy(EgressPlan("deny", []))
    proxy.start()
    port = proxy.port
    assert port > 0
    proxy.stop()
    proxy.stop()  # second stop must be a no-op, not an error
    proxy.stop()


def test_stop_without_start_is_safe():
    EgressProxy(EgressPlan("deny", [])).stop()  # never started -> no crash


def test_double_start_keeps_one_server():
    proxy = EgressProxy(EgressPlan("deny", []))
    proxy.start()
    port = proxy.port
    proxy.start()  # idempotent
    assert proxy.port == port
    proxy.stop()


# --------------------------------------------------------------------------
# Finite read deadlines (no slow-loris / idle-tunnel thread+fd leak).
# An idle plain-TCP upstream: accepts one connection and then stays silent
# forever (never sends, never closes) so a tunnel to it is idle both ways.
# --------------------------------------------------------------------------
@pytest.fixture()
def idle_upstream():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    held: list[socket.socket] = []

    def _accept() -> None:
        try:
            conn, _ = srv.accept()
            held.append(conn)  # hold it open and idle
        except OSError:
            pass

    t = threading.Thread(target=_accept, daemon=True)
    t.start()
    try:
        yield srv.getsockname()[1]
    finally:
        for c in held:
            try:
                c.close()
            except OSError:
                pass
        try:
            srv.close()
        except OSError:
            pass
        t.join(timeout=5)


def _open_tunnel(proxy_port: int, host: str, port: int, timeout: float = 5.0):
    """Open a raw CONNECT tunnel; return (socket, established-response-bytes)."""
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\n\r\n".encode("latin-1"))
    s.settimeout(timeout)
    return s, s.recv(4096)


def test_slow_request_line_is_disconnected_within_request_timeout():
    # A client that connects and dribbles a partial CONNECT line then stalls
    # must be dropped within request_timeout (socketserver arms the accepted
    # socket via _ProxyHandler.timeout) — not leak a thread blocked forever.
    with EgressProxy(EgressPlan("deny", []), request_timeout=0.5) as proxy:
        s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        try:
            s.sendall(b"CONNECT api.exa")  # partial request line, then stall
            s.settimeout(5)
            start = time.monotonic()
            data = s.recv(4096)  # unblocks when the proxy times out and closes
            elapsed = time.monotonic() - start
        finally:
            s.close()
    assert data == b""  # server closed the connection (EOF), didn't hang
    assert elapsed < 4  # torn down near request_timeout, not unbounded


def test_idle_tunnel_torn_down_within_idle_timeout(idle_upstream):
    # An established tunnel idle in both directions must be torn down within
    # idle_timeout (relay recv() raises TimeoutError -> teardown), not block
    # its pump threads forever.
    with EgressProxy(
        EgressPlan("allowlist", ["127.0.0.1"]), idle_timeout=0.5
    ) as proxy:
        s, established = _open_tunnel(proxy.port, "127.0.0.1", idle_upstream)
        try:
            assert b"200" in established
            start = time.monotonic()
            rest = s.recv(4096)  # idle -> proxy tears the tunnel down
            elapsed = time.monotonic() - start
        finally:
            s.close()
    assert rest == b""  # tunnel closed by the proxy
    assert elapsed < 4  # near idle_timeout, not unbounded


def test_stop_closes_in_flight_tunnel(idle_upstream):
    # stop() must force-close in-flight tunnel sockets (reclaim their fds now,
    # not at process exit). idle_timeout is large so the tunnel would NOT
    # self-tear within the test — only stop() can close it here.
    proxy = EgressProxy(EgressPlan("allowlist", ["127.0.0.1"]), idle_timeout=60)
    proxy.start()
    s, established = _open_tunnel(proxy.port, "127.0.0.1", idle_upstream)
    try:
        assert b"200" in established
        # Wait for the tunnel to be registered (registration happens just after
        # the 200 line is sent, so poll briefly to avoid a race).
        deadline = time.monotonic() + 2
        while not proxy._tunnels and time.monotonic() < deadline:
            time.sleep(0.01)
        assert proxy._tunnels  # tunnel sockets are tracked for reclamation
        start = time.monotonic()
        proxy.stop()  # force-closes the in-flight tunnel sockets
        rest = s.recv(4096)
        elapsed = time.monotonic() - start
    finally:
        s.close()
    assert rest == b""  # proxy closed the tunnel on stop()
    assert elapsed < 4  # reclaimed by stop(), not left to idle_timeout=60
    assert not proxy._tunnels  # registry drained


# --------------------------------------------------------------------------
# TCP half-close is preserved through a CONNECT tunnel: the client ends its
# request with shutdown(SHUT_WR) while still reading, and the upstream's
# response (sent AFTER it sees the FIN) must arrive intact — not truncated by
# the relay tearing down both directions on the first EOF.
# --------------------------------------------------------------------------
def test_connect_tunnel_preserves_half_close():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    uport = srv.getsockname()[1]

    def _serve() -> None:
        conn, _ = srv.accept()
        # Drain the request until the client half-closes (proxy propagates the
        # FIN as recv()==0), THEN send the response and close.
        while True:
            try:
                if not conn.recv(4096):
                    break
            except OSError:
                break
        try:
            conn.sendall(b"HALF-CLOSE-RESPONSE")
        except OSError:
            pass
        conn.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        with EgressProxy(EgressPlan("allowlist", ["127.0.0.1"])) as proxy:
            s, established = _open_tunnel(proxy.port, "127.0.0.1", uport)
            try:
                assert b"200" in established
                s.sendall(b"REQUEST-BODY")
                s.shutdown(socket.SHUT_WR)  # end-of-request, still reading
                chunks = []
                while True:
                    d = s.recv(4096)
                    if not d:
                        break
                    chunks.append(d)
            finally:
                s.close()
        assert b"".join(chunks) == b"HALF-CLOSE-RESPONSE"  # not truncated
    finally:
        t.join(timeout=5)
        srv.close()


# --------------------------------------------------------------------------
# Per-run proxy credential (auth_token): a 0.0.0.0-bound proxy must not be an
# open relay. Without the token -> 407 and the upstream is never dialled;
# with the token -> normal enforcement.
# --------------------------------------------------------------------------
def _basic_proxy_auth(token: str) -> str:
    raw = base64.b64encode(b"mcp:" + token.encode("utf-8")).decode("ascii")
    return "Basic " + raw


def test_auth_token_connect_without_credential_is_407(monkeypatch):
    dialed: list[str] = []

    def fake_connect(host: str, port: int, timeout: float) -> socket.socket:
        dialed.append(host)  # must never happen: auth gates before dialing
        raise AssertionError("upstream dialled despite failed proxy auth")

    monkeypatch.setattr(proxy_server, "_connect_upstream", fake_connect)
    # open mode: only the missing credential can stop the request.
    with EgressProxy(EgressPlan("open", []), auth_token="s3cret-token") as proxy:
        s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        try:
            s.sendall(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n")
            s.settimeout(5)
            resp = s.recv(4096)
        finally:
            s.close()
    assert b"407" in resp
    assert dialed == []  # upstream never contacted
    assert proxy.events == []  # no net.connect emitted for an unauth probe


def test_auth_token_wrong_credential_is_407(monkeypatch):
    monkeypatch.setattr(
        proxy_server,
        "_connect_upstream",
        lambda *a: (_ for _ in ()).throw(AssertionError("dialled")),
    )
    with EgressProxy(EgressPlan("open", []), auth_token="right-token") as proxy:
        s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        try:
            s.sendall(
                b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n"
                + f"Proxy-Authorization: {_basic_proxy_auth('wrong-token')}\r\n".encode()
                + b"\r\n"
            )
            s.settimeout(5)
            resp = s.recv(4096)
        finally:
            s.close()
    assert b"407" in resp


def test_auth_token_correct_credential_allows(sentinel):
    sport = sentinel.server_address[1]
    token = "s3cret-token"
    with EgressProxy(
        EgressPlan("allowlist", ["127.0.0.1"]), auth_token=token
    ) as proxy:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
        conn.set_tunnel(
            "127.0.0.1",
            sport,
            headers={"Proxy-Authorization": _basic_proxy_auth(token)},
        )
        try:
            conn.request("GET", "/ok")
            resp = conn.getresponse()
            status, body = resp.status, resp.read()
        finally:
            conn.close()
    assert status == 200
    assert body == b"sentinel-ok"
    assert len(sentinel.hits) == 1
    assert proxy.events[0].detail["allowed"] is True


def test_auth_token_http_forward_without_credential_is_407(sentinel):
    # The absolute-form HTTP path must also require the credential; a real
    # forward would leave a sentinel hit, so zero hits proves it was gated.
    sport = sentinel.server_address[1]
    with EgressProxy(
        EgressPlan("allowlist", ["127.0.0.1"]), auth_token="tok"
    ) as proxy:
        resp = _raw_request(
            proxy.port,
            f"GET http://127.0.0.1:{sport}/x HTTP/1.1",
            f"Host: 127.0.0.1:{sport}\r\n",
        )
    assert b"407" in resp
    assert sentinel.hits == []
