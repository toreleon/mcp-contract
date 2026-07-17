"""Enforcing forward proxy — the load-bearing egress control point.

``EgressProxy`` is a threaded HTTP/CONNECT forward proxy. Sanctioned traffic
flows *through* it: the proxy resolves the hostname (from the ``CONNECT``
target or the absolute-form request URL), enforces the allowlist
(deny-by-default, ``403`` on a miss), and emits a ``net.connect``
``BehaviorEvent`` carrying ``detail["host"]`` for every attempt — allowed or
denied — so BCM sees hostname-level egress.

Security contract (see ``docs/DESIGN-egress-proxy.md``): a denied host is
**never** connected upstream. The upstream socket is only ever opened after
``allowed()`` returns ``True``. Allowlist decisions reuse
``bcm.diff.host_matches`` verbatim so proxy enforcement and BCM classification
share exactly one matching rule.

stdlib only. A malformed client request or an upstream failure is caught per
connection and never crashes the process.
"""
from __future__ import annotations

import base64
import hmac
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlsplit

from mcp_contract.bcm.diff import host_matches
from mcp_contract.models import BehaviorEvent, EventKind
from mcp_contract.proxy.plan import EgressPlan

_RELAY_BUFSIZE = 65536

# Methods the absolute-form HTTP forward path handles.
_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS")

# Defaults for the finite deadlines that keep a hung client from leaking a
# thread + file descriptors forever (see EgressProxy.__init__ for the knobs).
_DEFAULT_REQUEST_TIMEOUT = 30.0   # slow request line/headers -> socket teardown
_DEFAULT_IDLE_TIMEOUT = 300.0     # idle established tunnel -> torn down


def _expected_proxy_auth(token: str) -> str:
    """The exact ``Proxy-Authorization`` value a per-run proxy token demands.

    Fixed-username HTTP Basic; the container's HTTP client derives this header
    automatically from ``http://mcp:<token>@host...`` in its ``HTTP_PROXY`` env.
    """
    raw = base64.b64encode(b"mcp:" + token.encode("utf-8")).decode("ascii")
    return "Basic " + raw


def _connect_upstream(host: str, port: int, timeout: float) -> socket.socket:
    """Open a TCP socket to ``(host, port)``.

    Isolated as a module-level seam: the only place the proxy dials upstream,
    so tests can redirect it to a loopback sentinel without patching the
    global ``socket`` module (which the test client itself relies on).
    """
    return socket.create_connection((host, port), timeout=timeout)


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    """Split a ``host:port`` authority into ``(host, port)``.

    Handles bare hosts, ``host:port``, and bracketed IPv6 (``[::1]:443`` ->
    ``("::1", 443)``). Falls back to ``default_port`` when the port is absent
    or unparseable. The host is returned as-is (case preserved); callers
    lowercase for matching.
    """
    target = target.strip()
    if target.startswith("["):  # bracketed IPv6 literal
        end = target.find("]")
        if end == -1:
            return target, default_port
        host = target[1:end]
        rest = target[end + 1 :]
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                return host, default_port
        return host, default_port
    if ":" in target:
        host, _, port_s = target.rpartition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return target, default_port
    return target, default_port


def _relay(client_sock: socket.socket, upstream_sock: socket.socket) -> None:
    """Full-duplex byte relay between two connected sockets until either ends.

    One direction runs in a helper thread, the other in the caller's thread.
    A **clean** EOF in one direction is propagated as a half-close (``FIN``)
    toward the peer while the opposite pump keeps draining to its own EOF, so
    tunneled plaintext protocols that use TCP half-close are not truncated. A
    **hard** error (including a recv timeout) tears down both directions so no
    peer pump wedges. The caller arms both sockets with a finite idle timeout,
    which also bounds a peer that never closes its own write side after the
    ``FIN`` — the opposite recv() cannot linger forever.
    """

    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(_RELAY_BUFSIZE)
                if not data:
                    break
                dst.sendall(data)
            # Clean EOF on src: signal end-of-stream to dst's peer with a FIN
            # (write-side only) and let the opposite pump drain dst->src to its
            # own EOF. Preserves half-close; TLS still ends both ways promptly.
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        except OSError:
            # Hard error / timeout: tear both directions down so neither pump
            # (nor its peer) can wedge on a recv that will never complete.
            for sock in (src, dst):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    helper = threading.Thread(
        target=pump, args=(upstream_sock, client_sock), daemon=True
    )
    helper.start()
    pump(client_sock, upstream_sock)
    helper.join()
    try:
        upstream_sock.close()
    except OSError:
        pass


class _ProxyHandler(BaseHTTPRequestHandler):
    """One client connection: dispatch ``CONNECT`` tunnels and HTTP forwards.

    The bound :class:`EgressProxy` is reached via ``self.server.proxy``.
    """

    # Quiet: never write request logs to stderr.
    def log_message(self, *args: object) -> None:  # noqa: D401
        return

    @property
    def _proxy(self) -> EgressProxy:
        return self.server.proxy  # type: ignore[attr-defined]

    @property
    def timeout(self) -> float:  # type: ignore[override]
        # socketserver's setup() arms the accepted socket with this before
        # handle() runs, so a client that dribbles (or never sends) the request
        # line/headers hits socket.timeout and the thread exits — no slow-loris
        # thread/fd leak. self.server is set before setup() is called.
        return self._proxy._request_timeout

    def _authorized(self) -> bool:
        """Whether the request carries the per-run proxy credential.

        When the proxy has no ``auth_token`` (the standalone/loopback case)
        every request is authorized. When it does (the docker path binds
        ``0.0.0.0``), a matching ``Proxy-Authorization`` header is required so a
        LAN peer that merely reaches the port cannot use it as an open relay.
        """
        token = self._proxy._auth_token
        if token is None:
            return True
        provided = self.headers.get("Proxy-Authorization", "")
        try:
            return hmac.compare_digest(provided, _expected_proxy_auth(token))
        except TypeError:
            # A non-ASCII header can't match an ASCII Basic value -> fail closed.
            return False

    def _send_proxy_auth_required(self) -> None:
        body = b"proxy authentication required\n"
        header = (
            "HTTP/1.1 407 Proxy Authentication Required\r\n"
            'Proxy-Authenticate: Basic realm="mcp-contract"\r\n'
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1")
        try:
            self.connection.sendall(header + body)
        except OSError:
            pass
        self.close_connection = True

    # -- CONNECT tunneling (HTTPS and any TLS/TCP tunnel) ------------------
    def do_CONNECT(self) -> None:  # noqa: N802 (http.server dispatch name)
        try:
            self._do_connect()
        except Exception:  # never let a handler error escape the thread
            self.close_connection = True

    def _do_connect(self) -> None:
        proxy = self._proxy
        if not self._authorized():
            self._send_proxy_auth_required()
            return
        host, port = _split_host_port(self.path, 443)
        host = host.lower()
        if not proxy.allowed(host):
            proxy._emit(host, port, False)
            self._send_raw(403, "Forbidden", b"egress denied by mcp-contract\n")
            return
        try:
            upstream = _connect_upstream(host, port, proxy._connect_timeout)
        except OSError as exc:
            # Allowed but the upstream connect failed: still a sanctioned
            # attempt, so emit allowed=True and record the error.
            proxy._emit(host, port, True, error=str(exc))
            self._send_raw(502, "Bad Gateway", b"upstream connection failed\n")
            return
        proxy._emit(host, port, True)
        try:
            self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            try:
                upstream.close()
            except OSError:
                pass
            return
        self.close_connection = True
        # Finite idle timeout (never None): an established tunnel where neither
        # side sends nor closes is torn down instead of leaking a thread + fds.
        idle = proxy._idle_timeout
        upstream.settimeout(idle)
        self.connection.settimeout(idle)
        proxy._register_tunnel(self.connection, upstream)
        try:
            _relay(self.connection, upstream)
        finally:
            proxy._unregister_tunnel(self.connection, upstream)

    # -- absolute-form HTTP forwarding (GET http://host/path ...) ----------
    def _handle_http(self) -> None:
        try:
            self._do_http()
        except Exception:
            self.close_connection = True

    def _do_http(self) -> None:
        if not self._authorized():
            self._send_proxy_auth_required()
            return
        parsed = urlsplit(self.path)
        host = parsed.hostname
        if host:
            port = parsed.port or 80
        else:  # not absolute-form: fall back to the Host header
            host, port = _split_host_port(self.headers.get("Host", ""), 80)
        host = (host or "").lower()
        proxy = self._proxy
        if not host or not proxy.allowed(host):
            proxy._emit(host, port, False)
            self._send_raw(403, "Forbidden", b"egress denied by mcp-contract\n")
            return

        body = b""
        length = self.headers.get("Content-Length")
        if length:
            try:
                n = int(length)
            except ValueError:
                n = 0
            if n > 0:
                body = self.rfile.read(n)

        try:
            upstream = _connect_upstream(host, port, proxy._connect_timeout)
        except OSError as exc:
            proxy._emit(host, port, True, error=str(exc))
            self._send_raw(502, "Bad Gateway", b"upstream connection failed\n")
            return
        proxy._emit(host, port, True)
        self.close_connection = True
        proxy._register_tunnel(upstream)
        try:
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
            lines = [f"{self.command} {target} {self.request_version}"]
            has_host = False
            for key, value in self.headers.items():
                lk = key.lower()
                if lk in ("proxy-connection", "connection"):
                    continue
                if lk == "host":
                    has_host = True
                lines.append(f"{key}: {value}")
            if not has_host:
                lines.insert(1, f"Host: {host}")
            lines.append("Connection: close")
            head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
            upstream.sendall(head)
            if body:
                upstream.sendall(body)
            # Finite idle timeout (never None) so a stalled upstream response
            # cannot hang the recv loop and leak the handler thread.
            upstream.settimeout(proxy._idle_timeout)
            while True:
                chunk = upstream.recv(_RELAY_BUFSIZE)
                if not chunk:
                    break
                self.connection.sendall(chunk)
        except OSError:
            pass
        finally:
            proxy._unregister_tunnel(upstream)
            try:
                upstream.close()
            except OSError:
                pass

    # http.server dispatches on do_<METHOD>; route them all to the forwarder.
    do_GET = _handle_http
    do_POST = _handle_http
    do_PUT = _handle_http
    do_DELETE = _handle_http
    do_HEAD = _handle_http
    do_PATCH = _handle_http
    do_OPTIONS = _handle_http

    # -- helpers -----------------------------------------------------------
    def _send_raw(self, code: int, reason: str, body: bytes) -> None:
        header = (
            f"HTTP/1.1 {code} {reason}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1")
        try:
            self.connection.sendall(header + body)
        except OSError:
            pass
        self.close_connection = True

    def finish(self) -> None:
        # We hijack the socket for CONNECT tunnels; swallow teardown errors
        # so a shut-down connection never surfaces as a handler exception.
        try:
            super().finish()
        except OSError:
            pass


class _ProxyHTTPServer(ThreadingHTTPServer):
    """Threaded server so concurrent tunnels never block one another."""

    daemon_threads = True
    allow_reuse_address = True
    proxy: "EgressProxy"

    def handle_error(self, request: object, client_address: object) -> None:
        # Relay teardown races produce benign socket errors; stay quiet.
        return


class EgressProxy:
    """A threaded, deny-by-default forward proxy that enforces an allowlist.

    Construct with an :class:`EgressPlan` (or a bare ``list[str]`` of allow
    patterns, wrapped as ``EgressPlan("allowlist", ...)`` — deny-by-default),
    ``start()`` it, point an MCP server/client at ``address``, and drain
    ``events`` (or supply ``on_event``) for hostname-level ``net.connect``
    observations.
    """

    def __init__(
        self,
        allow: EgressPlan | list[str],
        *,
        on_event: Callable[[BehaviorEvent], None] | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        connect_timeout: float = 10.0,
        request_timeout: float = _DEFAULT_REQUEST_TIMEOUT,
        idle_timeout: float = _DEFAULT_IDLE_TIMEOUT,
        auth_token: str | None = None,
    ) -> None:
        self._plan = allow if isinstance(allow, EgressPlan) else EgressPlan(
            "allowlist", list(allow)
        )
        self._on_event = on_event
        self._host = host
        self._connect_timeout = connect_timeout
        # Finite read deadlines: request_timeout bounds slow-loris request
        # parsing (armed on the accepted socket); idle_timeout bounds an idle
        # established tunnel / stalled upstream response. Neither is ever None.
        self._request_timeout = request_timeout
        self._idle_timeout = idle_timeout
        # None => no proxy auth (loopback/standalone). A token requires a
        # matching Proxy-Authorization header so a 0.0.0.0 bind is not an open
        # relay for any LAN peer that can reach the port.
        self._auth_token = auth_token
        self.events: list[BehaviorEvent] = []
        self._lock = threading.Lock()
        self._state_lock = threading.Lock()
        # Live tunnel sockets, so stop() can force-close in-flight tunnels and
        # reclaim their fds instead of waiting for process exit.
        self._tunnels: set[socket.socket] = set()
        self._tunnels_lock = threading.Lock()
        self._httpd: _ProxyHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._stopped = False
        self.port: int = port
        self.address: tuple[str, int] = (host, port)

    def _register_tunnel(self, *socks: socket.socket) -> None:
        with self._tunnels_lock:
            self._tunnels.update(socks)

    def _unregister_tunnel(self, *socks: socket.socket) -> None:
        with self._tunnels_lock:
            for sock in socks:
                self._tunnels.discard(sock)

    @property
    def plan(self) -> EgressPlan:
        """The effective egress plan being enforced."""
        return self._plan

    def allowed(self, host: str) -> bool:
        """Whether ``host`` may egress under the current plan.

        ``open`` -> always ``True``; ``deny`` -> always ``False``;
        ``allowlist`` -> ``host_matches`` (case-insensitive, ``"*"`` /
        ``"*.suffix"`` wildcards) against the allowlist patterns.
        """
        mode = self._plan.mode
        if mode == "open":
            return True
        if mode == "deny":
            return False
        return host_matches(host, self._plan.hosts)

    def _emit(
        self,
        host: str,
        port: int,
        allowed: bool,
        error: str | None = None,
    ) -> BehaviorEvent:
        detail: dict[str, object] = {
            "host": host,
            "port": port,
            "allowed": allowed,
            "via": "proxy",
        }
        if error is not None:
            detail["error"] = error
        event = BehaviorEvent(
            ts=time.time(),
            kind=EventKind.NET_CONNECT,
            detail=detail,
            backend="egress-proxy",
        )
        # Guard the event log and the callback together so events append and
        # dispatch atomically (one event per attempt, ordered, never racing).
        with self._lock:
            self.events.append(event)
            if self._on_event is not None:
                try:
                    self._on_event(event)
                except Exception:
                    # A misbehaving sink must never break enforcement.
                    pass
        return event

    def start(self) -> None:
        """Bind and serve in a background daemon thread; returns once bound."""
        with self._state_lock:
            if self._thread is not None:
                return
            httpd = _ProxyHTTPServer((self._host, self.port), _ProxyHandler)
            httpd.proxy = self
            self._httpd = httpd
            self.port = httpd.server_address[1]
            self.address = (httpd.server_address[0], httpd.server_address[1])
            thread = threading.Thread(
                # Small poll interval so stop() -> shutdown() returns promptly.
                target=lambda: httpd.serve_forever(poll_interval=0.05),
                name="egress-proxy",
                daemon=True,
            )
            self._thread = thread
            thread.start()

    def stop(self) -> None:
        """Stop serving and join the thread. Idempotent.

        After the listener is closed, any in-flight tunnel sockets are
        force-closed so a hung/idle tunnel's fds are reclaimed here rather than
        surviving until process exit (a real problem for a long-lived host that
        starts/stops a proxy per server).
        """
        with self._state_lock:
            if self._stopped:
                return
            self._stopped = True
            httpd = self._httpd
            thread = self._thread
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        # Force-close live tunnels: recv() in each pump raises, running its
        # teardown so the relay/HTTP threads unblock and their fds are freed.
        with self._tunnels_lock:
            tunnels = list(self._tunnels)
            self._tunnels.clear()
        for sock in tunnels:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        if thread is not None:
            thread.join(timeout=5.0)

    def __enter__(self) -> EgressProxy:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
