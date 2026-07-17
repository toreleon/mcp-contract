"""Docker RAL backend: `docker run` hardening + polling-based observation.

Honest v0 limits (also reflected in `capabilities()`):
- Network is OBSERVE-only per-host: we poll `/proc/net/tcp{,6}` inside the
  container, so events carry remote IPs, not hostnames — hostname-level
  matching and per-host egress *enforcement* both need an egress proxy.
  Boot-time we can only do all-or-nothing (`--network none` when net.http
  is not granted). Polling is sampling, not tracing: a connection whose
  entire lifetime and close-state residue (TIME_WAIT lingers ~60s) fall
  between polls is missed entirely — complete egress coverage needs the
  same egress proxy.
- Filesystem is ENFORCE at boot time via ro/rw bind mounts, but Docker
  gives us no per-open events, so no fs.open events are emitted.
- Process is OBSERVE via `docker top` polling; syscalls are invisible.
- `block` is coarse: it kills the container.

Network *enforcement* (hostname-level, deny-by-default) is available by
constructing the adapter with `egress_proxy=True`: `start` then boots an
in-process `EgressProxy` (see `mcp_contract.proxy`) and wires the container's
`HTTP(S)_PROXY` env at it via `--add-host=host.docker.internal:host-gateway`,
so sanctioned egress flows *through* the proxy (which resolves the hostname
and applies the allowlist). Proxy-emitted `net.connect` events (hostname-level,
`via="proxy"`) are drained into `event_stream` alongside the IP-level
`/proc/net/tcp` and `docker top` events — two observation sources, one
contract. With `egress_proxy=True` the network axis reports `ENFORCE`; without
it, the historical `OBSERVE`-only behaviour (below) is unchanged.

All subprocess calls go through the docker CLI (no docker-py), with
`check=False`, captured output, and never `shell=True`.
"""
from __future__ import annotations

import ipaddress
import os
import posixpath
import queue
import secrets
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterator

from mcp_contract.models import BehaviorEvent, CapabilityId, EventKind, Policy
from mcp_contract.ral.base import BackendCaps, ServerHandle, ServerSpec, SupportLevel

if TYPE_CHECKING:
    from mcp_contract.proxy.plan import EgressPlan


def translate_policy_args(policy: Policy, spec: ServerSpec) -> list[str]:
    """Translate a neutral policy into `docker run` arguments (pure function).

    Only capabilities with status `inferred` are granted (`Policy.granted`).
    Emits: baseline hardening flags; `--network none` unless net.http is
    granted (per-host egress needs a proxy — v0 gap, so granted net means
    the default network); ro/rw bind mounts for absolute fs.read/fs.write
    values (non-absolute values are skipped — they cannot be mounted
    deterministically); `-e VAR` passthrough for granted env vars that the
    spec actually provides (the caller must put them in the subprocess
    environment; passthrough keeps secrets out of the argv).
    """
    args = [
        "--rm",
        "-d",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
    ]

    if policy.granted(CapabilityId.NET_HTTP) is None:
        args += ["--network", "none"]

    # Bind mounts: same path inside and out; write wins over read for a path
    # granted both ways (mounting one target twice is a docker error).
    mounts: dict[str, str] = {}
    for cap_id, mode in ((CapabilityId.FS_WRITE, "rw"), (CapabilityId.FS_READ, "ro")):
        cap = policy.granted(cap_id)
        if cap is None:
            continue
        for value in cap.values:
            path = posixpath.normpath(value)
            if not path.startswith("/"):
                continue
            if mode == "rw":
                mounts[path] = "rw"
            else:
                mounts.setdefault(path, "ro")
    for path in sorted(mounts):
        args += ["-v", f"{path}:{path}:{mounts[path]}"]

    env_cap = policy.granted(CapabilityId.ENV)
    if env_cap is not None:
        if "*" in env_cap.values:
            # Class-level env grant: pass through every var the spec provides.
            wanted = set(spec.env)
        else:
            wanted = {v for v in env_cap.values if v in spec.env}
        for var in sorted(wanted):
            args += ["-e", var]

    return args


def translate_network_args(
    plan: EgressPlan, proxy_endpoint: str | None, spec: ServerSpec
) -> list[str]:
    """Translate an egress plan into the `docker run` *network* arguments.

    Pure function (unit-testable without docker). Exactly one of three shapes:

    - `proxy_endpoint` set (an `EgressProxy` is enforcing on the host) → point
      the container's HTTP client at it: `-e HTTP_PROXY=<ep>` /
      `-e HTTPS_PROXY=<ep>` plus the lowercase `http_proxy`/`https_proxy`
      (many clients honour only one casing), and
      `--add-host=host.docker.internal:host-gateway` so the container can reach
      the host. Deliberately **no** `--network none`: the container needs the
      bridge to reach the proxy, and the proxy — not the bridge — is what
      enforces the allowlist.
    - no proxy and `plan.mode == "deny"` → `["--network", "none"]` (fail
      closed: nothing granted, so cut the container off from the network).
    - no proxy and `plan.mode in ("open", "allowlist")` → `[]` (default
      bridge, observe-only). Without the proxy an allowlist cannot be enforced
      at the hostname level — that is the whole reason the proxy exists.

    `spec` is accepted for signature stability with `translate_policy_args`;
    the network decision derives entirely from `plan` and `proxy_endpoint`.
    """
    if proxy_endpoint is not None:
        return [
            "-e",
            f"HTTP_PROXY={proxy_endpoint}",
            "-e",
            f"HTTPS_PROXY={proxy_endpoint}",
            "-e",
            f"http_proxy={proxy_endpoint}",
            "-e",
            f"https_proxy={proxy_endpoint}",
            "--add-host=host.docker.internal:host-gateway",
        ]
    if plan.mode == "deny":
        return ["--network", "none"]
    return []


def _without_network_flag(args: list[str]) -> list[str]:
    """Drop any `--network <value>` pair from `args`.

    So the network decision is owned solely by `translate_network_args`: the
    baseline `translate_policy_args` also emits `--network none` for an
    ungranted net policy, and composing the two would otherwise double-add a
    network flag (a `docker run` error).
    """
    out: list[str] = []
    i = 0
    n = len(args)
    while i < n:
        if args[i] == "--network" and i + 1 < n:
            i += 2
            continue
        out.append(args[i])
        i += 1
    return out


@dataclass
class _ProxyChannel:
    """Bundles a running `EgressProxy` with the queue its events land in.

    Stored on `ServerHandle.native` when `egress_proxy=True`, so `event_stream`
    can drain hostname-level proxy events into the stream and `stop` can shut
    the proxy down.

    `gateway_ip` caches the container's resolved default-route gateway (the
    address it reaches the host — and thus the proxy — through). Resolved
    best-effort once on the first poll so the IP-level `/proc/net/tcp` poller
    can suppress the *sanctioned* hop to the proxy without masking a genuine
    raw-IP connection that bypasses the proxy.
    """

    proxy: Any  # mcp_contract.proxy.server.EgressProxy
    events: "queue.Queue[BehaviorEvent]"
    gateway_ip: str | None = None
    gateway_resolved: bool = False


def _decode_proc_addr(hex_addr: str) -> str | None:
    """Decode a /proc/net/tcp{,6} hex address into a printable IP.

    IPv4 is 8 hex chars: one 32-bit word printed in host (little-endian)
    byte order. IPv6 is 32 hex chars: four 32-bit words, each printed in
    little-endian byte order. IPv4-mapped IPv6 collapses to dotted quad.
    """
    try:
        if len(hex_addr) == 8:
            return ".".join(str(b) for b in bytes.fromhex(hex_addr)[::-1])
        if len(hex_addr) == 32:
            raw = b"".join(
                bytes.fromhex(hex_addr[i : i + 8])[::-1] for i in range(0, 32, 8)
            )
            addr = ipaddress.IPv6Address(raw)
            mapped = addr.ipv4_mapped
            return str(mapped) if mapped is not None else str(addr)
    except ValueError:
        return None
    return None


def parse_default_gateway(text: str) -> str | None:
    """Return the container's default-route gateway IP from /proc/net/route.

    The default route is the row whose Destination is all-zero; its Gateway
    column is a little-endian hex IPv4 (the same encoding as /proc/net/tcp
    addresses, so `_decode_proc_addr` decodes it). This is the address the
    container reaches the host — and thus the egress proxy — through. Returns
    None when the table is absent, headerless, or has no usable default route.
    """
    lines = text.splitlines()
    if not lines:
        return None
    header = lines[0].split()
    try:
        dest_idx = header.index("Destination")
        gw_idx = header.index("Gateway")
    except ValueError:
        return None
    for line in lines[1:]:
        parts = line.split()
        if len(parts) <= max(dest_idx, gw_idx):
            continue
        if parts[dest_idx] != "00000000":  # not the default route
            continue
        gw = _decode_proc_addr(parts[gw_idx])
        if gw and gw != "0.0.0.0":
            return gw
    return None


# /proc/net/tcp states with no egress evidence: 0A=LISTEN and 07=CLOSE have
# no meaningful remote; 03=SYN_RECV is an inbound handshake. Every other
# state (ESTABLISHED, SYN_SENT, FIN_WAIT*, TIME_WAIT, CLOSE_WAIT, LAST_ACK,
# CLOSING) is a current or recent outbound remote — TIME_WAIT lingers ~60s,
# so short-lived connections stay visible across many polls.
_NON_EGRESS_STATES = frozenset({"0A", "07", "03"})


def parse_proc_net_tcp(text: str) -> list[tuple[str, int]]:
    """Extract remote egress endpoints from /proc/net/tcp{,6} content.

    Accepts concatenated tcp+tcp6 dumps. Skips header lines, LISTEN/CLOSE/
    SYN_RECV sockets (no egress evidence), wildcard remotes (addr 0,
    port 0), loopback remotes, and — critically — sockets whose LOCAL port
    is a listening port: those are inbound client connections to a serving
    MCP server, not egress, and reporting them would turn every legitimate
    client into a fake net.connect violation. Two passes are needed because
    LISTEN rows may appear after their inbound-connection rows and a tcp6
    listener (:::8080) covers v4-mapped clients in either file.

    Residual caveats: an outbound connection whose ephemeral local port
    happens to coincide with a listen port is a rare false negative, and a
    listener that closed before the poll snapshot leaks its inbound rows
    through. Returns unique (ip, port) pairs in first-seen order.
    """
    rows: list[tuple[str, str, str]] = []  # (local, remote, state)
    listen_ports: set[int] = set()
    for line in text.splitlines():
        parts = line.split()
        # Data rows start with "<n>:"; header rows ("sl local_address ...") don't.
        if len(parts) < 4 or not parts[0].endswith(":"):
            continue
        local, remote, state = parts[1], parts[2], parts[3]
        if state == "0A":
            _, sep, port_hex = local.partition(":")
            if sep:
                try:
                    listen_ports.add(int(port_hex, 16))
                except ValueError:
                    pass
            continue
        rows.append((local, remote, state))

    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for local, remote, state in rows:
        if state in _NON_EGRESS_STATES:
            continue
        _, sep, local_port_hex = local.partition(":")
        if sep:
            try:
                if int(local_port_hex, 16) in listen_ports:
                    continue  # inbound client connection, not egress
            except ValueError:
                pass
        addr_hex, sep, port_hex = remote.partition(":")
        if not sep:
            continue
        ip = _decode_proc_addr(addr_hex)
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        if ip is None or port == 0:
            continue
        if ip in ("0.0.0.0", "::", "::1") or ip.startswith("127."):
            continue
        endpoint = (ip, port)
        if endpoint not in seen:
            seen.add(endpoint)
            out.append(endpoint)
    return out


def parse_docker_top(text: str) -> list[tuple[int, str]]:
    """Parse `docker top` output into (pid, command) pairs.

    Handles both the `-eo pid,comm` shape (PID/COMM columns) and the
    default shape (UID PID PPID ... CMD). When the command column is the
    last header column, the row tail is joined so commands with spaces
    survive.
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []
    header = [h.upper() for h in lines[0].split()]
    if "PID" not in header:
        return []
    pid_idx = header.index("PID")
    cmd_idx: int | None = None
    for name in ("COMM", "CMD", "COMMAND", "ARGS"):
        if name in header:
            cmd_idx = header.index(name)
            break
    out: list[tuple[int, str]] = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) <= pid_idx:
            continue
        try:
            pid = int(parts[pid_idx])
        except ValueError:
            continue
        cmd = ""
        if cmd_idx is not None and len(parts) > cmd_idx:
            if cmd_idx == len(header) - 1:
                cmd = " ".join(parts[cmd_idx:])
            else:
                cmd = parts[cmd_idx]
        out.append((pid, cmd))
    return out


class DockerAdapter:
    """Sandbox backend shelling out to the docker CLI."""

    name = "docker"

    def __init__(
        self,
        docker_bin: str = "docker",
        poll_interval: float = 1.0,
        egress_proxy: bool = False,
    ) -> None:
        self.docker_bin = docker_bin
        self.poll_interval = poll_interval
        # When True, start() boots an in-process EgressProxy and routes the
        # container's HTTP(S) traffic through it (hostname-level enforcement).
        self.egress_proxy = egress_proxy

    def capabilities(self) -> BackendCaps:
        """Honest declaration — see module docstring for the gap list.

        With `egress_proxy=True` the network axis is `ENFORCE` (the proxy
        applies the allowlist, deny-by-default); otherwise `OBSERVE` (the
        `/proc/net/tcp` poller sees IPs only, never blocks).
        """
        return BackendCaps(
            network=(
                SupportLevel.ENFORCE if self.egress_proxy else SupportLevel.OBSERVE
            ),
            filesystem=SupportLevel.ENFORCE,
            process=SupportLevel.OBSERVE,
            syscall=SupportLevel.NONE,
            boot_time_policy=True,
            runtime_block=True,
        )

    def _run(
        self, args: list[str], env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.docker_bin, *args],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def start(self, spec: ServerSpec, policy: Policy) -> ServerHandle:
        """`docker run` the image with the policy translated to native flags.

        When `egress_proxy=True` and the policy allows any egress
        (`plan.mode in {"allowlist", "open"}`), an `EgressProxy` is started on
        the host first and the container's HTTP(S) traffic is routed through
        it; its handle rides on `ServerHandle.native` for draining/teardown.
        """
        if not spec.image:
            raise ValueError("docker backend requires spec.image")

        # Lazy import keeps the proxy package an optional, run-time dependency
        # (no import-time coupling with the parallel proxy module).
        from mcp_contract.proxy.plan import egress_plan

        plan = egress_plan(policy)
        channel: _ProxyChannel | None = None
        proxy_endpoint: str | None = None
        if self.egress_proxy and plan.mode in ("allowlist", "open"):
            from mcp_contract.proxy.server import EgressProxy

            events: "queue.Queue[BehaviorEvent]" = queue.Queue()
            # Bind on 0.0.0.0 so the container can reach the proxy over the
            # bridge via host.docker.internal; on_event feeds the drain queue.
            # A per-run credential closes the open-relay exposure of the
            # 0.0.0.0 bind: only a client holding the token (the container, via
            # its HTTP_PROXY env) is served; any other LAN peer gets 407.
            token = secrets.token_urlsafe(24)
            proxy = EgressProxy(
                plan,
                on_event=events.put,
                host="0.0.0.0",
                port=0,
                auth_token=token,
            )
            proxy.start()
            proxy_endpoint = (
                f"http://mcp:{token}@host.docker.internal:{proxy.port}"
            )
            channel = _ProxyChannel(proxy=proxy, events=events)

        try:
            # Network flags come solely from translate_network_args; strip the
            # baseline network flag so we never double-add one.
            policy_args = _without_network_flag(translate_policy_args(policy, spec))
            net_args = translate_network_args(plan, proxy_endpoint, spec)
            args = ["run", *policy_args, *net_args]
            if spec.workdir:
                args += ["-w", spec.workdir]
            args.append(spec.image)
            args += list(spec.command)
            # spec.env goes into the CLI's environment so `-e VAR` passthrough
            # resolves without secrets ever appearing in argv.
            env = {**os.environ, **spec.env}
            res = self._run(args, env=env)
            if res.returncode != 0:
                raise RuntimeError(
                    f"docker run failed ({res.returncode}): {res.stderr.strip()}"
                )
            container_id = (
                res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
            )
            if not container_id:
                raise RuntimeError("docker run succeeded but printed no container id")
        except BaseException:
            # Don't leak the proxy thread if the container failed to launch.
            if channel is not None:
                try:
                    channel.proxy.stop()
                except Exception:
                    pass
            raise
        return ServerHandle(
            id=container_id, backend=self.name, spec=spec, native=channel
        )

    def _container_state(self, container_id: str) -> bool | None:
        """True/False when `docker inspect` answers definitively, else None.

        None means the daemon failed to answer (transient error, restart,
        throttling) — NOT that the container exited. Conflating the two
        would silently end observation of a still-running server.
        """
        res = self._run(["inspect", "-f", "{{.State.Running}}", container_id])
        if res.returncode != 0:
            return None
        answer = res.stdout.strip()
        if answer == "true":
            return True
        if answer == "false":
            return False
        return None

    def _running(self, container_id: str, attempts: int = 3) -> bool:
        """Whether the container is running; fail LOUD when unknowable.

        Retries transient `docker inspect` failures, then raises rather
        than returning False: a monitor that silently stops observing a
        live container is an unobserved attacker.
        """
        for attempt in range(attempts):
            state = self._container_state(container_id)
            if state is not None:
                return state
            if attempt + 1 < attempts:
                time.sleep(self.poll_interval)
        raise RuntimeError(
            f"docker inspect failed {attempts}x for {container_id}; container "
            "state unknown — cannot distinguish exit from daemon failure"
        )

    @staticmethod
    def _drain_proxy(channel: _ProxyChannel) -> Iterator[BehaviorEvent]:
        """Yield every proxy event currently queued, non-blocking."""
        while True:
            try:
                yield channel.events.get_nowait()
            except queue.Empty:
                return

    def event_stream(self, handle: ServerHandle) -> Iterator[BehaviorEvent]:
        """Poll the container for new remote endpoints and new pids.

        Emits `net.connect` (detail: ip/port — IPs, not hostnames) and
        `proc.spawn` (detail: cmd/pid) from polling, and — when an egress
        proxy is wired — hostname-level `net.connect` events (`via="proxy"`)
        drained from the proxy each cycle. Ends when the container exits, at
        which point the proxy is stopped.
        """
        seen_endpoints: set[tuple[str, int]] = set()
        seen_pids: set[int] = set()
        channel = handle.native if isinstance(handle.native, _ProxyChannel) else None
        try:
            while self._running(handle.id):
                # Resolve the container's default gateway once (best-effort): it
                # is the address the container reaches the egress proxy through,
                # so (gateway_ip, proxy_port) is the sanctioned hop, not drift.
                if channel is not None and not channel.gateway_resolved:
                    channel.gateway_resolved = True
                    route = self._run(
                        ["exec", handle.id, "cat", "/proc/net/route"]
                    )
                    if route.returncode == 0:
                        channel.gateway_ip = parse_default_gateway(route.stdout)
                net = self._run(
                    ["exec", handle.id, "cat", "/proc/net/tcp", "/proc/net/tcp6"]
                )
                # cat may exit non-zero when tcp6 is absent yet still print tcp.
                for ip, port in parse_proc_net_tcp(net.stdout):
                    # Suppress the sanctioned hop to the egress proxy: the proxy
                    # already emits a hostname-level net.connect for everything
                    # flowing through it, so the container->gateway->proxy TCP
                    # connection is not a bypass and must not be flagged
                    # outside_contract. Match the exact (gateway_ip, proxy_port)
                    # tuple when the gateway is known; fall back to port-only
                    # suppression when it could not be resolved.
                    if channel is not None and port == channel.proxy.port and (
                        channel.gateway_ip is None or ip == channel.gateway_ip
                    ):
                        continue
                    if (ip, port) in seen_endpoints:
                        continue
                    seen_endpoints.add((ip, port))
                    yield BehaviorEvent(
                        ts=time.time(),
                        kind=EventKind.NET_CONNECT,
                        detail={"ip": ip, "port": port},
                        backend=self.name,
                    )
                top = self._run(["top", handle.id, "-eo", "pid,comm"])
                if top.returncode != 0:
                    top = self._run(["top", handle.id])
                if top.returncode == 0:
                    for pid, cmd in parse_docker_top(top.stdout):
                        if pid in seen_pids:
                            continue
                        seen_pids.add(pid)
                        yield BehaviorEvent(
                            ts=time.time(),
                            kind=EventKind.PROC_SPAWN,
                            detail={"cmd": cmd, "pid": pid},
                            backend=self.name,
                        )
                if channel is not None:
                    yield from self._drain_proxy(channel)
                time.sleep(self.poll_interval)
            # Container exited: surface any events emitted just before exit.
            if channel is not None:
                yield from self._drain_proxy(channel)
        finally:
            # Stop the proxy on container exit or early generator close; stop()
            # also calls this idempotently, so double-stop is harmless.
            if channel is not None:
                try:
                    channel.proxy.stop()
                except Exception:
                    pass

    def block(self, handle: ServerHandle, event: BehaviorEvent) -> None:
        """Coarse enforcement: kill the container (no finer hook in v0).

        A failed kill must not be silent — enforcement that no-ops while
        the report claims the action was stopped is worse than no
        enforcement. The benign race (container already exited, `--rm`
        reaped it) is tolerated; a surviving container raises.
        """
        res = self._run(["kill", handle.id])
        if res.returncode != 0 and self._running(handle.id):
            raise RuntimeError(
                f"enforce failed: docker kill {handle.id} returned "
                f"{res.returncode} ({res.stderr.strip()}) and the container "
                "is still running"
            )

    def stop(self, handle: ServerHandle) -> None:
        """Force-remove the container; already-gone containers are fine.

        The egress proxy (if any) is shut down first, best-effort — its
        `stop()` is idempotent, so an already-stopped proxy is a no-op. A
        failed removal is retried once and then raised — a silently failed
        stop leaves the container alive and unobserved.
        """
        if isinstance(handle.native, _ProxyChannel):
            try:
                handle.native.proxy.stop()
            except Exception:
                pass
        for attempt in range(2):
            res = self._run(["rm", "-f", handle.id])
            if res.returncode == 0 or "no such container" in res.stderr.lower():
                return
            if attempt == 0:
                time.sleep(self.poll_interval)
        raise RuntimeError(
            f"docker rm -f {handle.id} failed ({res.returncode}): "
            f"{res.stderr.strip()} — the container may still be running"
        )
