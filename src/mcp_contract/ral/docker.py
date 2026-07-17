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

All subprocess calls go through the docker CLI (no docker-py), with
`check=False`, captured output, and never `shell=True`.
"""
from __future__ import annotations

import ipaddress
import os
import posixpath
import subprocess
import time
from typing import Iterator

from mcp_contract.models import BehaviorEvent, CapabilityId, EventKind, Policy
from mcp_contract.ral.base import BackendCaps, ServerHandle, ServerSpec, SupportLevel


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

    def __init__(self, docker_bin: str = "docker", poll_interval: float = 1.0) -> None:
        self.docker_bin = docker_bin
        self.poll_interval = poll_interval

    def capabilities(self) -> BackendCaps:
        """Honest declaration — see module docstring for the gap list."""
        return BackendCaps(
            network=SupportLevel.OBSERVE,
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
        """`docker run` the image with the policy translated to native flags."""
        if not spec.image:
            raise ValueError("docker backend requires spec.image")
        args = ["run", *translate_policy_args(policy, spec)]
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
        container_id = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
        if not container_id:
            raise RuntimeError("docker run succeeded but printed no container id")
        return ServerHandle(id=container_id, backend=self.name, spec=spec)

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

    def event_stream(self, handle: ServerHandle) -> Iterator[BehaviorEvent]:
        """Poll the container for new remote endpoints and new pids.

        Emits `net.connect` (detail: ip/port — IPs, not hostnames) and
        `proc.spawn` (detail: cmd/pid). Ends when the container exits.
        """
        seen_endpoints: set[tuple[str, int]] = set()
        seen_pids: set[int] = set()
        while self._running(handle.id):
            net = self._run(
                ["exec", handle.id, "cat", "/proc/net/tcp", "/proc/net/tcp6"]
            )
            # cat may exit non-zero when tcp6 is absent yet still print tcp.
            for ip, port in parse_proc_net_tcp(net.stdout):
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
            time.sleep(self.poll_interval)

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

        A failed removal is retried once and then raised — a silently
        failed stop leaves the container alive and unobserved.
        """
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
