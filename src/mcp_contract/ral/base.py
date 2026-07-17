"""RAL — Runtime Adapter Layer interface.

PIE and BCM only ever talk to `RuntimeAdapter`. Adding a sandbox backend
means implementing this protocol; the core never changes.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Iterator, Protocol, runtime_checkable

from mcp_contract.models import BehaviorEvent, Policy


class SupportLevel(str, enum.Enum):
    """How far a backend can go on one observation/enforcement axis."""

    NONE = "none"        # backend cannot see or restrict this axis
    OBSERVE = "observe"  # backend can emit events for this axis
    ENFORCE = "enforce"  # backend can additionally restrict/block this axis


@dataclass
class BackendCaps:
    """Honest declaration of what a backend supports (spec §6.3).

    ENFORCE on an axis may mean boot-time restriction (e.g. Docker mounts)
    rather than per-event blocking; `boot_time_policy` says whether the
    backend applies the policy at start, and `runtime_block` whether
    `RuntimeAdapter.block` can stop an in-flight action at all (the
    coarsest legal implementation is killing the server).
    """

    network: SupportLevel = SupportLevel.NONE
    filesystem: SupportLevel = SupportLevel.NONE
    process: SupportLevel = SupportLevel.NONE
    syscall: SupportLevel = SupportLevel.NONE
    boot_time_policy: bool = False
    runtime_block: bool = False


@dataclass
class ServerSpec:
    """Backend-agnostic description of how to launch an MCP server."""

    server_id: str
    image: str | None = None                          # OCI image (container backends)
    command: list[str] = field(default_factory=list)  # argv (process backends)
    env: dict[str, str] = field(default_factory=dict)
    workdir: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)  # backend-specific knobs


@dataclass
class ServerHandle:
    """A running (or replayed) server instance, as seen by one backend."""

    id: str  # backend-native id (container id, pid, ...)
    backend: str
    spec: ServerSpec
    native: Any = None


@runtime_checkable
class RuntimeAdapter(Protocol):
    """One sandbox backend.

    Contract:
    - `start` translates the neutral policy into backend-native rules and
      boots the server with them applied (deny-by-default for everything
      the backend can enforce and the policy does not grant).
    - `event_stream` yields normalized `BehaviorEvent`s until the server
      stops; it must not raise on server exit, just end.
    - `block` is only called in enforce mode and only for events whose
      classification is OUTSIDE_CONTRACT.
    """

    name: str

    def capabilities(self) -> BackendCaps: ...

    def start(self, spec: ServerSpec, policy: Policy) -> ServerHandle: ...

    def event_stream(self, handle: ServerHandle) -> Iterator[BehaviorEvent]: ...

    def block(self, handle: ServerHandle, event: BehaviorEvent) -> None: ...

    def stop(self, handle: ServerHandle) -> None: ...
