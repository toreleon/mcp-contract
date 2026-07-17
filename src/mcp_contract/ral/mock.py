"""Mock RAL backend: replays pre-recorded events for tests and CI.

No sandbox is involved. `start` records what it was asked to do,
`event_stream` replays the injected events, and `block` collects the events
the monitor decided to block so tests can assert on them.
"""
from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path
from typing import Iterator, Sequence

from mcp_contract.models import BehaviorEvent, EventKind, Policy
from mcp_contract.ral.base import BackendCaps, ServerHandle, ServerSpec, SupportLevel

_KNOWN_KINDS = frozenset(k.value for k in EventKind)


def _load_events_jsonl(path: str | Path) -> list[BehaviorEvent]:
    """Read one BehaviorEvent per non-blank line from a JSONL file.

    Same format (and same unknown-kind/error semantics) as `bcm.report`;
    parsed locally to avoid an import cycle. Unknown kinds become
    informational syscall events (original kind in detail["group"]);
    malformed lines raise ValueError with file:line context.
    """
    events: list[BehaviorEvent] = []
    warned = False
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if not isinstance(d, dict):
                    raise ValueError("event line is not a JSON object")
                kind = d.get("kind")
                if not isinstance(kind, str) or not kind:
                    raise ValueError(f"event has no usable 'kind': {kind!r}")
                remapped = kind not in _KNOWN_KINDS
                if remapped:
                    detail = d.get("detail")
                    detail = dict(detail) if isinstance(detail, dict) else {}
                    detail.setdefault("group", kind)
                    d = {**d, "kind": EventKind.SYSCALL.value, "detail": detail}
                events.append(BehaviorEvent.from_dict(d))
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"{path}:{lineno}: bad event: {exc}") from exc
            if remapped and not warned:
                warned = True
                print(
                    f"[mcp-contract] warning: {path}:{lineno}: unknown event "
                    "kind(s) treated as informational (within_policy)",
                    file=sys.stderr,
                )
    return events


class MockAdapter:
    """Replay backend: yields injected events instead of observing a sandbox."""

    name = "mock"

    def __init__(self, events: Sequence[BehaviorEvent] | str | Path = ()) -> None:
        if isinstance(events, (str, Path)):
            self.events: list[BehaviorEvent] = _load_events_jsonl(events)
        else:
            self.events = list(events)
        self.blocked: list[BehaviorEvent] = []
        self.started: list[tuple[ServerSpec, Policy]] = []
        self.stopped: list[ServerHandle] = []
        self._ids = itertools.count(1)

    def capabilities(self) -> BackendCaps:
        """The mock pretends to be a perfect backend (it replays, after all)."""
        return BackendCaps(
            network=SupportLevel.ENFORCE,
            filesystem=SupportLevel.ENFORCE,
            process=SupportLevel.ENFORCE,
            syscall=SupportLevel.ENFORCE,
            boot_time_policy=True,
            runtime_block=True,
        )

    def start(self, spec: ServerSpec, policy: Policy) -> ServerHandle:
        """Record the spec+policy and hand back a synthetic handle."""
        self.started.append((spec, policy))
        return ServerHandle(
            id=f"mock-{next(self._ids)}",
            backend=self.name,
            spec=spec,
            native=policy,
        )

    def event_stream(self, handle: ServerHandle) -> Iterator[BehaviorEvent]:
        """Replay the injected events in order, then end."""
        yield from self.events

    def block(self, handle: ServerHandle, event: BehaviorEvent) -> None:
        """Record the event as blocked (visible to tests via `self.blocked`)."""
        self.blocked.append(event)

    def stop(self, handle: ServerHandle) -> None:
        """No-op: nothing is running. Records the handle for assertions."""
        self.stopped.append(handle)
