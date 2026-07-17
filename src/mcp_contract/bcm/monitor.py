"""BCM runtime monitor: drive an adapter's event stream against a contract."""
from __future__ import annotations

import json
import queue
import sys
import threading
import time
from typing import Callable

from mcp_contract.bcm.contract import manifest_implied_caps
from mcp_contract.bcm.diff import classify_event, track_tool_ctx
from mcp_contract.models import (
    BehaviorEvent,
    EventClass,
    Manifest,
    Mode,
    Policy,
    ViolationReport,
)
from mcp_contract.ral.base import RuntimeAdapter, ServerHandle


class ManifestDriftError(Exception):
    """The manifest changed since the policy was inferred (rug-pull gate).

    Carries the `expected` hash (what the policy was generated from) and
    the `actual` hash (what the manifest hashes to now).
    """

    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(
            f"manifest drift: policy was generated from manifest {expected} "
            f"but the current manifest hashes to {actual}; re-run infer and "
            "re-approve, or pass allow_drift=True to monitor anyway"
        )
        self.expected = expected
        self.actual = actual


def _default_alert(event: BehaviorEvent) -> None:
    """Default on_alert: one line to stderr per outside_contract event."""
    print(
        "[mcp-contract] outside_contract: "
        f"{event.kind.value} tool_ctx={event.tool_ctx or '-'} "
        f"detail={json.dumps(event.detail, sort_keys=True)}",
        file=sys.stderr,
    )


class Monitor:
    """Consume an adapter's event stream and classify it against the contract.

    Modes: OBSERVE only records; ALERT additionally calls `on_alert` for
    every outside_contract event; ENFORCE additionally asks the adapter
    to block those events.
    """

    def __init__(
        self,
        adapter: RuntimeAdapter,
        handle: ServerHandle,
        policy: Policy,
        manifest: Manifest,
        mode: Mode,
        *,
        on_alert: Callable[[BehaviorEvent], None] | None = None,
        allow_drift: bool = False,
    ) -> None:
        actual = manifest.hash()
        if policy.manifest_hash != actual and not allow_drift:
            raise ManifestDriftError(policy.manifest_hash, actual)
        self.adapter = adapter
        self.handle = handle
        self.policy = policy
        self.manifest = manifest
        self.mode = mode
        self.on_alert = on_alert if on_alert is not None else _default_alert
        self.manifest_caps = manifest_implied_caps(manifest)

    def run(
        self,
        *,
        max_events: int | None = None,
        duration: float | None = None,
    ) -> ViolationReport:
        """Classify events in place until the stream ends, `max_events`
        have been processed, or `duration` seconds have elapsed.

        The duration deadline is enforced even when the adapter's stream
        blocks without yielding (a quiet-but-alive server): with a
        `duration`, the stream is pumped from a daemon thread and consumed
        with a bounded wait, so `run` returns on time regardless of the
        adapter's behavior.
        """
        report = ViolationReport(
            server_id=self.policy.server_id,
            manifest_hash=self.policy.manifest_hash,
            mode=self.mode,
        )
        tool_ctx: str | None = None

        def handle_event(event: BehaviorEvent) -> bool:
            """Classify/alert/block one event; True when run should stop."""
            nonlocal tool_ctx
            tool_ctx = track_tool_ctx(event, tool_ctx)
            event.classification = classify_event(
                event, self.policy, self.manifest_caps
            )
            report.events.append(event)
            if event.classification is EventClass.OUTSIDE_CONTRACT:
                if self.mode in (Mode.ALERT, Mode.ENFORCE):
                    self.on_alert(event)
                if self.mode is Mode.ENFORCE:
                    self.adapter.block(self.handle, event)
            return max_events is not None and len(report.events) >= max_events

        if duration is None:
            for event in self.adapter.event_stream(self.handle):
                if handle_event(event):
                    break
            return report

        deadline = time.monotonic() + duration
        events_q: queue.Queue[BehaviorEvent | None] = queue.Queue()
        pump_error: list[BaseException] = []

        def pump() -> None:
            try:
                for event in self.adapter.event_stream(self.handle):
                    events_q.put(event)
            except BaseException as exc:  # noqa: BLE001 — re-raised in run()
                pump_error.append(exc)
            finally:
                events_q.put(None)

        threading.Thread(target=pump, daemon=True).start()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                event = events_q.get(timeout=remaining)
            except queue.Empty:
                break  # deadline hit while the stream was blocking
            if event is None:
                if pump_error:
                    raise pump_error[0]
                break  # stream ended
            if handle_event(event):
                break
        return report
