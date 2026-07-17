"""mcp-contract command-line interface (spec §8.1).

Subcommands:
  infer   manifest -> least-privilege policy YAML (needs_review summary on stderr)
  run     start (or replay) a server on a sandbox backend and monitor it
  audit   offline classification of a recorded event stream (always exit 0)
  verify  CI gate: exit 2 on manifest-hash mismatch (rug-pull), 1 on any
          outside_contract event, 4 when the input is missing/corrupt or
          zero events were observed (inconclusive, never a security
          signal; --allow-empty accepts an empty stream), 0 clean
  proxy   run the enforcing egress proxy standalone (deny-by-default,
          hostname-level net.http enforcement; every attempt logged)

Conventions: human-facing chatter goes to stderr; machine output (YAML/JSON)
goes to stdout. PIE/BCM/policy modules are imported inside the subcommand
handlers so `--help` stays fast and backends stay optional.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Callable, TextIO

from mcp_contract.models import (
    BehaviorEvent,
    CapabilityId,
    CapabilityStatus,
    Mode,
    Severity,
    ViolationReport,
)

EXIT_OK = 0
EXIT_VIOLATION = 1      # run: critical severity; verify: outside_contract seen
EXIT_USAGE = 2          # bad invocation (argparse convention)
EXIT_HASH_MISMATCH = 2  # verify: manifest changed since the policy was generated
EXIT_DRIFT = 3          # run: ManifestDriftError
# 4 = operational/inconclusive, never a security signal: a missing or
# corrupt manifest/policy/events file, or a verify run that observed zero
# events. Distinct from 1 (violation) and 2 (rug-pull) so a CI gate keyed
# on those codes is never triggered by a broken pipeline.
EXIT_BAD_INPUT = 4      # input file missing, unreadable, or corrupt
EXIT_NO_EVENTS = 4      # verify: zero events observed (inconclusive, not clean)


def _say(message: str) -> None:
    """Human-facing chatter; never mixed into machine output."""
    print(message, file=sys.stderr)


# Test seam for the `proxy` subcommand. When set, it is called with the bound
# EgressProxy right after start-up and is expected to drive traffic and then
# return, at which point the proxy is torn down. This lets tests exercise the
# standalone proxy in-process, on an ephemeral port, without real SIGINT
# delivery (which only reaches the main thread). Production leaves it None and
# blocks in `_wait_for_sigint`.
_PROXY_SERVE_HOOK: Callable[[object], None] | None = None


def _wait_for_sigint() -> None:
    """Block until SIGINT (Ctrl-C), then return so the caller can shut down."""
    stop = threading.Event()
    try:
        signal.signal(signal.SIGINT, lambda *_: stop.set())
    except ValueError:
        # Signal handlers install only on the main thread; when the proxy is
        # driven from a worker thread the caller uses the serve hook instead.
        pass
    try:
        stop.wait()
    except KeyboardInterrupt:  # pragma: no cover - defensive
        pass


def _print_report_summary(report: ViolationReport, stream: TextIO) -> None:
    """Render a short human-readable report (shared by run/audit)."""
    counts = report.counts()
    print(
        f"[{report.server_id}] mode={report.mode.value} "
        f"events={len(report.events)} severity={report.severity.value}",
        file=stream,
    )
    print("  " + "  ".join(f"{name}={counts[name]}" for name in counts), file=stream)
    for event in report.violations:
        detail = json.dumps(event.detail, sort_keys=True)
        print(
            f"  OUTSIDE CONTRACT: {event.kind.value} {detail} "
            f"(tool_ctx={event.tool_ctx or '-'})",
            file=stream,
        )
    print(f"  suggested action: {report.suggested_action}", file=stream)


def _cmd_infer(args: argparse.Namespace) -> int:
    """Infer a policy from a manifest; emit YAML (or JSON) to stdout/--output."""
    from mcp_contract.manifest import load_manifest
    from mcp_contract.pie.inference import infer_policy
    from mcp_contract.policy import dump_policy, policy_to_dict

    manifest = load_manifest(args.manifest)
    policy = infer_policy(manifest, server_id=args.server_id)

    if args.json:
        text = json.dumps(policy_to_dict(policy), indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    else:
        text = dump_policy(policy, args.output)  # writes the file when --output is set
        if not args.output:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")
    if args.output:
        _say(f"wrote policy for server {policy.server_id!r} to {args.output}")

    review = [c for c in policy.caps if c.status is CapabilityStatus.NEEDS_REVIEW]
    if review:
        _say(f"{len(review)} caps need review: " + ", ".join(c.id.value for c in review))
        for cap in review:
            scope = ", ".join(cap.values) if cap.values else "(class-level, scope unknown)"
            _say(f"  {cap.id.value}: {scope}")
        _say(
            "approve by editing the policy YAML: flip status needs_review -> inferred "
            "and narrow values to what the server really needs"
        )
    else:
        _say("0 caps need review")
    return EXIT_OK


def _cmd_run(args: argparse.Namespace) -> int:
    """Start (or replay) a server on a backend and monitor it live."""
    from mcp_contract.bcm.monitor import ManifestDriftError, Monitor
    from mcp_contract.bcm.report import dump_events_jsonl
    from mcp_contract.manifest import load_manifest
    from mcp_contract.policy import load_policy
    from mcp_contract.ral import ServerSpec, get_adapter

    manifest = load_manifest(args.manifest)
    # Path() so a mistyped --policy fails as "file not found" instead of
    # being reinterpreted as inline YAML text (load_policy's str form).
    policy = load_policy(Path(args.policy))

    if args.backend == "mock":
        if args.egress_proxy:
            _say(
                "note: --egress-proxy has no effect with --backend mock "
                "(mock replays recorded events); ignoring"
            )
        if not args.events_in:
            _say("error: --backend mock replays a recorded stream; pass --events-in FILE")
            return EXIT_USAGE
        adapter = get_adapter("mock", events=args.events_in)
    else:
        if not args.image:
            _say("error: --backend docker requires --image")
            return EXIT_USAGE
        # egress_proxy=True makes the docker adapter route the container's
        # egress through an EgressProxy for hostname-level net.http ENFORCE.
        adapter = get_adapter("docker", egress_proxy=args.egress_proxy)

    # Only granted env values are forwarded from the host environment; the
    # adapter filters again on its side (defense in depth).
    env: dict[str, str] = {}
    granted_env = policy.granted(CapabilityId.ENV)
    if granted_env is not None:
        env = {v: os.environ[v] for v in granted_env.values if v in os.environ}
    spec = ServerSpec(
        server_id=policy.server_id,
        image=args.image,
        command=list(args.cmd or []),
        env=env,
    )

    handle = adapter.start(spec, policy)
    try:
        monitor = Monitor(
            adapter,
            handle,
            policy,
            manifest,
            Mode(args.mode),
            allow_drift=args.allow_drift,
        )
        report = monitor.run(max_events=args.max_events, duration=args.duration)
    except ManifestDriftError as exc:
        _say(
            f"manifest drift: {exc} — the manifest changed since this policy was "
            "generated; re-run `mcp-contract infer` and re-approve "
            "(or pass --allow-drift to proceed anyway)"
        )
        return EXIT_DRIFT
    finally:
        try:
            adapter.stop(handle)
        except Exception:  # noqa: BLE001 — best-effort cleanup, keep the real outcome
            pass

    if args.events_out:
        dump_events_jsonl(report.events, args.events_out)
        _say(f"wrote {len(report.events)} events to {args.events_out}")
    if args.report_out:
        Path(args.report_out).write_text(report.to_json() + "\n", encoding="utf-8")
        _say(f"wrote report to {args.report_out}")

    _print_report_summary(report, sys.stderr)
    return EXIT_VIOLATION if report.severity is Severity.CRITICAL else EXIT_OK


def _cmd_audit(args: argparse.Namespace) -> int:
    """Classify a recorded event stream offline; reporting only (exit 0)."""
    from mcp_contract.bcm.report import classify_events, load_events_jsonl
    from mcp_contract.manifest import load_manifest
    from mcp_contract.policy import load_policy

    events = load_events_jsonl(args.events)
    policy = load_policy(Path(args.policy))
    manifest = load_manifest(args.manifest)
    report = classify_events(events, policy, manifest)

    _print_report_summary(report, sys.stderr)
    if args.json:
        print(report.to_json())
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    """CI gate: 2 = hash mismatch, 1 = outside_contract, 4 = no events, 0 = clean."""
    from mcp_contract.bcm.report import classify_events, load_events_jsonl
    from mcp_contract.manifest import load_manifest
    from mcp_contract.policy import load_policy, verify_manifest_hash

    manifest = load_manifest(args.manifest)
    policy = load_policy(Path(args.policy))

    if not verify_manifest_hash(policy, manifest):
        _say(
            "VERIFY FAIL: manifest hash mismatch "
            f"(policy: {policy.manifest_hash}, manifest: {manifest.hash()}) — "
            "the manifest changed since this policy was generated (possible "
            "rug-pull); re-run `mcp-contract infer` and re-approve"
        )
        return EXIT_HASH_MISMATCH

    events = load_events_jsonl(args.events)
    report = classify_events(events, policy, manifest)
    print(json.dumps(report.counts()))

    violations = len(report.violations)
    if violations:
        _say(f"VERIFY FAIL: {violations} event(s) outside the declared contract")
        return EXIT_VIOLATION
    if not report.events and not args.allow_empty:
        _say(
            "VERIFY INCONCLUSIVE: 0 events observed — the monitor may have "
            "captured nothing (harness failure?); pass --allow-empty to "
            "accept an empty stream as clean"
        )
        return EXIT_NO_EVENTS
    _say(f"VERIFY OK: {len(report.events)} event(s), none outside the contract")
    return EXIT_OK


def _cmd_proxy(args: argparse.Namespace) -> int:
    """Run the enforcing egress proxy standalone (backend-agnostic).

    Point any MCP server or client at it via HTTP_PROXY/HTTPS_PROXY. The
    allowlist comes from `--allow HOST ...` or, with `--policy FILE`, from the
    policy's granted `net.http` (`egress_plan`, deny-by-default). Every
    connection attempt — allowed or denied — is emitted as one JSON line to
    stdout and appended to `--events-out` when given. Runs until SIGINT and
    exits 0 on a clean shutdown; a denied host is 403'd and never dialled
    upstream.
    """
    from mcp_contract.proxy.plan import egress_plan
    from mcp_contract.proxy.server import EgressProxy

    if args.allow and args.policy:
        _say("error: pass either --allow or --policy, not both")
        return EXIT_USAGE

    allow: object
    if args.policy:
        # Path() so a mistyped --policy fails as "file not found" rather than
        # being reinterpreted as inline YAML text (load_policy's str form).
        from mcp_contract.policy import load_policy

        plan = egress_plan(load_policy(Path(args.policy)))
        allow = plan
        hosts = ", ".join(plan.hosts) if plan.hosts else "(none)"
        _say(f"egress plan from {args.policy}: mode={plan.mode} hosts={hosts}")
    elif args.allow:
        allow = list(args.allow)  # bare list => allowlist (deny-by-default)
        _say("egress allowlist: " + ", ".join(allow))
    else:
        # Deny-by-default: no allowlist means block (and observe) all egress.
        allow = []
        _say("no --allow/--policy given: denying all egress (deny-by-default)")

    # Append mode: an --events-out log accumulates across proxy runs and is
    # never clobbered (it may be a standing audit trail).
    events_file = (
        open(args.events_out, "a", encoding="utf-8") if args.events_out else None
    )

    def _on_event(event: BehaviorEvent) -> None:
        # Called synchronously under the proxy's lock, so lines from
        # concurrent tunnels never interleave.
        line = json.dumps(event.to_dict(), sort_keys=True)
        print(line, file=sys.stdout, flush=True)
        if events_file is not None:
            events_file.write(line + "\n")
            events_file.flush()

    attempts: list[BehaviorEvent] = []
    try:
        with EgressProxy(
            allow, on_event=_on_event, host=args.host, port=args.port
        ) as proxy:
            _say(
                f"egress proxy listening on {proxy.address[0]}:{proxy.port} "
                "(Ctrl-C to stop)"
            )
            hook = _PROXY_SERVE_HOOK
            if hook is not None:
                hook(proxy)  # test seam: drive clients in-process, then return
            else:
                _wait_for_sigint()
            attempts = list(proxy.events)
    finally:
        if events_file is not None:
            events_file.close()

    allowed = sum(1 for e in attempts if e.detail.get("allowed"))
    _say(
        f"egress proxy stopped: {len(attempts)} connection attempt(s), "
        f"{allowed} allowed, {len(attempts) - allowed} denied"
    )
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    """Assemble the argparse tree for all four subcommands."""
    parser = argparse.ArgumentParser(
        prog="mcp-contract",
        description=(
            "Treat MCP tool manifests as enforceable contracts: infer "
            "least-privilege sandbox policies and monitor runtime behavior "
            "for drift from what the server declared."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "infer", help="infer a least-privilege policy from an MCP manifest"
    )
    p.add_argument("manifest", help="manifest file (tools/list JSON or YAML)")
    p.add_argument("-o", "--output", default=None, help="write the policy to FILE")
    p.add_argument("--server-id", default=None, help="override the server id")
    p.add_argument("--json", action="store_true", help="emit JSON instead of YAML")
    p.set_defaults(func=_cmd_infer)

    p = sub.add_parser("run", help="run a server on a sandbox backend and monitor it")
    p.add_argument("manifest", help="manifest file the policy was inferred from")
    p.add_argument("--policy", required=True, help="policy YAML to enforce/compare")
    p.add_argument("--backend", required=True, choices=["docker", "mock"])
    p.add_argument(
        "--mode",
        required=True,
        choices=[Mode.OBSERVE.value, Mode.ALERT.value, Mode.ENFORCE.value],
    )
    p.add_argument("--image", default=None, help="OCI image (docker backend)")
    p.add_argument("--cmd", nargs="+", default=None, help="server argv")
    p.add_argument("--events-in", default=None, help="JSONL replayed by the mock backend")
    p.add_argument("--events-out", default=None, help="write classified events JSONL")
    p.add_argument("--report-out", default=None, help="write the report as JSON")
    p.add_argument("--duration", type=float, default=None, help="stop after SEC seconds")
    p.add_argument("--max-events", type=int, default=None, help="stop after N events")
    p.add_argument(
        "--allow-drift",
        action="store_true",
        help="proceed even if the manifest hash no longer matches the policy",
    )
    p.add_argument(
        "--egress-proxy",
        action="store_true",
        help="(docker backend) enforce hostname-level net.http by routing "
        "container egress through an egress proxy; no effect with --backend mock",
    )
    p.set_defaults(func=_cmd_run)

    p = sub.add_parser("audit", help="classify a recorded event stream offline")
    p.add_argument("--events", required=True, help="events JSONL file")
    p.add_argument("--policy", required=True, help="policy YAML file")
    p.add_argument("--manifest", required=True, help="manifest file")
    p.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    p.set_defaults(func=_cmd_audit)

    p = sub.add_parser(
        "verify",
        help=(
            "CI gate: exit 2 on manifest drift (rug-pull), 1 on contract "
            "violations, 4 on missing/corrupt input or zero observed events "
            "(inconclusive), 0 clean"
        ),
    )
    p.add_argument("manifest", help="manifest file")
    p.add_argument("--policy", required=True, help="policy YAML file")
    p.add_argument("--events", required=True, help="events JSONL file")
    p.add_argument(
        "--allow-empty",
        action="store_true",
        help="treat an events file with zero events as clean instead of "
        "inconclusive (exit 4)",
    )
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser(
        "proxy",
        help="run the enforcing egress proxy standalone (deny-by-default)",
        description=(
            "Run the hostname-level egress proxy standalone and point any MCP "
            "server or client at it (HTTP_PROXY/HTTPS_PROXY). Denies by "
            "default; allowed and denied attempts are logged as JSONL to "
            "stdout. Runs until Ctrl-C."
        ),
    )
    p.add_argument(
        "--allow",
        nargs="*",
        default=None,
        metavar="HOST",
        help="allowlisted hostnames/patterns (exact, '*', or '*.example.com'); "
        "omit both --allow and --policy to deny all egress",
    )
    p.add_argument(
        "--policy",
        default=None,
        help="derive the allowlist from a policy YAML's granted net.http "
        "(egress_plan); mutually exclusive with --allow",
    )
    p.add_argument(
        "--host", default="127.0.0.1", help="bind address (default 127.0.0.1)"
    )
    p.add_argument(
        "--port", type=int, default=0, help="bind port (default 0 = ephemeral)"
    )
    p.add_argument(
        "--events-out",
        default=None,
        help="also write each connection event as one JSON line to FILE",
    )
    p.set_defaults(func=_cmd_proxy)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        # Operational error, never a security signal: must not collide with
        # exit 2 (rug-pull) or exit 1 (violation).
        _say(f"error: {exc}")
        return EXIT_BAD_INPUT
    except (ValueError, KeyError) as exc:
        # Corrupt/malformed manifest, policy, or events input
        # (json.JSONDecodeError is a ValueError). Fail closed with a
        # distinct code and a one-line verdict instead of a traceback.
        _say(f"error: invalid input: {exc}")
        return EXIT_BAD_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
