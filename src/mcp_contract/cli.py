"""mcp-contract command-line interface (spec §8.1, GO-FORWARD §2.6).

Subcommands:
  infer   manifest -> least-privilege policy YAML (needs_review summary on stderr);
          --emit base writes the strict policy-mcp/v1 projection
  run     start (or replay) a server on a sandbox backend and monitor it;
          --sarif/--siem write standardized reports as additional artifacts
  audit   offline classification of a recorded event stream (always exit 0);
          --sarif/--siem additional artifacts
  verify  CI gate: exit 2 on manifest-hash mismatch (rug-pull), 1 on any
          outside_contract event, 4 when the input is missing/corrupt or
          zero events were observed (inconclusive, never a security
          signal; --allow-empty accepts an empty stream), 0 clean;
          --sarif/--siem additional artifacts
  proxy   run the enforcing egress proxy standalone (deny-by-default,
          hostname-level net.http enforcement; every attempt logged)
  fleet   batch inference/verification across a fleet of MCP servers
          (fleet infer|audit|verify|run); one aggregate FleetReport,
          --format json|ndjson|sarif, --sarif/--siem exports. `fleet verify`
          returns the aggregate exit code (precedence 2 > 1 > 4 > 0).

Conventions: human-facing chatter goes to stderr; machine output (YAML/JSON)
goes to stdout. PIE/BCM/policy/fleet/report modules are imported inside the
subcommand handlers so `--help` stays fast and backends stay optional.
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


def _write_text_artifact(path: str, text: str) -> None:
    """Write a machine artifact to ``path``, guaranteeing a trailing newline.

    An empty document stays empty (0-byte file): a SIEM feed for an all-clean
    fleet has zero notable events, and appending a lone ``"\\n"`` would make a
    strict JSON-lines forwarder choke on the blank line.
    """
    if text and not text.endswith("\n"):
        text += "\n"
    Path(path).write_text(text, encoding="utf-8")


def _write_single_exports(
    report: ViolationReport, args: argparse.Namespace, manifest_uri: str | None = None
) -> None:
    """Write standardized SARIF/SIEM artifacts for one report (additive).

    Exit codes are unaffected — these are extra machine outputs written to the
    paths given by ``--sarif``/``--siem`` on the single-server subcommands.
    """
    sarif_path = getattr(args, "sarif", None)
    if sarif_path:
        from mcp_contract.report import to_sarif_json

        _write_text_artifact(sarif_path, to_sarif_json([report], manifest_uri=manifest_uri))
        _say(f"wrote SARIF to {sarif_path}")
    siem_path = getattr(args, "siem", None)
    if siem_path:
        from mcp_contract.report import to_siem_ndjson

        _write_text_artifact(siem_path, to_siem_ndjson([report]))
        _say(f"wrote SIEM NDJSON to {siem_path}")


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

    if getattr(args, "emit", "full") == "base":
        # Strict policy-mcp/v1 projection: only {version, description,
        # permissions}, no x-mcp-contract block (schema/v1.json-valid form).
        from mcp_contract.policy import policy_to_policy_mcp_base

        doc = policy_to_policy_mcp_base(policy)
        if args.json:
            text = json.dumps(doc, indent=2) + "\n"
        else:
            import yaml

            text = yaml.safe_dump(doc, sort_keys=False)
        text = text if text.endswith("\n") else text + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    elif args.json:
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
    _write_single_exports(report, args, args.manifest)

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
    _write_single_exports(report, args, args.manifest)

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
    _write_single_exports(report, args, args.manifest)

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


# ------------------------------------------------------------------ fleet
#
# The `fleet` group runs the single-server verbs in batch across a fleet of
# MCP servers (GO-FORWARD §2.6). Every verb produces one aggregate
# FleetReport; `fleet verify` returns its aggregate exit code (precedence
# 2 > 1 > 4 > 0). Fleet/report modules are imported lazily so `--help` and the
# single-server path never pay for them.


def _parse_selectors(select_args: list[str] | None) -> dict[str, str]:
    """Parse repeated ``--select K=V`` into a label filter dict."""
    out: dict[str, str] = {}
    for item in select_args or []:
        if "=" not in item:
            raise ValueError(f"--select expects K=V, got {item!r}")
        key, _, value = item.partition("=")
        out[key.strip()] = value.strip()
    return out


def _apply_select(fleet: object, args: argparse.Namespace) -> object:
    """Slice the fleet by ``--select`` labels when any were given."""
    selectors = _parse_selectors(getattr(args, "select", None))
    if selectors:
        return fleet.select(**selectors)  # type: ignore[attr-defined]
    return fleet


def _resolve_manifest_paths(source: str) -> list[str]:
    """Expand a DIR, GLOB, or single-file source to a sorted manifest list."""
    import glob as _glob

    path = Path(source)
    if path.is_dir():
        return sorted(str(p) for p in path.glob("*.json"))
    matches = sorted(_glob.glob(source))
    if matches:
        return matches
    if path.is_file():
        return [str(path)]
    return []


def _fleet_from_infer_source(args: argparse.Namespace):
    """Build a Fleet for `fleet infer` from exactly one of DIR|GLOB/--config/--from-mcp."""
    from mcp_contract.fleet import Fleet

    chosen = [bool(args.source), bool(args.config), bool(args.from_mcp)]
    if sum(chosen) != 1:
        raise ValueError(
            "fleet infer: give exactly one of DIR|GLOB, --config FILE, or "
            "--from-mcp FILE"
        )
    if args.config:
        return Fleet.from_config(args.config)
    if args.from_mcp:
        return Fleet.from_mcp_servers(args.from_mcp)
    paths = _resolve_manifest_paths(args.source)
    if not paths:
        raise FileNotFoundError(f"no manifest files matched {args.source!r}")
    return Fleet.from_manifests(paths)


def _fleet_violation_reports(report: object) -> list[ViolationReport]:
    """The non-None per-server ViolationReports, in fleet order (for exports)."""
    return [run.report for run in report.runs if run.report is not None]  # type: ignore[attr-defined]


def _emit_fleet_report(report: object, out_path: str | None, fmt: str) -> None:
    """Write the aggregate FleetReport to ``out_path`` (or stdout) in ``fmt``."""
    if fmt == "ndjson":
        text = report.to_ndjson()  # type: ignore[attr-defined]
    elif fmt == "sarif":
        from mcp_contract.report import to_sarif_json

        text = to_sarif_json(_fleet_violation_reports(report))
    else:  # json
        text = report.to_json()  # type: ignore[attr-defined]
    if not text.endswith("\n"):
        text += "\n"
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
        _say(f"wrote fleet report to {out_path}")
    else:
        sys.stdout.write(text)


def _write_fleet_side_exports(report: object, args: argparse.Namespace) -> None:
    """Write `--sarif`/`--siem` fleet artifacts (additive; exit code untouched)."""
    reports = _fleet_violation_reports(report)
    sarif_path = getattr(args, "sarif", None)
    if sarif_path:
        from mcp_contract.report import to_sarif_json

        _write_text_artifact(sarif_path, to_sarif_json(reports))
        _say(f"wrote SARIF to {sarif_path}")
    siem_path = getattr(args, "siem", None)
    if siem_path:
        from mcp_contract.report import to_siem_ndjson

        _write_text_artifact(siem_path, to_siem_ndjson(reports))
        _say(f"wrote SIEM NDJSON to {siem_path}")


def _reproject_written_base(fleet: object) -> None:
    """Rewrite each server's just-written policy as the strict policy-mcp base.

    Used by `fleet infer --emit base`: infer_all wrote the full x-mcp-contract
    document; re-read it and overwrite with the schema/v1.json-valid projection.
    """
    import yaml

    from mcp_contract.policy import load_policy, policy_to_policy_mcp_base

    for server in fleet.servers:  # type: ignore[attr-defined]
        policy_path = getattr(server, "policy_path", None)
        if not policy_path or not Path(policy_path).is_file():
            continue
        doc = policy_to_policy_mcp_base(load_policy(Path(policy_path)))
        Path(policy_path).write_text(
            yaml.safe_dump(doc, sort_keys=False), encoding="utf-8"
        )


def _cmd_fleet_infer(args: argparse.Namespace) -> int:
    """Infer per-server policies across a fleet; one aggregate FleetReport.

    Never gates: returns 0 unless a bad/unresolved input made a server skip (4).
    """
    try:
        fleet = _fleet_from_infer_source(args)
    except (ValueError, FileNotFoundError) as exc:
        _say(f"error: {exc}")
        return EXIT_BAD_INPUT

    fleet = _apply_select(fleet, args)

    outdir = args.output
    if outdir:
        Path(outdir).mkdir(parents=True, exist_ok=True)
        for server in fleet.servers:  # type: ignore[attr-defined]
            if not getattr(server, "policy_path", None):
                server.policy_path = str(Path(outdir) / f"{server.id}.policy.yaml")

    report = fleet.infer_all(write=bool(outdir))  # type: ignore[attr-defined]
    if outdir and args.emit == "base":
        _reproject_written_base(fleet)
        _say("emitted strict policy-mcp/v1 base projections (--emit base)")
    _emit_fleet_report(report, args.report, args.format)
    return report.exit_code()  # type: ignore[attr-defined]


def _cmd_fleet_audit(args: argparse.Namespace) -> int:
    """Offline classification across a fleet; reports only (0, or 4 on bad input)."""
    from mcp_contract.fleet import Fleet

    fleet = _apply_select(Fleet.from_config(args.config), args)
    report = fleet.audit_all()  # type: ignore[attr-defined]
    _emit_fleet_report(report, args.report, args.format)
    return report.exit_code()  # type: ignore[attr-defined]


def _cmd_fleet_verify(args: argparse.Namespace) -> int:
    """The fleet CI gate: aggregate exit code (precedence 2 > 1 > 4 > 0)."""
    from mcp_contract.fleet import Fleet

    fleet = _apply_select(Fleet.from_config(args.config), args)
    report = fleet.verify_all(allow_empty=args.allow_empty)  # type: ignore[attr-defined]
    _emit_fleet_report(report, args.report, args.format)
    _write_fleet_side_exports(report, args)
    if not report.runs:  # type: ignore[attr-defined]
        # A gate that examined zero servers must not read as clean. This is
        # distinct from --allow-empty (an empty *event stream* per server): an
        # empty *fleet* (a --select that matched nothing, or an emptied
        # `servers:` block) is always inconclusive (exit 4), never a clean
        # signal.
        _say(
            "fleet verify: 0 server(s) selected — nothing was verified "
            "(check --select labels and the config's 'servers' block); exit 4"
        )
        return EXIT_BAD_INPUT
    rc = report.exit_code()  # type: ignore[attr-defined]
    _say(f"fleet verify: {len(report.runs)} server(s), aggregate exit {rc}")  # type: ignore[attr-defined]
    return rc


def _cmd_fleet_run(args: argparse.Namespace) -> int:
    """Start/monitor a fleet (sequential in v0); aggregate exit code."""
    from mcp_contract.fleet import Fleet

    fleet = _apply_select(Fleet.from_config(args.config), args)
    report = fleet.run_all(  # type: ignore[attr-defined]
        max_events=args.max_events, duration=args.duration
    )
    if args.report_out:
        _write_text_artifact(args.report_out, report.to_json())  # type: ignore[attr-defined]
        _say(f"wrote fleet report to {args.report_out}")
    _write_fleet_side_exports(report, args)
    if not report.runs:  # type: ignore[attr-defined]
        # A gating verb that examined zero servers must not read as clean
        # (mirrors fleet verify): an empty fleet is inconclusive (exit 4).
        _say(
            "fleet run: 0 server(s) selected — nothing was run "
            "(check --select labels and the config's 'servers' block); exit 4"
        )
        return EXIT_BAD_INPUT
    return report.exit_code()  # type: ignore[attr-defined]


def _build_parser() -> argparse.ArgumentParser:
    """Assemble the argparse tree for all subcommands."""
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
    p.add_argument(
        "--emit",
        choices=["full", "base"],
        default="full",
        help="'full' (default) = our policy-mcp doc + x-mcp-contract block; "
        "'base' = strict policy-mcp/v1 projection (schema-valid, no extension)",
    )
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
    p.add_argument(
        "--sarif", default=None, metavar="PATH",
        help="also write a SARIF 2.1.0 report to PATH (CI code-scanning)",
    )
    p.add_argument(
        "--siem", default=None, metavar="PATH",
        help="also write ECS-aligned NDJSON to PATH (SIEM ingestion)",
    )
    p.set_defaults(func=_cmd_run)

    p = sub.add_parser("audit", help="classify a recorded event stream offline")
    p.add_argument("--events", required=True, help="events JSONL file")
    p.add_argument("--policy", required=True, help="policy YAML file")
    p.add_argument("--manifest", required=True, help="manifest file")
    p.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    p.add_argument(
        "--sarif", default=None, metavar="PATH",
        help="also write a SARIF 2.1.0 report to PATH (CI code-scanning)",
    )
    p.add_argument(
        "--siem", default=None, metavar="PATH",
        help="also write ECS-aligned NDJSON to PATH (SIEM ingestion)",
    )
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
    p.add_argument(
        "--sarif", default=None, metavar="PATH",
        help="also write a SARIF 2.1.0 report to PATH (CI code-scanning)",
    )
    p.add_argument(
        "--siem", default=None, metavar="PATH",
        help="also write ECS-aligned NDJSON to PATH (SIEM ingestion)",
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

    _add_fleet_parsers(sub)

    return parser


def _add_fleet_parsers(sub: argparse._SubParsersAction) -> None:
    """Attach the `fleet infer|audit|verify|run` group (GO-FORWARD §2.6)."""
    fleet = sub.add_parser(
        "fleet",
        help="batch inference/verification across a fleet of MCP servers",
        description=(
            "Run the single-server verbs in batch across a fleet. Every verb "
            "produces one aggregate FleetReport; `fleet verify` returns the "
            "aggregate exit code (precedence 2 > 1 > 4 > 0)."
        ),
    )
    fsub = fleet.add_subparsers(dest="fleet_command", required=True)

    def _add_format(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--report", default=None, metavar="FILE",
            help="write the aggregate FleetReport to FILE (default: stdout)",
        )
        parser.add_argument(
            "--format", choices=["json", "ndjson", "sarif"], default="json",
            help="report format written to --report/stdout (default: json)",
        )

    def _add_select(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--select", action="append", default=None, metavar="K=V",
            help="filter servers by label (repeatable), e.g. --select env=prod",
        )

    # fleet infer -------------------------------------------------------
    fi = fsub.add_parser(
        "infer",
        help="infer per-server policies over a manifest dir/glob, fleet config, "
        "or an mcpServers file",
    )
    fi.add_argument(
        "source", nargs="?", default=None,
        help="manifest DIR, GLOB, or single file (zero-config onboarding)",
    )
    fi.add_argument("--config", default=None, help="native fleet.yaml config")
    fi.add_argument(
        "--from-mcp", dest="from_mcp", default=None,
        help="ingest an mcpServers / VS Code servers file",
    )
    fi.add_argument(
        "-o", "--output", default=None, metavar="OUTDIR",
        help="write per-server policies into OUTDIR (default: report only)",
    )
    fi.add_argument(
        "--emit", choices=["full", "base"], default="full",
        help="written policy form: 'full' (default) or strict policy-mcp/v1 'base'",
    )
    _add_select(fi)
    _add_format(fi)
    fi.set_defaults(func=_cmd_fleet_infer)

    # fleet audit -------------------------------------------------------
    fa = fsub.add_parser(
        "audit", help="offline classification across a fleet (reports only)"
    )
    fa.add_argument("--config", required=True, help="native fleet.yaml config")
    _add_select(fa)
    _add_format(fa)
    fa.set_defaults(func=_cmd_fleet_audit)

    # fleet verify ------------------------------------------------------
    fv = fsub.add_parser(
        "verify",
        help="the fleet CI gate: aggregate exit code (2 > 1 > 4 > 0)",
    )
    fv.add_argument("--config", required=True, help="native fleet.yaml config")
    fv.add_argument(
        "--allow-empty", action="store_true",
        help="treat a server's zero-event stream as clean, not inconclusive",
    )
    fv.add_argument(
        "--sarif", default=None, metavar="PATH",
        help="also write an aggregate SARIF 2.1.0 report to PATH",
    )
    fv.add_argument(
        "--siem", default=None, metavar="PATH",
        help="also write aggregate ECS-aligned NDJSON to PATH",
    )
    _add_select(fv)
    _add_format(fv)
    fv.set_defaults(func=_cmd_fleet_verify)

    # fleet run ---------------------------------------------------------
    fr = fsub.add_parser(
        "run",
        help="start/monitor a fleet (sequential in v0); aggregate exit code",
    )
    fr.add_argument("--config", required=True, help="native fleet.yaml config")
    fr.add_argument(
        "--report-out", default=None, metavar="FILE",
        help="write the aggregate FleetReport JSON to FILE",
    )
    fr.add_argument("--max-events", type=int, default=None, help="stop each server after N events")
    fr.add_argument("--duration", type=float, default=None, help="stop each server after S seconds")
    fr.add_argument(
        "--siem", default=None, metavar="PATH",
        help="also write aggregate ECS-aligned NDJSON to PATH",
    )
    _add_select(fr)
    fr.set_defaults(func=_cmd_fleet_run)


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
