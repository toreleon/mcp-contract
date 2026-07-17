"""Tests for the SARIF + SIEM exporters (GO-FORWARD §5 A4/A5).

Reports are built inline from the frozen models (no dependency on other new
modules). The exfil scenario mirrors tests/fixtures/events/filesystem-exfil.jsonl:
an outside_contract net.connect to evil.example.com:443 during tool read_file.
"""
from __future__ import annotations

import json

import pytest

from mcp_contract import __version__
from mcp_contract.models import (
    BehaviorEvent,
    EventClass,
    EventKind,
    Mode,
    ViolationReport,
)
from mcp_contract.report import (
    event_target,
    to_sarif,
    to_sarif_json,
    to_siem_json,
    to_siem_ndjson,
    violation_identity,
)
from mcp_contract.report.export import SARIF_MAX_RESULTS, SARIF_SCHEMA_URI

SERVER = "filesystem"
MHASH = "sha256:deadbeef"


def _exfil_report() -> ViolationReport:
    """A report with within_policy, within_manifest, and outside_contract events."""
    events = [
        BehaviorEvent(
            ts=1760000000.0,
            kind=EventKind.MCP_CALL,
            detail={"tool": "read_file", "params": {"path": "/data/x"}},
            classification=EventClass.WITHIN_POLICY,
            backend="mock",
        ),
        BehaviorEvent(
            ts=1760000001.1,
            kind=EventKind.FS_OPEN,
            detail={"path": "/data/notes.txt", "mode": "r"},
            tool_ctx="read_file",
            classification=EventClass.WITHIN_POLICY,
            backend="mock",
        ),
        BehaviorEvent(
            ts=1760000002.3,
            kind=EventKind.FS_OPEN,
            detail={"path": "/data/summary.md", "mode": "w"},
            tool_ctx="write_file",
            classification=EventClass.WITHIN_MANIFEST,
            backend="mock",
        ),
        BehaviorEvent(
            ts=1760000003.4,
            kind=EventKind.NET_CONNECT,
            detail={"host": "evil.example.com", "port": 443},
            tool_ctx="read_file",
            classification=EventClass.OUTSIDE_CONTRACT,
            backend="mock",
        ),
    ]
    return ViolationReport(
        server_id=SERVER, manifest_hash=MHASH, mode=Mode.OBSERVE, events=events
    )


def _net_event() -> BehaviorEvent:
    return BehaviorEvent(
        ts=1760000003.4,
        kind=EventKind.NET_CONNECT,
        detail={"host": "evil.example.com", "port": 443},
        tool_ctx="read_file",
        classification=EventClass.OUTSIDE_CONTRACT,
    )


# --- event_target ----------------------------------------------------------


def test_event_target_net_host():
    assert event_target(_net_event()) == "evil.example.com"


def test_event_target_net_ip_fallback():
    e = BehaviorEvent(ts=1.0, kind=EventKind.NET_CONNECT, detail={"ip": "10.0.0.5"})
    assert event_target(e) == "10.0.0.5"


def test_event_target_fs_open_path_and_mode():
    e = BehaviorEvent(ts=1.0, kind=EventKind.FS_OPEN, detail={"path": "/data/x", "mode": "r"})
    assert event_target(e) == "/data/x:r"


def test_event_target_proc_spawn_basename_of_argv():
    e = BehaviorEvent(
        ts=1.0, kind=EventKind.PROC_SPAWN, detail={"argv": ["/usr/bin/curl", "-s"]}
    )
    assert event_target(e) == "curl"


def test_event_target_proc_spawn_cmd_first_token():
    e = BehaviorEvent(ts=1.0, kind=EventKind.PROC_SPAWN, detail={"cmd": "/bin/sh -c ls"})
    assert event_target(e) == "sh"


def test_event_target_env_read():
    e = BehaviorEvent(ts=1.0, kind=EventKind.ENV_READ, detail={"var": "GITHUB_TOKEN"})
    assert event_target(e) == "GITHUB_TOKEN"


def test_event_target_other_kind_empty():
    e = BehaviorEvent(ts=1.0, kind=EventKind.SYSCALL, detail={"group": "net"})
    assert event_target(e) == ""


# --- violation_identity ----------------------------------------------------


def test_violation_identity_is_sha256_hex():
    h = violation_identity("s", "outside_contract", "net.connect", "evil.example.com")
    assert isinstance(h, str)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_violation_identity_matches_manual_recipe():
    import hashlib

    identity = "\x00".join(["s", "outside_contract", "net.connect", "evil.example.com"])
    expected = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    assert (
        violation_identity("s", "outside_contract", "net.connect", "evil.example.com")
        == expected
    )


def test_violation_identity_excludes_ts():
    """Two events with different ts but identical scope share a fingerprint."""
    e1 = BehaviorEvent(
        ts=1.0, kind=EventKind.NET_CONNECT,
        detail={"host": "evil.example.com", "port": 443},
        classification=EventClass.OUTSIDE_CONTRACT,
    )
    e2 = BehaviorEvent(
        ts=999999.0, kind=EventKind.NET_CONNECT,
        detail={"host": "evil.example.com", "port": 8080},
        classification=EventClass.OUTSIDE_CONTRACT,
    )
    id1 = violation_identity(SERVER, "outside_contract", "net.connect", event_target(e1))
    id2 = violation_identity(SERVER, "outside_contract", "net.connect", event_target(e2))
    assert id1 == id2


# --- SARIF (A4) ------------------------------------------------------------


def test_sarif_top_level_shape():
    doc = to_sarif([_exfil_report()])
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == SARIF_SCHEMA_URI
    assert len(doc["runs"]) == 1


def test_sarif_driver_metadata():
    doc = to_sarif([_exfil_report()], tool_version="9.9.9")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mcp-contract"
    assert driver["version"] == "9.9.9"
    assert driver["semanticVersion"] == "9.9.9"
    assert driver["informationUri"].endswith("mcp-contract")


def test_sarif_default_tool_version_is_package_version():
    doc = to_sarif([_exfil_report()])
    assert doc["runs"][0]["tool"]["driver"]["version"] == __version__


def test_sarif_has_at_least_one_rule():
    doc = to_sarif([_exfil_report()])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 1


def test_sarif_level_mapping_error_and_note():
    doc = to_sarif([_exfil_report()])
    results = doc["runs"][0]["results"]
    by_kind = {r["properties"]["classification"]: r["level"] for r in results}
    assert by_kind["outside_contract"] == "error"
    assert by_kind["within_manifest_not_policy"] == "note"


def test_sarif_rule_level_and_severity():
    doc = to_sarif([_exfil_report()])
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    oc = rules["outside_contract/net.connect"]
    assert oc["defaultConfiguration"]["level"] == "error"
    assert oc["properties"]["security-severity"] == "9.0"
    assert "security" in oc["properties"]["tags"]
    assert "net.connect" in oc["properties"]["tags"]
    wm = rules["within_manifest_not_policy/fs.open"]
    assert wm["defaultConfiguration"]["level"] == "note"
    assert wm["properties"]["security-severity"] == "4.0"


def test_sarif_rule_name_is_pascalcase():
    doc = to_sarif([_exfil_report()])
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["outside_contract/net.connect"]["name"] == "OutsideContractNetConnect"


def test_sarif_fingerprint_equals_violation_identity():
    doc = to_sarif([_exfil_report()])
    net = [
        r for r in doc["runs"][0]["results"]
        if r["properties"]["kind"] == "net.connect"
    ][0]
    expected = violation_identity(
        SERVER, "outside_contract", "net.connect", "evil.example.com"
    )
    assert net["partialFingerprints"]["primaryLocationLineHash"] == expected


def test_sarif_result_ruleindex_points_at_its_rule():
    doc = to_sarif([_exfil_report()])
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_location_and_manifest_uri():
    doc = to_sarif([_exfil_report()], manifest_uri="servers/filesystem.json")
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "servers/filesystem.json"
    assert loc["region"]["startLine"] == 1


def test_sarif_location_uri_fallback():
    doc = to_sarif([_exfil_report()])
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "filesystem.manifest.json"


def test_sarif_within_policy_never_a_result():
    doc = to_sarif([_exfil_report()])
    for r in doc["runs"][0]["results"]:
        assert r["properties"]["classification"] != "within_policy"


def test_sarif_exclude_within_manifest():
    doc = to_sarif([_exfil_report()], include_within_manifest=False)
    classes = {r["properties"]["classification"] for r in doc["runs"][0]["results"]}
    assert classes == {"outside_contract"}


def test_sarif_empty_results_is_valid():
    clean = ViolationReport(
        server_id="clean", manifest_hash=MHASH, mode=Mode.OBSERVE,
        events=[
            BehaviorEvent(
                ts=1.0, kind=EventKind.FS_OPEN, detail={"path": "/data", "mode": "r"},
                classification=EventClass.WITHIN_POLICY,
            )
        ],
    )
    doc = to_sarif([clean])
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_message_names_server_target_and_tool():
    doc = to_sarif([_exfil_report()])
    net = [
        r for r in doc["runs"][0]["results"]
        if r["properties"]["kind"] == "net.connect"
    ][0]
    text = net["message"]["text"]
    assert "filesystem" in text
    assert "evil.example.com:443" in text
    assert "read_file" in text


def test_sarif_json_is_valid_and_newline_terminated():
    out = to_sarif_json([_exfil_report()])
    assert out.endswith("\n")
    parsed = json.loads(out)
    assert parsed["version"] == "2.1.0"


def test_sarif_json_passes_kwargs_through():
    out = to_sarif_json([_exfil_report()], include_within_manifest=False, indent=None)
    parsed = json.loads(out)
    classes = {r["properties"]["classification"] for r in parsed["runs"][0]["results"]}
    assert classes == {"outside_contract"}


# --- SARIF result cap (finding 8) ------------------------------------------


def _many_outside_contract(n: int) -> ViolationReport:
    events = [
        BehaviorEvent(
            ts=float(i), kind=EventKind.NET_CONNECT,
            detail={"host": f"h{i}.example.com", "port": 443},
            classification=EventClass.OUTSIDE_CONTRACT,
        )
        for i in range(n)
    ]
    return ViolationReport(
        server_id=SERVER, manifest_hash=MHASH, mode=Mode.OBSERVE, events=events
    )


def test_sarif_caps_results_and_surfaces_truncation():
    doc = to_sarif([_many_outside_contract(5)], max_results=2)
    run = doc["runs"][0]
    assert len(run["results"]) == 2  # only the first max_results kept
    assert run["properties"]["mcp_contract.truncated_results"] == 3
    notif = run["invocations"][0]["toolExecutionNotifications"][0]
    assert notif["level"] == "warning"
    assert "2-result" in notif["message"]["text"]  # uses the passed limit
    # deterministic: the kept results are the first two (report/event order).
    hosts = [r["properties"]["detail"]["host"] for r in run["results"]]
    assert hosts == ["h0.example.com", "h1.example.com"]


def test_sarif_no_truncation_adds_no_properties_or_invocations():
    run = to_sarif([_exfil_report()])["runs"][0]
    assert "properties" not in run
    assert "invocations" not in run


def test_sarif_default_max_results_is_github_limit():
    assert SARIF_MAX_RESULTS == 25000


# --- SIEM (A4) -------------------------------------------------------------


def test_siem_alert_kind_for_outside_contract():
    rows = to_siem_json([_exfil_report()])
    net = [r for r in rows if r["event.action"] == "net.connect"][0]
    assert net["event.kind"] == "alert"


def test_siem_event_kind_event_for_within_manifest():
    rows = to_siem_json([_exfil_report()])
    fs_w = [r for r in rows if r["event.action"] == "fs.open"][0]
    assert fs_w["event.kind"] == "event"


def test_siem_net_category_and_type():
    rows = to_siem_json([_exfil_report()])
    net = [r for r in rows if r["event.action"] == "net.connect"][0]
    assert net["event.category"] == ["network"]
    assert net["event.type"] == ["connection", "allowed"]


def test_siem_fs_write_type_is_change():
    rows = to_siem_json([_exfil_report()])
    fs_w = [r for r in rows if r["event.action"] == "fs.open"][0]
    assert fs_w["event.category"] == ["file"]
    assert fs_w["event.type"] == ["change"]


def test_siem_fs_read_type_is_access():
    rows = to_siem_json([_exfil_report()], include_within_policy=True)
    fs_r = [
        r for r in rows
        if r["event.action"] == "fs.open" and r["file.path"] == "/data/notes.txt"
    ][0]
    assert fs_r["event.type"] == ["access"]


def _fs_open_row(mode: str) -> dict:
    report = ViolationReport(
        server_id=SERVER, manifest_hash=MHASH, mode=Mode.OBSERVE,
        events=[
            BehaviorEvent(
                ts=1.0, kind=EventKind.FS_OPEN,
                detail={"path": "/data/x", "mode": mode},
                classification=EventClass.WITHIN_MANIFEST,
            )
        ],
    )
    return to_siem_json([report])[0]


@pytest.mark.parametrize("mode", ["r", "rb", "rt", "R", "RB", "tr"])
def test_siem_fs_read_modes_map_to_access(mode):
    # Mirror bcm.diff.event_capability: 'r' plus optional 'b'/'t', case-folded,
    # is a read -> event.type ['access']. 'rb'/'rt'/'R' must NOT read as 'change'.
    row = _fs_open_row(mode)
    assert row["event.category"] == ["file"]
    assert row["event.type"] == ["access"]


@pytest.mark.parametrize("mode", ["w", "a", "rw", "w+", "x", "r+", "wb", "unknown"])
def test_siem_fs_write_modes_map_to_change(mode):
    # Any write-capable or unrecognized mode fails closed to ['change'].
    row = _fs_open_row(mode)
    assert row["event.category"] == ["file"]
    assert row["event.type"] == ["change"]


def test_siem_destination_address_for_exfil():
    rows = to_siem_json([_exfil_report()])
    net = [r for r in rows if r["event.action"] == "net.connect"][0]
    assert net["destination.address"] == "evil.example.com"
    assert net["destination.port"] == 443


def test_siem_flat_keys_only():
    rows = to_siem_json([_exfil_report()], include_within_policy=True)
    assert rows
    for row in rows:
        for value in row.values():
            assert not isinstance(value, dict)


def test_siem_mcp_call_skipped():
    rows = to_siem_json([_exfil_report()], include_within_policy=True)
    assert all(r["event.action"] != "mcp.call" for r in rows)
    assert all(r["mcp_contract.event_kind"] != "mcp.call" for r in rows)


def test_siem_within_policy_excluded_by_default():
    rows = to_siem_json([_exfil_report()])
    classes = {r["mcp_contract.classification"] for r in rows}
    assert "within_policy" not in classes
    assert classes == {"outside_contract", "within_manifest_not_policy"}


def test_siem_within_policy_included_when_flagged():
    rows = to_siem_json([_exfil_report()], include_within_policy=True)
    classes = {r["mcp_contract.classification"] for r in rows}
    assert "within_policy" in classes


def test_siem_severity_mapping():
    rows = to_siem_json([_exfil_report()], include_within_policy=True)
    sev = {r["mcp_contract.classification"]: r["event.severity"] for r in rows}
    assert sev["outside_contract"] == 9
    assert sev["within_manifest_not_policy"] == 4
    assert sev["within_policy"] == 1


def test_siem_rule_vocabulary_matches_sarif():
    rows = to_siem_json([_exfil_report()])
    net = [r for r in rows if r["event.action"] == "net.connect"][0]
    assert net["rule.id"] == "outside_contract/net.connect"


def test_siem_timestamp_is_iso_utc():
    rows = to_siem_json([_exfil_report()])
    net = [r for r in rows if r["event.action"] == "net.connect"][0]
    assert net["@timestamp"].endswith("+00:00")


def test_siem_reason_has_no_server_prefix():
    rows = to_siem_json([_exfil_report()])
    net = [r for r in rows if r["event.action"] == "net.connect"][0]
    assert not net["event.reason"].startswith("MCP server")
    assert "evil.example.com:443" in net["event.reason"]


def test_siem_denied_outcome_when_blocked():
    report = ViolationReport(
        server_id=SERVER, manifest_hash=MHASH, mode=Mode.ENFORCE,
        events=[
            BehaviorEvent(
                ts=1.0, kind=EventKind.NET_CONNECT,
                detail={"host": "evil.example.com", "port": 443, "allowed": False},
                classification=EventClass.OUTSIDE_CONTRACT,
            )
        ],
    )
    rows = to_siem_json([report])
    assert rows[0]["event.outcome"] == "failure"
    assert rows[0]["event.type"] == ["connection", "denied"]


def test_siem_ndjson_line_count_and_valid_json():
    out = to_siem_ndjson([_exfil_report()])
    assert out.endswith("\n")
    lines = out.strip().split("\n")
    assert len(lines) == 2  # outside_contract + within_manifest
    for line in lines:
        assert json.loads(line)  # sorted-key JSON per line


def test_siem_ndjson_sorted_keys():
    out = to_siem_ndjson([_exfil_report()])
    first = out.strip().split("\n")[0]
    reserialized = json.dumps(json.loads(first), sort_keys=True)
    assert first == reserialized


def test_siem_ndjson_empty_document_for_zero_notable_events():
    # The all-clean case (the common passing-gate case) yields a 0-byte NDJSON,
    # NOT a lone '\n' that would choke a strict JSON-lines forwarder (finding 7).
    clean = ViolationReport(
        server_id="clean", manifest_hash=MHASH, mode=Mode.OBSERVE,
        events=[
            BehaviorEvent(
                ts=1.0, kind=EventKind.FS_OPEN,
                detail={"path": "/data", "mode": "r"},
                classification=EventClass.WITHIN_POLICY,
            )
        ],
    )
    assert to_siem_ndjson([clean]) == ""
    assert to_siem_ndjson([]) == ""
    # every emitted line is still newline-terminated in the non-empty case.
    out = to_siem_ndjson([_exfil_report()])
    assert out.endswith("\n")
    assert all(json.loads(line) for line in out.splitlines())


# --- determinism (A5) ------------------------------------------------------


def test_sarif_json_byte_stable_across_runs():
    r = _exfil_report()
    assert to_sarif_json([r]) == to_sarif_json([_exfil_report()])


def test_siem_ndjson_byte_stable_across_runs():
    r = _exfil_report()
    assert to_siem_ndjson([r]) == to_siem_ndjson([_exfil_report()])


def test_exports_stable_regardless_of_ts_within_identity():
    """Same scope, different ts -> identical SARIF fingerprint (no churn)."""
    def report(ts: float) -> ViolationReport:
        return ViolationReport(
            server_id=SERVER, manifest_hash=MHASH, mode=Mode.OBSERVE,
            events=[
                BehaviorEvent(
                    ts=ts, kind=EventKind.NET_CONNECT,
                    detail={"host": "evil.example.com", "port": 443},
                    classification=EventClass.OUTSIDE_CONTRACT,
                )
            ],
        )

    fp1 = to_sarif([report(1.0)])["runs"][0]["results"][0][
        "partialFingerprints"
    ]["primaryLocationLineHash"]
    fp2 = to_sarif([report(9999.0)])["runs"][0]["results"][0][
        "partialFingerprints"
    ]["primaryLocationLineHash"]
    assert fp1 == fp2


# --- ordering / multi-report -----------------------------------------------


def test_sarif_rules_in_first_seen_order():
    doc = to_sarif([_exfil_report()])
    ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    # within_manifest fs.open event precedes the outside_contract net.connect
    assert ids == ["within_manifest_not_policy/fs.open", "outside_contract/net.connect"]


def test_multi_report_results_in_report_then_event_order():
    r1 = ViolationReport(
        server_id="a", manifest_hash=MHASH, mode=Mode.OBSERVE,
        events=[_net_event()],
    )
    r2 = ViolationReport(
        server_id="b", manifest_hash=MHASH, mode=Mode.OBSERVE,
        events=[_net_event()],
    )
    doc = to_sarif([r1, r2])
    servers = [res["properties"]["server_id"] for res in doc["runs"][0]["results"]]
    assert servers == ["a", "b"]


def test_shared_rule_across_reports_deduped():
    r1 = ViolationReport(
        server_id="a", manifest_hash=MHASH, mode=Mode.OBSERVE, events=[_net_event()]
    )
    r2 = ViolationReport(
        server_id="b", manifest_hash=MHASH, mode=Mode.OBSERVE, events=[_net_event()]
    )
    doc = to_sarif([r1, r2])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert all(res["ruleIndex"] == 0 for res in doc["runs"][0]["results"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
