"""Fleet API tests (GO-FORWARD-0.1.0 §5 A1/A2/A3 + §4/§6 rules).

Everything runs against the bundled fixtures and the mock backend — no
docker, no gVisor, no network. Determinism is asserted with a fixed
``started_at`` so serialized reports are byte-stable.
"""
from __future__ import annotations

import glob
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from mcp_contract.fleet import (
    Fleet,
    FleetReport,
    FleetServer,
    FleetServerReport,
)
from mcp_contract.models import (
    Capability,
    CapabilityId,
    CapabilityStatus,
    Mode,
    Policy,
)
from mcp_contract.policy.io import load_policy

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MANIFESTS = FIXTURES / "manifests"
FLEET_CONFIG = FIXTURES / "fleet" / "fleet.yaml"

FIXED_START = 1_700_000_000.0  # any constant -> byte-stable serialization

# The least-privilege needs_review surface each fixture manifest infers to.
EXPECTED_NEEDS_REVIEW = {
    "fetch": {"net.http"},
    "filesystem": {"fs.read", "fs.write"},
    "github": {"env"},
    "shell": {"proc.exec"},
    "slack": {"env"},
    "sqlite": {"fs.read"},
}


def _report_available() -> bool:
    return importlib.util.find_spec("mcp_contract.report.export") is not None


# ---------------------------------------------------------------- A1: infer


def test_from_manifests_builds_one_server_per_file():
    fleet = Fleet.from_manifests(sorted(MANIFESTS.glob("*.json")))
    assert {s.id for s in fleet.servers} == set(EXPECTED_NEEDS_REVIEW)
    assert all(s.manifest_path for s in fleet.servers)
    assert all(s.policy_path is None for s in fleet.servers)


def test_infer_all_writes_six_policies_exit_zero(tmp_path):
    fleet = Fleet.from_manifests(sorted(MANIFESTS.glob("*.json")))
    report = fleet.infer_all(started_at=FIXED_START, out_dir=tmp_path)

    assert report.exit_code() == 0
    assert {r.status for r in report.runs} == {"ok"}
    assert report.totals()["servers"] == 6

    written = {p.stem.replace(".policy", ""): p for p in tmp_path.glob("*.policy.yaml")}
    assert set(written) == set(EXPECTED_NEEDS_REVIEW)

    # Each row carries provenance; the written policy matches the known
    # least-privilege needs_review surface for that fixture.
    for run in report.runs:
        assert run.manifest_hash.startswith("sha256:")
        policy = load_policy(written[run.server_id])
        needs_review = {
            c.id.value for c in policy.caps
            if c.status is CapabilityStatus.NEEDS_REVIEW
        }
        assert needs_review == EXPECTED_NEEDS_REVIEW[run.server_id]


def test_infer_all_writes_to_server_policy_path_when_no_outdir(tmp_path):
    fleet = Fleet.from_manifests([MANIFESTS / "fetch.json"])
    fleet.servers[0].policy_path = str(tmp_path / "fetch.custom.yaml")
    report = fleet.infer_all(started_at=FIXED_START)
    assert report.exit_code() == 0
    assert (tmp_path / "fetch.custom.yaml").exists()


def test_infer_all_bad_manifest_marks_server_skipped(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    fleet = Fleet.from_manifests([bad])
    report = fleet.infer_all(started_at=FIXED_START, write=False)
    assert report.runs[0].status == "skipped"
    assert report.exit_code() == 4


# --------------------------------------------------- A2: verify aggregation


def _verify_suite() -> Fleet:
    return Fleet.from_config(FLEET_CONFIG).select(suite="verify")


def test_fleet_config_loads_all_servers_and_labels():
    fleet = Fleet.from_config(FLEET_CONFIG)
    assert len(fleet.servers) == 10
    verify = fleet.select(suite="verify")
    assert {s.id for s in verify.servers} == {
        "fs-clean", "fs-exfil", "fs-tampered", "fs-corrupt"
    }
    # defaults merged: backend/mode come from the config's `defaults` block.
    assert all(s.backend == "mock" for s in verify.servers)
    assert all(s.mode is Mode.OBSERVE for s in verify.servers)
    # manifest/policy/events resolved to real files under the fixture tree.
    clean = next(s for s in verify.servers if s.id == "fs-clean")
    assert Path(clean.manifest_path).is_file()
    assert Path(clean.policy_path).is_file()
    assert Path(clean.events_path).is_file()


def test_verify_full_suite_rug_pull_outranks_all_exit_two():
    report = _verify_suite().verify_all(started_at=FIXED_START)
    by_id = {r.server_id: r.status for r in report.runs}
    assert by_id == {
        "fs-clean": "ok",
        "fs-exfil": "violation",
        "fs-tampered": "rug_pull",
        "fs-corrupt": "error",
    }
    # rug_pull(2) + violation(1) + error(4) together -> 2 (precedence, not max).
    assert report.exit_code() == 2
    assert report.severity().value == "critical"


def test_verify_without_tampered_violation_outranks_corrupt_exit_one():
    fleet = Fleet.from_config(FLEET_CONFIG)
    report = fleet.select(suite="verify", nodrift="yes").verify_all(
        started_at=FIXED_START
    )
    statuses = {r.status for r in report.runs}
    assert "rug_pull" not in statuses
    assert statuses == {"ok", "violation", "error"}
    # violation(1) + corrupt error(4) -> 1.
    assert report.exit_code() == 1


def test_verify_clean_and_corrupt_only_is_inconclusive_exit_four():
    fleet = Fleet.from_config(FLEET_CONFIG)
    report = fleet.select(suite="verify", novio="yes", nodrift="yes").verify_all(
        started_at=FIXED_START
    )
    assert {r.status for r in report.runs} == {"ok", "error"}
    # no violation, no rug_pull -> the broken pipeline (4) surfaces.
    assert report.exit_code() == 4


def test_verify_empty_events_inconclusive_unless_allowed(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    server = next(
        s for s in _verify_suite().servers if s.id == "fs-clean"
    )
    server.events_path = str(empty)
    fleet = Fleet([server])
    assert fleet.verify_all(started_at=FIXED_START).runs[0].status == "skipped"
    assert fleet.verify_all(started_at=FIXED_START).exit_code() == 4
    allowed = fleet.verify_all(started_at=FIXED_START, allow_empty=True)
    assert allowed.runs[0].status == "ok"
    assert allowed.exit_code() == 0


def test_verify_missing_policy_errors_never_gates_without_contract():
    server = FleetServer(
        id="no-policy",
        backend="mock",
        manifest_path=str(MANIFESTS / "filesystem.json"),
        events_path=str(FIXTURES / "events" / "filesystem-clean.jsonl"),
    )
    report = Fleet([server]).verify_all(started_at=FIXED_START)
    assert report.runs[0].status == "error"
    assert report.exit_code() == 4


def test_malformed_launch_env_isolated_not_batch_abort():
    """A non-mapping launch.env (a common YAML typo — env written as a scalar)
    must skip THAT server (exit 4), never abort the whole batch and mask a
    rug_pull/violation on the siblings (findings 2/5)."""
    good = next(s for s in _verify_suite().servers if s.id == "fs-exfil")
    bad = FleetServer(
        id="bad-env",
        backend="mock",
        launch={"command": "mock", "env": "GITHUB_TOKEN"},  # scalar, not a map
    )
    # Before the fix this raised ValueError out of the verify_all comprehension.
    report = Fleet([bad, good]).verify_all(started_at=FIXED_START)
    by_id = {r.server_id: r.status for r in report.runs}
    assert by_id["bad-env"] == "skipped"          # isolated to that server
    assert by_id["fs-exfil"] == "violation"       # sibling still evaluated
    assert report.exit_code() == 1                # violation surfaces, not masked to 4


def test_verify_classification_failure_contained_not_batch_abort(monkeypatch):
    """classify_events is guarded in _verify_one just like _audit_one, so a
    classifier failure resolves to that server's status='error' (exit 4)
    instead of escaping verify_all and aborting the whole batch (finding 6)."""
    import mcp_contract.fleet as fleet_mod

    def boom(events, policy, manifest):
        raise RuntimeError("classifier blew up")

    monkeypatch.setattr(fleet_mod, "classify_events", boom)
    # Before the fix, the first server to reach classify raised and the whole
    # verify_all() call blew up; now it returns a FleetReport.
    report = _verify_suite().verify_all(started_at=FIXED_START)
    by_id = {r.server_id: r.status for r in report.runs}
    assert by_id["fs-clean"] == "error"           # classify failure contained
    assert by_id["fs-exfil"] == "error"
    assert by_id["fs-tampered"] == "rug_pull"     # rug-pull gate precedes classify
    assert by_id["fs-corrupt"] == "error"         # load failure (already contained)


def test_exit_code_precedence_is_security_first_not_numeric_max():
    def row(status: str) -> FleetServerReport:
        return FleetServerReport(server_id=f"s-{status}", status=status, exit_code=0)

    assert FleetReport([row("rug_pull"), row("violation"),
                        row("error")], 0.0).exit_code() == 2
    assert FleetReport([row("violation"), row("error"),
                        row("ok")], 0.0).exit_code() == 1
    assert FleetReport([row("error"), row("skipped"),
                        row("ok")], 0.0).exit_code() == 4
    assert FleetReport([row("ok"), row("ok")], 0.0).exit_code() == 0
    assert FleetReport([], 0.0).exit_code() == 0


# --------------------------------------------------------- A3: determinism


def test_to_json_byte_stable_with_fixed_started_at():
    a = _verify_suite().verify_all(started_at=FIXED_START).to_json()
    b = _verify_suite().verify_all(started_at=FIXED_START).to_json()
    assert a == b
    doc = json.loads(a)
    # keys sorted, runs sorted by server_id, timestamp derived from started_at.
    assert doc["runs"] == sorted(doc["runs"], key=lambda r: r["server_id"])
    assert doc["generated_at"].endswith("+00:00")
    assert doc["exit_code"] == 2


def test_to_ndjson_one_row_per_server_sorted():
    nd = _verify_suite().verify_all(started_at=FIXED_START).to_ndjson()
    rows = [json.loads(line) for line in nd.splitlines() if line.strip()]
    assert [r["server_id"] for r in rows] == [
        "fs-clean", "fs-corrupt", "fs-exfil", "fs-tampered"
    ]
    assert nd.endswith("\n")


def test_totals_sums_event_classes_and_status_tallies():
    totals = _verify_suite().verify_all(started_at=FIXED_START).totals()
    assert totals["servers"] == 4
    assert totals["violations"] == 1
    assert totals["rug_pulls"] == 1
    assert totals["errors"] == 1
    assert totals["ok"] == 1
    # the exfil trace contributes exactly one outside_contract event.
    assert totals["outside_contract"] == 1


# ----------------------------------------------------- env expansion + redaction


def test_env_expansion_default_and_missing(monkeypatch):
    monkeypatch.delenv("MCP_FLEET_TEST_VAR", raising=False)
    ok = FleetServer(
        id="d", backend="mock",
        launch={"command": "mock", "env": {"T": "${MCP_FLEET_TEST_VAR:-fallback}"}},
    )
    assert ok.resolved_env() == {"T": "fallback"}

    monkeypatch.setenv("MCP_FLEET_TEST_VAR", "real")
    assert ok.resolved_env() == {"T": "real"}


def test_unresolved_var_marks_server_skipped(monkeypatch):
    monkeypatch.delenv("MCP_FLEET_UNSET_XYZ", raising=False)
    server = FleetServer(
        id="needs-var", backend="mock",
        launch={"command": "mock", "env": {"T": "${MCP_FLEET_UNSET_XYZ}"}},
        manifest_path=str(MANIFESTS / "fetch.json"),
    )
    report = Fleet([server]).infer_all(started_at=FIXED_START, write=False)
    assert report.runs[0].status == "skipped"
    assert report.exit_code() == 4


def test_env_values_never_serialized(monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN_ENV", "super-secret-value")
    server = FleetServer(
        id="s", backend="mock",
        launch={"command": "mock", "env": {"SECRET_TOKEN_ENV": "${SECRET_TOKEN_ENV}"}},
        manifest_path=str(MANIFESTS / "fetch.json"),
    )
    report = Fleet([server]).infer_all(started_at=FIXED_START, write=False)
    fp = report.runs[0].launch_fingerprint
    assert fp["env_keys"] == ["SECRET_TOKEN_ENV"]
    assert "env" not in fp
    assert "super-secret-value" not in report.to_json()
    assert "super-secret-value" not in report.to_ndjson()


def test_launch_fingerprint_redacts_stray_env_dict():
    row = FleetServerReport(
        server_id="s", status="ok", exit_code=0,
        launch_fingerprint={"command": "docker", "env": {"K": "leak-me"}},
    )
    d = row.to_dict()
    assert d["launch_fingerprint"]["env_keys"] == ["K"]
    assert "env" not in d["launch_fingerprint"]
    assert "leak-me" not in json.dumps(d)


def test_launch_fingerprint_redacts_url_and_arg_secrets():
    """url query strings / userinfo and secret-flag arg values are credential
    carriers for remote servers; they must never reach the serialized report,
    while env_keys still lists the key names (finding 4)."""
    server = FleetServer(
        id="remote",
        backend="mock",
        launch={
            "transport": "sse",
            "url": "https://user:pw@mcp.vendor.com/sse?access_token=SECRET-TOKEN-123",
            "args": ["--api-key", "sk-LIVE-9999", "--verbose"],
            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN:-x}"},
        },
    )
    row = FleetServerReport(
        server_id="remote", status="ok", exit_code=0,
        launch_fingerprint=server.launch_fingerprint(),
    )
    d = row.to_dict()
    fp = d["launch_fingerprint"]
    # url identity (scheme/host/path) kept; query + userinfo stripped.
    assert fp["url"] == "https://mcp.vendor.com/sse?REDACTED"
    assert fp["args"] == ["--api-key", "REDACTED", "--verbose"]
    assert fp["env_keys"] == ["GITHUB_TOKEN"]

    report = FleetReport([row], started_at=FIXED_START)
    for secret in ("SECRET-TOKEN-123", "sk-LIVE-9999", "user:pw"):
        assert secret not in report.to_json()
        assert secret not in report.to_ndjson()
    # the non-secret token name is still present so the report stays useful.
    assert "GITHUB_TOKEN" in report.to_json()


def test_to_server_spec_filters_env_to_granted_keys(monkeypatch):
    monkeypatch.setenv("GRANTED_TOK", "g")
    monkeypatch.setenv("DENIED_TOK", "d")
    server = FleetServer(
        id="s", backend="mock",
        launch={
            "command": "mock",
            "env": {"GRANTED_TOK": "${GRANTED_TOK}", "DENIED_TOK": "${DENIED_TOK}"},
        },
    )
    policy = Policy(
        server_id="s", manifest_hash="sha256:0",
        caps=[
            Capability(
                id=CapabilityId.ENV,
                status=CapabilityStatus.INFERRED,
                values=["GRANTED_TOK"],
            )
        ],
    )
    spec = server.to_server_spec(policy)
    assert spec.env == {"GRANTED_TOK": "g"}  # denied key filtered out
    assert spec.extra["launch_fingerprint"]["env_keys"] == ["DENIED_TOK", "GRANTED_TOK"]


def test_to_server_spec_wildcard_env_passes_all_keys(monkeypatch):
    monkeypatch.setenv("A_TOK", "a")
    monkeypatch.setenv("B_TOK", "b")
    server = FleetServer(
        id="s", backend="mock",
        launch={"command": "mock", "env": {"A_TOK": "${A_TOK}", "B_TOK": "${B_TOK}"}},
    )
    policy = Policy(
        server_id="s", manifest_hash="sha256:0",
        caps=[Capability(id=CapabilityId.ENV, status=CapabilityStatus.INFERRED,
                         values=["*"])],
    )
    assert server.to_server_spec(policy).env == {"A_TOK": "a", "B_TOK": "b"}


# ---------------------------------------------------- config validation rules


def test_docker_backend_requires_image(tmp_path):
    cfg = tmp_path / "f.yaml"
    cfg.write_text(
        'version: "0.1"\nservers:\n  x:\n    backend: docker\n'
        '    launch: {command: docker, args: [run, mcp/x]}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="requires an 'image'"):
        Fleet.from_config(cfg)


def test_remote_transport_downgrades_mode_to_observe(tmp_path, capsys):
    cfg = tmp_path / "f.yaml"
    cfg.write_text(
        'version: "0.1"\nservers:\n  remote:\n    backend: mock\n    mode: enforce\n'
        '    launch: {transport: http, url: "https://example.test/mcp"}\n',
        encoding="utf-8",
    )
    fleet = Fleet.from_config(cfg)
    assert fleet.servers[0].mode is Mode.OBSERVE
    assert "forcing mode=observe" in capsys.readouterr().err


def test_streamable_http_transport_alias():
    server = FleetServer(id="s", launch={"transport": "streamable-http", "url": "x"})
    assert server.transport == "http"


def test_url_without_transport_is_an_error():
    server = FleetServer(id="s", launch={"url": "https://x.example"})
    with pytest.raises(ValueError, match="transport"):
        _ = server.transport


def test_select_slices_by_labels():
    fleet = Fleet.from_config(FLEET_CONFIG)
    prod = fleet.select(env="prod")
    assert all(s.labels.get("env") == "prod" for s in prod.servers)
    assert {s.id for s in prod.servers} >= {"fs-clean", "fs-exfil"}
    assert "fs-tampered" not in {s.id for s in prod.servers}  # env=staging


# ------------------------------------------------------------- ingest adapters


def test_from_mcp_servers_claude_shape(tmp_path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(
        json.dumps({"mcpServers": {"gh": {"command": "docker",
                                          "args": ["run", "-i", "mcp/gh"]}}}),
        encoding="utf-8",
    )
    fleet = Fleet.from_mcp_servers(cfg, backend="mock")
    assert [s.id for s in fleet.servers] == ["gh"]
    assert fleet.servers[0].labels["client"] == "mcp"
    assert fleet.servers[0].transport == "stdio"


def test_from_mcp_servers_vscode_shape(tmp_path):
    cfg = tmp_path / "settings.json"
    cfg.write_text(
        json.dumps({"servers": {"fetch": {"command": "uvx",
                                          "args": ["mcp-server-fetch"]}}}),
        encoding="utf-8",
    )
    fleet = Fleet.from_mcp_servers(cfg, backend="mock")
    assert fleet.servers[0].labels["client"] == "vscode"


# --------------------------------------------------------------- run + audit


def test_run_all_mock_backend_aggregates_like_verify():
    report = _verify_suite().run_all(started_at=FIXED_START)
    by_id = {r.server_id: r.status for r in report.runs}
    assert by_id["fs-clean"] == "ok"
    assert by_id["fs-exfil"] == "violation"
    assert by_id["fs-tampered"] == "rug_pull"  # ManifestDriftError -> rug_pull
    assert report.exit_code() == 2


def test_audit_all_reports_but_never_gates():
    fleet = Fleet.from_config(FLEET_CONFIG)
    # exfil alone: audit sees the outside_contract event but does not gate.
    exfil = fleet.select(suite="verify", novio="no")
    report = exfil.audit_all(started_at=FIXED_START)
    assert {r.status for r in report.runs} == {"ok"}
    assert report.exit_code() == 0
    assert report.severity().value == "critical"  # severity still flags it
    assert report.totals()["outside_contract"] == 1


# --------------------------------------------------- export delegation (REPORT)


@pytest.mark.skipif(
    not _report_available(),
    reason="Module REPORT (mcp_contract.report.export) not present yet",
)
def test_to_sarif_and_siem_delegate_to_report_module():
    report = _verify_suite().verify_all(started_at=FIXED_START)
    sarif = report.to_sarif()
    assert sarif["version"] == "2.1.0"
    siem = report.to_siem_ndjson()
    assert "evil.example.com" in siem
