"""Tests for PIE: rule-based classification, aggregation, LLM guardrails.

All fixtures are inline objects (no tests/fixtures/ files).
"""
from __future__ import annotations

from mcp_contract.models import (
    Capability,
    CapabilityId,
    CapabilityStatus,
    Evidence,
    Manifest,
    ToolIR,
)
from mcp_contract.pie import LLMAssist, NullLLM, classify_tool, infer_policy


def make_tool(
    name: str,
    description: str = "",
    params: tuple[str, ...] = (),
    schema: dict | None = None,
) -> ToolIR:
    if schema is None:
        props = {p: {"type": "string"} for p in params}
        schema = {"type": "object", "properties": props} if props else {}
    return ToolIR(name=name, description=description, input_schema=schema)


def make_manifest(*tools: ToolIR, server_name: str = "test-server") -> Manifest:
    return Manifest(server_name=server_name, tools=list(tools))


def cap_by_id(caps: list[Capability], cap_id: CapabilityId) -> Capability | None:
    matches = [c for c in caps if c.id == cap_id]
    assert len(matches) <= 1, f"duplicate caps for {cap_id}"
    return matches[0] if matches else None


# --- classifier: net.http ---------------------------------------------------


def test_url_literal_infers_host() -> None:
    tool = make_tool(
        "list_issues",
        "List issues via https://api.github.com/repos/{owner}/{repo}/issues.",
    )
    caps = classify_tool(tool)
    net = cap_by_id(caps, CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.INFERRED
    assert net.values == ["api.github.com"]
    assert net.evidence
    assert all(e.tool == "list_issues" for e in net.evidence)
    assert any("api.github.com" in e.detail for e in net.evidence)


def test_bare_hostname_inferred_and_filenames_filtered() -> None:
    tool = make_tool(
        "check_status", "Check the service status of api.example.com and status.json."
    )
    caps = classify_tool(tool)
    net = cap_by_id(caps, CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.INFERRED
    assert net.values == ["api.example.com"]  # status.json is not a host


def test_fetch_url_param_needs_review_star() -> None:
    tool = make_tool("fetch", "Fetch the contents of a URL.", params=("url",))
    caps = classify_tool(tool)
    net = cap_by_id(caps, CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.NEEDS_REVIEW
    assert net.values == ["*"]
    assert net.evidence


def test_uri_format_param_is_net_signal() -> None:
    tool = make_tool(
        "open_page",
        "Open the given page.",
        schema={
            "type": "object",
            "properties": {"target": {"type": "string", "format": "uri"}},
        },
    )
    caps = classify_tool(tool)
    net = cap_by_id(caps, CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.NEEDS_REVIEW
    assert net.values == ["*"]


def test_filename_lookalike_grants_nothing() -> None:
    # "data.parquet" is a filename, not a host: it must never produce an
    # inferred (granted) net.http cap, which would hand the container the
    # full docker network at boot.
    tool = make_tool("read_parquet", "Parses a data.parquet file and returns rows")
    caps = classify_tool(tool)
    net = cap_by_id(caps, CapabilityId.NET_HTTP)
    assert net is None or net.status != CapabilityStatus.INFERRED


def test_ambiguous_tld_bare_literal_clamped_to_needs_review() -> None:
    # ".pt" is a registrable TLD *and* a model-file suffix — ambiguous, so
    # it fails closed: kept for the reviewer, never auto-granted.
    tool = make_tool("load_model", "Loads the model.pt weights for inference")
    caps = classify_tool(tool)
    net = cap_by_id(caps, CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.NEEDS_REVIEW
    assert net.values == ["model.pt"]
    policy = infer_policy(make_manifest(tool))
    assert policy.granted(CapabilityId.NET_HTTP) is None


def test_url_param_with_example_url_stays_needs_review() -> None:
    # SPEC §4.4: fetch(url)'s host is a runtime value. An example URL in
    # the description must not flip the cap to inferred and must not drop
    # the "*" scope-unknown widener (bucket-2 would otherwise misclassify
    # every non-example host as outside_contract).
    tool = make_tool(
        "fetch",
        "Fetch a web page and return its text. Example: https://example.com/page",
        schema={
            "type": "object",
            "properties": {"url": {"type": "string", "format": "uri"}},
        },
    )
    caps = classify_tool(tool)
    net = cap_by_id(caps, CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.NEEDS_REVIEW
    assert set(net.values) == {"example.com", "*"}
    policy = infer_policy(make_manifest(tool))
    assert policy.granted(CapabilityId.NET_HTTP) is None


# --- classifier: fs ---------------------------------------------------------


def test_fs_read_with_path_literal_inferred() -> None:
    tool = make_tool(
        "read_file",
        "Read a file under /data and return its contents.",
        params=("path",),
    )
    caps = classify_tool(tool)
    fs_read = cap_by_id(caps, CapabilityId.FS_READ)
    assert fs_read is not None
    assert fs_read.status == CapabilityStatus.INFERRED
    assert fs_read.values == ["/data"]
    assert cap_by_id(caps, CapabilityId.FS_WRITE) is None


def test_fs_write_without_literal_is_class_level_review() -> None:
    tool = make_tool(
        "write_file", "Write content to a file.", params=("path", "content")
    )
    caps = classify_tool(tool)
    fs_write = cap_by_id(caps, CapabilityId.FS_WRITE)
    assert fs_write is not None
    assert fs_write.status == CapabilityStatus.NEEDS_REVIEW
    assert fs_write.values == []
    assert cap_by_id(caps, CapabilityId.FS_READ) is None


def test_move_implies_read_and_write() -> None:
    tool = make_tool(
        "move_file",
        "Move a file to a new location.",
        params=("source_path", "dest"),
    )
    caps = classify_tool(tool)
    assert cap_by_id(caps, CapabilityId.FS_READ) is not None
    assert cap_by_id(caps, CapabilityId.FS_WRITE) is not None


def test_relative_path_literal() -> None:
    tool = make_tool("load_config", "Load settings from ./config", params=("file",))
    caps = classify_tool(tool)
    fs_read = cap_by_id(caps, CapabilityId.FS_READ)
    assert fs_read is not None
    assert fs_read.status == CapabilityStatus.INFERRED
    assert fs_read.values == ["./config"]


def test_rest_route_tool_never_infers_fs() -> None:
    # A REST wrapper's "path" param + route literal must not become an
    # unreviewed host bind mount: any net context clamps fs to needs_review.
    tool = make_tool(
        "get_resource",
        "Get the resource at the given API path, e.g. /repos/octocat/hello",
        params=("path",),
    )
    caps = classify_tool(tool)
    for cap in caps:
        if cap.id in (CapabilityId.FS_READ, CapabilityId.FS_WRITE):
            assert cap.status == CapabilityStatus.NEEDS_REVIEW
    policy = infer_policy(make_manifest(tool))
    assert policy.granted(CapabilityId.FS_READ) is None
    assert policy.granted(CapabilityId.FS_WRITE) is None


def test_route_template_literal_is_not_a_mount_prefix() -> None:
    tool = make_tool(
        "read_entry",
        "Read the entry stored at /records/{id} for the caller",
        params=("path",),
    )
    caps = classify_tool(tool)
    fs_read = cap_by_id(caps, CapabilityId.FS_READ)
    assert fs_read is not None
    # the templated route is not harvested, so no concrete prefix exists
    assert fs_read.values == []
    assert fs_read.status == CapabilityStatus.NEEDS_REVIEW


# --- classifier: proc.exec --------------------------------------------------


def test_exec_tool_needs_review_never_inferred() -> None:
    tool = make_tool(
        "run_command",
        "Run a shell command and return its output.",
        params=("command",),
    )
    caps = classify_tool(tool)
    proc = cap_by_id(caps, CapabilityId.PROC_EXEC)
    assert proc is not None
    assert proc.status == CapabilityStatus.NEEDS_REVIEW
    assert proc.values == []
    assert proc.evidence


def test_bare_run_is_not_an_exec_signal() -> None:
    tool = make_tool("run_analysis", "Run analysis over the input numbers.")
    assert classify_tool(tool) == []


# --- classifier: env --------------------------------------------------------


def test_env_phrase_and_all_caps_values() -> None:
    tool = make_tool(
        "post_message",
        "Post a message to a Slack channel via the Slack API. "
        "Requires the SLACK_BOT_TOKEN environment variable.",
        params=("channel", "text"),
    )
    caps = classify_tool(tool)
    env = cap_by_id(caps, CapabilityId.ENV)
    assert env is not None
    assert env.status == CapabilityStatus.NEEDS_REVIEW
    assert env.values == ["SLACK_BOT_TOKEN"]
    net = cap_by_id(caps, CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.NEEDS_REVIEW
    assert net.values == ["*"]


# --- classifier: pure -------------------------------------------------------


def test_pure_tool_has_no_signals() -> None:
    tool = make_tool("add", "Add two numbers together.", params=("a", "b"))
    assert classify_tool(tool) == []


# --- infer_policy: aggregation ----------------------------------------------


def test_pure_tool_policy_all_five_denied() -> None:
    policy = infer_policy(
        make_manifest(make_tool("add", "Add two numbers.", params=("a", "b")))
    )
    assert {c.id for c in policy.caps} == set(CapabilityId)
    assert len(policy.caps) == len(CapabilityId)
    for cap in policy.caps:
        assert cap.status == CapabilityStatus.DENIED
        assert cap.values == []
        assert cap.evidence == []


def test_empty_manifest_all_denied() -> None:
    policy = infer_policy(make_manifest())
    assert all(c.status == CapabilityStatus.DENIED for c in policy.caps)
    assert len(policy.caps) == len(CapabilityId)


def test_merge_inferred_plus_unknown_union_needs_review() -> None:
    github = make_tool(
        "list_issues", "List issues via https://api.github.com/issues."
    )
    fetch = make_tool("fetch", "Fetch a URL.", params=("url",))
    policy = infer_policy(make_manifest(github, fetch))
    net = policy.cap(CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.NEEDS_REVIEW
    assert set(net.values) == {"api.github.com", "*"}
    assert {e.tool for e in net.evidence} == {"list_issues", "fetch"}
    # not granted while under review
    assert policy.granted(CapabilityId.NET_HTTP) is None


def test_merge_all_inferred_stays_inferred() -> None:
    a = make_tool("list_issues", "List issues via https://api.github.com/issues.")
    b = make_tool("get_user", "Get a user profile from https://api.github.com/users.")
    policy = infer_policy(make_manifest(a, b))
    net = policy.cap(CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.INFERRED
    assert net.values == ["api.github.com"]
    assert policy.granted(CapabilityId.NET_HTTP) is not None


def test_exec_never_granted_by_inference() -> None:
    policy = infer_policy(
        make_manifest(
            make_tool("run_command", "Run a shell command.", params=("command",))
        )
    )
    proc = policy.cap(CapabilityId.PROC_EXEC)
    assert proc is not None
    assert proc.status == CapabilityStatus.NEEDS_REVIEW
    assert policy.granted(CapabilityId.PROC_EXEC) is None


def test_policy_metadata_and_signal_evidence() -> None:
    manifest = make_manifest(
        make_tool("fetch", "Fetch a URL.", params=("url",)),
        server_name="fetcher",
    )
    policy = infer_policy(manifest)
    assert policy.server_id == "fetcher"
    assert policy.manifest_hash == manifest.hash()
    assert infer_policy(manifest, server_id="custom").server_id == "custom"
    for cap in policy.caps:
        if cap.status == CapabilityStatus.DENIED:
            assert cap.evidence == []
        else:
            assert cap.evidence, f"{cap.id} has no evidence"


# --- infer_policy: overrides ------------------------------------------------


def test_override_replaces_wholesale() -> None:
    manifest = make_manifest(make_tool("fetch", "Fetch a URL.", params=("url",)))
    override = Capability(
        CapabilityId.NET_HTTP,
        CapabilityStatus.INFERRED,
        values=["internal.proxy"],
        evidence=[Evidence("", "override", "ops pinned egress to the proxy")],
    )
    policy = infer_policy(manifest, overrides=[override])
    net = policy.cap(CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.INFERRED
    assert net.values == ["internal.proxy"]  # merged values fully replaced
    assert any(e.source == "override" for e in net.evidence)
    assert len(policy.caps) == len(CapabilityId)


def test_override_can_grant_exec() -> None:
    manifest = make_manifest(
        make_tool("run_command", "Run a shell command.", params=("command",))
    )
    override = Capability(
        CapabilityId.PROC_EXEC, CapabilityStatus.INFERRED, values=["git"]
    )
    policy = infer_policy(manifest, overrides=[override])
    granted = policy.granted(CapabilityId.PROC_EXEC)
    assert granted is not None
    assert granted.values == ["git"]
    assert any(e.source == "override" for e in granted.evidence)


# --- infer_policy: LLM guardrails -------------------------------------------


class EscalatingLLM:
    """Adversarial assist: claims everything is inferred (granted)."""

    def suggest(self, tool: ToolIR) -> list[Capability]:
        return [
            Capability(
                CapabilityId.NET_HTTP,
                CapabilityStatus.INFERRED,
                values=["evil.example.com"],
                evidence=[Evidence(tool.name, "description", "llm claims net")],
            ),
            Capability(
                CapabilityId.PROC_EXEC,
                CapabilityStatus.INFERRED,
                values=["bash"],
            ),
        ]


def test_llm_cannot_escalate() -> None:
    manifest = make_manifest(
        make_tool("list_issues", "List issues via https://api.github.com/issues.")
    )
    policy = infer_policy(manifest, llm=EscalatingLLM())
    # Rule-derived class: LLM suggestion dropped entirely.
    net = policy.cap(CapabilityId.NET_HTTP)
    assert net is not None
    assert net.status == CapabilityStatus.INFERRED
    assert net.values == ["api.github.com"]
    assert all(e.source != "llm" for e in net.evidence)
    # New class: added but clamped to needs_review, evidence tagged llm.
    proc = policy.cap(CapabilityId.PROC_EXEC)
    assert proc is not None
    assert proc.status == CapabilityStatus.NEEDS_REVIEW
    assert proc.values == ["bash"]
    assert proc.evidence
    assert all(e.source == "llm" for e in proc.evidence)
    assert policy.granted(CapabilityId.PROC_EXEC) is None


def test_llm_addition_does_not_touch_rule_values() -> None:
    class WideningLLM:
        def suggest(self, tool: ToolIR) -> list[Capability]:
            return [
                Capability(
                    CapabilityId.NET_HTTP,
                    CapabilityStatus.INFERRED,
                    values=["*"],
                )
            ]

    manifest = make_manifest(
        make_tool("list_issues", "List issues via https://api.github.com/issues.")
    )
    policy = infer_policy(manifest, llm=WideningLLM())
    net = policy.cap(CapabilityId.NET_HTTP)
    assert net is not None
    assert net.values == ["api.github.com"]
    assert net.status == CapabilityStatus.INFERRED


def test_merge_class_signals_empty_input_is_denied() -> None:
    # No signal must mean DENIED, never a vacuous-truth INFERRED grant.
    from mcp_contract.pie.inference import merge_class_signals

    for cap_id in CapabilityId:
        merged = merge_class_signals(cap_id, [])
        assert merged.status == CapabilityStatus.DENIED
        assert merged.values == []


def test_null_llm_is_a_no_op() -> None:
    assert NullLLM().suggest(make_tool("t")) == []
    assert isinstance(NullLLM(), LLMAssist)
    manifest = make_manifest(make_tool("add", "Add two numbers.", params=("a", "b")))
    with_null = infer_policy(manifest, llm=NullLLM())
    without = infer_policy(manifest)
    assert [c.to_dict() for c in with_null.caps] == [
        c.to_dict() for c in without.caps
    ]
