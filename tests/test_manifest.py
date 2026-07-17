"""Tests for manifest loading/normalization (inline dict fixtures only)."""
from __future__ import annotations

import json

import pytest

from mcp_contract.manifest import load_manifest
from mcp_contract.models import Manifest

READ_FILE_TOOL = {
    "name": "read_file",
    "description": "Read a file from disk.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}


def test_tools_only_dict() -> None:
    manifest = load_manifest({"tools": [READ_FILE_TOOL]})
    assert isinstance(manifest, Manifest)
    assert manifest.server_name == "unknown"
    assert len(manifest.tools) == 1
    tool = manifest.tools[0]
    assert tool.name == "read_file"
    assert tool.description == "Read a file from disk."
    assert tool.input_schema["properties"] == {"path": {"type": "string"}}
    assert tool.raw == READ_FILE_TOOL


def test_named_manifest_dict() -> None:
    manifest = load_manifest({"name": "filesystem", "tools": [READ_FILE_TOOL]})
    assert manifest.server_name == "filesystem"


def test_jsonrpc_response_shape() -> None:
    manifest = load_manifest(
        {"jsonrpc": "2.0", "id": 1, "result": {"tools": [READ_FILE_TOOL]}}
    )
    assert manifest.server_name == "unknown"
    assert [t.name for t in manifest.tools] == ["read_file"]


def test_server_info_name() -> None:
    manifest = load_manifest(
        {
            "serverInfo": {"name": "github", "version": "1.0"},
            "tools": [READ_FILE_TOOL],
        }
    )
    assert manifest.server_name == "github"


def test_server_info_name_under_result() -> None:
    manifest = load_manifest(
        {
            "result": {
                "serverInfo": {"name": "slack"},
                "tools": [READ_FILE_TOOL],
            }
        }
    )
    assert manifest.server_name == "slack"


def test_snake_case_input_schema_accepted() -> None:
    manifest = load_manifest(
        {
            "tools": [
                {
                    "name": "t",
                    "input_schema": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                    },
                }
            ]
        }
    )
    assert "url" in manifest.tools[0].input_schema["properties"]


def test_missing_description_defaults_empty() -> None:
    manifest = load_manifest({"tools": [{"name": "t"}]})
    assert manifest.tools[0].description == ""
    assert manifest.tools[0].input_schema == {}


def test_json_file_server_name_from_stem(tmp_path) -> None:
    path = tmp_path / "filesystem.json"
    path.write_text(json.dumps({"tools": [READ_FILE_TOOL]}), encoding="utf-8")
    manifest = load_manifest(path)
    assert manifest.server_name == "filesystem"
    assert manifest.tools[0].name == "read_file"


def test_json_file_name_beats_stem(tmp_path) -> None:
    path = tmp_path / "whatever.json"
    path.write_text(
        json.dumps({"name": "github", "tools": [READ_FILE_TOOL]}), encoding="utf-8"
    )
    assert load_manifest(str(path)).server_name == "github"


def test_yaml_file(tmp_path) -> None:
    path = tmp_path / "server.yaml"
    path.write_text(
        "name: fetcher\n"
        "tools:\n"
        "  - name: fetch\n"
        "    description: Fetch a URL.\n"
        "    inputSchema:\n"
        "      type: object\n"
        "      properties:\n"
        "        url: {type: string}\n",
        encoding="utf-8",
    )
    manifest = load_manifest(path)
    assert manifest.server_name == "fetcher"
    assert manifest.tools[0].name == "fetch"
    assert "url" in manifest.tools[0].input_schema["properties"]


def test_hash_is_stable_and_tool_sensitive() -> None:
    a = load_manifest({"tools": [READ_FILE_TOOL]})
    b = load_manifest({"tools": [READ_FILE_TOOL]})
    c = load_manifest({"tools": [{"name": "other_tool"}]})
    assert a.hash() == b.hash()
    assert a.hash() != c.hash()
    assert a.hash().startswith("sha256:")


def test_hash_covers_annotations_and_output_schema() -> None:
    """Rug-pull gate: annotations/outputSchema changes must change the hash.

    A server flipping readOnlyHint -> destructiveHint (or swapping the
    outputSchema driving client handling) while keeping name/description/
    inputSchema byte-identical is a declared-contract change and must not
    slip past the drift gate.
    """
    base = dict(READ_FILE_TOOL)
    ro = {**base, "annotations": {"readOnlyHint": True}}
    destructive = {**base, "annotations": {"destructiveHint": True}}
    with_output = {**base, "outputSchema": {"type": "object"}}

    plain = load_manifest({"tools": [base]})
    assert load_manifest({"tools": [ro]}).hash() != plain.hash()
    assert (
        load_manifest({"tools": [ro]}).hash()
        != load_manifest({"tools": [destructive]}).hash()
    )
    assert load_manifest({"tools": [with_output]}).hash() != plain.hash()
    # snake_case outputSchema key is normalized into the same hash surface
    with_output_snake = {**base, "output_schema": {"type": "object"}}
    assert (
        load_manifest({"tools": [with_output]}).hash()
        == load_manifest({"tools": [with_output_snake]}).hash()
    )


def test_unrecognized_shape_raises() -> None:
    with pytest.raises(ValueError, match="tools"):
        load_manifest({"foo": "bar"})


def test_tools_not_a_list_raises() -> None:
    with pytest.raises(ValueError, match="list"):
        load_manifest({"tools": "read_file"})


def test_tool_without_name_raises() -> None:
    with pytest.raises(ValueError, match="name"):
        load_manifest({"tools": [{"description": "anonymous"}]})


def test_tool_not_a_dict_raises() -> None:
    with pytest.raises(ValueError, match="tool #0"):
        load_manifest({"tools": ["read_file"]})


def test_non_dict_non_path_source_raises() -> None:
    with pytest.raises(ValueError, match="file path or a parsed dict"):
        load_manifest(42)  # type: ignore[arg-type]


def test_top_level_list_file_raises(tmp_path) -> None:
    path = tmp_path / "list.json"
    path.write_text(json.dumps([READ_FILE_TOOL]), encoding="utf-8")
    with pytest.raises(ValueError, match="object"):
        load_manifest(path)


def test_invalid_json_file_raises(tmp_path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_manifest(path)


def test_missing_file_raises(tmp_path) -> None:
    with pytest.raises(ValueError, match="cannot read"):
        load_manifest(tmp_path / "nope.json")
