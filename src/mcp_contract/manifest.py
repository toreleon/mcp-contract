"""Manifest loading: normalize an MCP tool list into the internal IR.

Accepts the common shapes a manifest shows up in — a raw ``tools/list``
result, a full JSON-RPC response envelope, or a hand-written file with a
server name — and produces a `Manifest` of `ToolIR`s that the rest of the
engine (PIE, BCM) consumes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from mcp_contract.models import Manifest, ToolIR


def load_manifest(source: str | Path | dict) -> Manifest:
    """Load a manifest from a JSON/YAML file path or an already-parsed dict.

    Supported shapes:
    - ``{"tools": [...]}`` — an MCP ``tools/list`` result;
    - ``{"result": {"tools": [...]}}`` — a full JSON-RPC response;
    - ``{"name": ..., "tools": [...]}`` — a named manifest.

    ``server_name`` comes from ``"name"`` or ``"serverInfo".name`` (top level
    or under ``"result"``) if present, else the file stem, else ``"unknown"``.
    Each tool accepts both ``inputSchema`` and ``input_schema`` keys.

    Raises `ValueError` on unrecognized shapes or unparseable files.
    """
    file_stem: str | None = None
    if isinstance(source, dict):
        data: Any = source
    elif isinstance(source, (str, Path)):
        path = Path(source)
        file_stem = path.stem
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"cannot read manifest file {path}: {exc}") from exc
        data = _parse_text(text, path)
    else:
        raise ValueError(
            "load_manifest expects a file path or a parsed dict, got "
            f"{type(source).__name__}"
        )

    if not isinstance(data, dict):
        raise ValueError(
            "unrecognized manifest shape: expected a JSON/YAML object, got "
            f"{type(data).__name__}"
        )

    tools_raw = _extract_tools(data)
    tools = [_tool_ir(entry, i) for i, entry in enumerate(tools_raw)]
    return Manifest(
        server_name=_server_name(data, file_stem),
        tools=tools,
        raw=data,
    )


def _parse_text(text: str, path: Path) -> Any:
    """Parse file content as JSON or YAML based on suffix (try both else)."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"manifest file {path} is not valid JSON: {exc}") from exc
    if suffix in (".yaml", ".yml"):
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"manifest file {path} is not valid YAML: {exc}") from exc
    # Unknown suffix: JSON first (strict), then YAML (superset).
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(
                f"manifest file {path} is neither valid JSON nor valid YAML: {exc}"
            ) from exc


def _extract_tools(data: dict[str, Any]) -> list[Any]:
    if "tools" in data:
        tools = data["tools"]
    elif isinstance(data.get("result"), dict) and "tools" in data["result"]:
        tools = data["result"]["tools"]
    else:
        raise ValueError(
            "unrecognized manifest shape: expected a 'tools' list at the top "
            "level or under 'result' (MCP tools/list result or JSON-RPC "
            f"response); got keys {sorted(data.keys())!r}"
        )
    if not isinstance(tools, list):
        raise ValueError(
            f"unrecognized manifest shape: 'tools' must be a list, got "
            f"{type(tools).__name__}"
        )
    return tools


def _server_name(data: dict[str, Any], file_stem: str | None) -> str:
    scopes: list[dict[str, Any]] = [data]
    if isinstance(data.get("result"), dict):
        scopes.append(data["result"])
    for scope in scopes:
        name = scope.get("name")
        if isinstance(name, str) and name:
            return name
        info = scope.get("serverInfo")
        if isinstance(info, dict):
            info_name = info.get("name")
            if isinstance(info_name, str) and info_name:
                return info_name
    return file_stem or "unknown"


def _tool_ir(entry: Any, index: int) -> ToolIR:
    if not isinstance(entry, dict):
        raise ValueError(
            f"tool #{index} is not an object: {entry!r} (each entry in 'tools' "
            "must be a dict with at least a 'name')"
        )
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"tool #{index} has no 'name' (got {name!r})")
    schema = entry.get("inputSchema", entry.get("input_schema", {}))
    if not isinstance(schema, dict):
        schema = {}
    description = entry.get("description")
    return ToolIR(
        name=name,
        description=str(description) if description is not None else "",
        input_schema=schema,
        raw=entry,
    )
