"""Structural conformance check for policy-mcp/v1 base documents.

A hand-rolled, stdlib-only structural validator for the *base* policy-mcp
document — the ``{version, description, permissions}`` projection produced by
:func:`mcp_contract.policy.io.policy_to_policy_mcp_base`. It mirrors the parts
of ``microsoft/policy-mcp`` → ``schema/v1.json`` (pinned commit below) that our
emitter produces, so the release gate needs **no** third-party dependency.

Why not ``jsonschema``: keeping runtime dependencies at stdlib + PyYAML. A
vendored copy of the real ``schema/v1.json`` snapshot lives at
``tests/fixtures/policy-mcp/v1.json`` (same commit) for an optional dev-only
``jsonschema`` cross-check; this structural check is the authoritative gate.

The check deliberately catches the one thing that makes our *full* self-
describing document (with the top-level ``x-mcp-contract`` key) schema-invalid:
the schema root is ``additionalProperties: false`` with no ``x-`` escape hatch,
so ``policy_mcp_base_conforms(policy_to_dict(p))`` returns a non-empty problem
list — a gap we surface rather than hide.
"""
from __future__ import annotations

import re
from typing import Any

# microsoft/policy-mcp schema/v1.json — pin (do not re-fetch at runtime).
POLICY_MCP_SCHEMA_COMMIT = "186e58128fa38da3df6ae2636782e820fe5d3da6"
POLICY_MCP_SCHEMA_URL = (
    "https://raw.githubusercontent.com/microsoft/policy-mcp/"
    "186e58128fa38da3df6ae2636782e820fe5d3da6/schema/v1.json"
)

# Schema vocabularies (schema/v1.json, pinned commit).
_ROOT_KEYS = ("version", "description", "permissions")
_PERMISSION_KEYS = ("storage", "network", "environment", "runtime", "resources", "ipc")
_ACCESS_TYPES = ("read", "write")
_VERSION_RE = re.compile(r"^1\.")
# NetworkCidrPermission pattern (IPv4 only) + EnvironmentPermission key pattern.
_CIDR_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
_ENV_KEY_RE = re.compile(r"^[^*]*$")


def policy_mcp_base_conforms(doc: Any) -> list[str]:
    """Structurally validate ``doc`` against policy-mcp/v1 (base form).

    Returns ``[]`` when ``doc`` conforms, else a list of human-readable
    problems (most-specific location first within each family). Checks, per
    ``schema/v1.json`` @ ``POLICY_MCP_SCHEMA_COMMIT``:

    - root keys ⊆ ``{version, description, permissions}`` (root
      ``additionalProperties: false``); ``version`` and ``permissions`` required;
    - ``version`` is a string matching ``^1\\.``; ``description`` (if present) a
      string;
    - ``permissions`` sub-keys ⊆ ``{storage, network, environment, runtime,
      resources, ipc}``;
    - ``network.allow[]/deny[]`` each ``oneOf {host}|{cidr IPv4}|{defaults:true}``;
    - ``storage.allow[]/deny[]`` each ``{uri: non-empty, access: non-empty ⊆
      {read, write}}``;
    - ``environment.allow[]`` each ``{key: non-empty, no '*'}``.

    ``runtime``/``resources``/``ipc`` are accepted as legal sub-keys but not
    validated in depth (our emitter never produces them).
    """
    problems: list[str] = []
    if not isinstance(doc, dict):
        return [f"root: document must be a mapping, got {type(doc).__name__}"]

    for key in sorted(k for k in doc if k not in _ROOT_KEYS):
        problems.append(
            f"root: unexpected key {key!r} — schema root is "
            "additionalProperties:false (only version/description/permissions)"
        )

    if "version" not in doc:
        problems.append("root: missing required key 'version'")
    else:
        version = doc["version"]
        if not isinstance(version, str):
            problems.append(
                f"version: must be a string, got {type(version).__name__}"
            )
        elif not _VERSION_RE.match(version):
            problems.append(f"version: must match ^1\\. (got {version!r})")

    if "description" in doc and not isinstance(doc["description"], str):
        problems.append(
            f"description: must be a string, got {type(doc['description']).__name__}"
        )

    if "permissions" not in doc:
        problems.append("root: missing required key 'permissions'")
    else:
        _check_permissions(doc["permissions"], problems)

    return problems


def _check_permissions(permissions: Any, problems: list[str]) -> None:
    if not isinstance(permissions, dict):
        problems.append(
            f"permissions: must be a mapping, got {type(permissions).__name__}"
        )
        return
    for key in sorted(k for k in permissions if k not in _PERMISSION_KEYS):
        problems.append(
            f"permissions: unexpected key {key!r} — allowed sub-keys are "
            "storage/network/environment/runtime/resources/ipc"
        )
    if "network" in permissions:
        _check_list(
            permissions["network"], "permissions.network", _check_network_perm, problems
        )
    if "storage" in permissions:
        _check_list(
            permissions["storage"], "permissions.storage", _check_storage_perm, problems
        )
    if "environment" in permissions:
        _check_environment(permissions["environment"], problems)


def _check_list(node: Any, loc: str, item_check, problems: list[str]) -> None:
    """Validate a ``{allow?, deny?}`` permission-list node."""
    if not isinstance(node, dict):
        problems.append(f"{loc}: must be a mapping, got {type(node).__name__}")
        return
    for key in sorted(k for k in node if k not in ("allow", "deny")):
        problems.append(f"{loc}: unexpected key {key!r} (allowed: allow/deny)")
    for list_key in ("allow", "deny"):
        if list_key not in node:
            continue
        items = node[list_key]
        if items is None:  # schema allows null
            continue
        if not isinstance(items, list):
            problems.append(
                f"{loc}.{list_key}: must be a list or null, got "
                f"{type(items).__name__}"
            )
            continue
        for index, item in enumerate(items):
            item_check(item, f"{loc}.{list_key}[{index}]", problems)


def _check_network_perm(item: Any, loc: str, problems: list[str]) -> None:
    if not isinstance(item, dict):
        problems.append(f"{loc}: must be a mapping, got {type(item).__name__}")
        return
    keys = set(item)
    if keys == {"host"}:
        host = item["host"]
        if not isinstance(host, str) or not host:
            problems.append(f"{loc}.host: must be a non-empty string")
    elif keys == {"cidr"}:
        cidr = item["cidr"]
        if not isinstance(cidr, str) or not _CIDR_RE.match(cidr):
            problems.append(
                f"{loc}.cidr: must match IPv4 CIDR pattern "
                f"^\\d{{1,3}}(\\.\\d{{1,3}}){{3}}/\\d{{1,2}}$ (got {cidr!r})"
            )
    elif keys == {"defaults"}:
        if item["defaults"] is not True:
            problems.append(f"{loc}.defaults: must be the boolean true")
    else:
        problems.append(
            f"{loc}: must be exactly one of {{host}}, {{cidr}}, or {{defaults}} "
            f"(got keys {sorted(keys)})"
        )


def _check_storage_perm(item: Any, loc: str, problems: list[str]) -> None:
    if not isinstance(item, dict):
        problems.append(f"{loc}: must be a mapping, got {type(item).__name__}")
        return
    for key in sorted(k for k in item if k not in ("uri", "access")):
        problems.append(f"{loc}: unexpected key {key!r} (allowed: uri/access)")
    uri = item.get("uri")
    if "uri" not in item:
        problems.append(f"{loc}: missing required key 'uri'")
    elif not isinstance(uri, str) or not uri:
        problems.append(f"{loc}.uri: must be a non-empty string")
    if "access" not in item:
        problems.append(f"{loc}: missing required key 'access'")
    else:
        access = item["access"]
        if not isinstance(access, list) or not access:
            problems.append(f"{loc}.access: must be a non-empty list")
        else:
            if len(set(map(_hashable, access))) != len(access):
                problems.append(f"{loc}.access: items must be unique")
            for value in access:
                if value not in _ACCESS_TYPES:
                    problems.append(
                        f"{loc}.access: {value!r} is not one of "
                        f"{list(_ACCESS_TYPES)}"
                    )


def _check_environment(node: Any, problems: list[str]) -> None:
    loc = "permissions.environment"
    if not isinstance(node, dict):
        problems.append(f"{loc}: must be a mapping, got {type(node).__name__}")
        return
    for key in sorted(k for k in node if k != "allow"):
        problems.append(f"{loc}: unexpected key {key!r} (allowed: allow)")
    if "allow" not in node:
        return
    items = node["allow"]
    if items is None:
        return
    if not isinstance(items, list):
        problems.append(
            f"{loc}.allow: must be a list or null, got {type(items).__name__}"
        )
        return
    for index, item in enumerate(items):
        item_loc = f"{loc}.allow[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{item_loc}: must be a mapping, got {type(item).__name__}")
            continue
        for key in sorted(k for k in item if k != "key"):
            problems.append(f"{item_loc}: unexpected key {key!r} (allowed: key)")
        if "key" not in item:
            problems.append(f"{item_loc}: missing required key 'key'")
            continue
        env_key = item["key"]
        if not isinstance(env_key, str) or not env_key:
            problems.append(f"{item_loc}.key: must be a non-empty string")
        elif not _ENV_KEY_RE.match(env_key):
            problems.append(
                f"{item_loc}.key: must not contain '*' (pattern ^[^*]*$; got "
                f"{env_key!r})"
            )


def _hashable(value: Any) -> Any:
    """Best-effort hashable projection for uniqueness checks."""
    try:
        hash(value)
        return value
    except TypeError:
        return repr(value)
