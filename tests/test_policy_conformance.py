"""Tests for policy-mcp conformance (GO-FORWARD §2.3/§2.4, acceptance A6).

Exercises the strict base projection, the policy hash, the CIDR-vs-host and
env-key ``*`` emit guards, and the hand-rolled structural conformance check —
cross-checked against the vendored ``schema/v1.json`` snapshot (never fetched
from the network here).
"""
from __future__ import annotations

import glob
import json
from pathlib import Path

import pytest

from mcp_contract.manifest import load_manifest
from mcp_contract.models import (
    Capability,
    CapabilityId,
    CapabilityStatus,
    Policy,
)
from mcp_contract.pie.inference import infer_policy
from mcp_contract.policy import (
    POLICY_MCP_SCHEMA_COMMIT,
    POLICY_MCP_SCHEMA_URL,
    policy_hash,
    policy_mcp_base_conforms,
    policy_to_dict,
    policy_to_policy_mcp_base,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MANIFEST_GLOB = str(_REPO_ROOT / "tests" / "fixtures" / "manifests" / "*.json")
_SCHEMA_SNAPSHOT = _REPO_ROOT / "tests" / "fixtures" / "policy-mcp" / "v1.json"


def _manifest_paths() -> list[str]:
    paths = sorted(glob.glob(_MANIFEST_GLOB))
    assert paths, "no fixture manifests found"
    return paths


def _fixture_policies() -> list[tuple[str, Policy]]:
    return [
        (Path(p).stem, infer_policy(load_manifest(p))) for p in _manifest_paths()
    ]


def _net_policy(*values: str) -> Policy:
    return Policy(
        server_id="net",
        manifest_hash="sha256:abc",
        caps=[
            Capability(
                id=CapabilityId.NET_HTTP,
                status=CapabilityStatus.INFERRED,
                values=list(values),
            )
        ],
    )


def _env_policy(*values: str) -> Policy:
    return Policy(
        server_id="env",
        manifest_hash="sha256:abc",
        caps=[
            Capability(
                id=CapabilityId.ENV,
                status=CapabilityStatus.INFERRED,
                values=list(values),
            )
        ],
    )


# --------------------------------------------------------------------------- #
# A6 — every fixture manifest's inferred base document conforms.
# --------------------------------------------------------------------------- #
class TestFixtureConformance:
    @pytest.mark.parametrize("stem,policy", _fixture_policies(), ids=lambda x: x)
    def test_base_projection_conforms(self, stem: str, policy: Policy):
        base = policy_to_policy_mcp_base(policy)
        assert policy_mcp_base_conforms(base) == []

    @pytest.mark.parametrize("stem,policy", _fixture_policies(), ids=lambda x: x)
    def test_full_document_fails_on_extension_key(self, stem: str, policy: Policy):
        # The full self-describing doc carries a top-level x-mcp-contract key;
        # the schema root is additionalProperties:false — this KNOWN gap must
        # surface, not hide.
        problems = policy_mcp_base_conforms(policy_to_dict(policy))
        assert problems != []
        assert any("x-mcp-contract" in p for p in problems)

    def test_base_projection_has_only_three_keys(self):
        _, policy = _fixture_policies()[0]
        base = policy_to_policy_mcp_base(policy)
        assert set(base) == {"version", "description", "permissions"}

    def test_base_and_full_share_first_three_keys(self):
        # The projection is exactly policy_to_dict's first three keys.
        for _, policy in _fixture_policies():
            full = policy_to_dict(policy)
            base = policy_to_policy_mcp_base(policy)
            assert base == {k: full[k] for k in ("version", "description", "permissions")}


# --------------------------------------------------------------------------- #
# CIDR-vs-host and env-key guards (the CRITICAL correctness note).
# --------------------------------------------------------------------------- #
class TestNetworkGuards:
    def test_host_value_emits_host(self):
        base = policy_to_policy_mcp_base(_net_policy("api.github.com"))
        assert base["permissions"]["network"]["allow"] == [{"host": "api.github.com"}]
        assert policy_mcp_base_conforms(base) == []

    def test_cidr_value_emits_cidr(self):
        base = policy_to_policy_mcp_base(_net_policy("10.0.0.0/8"))
        assert base["permissions"]["network"]["allow"] == [{"cidr": "10.0.0.0/8"}]
        assert policy_mcp_base_conforms(base) == []

    def test_mixed_host_and_cidr(self):
        base = policy_to_policy_mcp_base(
            _net_policy("api.github.com", "192.168.0.0/16")
        )
        assert base["permissions"]["network"]["allow"] == [
            {"host": "api.github.com"},
            {"cidr": "192.168.0.0/16"},
        ]

    def test_wildcard_and_bare_ip_stay_host(self):
        # Wildcard hosts and raw IPs are legal host strings, not CIDRs.
        base = policy_to_policy_mcp_base(_net_policy("*.github.com", "*", "10.0.0.1"))
        assert base["permissions"]["network"]["allow"] == [
            {"host": "*.github.com"},
            {"host": "*"},
            {"host": "10.0.0.1"},
        ]
        assert policy_mcp_base_conforms(base) == []


class TestEnvGuards:
    def test_plain_key_emitted(self):
        base = policy_to_policy_mcp_base(_env_policy("GITHUB_TOKEN"))
        assert base["permissions"]["environment"]["allow"] == [{"key": "GITHUB_TOKEN"}]
        assert policy_mcp_base_conforms(base) == []

    def test_bare_wildcard_env_omitted_not_raised(self):
        # ["*"] is the internal class-level "grant all env vars" convention.
        # It has no policy-mcp primitive: OMIT it from the strict base (never
        # raise), and drop the now-empty environment block entirely.
        base = policy_to_policy_mcp_base(_env_policy("*"))
        assert "environment" not in base["permissions"]
        assert policy_mcp_base_conforms(base) == []

    def test_bare_wildcard_still_present_in_full_caps(self):
        # The omission is only from the strict base; the cap is preserved.
        policy = _env_policy("*")
        full = policy_to_dict(policy)
        env_cap = next(c for c in full["x-mcp-contract"]["caps"] if c["id"] == "env")
        assert env_cap["values"] == ["*"]

    def test_wildcard_mixed_with_real_keys_keeps_real_keys(self):
        base = policy_to_policy_mcp_base(_env_policy("*", "GITHUB_TOKEN"))
        assert base["permissions"]["environment"]["allow"] == [{"key": "GITHUB_TOKEN"}]

    def test_malformed_key_raises(self):
        # "FOO*" is a malformed env var name (star with other chars) — fail loud.
        with pytest.raises(ValueError, match=r"contains '\*'"):
            policy_to_policy_mcp_base(_env_policy("FOO*"))

    def test_malformed_key_raises_in_policy_to_dict(self):
        with pytest.raises(ValueError, match=r"contains '\*'"):
            policy_to_dict(_env_policy("PREFIX*SUFFIX"))


class TestStorageGuards:
    def _fs_read_policy(self, *values: str) -> Policy:
        return Policy(
            server_id="fs",
            manifest_hash="sha256:abc",
            caps=[
                Capability(
                    id=CapabilityId.FS_READ,
                    status=CapabilityStatus.INFERRED,
                    values=list(values),
                )
            ],
        )

    def test_duplicate_fs_read_path_dedupes_access(self):
        # A hand-edited/loaded policy with a repeated fs.read path must not emit
        # access ['read','read'] (schema access has uniqueItems:true) — finding 9.
        base = policy_to_policy_mcp_base(self._fs_read_policy("/data", "/data"))
        allow = base["permissions"]["storage"]["allow"]
        assert allow == [{"uri": "fs:///data", "access": ["read"]}]
        assert policy_mcp_base_conforms(base) == []

    def test_read_write_same_path_merges_without_duplicates(self):
        policy = Policy(
            server_id="fs",
            manifest_hash="sha256:abc",
            caps=[
                Capability(CapabilityId.FS_READ, CapabilityStatus.INFERRED,
                           ["/data", "/data"]),
                Capability(CapabilityId.FS_WRITE, CapabilityStatus.INFERRED,
                           ["/data", "/data"]),
            ],
        )
        base = policy_to_policy_mcp_base(policy)
        assert base["permissions"]["storage"]["allow"] == [
            {"uri": "fs:///data", "access": ["read", "write"]}
        ]
        assert policy_mcp_base_conforms(base) == []


# --------------------------------------------------------------------------- #
# policy_hash — stable, granted-surface-only, excludes generated_by.
# --------------------------------------------------------------------------- #
class TestPolicyHash:
    def test_format(self):
        h = policy_hash(_net_policy("api.github.com"))
        assert h.startswith("sha256:")
        assert len(h) == len("sha256:") + 64

    def test_deterministic(self):
        p = _net_policy("api.github.com")
        assert policy_hash(p) == policy_hash(p)

    def test_excludes_generated_by(self):
        a = Policy(
            server_id="x",
            manifest_hash="sha256:abc",
            caps=[
                Capability(CapabilityId.NET_HTTP, CapabilityStatus.INFERRED, ["h.com"])
            ],
            generated_by="mcp-contract/0.1",
        )
        b = Policy(
            server_id="x",
            manifest_hash="sha256:abc",
            caps=[
                Capability(CapabilityId.NET_HTTP, CapabilityStatus.INFERRED, ["h.com"])
            ],
            generated_by="something-else/9.9",
        )
        assert policy_hash(a) == policy_hash(b)

    def test_widened_grant_changes_hash(self):
        narrow = _net_policy("api.github.com")
        wide = _net_policy("api.github.com", "evil.example.com")
        assert policy_hash(narrow) != policy_hash(wide)

    def test_status_flip_changes_hash(self):
        # Same values, needs_review -> inferred widens the granted surface.
        needs_review = Policy(
            server_id="x",
            manifest_hash="sha256:abc",
            caps=[
                Capability(
                    CapabilityId.NET_HTTP, CapabilityStatus.NEEDS_REVIEW, ["h.com"]
                )
            ],
        )
        inferred = _net_policy("h.com")
        # differ in caps AND in permissions block
        assert policy_hash(needs_review) != policy_hash(inferred)


# --------------------------------------------------------------------------- #
# Structural check — negative cases.
# --------------------------------------------------------------------------- #
class TestStructuralCheck:
    def _base(self, permissions: dict) -> dict:
        return {"version": "1.0", "description": "d", "permissions": permissions}

    def test_empty_permissions_conforms(self):
        assert policy_mcp_base_conforms(self._base({})) == []

    def test_non_mapping_rejected(self):
        assert policy_mcp_base_conforms(["not", "a", "map"]) != []

    def test_missing_version(self):
        problems = policy_mcp_base_conforms({"permissions": {}})
        assert any("version" in p for p in problems)

    def test_missing_permissions(self):
        problems = policy_mcp_base_conforms({"version": "1.0"})
        assert any("permissions" in p for p in problems)

    def test_bad_version_pattern(self):
        problems = policy_mcp_base_conforms(self._base({}) | {"version": "2.0"})
        assert any("^1" in p for p in problems)

    def test_unexpected_root_key(self):
        doc = self._base({})
        doc["extra"] = 1
        problems = policy_mcp_base_conforms(doc)
        assert any("extra" in p for p in problems)

    def test_unexpected_permission_subkey(self):
        problems = policy_mcp_base_conforms(self._base({"bogus": {}}))
        assert any("bogus" in p for p in problems)

    def test_network_item_with_both_host_and_cidr(self):
        problems = policy_mcp_base_conforms(
            self._base({"network": {"allow": [{"host": "h", "cidr": "1.2.3.4/8"}]}})
        )
        assert problems != []

    def test_network_cidr_bad_pattern(self):
        problems = policy_mcp_base_conforms(
            self._base({"network": {"allow": [{"cidr": "not-a-cidr"}]}})
        )
        assert any("CIDR" in p for p in problems)

    def test_network_defaults_true_conforms(self):
        assert (
            policy_mcp_base_conforms(
                self._base({"network": {"allow": [{"defaults": True}]}})
            )
            == []
        )

    def test_network_allow_null_conforms(self):
        assert policy_mcp_base_conforms(self._base({"network": {"allow": None}})) == []

    def test_storage_missing_access(self):
        problems = policy_mcp_base_conforms(
            self._base({"storage": {"allow": [{"uri": "fs:///data"}]}})
        )
        assert any("access" in p for p in problems)

    def test_storage_bad_access_value(self):
        problems = policy_mcp_base_conforms(
            self._base(
                {"storage": {"allow": [{"uri": "fs:///d", "access": ["execute"]}]}}
            )
        )
        assert any("access" in p for p in problems)

    def test_storage_empty_uri(self):
        problems = policy_mcp_base_conforms(
            self._base({"storage": {"allow": [{"uri": "", "access": ["read"]}]}})
        )
        assert any("uri" in p for p in problems)

    def test_environment_key_with_star(self):
        problems = policy_mcp_base_conforms(
            self._base({"environment": {"allow": [{"key": "FOO*"}]}})
        )
        assert any("*" in p for p in problems)

    def test_environment_missing_key(self):
        problems = policy_mcp_base_conforms(
            self._base({"environment": {"allow": [{"name": "FOO"}]}})
        )
        assert problems != []

    def test_environment_deny_not_allowed(self):
        # EnvironmentPermissions only exposes `allow`.
        problems = policy_mcp_base_conforms(
            self._base({"environment": {"deny": []}})
        )
        assert any("deny" in p for p in problems)


# --------------------------------------------------------------------------- #
# Schema pin + vendored snapshot alignment (offline only).
# --------------------------------------------------------------------------- #
class TestSchemaPin:
    def test_commit_and_url_agree(self):
        assert POLICY_MCP_SCHEMA_COMMIT in POLICY_MCP_SCHEMA_URL
        assert POLICY_MCP_SCHEMA_COMMIT == "186e58128fa38da3df6ae2636782e820fe5d3da6"

    def test_snapshot_present_and_pinned_in_readme(self):
        readme = (_SCHEMA_SNAPSHOT.parent / "README.md").read_text(encoding="utf-8")
        assert POLICY_MCP_SCHEMA_COMMIT in readme

    def test_snapshot_root_matches_our_vocabulary(self):
        schema = json.loads(_SCHEMA_SNAPSHOT.read_text(encoding="utf-8"))
        assert schema["additionalProperties"] is False
        assert set(schema["properties"]) == set(_root_keys())
        assert set(schema["properties"]["permissions"]["properties"]) == {
            "storage",
            "network",
            "environment",
            "runtime",
            "resources",
            "ipc",
        }


def _root_keys() -> set[str]:
    return {"version", "description", "permissions"}


# --------------------------------------------------------------------------- #
# Optional belt-and-suspenders: cross-check with jsonschema if installed.
# (jsonschema is a dev-only extra; never a runtime dependency.)
# --------------------------------------------------------------------------- #
class TestJsonSchemaCrossCheck:
    def _validator(self):
        jsonschema = pytest.importorskip("jsonschema")
        schema = json.loads(_SCHEMA_SNAPSHOT.read_text(encoding="utf-8"))
        return jsonschema, schema

    @pytest.mark.parametrize("stem,policy", _fixture_policies(), ids=lambda x: x)
    def test_base_validates_against_vendored_schema(self, stem: str, policy: Policy):
        jsonschema, schema = self._validator()
        jsonschema.validate(policy_to_policy_mcp_base(policy), schema)

    def test_full_document_rejected_by_vendored_schema(self):
        jsonschema, schema = self._validator()
        _, policy = _fixture_policies()[0]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(policy_to_dict(policy), schema)
