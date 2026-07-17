"""Tests for policy I/O (Module B) — inline objects only, no fixtures dir."""
from __future__ import annotations

import pytest

from mcp_contract.models import (
    Capability,
    CapabilityId,
    CapabilityStatus,
    Evidence,
    Manifest,
    Policy,
    ToolIR,
)
from mcp_contract.policy import (
    dump_policy,
    load_policy,
    policy_to_dict,
    verify_manifest_hash,
)


def _manifest() -> Manifest:
    return Manifest(
        server_name="github",
        tools=[
            ToolIR(
                name="list_issues",
                description="List issues via api.github.com",
                input_schema={"type": "object"},
            ),
            ToolIR(
                name="read_file",
                description="Read a file from /data",
                input_schema={"type": "object"},
            ),
        ],
    )


def _policy(manifest_hash: str = "sha256:abc") -> Policy:
    return Policy(
        server_id="github",
        manifest_hash=manifest_hash,
        caps=[
            Capability(
                id=CapabilityId.NET_HTTP,
                status=CapabilityStatus.INFERRED,
                values=["api.github.com"],
                evidence=[
                    Evidence(
                        tool="list_issues",
                        source="description",
                        detail="host literal api.github.com",
                    )
                ],
            ),
            Capability(
                id=CapabilityId.FS_READ,
                status=CapabilityStatus.INFERRED,
                values=["/data"],
                evidence=[
                    Evidence(tool="read_file", source="param", detail="path param")
                ],
            ),
            Capability(id=CapabilityId.FS_WRITE, status=CapabilityStatus.NEEDS_REVIEW),
            Capability(id=CapabilityId.PROC_EXEC, status=CapabilityStatus.DENIED),
            Capability(
                id=CapabilityId.ENV,
                status=CapabilityStatus.INFERRED,
                values=["GITHUB_TOKEN"],
                evidence=[
                    Evidence(
                        tool="list_issues", source="description", detail="GITHUB_TOKEN"
                    )
                ],
            ),
        ],
    )


class TestRoundTrip:
    def test_yaml_string_round_trip_preserves_everything(self):
        original = _policy()
        loaded = load_policy(dump_policy(original))

        assert loaded.server_id == original.server_id
        assert loaded.manifest_hash == original.manifest_hash
        assert loaded.backend_hint == original.backend_hint
        assert loaded.generated_by == original.generated_by
        assert [c.to_dict() for c in loaded.caps] == [
            c.to_dict() for c in original.caps
        ]

    def test_file_round_trip_via_path_and_str(self, tmp_path):
        original = _policy()
        out = tmp_path / "policy.yaml"
        text = dump_policy(original, out)
        assert out.read_text(encoding="utf-8") == text

        for source in (out, str(out)):
            loaded = load_policy(source)
            assert loaded.manifest_hash == original.manifest_hash
            assert [c.to_dict() for c in loaded.caps] == [
                c.to_dict() for c in original.caps
            ]

    def test_dict_source(self):
        original = _policy()
        loaded = load_policy(policy_to_dict(original))
        assert [c.to_dict() for c in loaded.caps] == [
            c.to_dict() for c in original.caps
        ]

    def test_unrecognized_source_raises(self):
        with pytest.raises(ValueError):
            load_policy("just a scalar, not a mapping")
        with pytest.raises(ValueError):
            load_policy({"unrelated": True})


class TestFailClosedValidation:
    """The human-approval seam must fail closed on malformed edits."""

    @staticmethod
    def _doc(caps: list[dict] | object) -> dict:
        return {
            "version": "1.0",
            "x-mcp-contract": {
                "schema": "policy-mcp/v1",
                "server_id": "s",
                "source_manifest_hash": "sha256:abc",
                "caps": caps,
            },
        }

    def test_scalar_string_values_rejected(self):
        # A reviewer typing `values: /data` (YAML scalar) instead of
        # `values: [/data]` would otherwise be char-split into ['/', 'd',
        # 'a', 't', 'a'] and '/' matches every absolute path — a silent
        # filesystem-wide grant. Must raise instead.
        doc = self._doc(
            [{"id": "fs.read", "status": "inferred", "values": "/data"}]
        )
        with pytest.raises(ValueError, match="'values' must be a"):
            load_policy(doc)

    def test_scalar_string_values_rejected_from_yaml_text(self):
        text = (
            "version: '1.0'\n"
            "x-mcp-contract:\n"
            "  server_id: s\n"
            "  source_manifest_hash: 'sha256:abc'\n"
            "  caps:\n"
            "    - {id: fs.read, status: inferred, values: /data}\n"
        )
        with pytest.raises(ValueError, match="values"):
            load_policy(text)

    def test_non_list_caps_rejected(self):
        with pytest.raises(ValueError, match="caps"):
            load_policy(self._doc({"id": "fs.read"}))
        with pytest.raises(ValueError, match="mapping"):
            load_policy(self._doc(["fs.read"]))

    def test_duplicate_cap_ids_rejected(self):
        # First-wins resolution would silently ignore an appended
        # revocation ({id: fs.read, status: denied}); reject instead.
        doc = self._doc(
            [
                {"id": "fs.read", "status": "inferred", "values": ["/data"]},
                {"id": "fs.read", "status": "denied", "values": []},
            ]
        )
        with pytest.raises(ValueError, match="duplicate capability id"):
            load_policy(doc)

    def test_invalid_yaml_text_raises_value_error(self):
        with pytest.raises(ValueError, match="not valid YAML"):
            load_policy("permissions: {network: [unclosed\n")


class TestForeignImport:
    """Files in the real policy-mcp shape, without x-mcp-contract."""

    FOREIGN = {
        "version": "1.0",
        "permissions": {
            "network": {
                "allow": [{"host": "api.openai.com"}, {"cidr": "10.0.0.0/8"}]
            },
            "storage": {
                "allow": [
                    {"uri": "fs:///data", "access": ["read", "write"]},
                    {"uri": "fs://workspace/**", "access": ["read"]},
                    {"uri": "fs:///no-access-listed"},
                ]
            },
            "environment": {"allow": [{"key": "API_KEY"}]},
        },
    }

    def test_grants_become_inferred_caps(self):
        policy = load_policy(self.FOREIGN)

        net = policy.cap(CapabilityId.NET_HTTP)
        assert net is not None
        assert net.status == CapabilityStatus.INFERRED
        assert net.values == ["api.openai.com", "10.0.0.0/8"]
        assert net.evidence[0].source == "override"
        assert net.evidence[0].detail == "imported from policy-mcp permissions"

        fs_read = policy.cap(CapabilityId.FS_READ)
        assert fs_read is not None
        assert fs_read.status == CapabilityStatus.INFERRED
        # glob suffix stripped to a plain prefix; access-less entry skipped
        assert fs_read.values == ["/data", "workspace"]

        fs_write = policy.cap(CapabilityId.FS_WRITE)
        assert fs_write is not None
        assert fs_write.values == ["/data"]

        env = policy.cap(CapabilityId.ENV)
        assert env is not None
        assert env.values == ["API_KEY"]

    def test_absent_classes_denied_and_all_five_present(self):
        policy = load_policy(self.FOREIGN)
        assert {c.id for c in policy.caps} == set(CapabilityId)
        proc = policy.cap(CapabilityId.PROC_EXEC)
        assert proc is not None
        assert proc.status == CapabilityStatus.DENIED
        assert proc.values == []
        assert proc.evidence == []

    def test_foreign_file_server_id_from_stem(self, tmp_path):
        import yaml

        path = tmp_path / "weather.yaml"
        path.write_text(yaml.safe_dump(self.FOREIGN), encoding="utf-8")
        policy = load_policy(path)
        assert policy.server_id == "weather"
        assert policy.manifest_hash == ""

    def test_version_only_policy_imports_as_all_denied(self):
        policy = load_policy({"version": "1.0"})
        assert all(c.status == CapabilityStatus.DENIED for c in policy.caps)


class TestVerifyManifestHash:
    def test_matching_hash(self):
        manifest = _manifest()
        policy = _policy(manifest_hash=manifest.hash())
        assert verify_manifest_hash(policy, manifest) is True

    def test_tampered_manifest_fails(self):
        manifest = _manifest()
        policy = _policy(manifest_hash=manifest.hash())
        manifest.tools[0].description = "List issues via evil.example.com"
        assert verify_manifest_hash(policy, manifest) is False

    def test_survives_round_trip(self, tmp_path):
        manifest = _manifest()
        policy = _policy(manifest_hash=manifest.hash())
        loaded = load_policy(dump_policy(policy, tmp_path / "p.yaml"))
        assert verify_manifest_hash(loaded, manifest) is True


class TestOnlyInferredCapsInPermissions:
    def test_non_inferred_caps_absent_from_permissions(self):
        policy = Policy(
            server_id="mixed",
            manifest_hash="sha256:abc",
            caps=[
                Capability(
                    id=CapabilityId.NET_HTTP,
                    status=CapabilityStatus.NEEDS_REVIEW,
                    values=["*"],
                ),
                Capability(
                    id=CapabilityId.FS_READ,
                    status=CapabilityStatus.INFERRED,
                    values=["/data"],
                ),
                Capability(
                    id=CapabilityId.FS_WRITE,
                    status=CapabilityStatus.INFERRED,
                    values=["/data"],
                ),
                Capability(id=CapabilityId.PROC_EXEC, status=CapabilityStatus.NEEDS_REVIEW),
                Capability(id=CapabilityId.ENV, status=CapabilityStatus.DENIED),
            ],
        )
        doc = policy_to_dict(policy)
        permissions = doc["permissions"]

        assert "network" not in permissions  # needs_review is NOT granted
        assert "environment" not in permissions  # denied is NOT granted
        # proc.exec has no policy-mcp analog even when reviewed
        assert "storage" in permissions
        assert permissions["storage"]["allow"] == [
            {"uri": "fs:///data", "access": ["read", "write"]}
        ]
        # the full three-status picture still lives in the extension block
        ext_caps = {c["id"]: c for c in doc["x-mcp-contract"]["caps"]}
        assert set(ext_caps) == {cid.value for cid in CapabilityId}
        assert ext_caps["net.http"]["status"] == "needs_review"
        assert ext_caps["proc.exec"]["status"] == "needs_review"

    def test_inferred_proc_exec_never_in_permissions(self):
        policy = Policy(
            server_id="shellish",
            manifest_hash="sha256:abc",
            caps=[
                Capability(
                    id=CapabilityId.PROC_EXEC,
                    status=CapabilityStatus.INFERRED,
                    values=["git"],
                )
            ],
        )
        assert policy_to_dict(policy)["permissions"] == {}
