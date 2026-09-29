"""A fence authority plan needs reviewed source, release, deletion and target identity."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from scripts import check_passport_beta_fence_authority as authority
from scripts.probe_passport_beta_host import HostProbeError


HEAD = "a" * 40
TAG_OBJECT = "b" * 40
DELETION_HEAD = "c" * 40
OBSERVATION = "d" * 64
DIGEST = "sha256:" + "e" * 64


def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path
    approval = root / "deploy-config/passport-beta-fence-approved-target.json"
    approval.parent.mkdir()
    planned_dir = root / "planned"
    planned_dir.mkdir()
    manifest = planned_dir / "stack-manifest.json"
    def component(name: str, repository: str) -> dict:
        return {
            "name": name, "repository": repository, "commit": "3" * 40,
            "version": "1.0.0", "artifacts": [{
                "type": "python", "uri": "https://example.test/artifact.whl",
                "digest": DIGEST,
            }],
        }
    manifest.write_text(json.dumps({
        "schema": "marty.stack/v1", "release": "marty-ui@1.2.3",
        "components": [
            component("marty-api-core", "ElevenID/marty-cli"),
            component("marty-blog", "ElevenID/marty-blog"),
            component("marty-core-python", "ElevenID/marty-core"),
            component("marty-verification-python", "ElevenID/marty-core"),
            component("marty-iso18013-python", "ElevenID/marty-core"),
            component("marty-common", "ElevenID/Marty"),
            component("marty-cli", "ElevenID/marty-cli"),
            component("marty-integration-tests", "ElevenID/marty-integration-tests"),
            {**component("marty-credentials-issuance", "ElevenID/marty-credentials"),
             "artifacts": [{"type": "oci",
                            "uri": "ghcr.io/elevenid/marty-credentials-issuance",
                            "digest": "sha256:" + "f" * 64}]},
            {
            "name": "marty-ui", "repository": "ElevenID/marty-ui", "commit": HEAD,
            "version": "1.2.3",
            "artifacts": [{"type": "oci", "uri": role,
                           "digest": "sha256:" + format(index, "x") * 64}
                          for index, role in enumerate(sorted(authority.OCI_ROLES), 1)],
            },
        ],
    }), encoding="utf-8")
    baseline_dir = root / "beta-baseline"
    baseline_dir.mkdir()
    baseline = baseline_dir / "stack-manifest.json"
    baseline_source = json.loads(manifest.read_text(encoding="utf-8"))
    baseline_source["components"][-1]["commit"] = "9" * 40
    baseline.write_text(json.dumps(baseline_source), encoding="utf-8")
    planned = json.loads(manifest.read_text(encoding="utf-8"))
    planned["components"][-2]["artifacts"][0]["digest"] = "sha256:" + "5" * 64
    planned["components"][-1]["artifacts"][1]["digest"] = "sha256:" + "4" * 64
    manifest.write_text(json.dumps(planned), encoding="utf-8")
    (planned_dir / "SHA256SUMS").write_text("synthetic", encoding="utf-8")
    (baseline_dir / "SHA256SUMS").write_text("synthetic", encoding="utf-8")
    approval.write_text(json.dumps({
        "schema": "marty.passport-beta-fence-approved-target/v1",
        "observation_sha256": OBSERVATION,
        "postgres_system_identifier": "12345",
        "database_oid": "87774",
        "credentials_deletion_head": DELETION_HEAD,
        "beta_baseline_source_commit": "9" * 40,
        "beta_baseline_manifest_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    install = root / "install.sql"
    drain = root / "drain.sql"
    verify = root / "verify.sql"
    install.write_text("install", encoding="utf-8")
    drain.write_text("drain", encoding="utf-8")
    verify.write_text("verify", encoding="utf-8")
    for relative in authority.PROTECTED_FILES:
        path = root / relative
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative, encoding="utf-8")
    def blob(path: Path) -> str:
        data = path.read_bytes()
        return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()

    committed_blobs = {relative: blob(root / relative)
                       for relative in authority.PROTECTED_FILES}
    monkeypatch.setattr(authority, "ROOT", root)
    monkeypatch.setattr(authority, "APPROVAL", approval)
    monkeypatch.setattr(authority, "INSTALL", install)
    monkeypatch.setattr(authority, "DRAIN", drain)
    monkeypatch.setattr(authority, "VERIFY", verify)
    values = {
        "branch": "main", "status": "", "protected": True, "remote_head": HEAD,
        "tracked": True, "custom_filter": False,
        "tag_object": TAG_OBJECT, "tag_type": "tag", "tag_commit": HEAD,
        "published_tag_object": TAG_OBJECT, "published_tag_commit": HEAD,
        "deletion_state": "OPEN", "deletion_draft": True,
        "deletion_head": DELETION_HEAD,
        "baseline": baseline,
    }

    def runner(command: list[str]) -> str:
        if command[:3] == ["git", "-C", str(root)]:
            args = command[3:]
            if args == ["rev-parse", "HEAD"]:
                return HEAD
            if args == ["branch", "--show-current"]:
                return values["branch"]
            if args[:2] == ["status", "--porcelain=v1"]:
                return values["status"]
            if args[:2] == ["ls-files", "-s"]:
                relative = args[-1]
                if not values["tracked"]:
                    return ""
                return f"100644 {committed_blobs[relative]} 0\t{relative}"
            if args[:1] == ["hash-object"]:
                return blob(Path(args[-1]))
            if args[:1] == ["check-attr"]:
                relative = args[-1]
                filter_value = "custom" if values["custom_filter"] else "unspecified"
                return (f"{relative}: filter: {filter_value}\n"
                        f"{relative}: ident: unspecified\n"
                        f"{relative}: working-tree-encoding: unspecified")
            if args[:1] == ["rev-parse"] and args[1].startswith("HEAD:"):
                return committed_blobs[args[1].removeprefix("HEAD:")]
            if args == ["rev-parse", "refs/tags/v1.2.3"]:
                return values["tag_object"]
            if args == ["cat-file", "-t", "refs/tags/v1.2.3"]:
                return values["tag_type"]
            if args == ["rev-parse", "refs/tags/v1.2.3^{commit}"]:
                return values["tag_commit"]
        if command[:3] == ["gh", "api", "repos/ElevenID/marty-ui/branches/main"]:
            return json.dumps({"protected": values["protected"],
                               "commit": {"sha": values["remote_head"]}})
        if command[:2] == ["git", "ls-remote"]:
            return (f"{values['published_tag_object']}\trefs/tags/v1.2.3\n"
                    f"{values['published_tag_commit']}\trefs/tags/v1.2.3^{{}}")
        if command[:3] == ["gh", "pr", "view"]:
            return json.dumps({"state": values["deletion_state"],
                               "isDraft": values["deletion_draft"],
                               "headRefOid": values["deletion_head"]})
        raise AssertionError(command)

    target = {
        "authority": "discovery_only_requires_protected_baseline",
        "observation_sha256": OBSERVATION,
        "beta": {
            "postgres_system_identifier": "12345", "database_oid": "87774",
            "services": {"postgres": {"container_id": "f" * 64}},
        },
        "production": {"sha256": "1" * 64},
    }
    target["beta"]["services"].update({
        "issuance": {"configured_image": "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "f" * 64},
        **{name: {"configured_image": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "2" * 64}
           for name in ("gateway", "flow", "issuance-native", "signing-keys")},
    })
    return approval, manifest, values, target, runner


def test_authority_plan_binds_all_four_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    plan = authority.check_authority(approval, manifest, values["baseline"], runner, lambda: target,
                                     lambda path, digests, commit: True,
                                     lambda image, commit, version: True)
    assert plan["source"]["source_commit"] == HEAD
    assert plan["deployed_beta_baseline"]["source_commit"] == "9" * 40
    assert plan["source"]["services_image"] != plan["deployed_beta_baseline"]["services_image"]
    assert plan["source"]["signed_manifest_verified"] is True
    assert plan["credentials_deletion_head"] == DELETION_HEAD
    assert plan["target_observation_sha256"] == OBSERVATION
    assert plan["postgres_container_id"] == "f" * 64
    assert plan["production_snapshot_sha256"] == "1" * 64
    assert plan["verify_sql_sha256"] == hashlib.sha256(b"verify").hexdigest()


def test_hidden_worktree_change_cannot_replace_protected_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    approval.write_text(approval.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(HostProbeError, match="content differs"):
        authority.check_authority(approval, manifest, values["baseline"], runner, lambda: target,
                                  lambda path, digests, commit: True,
                                  lambda image, commit, version: True)


def test_hidden_worktree_change_cannot_replace_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    (authority.ROOT / "scripts/sql/passport-beta-fence-verify.sql").write_text(
        "altered", encoding="utf-8"
    )
    with pytest.raises(HostProbeError, match="content differs"):
        authority.check_authority(approval, manifest, values["baseline"], runner, lambda: target,
                                  lambda path, digests, commit: True,
                                  lambda image, commit, version: True)


@pytest.mark.parametrize("field,value", [
    ("branch", "topic"), ("status", " M script.py"),
    ("protected", False), ("remote_head", "2" * 40),
    ("tracked", False), ("custom_filter", True),
    ("published_tag_object", "2" * 40),
    ("published_tag_commit", "2" * 40), ("deletion_head", "2" * 40),
    ("deletion_draft", False),
])
def test_authority_rejects_unapproved_source_or_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    values[field] = value
    with pytest.raises(HostProbeError):
        authority.check_authority(approval, manifest, values["baseline"], runner, lambda: target,
                                  lambda path, digests, commit: True,
                                  lambda image, commit, version: True)


@pytest.mark.parametrize("drift", [
    "observation", "cluster", "database", "manifest", "attestation",
    "issuance_attestation", "issuance_image", "services_image",
])
def test_authority_rejects_target_or_release_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    if drift == "observation":
        target["observation_sha256"] = "2" * 64
    elif drift == "cluster":
        target["beta"]["postgres_system_identifier"] = "98765"
    elif drift == "database":
        target["beta"]["database_oid"] = "123"
    elif drift == "manifest":
        source = json.loads(manifest.read_text(encoding="utf-8"))
        source["schema"] = "unsupported"
        manifest.write_text(json.dumps(source), encoding="utf-8")
    elif drift == "issuance_image":
        target["beta"]["services"]["issuance"]["configured_image"] = "wrong"
    elif drift == "services_image":
        target["beta"]["services"]["flow"]["configured_image"] = "wrong"
    def attest(path: Path, digests: dict[str, str], commit: str) -> bool:
        return drift != "attestation"
    with pytest.raises(HostProbeError):
        authority.check_authority(approval, manifest, values["baseline"], runner, lambda: target, attest,
                                  lambda image, commit, version: drift != "issuance_attestation")
