"""A fence authority plan needs reviewed source, release, deletion and target identity."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import subprocess

import pytest

from scripts import check_passport_beta_fence_authority as authority
from scripts.probe_passport_beta_host import HostProbeError


HEAD = "a" * 40
TAG_OBJECT = "b" * 40
DELETION_HEAD = "c" * 40
OBSERVATION = "d" * 64
DIGEST = "sha256:" + "e" * 64
LEGACY_COMMIT = "85b128a85426b3f5aeaf6f948ba5dfa2836e95d8"
LEGACY_IMAGE = ("ghcr.io/elevenid/marty-credentials-issuance@sha256:"
                "9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176")


def test_deletion_lineage_requires_approved_commit_in_pr_history():
    def runner(command):
        if command[:3] == ["gh", "api", "--paginate"]:
            return "\n".join(["b" * 40, "c" * 40])
        return json.dumps({
            "status": "ahead", "behind_by": 0,
            "base_commit": {"sha": "a" * 40},
            "merge_base_commit": {"sha": "a" * 40},
        })
    with pytest.raises(HostProbeError, match="not in PR"):
        authority.require_deletion_lineage("a" * 40, "c" * 40, runner)


def test_deletion_lineage_rejects_rebase_that_drops_approval():
    def runner(command):
        if command[:3] == ["gh", "api", "--paginate"]:
            return "\n".join(["a" * 40, "c" * 40])
        return json.dumps({
            "status": "diverged", "behind_by": 1,
            "base_commit": {"sha": "a" * 40},
            "merge_base_commit": {"sha": "b" * 40},
        })
    with pytest.raises(HostProbeError, match="no longer descends"):
        authority.require_deletion_lineage("a" * 40, "c" * 40, runner)


def test_deletion_lineage_requires_final_head_in_pr_history():
    def runner(command):
        if command[:3] == ["gh", "api", "--paginate"]:
            return "\n".join(["a" * 40, "b" * 40])
        raise AssertionError("Comparison must not run for a foreign head")
    with pytest.raises(HostProbeError, match="not in PR"):
        authority.require_deletion_lineage("a" * 40, "c" * 40, runner)


def test_deletion_lineage_rejects_behind_comparison():
    def runner(command):
        if command[:3] == ["gh", "api", "--paginate"]:
            return "\n".join(["a" * 40, "c" * 40])
        return json.dumps({
            "status": "behind", "behind_by": 1,
            "base_commit": {"sha": "a" * 40},
            "merge_base_commit": {"sha": "a" * 40},
        })
    with pytest.raises(HostProbeError, match="no longer descends"):
        authority.require_deletion_lineage("a" * 40, "c" * 40, runner)


def test_credentials_release_tag_and_attestation_share_commit_and_tag_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []

    def runner(command: list[str]) -> str:
        observed.append(command)
        if command[-1] == "repos/ElevenID/marty-credentials/git/ref/tags/v0.1.72":
            return json.dumps({"object": {"type": "tag", "sha": TAG_OBJECT}})
        return json.dumps({"tag": "v0.1.72", "object": {
            "type": "commit", "sha": HEAD,
        }})

    def attest(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(authority.subprocess, "run", attest)
    assert authority.verify_issuance_attestation(
        "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "f" * 64,
        HEAD, "0.1.72", runner,
    )
    assert ["--source-ref", "refs/tags/v0.1.72"] == observed[-1][
        observed[-1].index("--source-ref"):
        observed[-1].index("--source-ref") + 2]
    assert ["--source-digest", HEAD] == observed[-1][
        observed[-1].index("--source-digest"):
        observed[-1].index("--source-digest") + 2]


def test_credentials_release_tag_must_point_to_attested_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(authority.subprocess, "run", lambda *args, **kwargs:
                        pytest.fail("Attestation must not run for a mismatched tag"))

    def runner(command: list[str]) -> str:
        if "/git/ref/tags/" in command[-1]:
            return json.dumps({"object": {"type": "tag", "sha": TAG_OBJECT}})
        return json.dumps({"tag": "v0.1.72", "object": {
            "type": "commit", "sha": "0" * 40,
        }})

    with pytest.raises(HostProbeError, match="differs from signed source"):
        authority.verify_issuance_attestation("oci", HEAD, "0.1.72", runner)


def test_credentials_attestation_accepts_historical_main_build_at_tagged_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[list[str]] = []

    def runner(command: list[str]) -> str:
        if "/git/ref/tags/" in command[-1]:
            return json.dumps({"object": {"type": "tag", "sha": TAG_OBJECT}})
        return json.dumps({"tag": "v0.1.72", "object": {
            "type": "commit", "sha": LEGACY_COMMIT,
        }})

    def attest(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        attempts.append(command)
        if command[command.index("--source-ref") + 1] != "refs/heads/main":
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(authority.subprocess, "run", attest)
    assert authority.verify_issuance_attestation(
        LEGACY_IMAGE, LEGACY_COMMIT, "0.1.72", runner)
    assert [attempt[attempt.index("--source-ref") + 1] for attempt in attempts] == [
        "refs/tags/v0.1.72", "refs/heads/main",
    ]
    assert all(attempt[attempt.index("--source-digest") + 1] == LEGACY_COMMIT
               and "--deny-self-hosted-runners" in attempt for attempt in attempts)


def test_credentials_attestation_rejects_when_neither_ref_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def runner(command: list[str]) -> str:
        if "/git/ref/tags/" in command[-1]:
            return json.dumps({"object": {"type": "tag", "sha": TAG_OBJECT}})
        return json.dumps({"tag": "v0.1.72", "object": {
            "type": "commit", "sha": LEGACY_COMMIT,
        }})

    def reject(command: list[str], **kwargs: object) -> None:
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(authority.subprocess, "run", reject)
    with pytest.raises(HostProbeError, match="attestation is invalid"):
        authority.verify_issuance_attestation(
            LEGACY_IMAGE, LEGACY_COMMIT, "0.1.72", runner)


def test_credentials_attestation_does_not_fallback_for_other_images(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[list[str]] = []

    def runner(command: list[str]) -> str:
        if "/git/ref/tags/" in command[-1]:
            return json.dumps({"object": {"type": "tag", "sha": TAG_OBJECT}})
        return json.dumps({"tag": "v0.1.72", "object": {
            "type": "commit", "sha": LEGACY_COMMIT,
        }})

    def reject(command: list[str], **kwargs: object) -> None:
        attempts.append(command)
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(authority.subprocess, "run", reject)
    with pytest.raises(HostProbeError, match="attestation is invalid"):
        authority.verify_issuance_attestation(
            "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "f" * 64,
            LEGACY_COMMIT, "0.1.72", runner)
    assert len(attempts) == 1
    assert attempts[0][attempts[0].index("--source-ref") + 1] == "refs/tags/v0.1.72"


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
        "production_attachments_sha256": "6" * 64,
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
    premigrated = root / "docker-compose.profile.passport-premigrated-beta.yml"
    premigrated.write_text(
        'services:\n  flow:\n    environment:\n      MARTY_SCHEMA_STARTUP_MODE: validate\n'
        '  issuance-native:\n    environment:\n      MARTY_SCHEMA_STARTUP_MODE: validate\n',
        encoding="utf-8",
    )
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
    monkeypatch.setattr(authority, "PREMIGRATED", premigrated)
    values = {
        "branch": "main", "status": "", "protected": True, "remote_head": HEAD,
        "tracked": True, "custom_filter": False,
        "tag_object": TAG_OBJECT, "tag_type": "tag", "tag_commit": HEAD,
        "published_tag_object": TAG_OBJECT, "published_tag_commit": HEAD,
        "deletion_state": "OPEN", "deletion_draft": True,
        "deletion_head": DELETION_HEAD,
        "deletion_history": [DELETION_HEAD], "deletion_base": "main",
        "deletion_repo": authority.DELETION_REPOSITORY,
        "deletion_merge_base": DELETION_HEAD,
        "baseline": baseline,
        "release_files": {
            relative: "\n".join(markers)
            for relative, markers in authority.RELEASE_SCHEMA_VALIDATION_MARKERS.items()
        },
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
            if args[:1] == ["show"] and args[1].startswith(HEAD + ":"):
                return values["release_files"][args[1].split(":", 1)[1]]
        if command[:3] == ["gh", "api", "repos/ElevenID/marty-ui/branches/main"]:
            return json.dumps({"protected": values["protected"],
                               "commit": {"sha": values["remote_head"]}})
        if command[:2] == ["git", "ls-remote"]:
            return (f"{values['published_tag_object']}\trefs/tags/v1.2.3\n"
                    f"{values['published_tag_commit']}\trefs/tags/v1.2.3^{{}}")
        if command[:3] == ["gh", "api", "repos/ElevenID/marty-credentials/pulls/305"]:
            return json.dumps({
                "number": 305, "state": values["deletion_state"].lower(),
                "draft": values["deletion_draft"],
                "base": {"ref": values["deletion_base"], "repo": {
                    "full_name": values["deletion_repo"]}},
                "head": {"sha": values["deletion_head"], "repo": {
                    "full_name": values["deletion_repo"]}},
            })
        if command[:3] == ["gh", "api", "--paginate"]:
            return "\n".join(values["deletion_history"])
        if command[:2] == ["gh", "api"] and "/compare/" in command[2]:
            approved, current = command[2].rsplit("/", 1)[-1].split("...")
            return json.dumps({
                "status": "identical" if approved == current else "ahead",
                "behind_by": 0,
                "base_commit": {"sha": approved},
                "merge_base_commit": {"sha": values["deletion_merge_base"]},
            })
        raise AssertionError(command)

    target = {
        "authority": "discovery_only_requires_protected_baseline",
        "observation_sha256": OBSERVATION,
        "production_attachments_sha256": "6" * 64,
        "docker": {"context": "test", "daemon_id": "daemon"},
        "beta": {
            "postgres_system_identifier": "12345", "database_oid": "87774",
            "ui_service": {"configured_image":
                           "ghcr.io/elevenid/marty-ui-oss/ui@sha256:" + "3" * 64},
            "database_route": {"name": "elevenid-beta-network", "id": "a" * 64,
                               "postgres_container_id": "f" * 64},
            "postgres_runtime": {"image_id": "sha256:" + "f" * 64,
                                 "server_version_num": "150017"},
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
    assert plan["source"]["build_only_artifacts"]["MARTY_COMMON_URI"] == (
        "https://example.test/artifact.whl")
    assert plan["source"]["build_only_artifacts"]["MARTY_RS_DIGEST"] == DIGEST
    assert plan["credentials_deletion_head"] == DELETION_HEAD
    assert plan["target_observation_sha256"] == OBSERVATION
    assert plan["postgres_container_id"] == "f" * 64
    assert plan["database_route"]["postgres_container_id"] == plan["postgres_container_id"]
    assert plan["docker"] == {"context": "test", "daemon_id": "daemon"}
    assert plan["postgres_runtime"]["server_version_num"] == "150017"
    assert plan["production_snapshot_sha256"] == "1" * 64
    assert plan["verify_sql_sha256"] == hashlib.sha256(b"verify").hexdigest()


def test_authority_keeps_approved_head_after_qualification_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    values["deletion_head"] = "2" * 40
    values["deletion_history"].append(values["deletion_head"])
    plan = authority.check_authority(
        approval, manifest, values["baseline"], runner, lambda: target,
        lambda *_: True, lambda *_: True,
    )
    assert plan["credentials_deletion_head"] == DELETION_HEAD


@pytest.mark.parametrize("field,value", [
    ("deletion_merge_base", "2" * 40),
    ("deletion_base", "other"),
    ("deletion_repo", "someone/marty-credentials"),
])
def test_authority_rejects_diverged_or_wrong_pull(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: str,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    values[field] = value
    with pytest.raises(HostProbeError):
        authority.check_authority(approval, manifest, values["baseline"], runner,
                                  lambda: target, lambda *_: True, lambda *_: True)


def test_authority_requires_signed_shared_validation_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    values["release_files"]["rust/services/issuance/src/main.rs"] = "migration::migrate(&pool).await"
    with pytest.raises(HostProbeError, match="DDL-free schema validation"):
        authority.check_authority(approval, manifest, values["baseline"], runner,
                                  lambda: target, lambda *_: True, lambda *_: True)


def test_authority_requires_exact_two_service_premigrated_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    authority.PREMIGRATED.write_text(
        'services:\n  flow:\n    environment:\n      MARTY_SCHEMA_STARTUP_MODE: validate\n'
        '  issuance-native:\n    environment:\n      MARTY_SCHEMA_STARTUP_MODE: migrate\n',
        encoding="utf-8",
    )
    with pytest.raises(HostProbeError, match="content differs"):
        authority.check_authority(approval, manifest, values["baseline"], runner,
                                  lambda: target, lambda *_: True, lambda *_: True)
    with pytest.raises(HostProbeError, match="does not use DDL-free startup"):
        authority.require_premigrated_compose_validation(
            authority.PREMIGRATED.read_text(encoding="utf-8"))


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
    "observation", "attachments", "cluster", "database", "manifest", "attestation",
    "issuance_attestation", "issuance_image", "services_image", "ui_image",
])
def test_authority_rejects_target_or_release_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str,
) -> None:
    approval, manifest, values, target, runner = fixture(tmp_path, monkeypatch)
    if drift == "observation":
        target["observation_sha256"] = "2" * 64
    elif drift == "attachments":
        target["production_attachments_sha256"] = "2" * 64
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
    elif drift == "ui_image":
        target["beta"]["ui_service"]["configured_image"] = "wrong"
    def attest(path: Path, digests: dict[str, str], commit: str) -> bool:
        return drift != "attestation"
    with pytest.raises(HostProbeError):
        authority.check_authority(approval, manifest, values["baseline"], runner, lambda: target, attest,
                                  lambda image, commit, version: drift != "issuance_attestation")
