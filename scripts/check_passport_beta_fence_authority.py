#!/usr/bin/env python3
"""Read-only protected-source gate for a future locked beta fence installer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable
import yaml
from yaml.nodes import MappingNode, ScalarNode

try:
    from .collect_passport_beta_acceptance import verify_attestations
    from .probe_passport_beta_fence_target import observe
    from .probe_passport_beta_host import HostProbeError, run
    from .prepare_official_beta_release import OfficialReleaseError, _validated_components
except ImportError:
    from collect_passport_beta_acceptance import verify_attestations
    from probe_passport_beta_fence_target import observe
    from probe_passport_beta_host import HostProbeError, run
    from prepare_official_beta_release import OfficialReleaseError, _validated_components


ROOT = Path(__file__).resolve().parents[1]
APPROVAL = ROOT / "deploy-config/passport-beta-fence-approved-target.json"
INSTALL = ROOT / "scripts/sql/passport-beta-fence-install.sql"
DRAIN = ROOT / "scripts/sql/passport-beta-fence-drain.sql"
VERIFY = ROOT / "scripts/sql/passport-beta-fence-verify.sql"
PREMIGRATED = ROOT / "docker-compose.profile.passport-premigrated-beta.yml"
DELETION_REPOSITORY = "ElevenID/marty-credentials"
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
OCI_ROLES = {
    "ghcr.io/elevenid/marty-ui-oss/ui",
    "ghcr.io/elevenid/marty-ui-oss/services",
    "ghcr.io/elevenid/marty-ui-oss/migrations",
}
PROTECTED_FILES = (
    ".gitattributes",
    "deploy-config/passport-beta-fence-approved-target.json",
    "scripts/check_passport_beta_fence_authority.py",
    "scripts/prepare_passport_beta_fence_approval.py",
    "scripts/beta-deployment-lock.ps1",
    "scripts/beta-passport-fence-legacy-boundary.ps1",
    "scripts/beta-passport-fence-recovery-intent.ps1",
    "scripts/beta-passport-migration-lease.ps1",
    "scripts/install-passport-beta-fence.ps1",
    "scripts/check_passport_beta_fence_recovery_authority.py",
    "scripts/probe_passport_beta_fence_target.py",
    "scripts/probe_passport_beta_fence_direct_writes.py",
    "scripts/probe_passport_beta_host.py",
    "scripts/collect_passport_beta_acceptance.py",
    "scripts/collect_passport_beta_aggregate_acceptance.py",
    "scripts/prepare_official_beta_release.py",
    "scripts/sql/passport-beta-fence-install.sql",
    "scripts/sql/passport-beta-fence-drain.sql",
    "scripts/sql/passport-beta-fence-verify.sql",
    "scripts/sql/passport-beta-batch-acl-finalize.sql",
    "scripts/sql/passport-beta-db-maintenance-start.sql",
    "scripts/sql/passport-beta-db-enable-app-login.sql",
    "scripts/sql/passport-beta-rust-owner-transition.sql",
    "scripts/sql/passport-beta-rust-owner-verify.sql",
    "scripts/prepare_passport_beta_native_migrations.py",
    "scripts/prepare_passport_beta_db_maintenance.py",
    "scripts/start-passport-beta-db-maintenance.ps1",
    "scripts/run-passport-beta-native-db-gates.ps1",
    "scripts/prepare_passport_beta_aggregate_handoff.py",
    "scripts/prepare_passport_beta_aggregate_compose.py",
    "scripts/verify_passport_beta_aggregate_runtime.py",
    "scripts/verify_passport_beta_rust_owner.py",
    "scripts/probe_passport_beta_rust_owner_write.py",
    "scripts/probe_passport_beta_rust_owner_flow.py",
    "scripts/probe_passport_beta_aggregate_kms.py",
    "scripts/probe_passport_beta_aggregate_ceremony.py",
    "scripts/probe_passport_beta_reference_provision.py",
    "scripts/passport_beta_reference_intents.py",
    "scripts/passport_supported_flow_references.py",
    "scripts/passport_supported_flow_start.py",
    "scripts/probe_passport_beta_chain.py",
    "scripts/verify_passport_beta_issuer_profiles.py",
    "scripts/probe_passport_beta_credentials_continuity.py",
    "scripts/run-passport-beta-aggregate-deploy.ps1",
    "rust/services/issuance/src/dependency_probe.rs",
    "rust/services/issuance/src/grpc_client_channel.rs",
    "rust/services/issuance/src/migration_seed.rs",
    "rust/services/issuance/migrations/0000_issuance_service_baseline.sql",
    "rust/services/issuance/migrations/0000_issuance_service_catalog.json",
    "rust/services/issuance/migrations/0000_merge_issuance_heads_bridge.sql",
    "scripts/probe_passport_beta_cutover_snapshot.py",
    "scripts/verify_passport_beta_protected_cutover.py",
    "scripts/collect_passport_python_deletion_cutover.py",
    ".github/workflows/passport-python-deletion-cutover.yml",
    "scripts/collect_passport_beta_rust_readiness.py",
    "scripts/verify_passport_beta_rust_readiness.py",
    ".github/workflows/passport-beta-rust-readiness.yml",
    "docker-compose.base.yml",
    "docker-compose.beta.yml",
    "docker-compose.profile.dev.yml",
    "docker-compose.profile.tunnel.yml",
    "docker-compose.profile.waltid.yml",
    "docker-compose.profile.canvas-real.yml",
    "docker-compose.profile.canvas-sandbox.yml",
    "docker-compose.profile.passport-native-beta.yml",
    "docker-compose.profile.passport-premigrated-beta.yml",
    "docker-compose.ui-release.yml",
    "services/Dockerfile.migrations",
    "rust/services/issuance/migrations/0001_oid4vci_public_protocol.sql",
    "rust/services/issuance/migrations/0002_physical_document_jobs.sql",
    "rust/services/issuance/migrations/0003_passport_bureau_provider_binding.sql",
    "rust/services/issuance/migrations/0004_passport_submission_intent.sql",
    "rust/services/issuance/migrations/0005_passport_submission_provenance.sql",
    "rust/services/issuance/migrations/0006_passport_beta_batch_identity.sql",
    "rust/services/issuance/migrations/0007_passport_beta_batch_provenance.sql",
    "rust/services/issuance/migrations/0008_passport_beta_batch_wire_evidence.sql",
    "rust/services/flow/migrations/0001_flow_schema.sql",
    "rust/services/flow/migrations/0002_builtin_flows.sql",
)
RELEASE_SCHEMA_VALIDATION_MARKERS = {
    "rust/crates/schema-startup/src/lib.rs": (
        'std::env::var("MARTY_SCHEMA_STARTUP_MODE")',
        'Some("validate") => Ok(Self::Validate)',
    ),
    "rust/services/flow/src/connections.rs": (
        "SchemaStartupMode::from_env()",
        "SchemaStartupMode::Validate => crate::validate_flow_schema(&pool).await?",
    ),
    "rust/services/flow/src/migration.rs": (
        "SET TRANSACTION READ ONLY", "pub async fn validate_flow_schema",
    ),
    "rust/services/issuance/src/main.rs": (
        "SchemaStartupMode::from_env()",
        "SchemaStartupMode::Validate => migration::validate(&pool).await",
        "SchemaStartupMode::Validate => migration::validate_passport(&pool).await",
    ),
    "rust/services/issuance/src/migration.rs": (
        "SET TRANSACTION READ ONLY", "pub async fn validate_passport",
    ),
    "scripts/prepare_passport_beta_aggregate_compose.py": (
        '"docker-compose.profile.passport-premigrated-beta.yml"',
        '"MARTY_SCHEMA_STARTUP_MODE": "validate"',
    ),
    "scripts/run-passport-beta-aggregate-deploy.ps1": (
        "docker-compose.profile.passport-premigrated-beta.yml",
    ),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_issuance_attestation(
    reference: str, source_commit: str, version: str,
    runner: Callable[[list[str]], str] = run,
) -> bool:
    require(re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
                         version) is not None,
            "Credentials issuance version is invalid")
    require(SHA.fullmatch(source_commit) is not None,
            "Credentials issuance source commit is invalid")
    try:
        tag_ref = json.loads(runner([
            "gh", "api", f"repos/ElevenID/marty-credentials/git/ref/tags/v{version}",
        ]))
        tag_object = tag_ref.get("object") if isinstance(tag_ref, dict) else None
        require(isinstance(tag_object, dict) and tag_object.get("type") == "tag"
                and SHA.fullmatch(str(tag_object.get("sha"))) is not None,
                "Credentials issuance release tag is not annotated")
        tag = json.loads(runner([
            "gh", "api", "repos/ElevenID/marty-credentials/git/tags/"
            + tag_object["sha"],
        ]))
    except (ValueError, OSError) as exc:
        raise HostProbeError("Credentials issuance release tag is unavailable") from exc
    target = tag.get("object") if isinstance(tag, dict) else None
    require(isinstance(tag, dict) and tag.get("tag") == f"v{version}"
            and isinstance(target, dict) and target.get("type") == "commit"
            and target.get("sha") == source_commit,
            "Credentials issuance release tag differs from signed source")
    # The deployed v1.1.217 baseline contains a Credentials image built on
    # main before v0.1.72 was tagged. Its annotated tag still names this exact
    # commit; no later release may substitute a main-branch attestation.
    legacy_main_build = (
        version == "0.1.72"
        and source_commit == "85b128a85426b3f5aeaf6f948ba5dfa2836e95d8"
        and reference == "ghcr.io/elevenid/marty-credentials-issuance@sha256:"
        "9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176"
    )
    source_refs = (f"refs/tags/v{version}", "refs/heads/main") if legacy_main_build else (
        f"refs/tags/v{version}",
    )
    for source_ref in source_refs:
        try:
            subprocess.run([
                "gh", "attestation", "verify", f"oci://{reference}",
                "--repo", "ElevenID/marty-credentials",
                "--signer-workflow",
                "ElevenID/marty-credentials/.github/workflows/release-images.yml",
                "--source-digest", source_commit, "--source-ref", source_ref,
                "--deny-self-hosted-runners",
            ], check=True, capture_output=True, text=True, timeout=120)
            break
        except (OSError, subprocess.SubprocessError):
            continue
    else:
        raise HostProbeError("Credentials issuance image attestation is invalid")
    return True


def manifest_source(
    path: Path, expected_commit: str,
    attest: Callable[[Path, dict[str, str], str], bool] = verify_attestations,
    attest_issuance: Callable[[str, str, str], bool] = verify_issuance_attestation,
    *, rust_only: bool = False,
) -> dict[str, Any]:
    require(path.name == "stack-manifest.json"
            and (path.parent / "SHA256SUMS").is_file(),
            "Official stack release files are incomplete")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HostProbeError("Official stack manifest is unreadable") from exc
    require(isinstance(manifest, dict), "Official stack manifest is invalid")
    require(manifest.get("schema") == "marty.stack/v1",
            "Official stack manifest schema is invalid")
    release = manifest.get("release")
    require(isinstance(release, str) and re.fullmatch(r"marty-ui@[0-9]+\.[0-9]+\.[0-9]+", release) is not None,
            "Official stack release coordinate is invalid")
    try:
        version, _, images = _validated_components(
            manifest, expected_commit, rust_only=rust_only)
    except OfficialReleaseError as exc:
        raise HostProbeError("Official stack components are invalid") from exc
    require(release == f"marty-ui@{version}", "Official release version differs")
    digests = {images[role]["uri"]: images[role]["digest"]
               for role in ("ui", "services", "migrations")}
    require(set(digests) == OCI_ROLES and len(digests) == 3,
            "Official UI OCI roles are incomplete")
    credentials = None if rust_only else next(
        item for item in manifest["components"]
        if item["name"] == "marty-credentials-issuance")
    if credentials is not None:
        require(credentials["repository"] == "ElevenID/marty-credentials",
                "Credentials issuer repository is invalid")
    require(attest(path, digests, expected_commit) is True,
            "Official stack manifest or OCI attestation is invalid")
    if credentials is not None:
        require(attest_issuance(images["issuance"]["reference"], credentials["commit"],
                                credentials["version"]) is True,
                "Credentials issuance image attestation is invalid")
    build_only = {}
    for variable, component_name in (
        ("MARTY_COMMON", "marty-common"),
        ("MARTY_RS", "marty-core-python"),
        ("MARTY_VERIFICATION", "marty-verification-python"),
        ("MARTY_ISO18013", "marty-iso18013-python"),
    ):
        matches = [item for item in manifest["components"]
                   if item.get("name") == component_name]
        require(len(matches) == 1,
                "Signed beta build-only component is ambiguous")
        artifacts = [item for item in matches[0].get("artifacts", [])
                     if isinstance(item, dict) and item.get("type") == "python"]
        require(len(artifacts) == 1
                and isinstance(artifacts[0].get("uri"), str)
                and artifacts[0]["uri"].startswith("https://")
                and re.fullmatch(r"sha256:[0-9a-f]{64}",
                                 str(artifacts[0].get("digest"))) is not None,
                "Signed beta build-only wheel is invalid")
        build_only[variable + "_URI"] = artifacts[0]["uri"]
        build_only[variable + "_DIGEST"] = artifacts[0]["digest"]
    return {
        "release": release, "source_commit": expected_commit,
        "manifest_sha256": file_sha256(path), "oci_digests": digests,
        "issuance_image": images["services" if rust_only else "issuance"]["reference"],
        "ui_image": images["ui"]["reference"],
        "services_image": images["services"]["reference"],
        "build_only_artifacts": build_only,
        "issuance_source_commit": expected_commit if rust_only else credentials["commit"],
        "signed_manifest_verified": True,
    }


def protected_source(
    runner: Callable[[list[str]], str] = run,
) -> str:
    head = runner(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    require(SHA.fullmatch(head) is not None, "Local Marty UI commit is invalid")
    require(runner(["git", "-C", str(ROOT), "branch", "--show-current"]) == "main",
            "Fence operation requires protected main")
    require(not runner(["git", "-C", str(ROOT), "status", "--porcelain=v1",
                        "--untracked-files=normal"]),
            "Fence operation requires a clean protected source")
    branch = json.loads(runner(["gh", "api", "repos/ElevenID/marty-ui/branches/main"]))
    require(branch.get("protected") is True
            and isinstance(branch.get("commit"), dict)
            and branch["commit"].get("sha") == head,
            "Local source differs from protected remote main")
    return head


def protected_file(relative: str, runner: Callable[[list[str]], str]) -> None:
    """Check real bytes as well as Git status, which index flags can suppress."""
    path = ROOT / relative
    require(path.is_file() and not path.is_symlink()
            and path.resolve().is_relative_to(ROOT.resolve()),
            f"Protected file is absent or redirected: {relative}")
    entry = runner(["git", "-C", str(ROOT), "ls-files", "-s", "--", relative])
    require(re.fullmatch(r"100644 [0-9a-f]{40} 0\t" + re.escape(relative), entry)
            is not None, f"Protected file is not a regular tracked blob: {relative}")
    expected_blob = entry.split(" ", 2)[1]
    head_blob = runner(["git", "-C", str(ROOT), "rev-parse", f"HEAD:{relative}"])
    attributes = runner(["git", "-C", str(ROOT), "check-attr", "filter", "ident",
                         "working-tree-encoding", "--", relative])
    require(set(attributes.splitlines()) == {
        f"{relative}: filter: unspecified",
        f"{relative}: ident: unspecified",
        f"{relative}: working-tree-encoding: unspecified",
    }, f"Protected file has unsupported Git filters: {relative}")
    actual_blob = runner(["git", "-C", str(ROOT), "hash-object",
                          f"--path={relative}", str(path)])
    require(actual_blob == expected_blob == head_blob,
            f"Protected file content differs from remote main: {relative}")


def require_release_schema_validation_capability(
    source_commit: str, runner: Callable[[list[str]], str],
) -> None:
    """Bind the signed Rust image source to shared DDL-free startup paths."""
    for relative, markers in RELEASE_SCHEMA_VALIDATION_MARKERS.items():
        try:
            contents = runner(["git", "-C", str(ROOT), "show",
                               f"{source_commit}:{relative}"])
        except HostProbeError as exc:
            raise HostProbeError("Signed Rust release lacks schema validation source") from exc
        require(all(marker in contents for marker in markers),
                "Signed Rust release lacks DDL-free schema validation")


def require_premigrated_compose_validation(contents: str) -> None:
    """Require the protected post-migration overlay to select both Rust services."""
    try:
        root = yaml.compose(contents)
    except yaml.YAMLError as exc:
        raise HostProbeError("Signed premigrated beta Compose is invalid") from exc

    def one_value(node: MappingNode | None, name: str) -> Any:
        require(isinstance(node, MappingNode),
                "Signed premigrated beta Compose has invalid service structure")
        matches = [value for key, value in node.value
                   if isinstance(key, ScalarNode) and key.value == name]
        require(len(matches) == 1,
                f"Signed premigrated beta Compose has ambiguous {name}")
        return matches[0]

    services = one_value(root, "services")
    require(isinstance(services, MappingNode)
            and {key.value for key, _ in services.value
                 if isinstance(key, ScalarNode)} == {"flow", "issuance-native"},
            "Signed premigrated beta Compose selects unexpected services")
    for service in ("flow", "issuance-native"):
        entry = one_value(services, service)
        environment = one_value(entry, "environment")
        selector = one_value(environment, "MARTY_SCHEMA_STARTUP_MODE")
        require(isinstance(selector, ScalarNode)
                and selector.tag == "tag:yaml.org,2002:str"
                and selector.value == "validate",
                f"Signed premigrated beta {service} does not use DDL-free startup")


def require_deletion_lineage(
    approved_head: str, current_head: str,
    runner: Callable[[list[str]], str] = run,
) -> None:
    """Bind the approved PR commit to a later head without allowing a rebase."""
    require(SHA.fullmatch(approved_head) is not None
            and SHA.fullmatch(current_head) is not None,
            "Credentials deletion head is invalid")
    commits = runner([
        "gh", "api", "--paginate",
        f"repos/{DELETION_REPOSITORY}/pulls/305/commits?per_page=100",
        "--jq", ".[].sha",
    ]).splitlines()
    require(bool(commits) and all(SHA.fullmatch(commit) for commit in commits)
            and approved_head in commits and current_head in commits,
            "Approved credentials deletion head is not in PR #305")
    comparison = json.loads(runner([
        "gh", "api", f"repos/{DELETION_REPOSITORY}/compare/"
        f"{approved_head}...{current_head}",
    ]))
    base = comparison.get("base_commit") if isinstance(comparison, dict) else None
    merge_base = comparison.get("merge_base_commit") if isinstance(comparison, dict) else None
    require(isinstance(comparison, dict)
            and comparison.get("status") in ("identical", "ahead")
            and type(comparison.get("behind_by")) is int
            and comparison["behind_by"] == 0
            and isinstance(base, dict) and base.get("sha") == approved_head
            and isinstance(merge_base, dict)
            and merge_base.get("sha") == approved_head,
            "Credentials deletion PR no longer descends from approved head")


def merged_deletion_pr(
    runner: Callable[[list[str]], str] = run,
) -> tuple[str, str]:
    """Require the deleted source to be merged into protected Credentials main."""
    pull = json.loads(runner([
        "gh", "api", f"repos/{DELETION_REPOSITORY}/pulls/305",
    ]))
    base = pull.get("base") if isinstance(pull, dict) else None
    head = pull.get("head") if isinstance(pull, dict) else None
    merge_commit = pull.get("merge_commit_sha") if isinstance(pull, dict) else None
    require(isinstance(pull, dict) and pull.get("number") == 305
            and pull.get("state") == "closed" and pull.get("merged") is True
            and isinstance(pull.get("merged_at"), str)
            and SHA.fullmatch(str(merge_commit)) is not None
            and isinstance(base, dict) and base.get("ref") == "main"
            and isinstance(base.get("repo"), dict)
            and base["repo"].get("full_name") == DELETION_REPOSITORY
            and isinstance(head, dict) and SHA.fullmatch(str(head.get("sha"))) is not None
            and isinstance(head.get("repo"), dict)
            and head["repo"].get("full_name") == DELETION_REPOSITORY,
            "Credentials passport deletion is not a merged same-repository PR")
    branch = json.loads(runner([
        "gh", "api", f"repos/{DELETION_REPOSITORY}/branches/main",
    ]))
    main_commit = branch.get("commit") if isinstance(branch, dict) else None
    require(isinstance(branch, dict) and branch.get("protected") is True
            and isinstance(main_commit, dict)
            and SHA.fullmatch(str(main_commit.get("sha"))) is not None,
            "Protected Credentials main is unavailable")
    comparison = json.loads(runner([
        "gh", "api", f"repos/{DELETION_REPOSITORY}/compare/"
        f"{merge_commit}...{main_commit['sha']}",
    ]))
    require(isinstance(comparison, dict)
            and comparison.get("status") in ("identical", "ahead")
            and comparison.get("behind_by") == 0
            and isinstance(comparison.get("merge_base_commit"), dict)
            and comparison["merge_base_commit"].get("sha") == merge_commit,
            "Credentials passport deletion merge is not on protected main")
    return head["sha"], merge_commit


def require_predeletion_signed_image(
    merge_commit: str, image_source_commit: str,
    runner: Callable[[list[str]], str] = run,
) -> None:
    """Keep passport routes available until the beta Rust owner is live."""
    require(SHA.fullmatch(merge_commit) is not None
            and SHA.fullmatch(str(image_source_commit)) is not None,
            "Signed Credentials source is invalid")
    require(image_source_commit != merge_commit,
            "Signed Credentials image must predate passport Python deletion")
    comparison = json.loads(runner([
        "gh", "api", f"repos/{DELETION_REPOSITORY}/compare/"
        f"{image_source_commit}...{merge_commit}",
    ]))
    require(isinstance(comparison, dict)
            and comparison.get("status") == "ahead"
            and type(comparison.get("ahead_by")) is int
            and comparison["ahead_by"] > 0
            and comparison.get("behind_by") == 0
            and isinstance(comparison.get("merge_base_commit"), dict)
            and comparison["merge_base_commit"].get("sha") == image_source_commit,
            "Signed Credentials image must be the predeletion ancestor")


def check_authority(
    approval_path: Path, manifest_path: Path, beta_baseline_manifest_path: Path,
    runner: Callable[[list[str]], str] = run,
    observer: Callable[[], dict[str, Any]] = observe,
    attest: Callable[[Path, dict[str, str], str], bool] = verify_attestations,
    attest_issuance: Callable[[str, str, str], bool] = verify_issuance_attestation,
) -> dict[str, Any]:
    """All checks are read-only; a later operator must rerun under the beta lock."""
    resolved = approval_path.resolve()
    require(resolved == APPROVAL.resolve(),
            "Fence approval must be the reviewed protected-source path")
    head = protected_source(runner)
    for relative in PROTECTED_FILES:
        protected_file(relative, runner)
    try:
        approval = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HostProbeError("Protected beta target approval is unavailable") from exc
    require(isinstance(approval, dict)
            and approval.get("schema") == "marty.passport-beta-fence-approved-target/v1",
            "Protected beta target approval is invalid")
    require(SHA256.fullmatch(str(approval.get("observation_sha256"))) is not None
            and SHA256.fullmatch(str(approval.get("production_attachments_sha256")))
                is not None
            and re.fullmatch(r"[0-9]+", str(approval.get("postgres_system_identifier"))) is not None
            and re.fullmatch(r"[0-9]+", str(approval.get("database_oid"))) is not None
            and SHA.fullmatch(str(approval.get("credentials_deletion_head"))) is not None
            and SHA.fullmatch(str(approval.get("beta_baseline_source_commit"))) is not None
            and SHA256.fullmatch(str(approval.get("beta_baseline_manifest_sha256")))
                is not None,
            "Protected beta target approval fields are invalid")
    source = manifest_source(manifest_path, head, attest, attest_issuance,
                             rust_only=True)
    require_release_schema_validation_capability(source["source_commit"], runner)
    require_premigrated_compose_validation(PREMIGRATED.read_text(encoding="utf-8"))
    require(file_sha256(beta_baseline_manifest_path)
            == approval["beta_baseline_manifest_sha256"],
            "Deployed beta baseline manifest differs from protected approval")
    baseline = manifest_source(beta_baseline_manifest_path,
                               approval["beta_baseline_source_commit"], attest,
                               attest_issuance)
    version = source["release"].split("@", 1)[1]
    tag = f"v{version}"
    local_tag_object = runner(["git", "-C", str(ROOT), "rev-parse", f"refs/tags/{tag}"])
    require(SHA.fullmatch(local_tag_object) is not None
            and runner(["git", "-C", str(ROOT), "cat-file", "-t", f"refs/tags/{tag}"]) == "tag"
            and runner(["git", "-C", str(ROOT), "rev-parse",
                        f"refs/tags/{tag}^{{commit}}"] ) == head,
            "Official local annotated release tag is absent or changed")
    remote_tags = runner(["git", "ls-remote", "https://github.com/ElevenID/marty-ui.git",
                          f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"])
    require(set(remote_tags.splitlines()) == {
        f"{local_tag_object}\trefs/tags/{tag}",
        f"{head}\trefs/tags/{tag}^{{}}",
    }, "Published annotated release tag differs from protected source")
    deletion_head, deletion_merge_commit = merged_deletion_pr(runner)
    require_predeletion_signed_image(
        deletion_merge_commit, baseline["issuance_source_commit"], runner)
    require_deletion_lineage(approval["credentials_deletion_head"],
                             deletion_head, runner)
    target = observer()
    require(target.get("authority") == "discovery_only_requires_protected_baseline"
            and target.get("observation_sha256") == approval["observation_sha256"]
            and target.get("production_attachments_sha256")
                == approval["production_attachments_sha256"],
            "Fresh beta/production target differs from protected approval")
    beta = target.get("beta")
    require(isinstance(beta, dict)
            and beta.get("postgres_system_identifier")
                == approval["postgres_system_identifier"]
            and beta.get("database_oid") == approval["database_oid"],
            "PostgreSQL cluster or database identity differs from protected approval")
    services = beta.get("services")
    require(isinstance(services, dict)
            and isinstance(services.get("issuance"), dict)
            and services["issuance"].get("configured_image") == baseline["issuance_image"]
            and isinstance(beta.get("ui_service"), dict)
            and beta["ui_service"].get("configured_image") == baseline["ui_image"]
            and all(isinstance(services.get(name), dict)
                    and services[name].get("configured_image") == baseline["services_image"]
                    for name in ("gateway", "flow", "issuance-native", "signing-keys")),
            "Live beta passport images differ from signed aggregate release")
    return {
        "schema": "marty.passport-beta-fence-authority-plan/v1",
        "verified": True, "source": source, "deployed_beta_baseline": baseline,
        # The v1 field is the approved historical PR head, not its final head.
        "credentials_deletion_head": approval["credentials_deletion_head"],
        "target_observation_sha256": target["observation_sha256"],
        "beta_services": services,
        "postgres_container_id": beta["services"]["postgres"]["container_id"],
        "docker": target["docker"],
        "database_route": beta["database_route"],
        "postgres_runtime": beta["postgres_runtime"],
        "postgres_system_identifier": beta["postgres_system_identifier"],
        "database_oid": beta["database_oid"],
        "install_sql_sha256": file_sha256(INSTALL),
        "drain_sql_sha256": file_sha256(DRAIN),
        "verify_sql_sha256": file_sha256(VERIFY),
        "production_snapshot_sha256": target["production"]["sha256"],
        "production_attachments_sha256": target["production_attachments_sha256"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved-target", type=Path, required=True)
    parser.add_argument("--stack-manifest", type=Path, required=True)
    parser.add_argument("--beta-baseline-manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(check_authority(args.approved_target, args.stack_manifest,
                                         args.beta_baseline_manifest),
                         sort_keys=True, separators=(",", ":")))
    except (HostProbeError, OSError, ValueError, KeyError) as exc:
        raise SystemExit(f"Beta fence authority is not established: {exc}") from exc
