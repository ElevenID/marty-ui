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
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
OCI_ROLES = {
    "ghcr.io/elevenid/marty-ui-oss/ui",
    "ghcr.io/elevenid/marty-ui-oss/services",
    "ghcr.io/elevenid/marty-ui-oss/migrations",
}
PROTECTED_FILES = (
    "deploy-config/passport-beta-fence-approved-target.json",
    "scripts/check_passport_beta_fence_authority.py",
    "scripts/probe_passport_beta_fence_target.py",
    "scripts/probe_passport_beta_host.py",
    "scripts/collect_passport_beta_acceptance.py",
    "scripts/prepare_official_beta_release.py",
    "scripts/sql/passport-beta-fence-install.sql",
    "scripts/sql/passport-beta-fence-drain.sql",
    "scripts/sql/passport-beta-fence-verify.sql",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_issuance_attestation(reference: str, source_commit: str, version: str) -> bool:
    require(re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
                         version) is not None,
            "Credentials issuance version is invalid")
    try:
        subprocess.run([
            "gh", "attestation", "verify", f"oci://{reference}",
            "--repo", "ElevenID/marty-credentials",
            "--signer-workflow",
            "ElevenID/marty-credentials/.github/workflows/release-images.yml",
            "--source-digest", source_commit, "--source-ref", f"refs/tags/v{version}",
            "--deny-self-hosted-runners",
        ], check=True, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostProbeError("Credentials issuance image attestation is invalid") from exc
    return True


def manifest_source(
    path: Path, expected_commit: str,
    attest: Callable[[Path, dict[str, str], str], bool] = verify_attestations,
    attest_issuance: Callable[[str, str, str], bool] = verify_issuance_attestation,
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
        version, _, images = _validated_components(manifest, expected_commit)
    except OfficialReleaseError as exc:
        raise HostProbeError("Official stack components are invalid") from exc
    require(release == f"marty-ui@{version}", "Official release version differs")
    digests = {images[role]["uri"]: images[role]["digest"]
               for role in ("ui", "services", "migrations")}
    require(set(digests) == OCI_ROLES and len(digests) == 3,
            "Official UI OCI roles are incomplete")
    credentials = next(item for item in manifest["components"]
                       if item["name"] == "marty-credentials-issuance")
    require(credentials["repository"] == "ElevenID/marty-credentials",
            "Credentials issuer repository is invalid")
    require(attest(path, digests, expected_commit) is True,
            "Official stack manifest or OCI attestation is invalid")
    require(attest_issuance(images["issuance"]["reference"], credentials["commit"],
                            credentials["version"]) is True,
            "Credentials issuance image attestation is invalid")
    return {
        "release": release, "source_commit": expected_commit,
        "manifest_sha256": file_sha256(path), "oci_digests": digests,
        "issuance_image": images["issuance"]["reference"],
        "services_image": images["services"]["reference"],
        "issuance_source_commit": credentials["commit"],
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
            and re.fullmatch(r"[0-9]+", str(approval.get("postgres_system_identifier"))) is not None
            and re.fullmatch(r"[0-9]+", str(approval.get("database_oid"))) is not None
            and SHA.fullmatch(str(approval.get("credentials_deletion_head"))) is not None
            and SHA.fullmatch(str(approval.get("beta_baseline_source_commit"))) is not None
            and SHA256.fullmatch(str(approval.get("beta_baseline_manifest_sha256")))
                is not None,
            "Protected beta target approval fields are invalid")
    source = manifest_source(manifest_path, head, attest, attest_issuance)
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
    deletion = json.loads(runner([
        "gh", "pr", "view", "305", "--repo", "ElevenID/marty-credentials",
        "--json", "state,isDraft,headRefOid",
    ]))
    require(deletion.get("state") == "OPEN" and deletion.get("isDraft") is True
            and deletion.get("headRefOid") == approval["credentials_deletion_head"],
            "Credentials deletion PR head differs from protected approval")
    target = observer()
    require(target.get("authority") == "discovery_only_requires_protected_baseline"
            and target.get("observation_sha256") == approval["observation_sha256"],
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
            and all(isinstance(services.get(name), dict)
                    and services[name].get("configured_image") == baseline["services_image"]
                    for name in ("gateway", "flow", "issuance-native", "signing-keys")),
            "Live beta passport images differ from signed aggregate release")
    return {
        "schema": "marty.passport-beta-fence-authority-plan/v1",
        "verified": True, "source": source, "deployed_beta_baseline": baseline,
        "credentials_deletion_head": deletion["headRefOid"],
        "target_observation_sha256": target["observation_sha256"],
        "postgres_container_id": beta["services"]["postgres"]["container_id"],
        "postgres_system_identifier": beta["postgres_system_identifier"],
        "database_oid": beta["database_oid"],
        "install_sql_sha256": file_sha256(INSTALL),
        "drain_sql_sha256": file_sha256(DRAIN),
        "verify_sql_sha256": file_sha256(VERIFY),
        "production_snapshot_sha256": target["production"]["sha256"],
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
