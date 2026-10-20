#!/usr/bin/env python3
"""Audit both live and rollback KMS generations before bootstrap-root retirement.

It logs into scoped roles and signs fixed canary bytes, but never revokes a token
or changes deployment configuration. Passing it does not replace a coordinated
backup/restore or business journey.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.error import HTTPError
import zipfile

sys.dont_write_bytecode = True
from activate_selfhost_renewed_secrets import (  # noqa: E402
    PROJECT, checked_certificates, checked_compose_secret_files, checked_env,
    checked_overlap_mounts,
    checked_tokens, compose_args,
    healthy, owned_service_closure, require_rootless_migration, run_json,
    secret_mounts, statuses,
)
from provision_selfhost_renewal_identity import checked_login as renewal_login  # noqa: E402
from provision_selfhost_ca_rotation_identity import checked_login as ca_rotation_login  # noqa: E402
from provision_selfhost_evidence_identity import checked_login as evidence_login  # noqa: E402
from provision_selfhost_audit_identity import checked_login as audit_login  # noqa: E402
from provision_selfhost_audit_token import policy_for as audit_policy_for  # noqa: E402
from provision_selfhost_snapshot_identity import (  # noqa: E402
    checked_login as snapshot_login, snapshot_origin,
)
from provision_selfhost_snapshot_rotator import checked_login as rotator_login  # noqa: E402
from selfhost_openbao_client import (  # noqa: E402
    Bao, require_ca_rotation_authority, require_renewal_authority,
)
from stage_selfhost_renewed_secrets import bounded_file, verify_generations  # noqa: E402


STATIC_KMS_TOKENS = {
    "openbao_service_token": {"credential-service", "default"},
    "signing_keys_openbao_token": {"credential-service", "signing-keys-managed"},
    "didcomm_issuance_openbao_token": {"didcomm-issuance"},
    "notification_openbao_token": {"notification-webhook-service", "default"},
    "haip_kms_token": {"haip-response-service"},
    "sign_grant_verify_token": {"sign-grant-verify"},
    **{
        f"sign_grant_mint_{origin.replace('-', '_')}_token":
            {f"sign-grant-mint-{origin}"}
        for origin in (
            "gateway-service", "gateway-issuer-did", "flow-wallet",
            "issuance-credential", "issuance-canvas", "issuance-readiness",
            "issuance-passport",
        )
    },
}

FORBIDDEN_STATIC_CAPABILITIES = (
    "auth/token/create",
    "auth/token/create-orphan",
    "auth/token/revoke",
    "auth/token/roles/selfhost-renew-leaf",
    "sys/auth/selfhost-renew",
    "sys/auth/selfhost-ca-rotation",
    "sys/mounts/transit",
    "sys/mounts/workload-pki-v2",
    "sys/mounts/keycloak-pki-v2",
    "workload-pki-v2/root/generate/internal",
    "keycloak-pki-v2/root/generate/internal",
    "sys/policies/acl/credential-service",
    "sys/seal",
    "sys/step-down",
    "transit/export/signing-key/cred-issuer-canary",
    "transit/export/decryption-key/integration-secret-envelope-marty-aes256",
    "transit/backup/cred-issuer-canary",
    "transit/restore/cred-issuer-canary",
)


def checked_static_tokens(bao: Bao, root: Path, minimum_ttl: int) -> None:
    for name, policies in STATIC_KMS_TOKENS.items():
        raw = bounded_file(root / name).decode("ascii")
        token = raw.strip()
        if len(token) < 20 or "\n" in token or "\r" in token:
            raise ValueError("static KMS token input is invalid")
        data = bao.request("POST", "auth/token/lookup", {"token": token}).get("data", {})
        actual = data.get("policies") if isinstance(data, dict) else None
        if (not isinstance(actual, list)
                or not all(isinstance(policy, str) for policy in actual)
                or set(actual) != policies
                or len(actual) != len(policies) or data.get("orphan") is not True
                or type(data.get("ttl")) is not int
                or data["ttl"] < minimum_ttl):
            raise ValueError("static KMS token still depends on root or has invalid scope")
        capabilities = bao.request(
            "POST", "sys/capabilities",
            {"token": token, "paths": list(FORBIDDEN_STATIC_CAPABILITIES)},
        ).get("data", {})
        if (not isinstance(capabilities, dict)
                or any(capabilities.get(path) != ["deny"]
                       for path in FORBIDDEN_STATIC_CAPABILITIES)):
            raise ValueError("static KMS token has privileged or private-key authority")


def checked_model(command: list[str], cwd: Path, secrets: Path) -> dict:
    model = run_json([*command, "--profile", "*", "config", "--format", "json"], cwd=cwd)
    if not isinstance(model, dict):
        raise ValueError("owned Compose model is invalid")
    require_rootless_migration(model)
    checked_compose_secret_files(model, secrets)
    return model


def export_current_snapshot(args: argparse.Namespace) -> Path:
    before = set(args.snapshot_export_dir.glob("openbao-raft-*.zip"))
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[1] /
                            "scripts/export-selfhost-openbao.py"),
         "--state-dir", str(args.openbao_state_dir),
         "--export-dir", str(args.snapshot_export_dir),
         "--config-file", str(args.openbao_config),
         "--bao-url", args.bao_addr,
         "--snapshot-identity-dir", str(args.snapshot_identity)],
        capture_output=True, text=True, timeout=360, check=False,
    )
    if result.returncode:
        raise RuntimeError("scoped Raft snapshot export failed")
    created = set(args.snapshot_export_dir.glob("openbao-raft-*.zip")) - before
    if len(created) != 1:
        raise RuntimeError("scoped Raft snapshot archive is absent or ambiguous")
    archive = created.pop()
    with zipfile.ZipFile(archive) as bundle:
        if set(bundle.namelist()) != {"raft.snap", "openbao-selfhost.hcl", "manifest.json"}:
            raise ValueError("scoped Raft snapshot archive contains unexpected files")
        if (bundle.getinfo("manifest.json").file_size > 64 * 1024
                or bundle.getinfo("raft.snap").file_size == 0):
            raise ValueError("scoped Raft snapshot archive is invalid")
        manifest = json.loads(bundle.read("manifest.json"))
        if (not isinstance(manifest, dict)
                or manifest.get("format") != "marty-openbao-raft-snapshot-v2"):
            raise ValueError("scoped Raft snapshot archive format is invalid")
        digest = hashlib.sha256()
        with bundle.open("raft.snap") as snapshot:
            while chunk := snapshot.read(1024 * 1024):
                digest.update(chunk)
        if digest.hexdigest() != manifest.get("snapshot_sha256"):
            raise ValueError("scoped Raft snapshot checksum differs")
    return archive


def audit(args: argparse.Namespace) -> Path:
    if (os.name != "posix" or PROJECT.fullmatch(args.project_name) is None
            or args.minimum_token_ttl < 3600 or args.minimum_token_ttl > 8 * 60 * 60
            or not args.compose_file.is_absolute() or args.compose_file.is_symlink()
            or not args.compose_file.is_file()
            or (args.compose_override is not None
                and (not args.compose_override.is_absolute()
                     or args.compose_override.is_symlink()
                     or not args.compose_override.is_file()
                     or args.compose_override == args.compose_file))
            or not args.bao_ca.is_absolute()
            or args.bao_ca.is_symlink() or not args.bao_ca.is_file()
            or args.bao_ca.stat().st_size > 64 * 1024
            or not args.openbao_state_dir.is_absolute()
            or not args.snapshot_export_dir.is_absolute()
            or not args.openbao_config.is_absolute()
            or not args.evidence_identity.is_absolute()
            or not args.audit_identity.is_absolute()
            or not args.ca_rotation_identity.is_absolute()
            or not args.snapshot_rotator_identity.is_absolute()):
        raise ValueError("root retirement audit inputs are invalid")
    snapshot_origin(args.bao_addr)
    rollback = args.rollback_secrets
    active = args.active_secrets
    ca_retire = getattr(args, "ca_retire", False)
    if args.ca_overlap and ca_retire:
        raise ValueError("CA overlap and trust retirement are separate ceremonies")
    ca_change = args.ca_overlap or ca_retire
    checked_overlap_mounts(ca_change, args.workload_pki_mount,
                           args.keycloak_pki_mount)
    verify_generations(rollback, active, ca_overlap=args.ca_overlap,
                       ca_retire=ca_retire)
    if checked_env(args.rollback_env, rollback) != checked_env(args.active_env, active):
        raise ValueError("active and rollback Compose env differ beyond secret generation")

    renewal = Bao(args.bao_addr, args.bao_ca, "")
    _, _, _, operator_token = renewal_login(renewal, args.renewal_identity)
    ca_token = ca_rotation_login(Bao(args.bao_addr, args.bao_ca, ""),
                                 args.ca_rotation_identity)
    bao = Bao(args.bao_addr, args.bao_ca, operator_token)
    require_renewal_authority(bao)
    checked_tokens(bao, rollback, active, args.minimum_token_ttl,
                   require_orphan_old=True, require_orphan_new=True)
    checked_static_tokens(bao, rollback, args.minimum_token_ttl)
    checked_static_tokens(bao, active, args.minimum_token_ttl)
    if ca_change:
        ca_bao = Bao(args.bao_addr, args.bao_ca, ca_token)
        require_ca_rotation_authority(ca_bao)
        checked_certificates(bao, rollback, active, args.minimum_token_ttl,
                             replacement=(ca_bao, args.workload_pki_mount,
                                          args.keycloak_pki_mount),
                             retiring=ca_retire)
    else:
        checked_certificates(bao, rollback, active, args.minimum_token_ttl)
    snapshot_login(Bao(args.bao_addr, args.bao_ca, ""), args.snapshot_identity)
    rotator_login(Bao(args.bao_addr, args.bao_ca, ""),
                  args.snapshot_rotator_identity)
    evidence_login(Bao(args.bao_addr, args.bao_ca, ""), args.evidence_identity)
    audit_policy, _ = audit_policy_for(args.audit_org_id, args.audit_org_slug,
                                       args.audit_did)
    audit_login(Bao(args.bao_addr, args.bao_ca, ""), args.audit_identity,
                audit_policy)

    cwd = args.compose_file.parent
    old = compose_args(args.project_name, args.rollback_env, args.compose_file,
                       args.compose_override)
    new = compose_args(args.project_name, args.active_env, args.compose_file,
                       args.compose_override)
    old_model = checked_model(old, cwd, rollback)
    new_model = checked_model(new, cwd, active)
    normalized = json.loads(json.dumps(new_model))
    for name, value in normalized.get("secrets", {}).items():
        if "file" in value:
            value["file"] = str(rollback / name)
    if normalized != old_model:
        raise ValueError("active and rollback Compose models differ beyond secrets")
    items = statuses(new, cwd=cwd)
    services = {item.get("Service") for item in items}
    declared = set(new_model.get("services", {}))
    if (not all(isinstance(name, str) for name in services)
            or not owned_service_closure(declared, services)
            or not {"keycloak", "gateway", "signing-keys", "postgres"} <= services
            or not healthy(items, services, new_model)):
        raise ValueError("active KMS-only project is not healthy")
    secret_mounts(args.project_name, active, services, new_model)
    return export_current_snapshot(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("compose_file", "rollback_env", "active_env", "rollback_secrets",
                 "active_secrets", "bao_ca", "renewal_identity", "ca_rotation_identity",
                 "snapshot_identity",
                 "evidence_identity", "audit_identity", "snapshot_rotator_identity",
                 "openbao_state_dir",
                 "snapshot_export_dir", "openbao_config"):
        parser.add_argument("--" + name.replace("_", "-"), required=True, type=Path)
    parser.add_argument("--compose-override", type=Path)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--bao-addr", required=True)
    parser.add_argument("--audit-org-id", required=True)
    parser.add_argument("--audit-org-slug", required=True)
    parser.add_argument("--audit-did", required=True)
    parser.add_argument("--minimum-token-ttl", type=int, default=3600)
    ca_mode = parser.add_mutually_exclusive_group()
    ca_mode.add_argument("--ca-overlap", action="store_true")
    ca_mode.add_argument("--ca-retire", action="store_true")
    parser.add_argument("--workload-pki-mount")
    parser.add_argument("--keycloak-pki-mount")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        archive = audit(args)
    except (OSError, ValueError, RuntimeError, HTTPError, subprocess.SubprocessError,
            zipfile.BadZipFile) as error:
        print(f"self-host root retirement audit failed: {type(error).__name__}",
              file=sys.stderr)
        return 2
    print(f"Both KMS generations passed root-lineage audit; snapshot: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
