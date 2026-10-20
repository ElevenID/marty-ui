#!/usr/bin/env python3
"""Recreate one owned KMS-only self-host project with a renewed secret generation.

This operator command keeps the old generation available for a bounded
rollback. A successful return proves readiness and file mounts, not business
journeys, trust retirement, or zero-downtime service continuity.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import time

if os.name == "posix":
    import fcntl

sys.dont_write_bytecode = True
from passport_remote_tls import SELFHOST_CERT_FILES  # noqa: E402
from selfhost_openbao_client import (  # noqa: E402
    Bao, certificate_public_key_der, public_key_der, require_ca_rotation_authority,
    require_renewal_authority,
)
from provision_selfhost_disposable_tls import ENV_PREFIX_ROLE, KEY_NAMES  # noqa: E402
from provision_selfhost_keycloak_kms import PURPOSES, REALMS, jwe_policy, signing_policy  # noqa: E402
from stage_selfhost_renewed_secrets import (  # noqa: E402
    RENEWED_TOKEN_FILES, bounded_file, entries, public_trust_overlap,
    verify_generations,
)


PROJECT = re.compile(r"marty-selfhost-[a-z0-9-]{1,60}\Z")
STARTUP_SECONDS = 600
COMPLETED_SERVICES = frozenset({
    "db-migrate", "issuance-migrations", "revocation-profile-migrate",
    "keycloak-configurator",
})
OPTIONAL_EDGE_SERVICES = frozenset({"cloudflared", "cloudflared-beta", "tunnel-nginx-proxy",
                                    "kms-initialize"})
TLS_CERT_BY_ROLE = {
    "signing-keys-server": "signing_keys_workload_server_cert",
    "gateway-client": "gateway_workload_client_cert",
    "auth-client": "auth_workload_client_cert",
    "auth-server": "auth_workload_server_cert",
    "compliance-profile-client": "compliance_profile_workload_client_cert",
    "deployment-profile-client": "deployment_profile_workload_client_cert",
    "organization-server": "org_workload_server_cert",
    "event-stream-server": "es_workload_server_cert",
    "notification-server": "notification_workload_server_cert",
    "revocation-profile-server": "rp_workload_server_cert",
    "credential-template-server": "ct_workload_server_cert",
    "issuance-server": "issuance_workload_server_cert",
    "flow-client": "flow_workload_client_cert",
    "flow-server": "flow_workload_server_cert",
    "pp-server": "pp_workload_server_cert",
    "verification-client": "verification_workload_client_cert",
}


def checked_overlap_mounts(enabled: bool, workload: str | None,
                           keycloak: str | None) -> None:
    if enabled != bool(workload and keycloak) or (not enabled and (workload or keycloak)):
        raise ValueError("CA overlap requires both replacement mounts")
    if enabled and (re.fullmatch(r"workload-pki-v[2-8]", workload) is None
                    or re.fullmatch(r"keycloak-pki-v[2-8]", keycloak) is None):
        raise ValueError("CA replacement mounts are outside reviewed versions")


def private_file(path: Path) -> str:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_size > 64 * 1024
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ValueError("operator input file is absent or not private")
    return path.read_text(encoding="utf-8")


def checked_env(path: Path, secret_root: Path) -> list[str]:
    lines = private_file(path).splitlines()
    matches = [line for line in lines if line.startswith("SELFHOST_SECRET_DIR=")]
    if len(matches) != 1 or matches[0] != f"SELFHOST_SECRET_DIR={secret_root}":
        raise ValueError("Compose env does not bind the expected secret generation")
    return [line for line in lines if not line.startswith("SELFHOST_SECRET_DIR=")]


def compose_args(project: str, env_file: Path, compose_file: Path,
                 override: Path | None = None) -> list[str]:
    command = ["docker", "compose", "--project-name", project,
               "--env-file", str(env_file), "-f", str(compose_file)]
    if override is not None:
        command.extend(("-f", str(override)))
    return command


def require_rootless_migration(model: dict) -> None:
    services = model.get("services", {})
    migrate = services.get("db-migrate", {})
    environment = migrate.get("environment", {}) if isinstance(migrate, dict) else {}
    if not isinstance(environment, dict) or str(environment.get(
            "MARTY_KMS_BOOTSTRAP_ENABLED", "")).lower() != "false":
        raise ValueError("owned db-migrate must not rerun KMS bootstrap")
    if any(secret == "openbao_bootstrap_token" or isinstance(secret, dict) and
           secret.get("source") == "openbao_bootstrap_token"
           for secret in migrate.get("secrets", [])):
        raise ValueError("owned db-migrate must not mount bootstrap token")
    initializer = services.get("kms-initialize", {})
    if not isinstance(initializer, dict) or initializer.get("profiles") != ["kms-init"]:
        raise ValueError("privileged KMS initializer must be opt-in")


def checked_compose_secret_files(model: dict, generation: Path) -> None:
    """Prove every rendered secret, including optional profiles, has a real file."""
    secrets = model.get("secrets")
    if not isinstance(secrets, dict) or not secrets:
        raise ValueError("owned Compose secrets model is invalid")
    files = entries(generation)
    if not secrets.keys() <= files.keys():
        raise ValueError("owned Compose secret is missing from the generation")
    for name, value in secrets.items():
        if (not isinstance(value, dict) or value.get("file") != str(generation / name)):
            raise ValueError("owned Compose secret binding is invalid")
        bounded_file(files[name], allow_empty=True)


def run_json(command: list[str], *, cwd: Path) -> object:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                            timeout=60, check=False)
    if result.returncode:
        raise RuntimeError("owned Compose inspection failed")
    return json.loads(result.stdout)


def statuses(command: list[str], *, cwd: Path) -> list[dict]:
    result = subprocess.run([*command, "ps", "--all", "--format", "json"],
                            cwd=cwd, capture_output=True, text=True,
                            timeout=60, check=False)
    if result.returncode:
        raise RuntimeError("owned Compose status failed")
    raw = result.stdout.strip()
    if not raw:
        raise ValueError("owned Compose project has no containers")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = [json.loads(line) for line in raw.splitlines()]
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
        raise ValueError("owned Compose status is invalid")
    return parsed


def healthy(items: list[dict], services: set[str], model: dict) -> bool:
    declared = model.get("services")
    if not isinstance(declared, dict) or not services <= declared.keys():
        return False
    by_service = {item.get("Service"): item for item in items}
    if set(by_service) != services or len(items) != len(services):
        return False
    for item in items:
        state = str(item.get("State", "")).lower()
        health = str(item.get("Health", "")).lower()
        if item["Service"] in COMPLETED_SERVICES:
            if state != "exited" or item.get("ExitCode") != 0:
                return False
        else:
            spec = declared[item["Service"]]
            if not isinstance(spec, dict):
                return False
            check = spec.get("healthcheck")
            if check is not None and not isinstance(check, dict):
                return False
            expected_health = "" if check is None or check.get("disable") is True else "healthy"
            if state != "running" or health != expected_health:
                return False
    return True


def owned_service_closure(declared: set[str], running: set[str]) -> bool:
    return ("kms-initialize" not in running and running <= declared
            and declared - running <= OPTIONAL_EDGE_SERVICES)


def secret_mounts(project: str, secret_root: Path, services: set[str],
                  model: dict) -> int:
    definitions = model.get("secrets")
    declared = model.get("services")
    if not isinstance(definitions, dict) or not isinstance(declared, dict):
        raise RuntimeError("owned Compose secret model is invalid")
    expected: dict[str, dict[str, str]] = {}
    names: set[str] = set()
    for service in services:
        spec = declared.get(service)
        if not isinstance(spec, dict) or not isinstance(spec.get("secrets", []), list):
            raise RuntimeError("owned Compose service secrets are invalid")
        targets: dict[str, str] = {}
        for reference in spec.get("secrets", []):
            if isinstance(reference, str):
                source, target = reference, f"/run/secrets/{reference}"
            elif isinstance(reference, dict):
                source, target = reference.get("source"), reference.get("target")
            else:
                raise RuntimeError("owned Compose service secret reference is invalid")
            definition = definitions.get(source) if isinstance(source, str) else None
            if (not isinstance(definition, dict) or not isinstance(target, str)
                    or not target.startswith("/run/secrets/")
                    or not target.removeprefix("/run/secrets/")
                    or definition.get("file") != str(secret_root / source)
                    or target in targets):
                raise RuntimeError("owned Compose secret binding is invalid")
            targets[target] = str(secret_root / source)
            names.add(source)
        expected[service] = targets
    ids = subprocess.run(["docker", "ps", "-aq", "--filter",
                          f"label=com.docker.compose.project={project}"],
                         capture_output=True, text=True, timeout=30, check=True).stdout.split()
    if len(ids) != len(services):
        raise RuntimeError("owned project container count changed")
    inspected = run_json(["docker", "inspect", *ids], cwd=secret_root)
    if (not isinstance(inspected, list) or len(inspected) != len(ids)
            or not all(isinstance(item, dict) and isinstance(item.get("Mounts"), list)
                       for item in inspected)):
        raise RuntimeError("owned project mounts are invalid")
    mount_count = 0
    inspected_services: set[str] = set()
    for item in inspected:
        labels = item.get("Config", {}).get("Labels", {})
        service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
        if (service not in expected or service in inspected_services
                or labels.get("com.docker.compose.project") != project):
            raise RuntimeError("owned project container identity is invalid")
        inspected_services.add(service)
        seen: set[str] = set()
        for mount in item["Mounts"]:
            if not isinstance(mount, dict):
                raise RuntimeError("owned project mounts are invalid")
            target = mount.get("Destination", "")
            if not isinstance(target, str):
                raise RuntimeError("owned project mounts are invalid")
            if not target.startswith("/run/secrets/"):
                continue
            mount_count += 1
            if (target in seen or target not in expected[service]
                    or mount.get("Source") != expected[service][target]
                    or mount.get("Type") != "bind" or mount.get("RW") is not False):
                raise RuntimeError("owned project secret mount differs from generation")
            seen.add(target)
        if seen != set(expected[service]):
            raise RuntimeError("owned project secret mounts are incomplete")
    if inspected_services != services or not RENEWED_TOKEN_FILES <= names:
        raise RuntimeError("owned project renewal token mounts are incomplete")
    return mount_count


def checked_certificate_lifetime(certificate: str, minimum_ttl: int) -> None:
    result = subprocess.run(
        ["openssl", "x509", "-dates", "-noout"],
        input=certificate.encode("ascii"), capture_output=True,
        timeout=10, check=False,
    )
    dates = dict(line.split("=", 1) for line in result.stdout.decode("ascii").splitlines()
                 if "=" in line)
    if result.returncode or set(dates) != {"notBefore", "notAfter"}:
        raise ValueError("renewed certificate validity is invalid")
    now = time.time()
    if (ssl.cert_time_to_seconds(dates["notBefore"]) > now
            or ssl.cert_time_to_seconds(dates["notAfter"]) < now + minimum_ttl):
        raise ValueError("renewed certificate is outside the required validity overlap")


def checked_certificate_chain(path: Path, issuer: str) -> None:
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", "/dev/stdin", str(path)],
        input=issuer.encode("ascii"), capture_output=True, timeout=10, check=False,
    )
    if result.returncode != 0:
        raise ValueError("renewed certificate is not signed by its OpenBao issuer")


def checked_certificates(bao: Bao, old: Path, new: Path, minimum_ttl: int,
                         *, replacement: tuple[Bao, str, str] | None = None,
                         retiring: bool = False) -> None:
    if retiring and replacement is None:
        raise ValueError("CA trust retirement requires live replacement issuers")
    if (set(TLS_CERT_BY_ROLE) != set(KEY_NAMES)
            or set(TLS_CERT_BY_ROLE.values()) != SELFHOST_CERT_FILES - {"workload_identity_ca_cert"}):
        raise ValueError("self-host TLS role and certificate inventory drifted")
    issuers = {
        "workload_identity_ca_cert": bao.request("GET", "workload-pki/cert/ca")
        .get("data", {}).get("certificate"),
        "keycloak": bao.request("GET", "keycloak-pki/cert/ca")
        .get("data", {}).get("certificate"),
    }
    new_issuers = issuers
    if replacement is not None:
        ca_bao, workload_mount, keycloak_mount = replacement
        new_issuers = {
            "workload_identity_ca_cert": ca_bao.request(
                "GET", f"{workload_mount}/cert/ca").get("data", {}).get("certificate"),
            "keycloak": ca_bao.request(
                "GET", f"{keycloak_mount}/cert/ca").get("data", {}).get("certificate"),
        }
        if new_issuers["keycloak"] == issuers["keycloak"]:
            raise ValueError("replacement Keycloak issuer did not change")
    if any(not isinstance(issuer, str)
           for issuer in (*issuers.values(), *new_issuers.values())):
        raise ValueError("renewed OpenBao issuer is absent")
    for issuer in (new_issuers.values() if retiring else
                   (*issuers.values(), *new_issuers.values())):
        checked_certificate_lifetime(issuer, minimum_ttl)
    old_ca = issuers["workload_identity_ca_cert"]
    new_ca = new_issuers["workload_identity_ca_cert"]
    bundle = (public_trust_overlap(old_ca.encode("ascii"), new_ca.encode("ascii"))
              .decode("ascii") if replacement is not None else old_ca)
    if retiring:
        generations = ((old, new_issuers, bundle),
                       (new, new_issuers, new_ca.rstrip("\n") + "\n"))
    elif replacement is not None:
        generations = ((old, issuers, old_ca), (new, new_issuers, bundle))
    else:
        generations = ((old, issuers, old_ca), (new, issuers, old_ca))
    for root, active_issuers, expected_ca in generations:
        workload_ca = (root / "workload_identity_ca_cert").read_text(encoding="ascii")
        if workload_ca != expected_ca:
            raise ValueError("workload issuer differs from the mounted trust anchor")
        for role, cert_name in TLS_CERT_BY_ROLE.items():
            key_name = KEY_NAMES[role]
            metadata = bao.request("GET", f"transit/keys/{key_name}").get("data", {})
            if (metadata.get("type") != "ecdsa-p256"
                    or metadata.get("exportable") is not False
                    or metadata.get("allow_plaintext_backup") is not False
                    or metadata.get("latest_version") != 1):
                raise ValueError("workload signer lost version-one non-exportable custody")
            public_key = metadata.get("keys", {}).get("1", {}).get("public_key")
            if not isinstance(public_key, str):
                raise ValueError("workload signer public key is absent")
            certificate_path = root / cert_name
            certificate = certificate_path.read_text(encoding="ascii")
            checked_certificate_lifetime(certificate, minimum_ttl)
            checked_certificate_chain(certificate_path, active_issuers["workload_identity_ca_cert"])
            if certificate_public_key_der(certificate) != public_key_der(public_key):
                raise ValueError("workload certificate differs from its remote signer")
        for realm in REALMS:
            key_name = f"keycloak-{realm}-rs256"
            metadata = bao.request("GET", f"transit/keys/{key_name}").get("data", {})
            if (metadata.get("type") != "rsa-2048"
                    or metadata.get("exportable") is not False
                    or metadata.get("allow_plaintext_backup") is not False
                    or metadata.get("latest_version") != 1):
                raise ValueError("Keycloak signer lost version-one non-exportable custody")
            public_key = metadata.get("keys", {}).get("1", {}).get("public_key")
            if not isinstance(public_key, str):
                raise ValueError("Keycloak signer public key is absent")
            certificate_path = root / f"keycloak_{realm}_rs256_cert"
            certificate = certificate_path.read_text(encoding="ascii")
            checked_certificate_lifetime(certificate, minimum_ttl)
            checked_certificate_chain(certificate_path, active_issuers["keycloak"])
            if certificate_public_key_der(certificate) != public_key_der(public_key):
                raise ValueError("Keycloak certificate differs from its remote signer")


def checked_tokens(bao: Bao, old: Path, new: Path, minimum_ttl: int,
                   *, require_orphan_new: bool,
                   require_orphan_old: bool = False) -> None:
    for root, require_orphan in ((old, require_orphan_old or
                                 (old == new and require_orphan_new)),
                                 (new, require_orphan_new)):
        for name in sorted(RENEWED_TOKEN_FILES):
            token = (root / name).read_text(encoding="ascii").strip()
            response = bao.request("POST", "auth/token/lookup", {"token": token})
            data = response.get("data", {})
            if (not isinstance(data, dict) or not isinstance(data.get("policies"), list)
                    or len(data["policies"]) != 1 or data["policies"][0] == "default"
                    or type(data.get("ttl")) is not int or data["ttl"] < minimum_ttl
                    or data["ttl"] > 8 * 60 * 60):
                raise ValueError("renewed OpenBao token has invalid scope or lifetime")
            if (require_orphan
                    and (data.get("orphan") is not True
                         or data.get("path") != "auth/token/create/selfhost-renew-leaf")):
                raise ValueError("renewed OpenBao token still depends on bootstrap root")
            policy_name = data["policies"][0]
            if not isinstance(policy_name, str) or not re.fullmatch(r"[a-z0-9-]{1,160}", policy_name):
                raise ValueError("renewed OpenBao policy reference is invalid")
            policy = bao.request("GET", f"sys/policies/acl/{policy_name}").get("data", {}).get("policy")
            if name.endswith("_tls_kms_token"):
                prefix = name.removesuffix("_tls_kms_token").upper()
                key = KEY_NAMES[ENV_PREFIX_ROLE[prefix]]
                expected = (f'path "transit/keys/{key}" {{ capabilities = ["read"] }}\n'
                            f'path "transit/sign/{key}" {{ capabilities = ["update"] }}')
                signature = bao.request("POST", f"transit/sign/{key}", {
                    "input": base64.b64encode(b"activation-scope").decode("ascii"),
                    "key_version": 1,
                }, token=token).get("data", {}).get("signature")
                if policy != expected or not isinstance(signature, str) or not signature.startswith("vault:v1:"):
                    raise ValueError("renewed TLS token cannot use its exact versioned signer")
            elif name == "keycloak_signing_kms_token":
                if policy != signing_policy():
                    raise ValueError("Keycloak signing policy changed before activation")
                for realm in REALMS:
                    signature = bao.request("POST", f"transit/sign/keycloak-{realm}-rs256", {
                        "input": base64.b64encode(b"activation-scope").decode("ascii"),
                        "hash_algorithm": "sha2-256", "signature_algorithm": "pkcs1v15",
                        "key_version": 1,
                    }, token=token).get("data", {}).get("signature")
                    if not isinstance(signature, str) or not signature.startswith("vault:v1:"):
                        raise ValueError("Keycloak signing token cannot use version-one signer")
            else:
                match = re.fullmatch(r"keycloak_(master|11id)_(cookie|ciba)_token", name)
                if match is None or match.group(1) not in REALMS or match.group(2) not in PURPOSES:
                    raise ValueError("unknown Keycloak renewal token")
                realm, purpose = match.groups()
                key_path = f"didcomm/keycloak/keys/{realm}/{purpose}"
                version = bao.request("GET", key_path).get("data", {}).get("version")
                if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", version):
                    raise ValueError("Keycloak JWE version changed before activation")
                if (policy != jwe_policy(realm, purpose, version)
                        or bao.request("GET", key_path, token=token).get("data", {}).get("version") != version):
                    raise ValueError("Keycloak JWE token cannot read its exact versioned key")


def recreate(command: list[str], services: set[str], model: dict, *, cwd: Path,
             log_file: Path) -> list[dict]:
    deadline = time.monotonic() + STARTUP_SECONDS
    fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as log:
        for attempt in range(8):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            options = ["--force-recreate"] if attempt == 0 else []
            subprocess.run([*command, "up", "-d", "--no-build", *options,
                            *sorted(services)], cwd=cwd, stdout=log,
                           stderr=subprocess.STDOUT, timeout=min(240, remaining),
                           check=False)
            try:
                items = statuses(command, cwd=cwd)
                if healthy(items, services, model):
                    return items
            except (RuntimeError, ValueError):
                pass
            time.sleep(10)
    raise RuntimeError("owned project did not become healthy after recreation")


def write_report(path: Path, report: dict) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("activation report path is invalid")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def activate(args: argparse.Namespace) -> dict:
    if os.name != "posix" or PROJECT.fullmatch(args.project_name) is None:
        raise ValueError("owned self-host project name is invalid")
    if (not args.compose_file.is_absolute() or args.compose_file.is_symlink()
            or not args.compose_file.is_file()):
        raise ValueError("owned Compose file is invalid")
    if (args.compose_override is not None
            and (not args.compose_override.is_absolute()
                 or args.compose_override.is_symlink()
                 or not args.compose_override.is_file()
                 or args.compose_override == args.compose_file)):
        raise ValueError("owned Compose override is invalid")
    if (args.report.exists() or args.report.is_symlink()
            or args.report.parent != args.log_dir
            or args.report.name in ("renewed-compose.log", "rollback-compose.log")):
        raise ValueError("activation report destination is invalid")
    ca_overlap = getattr(args, "ca_overlap", False)
    ca_retire = getattr(args, "ca_retire", False)
    workload_mount = getattr(args, "workload_pki_mount", None)
    keycloak_mount = getattr(args, "keycloak_pki_mount", None)
    ca_token_file = getattr(args, "ca_rotation_token_file", None)
    if ca_overlap and ca_retire:
        raise ValueError("CA overlap and trust retirement are separate ceremonies")
    ca_change = ca_overlap or ca_retire
    checked_overlap_mounts(ca_change, workload_mount, keycloak_mount)
    if ca_change != bool(ca_token_file):
        raise ValueError("CA change requires scoped CA authority")
    count, changed = verify_generations(args.current_secrets, args.renewed_secrets,
                                        ca_overlap=ca_overlap, ca_retire=ca_retire)
    if checked_env(args.current_env, args.current_secrets) != checked_env(
            args.renewed_env, args.renewed_secrets):
        raise ValueError("renewed Compose env changed non-secret configuration")
    if not args.bao_addr.startswith("https://") or not args.bao_ca.is_file():
        raise ValueError("OpenBao renewal endpoint is invalid")
    operator_token = private_file(args.bao_token_file).strip()
    if len(operator_token) < 20:
        raise ValueError("OpenBao renewal operator token is invalid")
    bao = Bao(args.bao_addr, args.bao_ca, operator_token)
    require_renewal_authority(bao)
    replacement = None
    if ca_change:
        ca_token = private_file(ca_token_file).strip()
        ca_bao = Bao(args.bao_addr, args.bao_ca, ca_token)
        require_ca_rotation_authority(ca_bao)
        replacement = (ca_bao, workload_mount, keycloak_mount)
    checked_tokens(bao, args.current_secrets, args.renewed_secrets,
                   args.minimum_token_ttl, require_orphan_new=True)
    if replacement is None:
        checked_certificates(bao, args.current_secrets, args.renewed_secrets,
                             args.minimum_token_ttl)
    else:
        checked_certificates(bao, args.current_secrets, args.renewed_secrets,
                             args.minimum_token_ttl, replacement=replacement,
                             retiring=ca_retire)
    old = compose_args(args.project_name, args.current_env, args.compose_file,
                       args.compose_override)
    new = compose_args(args.project_name, args.renewed_env, args.compose_file,
                       args.compose_override)
    cwd = args.compose_file.parent
    old_model = run_json([*old, "--profile", "*", "config", "--format", "json"], cwd=cwd)
    new_model = run_json([*new, "--profile", "*", "config", "--format", "json"], cwd=cwd)
    if not isinstance(old_model, dict) or not isinstance(new_model, dict):
        raise ValueError("owned Compose model is invalid")
    for model in (old_model, new_model):
        require_rootless_migration(model)
    checked_compose_secret_files(old_model, args.current_secrets)
    checked_compose_secret_files(new_model, args.renewed_secrets)
    normalized = json.loads(json.dumps(new_model))
    for name, value in normalized.get("secrets", {}).items():
        if "file" in value:
            value["file"] = str(args.current_secrets / name)
    if normalized != old_model:
        raise ValueError("Compose model changed beyond the secret generation")
    baseline = statuses(old, cwd=cwd)
    services = {item.get("Service") for item in baseline}
    declared = set(old_model.get("services", {}))
    if (not all(isinstance(name, str) for name in services)
            or not owned_service_closure(declared, services)
            or not {"keycloak", "gateway", "signing-keys", "postgres"} <= services
            or not healthy(baseline, services, old_model)):
        raise ValueError("owned KMS-only project is not healthy before renewal")
    secret_mounts(args.project_name, args.current_secrets, services, old_model)
    try:
        recreate(new, services, new_model, cwd=cwd,
                 log_file=args.log_dir / "renewed-compose.log")
        mount_count = secret_mounts(args.project_name, args.renewed_secrets, services,
                                    new_model)
        report = {"schema": "marty.selfhost-renewal-activation/v1",
                  "result": "activated", "project": args.project_name,
                  "ca_mode": ("retired" if ca_retire else "overlap" if ca_overlap else "unchanged"),
                  "secret_files": count, "renewed_files": changed,
                  "services": len(services), "secret_mounts": mount_count}
        write_report(args.report, report)
    except Exception:
        try:
            recreate(old, services, old_model, cwd=cwd,
                     log_file=args.log_dir / "rollback-compose.log")
            secret_mounts(args.project_name, args.current_secrets, services, old_model)
        except Exception as error:
            raise RuntimeError("renewal failed and KMS-only rollback failed") from error
        write_report(args.report, {"schema": "marty.selfhost-renewal-activation/v1",
                                   "result": "rolled_back", "project": args.project_name})
        raise RuntimeError("renewal failed; prior KMS-only generation restored") from None
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("compose_file", "current_env", "renewed_env", "current_secrets",
                 "renewed_secrets", "bao_ca", "bao_token_file", "log_dir", "report"):
        parser.add_argument("--" + name.replace("_", "-"), required=True, type=Path)
    parser.add_argument("--compose-override", type=Path)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--bao-addr", required=True)
    ca_mode = parser.add_mutually_exclusive_group()
    ca_mode.add_argument("--ca-overlap", action="store_true")
    ca_mode.add_argument("--ca-retire", action="store_true")
    parser.add_argument("--workload-pki-mount")
    parser.add_argument("--keycloak-pki-mount")
    parser.add_argument("--ca-rotation-token-file", type=Path)
    parser.add_argument("--minimum-token-ttl", type=int, default=3600)
    args = parser.parse_args()
    try:
        if (os.name != "posix"
                or args.minimum_token_ttl < 60 or args.minimum_token_ttl > 8 * 60 * 60
                or not args.log_dir.is_absolute() or args.log_dir.is_symlink()
                or not args.log_dir.is_dir()
                or stat.S_IMODE(args.log_dir.stat().st_mode) != 0o700
                or any(args.log_dir.iterdir())):
            raise ValueError("activation output directory or TTL is invalid")
        lock_path = args.current_secrets.parent / f".{args.project_name}.renewal.lock"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = activate(args)
        finally:
            os.close(lock_fd)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"self-host renewal activation failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(f"Renewed {result['services']} owned services with {result['secret_mounts']} secret mounts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
