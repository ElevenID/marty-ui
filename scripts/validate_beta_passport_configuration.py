"""Validate the opt-in beta passport Compose model without exposing secret data."""

from __future__ import annotations

if __package__:
    from .passport_model_policy import evaluate as evaluate_passport_policy
else:
    try:
        from passport_model_policy import evaluate as evaluate_passport_policy
    except ModuleNotFoundError:
        from scripts.passport_model_policy import evaluate as evaluate_passport_policy

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

try:
    from .check_beta_keycloak_kms import KeycloakKmsError, validate_model as validate_keycloak_kms
except ImportError:
    try:
        from scripts.check_beta_keycloak_kms import KeycloakKmsError, validate_model as validate_keycloak_kms
    except ImportError:
        from check_beta_keycloak_kms import KeycloakKmsError, validate_model as validate_keycloak_kms

MAX_MODEL_BYTES = 8 * 1024 * 1024
MAX_MOUNT_ENTRIES = 1024
MAX_MOUNT_FILES = 512
MAX_MOUNT_FILE_BYTES = 1024 * 1024
MAX_MOUNT_TOTAL_BYTES = 8 * 1024 * 1024
PROFILE = "docker-compose.profile.passport-native-beta.yml"
PHYSICAL_PROFILE = "docker-compose.profile.passport-native-physical-beta.yml"
PROVIDER_BASE_PROFILE = "docker-compose.profile.passport-provider-base.yml"
PHYSICAL_PROFILES = {PHYSICAL_PROFILE, PROVIDER_BASE_PROFILE}
PASSPORT_RAW_KEY_NAMES = (
    "PASSPORT_TENANT_API_KEYS",
    "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
    "ICAO_DOCUMENT_SIGNER_API_KEY",
    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
)
PRIVATE_BUREAU_URL = "http://passport-beta-bureau:8020"
PRIVATE_SIGNING_URL = "http://passport-callback-signer:8018/internal/documents"
PRIVATE_SIGNING_NETWORK = "passport-callback-signing"
PRIVATE_CALLBACK_URL = (
    "http://issuance-native:8005/v1/passport/webhooks/personalization"
)
PRIVATE_GATEWAY_CALLBACK_URL = (
    "http://gateway:8000/v1/passport/webhooks/personalization"
)
PHYSICAL_INGRESS_URL = "http://passport-provider-ingress:8021"
PHYSICAL_SIGNER_URL = "http://passport-callback-signer-supported:8018/internal/documents"
PHYSICAL_ALLOWLIST = Path(__file__).resolve().parents[1] / "deploy-config/passport-beta-physical-provider-allowlist.json"


class PassportConfigurationError(ValueError):
    pass


def physical_source_for_name_check(source, kind, repository_root):
    """Check bind alias and resolved target without trusting checkout names."""
    if kind != "bind" or not isinstance(source, str):
        return source
    lexical_source = Path(source).absolute()
    resolved_source = lexical_source.resolve()
    repository_root = Path(repository_root).resolve()
    if lexical_source.is_relative_to(repository_root):
        alias = lexical_source.relative_to(repository_root).as_posix()
        target = (resolved_source.relative_to(repository_root).as_posix()
                  if resolved_source.is_relative_to(repository_root)
                  else resolved_source.as_posix())
        return f"{alias} {target}"
    return f"{source} {resolved_source.as_posix()}"


def is_known_beta_canvas_config(source, service_name, repository_root):
    """Allow only the checked-in Canvas config without a symlinked parent."""
    expected = Path(repository_root).resolve() / "config/canvas/production-local.rb"
    candidate = Path(source).absolute() if isinstance(source, str) else None
    return (service_name == "canvas-real" and candidate == expected
            and not candidate.is_symlink() and candidate.resolve() == expected)


def is_known_openbao_bootstrap_file(source, service_name, repository_root):
    """Allow only the two KMS-owned Raft bootstrap inputs in beta."""
    allowed = {
        "openbao": {"docker/openbao-selfhost.hcl"},
        "openbao-init": {"docker/openbao-selfhost-init.sh"},
    }
    root = Path(repository_root).resolve()
    candidate = Path(source).absolute() if isinstance(source, str) else None
    return (
        candidate is not None
        and any(candidate == root / relative for relative in allowed.get(service_name, ()))
        and not candidate.is_symlink()
        and candidate.resolve() == candidate
    )


def environment(service):
    value = service.get("environment")
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return dict(item.split("=", 1) for item in value if "=" in item)
    raise PassportConfigurationError("Invalid beta passport service environment")


def contains_credential(value, credential):
    return evaluate_passport_policy("contains-credential", error_type=PassportConfigurationError, value=value, credential=credential)


def service_reuses_credential(service_name, service, credential, dedicated_name):
    return evaluate_passport_policy("service-reuses-credential", error_type=PassportConfigurationError,
                                    name=service_name, service=service, credential=credential,
                                    dedicated=dedicated_name)


def valid_operator_credential(value):
    return evaluate_passport_policy("compose-beta-operator-credential",
                                    error_type=PassportConfigurationError, value=value)


def validate_mounted_sources(model, services, credential, purpose, *,
                             excluded_secret_names=()):
    unavailable = (
        f"Beta {purpose} operator credential isolation cannot verify mounted files"
    )
    invalid = f"Beta {purpose} operator credential isolation is invalid"
    sources = []
    for name, secret in model.get("secrets", {}).items():
        if name in excluded_secret_names:
            continue
        path = secret.get("file") if isinstance(secret, dict) else None
        if not isinstance(path, str):
            raise PassportConfigurationError(unavailable)
        sources.append(path)
    for service in services.values():
        configs = service.get("configs", [])
        if not isinstance(configs, list):
            raise PassportConfigurationError(unavailable)
        definitions = model.get("configs", {})
        if not isinstance(definitions, dict):
            raise PassportConfigurationError(unavailable)
        for config in configs:
            name = (
                config
                if isinstance(config, str)
                else (config.get("source") if isinstance(config, dict) else None)
            )
            definition = definitions.get(name) if isinstance(name, str) else None
            path = definition.get("file") if isinstance(definition, dict) else None
            if not isinstance(path, str) or definition.get("external"):
                raise PassportConfigurationError(unavailable)
            sources.append(path)
        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            raise PassportConfigurationError(unavailable)
        for volume in volumes:
            if not isinstance(volume, dict):
                raise PassportConfigurationError(unavailable)
            kind = volume.get("type")
            if kind in {"volume", "tmpfs"}:
                continue
            if kind != "bind" or not isinstance(volume.get("source"), str):
                raise PassportConfigurationError(unavailable)
            sources.append(volume["source"])

    pending = [Path(source).absolute() for source in sources]
    visited = set()
    file_count = 0
    total_bytes = 0
    marker = credential.encode()
    try:
        while pending:
            path = pending.pop()
            if path in visited:
                continue
            visited.add(path)
            if len(visited) > MAX_MOUNT_ENTRIES or path.is_symlink():
                raise PassportConfigurationError(unavailable)
            if path.is_dir():
                with os.scandir(path) as entries:
                    for entry in entries:
                        if len(visited) + len(pending) >= MAX_MOUNT_ENTRIES:
                            raise PassportConfigurationError(unavailable)
                        pending.append(Path(entry.path))
            elif path.is_file():
                file_count += 1
                size = path.stat().st_size
                total_bytes += size
                if (
                    file_count > MAX_MOUNT_FILES
                    or size > MAX_MOUNT_FILE_BYTES
                    or total_bytes > MAX_MOUNT_TOTAL_BYTES
                ):
                    raise PassportConfigurationError(unavailable)
                with path.open("rb") as mounted:
                    if marker in mounted.read(MAX_MOUNT_FILE_BYTES + 1):
                        raise PassportConfigurationError(invalid)
            else:
                raise PassportConfigurationError(unavailable)
    except OSError:
        raise PassportConfigurationError(unavailable) from None


def validate_file_operator_credentials(model, services, gateway, signing,
                                       signing_key):
    """Validate the beta simulator's two private, holder-scoped operator files."""
    definitions = model.get("secrets")
    if not isinstance(definitions, dict):
        raise PassportConfigurationError("Beta operator secrets are missing")
    values = {}
    paths = {}
    for purpose, key_name, secret_name in (
        ("DSC", "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY", "dsc_issue_gateway_key"),
        ("CSCA", "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY", "csca_issue_gateway_key"),
    ):
        file_name = f"{key_name}_FILE"
        target = f"/run/secrets/{secret_name}"
        holders = {name for name, service in services.items()
                   if service.get("environment") is not None
                   and environment(service).get(file_name)}
        mounts = set()
        for name, service in services.items():
            entries = service.get("secrets", [])
            if not isinstance(entries, list):
                raise PassportConfigurationError("Beta operator secret mounts are invalid")
            selected = [entry for entry in entries if (
                entry == secret_name if isinstance(entry, str)
                else isinstance(entry, dict) and entry.get("source") == secret_name)]
            if selected:
                if (len(selected) != 1 or isinstance(selected[0], dict)
                        and selected[0].get("target") not in
                        {secret_name, f"/run/secrets/{secret_name}"}):
                    raise PassportConfigurationError(
                        f"Beta {purpose} operator secret mount is invalid")
                mounts.add(name)
        definition = definitions.get(secret_name)
        source = definition.get("file") if isinstance(definition, dict) else None
        if not (holders == mounts == {"gateway", "signing-keys"}
                and gateway.get(file_name) == signing.get(file_name) == target
                and all(key_name not in environment(service)
                        for service in services.values()
                        if service.get("environment") is not None)
                and isinstance(source, str) and Path(source).is_absolute()):
            raise PassportConfigurationError(
                f"Beta {purpose} operator file binding is invalid")
        path = Path(source)
        resolved = path.resolve()
        if (path.parent.name != "elevenid-beta-passport-ceremony"
                or resolved.parent.name != "elevenid-beta-passport-ceremony"
                or path.name != secret_name or path.is_symlink()
                or path.parent.is_symlink() or resolved != path
                or not path.is_file()):
            raise PassportConfigurationError(
                f"Beta {purpose} operator file root is not isolated")
        try:
            with path.open("rb") as credential_file:
                raw = credential_file.read(4097)
            credential = raw.decode("ascii")
        except (OSError, UnicodeError) as exc:
            raise PassportConfigurationError(
                f"Beta {purpose} operator file is unreadable") from exc
        if (not valid_operator_credential(credential)
                or re.fullmatch(r"[A-Za-z0-9._-]{32,256}", credential) is None
                or len(raw) > 4096):
            raise PassportConfigurationError(
                f"Beta {purpose} operator file is invalid")
        values[purpose] = credential
        paths[purpose] = source
        if (credential == signing_key
                or any(service_reuses_credential(name, service, credential, key_name)
                       for name, service in services.items())):
            raise PassportConfigurationError(
                f"Beta {purpose} operator credential isolation is invalid")
        validate_mounted_sources(model, services, credential, purpose,
                                 excluded_secret_names=(secret_name,))
    if values["DSC"] == values["CSCA"] or paths["DSC"] == paths["CSCA"]:
        raise PassportConfigurationError("Beta operator credentials are reused")


def physical_require(condition, message):
    if not condition:
        raise PassportConfigurationError(message)


def physical_secret_sources(service):
    entries = service.get("secrets", [])
    physical_require(isinstance(entries, list),
                     "Beta physical provider secret mounts are invalid")
    names = [entry if isinstance(entry, str) else
             entry.get("source") if isinstance(entry, dict) else None
             for entry in entries]
    physical_require(all(isinstance(name, str) for name in names),
                     "Beta physical provider secret mounts are invalid")
    return set(names)


def physical_secret_path(model, name):
    definition = model.get("secrets", {}).get(name)
    path = definition.get("file") if isinstance(definition, dict) else None
    physical_require(isinstance(path, str) and Path(path).is_absolute(),
                     "Beta physical provider secret binding is missing")
    source = Path(path)
    resolved = source.resolve()
    physical_require(source.parent.name == "elevenid-beta-passport-physical"
                     and not any(re.search(r"prod|production|selfhost", part, re.IGNORECASE)
                                 for part in source.parts)
                     and resolved.parent.name == "elevenid-beta-passport-physical"
                     and not any(re.search(r"prod|production|selfhost", part, re.IGNORECASE)
                                 for part in resolved.parts)
                     and not source.is_symlink() and not source.parent.is_symlink()
                     and source.is_file(),
                     "Beta physical provider secret root is not isolated")
    return source


def physical_secret(model, name):
    source = physical_secret_path(model, name)
    try:
        value = source.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise PassportConfigurationError("Beta physical provider secret is unreadable") from exc
    physical_require(len(value) >= 32 and not value.lower().startswith(("dev-", "change_me")),
                     "Beta physical provider secret is invalid")
    return value


def validate_physical_model(model, files, provider_registry=None):
    evaluate_passport_policy("compose-physical-layout", error_type=PassportConfigurationError,
                             model=model, files=[Path(path).name for path in files])
    services = model["services"]
    gateway = environment(services["gateway"])
    native = environment(services["issuance-native"])
    signing = environment(services["signing-keys"])
    physical_secrets = {
        "passport_physical_provider_api_key",
        "passport_callback_signer_api_key", "passport_callback_signer_bao_token",
    }
    physical_secret_root = physical_secret_path(
        model, "passport_callback_signer_bao_token").parent.resolve()
    approved_secret_names = physical_secrets | {"marty_db_password"}
    for secret_name, definition in model.get("secrets", {}).items():
        source = definition.get("file") if isinstance(definition, dict) else None
        physical_require(isinstance(source, str),
                         "Beta physical provider secret source is unverified")
        secret_path = Path(source).resolve()
        if secret_path == physical_secret_root or physical_secret_root in secret_path.parents:
            physical_require(secret_name in approved_secret_names
                             and secret_path.name == secret_name,
                             "Beta physical provider secret alias is forbidden")
    protected_values = [physical_secret(model, secret_name)
                        for secret_name in physical_secrets]
    config_definitions = model.get("configs", {})
    physical_require(isinstance(config_definitions, dict),
                     "Beta physical provider stack configs are invalid")
    volume_definitions = model.get("volumes", {})
    physical_require(isinstance(volume_definitions, dict),
                     "Beta physical provider stack volumes are invalid")
    evaluate_passport_policy("compose-physical-services", error_type=PassportConfigurationError,
                             model=model, protected_values=protected_values)
    for name, service in services.items():
        build = service.get("build")
        build_context = (build.get("context") if isinstance(build, dict) else build)
        if build_context:
            physical_require(isinstance(build_context, str),
                             "Beta physical provider build context is invalid")
            context_path = Path(build_context).resolve()
            physical_require(context_path != physical_secret_root
                             and context_path not in physical_secret_root.parents
                             and physical_secret_root not in context_path.parents,
                             "Beta physical provider secret root entered a build context")
        volumes = service.get("volumes", [])
        physical_require(isinstance(volumes, list),
                         "Beta physical provider service volume is invalid")
        for volume in volumes:
            physical_require(isinstance(volume, dict),
                             "Beta physical provider volume source is unverified")
            source = volume.get("source", "")
            kind = volume.get("type")
            if kind == "volume":
                physical_require(source in volume_definitions,
                                 "Beta physical provider named volume is undefined")
            if kind == "bind":
                physical_require(isinstance(source, str),
                                 "Beta physical provider bind source is unverified")
                bound_path = Path(source).resolve()
                physical_require(bound_path != physical_secret_root
                                 and physical_secret_root not in bound_path.parents
                                 and bound_path not in physical_secret_root.parents,
                                 "Beta physical secret root was bind-mounted")
            known_beta_canvas_config = is_known_beta_canvas_config(
                source, name, Path(__file__).resolve().parents[1])
            source_for_name_check = physical_source_for_name_check(
                source, kind, Path(__file__).resolve().parents[1])
            physical_require(known_beta_canvas_config
                             or is_known_openbao_bootstrap_file(
                                 source, name, Path(__file__).resolve().parents[1])
                             or not re.search(r"prod|production|selfhost",
                                              source_for_name_check,
                                              re.IGNORECASE),
                             "Beta physical provider stack references production volume")
        configs = service.get("configs", [])
        physical_require(isinstance(configs, list),
                         "Beta physical provider service configs are invalid")
        for config in configs:
            config_name = (config if isinstance(config, str) else
                           config.get("source") if isinstance(config, dict) else None)
            definition = config_definitions.get(config_name)
            path = definition.get("file") if isinstance(definition, dict) else None
            physical_require(isinstance(path, str),
                             "Beta physical provider config source is unverified")
            config_path = Path(path).resolve()
            physical_require(config_path != physical_secret_root
                             and physical_secret_root not in config_path.parents
                             and config_path not in physical_secret_root.parents,
                             "Beta physical secret root was mounted as config")
    evaluate_passport_policy("compose-physical-before-registry", error_type=PassportConfigurationError,
                             model=model)
    if provider_registry is None:
        try:
            provider_registry = json.loads(PHYSICAL_ALLOWLIST.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PassportConfigurationError("Beta physical provider approval is missing") from exc
    evaluate_passport_policy("compose-physical-after-registry", error_type=PassportConfigurationError,
                             model=model, provider_registry=provider_registry)
    for purpose, key_name in (("DSC", "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"),
                              ("CSCA", "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY")):
        credential = gateway[key_name]
        validate_mounted_sources(model, services, credential, purpose)
    secret_values = [physical_secret(model, name) for name in (
        "passport_physical_provider_api_key",
        "passport_callback_signer_api_key", "passport_callback_signer_bao_token",
    )]
    secret_paths = [physical_secret_path(model, name) for name in (
        "passport_physical_provider_api_key",
        "passport_callback_signer_api_key", "passport_callback_signer_bao_token",
        "marty_db_password",
    )]
    physical_require(len({path.resolve().parent for path in secret_paths}) == 1,
                     "Beta physical provider secrets must share one beta-only root")
    try:
        beta_db_password = secret_paths[-1].read_text(encoding="utf-8").strip()
        native_database = urlsplit(native.get("DATABASE_URL", ""))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PassportConfigurationError("Beta physical provider database binding is invalid") from exc
    physical_require(beta_db_password
                     and native_database.scheme == "postgresql"
                     and native_database.hostname == "postgres"
                     and native_database.port == 5432
                     and native_database.username == "marty"
                     and native_database.password == beta_db_password
                     and native_database.path == "/marty",
                     "Beta physical provider database binding is invalid")
    physical_require(len(set(secret_values)) == len(secret_values)
                     and all(value not in {
                         gateway["SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"],
                         gateway["SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"],
                         signing.get("SIGNING_KEYS_INTERNAL_API_KEY"),
                     } for value in secret_values),
                     "Beta physical provider credentials are reused")


def validate_model(model, *, passport_enabled, files, physical_provider=False,
                   provider_registry=None, prepared_services_image=None):
    mode = evaluate_passport_policy(
        "compose-beta-selection", error_type=PassportConfigurationError,
        passport_enabled=passport_enabled, physical_provider=physical_provider,
        prepared_services_image=prepared_services_image, files=[Path(path).name for path in files],
    )
    if mode == "physical":
        return validate_physical_model(model, files, provider_registry)
    evaluate_passport_policy("compose-beta-before-files", error_type=PassportConfigurationError,
                             model=model, passport_enabled=passport_enabled)
    if mode == "disabled":
        return
    services = model["services"]
    validate_file_operator_credentials(
        model, services, environment(services["gateway"]), environment(services["signing-keys"]),
        environment(services["passport-beta-bureau"]).get("SIGNING_KEYS_INTERNAL_API_KEY"),
    )
    evaluate_passport_policy("compose-beta-after-files", error_type=PassportConfigurationError,
                             model=model, prepared_services_image=prepared_services_image)


def validate_compose(
    *, project, env_files, files, passport_enabled, physical_provider=False,
    prepared_services_image=None,
    runner=subprocess.run, keycloak_validator=validate_keycloak_kms,
):
    command = ["docker", "compose", "--project-name", project]
    for path in env_files:
        command.extend(["--env-file", path])
    for path in files:
        command.extend(["--file", path])
    command.extend(["config", "--format", "json"])
    try:
        result = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if result.returncode or len(result.stdout) > MAX_MODEL_BYTES:
            raise PassportConfigurationError("Beta passport Compose validation failed")
        model = json.loads(result.stdout)
        keycloak_validator(model, check_files=True)
        validate_model(
            model, passport_enabled=passport_enabled, files=files,
            physical_provider=physical_provider,
            prepared_services_image=prepared_services_image,
        )
    except KeycloakKmsError as error:
        raise PassportConfigurationError(str(error)) from None
    except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
        raise PassportConfigurationError(
            "Beta passport Compose validation failed"
        ) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, choices=["elevenid-beta"])
    parser.add_argument("--env-file", action="append", required=True)
    parser.add_argument("--file", action="append", required=True)
    parser.add_argument("--passport-enabled", action="store_true")
    parser.add_argument("--physical-provider", action="store_true")
    parser.add_argument("--prepared-services-image", help="Exact caller-verified local services image ID; never a tag or an official release")
    args = parser.parse_args()
    try:
        validate_compose(
            project=args.project,
            env_files=args.env_file,
            files=args.file,
            passport_enabled=args.passport_enabled,
            physical_provider=args.physical_provider,
            prepared_services_image=args.prepared_services_image,
        )
    except PassportConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Beta passport configuration validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
