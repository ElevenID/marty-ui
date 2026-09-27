"""Validate the opt-in beta passport Compose model without exposing secret data."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

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
PHYSICAL_INGRESS_URL = "http://passport-provider-ingress:8021"
PHYSICAL_SIGNER_URL = "http://passport-callback-signer-supported:8018/internal/documents"
PHYSICAL_ALLOWLIST = Path(__file__).resolve().parents[1] / "deploy-config/passport-beta-physical-provider-allowlist.json"


class PassportConfigurationError(ValueError):
    pass


def environment(service):
    value = service.get("environment")
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return dict(item.split("=", 1) for item in value if "=" in item)
    raise PassportConfigurationError("Invalid beta passport service environment")


def contains_credential(value, credential):
    if isinstance(value, str):
        return credential in value
    if isinstance(value, (list, tuple)):
        return any(contains_credential(item, credential) for item in value)
    if isinstance(value, dict):
        return any(
            contains_credential(item, credential)
            for pair in value.items()
            for item in pair
        )
    return False


def service_reuses_credential(service_name, service, credential, dedicated_name):
    for field, value in service.items():
        if field == "environment" and service_name in {"gateway", "signing-keys"}:
            value = {
                name: entry
                for name, entry in environment(service).items()
                if name != dedicated_name
            }
        if contains_credential(value, credential):
            return True
    return False


def valid_operator_credential(value):
    return (
        isinstance(value, str)
        and len(value) >= 32
        and value.strip() == value
        and not re.match(r"(?i)^(change[-_]?me|replace[-_]?me)", value)
    )


def validate_mounted_sources(model, services, credential, purpose):
    unavailable = (
        f"Beta {purpose} operator credential isolation cannot verify mounted files"
    )
    invalid = f"Beta {purpose} operator credential isolation is invalid"
    sources = []
    for secret in model.get("secrets", {}).values():
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
    selected = [Path(path).name for path in files]
    physical_require(set(selected) & {PROFILE, PHYSICAL_PROFILE, PROVIDER_BASE_PROFILE}
                     == PHYSICAL_PROFILES
                     and all(selected.count(name) == 1 for name in PHYSICAL_PROFILES),
                     "Beta physical provider profiles are incomplete or mixed with simulator")
    try:
        services = model["services"]
        physical_require(model.get("name") == "elevenid-beta",
                         "Beta physical provider Compose project is invalid")
        physical_require(isinstance(services, dict)
                         and "passport-beta-bureau" not in services
                         and "passport-callback-signer" not in services,
                         "Beta physical provider must not start the simulator")
        gateway = environment(services["gateway"])
        flow = environment(services["flow"])
        native = environment(services["issuance-native"])
        signing = environment(services["signing-keys"])
        signer_service = services["passport-callback-signer-supported"]
        signer = environment(signer_service)
        ingress_service = services["passport-provider-ingress"]
        ingress = environment(ingress_service)
    except (KeyError, TypeError) as exc:
        raise PassportConfigurationError("Beta physical provider services are incomplete") from exc
    networks = model.get("networks")
    physical_require(isinstance(networks, dict)
                     and isinstance(networks.get("passport-provider-signing"), dict)
                     and networks["passport-provider-signing"].get("internal") is True
                     and networks["passport-provider-signing"].get("name")
                     == "elevenid-beta_passport-provider-signing"
                     and isinstance(networks.get("marty-network"), dict)
                     and networks["marty-network"].get("name") == "elevenid-beta-network",
                     "Beta physical provider networks are not isolated")
    for service, expected in ((services["gateway"], {"marty-network"}),
                              (services["flow"], {"marty-network"}),
                              (services["issuance-native"], {"marty-network"}),
                              (services["signing-keys"], {"marty-network"}),
                              (signer_service, {"passport-provider-signing"}),
                              (ingress_service, {"marty-network", "passport-provider-signing"}),
                              (services.get("openbao", {}),
                               {"marty-network", "passport-provider-signing"})):
        actual = service.get("networks")
        physical_require(isinstance(actual, dict) and set(actual) == expected,
                         "Beta physical provider service network membership is invalid")
    for service in (services["gateway"], services["flow"],
                    services["issuance-native"], services["signing-keys"],
                    signer_service, ingress_service):
        physical_require(not any(service.get(field) for field in (
            "volumes", "configs", "privileged", "network_mode", "container_name", "volumes_from",
            "devices", "extra_hosts", "pid", "ipc", "cgroup_parent")),
            "Beta physical provider service escaped isolation")
        labels = service.get("labels", {})
        physical_require(isinstance(labels, dict)
                         and not any(key.startswith("com.docker.compose.") for key in labels),
                         "Beta physical provider callback service labels are invalid")
    for name in ("gateway", "flow", "signing-keys"):
        physical_require(not physical_secret_sources(services[name]),
                         "Beta physical provider core service gained a secret mount")
    physical_require(physical_secret_sources(services["issuance-native"])
                     == {"passport_physical_provider_api_key"},
                     "Beta physical provider native secret mounts are invalid")
    for service in (signer_service, ingress_service):
        physical_require(not any(service.get(field) for field in (
            "ports", "build", "entrypoint", "command")),
            "Beta physical provider callback service escaped isolation")
    for env, selector in ((gateway, "PASSPORT_NATIVE_GATEWAY_ENABLED"),
                          (flow, "PASSPORT_NATIVE_FLOW_ENABLED"),
                          (native, "PASSPORT_NATIVE_HTTP_ENABLED")):
        physical_require(str(env.get(selector, "false")).lower() == "true"
                         and str(env.get("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED", "false"))
                         .lower() == "true"
                         and not env.get("PASSPORT_TENANT_API_KEYS")
                         and not env.get("PASSPORT_TENANT_API_KEYS_FILE"),
                         "Beta physical provider Rust owner or internal auth is incomplete")
    physical_require(flow.get("ISSUANCE_NATIVE_SERVICE_URL")
                     == "http://issuance-native:8005"
                     and str(gateway.get("PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED", "false"))
                     .lower() == "true"
                     and gateway.get("PASSPORT_PROVIDER_INGRESS_SERVICE_URL")
                     == PHYSICAL_INGRESS_URL,
                     "Beta physical provider callback ingress route is invalid")
    physical_require(all(str(native.get(name, "false")).lower() == "true" for name in (
        "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED", "PASSPORT_KMS_ARTIFACTS_ENABLED",
        "PASSPORT_KMS_CALLBACKS_ENABLED"))
        and str(native.get("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "false")).lower() == "false"
        and not native.get("ICAO_DOCUMENT_SIGNER_URL"),
        "Beta physical provider KMS mode is incomplete")
    for name in PASSPORT_RAW_KEY_NAMES:
        physical_require(not native.get(name) and not native.get(f"{name}_FILE"),
                         "Beta physical provider raw key binding is forbidden")
    provider_url = native.get("PERSONALIZATION_BUREAU_URL")
    try:
        parsed = urlsplit(provider_url) if isinstance(provider_url, str) else None
    except ValueError as exc:
        raise PassportConfigurationError("Beta physical provider endpoint is invalid") from exc
    host = parsed.hostname if parsed else None
    physical_require(parsed is not None and parsed.scheme == "https"
                     and host is not None and "." in host
                     and not parsed.username and not parsed.password
                     and not parsed.query and not parsed.fragment
                     and not host.endswith((".test", ".example", ".invalid", ".localhost"))
                     and host not in {"localhost", "passport-beta-bureau", "127.0.0.1"},
                     "Beta physical provider endpoint must be an external HTTPS identity")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise PassportConfigurationError("Beta physical provider endpoint must use DNS")
    profile_id = native.get("PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID")
    physical_require(isinstance(profile_id, str)
                     and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}", profile_id)
                     and not re.search(r"simulator|mock|placeholder|beta-bureau", profile_id,
                                       flags=re.IGNORECASE)
                     and ingress.get("PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID") == profile_id,
                     "Beta physical provider profile identity is invalid")
    if provider_registry is None:
        try:
            provider_registry = json.loads(PHYSICAL_ALLOWLIST.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PassportConfigurationError("Beta physical provider approval is missing") from exc
    physical_require(isinstance(provider_registry, dict)
                     and provider_registry.get("schema")
                     == "marty.passport-beta-physical-provider-allowlist/v1"
                     and provider_registry.get("status") == "approved"
                     and provider_registry.get("providers") == [{
                         "endpoint": provider_url, "profile_id": profile_id,
                         "provider_kind": "physical", "environment": "beta",
                     }],
                     "Beta physical provider endpoint/profile lacks governed approval")
    physical_require(native.get("PERSONALIZATION_BUREAU_API_KEY") in (None, "")
                     and native.get("PERSONALIZATION_BUREAU_API_KEY_FILE")
                     == "/run/secrets/passport_physical_provider_api_key"
                     and not native.get("PERSONALIZATION_BUREAU_WEBHOOK_SECRET")
                     and not native.get("PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE")
                     and "passport_physical_provider_api_key" in
                     physical_secret_sources(services["issuance-native"]),
                     "Beta physical provider API credential must be file-backed")
    physical_require(signer.get("SERVICE_NAME") == "passport_callback_signer"
                     and signer.get("ENVIRONMENT") == "beta"
                     and str(signer.get("PASSPORT_CALLBACK_SIGNER_ENABLED", "false")).lower()
                     == "true"
                     and signer.get("SIGNING_KEYS_INTERNAL_API_KEY_FILE")
                     == "/run/secrets/passport_callback_signer_api_key"
                     and signer.get("BAO_TOKEN_FILE")
                     == "/run/secrets/passport_callback_signer_bao_token"
                     and signer.get("BAO_ADDR") == "http://openbao:8200"
                     and not any(signer.get(name) for name in (
                         "SIGNING_KEYS_INTERNAL_API_KEY", "BAO_TOKEN", "OPENBAO_SERVICE_TOKEN",
                         "OPENBAO_SERVICE_TOKEN_FILE"))
                     and physical_secret_sources(signer_service) == {
                         "passport_callback_signer_api_key",
                         "passport_callback_signer_bao_token"},
                     "Beta physical provider signer is not isolated")
    physical_require(ingress.get("SERVICE_NAME") == "passport_provider_ingress"
                     and str(ingress.get("PASSPORT_PROVIDER_INGRESS_ENABLED", "false")).lower()
                     == "true"
                     and ingress.get("PASSPORT_PROVIDER_SIGNER_URL") == PHYSICAL_SIGNER_URL
                     and ingress.get("PASSPORT_PROVIDER_NATIVE_CALLBACK_URL")
                     == PRIVATE_CALLBACK_URL
                     and ingress.get("PASSPORT_PROVIDER_SIGNER_API_KEY_FILE")
                     == "/run/secrets/passport_callback_signer_api_key"
                     and ingress.get("PASSPORT_PROVIDER_WEBHOOK_SECRET_FILE")
                     == "/run/secrets/passport_provider_webhook_secret"
                     and physical_secret_sources(ingress_service) == {
                         "passport_callback_signer_api_key",
                         "passport_provider_webhook_secret", "marty_db_password"},
                     "Beta physical provider callback ingress is invalid")
    physical_require(signing.get("ENVIRONMENT") == "beta"
                     and str(signing.get("SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED", "false"))
                     .lower() == "true"
                     and valid_operator_credential(gateway.get("SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"))
                     and valid_operator_credential(gateway.get("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"))
                     and gateway.get("SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY")
                     == signing.get("SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY")
                     and gateway.get("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY")
                     == signing.get("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY")
                     and gateway.get("SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY")
                     != gateway.get("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"),
                     "Beta physical provider operator credentials are invalid")
    physical_require(not any(service.get(name) for service in
                             (signer_service, ingress_service)
                             for name in ("ports", "build", "entrypoint", "command",
                                          "privileged", "network_mode")),
                     "Beta physical provider callback services are exposed")
    image = signer_service.get("image")
    physical_require(isinstance(image, str)
                     and re.fullmatch(r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}",
                                      image)
                     and ingress_service.get("image") == image,
                     "Beta physical provider callback image is not immutable")
    secret_values = [physical_secret(model, name) for name in (
        "passport_physical_provider_api_key", "passport_provider_webhook_secret",
        "passport_callback_signer_api_key", "passport_callback_signer_bao_token",
    )]
    secret_paths = [physical_secret_path(model, name) for name in (
        "passport_physical_provider_api_key", "passport_provider_webhook_secret",
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
                     and native_database.scheme == "postgresql+asyncpg"
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
                   provider_registry=None):
    if physical_provider:
        physical_require(passport_enabled,
                         "Beta physical provider requires native passport selection")
        return validate_physical_model(model, files, provider_registry)
    selected = sum(Path(path).name == PROFILE for path in files)
    if selected != int(passport_enabled):
        raise PassportConfigurationError(
            "Beta passport profile selection is inconsistent"
        )
    try:
        services = model["services"]
        targets = {
            name: services[name] for name in ("gateway", "flow", "issuance-native")
        }
        selectors = (
            ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED"),
            ("flow", "PASSPORT_NATIVE_FLOW_ENABLED"),
            ("issuance-native", "PASSPORT_NATIVE_HTTP_ENABLED"),
        )
        for service_name, flag in selectors:
            actual = str(environment(targets[service_name]).get(flag, "false")).lower()
            if actual != ("true" if passport_enabled else "false"):
                raise PassportConfigurationError(
                    "Beta passport owner selection is inconsistent"
                )
        if not passport_enabled:
            for service in services.values():
                env = (
                    environment(service)
                    if service.get("environment") is not None
                    else {}
                )
                if (
                    "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY" in env
                    or str(
                        env.get("SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED", "false")
                    ).lower()
                    == "true"
                ):
                    raise PassportConfigurationError(
                        "Beta CSCA ceremony selected without passport profile"
                    )
            if (
                "passport-beta-bureau" in services
                or "passport-callback-signer" in services
            ):
                raise PassportConfigurationError(
                    "Beta passport callback services selected without profile"
                )
            return
        bureau = services["passport-beta-bureau"]
        callback_signer = services["passport-callback-signer"]
        signing = environment(services["signing-keys"])
        if signing.get("ENVIRONMENT") != "beta":
            raise PassportConfigurationError(
                "Beta CSCA signing service must run with ENVIRONMENT=beta"
            )
        gateway = environment(targets["gateway"])
        flow = environment(targets["flow"])
        if flow.get("ISSUANCE_NATIVE_SERVICE_URL") != "http://issuance-native:8005":
            raise PassportConfigurationError("Beta passport Flow target is not native")
        for owner in targets.values():
            env = environment(owner)
            if (
                str(env.get("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED", "false")).lower()
                != "true"
            ):
                raise PassportConfigurationError(
                    "Beta passport internal handoff is incomplete"
                )
            if env.get("PASSPORT_TENANT_API_KEYS") or env.get(
                "PASSPORT_TENANT_API_KEYS_FILE"
            ):
                raise PassportConfigurationError(
                    "Beta passport tenant keyring is forbidden"
                )
        native = environment(targets["issuance-native"])
        for name in (
            "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
            "PASSPORT_KMS_ARTIFACTS_ENABLED",
            "PASSPORT_KMS_CALLBACKS_ENABLED",
        ):
            if str(native.get(name, "false")).lower() != "true":
                raise PassportConfigurationError("Beta passport KMS mode is incomplete")
        if (
            str(native.get("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "false")).lower()
            != "false"
        ):
            raise PassportConfigurationError(
                "Beta passport self-signed mode is forbidden"
            )
        if native.get("ICAO_DOCUMENT_SIGNER_URL"):
            raise PassportConfigurationError("Beta passport remote signer is forbidden")
        if native.get("PERSONALIZATION_BUREAU_URL") != PRIVATE_BUREAU_URL:
            raise PassportConfigurationError("Beta passport bureau target is invalid")
        for name in PASSPORT_RAW_KEY_NAMES:
            if native.get(name) or native.get(f"{name}_FILE"):
                raise PassportConfigurationError(
                    "Beta passport raw key binding is forbidden"
                )
        if native.get("PERSONALIZATION_BUREAU_API_KEY_FILE"):
            raise PassportConfigurationError(
                "Beta passport bureau key file is forbidden"
            )
        bureau_env = environment(bureau)
        database_url = bureau_env.get("DATABASE_URL")
        native_database_url = native.get("DATABASE_URL")
        if not (
            isinstance(database_url, str)
            and isinstance(native_database_url, str)
            and native_database_url.startswith("postgresql+asyncpg://")
            and database_url
            == native_database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
        ):
            raise PassportConfigurationError("Beta passport database target is invalid")
        database_target = urlsplit(database_url)
        if not (
            database_target.scheme == "postgresql"
            and database_target.hostname == "postgres"
            and database_target.port == 5432
            and database_target.path == "/marty"
            and database_target.username == "marty"
            and database_target.password
            and not database_target.query
            and not database_target.fragment
        ):
            raise PassportConfigurationError("Beta passport database target is invalid")
        signing_key = bureau_env.get("SIGNING_KEYS_INTERNAL_API_KEY")
        csca_flag = "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED"
        flag_holders = {
            name
            for name, service in services.items()
            if service.get("environment") is not None
            and csca_flag in environment(service)
        }
        if (
            flag_holders != {"signing-keys"}
            or str(signing.get(csca_flag)).lower() != "true"
        ):
            raise PassportConfigurationError("Beta CSCA ceremony selection is invalid")
        for purpose, key_name in (
            ("DSC", "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"),
            ("CSCA", "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"),
        ):
            credential = gateway.get(key_name)
            holders = {
                name
                for name, service in services.items()
                if service.get("environment") is not None
                and environment(service).get(key_name)
            }
            reused = isinstance(credential, str) and any(
                service_reuses_credential(service_name, service, credential, key_name)
                for service_name, service in services.items()
            )
            if not (
                valid_operator_credential(credential)
                and credential == signing.get(key_name)
                and credential != signing_key
                and holders == {"gateway", "signing-keys"}
                and not reused
                and all(
                    not environment(service).get(f"{key_name}_FILE")
                    for service in services.values()
                    if service.get("environment") is not None
                )
            ):
                raise PassportConfigurationError(
                    f"Beta {purpose} operator credential isolation is invalid"
                )
            validate_mounted_sources(model, services, credential, purpose)
        callback_signer_env = environment(callback_signer)
        if not (
            bureau_env.get("SERVICE_NAME") == "passport_beta_bureau"
            and bureau_env.get("ENVIRONMENT") == "beta"
            and str(bureau_env.get("PASSPORT_BETA_BUREAU_ENABLED", "false")).lower()
            == "true"
            and bureau_env.get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("GRPC_SERVICE_TOKEN")
            == native.get("PERSONALIZATION_BUREAU_API_KEY")
            and bureau_env.get("GRPC_SERVICE_TOKEN")
            == gateway.get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("GRPC_SERVICE_TOKEN") == flow.get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("GRPC_SERVICE_TOKEN") == native.get("GRPC_SERVICE_TOKEN")
            and signing_key
            and all(
                signing_key == owner.get("SIGNING_KEYS_INTERNAL_API_KEY")
                for owner in (native, gateway, signing)
            )
            and bureau_env.get("SIGNING_KEYS_INTERNAL_URL") == PRIVATE_SIGNING_URL
            and bureau_env.get("PASSPORT_BUREAU_CALLBACK_URL") == PRIVATE_CALLBACK_URL
        ):
            raise PassportConfigurationError(
                "Beta passport bureau identity or route is invalid"
            )
        if not (
            callback_signer_env.get("SERVICE_NAME") == "passport_callback_signer"
            and callback_signer_env.get("ENVIRONMENT") == "beta"
            and str(
                callback_signer_env.get("PASSPORT_CALLBACK_SIGNER_ENABLED", "false")
            ).lower()
            == "true"
            and str(callback_signer_env.get("SIGNING_KEYS_SERVICE_PORT")) == "8018"
            and callback_signer_env.get("SIGNING_KEYS_INTERNAL_API_KEY") == signing_key
            and callback_signer_env.get("BAO_ADDR") == "http://openbao:8200"
            and callback_signer_env.get("BAO_TOKEN")
            and callback_signer_env.get("BAO_TOKEN") == signing.get("BAO_TOKEN")
        ):
            raise PassportConfigurationError(
                "Beta callback signer configuration is invalid"
            )
        if not re.fullmatch(
            r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}",
            str(bureau.get("image", "")),
        ):
            raise PassportConfigurationError(
                "Beta passport bureau image must be immutable"
            )
        if callback_signer.get("image") != bureau.get("image"):
            raise PassportConfigurationError(
                "Beta callback signer image must be immutable"
            )
        if (
            bureau.get("ports")
            or bureau.get("secrets")
            or bureau.get("volumes")
            or bureau.get("build")
            or bureau.get("entrypoint")
            or bureau.get("command")
            or bureau.get("privileged")
            or bureau.get("network_mode")
        ):
            raise PassportConfigurationError(
                "Beta passport bureau exposure is forbidden"
            )
        if any(
            callback_signer.get(name)
            for name in (
                "ports",
                "secrets",
                "volumes",
                "build",
                "entrypoint",
                "command",
                "privileged",
                "network_mode",
            )
        ):
            raise PassportConfigurationError(
                "Beta callback signer exposure is forbidden"
            )
        networks = bureau.get("networks", {})
        if not isinstance(networks, dict) or set(networks) != {
            "marty-network",
            PRIVATE_SIGNING_NETWORK,
        }:
            raise PassportConfigurationError("Beta passport bureau network is invalid")
        isolated = model.get("networks", {}).get(PRIVATE_SIGNING_NETWORK, {})
        if isolated.get("internal") is not True:
            raise PassportConfigurationError(
                "Beta callback signer network is not internal"
            )
        members = {
            name
            for name, service in services.items()
            if PRIVATE_SIGNING_NETWORK in service.get("networks", {})
        }
        if members != {"openbao", "passport-beta-bureau", "passport-callback-signer"}:
            raise PassportConfigurationError(
                "Beta callback signer network membership is invalid"
            )
        if set(callback_signer.get("networks", {})) != {PRIVATE_SIGNING_NETWORK}:
            raise PassportConfigurationError("Beta callback signer network is invalid")
        forbidden = {
            "passport_tenant_api_keys",
            "physical_document_artifact_key",
            "icao_document_signer_api_key",
            "personalization_bureau_api_key",
            "personalization_bureau_webhook_secret",
        }
        if forbidden.intersection(model.get("secrets", {})):
            raise PassportConfigurationError(
                "Legacy passport secret mounts are forbidden"
            )
        for owner in (*targets.values(), bureau, callback_signer):
            if any(
                item.get("source") in forbidden
                for item in owner.get("secrets", [])
                if isinstance(item, dict)
            ):
                raise PassportConfigurationError(
                    "Legacy passport secret mounts are forbidden"
                )
    except PassportConfigurationError:
        raise
    except (KeyError, TypeError, AttributeError, OSError, ValueError):
        raise PassportConfigurationError(
            "Invalid beta passport Compose model"
        ) from None


def validate_compose(
    *, project, env_files, files, passport_enabled, physical_provider=False,
    runner=subprocess.run
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
        validate_model(
            json.loads(result.stdout), passport_enabled=passport_enabled, files=files,
            physical_provider=physical_provider
        )
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
    args = parser.parse_args()
    try:
        validate_compose(
            project=args.project,
            env_files=args.env_file,
            files=args.file,
            passport_enabled=args.passport_enabled,
            physical_provider=args.physical_provider,
        )
    except PassportConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Beta passport configuration validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
