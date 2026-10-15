"""Rendered base-stack custody boundary; no Docker daemon or secret reads."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HTTPS_KMS = "https://openbao:8200"
PUBLIC_CA = "/bao/public-ca/ca.crt"
PINNED_PLUGIN = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "a" * 64
KMS_ROLES = {"openbao-tls-init", "openbao", "openbao-init"}
CLIENTS = {
    "db-migrate",
    "gateway",
    "notification",
    "signing-keys",
    "flow",
    "issuance",
    "canvas-sync-worker",
}
SCOPED_FILES = {
    "db-migrate": (
        "BAO_TOKEN_FILE",
        "/bao/bootstrap-token/token",
        "openbao_bootstrap_token",
    ),
    "notification": (
        "NOTIFICATION_OPENBAO_TOKEN_FILE",
        "/bao/notification/token",
        "openbao_notification",
    ),
    "signing-keys": (
        "BAO_TOKEN_FILE",
        "/bao/signing-keys-token/token",
        "openbao_signing_keys_token",
    ),
    "issuance": ("BAO_TOKEN_FILE", "/bao/service-token/token", "openbao_service_token"),
}


def environment(service):
    values = service.get("environment", {})
    return (
        dict(item.split("=", 1) for item in values if "=" in item)
        if isinstance(values, list)
        else values
    )


def mount(service, source, target, read_only):
    return any(
        entry.get("type") == "volume"
        and entry.get("source") == source
        and entry.get("target") == target
        and entry.get("read_only", False) is read_only
        for entry in service.get("volumes", [])
    )


def assert_https_graph(model):
    services = model["services"]
    assert KMS_ROLES <= set(services)
    node, tls_init, bootstrap = (
        services[name] for name in ("openbao", "openbao-tls-init", "openbao-init")
    )
    assert node["image"] == tls_init["image"] == bootstrap["image"]
    assert node["command"] == ["server", "-config=/bao/config/openbao.hcl"]
    assert (
        node["depends_on"]["openbao-tls-init"]["condition"]
        == "service_completed_successfully"
    )
    assert tls_init["entrypoint"] == ["/usr/local/bin/selfhost-tls-init"]
    assert bootstrap["entrypoint"] == ["/bin/sh", "/scripts/openbao-selfhost-init.sh"]
    assert bootstrap["depends_on"]["openbao"]["condition"] == "service_started"
    assert environment(bootstrap)["BAO_ADDR"] == HTTPS_KMS
    assert environment(bootstrap)["BAO_PUBLIC_CA_FILE"] == PUBLIC_CA
    assert environment(bootstrap)["DIDCOMM_KMS_PLUGIN_REQUIRED"] == "true"
    assert mount(bootstrap, "openbao_public_ca", "/bao/public-ca", False)
    for name in ("openbao", "openbao-tls-init", "openbao-init"):
        assert mount(services[name], "openbao_data", "/bao/data", False)

    for name, service in services.items():
        env = environment(service)
        assert "BAO_DEV_ROOT_TOKEN_ID" not in env
        if name not in KMS_ROLES:
            assert "BAO_TOKEN" not in env
            assert all(
                item.get("source") != "openbao_data"
                for item in service.get("volumes", [])
            )
        if name in CLIENTS or name == "issuance-native":
            assert env["BAO_ADDR"] == HTTPS_KMS
            assert env["BAO_CACERT"] == PUBLIC_CA
            assert mount(service, "openbao_public_ca", "/bao/public-ca", True)

    for name, (setting, path, volume) in SCOPED_FILES.items():
        assert environment(services[name])[setting] == path
        assert mount(
            services[name], volume, str(Path(path).parent).replace("\\", "/"), True
        )
    assert (
        environment(services["db-migrate"])["NOTIFICATION_OPENBAO_TOKEN_FILE"]
        == "/bao/notification/token"
    )
    assert mount(
        services["db-migrate"], "openbao_notification", "/bao/notification", True
    )
    assert (
        environment(services["notification"])["NOTIFICATION_OPENBAO_CA_CERT_FILE"]
        == PUBLIC_CA
    )
    if "issuance-native" in services:
        native = services["issuance-native"]
        env = environment(native)
        assert env["DIDCOMM_KMS_ADDR"] == HTTPS_KMS
        assert env["DIDCOMM_KMS_CA_CERT_FILE"] == PUBLIC_CA
        assert env["DIDCOMM_KMS_TOKEN_FILE"] == "/bao/didcomm-issuance-token/token"
        assert mount(
            native,
            "openbao_didcomm_issuance_token",
            "/bao/didcomm-issuance-token",
            True,
        )
    if "passport-callback-signer" in services:
        signer = services["passport-callback-signer"]
        signer_env = environment(signer)
        assert signer_env["BAO_ADDR"] == HTTPS_KMS
        assert signer_env["BAO_CACERT"] == PUBLIC_CA
        assert signer_env["BAO_TOKEN_FILE"] == "/bao/passport-callback/token"
        assert "BAO_TOKEN" not in signer_env
        assert mount(signer, "openbao_public_ca", "/bao/public-ca", True)
        assert mount(signer, "openbao_passport_callback", "/bao/passport-callback", True)
        assert (
            environment(bootstrap)["BAO_PASSPORT_CALLBACK_TOKEN_FILE"]
            == "/bao/passport-callback/token"
        )
        assert mount(bootstrap, "openbao_passport_callback", "/bao/passport-callback", False)
        assert signer["depends_on"]["openbao-init"]["condition"] == "service_completed_successfully"


def rendered(*profiles):
    command = ["docker", "compose", "-f", "docker-compose.base.yml"]
    for profile in profiles:
        command.extend(["-f", profile])
    command.extend(["config", "--format", "json"])
    selected = ("docker-compose.base.yml", *profiles)
    required = set()
    for name in selected:
        required.update(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", (ROOT / name).read_text()))
    env = {name: os.environ[name] for name in (
        "PATH", "SYSTEMROOT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        "HOME", "HOMEDRIVE", "HOMEPATH", "PROGRAMFILES", "PROGRAMFILES(X86)",
        "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG") if name in os.environ}
    env.update({name: "synthetic-required-value" for name in required})
    env["MARTY_RUNTIME_CONFIG_ROOT"] = str(ROOT)
    env["MARTY_OPENBAO_DIDCOMM_IMAGE"] = PINNED_PLUGIN
    env["MARTY_SERVICES_IMAGE"] = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64
    result = subprocess.run(
        command, cwd=ROOT, env=env, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    "profiles",
    [
        (),
        ("docker-compose.profile.issuance-native.yml",),
        (
            "docker-compose.profile.issuance-native.yml",
            "docker-compose.profile.issuance-native-authcrypt.yml",
        ),
        ("docker-compose.profile.ghcr.yml",),
        ("docker-compose.profile.passport-native-beta.yml",),
    ],
)
def test_rendered_base_graph_keeps_keys_inside_openbao(profiles):
    model = rendered(*profiles)
    assert_https_graph(model)
    if "docker-compose.profile.ghcr.yml" in profiles:
        for name in KMS_ROLES:
            service = model["services"][name]
            assert "build" not in service
            assert service["image"] == PINNED_PLUGIN


@pytest.mark.parametrize(
    "mutation", ["http", "root_token", "private_volume", "missing_ca"]
)
def test_graph_guard_rejects_custody_regressions(mutation):
    model = rendered("docker-compose.profile.issuance-native.yml")
    gateway = model["services"]["gateway"]
    gateway_environment = environment(gateway)
    if mutation == "http":
        gateway_environment["BAO_ADDR"] = "http://openbao:8200"
    elif mutation == "root_token":
        gateway_environment["BAO_TOKEN"] = "synthetic-root-token"
    elif mutation == "private_volume":
        gateway["volumes"].append({"source": "openbao_data", "target": "/bao/data"})
    else:
        gateway["volumes"] = [
            entry
            for entry in gateway["volumes"]
            if entry.get("source") != "openbao_public_ca"
        ]
    gateway["environment"] = gateway_environment
    with pytest.raises(AssertionError):
        assert_https_graph(model)
