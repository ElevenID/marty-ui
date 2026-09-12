"""Read-only Compose merge and synthetic binding gates; never starts services."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import runpy
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BASE = "docker-compose.base.yml"
BETA = "docker-compose.beta.yml"
ISOLATION = "docker-compose.profile.conformance.yml"
LEGACY_AUTHCRYPT = "docker-compose.profile.didcomm-authcrypt.yml"
AUTHCRYPT = "docker-compose.profile.didcomm-native-authcrypt.yml"
CONFORMANCE = "docker-compose.profile.didcomm-native-conformance.yml"
POLICY_DIRECTORY = "${DIDCOMM_ENCRYPTION_POLICY_DIR:?set DIDCOMM_ENCRYPTION_POLICY_DIR to an exact policy directory}"
CA_DIRECTORY = (
    "${OIDF_TLS_CERT_DIR:?set OIDF_TLS_CERT_DIR to generated conformance material}"
)
POLICY_TARGET = "/run/secrets/didcomm-authcrypt"
CA_TARGET = "/run/secrets/didcomm-conformance-root-ca.pem"


def mount(source, target):
    return {
        "type": "bind",
        "source": source,
        "target": target,
        "read_only": True,
        "bind": {"create_host_path": False},
    }


def expected_model(baseline, *, authcrypt, conformance):
    expected = deepcopy(baseline)
    native = expected["services"]["issuance-native"]
    if authcrypt:
        native["environment"]["DIDCOMM_ENCRYPTION_POLICY_FILE"] = (
            POLICY_TARGET + "/didcomm-encryption-policy.json"
        )
        native.setdefault("volumes", []).append(mount(POLICY_DIRECTORY, POLICY_TARGET))
    if conformance:
        native["environment"].update(
            {
                "DIDCOMM_TLS_CA_FILE": CA_TARGET,
                "DIDCOMM_ALLOW_PRIVATE_IPS": "true",
            }
        )
        native.setdefault("volumes", []).append(
            mount(CA_DIRECTORY + "/root-ca.pem", CA_TARGET)
        )
        native["extra_hosts"] = ["host.docker.internal:host-gateway"]
    return expected


def assert_model(actual, expected):
    # Compare the entire model, including unrelated services and resource scopes.
    # Mount ordering is not semantic; each target must still be unique.
    def normalized(model):
        result = deepcopy(model)
        for service in result["services"].values():
            if "volumes" in service:
                mounts = service["volumes"]
                assert len({item["target"] for item in mounts}) == len(mounts)
                mounts.sort(key=lambda item: item["target"])
        return result

    assert normalized(actual) == normalized(expected), (
        "Native DIDComm configuration changed outside its exact boundary"
    )


def assert_native_policy_pairing(model):
    """Reject an authcrypt-capable legacy model paired with unconfigured native delivery.

    Call on a rendered model before selecting native DIDComm routes. This gate
    does not itself change the deployment runner or gateway route ownership.
    """
    services = model["services"]
    if "issuance-native" not in services:
        return
    legacy = services["issuance"]
    native = services["issuance-native"]
    policy = legacy["environment"].get("DIDCOMM_ENCRYPTION_POLICY_FILE")
    if not policy:
        return
    assert native["environment"].get("DIDCOMM_ENCRYPTION_POLICY_FILE") == policy, (
        "Configured legacy DIDComm encryption policy must also be configured for native delivery"
    )
    legacy_mounts = {item["target"]: item for item in legacy.get("volumes", [])}
    native_mounts = {item["target"]: item for item in native.get("volumes", [])}
    assert POLICY_TARGET in legacy_mounts and POLICY_TARGET in native_mounts
    previous, candidate = legacy_mounts[POLICY_TARGET], native_mounts[POLICY_TARGET]
    assert candidate["source"] == previous["source"], (
        "Native DIDComm policy source differs from legacy"
    )
    assert candidate["type"] == "bind" and candidate["read_only"] is True
    assert candidate["bind"]["create_host_path"] is False


def assert_bindings(model, compose_command):
    # Reuse the existing sanitized Compose interpolation harness. Only the
    # already-merged native environment/mount projection and synthetic values
    # are supplied; no deployment .env, credentials, database, or daemon is read.
    binding_owner = runpy.run_path(
        str(ROOT / "scripts/test_beta_application_image_compose.py")
    )
    native = model["services"]["issuance-native"]
    has_policy = "DIDCOMM_ENCRYPTION_POLICY_FILE" in native["environment"]
    has_ca = "DIDCOMM_TLS_CA_FILE" in native["environment"]
    projection = {
        "services": {
            "issuance-native": {
                "image": "synthetic.invalid/issuance-native:test",
                "environment": native["environment"],
                "volumes": native.get("volumes", []),
            }
        }
    }
    with tempfile.TemporaryDirectory(prefix="didcomm-config-binding-") as temporary:
        directory = Path(temporary)
        source = directory / "native.json"
        source.write_text(json.dumps(projection), encoding="utf-8")
        required = set(
            re.findall(r"\$\{([A-Z0-9_]+):\?", source.read_text(encoding="utf-8"))
        )
        values = {name: "synthetic-owned-value" for name in required}
        values.update(
            {
                "DIDCOMM_ENCRYPTION_POLICY_DIR": (directory / "policy").as_posix(),
                "OIDF_TLS_CERT_DIR": (directory / "tls").as_posix(),
            }
        )
        for name in ("policy", "tls"):
            (directory / name).mkdir()

        def render(overrides=None, omit=None):
            inputs = {**values, **(overrides or {})}
            if omit:
                inputs.pop(omit)
            (directory / "images.env").write_text(
                "\n".join(f"{name}={value}" for name, value in inputs.items()) + "\n",
                encoding="utf-8",
            )
            return binding_owner["render_binding"](directory, compose_command, source)

        default = render()["services"]["issuance-native"]
        environment = default["environment"]
        assert environment["UNIVERSAL_RESOLVER_URL"] == ""
        assert environment["DIDCOMM_DID_WEB_INTERNAL_BASE_URL"] == "http://gateway:8000"
        assert environment["DIDCOMM_ALLOW_PRIVATE_IPS"] == (
            "true" if has_ca else "false"
        )
        assert environment.get("DIDCOMM_ENCRYPTION_POLICY_FILE") == (
            POLICY_TARGET + "/didcomm-encryption-policy.json" if has_policy else None
        )
        assert environment.get("DIDCOMM_TLS_CA_FILE") == (CA_TARGET if has_ca else None)
        sources = {
            item["target"]: item["source"].replace("\\", "/")
            for item in default.get("volumes", [])
        }
        expected_sources = {}
        if has_policy:
            expected_sources[POLICY_TARGET] = values["DIDCOMM_ENCRYPTION_POLICY_DIR"]
        if has_ca:
            expected_sources[CA_TARGET] = values["OIDF_TLS_CERT_DIR"] + "/root-ca.pem"
        assert sources == expected_sources
        explicit = render(
            {
                "UNIVERSAL_RESOLVER_URL": "https://resolver.example/identifiers/",
                "DIDCOMM_DID_WEB_INTERNAL_BASE_URL": "http://managed-gateway:8000",
                "DIDCOMM_ALLOW_PRIVATE_IPS": "yes",
            }
        )["services"]["issuance-native"]["environment"]
        assert (
            explicit["UNIVERSAL_RESOLVER_URL"]
            == "https://resolver.example/identifiers/"
        )
        assert (
            explicit["DIDCOMM_DID_WEB_INTERNAL_BASE_URL"]
            == "http://managed-gateway:8000"
        )
        assert explicit["DIDCOMM_ALLOW_PRIVATE_IPS"] == ("true" if has_ca else "yes")
        for name in sorted(
            required & {"DIDCOMM_ENCRYPTION_POLICY_DIR", "OIDF_TLS_CERT_DIR"}
        ):
            try:
                render(omit=name)
            except subprocess.CalledProcessError as error:
                assert name in error.stderr
            else:
                raise AssertionError(
                    "Missing explicit DIDComm mount input was accepted"
                )


def run(compose_command=None):
    compose_command = compose_command or ["docker", "compose"]
    owner = runpy.run_path(str(ROOT / "scripts/test_canvas_worker_compose_render.py"))

    def render(*files):
        model = owner["render"](
            *files, project="synthetic-didcomm-config", compose_command=compose_command
        )
        for service in model["services"].values():
            if "environment" in service:
                service["environment"] = owner["environment_mapping"](
                    service["environment"]
                )
        return model

    base = render(BASE, BETA)
    native = base["services"]["issuance-native"]
    legacy = base["services"]["issuance"]
    for name in (
        "UNIVERSAL_RESOLVER_URL",
        "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
        "DIDCOMM_ALLOW_PRIVATE_IPS",
    ):
        assert native["environment"][name] == legacy["environment"][name]
    assert (
        native["environment"]["DIDCOMM_ALLOW_PRIVATE_IPS"]
        == "${DIDCOMM_ALLOW_PRIVATE_IPS:-false}"
    )
    for name in ("DIDCOMM_ENCRYPTION_POLICY_FILE", "DIDCOMM_TLS_CA_FILE"):
        assert name not in native["environment"]
    assert not native.get("volumes") and not native.get("extra_hosts")
    assert_bindings(base, compose_command)
    for authcrypt, conformance in ((True, False), (False, True), (True, True)):
        files = [BASE, BETA, *([ISOLATION] if conformance else [])]
        baseline = render(*files)
        overlays = [
            *([AUTHCRYPT] if authcrypt else []),
            *([CONFORMANCE] if conformance else []),
        ]
        actual = render(*files, *overlays)
        assert_model(
            actual,
            expected_model(baseline, authcrypt=authcrypt, conformance=conformance),
        )
        if authcrypt and conformance:
            assert_bindings(actual, compose_command)
    legacy = render(BASE, LEGACY_AUTHCRYPT, ISOLATION)
    assert "issuance-native" not in legacy["services"]
    assert_native_policy_pairing(legacy)
    unpaired = render(BASE, BETA, LEGACY_AUTHCRYPT)
    try:
        assert_native_policy_pairing(unpaired)
    except AssertionError:
        pass
    else:
        raise AssertionError(
            "Legacy-only authcrypt configuration allowed native anoncrypt"
        )
    paired = render(BASE, BETA, LEGACY_AUTHCRYPT, AUTHCRYPT)
    assert_model(paired, expected_model(unpaired, authcrypt=True, conformance=False))
    assert_native_policy_pairing(paired)
    print(
        "Native DIDComm Compose gates passed: exact merge ownership, synthetic bindings, missing-input rejection and legacy isolation"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-command", nargs="+", default=["docker", "compose"])
    run(parser.parse_args().compose_command)
