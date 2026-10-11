"""Read-only Compose merge and synthetic binding gates; never starts services."""

from __future__ import annotations

import argparse
from copy import deepcopy
import difflib
import json
from pathlib import Path
import re
import runpy
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = runpy.run_path(str(ROOT / "scripts/validate_beta_didcomm_configuration.py"))
assert_native_kms_policy = VALIDATOR["assert_native_kms_policy"]
DidcommConfigurationError = VALIDATOR["DidcommConfigurationError"]
BASE = "docker-compose.base.yml"
BETA = "docker-compose.beta.yml"
ISOLATION = "docker-compose.profile.conformance.yml"
AUTHCRYPT = "docker-compose.profile.issuance-native-authcrypt.yml"
CONFORMANCE = "docker-compose.profile.didcomm-native-conformance.yml"
POLICY_DIRECTORY = "${DIDCOMM_ENCRYPTION_POLICY_DIR:?set DIDCOMM_ENCRYPTION_POLICY_DIR to an exact policy directory}"
CA_DIRECTORY = (
    "${OIDF_TLS_CERT_DIR:?set OIDF_TLS_CERT_DIR to generated conformance material}"
)
POLICY_TARGET = "/run/secrets/didcomm-authcrypt"
POLICY_FILE = POLICY_TARGET + "/didcomm-encryption-policy.json"
TOKEN_TARGET = "/run/secrets/didcomm-kms"
TOKEN_FILE = TOKEN_TARGET + "/openbao-token"
CA_TARGET = "/run/secrets/didcomm-conformance-root-ca.pem"
NATIVE_GRANT_MOUNTS = {
    ("openbao_issuance_credential_grant", "/bao/issuance-credential-grant"),
    ("openbao_issuance_canvas_grant", "/bao/issuance-canvas-grant"),
    ("openbao_issuance_readiness_grant", "/bao/issuance-readiness-grant"),
    ("openbao_issuance_passport_grant", "/bao/issuance-passport-grant"),
}
INITIATION_CONTROL_PLANE = {
    "ORG_GRPC_TARGET": "organization:9002",
    "CT_GRPC_TARGET": "credential-template:9003",
    "RP_GRPC_TARGET": "revocation-profile:9013",
    "CREDENTIAL_TEMPLATE_SERVICE_URL": "http://credential-template:8003",
}


def assert_initiation_consumer_bindings(model):
    services = model["services"]
    native = services["issuance-native"]
    legacy = services["issuance"]
    flow = services["flow"]
    for name, expected in INITIATION_CONTROL_PLANE.items():
        assert native["environment"][name] == legacy["environment"][name] == expected
    assert native["environment"]["ISSUANCE_GRPC_ENABLED"] == "true"
    assert native["environment"]["ISSUANCE_GRPC_PORT"] == "9005"
    assert flow["environment"]["ISSUANCE_GRPC_TARGET"] == "issuance-native:9005"
    assert flow["environment"]["ISSUANCE_SERVICE_URL"] == "http://issuance:8005"
    assert (
        flow["environment"]["GRPC_SERVICE_TOKEN"]
        == native["environment"]["GRPC_SERVICE_TOKEN"]
        == legacy["environment"]["GRPC_SERVICE_TOKEN"]
    )
    assert native["healthcheck"]["test"] == [
        "CMD",
        "curl",
        "--fail",
        "http://localhost:8005/health",
    ]
    assert native["depends_on"]["issuance-migrations"]["condition"] == (
        "service_completed_successfully"
    )
    assert native["depends_on"]["postgres"]["condition"] == "service_healthy"


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
        native["environment"].update(
            {
                "DIDCOMM_ENCRYPTION_POLICY_FILE": POLICY_FILE,
                "DIDCOMM_KMS_ADDR": "http://openbao:8200",
                "DIDCOMM_KMS_TOKEN_FILE": TOKEN_FILE,
            }
        )
        native.setdefault("volumes", []).extend(
            (
                mount(
                    POLICY_DIRECTORY + "/didcomm-encryption-policy.json", POLICY_FILE
                ),
                {
                    "type": "volume",
                    "source": "didcomm_issuance_token",
                    "target": TOKEN_TARGET,
                    "read_only": True,
                },
            )
        )
        native.setdefault("depends_on", {})["openbao-init"] = {
            "condition": "service_completed_successfully",
            "required": True,
        }
        image = "${MARTY_OPENBAO_DIDCOMM_IMAGE:?set MARTY_OPENBAO_DIDCOMM_IMAGE to the reviewed plugin image digest}"
        openbao = expected["services"]["openbao"]
        openbao["image"] = image
        openbao["command"] = [
            "server",
            "-dev",
            "-config",
            "/bao/config/didcomm-plugin.hcl",
        ]
        openbao["volumes"].append(
            mount("./docker/openbao-didcomm-dev.hcl", "/bao/config/didcomm-plugin.hcl")
        )
        bootstrap = expected["services"]["openbao-init"]
        bootstrap["image"] = image
        bootstrap["environment"]["DIDCOMM_KMS_PLUGIN_REQUIRED"] = "true"
        bootstrap["environment"]["DIDCOMM_ISSUANCE_TOKEN_FILE"] = (
            "/run/didcomm-token/openbao-token"
        )
        bootstrap["volumes"].append(
            {
                "type": "volume",
                "source": "didcomm_issuance_token",
                "target": "/run/didcomm-token",
            }
        )
        expected.setdefault("volumes", {})["didcomm_issuance_token"] = {
            "name": "synthetic-didcomm-config_didcomm_issuance_token"
        }
        expected["x-native-issuance-policy"] = {
            "environment": {
                "DIDCOMM_ENCRYPTION_POLICY_FILE": POLICY_FILE,
                "DIDCOMM_KMS_ADDR": "http://openbao:8200",
                "DIDCOMM_KMS_TOKEN_FILE": TOKEN_FILE,
            },
            "volumes": [
                mount(
                    POLICY_DIRECTORY + "/didcomm-encryption-policy.json", POLICY_FILE
                ),
                {
                    "type": "volume",
                    "source": "didcomm_issuance_token",
                    "target": TOKEN_TARGET,
                    "read_only": True,
                },
            ],
        }
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
                targets = [item["target"] for item in mounts if isinstance(item, dict)]
                assert len(set(targets)) == len(targets)
                mounts.sort(
                    key=lambda item: item["target"] if isinstance(item, dict) else item
                )
        return result

    actual = normalized(actual)
    expected = normalized(expected)
    assert actual == expected, "".join(
        difflib.unified_diff(
            json.dumps(expected, sort_keys=True, indent=2).splitlines(keepends=True),
            json.dumps(actual, sort_keys=True, indent=2).splitlines(keepends=True),
            fromfile="expected",
            tofile="actual",
        )
    )


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
            },
            # Only synthetic interpolation inputs are used for these ports.
            # Preserve the real merged consumer and legacy expressions too.
            **{
                name: {
                    "image": "synthetic.invalid/unused:test",
                    "environment": {
                        key: model["services"][name]["environment"][key] for key in keys
                    },
                }
                for name, keys in {
                    "flow": (
                        "ISSUANCE_GRPC_TARGET",
                        "ISSUANCE_SERVICE_URL",
                        "GRPC_SERVICE_TOKEN",
                    ),
                    "issuance": (
                        "VCDM_RELATED_RESOURCE_URLS",
                        "GRPC_SERVICE_TOKEN",
                        "CANVAS_CREDENTIALS_STATUS_SYNC_URL",
                    ),
                }.items()
            },
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
                "MARTY_OPENBAO_DIDCOMM_IMAGE": "synthetic.invalid/openbao-didcomm@sha256:"
                + "d" * 64,
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

        default_model = render()
        default = default_model["services"]["issuance-native"]
        environment = default["environment"]
        assert environment["CANVAS_CREDENTIALS_STATUS_SYNC_URL"] == ""
        assert (
            default_model["services"]["issuance"]["environment"][
                "CANVAS_CREDENTIALS_STATUS_SYNC_URL"
            ]
            == ""
        )
        assert environment["VCDM_RELATED_RESOURCE_URLS"] == ""
        assert (
            default_model["services"]["issuance"]["environment"][
                "VCDM_RELATED_RESOURCE_URLS"
            ]
            == ""
        )
        for name, expected in INITIATION_CONTROL_PLANE.items():
            assert environment[name] == expected
        flow = default_model["services"]["flow"]["environment"]
        assert flow["ISSUANCE_GRPC_TARGET"] == "issuance-native:9005"
        assert flow["ISSUANCE_SERVICE_URL"] == "http://issuance:8005"
        assert flow["GRPC_SERVICE_TOKEN"] == environment["GRPC_SERVICE_TOKEN"]
        assert environment["ISSUANCE_OFFER_TTL_MINUTES"] == "10080"
        assert environment["UNIVERSAL_RESOLVER_URL"] == ""
        assert environment["DIDCOMM_DID_WEB_INTERNAL_BASE_URL"] == "http://gateway:8000"
        assert environment["DIDCOMM_ALLOW_PRIVATE_IPS"] == (
            "true" if has_ca else "false"
        )
        assert environment.get("DIDCOMM_ENCRYPTION_POLICY_FILE") == (
            POLICY_FILE if has_policy else None
        )
        assert environment.get("DIDCOMM_KMS_ADDR") == (
            "http://openbao:8200" if has_policy else None
        )
        assert environment.get("DIDCOMM_KMS_TOKEN_FILE") == (
            TOKEN_FILE if has_policy else None
        )
        assert environment.get("DIDCOMM_TLS_CA_FILE") == (CA_TARGET if has_ca else None)
        sources = {
            item["target"]: item["source"].replace("\\", "/")
            for item in default.get("volumes", [])
        }
        expected_sources = {target: source for source, target in NATIVE_GRANT_MOUNTS}
        if has_policy:
            expected_sources[POLICY_FILE] = (
                values["DIDCOMM_ENCRYPTION_POLICY_DIR"]
                + "/didcomm-encryption-policy.json"
            )
            expected_sources[TOKEN_TARGET] = "didcomm_issuance_token"
        if has_ca:
            expected_sources[CA_TARGET] = values["OIDF_TLS_CERT_DIR"] + "/root-ca.pem"
        assert sources == expected_sources
        explicit = render(
            {
                "UNIVERSAL_RESOLVER_URL": "https://resolver.example/identifiers/",
                "DIDCOMM_DID_WEB_INTERNAL_BASE_URL": "http://managed-gateway:8000",
                "DIDCOMM_ALLOW_PRIVATE_IPS": "yes",
                "ISSUANCE_OFFER_TTL_MINUTES": "1_440",
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
        assert explicit["ISSUANCE_OFFER_TTL_MINUTES"] == "1_440"
        for resources in (
            "",
            "https://resources.example/context.json",
            "https://resources.example/a.json,https://resources.example/b.json",
        ):
            configured = render({"VCDM_RELATED_RESOURCE_URLS": resources})["services"]
            assert (
                configured["issuance-native"]["environment"][
                    "VCDM_RELATED_RESOURCE_URLS"
                ]
                == configured["issuance"]["environment"]["VCDM_RELATED_RESOURCE_URLS"]
                == resources
            )
        for status_url in ("", "https://canvas-mirror.example/status?mode=synthetic"):
            configured = render({"CANVAS_CREDENTIALS_STATUS_SYNC_URL": status_url})[
                "services"
            ]
            assert (
                configured["issuance-native"]["environment"][
                    "CANVAS_CREDENTIALS_STATUS_SYNC_URL"
                ]
                == configured["issuance"]["environment"][
                    "CANVAS_CREDENTIALS_STATUS_SYNC_URL"
                ]
                == status_url
            )
        for minutes in ("0", "-5"):
            configured = render({"ISSUANCE_OFFER_TTL_MINUTES": minutes})
            assert (
                configured["services"]["issuance-native"]["environment"][
                    "ISSUANCE_OFFER_TTL_MINUTES"
                ]
                == minutes
            )
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
    assert_initiation_consumer_bindings(base)
    native = base["services"]["issuance-native"]
    legacy = base["services"]["issuance"]
    for name in (
        "ISSUANCE_OFFER_TTL_MINUTES",
        "VCDM_RELATED_RESOURCE_URLS",
        "CANVAS_CREDENTIALS_STATUS_SYNC_URL",
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
    assert {
        (item["source"], item["target"])
        for item in native.get("volumes", [])
        if item.get("type") == "volume" and item.get("read_only") is True
    } == NATIVE_GRANT_MOUNTS
    assert len(native["volumes"]) == len(NATIVE_GRANT_MOUNTS)
    assert not native.get("extra_hosts")
    assert_bindings(base, compose_command)
    for authcrypt, conformance in ((True, False), (False, True), (True, True)):
        files = [BASE, BETA, *([ISOLATION] if conformance else [])]
        baseline = render(*files)
        overlays = [
            *([AUTHCRYPT] if authcrypt else []),
            *([CONFORMANCE] if conformance else []),
        ]
        actual = render(*files, *overlays)
        assert_initiation_consumer_bindings(actual)
        assert_model(
            actual,
            expected_model(baseline, authcrypt=authcrypt, conformance=conformance),
        )
        if authcrypt and conformance:
            assert_bindings(actual, compose_command)
    native_authcrypt = render(BASE, BETA, AUTHCRYPT)
    assert_model(
        native_authcrypt, expected_model(base, authcrypt=True, conformance=False)
    )
    assert (
        "DIDCOMM_ENCRYPTION_POLICY_FILE"
        not in native_authcrypt["services"]["issuance"]["environment"]
    )
    image_owner = runpy.run_path(
        str(ROOT / "scripts/test_beta_application_image_compose.py")
    )
    with tempfile.TemporaryDirectory(prefix="didcomm-generated-images-") as temporary:
        directory = Path(temporary)
        reports = image_owner["exercise"](
            directory,
            [image_owner["inputs"]("local"), image_owner["inputs"]("official")],
        )
        for mode, report in zip(("local", "official"), reports, strict=True):
            overlay = directory / f"{mode}-images.yml"
            overlay.write_text("\n".join(report["lines"]) + "\n", encoding="utf-8")
            actual = render(BASE, BETA, AUTHCRYPT, str(overlay))
            assert_model(
                actual,
                image_owner["expected_model"](
                    native_authcrypt, report["services"], mode
                ),
            )
            assert_native_kms_policy(actual)
    print(
        "Native DIDComm Compose gates passed: exact KMS-only merge ownership and synthetic bindings"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-command", nargs="+", default=["docker", "compose"])
    run(parser.parse_args().compose_command)
