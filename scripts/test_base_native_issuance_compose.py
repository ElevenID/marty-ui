"""Read-only general-base opt-in configuration gate; never runtime acceptance.

Only actual Compose rendering and synthetic inputs are used. No daemon, policy
contents, operator env file, image pull, container or deployment is accessed.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import runpy
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
BIND = runpy.run_path(str(ROOT / "scripts/test_beta_application_image_compose.py"))
NATIVE = runpy.run_path(str(ROOT / "scripts/conformance_native.py"))
POLICY = NATIVE["POLICY"]
EXTRACTION = runpy.run_path(str(ROOT / "scripts/test_conformance_native_compose.py"))
PROFILE = "docker-compose.profile.issuance-native.yml"
POLICY_PROFILE = "docker-compose.profile.issuance-native-authcrypt.yml"
IMAGES = "docker-compose.profile.issuance-native-images.yml"
RUNTIME = EXTRACTION["RUNTIME"]
PROJECT = "marty-base-native-render"
IMAGE = "synthetic.invalid/services@sha256:" + "a" * 64

# These are the ONLY added native environment bindings. Every other native
# expression is identical to the independently read existing base issuance map.
NATIVE_ONLY = {
    "GRPC_SERVICE_TOKEN": "${GRPC_SERVICE_TOKEN:-dev-grpc-service-token-change-before-production}",
    "SERVICE_NAME": "issuance_native",
    "ENVIRONMENT": "${ENVIRONMENT:-development}",
    "ISSUANCE_GRPC_ENABLED": "true",
    "MARTY_RELEASE_VERSION": "${MARTY_RELEASE_VERSION:-development}",
    "MARTY_UI_SHA": "${MARTY_UI_SHA:-unknown}",
    "RUST_LOG": "${ISSUANCE_NATIVE_RUST_LOG:-info}",
}
# Exact base legacy-only settings remain on the old owner; no wildcard copying
# of KMS/physical-document/worker secrets into the partial native owner.
LEGACY_ONLY = frozenset(
    """
BAO_ADDR BAO_TOKEN CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS
CANVAS_CREDENTIALS_PROVENANCE_BASE_URL CANVAS_CREDENTIALS_RECIPIENT_HASHED
CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS CANVAS_LTI_TOOL_ACTIVE_KID
CANVAS_LTI_TOOL_PUBLIC_JWKS ICAO_DOCUMENT_SIGNER_API_KEY ICAO_DOCUMENT_SIGNER_URL
ISSUANCE_AUTH_SESSION_TTL_MINUTES PERSONALIZATION_BUREAU_API_KEY
PERSONALIZATION_BUREAU_URL PERSONALIZATION_BUREAU_WEBHOOK_SECRET
PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED PHYSICAL_DOCUMENT_ARTIFACT_KEY
""".split()
)
# Exhaustive source-input inventory exclusions, each explained in the companion
# document. "Unforwarded" is NOT "unsupported" or "native-only".
UNFORWARDED_LEGACY = frozenset(
    """
APP_ENV CANVAS_ADMIN_API_TOKEN CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK
CANVAS_CREDENTIALS_BASE_URL CANVAS_CREDENTIALS_PUBLISH_TIMEOUT_SECONDS
CANVAS_CREDENTIALS_REVOKE_URL_TEMPLATE CANVAS_CREDENTIALS_STATUS_SYNC_TIMEOUT_SECONDS
CANVAS_CREDENTIALS_VALIDATE_URL_TEMPLATE CANVAS_LTI_DEEP_LINKING_ISSUER
CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES
CORS_ALLOWED_ORIGINS DIDCOMM_UNIVERSAL_RESOLVER_URL ISSUER_DISPLAY_NAME
TOKEN_RATE_WINDOW VCDM_RELATED_RESOURCE_MAX_BYTES VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS
INTEGRATION_SECRET_MASTER_KEY_ENV
""".split()
)
EXPLICIT_MOUNTS = frozenset({"DIDCOMM_ENCRYPTION_POLICY_FILE", "DIDCOMM_TLS_CA_FILE"})
FILE_SELECTORS = frozenset(
    {
        "CANVAS_CREDENTIALS_API_TOKEN_FILE",
        "CANVAS_CREDENTIALS_SHARED_SECRET_FILE",
        "GRPC_SERVICE_TOKEN_FILE",
    }
)
NATIVE_CONFIG_META = frozenset({"CARGO_PKG_VERSION", "MARTY_ISSUANCE__"})


def source(path):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def readiness_default():
    text = (ROOT / "rust/services/gateway/src/config.rs").read_text(encoding="utf-8")
    matches = re.findall(
        r"const DEFAULT_READY_SERVICES: &\[&str\] = &\[(.*?)\];", text, re.S
    )
    assert len(matches) == 1, "Gateway readiness default must remain explicit"
    members = re.findall(r'"([a-z-]+)"', matches[0])
    assert members and len(members) == len(set(members))
    return members


def assert_sources(base, profile, runtime):
    legacy = base["services"]["issuance"]["environment"]
    native = profile["services"]["issuance-native"]
    env = native["environment"]
    assert set(legacy) - set(env) == LEGACY_ONLY
    assert set(env) - set(legacy) == set(NATIVE_ONLY)
    assert {key: env[key] for key in NATIVE_ONLY} == NATIVE_ONLY
    for key in set(env) & set(legacy):
        assert env[key] == legacy[key], "Native expression changed legacy precedence"
    assert (
        "GATEWAY_REQUIRED_READY_SERVICES"
        not in base["services"]["gateway"]["environment"]
    )
    edge = profile["services"]["gateway"]
    assert edge["environment"] == {
        "GRPC_SERVICE_TOKEN": base["services"]["auth"]["environment"][
            "GRPC_SERVICE_TOKEN"
        ],
        "ISSUANCE_NATIVE_SERVICE_URL": NATIVE["NATIVE_URL"],
        "GATEWAY_REQUIRED_READY_SERVICES": ",".join(
            [*readiness_default(), "issuance-native"]
        ),
    }
    assert set(profile) == {"services", "x-native-issuance-grpc-auth"}
    assert set(profile["services"]) == {"issuance-native", *NATIVE["TOKEN_CONSUMERS"]}
    for name in set(NATIVE["TOKEN_CONSUMERS"]) - {"gateway"}:
        assert profile["services"][name] == {
            "environment": {"GRPC_SERVICE_TOKEN": NATIVE_ONLY["GRPC_SERVICE_TOKEN"]}
        }
    assert native["extends"] == {"file": RUNTIME, "service": "issuance-native"}
    assert set(native) == {
        "extends",
        "entrypoint",
        "command",
        "environment",
        "networks",
    }
    EXTRACTION["complete_common"](source(EXTRACTION["COMMON"]), runtime)
    text = (
        (ROOT / "rust/services/issuance/src/config.rs")
        .read_text(encoding="utf-8")
        .split("#[cfg(test)]")[0]
    )
    inputs = set(re.findall(r'"([A-Z][A-Z0-9_]+)"', text))
    omitted = UNFORWARDED_LEGACY | EXPLICIT_MOUNTS | FILE_SELECTORS | NATIVE_CONFIG_META
    assert inputs - set(env) == omitted, (
        "Update the exhaustive native configuration inventory"
    )
    assert not any(":?" in str(value) for value in env.values()), (
        "Beta required inputs leaked"
    )


def expected_model(baseline, *, local, authcrypt, inputs, policy_directory):
    """Independent closed delta; no observed native field is copied into it."""
    legacy = baseline["services"]["issuance"]["environment"]
    token = (
        inputs.get("GRPC_SERVICE_TOKEN")
        or "dev-grpc-service-token-change-before-production"
    )
    env = {key: value for key, value in legacy.items() if key not in LEGACY_ONLY}
    env.update(
        {
            "GRPC_SERVICE_TOKEN": token,
            "SERVICE_NAME": "issuance_native",
            "ENVIRONMENT": inputs.get("ENVIRONMENT") or "development",
            "ISSUANCE_GRPC_ENABLED": "true",
            "MARTY_RELEASE_VERSION": inputs.get("MARTY_RELEASE_VERSION")
            or "development",
            "MARTY_UI_SHA": inputs.get("MARTY_UI_SHA") or "unknown",
            "RUST_LOG": inputs.get("ISSUANCE_NATIVE_RUST_LOG") or "info",
        }
    )
    expected_native = {
        "command": [],
        "entrypoint": ["/app/services/entrypoint.sh"],
        "environment": env,
        "depends_on": {
            name: {"condition": condition, "required": True}
            for name, condition in (
                ("issuance-migrations", "service_completed_successfully"),
                ("postgres", "service_healthy"),
                ("signing-keys", "service_healthy"),
                ("revocation-profile", "service_healthy"),
            )
        },
        "healthcheck": {
            "test": ["CMD", "curl", "--fail", "http://localhost:8005/health"],
            "interval": "10s",
            "timeout": "5s",
            "retries": 3,
        },
        "networks": {"marty-network": None},
        "restart": "unless-stopped",
    }
    if local:
        expected_native["build"] = {
            "context": ".",
            "dockerfile": "services/Dockerfile",
            "args": {"SERVICE_NAME": "issuance-native"},
        }
    else:
        expected_native.update(image=IMAGE, pull_policy="always")
    expected = deepcopy(baseline)
    expected["services"]["issuance-native"] = expected_native
    for name in NATIVE["TOKEN_CONSUMERS"]:
        expected["services"][name]["environment"]["GRPC_SERVICE_TOKEN"] = token
    edge = expected["services"]["gateway"]
    edge["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] = NATIVE["NATIVE_URL"]
    edge["environment"]["GATEWAY_REQUIRED_READY_SERVICES"] = ",".join(
        [*readiness_default(), "issuance-native"]
    )
    edge["depends_on"]["issuance-native"] = {
        "condition": "service_healthy",
        "required": True,
    }
    expected["x-native-issuance-grpc-auth"] = {"GRPC_SERVICE_TOKEN": token}
    if authcrypt:
        assert policy_directory.is_dir(), "Explicit policy directory must already exist"
        policy = {
            "environment": {
                "DIDCOMM_ENCRYPTION_POLICY_FILE": POLICY["POLICY_TARGET"]
                + "/didcomm-encryption-policy.json"
            },
            "volumes": [
                {
                    "type": "bind",
                    "source": policy_directory.as_posix(),
                    "target": POLICY["POLICY_TARGET"],
                    "read_only": True,
                    "bind": {"create_host_path": False},
                }
            ],
        }
        for name in ("issuance", "issuance-native"):
            service = expected["services"][name]
            service["environment"].update(policy["environment"])
            service["volumes"] = [
                *service.get("volumes", []),
                *deepcopy(policy["volumes"]),
            ]
        expected["x-native-issuance-policy"] = policy
    return expected


def assert_model(baseline, actual, *, local, authcrypt, inputs, policy_directory):
    """Complete model equality plus independently derived native service model."""
    expected = expected_model(
        baseline,
        local=local,
        authcrypt=authcrypt,
        inputs=inputs,
        policy_directory=policy_directory,
    )
    assert actual == expected, (
        "Native opt-in changed an unowned field or required binding"
    )
    POLICY["validate_model"](actual, authcrypt_enabled=authcrypt)
    assert (
        actual["services"]["flow"]["environment"]["ISSUANCE_GRPC_TARGET"]
        == "issuance:9005"
    )
    assert (
        actual["services"]["flow"]["environment"]["ISSUANCE_SERVICE_URL"]
        == NATIVE["LEGACY_URL"]
    )
    assert (
        actual["services"]["gateway"]["environment"]["ISSUANCE_SERVICE_URL"]
        == NATIVE["LEGACY_URL"]
    )
    # No profile-provided permissive network policy or synthetic conformance CA.
    env = actual["services"]["issuance-native"]["environment"]
    assert "DIDCOMM_TLS_CA_FILE" not in env
    assert (
        env["DIDCOMM_ALLOW_PRIVATE_IPS"]
        == baseline["services"]["issuance"]["environment"]["DIDCOMM_ALLOW_PRIVATE_IPS"]
    )


def files(*, native, local, authcrypt):
    result = [ROOT / "docker-compose.base.yml"]
    if not local:
        result.append(ROOT / "docker-compose.profile.ghcr.yml")
    if native:
        result.append(ROOT / PROFILE)
        if not local:
            result.append(ROOT / IMAGES)
        if authcrypt:
            result.append(ROOT / POLICY_PROFILE)
    return result


def run(command):
    assert_sources(source("docker-compose.base.yml"), source(PROFILE), source(RUNTIME))
    NATIVE["validate_capabilities"](
        json.loads((ROOT / NATIVE["CAPABILITY_PATH"]).read_text())
    )
    with tempfile.TemporaryDirectory(prefix="base-native-render-") as temporary:
        directory = Path(temporary)
        policy_directory = directory / "explicit-policy"
        policy_directory.mkdir()
        required = {
            key: "synthetic-required-artifact"
            for key in re.findall(
                r"\$\{([A-Z0-9_]+):\?", (ROOT / "docker-compose.base.yml").read_text()
            )
        }
        profile_text = json.dumps(source(PROFILE))
        variables = set(re.findall(r"\$\{([A-Z0-9_]+):-", profile_text))
        custom = {key: "synthetic-custom" for key in variables}
        # These host inputs have no base-container binding. Exercise that
        # distinction rather than silently forwarding them into native only.
        custom.update(
            dict.fromkeys(
                UNFORWARDED_LEGACY | FILE_SELECTORS | EXPLICIT_MOUNTS,
                "synthetic-unforwarded",
            )
        )
        # Synthetic interpolation controls are not application-validity claims.
        # Later runtime acceptance must supply valid typed inputs of its own.
        custom.update(
            {
                "PUBLIC_API_URL": "https://issuer.synthetic.example",
                "UI_BASE_URL": "https://ui.synthetic.example",
                "GRPC_SERVICE_TOKEN": "synthetic-paired-012345678901234567890123456789",
                "TOKEN_HMAC_KEY": "synthetic-hmac-012345678901234567890123456789",
                "INTEGRATION_SECRET_MASTER_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "ISSUANCE_OFFER_TTL_MINUTES": "90",
                "TOKEN_RATE_LIMIT": "1200",
                "DIDCOMM_ALLOW_PRIVATE_IPS": "false",
            }
        )
        for mode, overrides in (
            ("default", {}),
            ("empty", dict.fromkeys(variables, "")),
            ("custom", custom),
        ):
            inputs = {
                **required,
                "MARTY_SERVICES_IMAGE": IMAGE,
                "MARTY_UI_IMAGE": "synthetic.invalid/ui@sha256:" + "b" * 64,
                "MARTY_MIGRATIONS_IMAGE": "synthetic.invalid/migrations@sha256:"
                + "c" * 64,
                "DIDCOMM_ENCRYPTION_POLICY_DIR": policy_directory.as_posix(),
                **overrides,
            }
            (directory / "images.env").write_text(
                "".join(f"{k}={v}\n" for k, v in sorted(inputs.items())),
                encoding="utf-8",
            )
            for local in (True, False):
                baseline = BIND["render_binding"](
                    directory,
                    command,
                    *files(native=False, local=local, authcrypt=False),
                    project=PROJECT,
                )
                for authcrypt in (False, True):
                    actual = BIND["render_binding"](
                        directory,
                        command,
                        *files(native=True, local=local, authcrypt=authcrypt),
                        project=PROJECT,
                    )
                    assert_model(
                        baseline,
                        actual,
                        local=local,
                        authcrypt=authcrypt,
                        inputs=inputs,
                        policy_directory=policy_directory,
                    )
            print(
                f"PASS: base {mode} x local/released x anoncrypt/authcrypt complete models"
            )
        for value in (None, ""):
            inputs = {
                **required,
                **({} if value is None else {"DIDCOMM_ENCRYPTION_POLICY_DIR": value}),
            }
            (directory / "images.env").write_text(
                "".join(f"{k}={v}\n" for k, v in inputs.items()), encoding="utf-8"
            )
            try:
                BIND["render_binding"](
                    directory,
                    command,
                    *files(native=True, local=True, authcrypt=True),
                    project=PROJECT,
                )
            except subprocess.CalledProcessError as error:
                assert "required variable DIDCOMM_ENCRYPTION_POLICY_DIR" in error.stderr
            else:
                raise AssertionError("Missing explicit policy directory was accepted")
        # Compose config does not stat bind sources. Our model assertion must
        # reject nonexistent paths and files without auto-creating a directory.
        not_directory = directory / "not-a-directory"
        not_directory.write_text("synthetic non-policy", encoding="utf-8")
        for invalid in (directory / "absent", not_directory):
            inputs = {**required, "DIDCOMM_ENCRYPTION_POLICY_DIR": invalid.as_posix()}
            (directory / "images.env").write_text(
                "".join(f"{k}={v}\n" for k, v in inputs.items()), encoding="utf-8"
            )
            baseline = BIND["render_binding"](
                directory,
                command,
                *files(native=False, local=True, authcrypt=False),
                project=PROJECT,
            )
            actual = BIND["render_binding"](
                directory,
                command,
                *files(native=True, local=True, authcrypt=True),
                project=PROJECT,
            )
            try:
                assert_model(
                    baseline,
                    actual,
                    local=True,
                    authcrypt=True,
                    inputs=inputs,
                    policy_directory=invalid,
                )
            except AssertionError as error:
                assert str(error) == "Explicit policy directory must already exist"
            else:
                raise AssertionError("Non-directory policy source was accepted")
    print(
        "PASS: 12 complete selected models + required-directory negatives. Configuration only; runtime acceptance outstanding."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-command", nargs="+", default=["docker", "compose"])
    run(parser.parse_args().compose_command)
