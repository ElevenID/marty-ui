"""Read-only Compose selection, whole-model preservation and synthetic binding gate.

No daemon, images, operator environment files, network or application is used.
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
OWNER = runpy.run_path(str(ROOT / "scripts/conformance_stack.py"))
NATIVE = runpy.run_path(str(ROOT / "scripts/conformance_native.py"))
MERGE = runpy.run_path(str(ROOT / "scripts/test_canvas_worker_compose_render.py"))
BIND = runpy.run_path(str(ROOT / "scripts/test_beta_application_image_compose.py"))
PROJECT = "marty-conformance-native-config"
COMMON = "docker-compose.service.issuance-native.yml"
RUNTIME = "docker-compose.service.issuance-native-runtime.yml"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
TOKEN_RATE_CASES = (
    (None, "30"),
    ("", "30"),
    ("30", "30"),
    ("1200", "1200"),
    ("0", "0"),
)
MIRROR_WORKER_SETTINGS = (
    "CANVAS_MIRROR_WORKER_ENABLED",
    "CANVAS_MIRROR_WORKER_ORGANIZATION_ID",
    "CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS",
    "CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS",
    "CANVAS_MIRROR_WORKER_BATCH_LIMIT",
    "CANVAS_MIRROR_WORKER_RETRY_FAILED",
    "CANVAS_MIRROR_WORKER_RUN_ON_STARTUP",
    "CANVAS_MIRROR_FAILURE_WARNING_ATTEMPTS",
    "CANVAS_MIRROR_FAILURE_CRITICAL_ATTEMPTS",
    "CANVAS_MIRROR_ALERT_WEBHOOK_URL",
    "CANVAS_MIRROR_ALERT_WEBHOOK_TIMEOUT_SECONDS",
)
SHARED_SETTING_REPAIRS = (
    "ALLOWED_REDIRECT_URIS",
    "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
    "TOKEN_RATE_LIMIT",
) + MIRROR_WORKER_SETTINGS


def files(*, native, local, authcrypt):
    command = OWNER["compose_command"](
        PROJECT,
        issuance_owner="native" if native else "legacy",
        use_ghcr=not local,
        include_didcomm_authcrypt=authcrypt,
    )
    return [
        command[index + 1] for index, part in enumerate(command) if part == "--file"
    ]


def synthetic_values(model, directory):
    text = json.dumps(model)
    values = {
        key: "synthetic-owned-012345678901234567890123456789"
        for key in re.findall(r"\$\{([A-Z0-9_]+):\?", text)
    }
    values.update(
        MARTY_CONFORMANCE_PROJECT=PROJECT,
        MARTY_SERVICES_IMAGE=IMAGE,
        MARTY_ISSUANCE_IMAGE="synthetic.invalid/issuance@sha256:" + "b" * 64,
        MARTY_UI_IMAGE="synthetic.invalid/ui@sha256:" + "c" * 64,
        OIDF_PUBLIC_BASE_URL="https://conformance.example:9443",
        OIDF_PUBLIC_PORT="9443",
        OIDF_TLS_INTERNAL_PORT="9443",
        PUBLIC_API_URL="https://conformance.example:9443",
        CORS_ORIGINS="https://conformance.example:9443",
        OIDF_TLS_CERT_DIR=(directory / "tls").as_posix(),
        DIDCOMM_ENCRYPTION_POLICY_DIR=(directory / "policy").as_posix(),
    )
    return values


def assert_native_delta(legacy, actual):
    expected = deepcopy(legacy)
    # The native owner is validated separately in full; all existing service,
    # network, secret, volume, routing and mount fields are compared unchanged
    # except the explicitly enumerated native authentication/selection delta.
    expected["services"]["issuance-native"] = actual["services"]["issuance-native"]
    token = actual["services"]["issuance-native"]["environment"]["GRPC_SERVICE_TOKEN"]
    for name in NATIVE["TOKEN_CONSUMERS"]:
        expected["services"][name]["environment"]["GRPC_SERVICE_TOKEN"] = token
    expected["services"]["issuance"]["environment"].update(
        DIDCOMM_DELIVERY_OWNER="native",
        ISSUANCE_NATIVE_SERVICE_URL=NATIVE["NATIVE_URL"],
    )
    expected["services"]["issuance"]["depends_on"]["issuance-native"] = {
        "condition": "service_healthy",
        "required": True,
    }
    expected["services"]["issuance"]["healthcheck"]["test"] = [
        "CMD",
        "curl",
        "--fail",
        "http://localhost:8005/ready",
    ]
    gateway = expected["services"]["gateway"]
    gateway["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] = NATIVE["NATIVE_URL"]
    gateway["depends_on"]["issuance-native"] = {
        "condition": "service_healthy",
        "required": True,
    }
    expected["x-conformance-grpc-auth"] = {"GRPC_SERVICE_TOKEN": token}
    assert actual == expected, "Native selection changed an unowned existing field"


def assert_beta_shared_setting_repairs(previous, actual):
    """Reviewed shared settings only, not a frozen-definition rewrite."""
    expected = deepcopy(previous)
    before = expected["services"]["issuance-native"]["environment"]
    legacy = expected["services"]["issuance"]["environment"]
    for setting in SHARED_SETTING_REPAIRS:
        assert setting in legacy
        selected = legacy[setting]
        if setting in before:
            assert before[setting] == selected
        else:
            before[setting] = selected
    assert actual == expected, (
        "Beta changed outside the reviewed shared-setting repairs"
    )


def complete_common(common, runtime):
    """Resolve the one reviewed structural edge, not arbitrary Compose inputs."""
    assert set(common) == set(runtime) == {"services"}
    assert set(common["services"]) == set(runtime["services"]) == {"issuance-native"}
    wrapper = deepcopy(common["services"]["issuance-native"])
    assert wrapper.pop("extends") == {"file": RUNTIME, "service": "issuance-native"}
    structural = runtime["services"]["issuance-native"]
    assert set(structural) == {"build", "depends_on", "healthcheck", "restart"}
    assert set(wrapper) == {"environment", "networks"}
    return {"services": {"issuance-native": {**deepcopy(structural), **wrapper}}}


def run(command):
    def render(*paths, project=PROJECT):
        return MERGE["render"](
            *paths, profiles=("oidf",), project=project, compose_command=command
        )

    beta = render("docker-compose.base.yml", "docker-compose.beta.yml")
    # Compose's no-interpolate representation may use list-form merged env/args
    # versus map-form inherited env/args. Compare complete interpolated models
    # below, plus the exact original source definition independently here.
    common = complete_common(
        yaml.safe_load((ROOT / COMMON).read_text(encoding="utf-8")),
        yaml.safe_load((ROOT / RUNTIME).read_text(encoding="utf-8")),
    )
    frozen = yaml.safe_load(
        (
            ROOT / "tests/fixtures/issuance-native-compose-before-extraction.yml"
        ).read_text(encoding="utf-8")
    )
    base_source = yaml.safe_load(
        (ROOT / "docker-compose.base.yml").read_text(encoding="utf-8")
    )
    legacy_environment = base_source["services"]["issuance"]["environment"]
    token_expression = legacy_environment["TOKEN_RATE_LIMIT"]
    assert token_expression == "${TOKEN_RATE_LIMIT:-30}"
    expected_common = deepcopy(frozen)
    expected_environment = expected_common["services"]["issuance-native"][
        "environment"
    ]
    for setting in SHARED_SETTING_REPAIRS:
        assert setting not in expected_environment
        assert setting in legacy_environment
        expected_environment[setting] = legacy_environment[setting]
    assert common == expected_common, (
        "Shared service changed beyond the governed shared-setting repairs"
    )
    assert set(common) == {"services"} and set(common["services"]) == {
        "issuance-native"
    }
    assert common["services"]["issuance-native"]["build"]["context"] == "."
    for path in (
        "docker-compose.beta.yml",
        "docker-compose.profile.conformance-native.yml",
    ):
        source = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
        assert source["services"]["issuance-native"]["extends"] == {
            "file": COMMON,
            "service": "issuance-native",
        }
        assert (ROOT / path).parent / COMMON == ROOT / COMMON

    with tempfile.TemporaryDirectory(prefix="conformance-native-render-") as temporary:
        directory = Path(temporary)
        before_source = yaml.safe_load(
            (ROOT / "docker-compose.beta.yml").read_text(encoding="utf-8")
        )
        before_source["services"]["issuance-native"] = frozen["services"][
            "issuance-native"
        ]
        before_path = directory / "beta-before.json"
        before_path.write_text(json.dumps(before_source), encoding="utf-8")

        def beta_binding(before, effective):
            (directory / "images.env").write_text(
                "".join(f"{key}={value}\n" for key, value in sorted(effective.items())),
                encoding="utf-8",
            )
            return BIND["render_binding"](
                directory,
                command,
                ROOT / "docker-compose.base.yml",
                before_path if before else ROOT / "docker-compose.beta.yml",
                project=PROJECT,
            )

        values = synthetic_values(beta, directory)
        optional = set(re.findall(r"\$\{([A-Z0-9_]+):-", json.dumps(common)))
        for overrides in (
            {},
            dict.fromkeys(optional, ""),
            {key: "synthetic-custom" for key in optional},
        ):
            effective = {**values, **overrides}
            assert_beta_shared_setting_repairs(
                beta_binding(True, effective), beta_binding(False, effective)
            )
        for configured, expected_rate in TOKEN_RATE_CASES:
            effective = dict(values)
            if configured is not None:
                effective["TOKEN_RATE_LIMIT"] = configured
            actual = beta_binding(False, effective)
            assert_beta_shared_setting_repairs(beta_binding(True, effective), actual)
            assert (
                actual["services"]["issuance-native"]["environment"]["TOKEN_RATE_LIMIT"]
                == expected_rate
            )
        required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", json.dumps(common)))
        for key in sorted(required):
            for missing in (True, False):
                effective = {**values, key: ""}
                if missing:
                    effective.pop(key)
                errors = []
                for before in (False, True):
                    try:
                        beta_binding(before, effective)
                    except subprocess.CalledProcessError as error:
                        errors.append(error.stderr)
                    else:
                        raise AssertionError(
                            "Required beta input unexpectedly accepted"
                        )
                # Compose may report a map key or list index for equivalent
                # environment forms; retain the complete required-variable
                # failure text, not that parser-internal collection location.
                failures = [
                    re.search(r"required variable .+", error).group(0)
                    for error in errors
                ]
                assert len(failures) == 2 and failures[0] == failures[1]
        for local in (False, True):
            for authcrypt in (False, True):
                selected = render(*files(native=True, local=local, authcrypt=authcrypt))
                inputs = synthetic_values(selected, directory)
                for configured, expected_rate in TOKEN_RATE_CASES:
                    effective = dict(inputs)
                    if configured is not None:
                        effective["TOKEN_RATE_LIMIT"] = configured
                    (directory / "images.env").write_text(
                        "".join(
                            f"{key}={value}\n"
                            for key, value in sorted(effective.items())
                        ),
                        encoding="utf-8",
                    )
                    baseline = BIND["render_binding"](
                        directory,
                        command,
                        *files(native=False, local=local, authcrypt=authcrypt),
                        project=PROJECT,
                    )
                    selected = BIND["render_binding"](
                        directory,
                        command,
                        *files(native=True, local=local, authcrypt=authcrypt),
                        project=PROJECT,
                    )
                    NATIVE["validate_model"](
                        selected,
                        project=PROJECT,
                        authcrypt=authcrypt,
                        local_build=local,
                    )
                    OWNER["validate_isolation"](selected, PROJECT)
                    assert_native_delta(baseline, selected)
                    assert (
                        selected["services"]["flow"]["environment"][
                            "ISSUANCE_GRPC_TARGET"
                        ]
                        == "issuance-native:9005"
                    )
                    assert (
                        selected["services"]["issuance-native"]["environment"][
                            "TOKEN_RATE_LIMIT"
                        ]
                        == expected_rate
                    )
    print(
        "PASS: beta whole-model preservation with reviewed shared-setting repairs; four native conformance compositions x five token-rate inputs. Configuration only, not runtime acceptance."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-command", nargs="+", default=["docker", "compose"])
    run(parser.parse_args().compose_command)
