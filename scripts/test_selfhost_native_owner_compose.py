"""Independent pre-change self-host model comparison; no service startup."""

from copy import deepcopy
import hashlib
from pathlib import Path
import runpy
import re
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/test_canvas_worker_compose_render.py"))
BIND = runpy.run_path(str(ROOT / "scripts/test_beta_application_image_compose.py"))
FROZEN = "tests/fixtures/selfhost-before-native-owner.yml"
LEGACY_ONLY = {
    "BAO_ADDR",
    "BAO_TOKEN_FILE",
    "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS",
    "CANVAS_LTI_TOOL_ACTIVE_KID",
    "CANVAS_LTI_TOOL_PUBLIC_JWKS",
}
PUBLICATION_SETTINGS = {
    "CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE": "${CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE:-}",
    "CANVAS_CREDENTIALS_ASSERTION_NARRATIVE": "${CANVAS_CREDENTIALS_ASSERTION_NARRATIVE:-}",
    "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL": "${CANVAS_CREDENTIALS_PROVENANCE_BASE_URL:-}",
    "CANVAS_CREDENTIALS_RECIPIENT_HASHED": "${CANVAS_CREDENTIALS_RECIPIENT_HASHED:-true}",
    "CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS": "${CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS:-false}",
}
READY = "auth,organizations,credential-templates,trust-profiles,presentation-policies,deployment-profiles,signing-keys,flows,issuance,issuance-native"
NATIVE_ADDITIVE = {
    "CANVAS_MIRROR_WORKER_ENABLED": "${CANVAS_MIRROR_WORKER_ENABLED:-false}",
    "CANVAS_MIRROR_WORKER_ORGANIZATION_ID": "${CANVAS_MIRROR_WORKER_ORGANIZATION_ID:-}",
    "CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS": "${CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS:-300}",
    "CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS": "${CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS:-900}",
    "CANVAS_MIRROR_WORKER_BATCH_LIMIT": "${CANVAS_MIRROR_WORKER_BATCH_LIMIT:-25}",
    "CANVAS_MIRROR_WORKER_RETRY_FAILED": "${CANVAS_MIRROR_WORKER_RETRY_FAILED:-true}",
    "CANVAS_MIRROR_WORKER_RUN_ON_STARTUP": "${CANVAS_MIRROR_WORKER_RUN_ON_STARTUP:-true}",
    "CANVAS_MIRROR_FAILURE_WARNING_ATTEMPTS": "${CANVAS_MIRROR_FAILURE_WARNING_ATTEMPTS:-3}",
    "CANVAS_MIRROR_FAILURE_CRITICAL_ATTEMPTS": "${CANVAS_MIRROR_FAILURE_CRITICAL_ATTEMPTS:-5}",
    "CANVAS_MIRROR_ALERT_WEBHOOK_URL": "${CANVAS_MIRROR_ALERT_WEBHOOK_URL:-}",
    "CANVAS_MIRROR_ALERT_WEBHOOK_TIMEOUT_SECONDS": "${CANVAS_MIRROR_ALERT_WEBHOOK_TIMEOUT_SECONDS:-5}",
    "PASSPORT_NATIVE_HTTP_ENABLED": "${PASSPORT_NATIVE_HTTP_ENABLED:-false}",
    "PASSPORT_TENANT_API_KEYS": "${PASSPORT_TENANT_API_KEYS:-}",
    "PASSPORT_TENANT_API_KEYS_FILE": "${PASSPORT_TENANT_API_KEYS_FILE:-}",
    "ICAO_DOCUMENT_SIGNER_URL": "${ICAO_DOCUMENT_SIGNER_URL:-}",
    "ICAO_DOCUMENT_SIGNER_API_KEY": "${ICAO_DOCUMENT_SIGNER_API_KEY:-}",
    "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED": "${PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED:-false}",
    "PHYSICAL_DOCUMENT_ARTIFACT_KEY": "${PHYSICAL_DOCUMENT_ARTIFACT_KEY:-}",
    "PERSONALIZATION_BUREAU_URL": "${PERSONALIZATION_BUREAU_URL:-}",
    "PERSONALIZATION_BUREAU_API_KEY": "${PERSONALIZATION_BUREAU_API_KEY:-}",
    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET": "${PERSONALIZATION_BUREAU_WEBHOOK_SECRET:-}",
}
PASSPORT_CONSUMER_ADDITIVE = {
    "gateway": {
        "PASSPORT_NATIVE_GATEWAY_ENABLED": "${PASSPORT_NATIVE_GATEWAY_ENABLED:-false}",
        "PASSPORT_TENANT_API_KEYS": "${PASSPORT_TENANT_API_KEYS:-}",
        "PASSPORT_TENANT_API_KEYS_FILE": "${PASSPORT_TENANT_API_KEYS_FILE:-}",
    },
    "flow": {
        "PASSPORT_NATIVE_FLOW_ENABLED": "${PASSPORT_NATIVE_FLOW_ENABLED:-false}",
        "PASSPORT_TENANT_API_KEYS": "${PASSPORT_TENANT_API_KEYS:-}",
        "PASSPORT_TENANT_API_KEYS_FILE": "${PASSPORT_TENANT_API_KEYS_FILE:-}",
    },
}

# Inputs populated by the existing file loader, not raw host interpolation.
LOADED_INPUTS = {
    "DATABASE_URL",
    "CANVAS_CREDENTIALS_SHARED_SECRET",
    "GRPC_SERVICE_TOKEN",
    "INTEGRATION_SECRET_MASTER_KEY",
    "ISSUANCE_API_KEY",
    "SIGNING_KEYS_INTERNAL_API_KEY",
    "TOKEN_HMAC_KEY",
}
EXPLICIT_POLICY = {"DIDCOMM_ENCRYPTION_POLICY_FILE", "DIDCOMM_TLS_CA_FILE"}
CONFIG_META = {"CARGO_PKG_VERSION", "MARTY_ISSUANCE__"}
SHARED_ADDITIONS = {
    "ALLOWED_REDIRECT_URIS": "${ALLOWED_REDIRECT_URIS:-}",
    "CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE": PUBLICATION_SETTINGS[
        "CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE"
    ],
    "CANVAS_CREDENTIALS_ASSERTION_NARRATIVE": PUBLICATION_SETTINGS[
        "CANVAS_CREDENTIALS_ASSERTION_NARRATIVE"
    ],
}
SHARED_SETTINGS = {
    **SHARED_ADDITIONS,
    "ISSUANCE_AUTH_SESSION_TTL_MINUTES": "${ISSUANCE_AUTH_SESSION_TTL_MINUTES:-60}",
}


def rendered_additions(templates, values):
    rendered = {}
    for key, template in templates.items():
        match = re.fullmatch(rf"\$\{{{key}:-([^}}]*)\}}", template)
        assert match, f"Unsupported closed interpolation for {key}"
        rendered[key] = values.get(key) or match.group(1)
    return rendered


def rendered_passport_consumer_additions(values):
    return {
        owner: rendered_additions(additions, values)
        for owner, additions in PASSPORT_CONSUMER_ADDITIVE.items()
    }


UNFORWARDED = set(
    """
APP_ENV CANVAS_ADMIN_API_TOKEN CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK
CANVAS_CREDENTIALS_API_TOKEN CANVAS_CREDENTIALS_API_TOKEN_FILE
CANVAS_CREDENTIALS_BASE_URL CANVAS_CREDENTIALS_PUBLISH_TIMEOUT_SECONDS
CANVAS_CREDENTIALS_REVOKE_URL_TEMPLATE CANVAS_CREDENTIALS_SIGNATURE_TOLERANCE_SECONDS
CANVAS_CREDENTIALS_STATUS_SYNC_TIMEOUT_SECONDS CANVAS_CREDENTIALS_VALIDATE_URL_TEMPLATE
CANVAS_LTI_DEEP_LINKING_ISSUER CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS
CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES CANVAS_LTI_JWKS_TTL_MINUTES
CANVAS_LTI_STATE_TTL_MINUTES CORS_ALLOWED_ORIGINS DIDCOMM_DID_WEB_INTERNAL_BASE_URL
DIDCOMM_UNIVERSAL_RESOLVER_URL INTEGRATION_SECRET_MASTER_KEY_ENV ISSUER_DISPLAY_NAME
MARTY_RELEASE_VERSION MARTY_UI_SHA TOKEN_RATE_LIMIT TOKEN_RATE_WINDOW
VCDM_RELATED_RESOURCE_MAX_BYTES VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS
VCDM_RELATED_RESOURCE_URLS
""".split()
)


def assert_input_inventory():
    source = (
        (ROOT / "rust/services/issuance/src/config.rs")
        .read_text()
        .split("#[cfg(test)]")[0]
    )
    inputs = set(re.findall(r'"([A-Z][A-Z0-9_]+)"', source))
    model = yaml.safe_load((ROOT / GATE["BASE"]).read_text())
    native = model["services"]["issuance-native"]["environment"]
    legacy = model["services"]["issuance"]["environment"]
    assert {
        key: model["x-issuance-application-env"].get(key) for key in SHARED_SETTINGS
    } == SHARED_SETTINGS
    assert {key: native.get(key) for key in NATIVE_ADDITIVE} == NATIVE_ADDITIVE
    expected_omitted = LOADED_INPUTS | EXPLICIT_POLICY | CONFIG_META | UNFORWARDED
    actual_omitted = inputs - set(native)
    assert actual_omitted == expected_omitted, (
        "Update the exhaustive self-host native configuration inventory: "
        f"unexpected={sorted(actual_omitted - expected_omitted)!r}, "
        f"stale={sorted(expected_omitted - actual_omitted)!r}"
    )
    assert not UNFORWARDED & set(legacy), (
        "Previously bound input must not become unforwarded"
    )
    assert READY.split(",") == [
        *runpy.run_path(str(ROOT / "scripts/test_base_native_issuance_compose.py"))[
            "readiness_default"
        ](),
        "issuance-native",
    ]


def assert_signing_binding(model):
    """Source-derived dependency proof, not a socket/readiness assertion."""
    services = model["services"]
    gateway = services["gateway"]["environment"]
    signer_port = services["signing-keys"]["environment"]["SIGNING_KEYS_SERVICE_PORT"]
    target = f"http://signing-keys:{signer_port}"
    assert gateway.get("SIGNING_KEYS_SERVICE_URL") == target
    assert "signing-keys" in gateway["GATEWAY_REQUIRED_READY_SERVICES"].split(",")
    native = services["issuance-native"]["environment"]
    assert (
        native["SIGNING_KEYS_INTERNAL_URL"]
        == "http://gateway:8000/internal/signing-keys"
    )
    assert (
        native["SIGNING_KEYS_INTERNAL_API_KEY_FILE"]
        == gateway["SIGNING_KEYS_INTERNAL_API_KEY_FILE"]
        == services["signing-keys"]["environment"]["SIGNING_KEYS_INTERNAL_API_KEY_FILE"]
    )
    config = (ROOT / "rust/services/gateway/src/config.rs").read_text()
    defaults = re.findall(
        r'"signing-keys",\s*"SIGNING_KEYS_SERVICE_URL",\s*"([^"]+)"', config
    )
    assert defaults == [f"http://localhost:{signer_port}"]
    assert target != defaults[0], "Separate container must not use loopback fallback"


def assert_models(
    before,
    after,
    *,
    shared_additions=SHARED_ADDITIONS,
    native_additive=NATIVE_ADDITIVE,
    passport_consumer_additive=PASSPORT_CONSUMER_ADDITIVE,
):
    preserved = deepcopy(after)
    native = GATE["native_dispatcher_model"](
        preserved["services"].pop("issuance-native")
    )
    shared = preserved.pop("x-issuance-application-env")
    assert {key: shared[key] for key in SHARED_ADDITIONS} == shared_additions
    legacy_after = preserved["services"]["issuance"]["environment"]
    assert {key: legacy_after.pop(key) for key in SHARED_ADDITIONS} == shared_additions
    gateway = preserved["services"]["gateway"]
    # Governed repair: the native signer and readiness need the separate owner,
    # whereas the unchanged frozen model omitted it and fell back to localhost.
    assert (
        gateway["environment"].pop("SIGNING_KEYS_SERVICE_URL")
        == "http://signing-keys:8017"
    )
    assert (
        gateway["environment"].pop("ISSUANCE_NATIVE_SERVICE_URL")
        == "http://issuance-native:8005"
    )
    assert gateway["environment"].pop("GATEWAY_REQUIRED_READY_SERVICES") == READY
    for owner in ("gateway", "flow"):
        environment = preserved["services"][owner]["environment"]
        expected = passport_consumer_additive[owner]
        assert {key: environment.pop(key) for key in expected} == expected
    assert gateway["depends_on"].pop("issuance-native") == {
        "condition": "service_healthy",
        "required": True,
    }
    flow = preserved["services"]["flow"]
    assert flow["environment"]["ISSUANCE_GRPC_TARGET"] == "issuance-native:9005"
    flow["environment"]["ISSUANCE_GRPC_TARGET"] = "issuance:9005"
    for key in ("ISSUANCE_API_KEY_FILE", "SIGNING_KEYS_INTERNAL_API_KEY_FILE"):
        assert flow["environment"].pop(key) == "/run/secrets/issuance_api_key"
    assert flow["secrets"].pop() == {
        "source": "issuance_api_key",
        "target": "/run/secrets/issuance_api_key",
    }
    assert preserved == before, "Unowned self-host model change"
    legacy = before["services"]["issuance"]
    environment = {
        key: value
        for key, value in legacy["environment"].items()
        if key not in LEGACY_ONLY
    }
    environment.update(shared_additions)
    assert shared == environment
    environment.update(
        SERVICE_NAME="issuance_native",
        ISSUANCE_GRPC_ENABLED="true",
        RP_GRPC_TARGET="revocation-profile:9013",
        **native_additive,
    )
    expected = {
        "build": {
            "context": ".",
            "dockerfile": "services/Dockerfile",
            "args": {"SERVICE_NAME": "issuance-native"},
        },
        "entrypoint": ["/app/services/entrypoint.sh"],
        "command": [],
        "environment": environment,
        "secrets": [
            item
            for item in legacy["secrets"]
            if item["source"] != "openbao_service_token"
        ],
        "depends_on": {
            name: {"condition": condition, "required": True}
            for name, condition in {
                "db-migrate": "service_completed_successfully",
                "issuance-migrations": "service_completed_successfully",
                "postgres": "service_healthy",
                "signing-keys": "service_healthy",
                "revocation-profile": "service_healthy",
            }.items()
        },
        "healthcheck": {
            "test": ["CMD", "curl", "--fail", "http://localhost:8005/health"],
            "interval": "10s",
            "timeout": "5s",
            "retries": 3,
        },
        "restart": "unless-stopped",
        "networks": {"default": None},
    }
    assert native == expected, "Native self-host model differs from closed additions"


def interpolated_models():
    original = (ROOT / FROZEN).read_text(encoding="utf-8")
    current = (ROOT / GATE["BASE"]).read_text(encoding="utf-8")
    required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", original))
    assert required == set(re.findall(r"\$\{([A-Z0-9_]+):\?", current))
    environment = yaml.safe_load(original)["services"]["issuance"]["environment"]
    variables = (
        set(re.findall(r"\$\{([A-Z0-9_]+):-", str(environment)))
        | set(SHARED_ADDITIONS)
        | set(NATIVE_ADDITIVE)
        | {
            key
            for additions in PASSPORT_CONSUMER_ADDITIVE.values()
            for key in additions
        }
    ) - required

    with tempfile.TemporaryDirectory(prefix="selfhost-native-config-") as temporary:
        directory = Path(temporary)
        inputs = dict.fromkeys(required, "https://synthetic.example")
        inputs.update(
            SELFHOST_STATE_DIR=(directory / "state").as_posix(),
            SELFHOST_SECRET_DIR=(directory / "secrets").as_posix(),
            KEYCLOAK_SOCIAL_LOGIN_ENABLED="false",
            MARTY_ISSUANCE_IMAGE="synthetic.invalid/issuance@sha256:" + "a" * 64,
        )

        def render(file, values):
            (directory / "images.env").write_text(
                "".join(f"{key}={value}\n" for key, value in sorted(values.items())),
                encoding="utf-8",
            )
            return BIND["render_binding"](
                directory,
                ["docker", "compose"],
                ROOT / file,
                project="selfhost-native-preservation",
            )

        for mode, overrides in (
            ("default", {}),
            ("empty", dict.fromkeys(variables, "")),
            (
                "custom",
                dict.fromkeys(
                    variables | UNFORWARDED | LOADED_INPUTS | EXPLICIT_POLICY,
                    "synthetic-custom",
                ),
            ),
        ):
            values = {**inputs, **overrides}
            after = render(GATE["BASE"], values)
            expected_publication = rendered_additions(PUBLICATION_SETTINGS, values)
            for owner in ("issuance", "issuance-native"):
                actual_publication = {
                    key: after["services"][owner]["environment"][key]
                    for key in PUBLICATION_SETTINGS
                }
                assert actual_publication == expected_publication
            if mode == "custom":
                assert set(expected_publication.values()) == {"synthetic-custom"}
            assert_models(
                render(FROZEN, values),
                after,
                shared_additions=rendered_additions(SHARED_ADDITIONS, values),
                native_additive=rendered_additions(NATIVE_ADDITIVE, values),
                passport_consumer_additive=rendered_passport_consumer_additions(values),
            )
            assert_signing_binding(after)
            print(f"PASS: self-host {mode} interpolated whole model")
        for name in sorted(required):
            for value in (None, ""):
                values = dict(inputs)
                if value is None:
                    values.pop(name)
                else:
                    values[name] = value
                for file in (FROZEN, GATE["BASE"]):
                    try:
                        render(file, values)
                    except subprocess.CalledProcessError as error:
                        assert f"required variable {name}" in error.stderr
                    else:
                        raise AssertionError(
                            f"Required self-host input accepted: {name}"
                        )
        print(f"PASS: {len(required)} required inputs, missing/empty in both models")


def run():
    assert_input_inventory()
    data = (ROOT / FROZEN).read_text(encoding="utf-8").encode()
    assert (
        hashlib.sha256(data).hexdigest()
        == "5c643478422ecb9f71bb9bd3133af55805e91b184bd8f3c84852fafd418905f8"
    )
    before = GATE["render"](FROZEN)
    after = GATE["render"](GATE["BASE"])
    assert_models(before, after)
    assert_signing_binding(after)
    interpolated_models()
    print(
        "PASS: frozen full self-host model and closed native additions (configuration only)"
    )


if __name__ == "__main__":
    run()
