"""Reviewed current self-host model and synthetic binding gate; no startup."""

from copy import deepcopy
import difflib
import hashlib
import json
from pathlib import Path
import runpy
import re
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "scripts/test_canvas_worker_compose_render.py"))
BIND = runpy.run_path(str(ROOT / "scripts/test_beta_application_image_compose.py"))
APPROVED = "selfhost-kms-only-model.keyless-tls.snapshot.yml"
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
    "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "${PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED:-false}",
    "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED": "${PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED:-false}",
    "PASSPORT_KMS_ARTIFACTS_ENABLED": "${PASSPORT_KMS_ARTIFACTS_ENABLED:-false}",
    "PASSPORT_KMS_CALLBACKS_ENABLED": "${PASSPORT_KMS_CALLBACKS_ENABLED:-false}",
    "PASSPORT_TENANT_API_KEYS": "${PASSPORT_TENANT_API_KEYS:-}",
    "PASSPORT_TENANT_API_KEYS_FILE": "${PASSPORT_TENANT_API_KEYS_FILE:-}",
    "PERSONALIZATION_BUREAU_URL": "${PERSONALIZATION_BUREAU_URL:-}",
    "PERSONALIZATION_BUREAU_API_KEY": "${PERSONALIZATION_BUREAU_API_KEY:-}",
    "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "${PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID:-}",
}
PASSPORT_CONSUMER_ADDITIVE = {
    "gateway": {
        "PASSPORT_NATIVE_GATEWAY_ENABLED": "${PASSPORT_NATIVE_GATEWAY_ENABLED:-false}",
        "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": "${PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED:-false}",
        "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "${PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED:-false}",
        "PASSPORT_TENANT_API_KEYS": "${PASSPORT_TENANT_API_KEYS:-}",
        "PASSPORT_TENANT_API_KEYS_FILE": "${PASSPORT_TENANT_API_KEYS_FILE:-}",
    },
    "flow": {
        "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
        "PASSPORT_NATIVE_FLOW_ENABLED": "${PASSPORT_NATIVE_FLOW_ENABLED:-false}",
        "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "${PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED:-false}",
        "PASSPORT_TENANT_API_KEYS": "${PASSPORT_TENANT_API_KEYS:-}",
        "PASSPORT_TENANT_API_KEYS_FILE": "${PASSPORT_TENANT_API_KEYS_FILE:-}",
    },
}

# Inputs populated by the existing file loader, not raw host interpolation.
LOADED_INPUTS = {
    "DATABASE_URL",
    "CANVAS_CREDENTIALS_SHARED_SECRET",
    "GRPC_SERVICE_TOKEN",
    "ISSUANCE_API_KEY",
    "SIGNING_KEYS_INTERNAL_API_KEY",
    "SIGNING_KEYS_ISSUER_SIGN_KEY",
    "SIGNING_KEYS_INTEGRATION_SECRET_KEY",
    "TOKEN_HMAC_KEY",
}
REJECTED_MASTER_KEY_INPUTS = {
    "INTEGRATION_SECRET_MASTER_KEY",
    "INTEGRATION_SECRET_MASTER_KEY_FILE",
}
EXPLICIT_POLICY = {"DIDCOMM_ENCRYPTION_POLICY_FILE", "DIDCOMM_TLS_CA_FILE"}
FORBIDDEN_LOCAL_CUSTODY_INPUTS = {
    "GRPC_WORKLOAD_TLS_SERVER_KEY",
    "ICAO_DOCUMENT_SIGNER_URL",
    "ICAO_DOCUMENT_SIGNER_API_KEY",
    "ICAO_DOCUMENT_SIGNER_API_KEY_FILE",
    "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
    "PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE",
    "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED",
    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE",
}
PASSPORT_BETA_OVERLAY_ONLY = {
    "PASSPORT_BETA_RECONCILIATION_ENABLED",
    "PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN",
}
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
        if key == "ISSUANCE_NATIVE_SERVICE_URL":
            assert template == "http://issuance-native:8005"
            rendered[key] = template
            continue
        match = re.fullmatch(rf"\$\{{{key}:-([^}}]*)\}}", template)
        assert match, f"Unsupported closed interpolation for {key}"
        rendered[key] = values.get(key) or match.group(1)
    return rendered


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
    beta_model = yaml.safe_load(
        (ROOT / "docker-compose.profile.passport-native-beta.yml").read_text()
    )
    beta_native = beta_model["services"]["issuance-native"]["environment"]
    assert beta_native.get("PASSPORT_BETA_RECONCILIATION_ENABLED") == "true"
    assert beta_native.get("PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN") == (
        "${PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN:?set a dedicated beta reconciliation operator token}"
    )
    assert not PASSPORT_BETA_OVERLAY_ONLY & set(native)
    assert not PASSPORT_BETA_OVERLAY_ONLY & set(legacy)
    assert not FORBIDDEN_LOCAL_CUSTODY_INPUTS & (
        set(native) | set(legacy) | set(beta_native)
    )
    assert {
        key: model["x-issuance-application-env"].get(key) for key in SHARED_SETTINGS
    } == SHARED_SETTINGS
    assert {key: native.get(key) for key in NATIVE_ADDITIVE} == NATIVE_ADDITIVE
    expected_omitted = (
        LOADED_INPUTS
        | REJECTED_MASTER_KEY_INPUTS
        | EXPLICIT_POLICY
        | FORBIDDEN_LOCAL_CUSTODY_INPUTS
        | PASSPORT_BETA_OVERLAY_ONLY
        | CONFIG_META
        | UNFORWARDED
    )
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


def assert_models(approved, actual):
    """Check the complete current KMS-only model against its reviewed snapshot."""
    expected = deepcopy(approved)
    issuance = expected["services"]["issuance"]
    envelope = "signing_keys_integration_secret_key"
    envelope_path = f"/run/secrets/{envelope}"
    assert issuance["environment"]["SIGNING_KEYS_INTEGRATION_SECRET_KEY_FILE"] == envelope_path
    assert [item["source"] for item in issuance["secrets"]].count(envelope) == 1
    assert expected == actual, "Unreviewed self-host model change:\n" + "".join(
        difflib.unified_diff(
            json.dumps(expected, sort_keys=True, indent=2).splitlines(keepends=True),
            json.dumps(actual, sort_keys=True, indent=2).splitlines(keepends=True),
            fromfile="approved keyless-TLS KMS model",
            tofile="current self-host model",
        )
    )
    retired_tls_settings = {
        "GRPC_WORKLOAD_TLS_CLIENT_KEY",
        "GRPC_WORKLOAD_TLS_SERVER_KEY",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KEY_FILE",
    }
    for name, service in actual["services"].items():
        assert not retired_tls_settings & set(service.get("environment", {})), (
            f"{name} still accepts a workload TLS private-key file"
        )
        assert not any(
            re.fullmatch(r".*_workload_(?:client|server)_key", secret["source"])
            for secret in service.get("secrets", [])
        ), f"{name} still mounts a workload TLS private-key file"
    assert not any(
        re.fullmatch(r".*_workload_(?:client|server)_key", name)
        for name in actual["secrets"]
    ), "Self-host still declares a workload TLS private-key secret"
    assert "INTEGRATION_SECRET_MASTER_KEY" not in json.dumps(actual)
    assert "integration_secret_master_key" not in actual.get("secrets", {})
    assert actual["secrets"][envelope]["file"].endswith(f"/{envelope}")
    envelope_owners = {
        "signing-keys",
        "issuance",
        "issuance-native",
        "canvas-sync-worker",
    }
    for name, service in actual["services"].items():
        environment = service.get("environment", {})
        mounts = [item["source"] for item in service.get("secrets", [])]
        if name in envelope_owners:
            assert (
                environment["SIGNING_KEYS_INTEGRATION_SECRET_KEY_FILE"] == envelope_path
            )
            assert mounts.count(envelope) == 1
        else:
            assert "SIGNING_KEYS_INTEGRATION_SECRET_KEY_FILE" not in environment
            assert envelope not in mounts
    grant_roles = [
        (
            {"gateway"},
            "GATEWAY_SIGN_GRANT_MINT_TOKEN_FILE",
            "sign_grant_mint_gateway_service_token",
        ),
        (
            {"gateway"},
            "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN_FILE",
            "sign_grant_mint_gateway_issuer_did_token",
        ),
        (
            {"flow"},
            "FLOW_SIGN_GRANT_MINT_TOKEN_FILE",
            "sign_grant_mint_flow_wallet_token",
        ),
        (
            {"signing-keys"},
            "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE",
            "sign_grant_verify_token",
        ),
        (
            {"issuance", "issuance-native"},
            "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN_FILE",
            "sign_grant_mint_issuance_credential_token",
        ),
        (
            {"issuance", "issuance-native", "canvas-sync-worker"},
            "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN_FILE",
            "sign_grant_mint_issuance_canvas_token",
        ),
        (
            {"issuance", "issuance-native"},
            "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN_FILE",
            "sign_grant_mint_issuance_readiness_token",
        ),
        (
            {"issuance", "issuance-native"},
            "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN_FILE",
            "sign_grant_mint_issuance_passport_token",
        ),
    ]
    for owner, setting, secret in grant_roles:
        assert actual["secrets"][secret]["file"].endswith(f"/{secret}")
        for name, service in actual["services"].items():
            environment = service.get("environment", {})
            mounts = [item["source"] for item in service.get("secrets", [])]
            if name in owner:
                assert environment[setting] == f"/run/secrets/{secret}"
                assert mounts.count(secret) == 1
            else:
                assert setting not in environment
                assert secret not in mounts
    assert "BAO_TOKEN_FILE" not in actual["services"]["gateway"]["environment"]
    assert "openbao_service_token" not in [
        item["source"] for item in actual["services"]["gateway"]["secrets"]
    ]
    tls_url = "https://signing-keys:8018/internal"
    ca_path = "/run/secrets/workload_identity_ca_cert"
    for name in ("issuance", "issuance-native", "canvas-sync-worker"):
        service = actual["services"][name]
        assert service["environment"]["INTEGRATION_SECRET_KMS_URL"] == tls_url
        assert service["environment"]["INTEGRATION_SECRET_KMS_CA_FILE"] == ca_path
        assert [item["source"] for item in service["secrets"]].count(
            "workload_identity_ca_cert"
        ) == 1
    GATE["native_dispatcher_model"](actual["services"]["issuance-native"])
    assert_signing_binding(actual)


def interpolated_models():
    approved = (ROOT / APPROVED).read_text(encoding="utf-8")
    current = (ROOT / GATE["BASE"]).read_text(encoding="utf-8")
    required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", approved))
    assert required == set(re.findall(r"\$\{([A-Z0-9_]+):\?", current))
    assert "MARTY_ISSUANCE_IMAGE" not in required
    assert "BAO_ADDR" in required
    environment = yaml.safe_load(approved)["services"]["issuance"]["environment"]
    variables = (
        (
            set(re.findall(r"\$\{([A-Z0-9_]+):-", str(environment)))
            | set(SHARED_ADDITIONS)
            | set(NATIVE_ADDITIVE)
            | {
                key
                for additions in PASSPORT_CONSUMER_ADDITIVE.values()
                for key in additions
            }
        )
        - required
        - {"BAO_ADDR"}
    )

    with tempfile.TemporaryDirectory(prefix="selfhost-native-config-") as temporary:
        directory = Path(temporary)
        inputs = dict.fromkeys(required, "https://synthetic.example")
        inputs.update(
            BAO_ADDR="http://synthetic-bao:8200",
            PUBLIC_DOMAIN="synthetic.example",
            SELFHOST_STATE_DIR=(directory / "state").as_posix(),
            SELFHOST_SECRET_DIR=(directory / "secrets").as_posix(),
            KEYCLOAK_SOCIAL_LOGIN_ENABLED="false",
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
            slug = values.get("MARTY_ORG_SLUG") or "marty"
            issuer_did = f"did:web:synthetic.example:orgs:{slug}"
            assert after["services"]["auth"]["environment"]["CREDENTIAL_LOGIN_ISSUER_DID"] == issuer_did
            assert after["services"]["flow"]["environment"]["OID4VP_ISSUER_DID"] == issuer_did
            assert after["services"]["trust-profile"]["environment"]["MARTY_ORG_SLUG"] == slug
            expected_publication = rendered_additions(PUBLICATION_SETTINGS, values)
            for owner in ("issuance", "issuance-native"):
                actual_publication = {
                    key: after["services"][owner]["environment"][key]
                    for key in PUBLICATION_SETTINGS
                }
                assert actual_publication == expected_publication
            if mode == "custom":
                assert set(expected_publication.values()) == {"synthetic-custom"}
            assert_models(render(APPROVED, values), after)
            print(f"PASS: self-host {mode} interpolated whole model")
        for name in sorted(required):
            for value in (None, ""):
                values = dict(inputs)
                if value is None:
                    values.pop(name)
                else:
                    values[name] = value
                for file in (APPROVED, GATE["BASE"]):
                    try:
                        render(file, values)
                    except subprocess.CalledProcessError as error:
                        assert f"required variable {name}" in error.stderr
                    else:
                        raise AssertionError(
                            f"Required self-host input accepted: {name}"
                        )
        print(
            f"PASS: {len(required)} current required inputs reject missing/empty; "
            "retired Python image input is absent"
        )


def run():
    assert_input_inventory()
    data = (ROOT / APPROVED).read_text(encoding="utf-8").encode()
    assert (
        hashlib.sha256(data).hexdigest()
        == "b5d4dd978c59f424d90e8cefeb5f5da0fbd2146faf40f28355dc4355a3de0122"
    )
    before = GATE["render"](APPROVED)
    after = GATE["render"](GATE["BASE"])
    assert_models(before, after)
    interpolated_models()
    print(
        "PASS: approved KMS-only self-host model and synthetic bindings (configuration only)"
    )


if __name__ == "__main__":
    run()
