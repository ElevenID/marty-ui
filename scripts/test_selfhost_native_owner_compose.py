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
APPROVED_SHA256 = (
    "6b904f625a0d6ff156a47b84de8e72b341e1d7d357bb67d600415b9995c3bac7"
)
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
    "PERSONALIZATION_BUREAU_API_KEY_FILE": "${PERSONALIZATION_BUREAU_API_KEY_FILE:-}",
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
    "GRPC_WORKLOAD_TLS_SERVER_KEY_FILE",
    "GRPC_WORKLOAD_TLS_SERVER_PRIVATE_KEY",
    "GRPC_WORKLOAD_TLS_SERVER_PRIVATE_KEY_FILE",
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
ALTERNATE_TLS_PROVIDER_INPUTS = {
    "GRPC_WORKLOAD_TLS_SERVER_KMS_PROVIDER",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_REGION",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_ARN",
}
SHARED_ADDITIONS = {
    "CANVAS_CREDENTIALS_API_TOKEN_FILE": "${CANVAS_CREDENTIALS_API_TOKEN_FILE:-}",
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
CANVAS_CREDENTIALS_API_TOKEN
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
    inputs = runpy.run_path(str(ROOT / "scripts/test_conformance_native_compose.py"))["issuance_configuration_inputs"]()
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
        | ALTERNATE_TLS_PROVIDER_INPUTS
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


def apply_foundation_reference_representation(model):
    """Admit only the reviewed empty-provider references in the frozen model.

    Compose interpolates the base before a selected foundation can remove its
    provider fields. Runtime provider validation still requires complete inputs;
    the model comparison continues to reject any unrelated environment change.
    """
    services = model["services"]
    optional_inputs = set()

    def replace(mapping, field, variable):
        assert re.fullmatch(r"\$\{" + re.escape(variable) + r":\?[^}]*\}",
                            mapping[field]), (field, variable)
        mapping[field] = "${" + variable + ":-}"
        optional_inputs.add(variable)

    for service, runtime_prefix, input_prefix in (
        ("signing-keys", "SIGNING_KEYS_INTEGRATION_SECRET_TLS", "SIGNING_KEYS"),
        ("gateway", "GRPC_WORKLOAD_TLS_CLIENT", "GATEWAY"),
        ("auth", "GRPC_WORKLOAD_TLS_CLIENT", "AUTH"),
        ("auth", "GRPC_WORKLOAD_TLS_SERVER", "AUTH_SERVER"),
        ("compliance-profile", "GRPC_WORKLOAD_TLS", "COMPLIANCE_PROFILE"),
        ("deployment-profile", "GRPC_WORKLOAD_TLS", "DEPLOYMENT_PROFILE"),
        ("issuance-native", "GRPC_WORKLOAD_TLS_SERVER", "ISSUANCE"),
        ("organization", "GRPC_WORKLOAD_TLS_SERVER", "ORG"),
        ("revocation-profile", "GRPC_WORKLOAD_TLS_SERVER", "RP"),
        ("credential-template", "GRPC_WORKLOAD_TLS_SERVER", "CT"),
        ("presentation-policy", "GRPC_WORKLOAD_TLS_SERVER", "PP"),
        ("flow", "GRPC_WORKLOAD_TLS_CLIENT", "FLOW_CLIENT"),
        ("flow", "GRPC_WORKLOAD_TLS_SERVER", "FLOW_SERVER"),
        ("verification", "GRPC_WORKLOAD_TLS", "VERIFICATION"),
        ("notification", "GRPC_TLS", "NOTIFICATION"),
        ("event-stream", "GRPC_WORKLOAD_TLS_SERVER", "ES"),
    ):
        for suffix in ("ADDR", "KEY_NAME", "KEY_VERSION"):
            replace(services[service]["environment"],
                    f"{runtime_prefix}_KMS_{suffix}", f"{input_prefix}_TLS_KMS_{suffix}")
    for service in ("issuance-native", "canvas-sync-worker", "flow"):
        replace(services[service]["environment"], "BAO_ADDR", "BAO_ADDR")
    for service in ("keycloak", "keycloak-configurator"):
        replace(services[service], "image", "MARTY_KEYCLOAK_KMS_IMAGE")
    replace(services["keycloak"]["environment"], "BAO_ADDR", "KEYCLOAK_KMS_ADDR")
    replace(services["keycloak"]["environment"],
            "MARTY_KEYCLOAK_KMS_KEY_VERSION", "KEYCLOAK_KMS_KEY_VERSION")
    replace(services["keycloak-configurator"]["environment"],
            "KEYCLOAK_SOCIAL_LOGIN_ENABLED", "KEYCLOAK_SOCIAL_LOGIN_ENABLED")
    replace(model["x-issuance-application-env"], "BAO_ADDR", "BAO_ADDR")
    return optional_inputs


def assert_models(
    approved, actual, *, interpolated=False, issuer_did="",
    ui_enabled_sections="public,console", bureau_api_key_file="", canvas_api_token_file="",
    passkeys_enabled="", passkey_rp_id="",
):
    """Check the complete current KMS-only model against its reviewed snapshot."""
    expected = deepcopy(approved)
    # Keep the approved snapshot and its hash frozen. Admit only the exact
    # hosting separation, memory ceilings, Keycloak heap setting and eager
    # provider startup dependencies reviewed;
    # the whole-model comparison below still rejects every other drift.
    # Synthetic interpolation uses the default profile; Compose omits the two
    # beta-tunnel services and their unused secret before this comparison.
    connector_services = ("cloudflared",) if interpolated else (
        "cloudflared", "cloudflared-beta", "tunnel-nginx-proxy"
    )
    connector_secrets = ("cloudflare_tunnel_token",) if interpolated else (
        "cloudflare_tunnel_token", "cloudflare_beta_tunnel_token"
    )
    for name in connector_services:
        assert name in expected["services"]
        del expected["services"][name]
    for name in connector_secrets:
        assert name in expected["secrets"]
        del expected["secrets"][name]
    one_gib = {
        "postgres",
        "db-migrate",
        "issuance-migrations",
        "revocation-profile-migrate",
        "ui",
    }
    for name, service in expected["services"].items():
        assert "mem_limit" not in service
        default = "2g" if name == "keycloak" else "1g" if name in one_gib else "512m"
        if interpolated:
            service["mem_limit"] = str(
                (2 if name == "keycloak" else 1) * 1024**3
                if default.endswith("g")
                else 512 * 1024**2
            )
        else:
            service["mem_limit"] = (
                "${MARTY_"
                + name.upper().replace("-", "_")
                + "_MEMORY_LIMIT:-"
                + default
                + "}"
            )
    assert "JAVA_OPTS_KC_HEAP" not in expected["services"]["keycloak"]["environment"]
    expected["services"]["keycloak"]["environment"]["JAVA_OPTS_KC_HEAP"] = (
        "-XX:InitialRAMPercentage=20 -XX:MaxRAMPercentage=65"
    )
    configurator_environment = expected["services"]["keycloak-configurator"]["environment"]
    assert "KEYCLOAK_SETUP_STRICT" not in configurator_environment
    configurator_environment["KEYCLOAK_SETUP_STRICT"] = "true"
    # Admit only the new public passkey settings. Keep the frozen model/hash,
    # provider credentials, all existing login controls and custody gates intact.
    auth_environment = expected["services"]["auth"]["environment"]
    assert "KEYCLOAK_PASSKEYS_ENABLED" not in auth_environment
    auth_environment["KEYCLOAK_PASSKEYS_ENABLED"] = (
        passkeys_enabled or "false" if interpolated else "${KEYCLOAK_PASSKEYS_ENABLED:-false}"
    )
    for key, value in (("KEYCLOAK_PASSKEYS_ENABLED", passkeys_enabled),
                       ("KEYCLOAK_PASSKEY_RP_ID", passkey_rp_id)):
        assert key not in configurator_environment
        configurator_environment[key] = value if interpolated else "${" + key + ":-}"
    gateway_environment = expected["services"]["gateway"]["environment"]
    assert "GATEWAY_OBSERVE_CLIENT_IP" not in gateway_environment
    gateway_environment["GATEWAY_OBSERVE_CLIENT_IP"] = (
        "true" if interpolated else "${GATEWAY_OBSERVE_CLIENT_IP:-true}"
    )
    # Customer startup selects the public and console sections. Health remains
    # observable when either or both documents are intentionally excluded.
    # Admit these exact changes without changing the frozen reference or any
    # other UI environment, healthcheck command, timing or service field.
    ui = expected["services"]["ui"]
    assert "UI_ENABLED_SECTIONS" not in ui["environment"]
    ui["environment"]["UI_ENABLED_SECTIONS"] = (
        ui_enabled_sections if interpolated
        else "${UI_ENABLED_SECTIONS-public,console}"
    )
    assert "ORGANIZATION_CREATION_ENABLED" not in ui["environment"]
    ui["environment"]["ORGANIZATION_CREATION_ENABLED"] = (
        expected["services"]["gateway"]["environment"]["ORGANIZATION_CREATION_ENABLED"]
    )
    assert ui["healthcheck"]["test"] == [
        "CMD", "wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1:80/",
    ]
    ui["healthcheck"]["test"][-1] = "http://127.0.0.1:80/healthz"
    # The existing edge must start independently of product health so retained
    # marketing remains available. Keep the frozen model/hash and admit only
    # these exact dependency removals and the local edge health target; ports,
    # mounts, upstreams, health timing and all other fields remain compared.
    edge = expected["services"]["edge"]
    assert edge.pop("depends_on") == {
        owner: {"condition": "service_healthy", "required": True}
        for owner in ("ui", "gateway", "flow", "keycloak")
    }
    assert edge["healthcheck"]["test"] == [
        "CMD", "wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1/ready",
    ]
    edge["healthcheck"]["test"][-1] = "http://127.0.0.1/edge-healthz"
    if not interpolated:
        apply_foundation_reference_representation(expected)
    # The installer supplies one normalized DNS did:web identity (including an
    # encoded nondefault port). Ordinary Compose retains its historical
    # PUBLIC_DOMAIN/MARTY_ORG_SLUG fallback. Keep the snapshot frozen and admit
    # only this exact shared value and its two existing authentication owners.
    for environment in [
        expected["x-runtime-env"],
        expected["x-issuance-application-env"],
        *(
            service["environment"]
            for service in expected["services"].values()
            if "MARTY_ISSUER_BASE_URL" in service.get("environment", {})
        ),
    ]:
        assert "MARTY_ISSUER_DID" not in environment
        environment["MARTY_ISSUER_DID"] = (
            issuer_did if interpolated else "${MARTY_ISSUER_DID:-}"
        )
    for owner, setting in (
        ("auth", "CREDENTIAL_LOGIN_ISSUER_DID"),
        ("flow", "OID4VP_ISSUER_DID"),
    ):
        environment = expected["services"][owner]["environment"]
        historical = environment[setting]
        environment[setting] = (
            issuer_did or historical if interpolated
            else "${MARTY_ISSUER_DID:-" + historical + "}"
        )
    # Move the existing dedicated token only; its producer, secret name and
    # authority remain unchanged. Both Issuance variants use Signing Keys HTTPS.
    didcomm_secret = "didcomm_issuance_openbao_token"
    didcomm_path = "/run/secrets/" + didcomm_secret
    signing = expected["services"]["signing-keys"]
    assert "DIDCOMM_KMS_TOKEN_FILE" not in signing["environment"]
    for owner in ("issuance", "issuance-native"):
        service = expected["services"][owner]
        assert service["environment"].pop("DIDCOMM_KMS_TOKEN_FILE") == didcomm_path
        assert service["environment"].pop("DIDCOMM_KMS_ADDR") == (
            service["environment"]["BAO_ADDR"] if interpolated
            else "${BAO_ADDR:?BAO_ADDR must be set for DIDComm KMS}"
        )
        assert service["environment"].pop("DIDCOMM_KMS_CA_CERT_FILE") == "/run/secrets/openbao_tls_ca_cert"
        selected = [item for item in service["secrets"] if item["source"] == didcomm_secret]
        assert selected == [{"source": didcomm_secret, "target": didcomm_path}]
        service["secrets"].remove(selected[0])
    signing["environment"]["DIDCOMM_KMS_TOKEN_FILE"] = didcomm_path
    token_position = next(index for index, item in enumerate(signing["secrets"])
                          if item["source"] == "signing_keys_openbao_token") + 1
    signing["secrets"].insert(token_position, {"source": didcomm_secret, "target": didcomm_path})
    # Optional Canvas/Passport credentials are file-backed and reach only their
    # existing runtime consumers. Empty files remain unused unless selected.
    secret_root = expected["secrets"]["google_client_id"]["file"].rsplit("/", 1)[0]
    for secret, owners in (
        ("passport_tenant_api_keys", ("gateway", "flow", "issuance-native")),
        ("personalization_bureau_api_key", ("issuance-native",)),
        ("canvas_credentials_api_token", ("issuance", "issuance-native")),
    ):
        assert secret not in expected["secrets"]
        expected["secrets"][secret] = {"file": f"{secret_root}/{secret}", "name": f"{expected['name']}_{secret}"}
        for owner in owners:
            expected["services"][owner]["secrets"].append(
                {"source": secret, "target": f"/run/secrets/{secret}"})
    expected["services"]["issuance-native"]["environment"]["PERSONALIZATION_BUREAU_API_KEY_FILE"] = (
        bureau_api_key_file if interpolated else "${PERSONALIZATION_BUREAU_API_KEY_FILE:-}"
    )
    for environment in (expected["x-issuance-application-env"],
                        expected["services"]["issuance"]["environment"],
                        expected["services"]["issuance-native"]["environment"]):
        environment["CANVAS_CREDENTIALS_API_TOKEN_FILE"] = (
            canvas_api_token_file if interpolated else "${CANVAS_CREDENTIALS_API_TOKEN_FILE:-}"
        )
    issuance = expected["services"]["issuance"]
    envelope = "signing_keys_integration_secret_key"
    envelope_path = f"/run/secrets/{envelope}"
    assert issuance["environment"]["SIGNING_KEYS_INTEGRATION_SECRET_KEY_FILE"] == envelope_path
    assert [item["source"] for item in issuance["secrets"]].count(envelope) == 1
    for consumer, provider in (
        ("flow", "trust-profile"),
        ("flow", "deployment-profile"),
        ("auth", "applicant"),
    ):
        dependencies = expected["services"][consumer]["depends_on"]
        assert provider not in dependencies
        dependencies[provider] = {"condition": "service_healthy", "required": True}
    # Applicant's native template reads use the same authenticated management
    # boundary as Gateway and Flow. Keep this one reviewed addition explicit.
    applicant = expected["services"]["applicant"]
    applicant["environment"]["ISSUANCE_API_KEY_FILE"] = "/run/secrets/issuance_api_key"
    applicant["secrets"].append({"source": "issuance_api_key", "target": "/run/secrets/issuance_api_key"})
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


def required_input_sets(approved, current):
    required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", approved))
    optional_inputs = apply_foundation_reference_representation(yaml.safe_load(approved))
    current_required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", current))
    assert current_required == required - optional_inputs, (
        "Unreviewed required self-host inputs",
        sorted(current_required - (required - optional_inputs)),
        sorted((required - optional_inputs) - current_required),
    )
    return required, current_required


def interpolated_models():
    approved = (ROOT / APPROVED).read_text(encoding="utf-8")
    current = (ROOT / GATE["BASE"]).read_text(encoding="utf-8")
    required, current_required = required_input_sets(approved, current)
    assert "MARTY_ISSUANCE_IMAGE" not in required
    assert "BAO_ADDR" in required
    environment = yaml.safe_load(approved)["services"]["issuance"]["environment"]
    variables = (
        (
            set(re.findall(r"\$\{([A-Z0-9_]+):-", str(environment)))
            | set(SHARED_ADDITIONS)
            | set(NATIVE_ADDITIVE)
            | {"MARTY_ISSUER_DID"}
            | {"KEYCLOAK_PASSKEYS_ENABLED", "KEYCLOAK_PASSKEY_RP_ID"}
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
            ("passkeys", {"KEYCLOAK_PASSKEYS_ENABLED": "true", "KEYCLOAK_PASSKEY_RP_ID": "login.example.test"}),
            ("empty", dict.fromkeys(variables, "")),
            ("installer-dns-port", {
                "MARTY_ISSUER_DID": "did:web:identity.example%3A8443:orgs:marty",
            }),
            ("web-public", {"UI_ENABLED_SECTIONS": "public"}),
            ("web-console", {"UI_ENABLED_SECTIONS": "console"}),
            ("web-none", {"UI_ENABLED_SECTIONS": "none"}),
            # An explicitly empty value must reach startup validation unchanged;
            # replacing '-' with ':-' would silently re-enable both sections.
            ("web-empty", {"UI_ENABLED_SECTIONS": ""}),
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
            issuer_did = values.get("MARTY_ISSUER_DID") or f"did:web:synthetic.example:orgs:{slug}"
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
            assert_models(
                render(APPROVED, values), after, interpolated=True,
                issuer_did=values.get("MARTY_ISSUER_DID") or "",
                ui_enabled_sections=values.get("UI_ENABLED_SECTIONS", "public,console"),
                bureau_api_key_file=values.get("PERSONALIZATION_BUREAU_API_KEY_FILE") or "",
                canvas_api_token_file=values.get("CANVAS_CREDENTIALS_API_TOKEN_FILE") or "",
                passkeys_enabled=values.get("KEYCLOAK_PASSKEYS_ENABLED") or "",
                passkey_rp_id=values.get("KEYCLOAK_PASSKEY_RP_ID") or "",
            )
            print(f"PASS: self-host {mode} interpolated whole model")
        for file, source_required in (
            (APPROVED, required),
            (GATE["BASE"], current_required),
        ):
            for name in sorted(source_required):
                for value in (None, ""):
                    values = dict(inputs)
                    if value is None:
                        values.pop(name)
                    else:
                        values[name] = value
                    try:
                        render(file, values)
                    except subprocess.CalledProcessError as error:
                        assert f"required variable {name}" in error.stderr
                    else:
                        raise AssertionError(
                            f"Required self-host input accepted: {name}"
                        )
        print(
            f"PASS: {len(required)} historical/{len(current_required)} current "
            "required inputs reject missing/empty; "
            "retired Python image input is absent"
        )


def run():
    assert_input_inventory()
    data = (ROOT / APPROVED).read_text(encoding="utf-8").encode()
    assert (
        hashlib.sha256(data).hexdigest()
        == APPROVED_SHA256
    )
    before = GATE["render"](APPROVED)
    after = GATE["render"](GATE["BASE"])
    assert_models(before, after)
    for change in ("limit", "heap"):
        changed = deepcopy(after)
        if change == "limit":
            changed["services"]["keycloak"]["mem_limit"] = "1g"
        else:
            changed["services"]["keycloak"]["environment"]["JAVA_OPTS_KC_HEAP"] = (
                "-XX:MaxRAMPercentage=100"
            )
        try:
            assert_models(before, changed)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"Unreviewed Keycloak {change} drift was accepted")
    interpolated_models()
    print(
        "PASS: approved KMS-only self-host model and synthetic bindings (configuration only)"
    )


if __name__ == "__main__":
    run()
