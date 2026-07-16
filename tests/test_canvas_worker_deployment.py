from __future__ import annotations

from pathlib import Path
import runpy

import pytest
import yaml
from marty_devops import DeploymentCatalog


ROOT = Path(__file__).resolve().parents[1]
PROCESSOR = (
    "issuance.infrastructure.api.canvas_routes:"
    "process_authoritative_canvas_sync_target"
)


def _yaml(path: str):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def test_compose_stacks_run_canvas_worker_outside_issuance_web_process() -> None:
    for path in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        services = _yaml(path)["services"]
        api = services["issuance"]
        worker = services["canvas-sync-worker"]

        assert "canvas_worker" not in str(api.get("command", ""))
        assert "issuance.canvas_worker" in str(worker["command"])
        assert worker["healthcheck"] == {"disable": True}
        assert "ports" not in worker
        assert worker["depends_on"]["db-migrate"]["condition"] == "service_completed_successfully"

        environment = worker["environment"]
        api_environment = api["environment"]
        assert "CANVAS_OAUTH_COMPLETION_REDIRECT_URL" in api_environment
        assert "CANVAS_PORTABLE_INTEGRATION_ENABLED" in environment
        assert {"TOKEN_HMAC_KEY", "TOKEN_HMAC_KEY_FILE"}.intersection(environment)
        assert "CANVAS_LEGACY_EVENT_INGEST_ENABLED" in environment
        assert "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID" in environment
        assert "CANVAS_LTI_TOOL_SIGNING_SERVICE_ID" in environment
        assert "CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE" in environment
        assert "CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES" in environment
        assert "CANVAS_LTI_TOOL_ACTIVE_KID" in environment
        assert "CANVAS_LTI_TOOL_PUBLIC_JWKS" in environment
        assert environment["CANVAS_BINDING_READINESS_MAX_AGE_SECONDS"].endswith(
            ":-900}"
        )
        assert environment["CANVAS_BACKGROUND_ROSTER_BATCH_SIZE"].endswith(":-500}")
        assert environment["CANVAS_BACKGROUND_ROSTER_MAX_SIZE"].endswith(":-5000}")
        assert environment["CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"].endswith(":-600}")
        assert environment["SIGNING_KEYS_INTERNAL_URL"] == "http://gateway:8000/internal/signing-keys"
        assert {"SIGNING_KEYS_INTERNAL_API_KEY", "SIGNING_KEYS_INTERNAL_API_KEY_FILE"}.intersection(environment)
        for key in (
            "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID",
            "CANVAS_LTI_TOOL_SIGNING_SERVICE_ID",
            "CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE",
            "CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES",
            "CANVAS_LTI_TOOL_ACTIVE_KID",
            "CANVAS_LTI_TOOL_PUBLIC_JWKS",
        ):
            assert key in api_environment
        assert api_environment["CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS"].endswith(
            ":-900}"
        )
        assert api_environment["CANVAS_BINDING_READINESS_MAX_AGE_SECONDS"].endswith(
            ":-900}"
        )
        for private_key_setting in (
            "CANVAS_LTI_TOOL_PRIVATE_JWKS",
            "CANVAS_LTI_TOOL_PRIVATE_JWKS_FILE",
            "CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK",
            "CANVAS_LTI_DEEP_LINKING_PRIVATE_JWK_FILE",
            "CANVAS_LTI_ALLOW_LOCAL_PRIVATE_JWK",
        ):
            assert private_key_setting not in environment
            assert private_key_setting not in api_environment
        assert PROCESSOR in environment["CANVAS_SYNC_PROCESSOR"]
        assert "CANVAS_SYNC_WORKER_POLL_SECONDS" in environment


def test_kubernetes_runs_headless_canvas_worker_as_its_own_deployment() -> None:
    documents = list(
        yaml.safe_load_all(
            (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
        )
    )
    worker = next(
        document
        for document in documents
        if document
        and document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "canvas-sync-worker"
    )
    container = worker["spec"]["template"]["spec"]["containers"][0]

    assert container["command"] == ["python"]
    assert container["args"] == ["-m", "issuance.canvas_worker"]
    assert "ports" not in container
    assert container["envFrom"] == [{"configMapRef": {"name": "marty-config"}}]
    secret_names = {
        item["name"]: item["valueFrom"]["secretKeyRef"]["key"]
        for item in container["env"]
        if "valueFrom" in item
    }
    assert secret_names == {
        "DATABASE_URL": "DATABASE_URL",
        "INTEGRATION_SECRET_MASTER_KEY": "INTEGRATION_SECRET_MASTER_KEY",
        "SIGNING_KEYS_INTERNAL_API_KEY": "SIGNING_KEYS_INTERNAL_API_KEY",
    }
    assert next(item for item in container["env"] if item["name"] == "SIGNING_KEYS_INTERNAL_URL")["value"] == (
        "http://gateway:8000/internal/signing-keys"
    )


def test_selfhost_bundle_reuses_the_published_services_image_for_worker() -> None:
    override = (ROOT / "docker-compose.selfhost.bundle.override.yml").read_text(
        encoding="utf-8"
    )
    worker_block = override.split("  canvas-sync-worker:", 1)[1].split(
        "\n  applicant:", 1
    )[0]

    assert "*selfhost-service-image" in worker_block
    assert "SERVICE_NAME: issuance" in worker_block


def test_canvas_worker_is_required_by_production_deployment_catalogs() -> None:
    catalog = DeploymentCatalog.load(ROOT)

    for stack in ("selfhost-production", "kubernetes-production"):
        assert "canvas-sync-worker" in catalog.running_services_for_stack(stack)

    service = catalog.services["canvas-sync-worker"]
    assert service["compose_service"] == "canvas-sync-worker"
    assert service["k8s_deployment"] == "canvas-sync-worker"
    assert service["image_name"] == "issuance"
    assert service["group"] == "app"
    assert "canvas-sync-worker" in catalog.service_groups["app"]


def test_kubernetes_canvas_worker_configuration_includes_safe_defaults() -> None:
    config = _yaml("k8s/oracle/01-configmap.yaml")["data"]
    expected = {
        "CANVAS_PORTABLE_INTEGRATION_ENABLED",
        "CANVAS_PILOT_ORGANIZATION_IDS",
        "CANVAS_LEGACY_EVENT_INGEST_ENABLED",
        "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID",
        "CANVAS_LTI_TOOL_SIGNING_SERVICE_ID",
        "CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE",
        "CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES",
        "CANVAS_LTI_TOOL_ACTIVE_KID",
        "CANVAS_LTI_TOOL_PUBLIC_JWKS",
        "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS",
        "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS",
        "CANVAS_BACKGROUND_ROSTER_BATCH_SIZE",
        "CANVAS_BACKGROUND_ROSTER_MAX_SIZE",
        "CANVAS_SYNC_PROCESSOR",
        "CANVAS_SYNC_WORKER_BATCH_SIZE",
        "CANVAS_SYNC_WORKER_LEASE_SECONDS",
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS",
        "CANVAS_SYNC_SCHEDULE_LIMIT",
        "CANVAS_OAUTH_REVOCATION_BATCH_SIZE",
        "CANVAS_SYNC_WORKER_POLL_SECONDS",
    }

    assert expected.issubset(config)
    assert config["CANVAS_BINDING_READINESS_MAX_AGE_SECONDS"] == "900"
    assert config["CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS"] == "900"
    assert config["CANVAS_BACKGROUND_ROSTER_BATCH_SIZE"] == "500"
    assert config["CANVAS_BACKGROUND_ROSTER_MAX_SIZE"] == "5000"
    assert config["CANVAS_SYNC_PROCESSOR"] == PROCESSOR
    assert config["CANVAS_SYNC_WORKER_BATCH_SIZE"] == "10"
    assert config["CANVAS_SYNC_WORKER_LEASE_SECONDS"] == "120"
    assert config["CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"] == "600"
    assert config["CANVAS_SYNC_SCHEDULE_LIMIT"] == "100"
    assert config["CANVAS_OAUTH_REVOCATION_BATCH_SIZE"] == "25"
    assert config["CANVAS_SYNC_WORKER_POLL_SECONDS"] == "5"


def test_production_preflight_requires_a_configured_canvas_worker_processor() -> None:
    namespace = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
    validate = namespace["validate_selfhost_canvas_public_config"]
    check_error = namespace["CheckError"]
    enabled = {
        "CANVAS_PORTABLE_INTEGRATION_ENABLED": "true",
        "CANVAS_LTI_EXPERIENCE_BASE_URL": "https://marty.example.com",
        "CANVAS_PILOT_ORGANIZATION_IDS": "org-pilot",
        "CANVAS_LEGACY_EVENT_INGEST_ENABLED": "false",
        "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID": "system-tools",
        "CANVAS_LTI_TOOL_SIGNING_SERVICE_ID": "canvas-lti-rs256",
        "CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE": "kms://canvas-lti-key",
        "CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES": "kms://credential-issuer-key",
        "CANVAS_LTI_TOOL_ACTIVE_KID": "canvas-lti-active",
        "CANVAS_LTI_TOOL_PUBLIC_JWKS": (
            '{"keys":[{"kty":"RSA","alg":"RS256","use":"sig",'
            '"kid":"canvas-lti-active","n":"public-modulus","e":"AQAB"}]}'
        ),
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "600",
    }

    with pytest.raises(check_error, match="CANVAS_SYNC_PROCESSOR"):
        validate(enabled)

    without_issuer_inventory = dict(enabled)
    without_issuer_inventory.pop("CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES")
    with pytest.raises(check_error, match="must inventory"):
        validate({**without_issuer_inventory, "CANVAS_SYNC_PROCESSOR": PROCESSOR})

    result = validate({**enabled, "CANVAS_SYNC_PROCESSOR": PROCESSOR})
    assert "CANVAS_SYNC_PROCESSOR" in result
    assert "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS" in result

    with pytest.raises(check_error, match="CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"):
        validate({
            **enabled,
            "CANVAS_SYNC_PROCESSOR": PROCESSOR,
            "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "601",
        })

    private_jwks = enabled["CANVAS_LTI_TOOL_PUBLIC_JWKS"].replace(
        '"e":"AQAB"',
        '"e":"AQAB","d":"private-material"',
    )
    with pytest.raises(check_error, match="private RSA parameters"):
        validate({
            **enabled,
            "CANVAS_SYNC_PROCESSOR": PROCESSOR,
            "CANVAS_LTI_TOOL_PUBLIC_JWKS": private_jwks,
        })

    with pytest.raises(check_error, match="credential issuer/document-signing key"):
        validate({
            **enabled,
            "CANVAS_SYNC_PROCESSOR": PROCESSOR,
            "CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE": "cred-issuer-marty-rs256",
        })

    with pytest.raises(check_error, match="also listed"):
        validate({
            **enabled,
            "CANVAS_SYNC_PROCESSOR": PROCESSOR,
            "CANVAS_CREDENTIAL_ISSUER_KEY_REFERENCES": (
                "kms://credential-key,kms://canvas-lti-key"
            ),
        })

    with pytest.raises(check_error, match="lti-tool- namespace"):
        validate({
            **enabled,
            "CANVAS_SYNC_PROCESSOR": PROCESSOR,
            "CANVAS_LTI_TOOL_SIGNING_SERVICE_ID": "managed-openbao-transit",
        })

    managed = validate({
        **enabled,
        "CANVAS_SYNC_PROCESSOR": PROCESSOR,
        "CANVAS_LTI_TOOL_SIGNING_SERVICE_ID": "managed-openbao-transit",
        "CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE": "lti-tool-marty-rs256",
    })
    assert "CANVAS_LTI_TOOL_SIGNING_KEY_REFERENCE" in managed
