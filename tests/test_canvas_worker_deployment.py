from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import subprocess
import tomllib

import pytest
import yaml
from marty_devops import DeploymentCatalog


ROOT = Path(__file__).resolve().parents[1]
PROCESSOR = (
    "issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target"
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
        assert (
            worker["depends_on"]["db-migrate"]["condition"]
            == "service_completed_successfully"
        )
        assert (
            worker["depends_on"]["issuance-migrations"]["condition"]
            == "service_completed_successfully"
        )

        environment = worker["environment"]
        api_environment = api["environment"]
        assert "CANVAS_OAUTH_COMPLETION_REDIRECT_URL" in api_environment
        assert "CANVAS_PORTABLE_INTEGRATION_ENABLED" in environment
        assert {"TOKEN_HMAC_KEY", "TOKEN_HMAC_KEY_FILE"}.intersection(environment)
        assert "CANVAS_LEGACY_EVENT_INGEST_ENABLED" in environment
        assert "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID" in environment
        assert "CANVAS_LTI_TOOL_ISSUER_DID" in environment
        assert "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS" in environment
        assert "CANVAS_LTI_TOOL_ACTIVE_KID" in environment
        assert "CANVAS_LTI_TOOL_PUBLIC_JWKS" in environment
        assert environment["CANVAS_BINDING_READINESS_MAX_AGE_SECONDS"].endswith(
            ":-900}"
        )
        assert environment["CANVAS_BACKGROUND_ROSTER_BATCH_SIZE"].endswith(":-500}")
        assert environment["CANVAS_BACKGROUND_ROSTER_MAX_SIZE"].endswith(":-5000}")
        assert environment["CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"].endswith(":-600}")
        assert (
            environment["SIGNING_KEYS_INTERNAL_URL"]
            == "http://gateway:8000/internal/signing-keys"
        )
        assert {
            "SIGNING_KEYS_INTERNAL_API_KEY",
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
        }.intersection(environment)
        for key in (
            "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID",
            "CANVAS_LTI_TOOL_ISSUER_DID",
            "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS",
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


def test_unrouted_rust_candidate_is_packaged_without_changing_consumers() -> None:
    cargo = (ROOT / "rust/services/issuance/Cargo.toml").read_text(encoding="utf-8")
    worker = (ROOT / "rust/services/issuance/src/bin/canvas_sync_worker.rs").read_text(
        encoding="utf-8"
    )
    service_image = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    ci_image = (ROOT / "rust/services/Dockerfile.ci").read_text(encoding="utf-8")

    assert 'name = "marty-canvas-sync-worker"' in cargo
    worker_target = next(
        target
        for target in tomllib.loads(cargo)["bin"]
        if target["name"] == "marty-canvas-sync-worker"
    )
    assert worker_target.get("test", True), (
        "workspace tests must execute worker binary tests"
    )
    assert "NativeCanvasSyncProcessor::new" in worker
    assert "canvas_sync_processor_unavailable" not in worker
    for dockerfile in (service_image, ci_image):
        assert "--bin marty-canvas-sync-worker" in dockerfile
        assert "target/release/marty-canvas-sync-worker" in dockerfile

    # Candidate packaging is not a cutover: every production consumer remains
    # on the Python oracle until the frozen differential/deletion gates pass.
    for path in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        worker = _yaml(path)["services"]["canvas-sync-worker"]
        assert "issuance.canvas_worker" in str(worker["command"])
        assert PROCESSOR in worker["environment"]["CANVAS_SYNC_PROCESSOR"]


def test_deployments_migrate_issuance_from_the_released_credentials_image() -> None:
    for path in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        services = _yaml(path)["services"]
        migration = services["issuance-migrations"]

        assert migration["image"] == services["issuance"]["image"]
        command = str(migration["command"])
        assert "manage_migrations.py" in command
        assert "upgrade" in command
        assert migration["healthcheck"] == {"disable": True}
        assert migration["restart"] == "no"
        assert (
            migration["depends_on"]["db-migrate"]["condition"]
            == "service_completed_successfully"
        )
        assert (
            services["issuance"]["depends_on"]["issuance-migrations"]["condition"]
            == "service_completed_successfully"
        )

    kubernetes = _yaml("k8s/oracle/06a-issuance-migrations.yaml")
    assert kubernetes["kind"] == "Job"
    assert kubernetes["metadata"]["name"] == "issuance-migrations"
    container = kubernetes["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "${OCIR_REGISTRY}/marty-ui/issuance:${IMAGE_TAG}"
    assert container["command"] == ["python", "manage_migrations.py", "upgrade"]
    assert (
        container["env"][0]["valueFrom"]["secretKeyRef"]["key"] == "DATABASE_SYNC_URL"
    )

    deploy = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    ui_wait = deploy.index("condition=complete job/db-migrate")
    issuance_apply = deploy.index("06a-issuance-migrations.yaml")
    issuance_wait = deploy.index("condition=complete job/issuance-migrations")
    assert ui_wait < issuance_apply < issuance_wait


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
    assert next(
        item for item in container["env"] if item["name"] == "SIGNING_KEYS_INTERNAL_URL"
    )["value"] == ("http://gateway:8000/internal/signing-keys")


@pytest.mark.parametrize(
    "service", ["canvas-sync-worker", "issuance", "issuance-migrations"]
)
def test_selfhost_bundle_does_not_override_unqualified_services(service) -> None:
    # Parse nodes rather than pretending Compose's !reset is ordinary YAML.
    # The executable rendering gate separately tests actual Compose merging.
    override = yaml.compose(
        (ROOT / "docker-compose.selfhost.bundle.override.yml").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(override, yaml.MappingNode)
    services = next(value for key, value in override.value if key.value == "services")
    assert isinstance(services, yaml.MappingNode)
    assert service not in {key.value for key, _ in services.value}


@pytest.fixture
def compose_worker_gate():
    return runpy.run_path(str(ROOT / "scripts/test_canvas_worker_compose_render.py"))


def test_ci_executes_real_compose_worker_merge_gate() -> None:
    workflow = _yaml(".github/workflows/ci.yml")
    steps = workflow["jobs"]["test-rust-service-images"]["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name") == "Verify merged Canvas worker deployment configuration"
    )
    assert gate["run"] == "python3 scripts/test_canvas_worker_compose_render.py"
    assert "if" not in gate and "continue-on-error" not in gate


@pytest.mark.parametrize(
    "field",
    [
        None,
        "image",
        "entrypoint",
        "command",
        "environment",
        "secrets",
        "depends_on",
        "healthcheck",
        "restart",
        "ports",
        "future_field",
    ],
)
def test_bundle_worker_comparison_preserves_every_field(compose_worker_gate, field):
    base = _yaml("docker-compose.selfhost.prod.yml")
    bundle = deepcopy(base)
    worker = bundle["services"]["canvas-sync-worker"]
    if field == "image":
        worker[field] = "synthetic-rust-services-image"
    elif field == "environment":
        worker[field]["SERVICE_NAME"] = "issuance_native"
    elif field == "secrets":
        worker[field].remove("integration_secret_master_key")
    elif field == "depends_on":
        worker[field]["issuance-migrations"]["condition"] = "service_started"
    elif field is not None:
        worker[field] = "synthetic-unexpected-change"
    compare = compose_worker_gate["assert_worker_preserved"]
    if field is None:
        compare(base, bundle)
    else:
        with pytest.raises(AssertionError, match="complete unqualified Python"):
            compare(base, bundle)


def test_compose_renderer_only_reads_fixed_sources_without_secret_resolution(
    compose_worker_gate, monkeypatch
):
    expected = {"services": {"canvas-sync-worker": {"synthetic": True}}}
    calls = []

    def execute(command, **options):
        calls.append((command, options))
        return subprocess.CompletedProcess(command, 0, json.dumps(expected), "")

    monkeypatch.setattr(compose_worker_gate["subprocess"], "run", execute)
    files = [compose_worker_gate["BASE"], compose_worker_gate["BUNDLE"]]
    assert compose_worker_gate["render"](*files) == expected
    assert calls == [
        (
            [
                "docker",
                "compose",
                "--env-file",
                os.devnull,
                "-f",
                files[0],
                "-f",
                files[1],
                "config",
                "--no-interpolate",
                "--no-env-resolution",
                "--no-path-resolution",
                "--no-consistency",
                "--format",
                "json",
            ],
            {
                "cwd": ROOT,
                "check": True,
                "capture_output": True,
                "text": True,
                "stdin": subprocess.DEVNULL,
                "timeout": 30,
            },
        )
    ]


@pytest.mark.parametrize("service", ["issuance", "issuance-migrations"])
@pytest.mark.parametrize(
    "field",
    [
        None,
        "image",
        "entrypoint",
        "command",
        "environment",
        "secrets",
        "volumes",
        "depends_on",
        "healthcheck",
        "restart",
        "future_field",
    ],
)
def test_bundle_issuance_comparison_preserves_every_field(
    compose_worker_gate, service, field
):
    base = _yaml("docker-compose.selfhost.prod.yml")
    bundle = deepcopy(base)
    if field is not None:
        bundle["services"][service][field] = "synthetic-unexpected-change"
    compare = compose_worker_gate["assert_published_issuance_preserved"]
    if field is None:
        compare(base, bundle)
    else:
        with pytest.raises(AssertionError, match="complete unqualified Python"):
            compare(base, bundle)


@pytest.mark.parametrize("failure", ["command", "timeout", "invalid_json"])
def test_compose_renderer_fails_closed(compose_worker_gate, monkeypatch, failure):
    def execute(command, **options):
        if failure == "command":
            raise subprocess.CalledProcessError(1, command)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, options["timeout"])
        return subprocess.CompletedProcess(command, 0, "not-json", "")

    monkeypatch.setattr(compose_worker_gate["subprocess"], "run", execute)
    with pytest.raises(
        (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError)
    ):
        compose_worker_gate["render"](compose_worker_gate["BASE"])


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
        "CANVAS_LTI_TOOL_ISSUER_DID",
        "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS",
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
        "CANVAS_LTI_TOOL_ISSUER_DID": "did:web:marty.example.com:orgs:system-tools",
        "CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS": "ip-marty-vc-jwt-issuer",
        "CANVAS_LTI_TOOL_ACTIVE_KID": "did:web:marty.example.com:orgs:system-tools#lti-tool-rs256",
        "CANVAS_LTI_TOOL_PUBLIC_JWKS": (
            '{"keys":[{"kty":"RSA","alg":"RS256","use":"sig",'
            '"kid":"did:web:marty.example.com:orgs:system-tools#lti-tool-rs256",'
            '"n":"public-modulus","e":"AQAB"}]}'
        ),
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "600",
    }

    with pytest.raises(check_error, match="CANVAS_SYNC_PROCESSOR"):
        validate(enabled)

    without_issuer_inventory = dict(enabled)
    without_issuer_inventory.pop("CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS")
    with pytest.raises(check_error, match="must inventory"):
        validate({**without_issuer_inventory, "CANVAS_SYNC_PROCESSOR": PROCESSOR})

    result = validate({**enabled, "CANVAS_SYNC_PROCESSOR": PROCESSOR})
    assert "CANVAS_SYNC_PROCESSOR" in result
    assert "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS" in result

    with pytest.raises(check_error, match="CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"):
        validate(
            {
                **enabled,
                "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "601",
            }
        )

    private_jwks = enabled["CANVAS_LTI_TOOL_PUBLIC_JWKS"].replace(
        '"e":"AQAB"',
        '"e":"AQAB","d":"private-material"',
    )
    with pytest.raises(check_error, match="private RSA parameters"):
        validate(
            {
                **enabled,
                "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                "CANVAS_LTI_TOOL_PUBLIC_JWKS": private_jwks,
            }
        )

    with pytest.raises(check_error, match="must be a DID"):
        validate(
            {
                **enabled,
                "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                "CANVAS_LTI_TOOL_ISSUER_DID": "kms://canvas-lti-key",
            }
        )

    with pytest.raises(check_error, match="verification method"):
        validate(
            {
                **enabled,
                "CANVAS_SYNC_PROCESSOR": PROCESSOR,
                "CANVAS_LTI_TOOL_ACTIVE_KID": "did:web:other.example#key-1",
            }
        )

    configured = validate(
        {
            **enabled,
            "CANVAS_SYNC_PROCESSOR": PROCESSOR,
        }
    )
    assert "CANVAS_LTI_TOOL_ISSUER_DID" in configured
