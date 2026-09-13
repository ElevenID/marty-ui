from __future__ import annotations

import json
from copy import deepcopy

import pytest

from scripts import check_canvas_beta_capabilities as capabilities

from scripts.canvas_worker_runtime import NATIVE_WORKER


def _environment() -> dict[str, str]:
    return {
        "CANVAS_PORTABLE_INTEGRATION_ENABLED": "true",
        "CANVAS_PILOT_ORGANIZATION_IDS": "org-pilot",
        "CANVAS_LTI_EXPERIENCE_BASE_URL": "https://beta.elevenidllc.com",
        "CANVAS_OAUTH_COMPLETION_REDIRECT_URL": "https://beta.elevenidllc.com/console/org/deploy/canvas",
        "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST": "https://canvas-test.elevenidllc.com",
        "CANVAS_LEGACY_EVENT_INGEST_ENABLED": "false",
        "CANVAS_ALLOW_PRIVATE_BASE_URLS": "false",
        "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS": "false",
        "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS": "900",
        "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS": "900",
        "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID": "org-signing-system",
        "CANVAS_LTI_TOOL_ISSUER_DID": "did:web:beta.elevenidllc.com:orgs:marty",
        "CANVAS_SYNC_PROCESSOR": "issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target",
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "600",
    }


def _native_provenance():
    worker = _environment()
    worker.pop("CANVAS_SYNC_PROCESSOR")
    worker.update(MARTY_UI_SHA="b" * 40, MARTY_RELEASE_VERSION="synthetic-release")
    image_id = "sha256:" + "c" * 64
    reference = "elevenid-local/canvas-sync-worker:synthetic-release"
    image = {
        "Id": image_id,
        "Config": {
            "Labels": {
                "org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
                "org.opencontainers.image.revision": worker["MARTY_UI_SHA"],
                "org.opencontainers.image.version": worker["MARTY_RELEASE_VERSION"],
            }
        },
    }
    return worker, image_id, reference, image


def test_native_beta_checks_actual_image_provenance_not_python_image_equality(
    monkeypatch,
):
    issuance = _environment()
    worker, image_id, reference, image = _native_provenance()
    _install_runtime(monkeypatch, issuance)
    legacy_container = capabilities._container
    monkeypatch.setattr(
        capabilities,
        "_container",
        lambda service: (
            (worker, image_id, reference, {"Entrypoint": None, "Cmd": [NATIVE_WORKER]})
            if service == capabilities.WORKER_SERVICE
            else legacy_container(service)
        ),
    )
    calls = []

    def inspect(*args):
        calls.append(args)
        assert args == ("image", "inspect", reference)
        return [image]

    monkeypatch.setattr(capabilities, "_docker_json", inspect)
    report = capabilities.validate("org-pilot")
    assert report["checks"]["canvas_worker_runtime_verified"] is True
    assert len(calls) == 1
    assert reference not in json.dumps(report)


@pytest.mark.parametrize(
    "field,value",
    [
        ("Id", "sha256:" + "d" * 64),
        ("org.opencontainers.image.source", "https://private.example/source"),
        ("org.opencontainers.image.revision", "e" * 40),
        ("org.opencontainers.image.revision", "private-not-a-sha"),
        ("org.opencontainers.image.version", "private-other-release"),
        ("org.opencontainers.image.version", "development"),
    ],
)
def test_native_worker_rejects_retargeted_image_or_wrong_source_revision_release(
    monkeypatch, field, value
):
    worker, image_id, reference, original = _native_provenance()
    image = deepcopy(original)
    if field == "Id":
        image[field] = value
    else:
        image["Config"]["Labels"][field] = value
    monkeypatch.setattr(capabilities, "_docker_json", lambda *args: [image])
    with pytest.raises(capabilities.CapabilityError) as error:
        capabilities._native_image(worker, image_id, reference)
    assert value not in str(error.value)


def test_native_image_inspection_failure_never_repeats_private_reference(monkeypatch):
    worker, image_id, _, _ = _native_provenance()
    private = "private-registry-reference-with-secret"

    def fail(*args):
        raise capabilities.CapabilityError(private)

    monkeypatch.setattr(capabilities, "_docker_json", fail)
    with pytest.raises(capabilities.CapabilityError) as error:
        capabilities._native_image(worker, image_id, private)
    assert str(error.value) == "Canvas worker image inspection failed"


def test_container_duplicate_environment_cannot_hide_processor_or_selector(monkeypatch):
    monkeypatch.setattr(
        capabilities, "_container_id", lambda service: "synthetic-container"
    )
    monkeypatch.setattr(
        capabilities,
        "_docker_json",
        lambda *args: [
            {
                "State": {"Running": True},
                "Config": {
                    "Env": [
                        "SERVICE_NAME=canvas_sync_worker",
                        "SERVICE_NAME=private-wrong",
                    ]
                },
            }
        ],
    )
    with pytest.raises(
        capabilities.CapabilityError, match="duplicate settings"
    ) as error:
        capabilities._container("canvas-sync-worker")
    assert "private-wrong" not in str(error.value)


def _install_runtime(
    monkeypatch: pytest.MonkeyPatch,
    issuance: dict[str, str],
    worker: dict[str, str] | None = None,
) -> None:
    worker = dict(issuance if worker is None else worker)
    monkeypatch.setattr(
        capabilities,
        "_container",
        lambda name: (
            dict(issuance if name == capabilities.ISSUANCE_SERVICE else worker),
            "sha256:" + "a" * 64,
            "elevenid-local/issuance:test",
            {"Entrypoint": None, "Cmd": ["python", "-m", "issuance.canvas_worker"]},
        ),
    )
    monkeypatch.setattr(
        capabilities,
        "_public_jwks",
        lambda issuer_did: {
            f"{issuer_did}#lti-tool-marty-rs256": {
                "kid": f"{issuer_did}#lti-tool-marty-rs256"
            }
        },
    )


def test_beta_container_discovery_is_compose_project_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[tuple[str, ...]] = []

    def fake_docker_json(*args: str) -> str:
        captured.append(args)
        return "container-id"

    monkeypatch.setattr(capabilities, "_docker_json", fake_docker_json)
    assert capabilities._container_id("issuance") == "container-id"
    assert captured == [
        (
            "ps",
            "--filter",
            "label=com.docker.compose.project=elevenid-beta",
            "--filter",
            "label=com.docker.compose.service=issuance",
            "--format",
            "{{json .ID}}",
        )
    ]


def test_beta_capability_preflight_proves_deployed_runtime_without_secret_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = _environment()
    _install_runtime(monkeypatch, env)
    report = capabilities.validate("org-pilot")
    serialized = json.dumps(report)
    assert report["checks"]["issuer_did_rs256_signer"] is True
    assert report["checks"]["readiness_and_evidence_ttls_fail_closed"] is True
    assert report["checks"]["worker_job_deadline_fail_closed"] is True
    assert report["composite_binding_readiness_required"] is True
    assert "public-modulus" not in serialized
    assert "org-signing-system" not in serialized
    assert report["checks"]["canvas_worker_runtime_verified"] is True


@pytest.mark.parametrize("mismatch", ["image_id", "reference", "missing", "callback"])
def test_legacy_beta_still_requires_same_image_and_python_processor(
    monkeypatch, mismatch
):
    _install_runtime(monkeypatch, _environment())
    original_container = capabilities._container

    def container(service):
        env, image_id, reference, config = original_container(service)
        if service == capabilities.WORKER_SERVICE:
            if mismatch == "image_id":
                image_id = "sha256:" + "f" * 64
            elif mismatch == "reference":
                reference = "elevenid-local/issuance:different"
            elif mismatch == "missing":
                env.pop("CANVAS_SYNC_PROCESSOR")
            else:
                env["CANVAS_SYNC_PROCESSOR"] = "not-a-module-function"
        return env, image_id, reference, config

    monkeypatch.setattr(capabilities, "_container", container)
    with pytest.raises(capabilities.CapabilityError):
        capabilities.validate("org-pilot")


def test_beta_capability_preflight_rejects_job_only_feature_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = _environment()
    env["CANVAS_PORTABLE_INTEGRATION_ENABLED"] = "false"
    _install_runtime(monkeypatch, env)
    with pytest.raises(
        capabilities.CapabilityError, match="not enabled in deployed beta issuance"
    ):
        capabilities.validate("org-pilot")


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        (
            "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS",
            "901",
            "readiness/KMS challenge TTL",
        ),
        ("CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS", "", "issuance evidence TTL"),
        ("CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS", "601", "absolute job deadline"),
    ],
)
def test_beta_capability_preflight_requires_pilot_ttls(
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
    value: str,
    message: str,
) -> None:
    env = _environment()
    env[setting] = value
    _install_runtime(monkeypatch, env)
    with pytest.raises(capabilities.CapabilityError, match=message):
        capabilities.validate("org-pilot")
