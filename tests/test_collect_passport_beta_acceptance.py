"""Behavioral checks for the live, fail-closed passport beta collector."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from scripts.collect_passport_beta_acceptance import (
    BETA_ORIGIN,
    REQUIRED_PROBES,
    SERVICES,
    EvidenceError,
    collect,
    verify_attestations,
)


COMMIT = "a" * 40
OCI = "sha256:" + "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
REFERENCE = "ghcr.io/elevenid/marty-ui-oss/services@" + OCI
UI_URI = "ghcr.io/elevenid/marty-ui-oss/ui"
MIGRATIONS_URI = "ghcr.io/elevenid/marty-ui-oss/migrations"


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def fixture(tmp_path: Path) -> tuple[dict, dict, dict]:
    manifest = {
        "schema": "marty.stack/v1", "release": "marty-ui@1.1.999",
        "components": [{"name": "marty-ui", "repository": "ElevenID/marty-ui", "commit": COMMIT,
                        "artifacts": [
                            {"type": "oci", "uri": UI_URI, "digest": "sha256:" + "d" * 64},
                            {"type": "oci", "uri": REFERENCE.split("@")[0], "digest": OCI},
                            {"type": "oci", "uri": MIGRATIONS_URI, "digest": "sha256:" + "e" * 64},
                        ]}],
    }
    source = {"schema_version": 2, "source_kind": "official-stack-release",
              "marty_ui_sha": COMMIT, "release_version": "1.1.999",
              "promotion_eligible": True, "release_ready": True}
    deployment = {
        "schema_version": 1, "source_kind": "official-stack-release", "marty_ui_sha": COMMIT,
        "release_version": "1.1.999", "beta_origin": BETA_ORIGIN,
        "compose_project": "elevenid-beta", "ui_compose_project": "elevenid-beta-ui",
        "source_manifest": "source-manifest.json",
        "official_stack_manifest": "stack-manifest.json",
        "images": [
            {"service": service, "container_id": service + "-container",
             "compose_project": "elevenid-beta", "compose_service": service,
             "image_id": IMAGE_ID, "configured_image": REFERENCE}
            for service in SERVICES
        ],
    }
    write(tmp_path / "stack-manifest.json", manifest)
    write(tmp_path / "source-manifest.json", source)
    deployment["official_stack_manifest_sha256"] = hashlib.sha256(
        (tmp_path / "stack-manifest.json").read_bytes()
    ).hexdigest()
    source["stack_manifest_sha256"] = deployment["official_stack_manifest_sha256"]
    write(tmp_path / "source-manifest.json", source)
    write(tmp_path / "local-deployment-manifest.json", deployment)
    return manifest, source, deployment


def inspect(container_id: str) -> dict:
    service = container_id.removesuffix("-container")
    return {
        "Image": IMAGE_ID,
        "Config": {"Image": REFERENCE, "Labels": {
            "com.docker.compose.project": "elevenid-beta",
            "com.docker.compose.service": service,
        }},
        "State": {"Running": True, "Status": "running", "Health": {"Status": "healthy"}},
    }


def probe(api_key: str | None) -> tuple[int, dict | None]:
    if not api_key:
        return 401, None
    return 200, {"supported": True, "encrypted_artifact_store": True,
                 "bureau_configured": True, "blockers": [],
                 "signer": {"configured": True, "mode": "MANAGED_ISSUER_PROFILE", "blockers": []}}


def test_collects_live_beta_prerequisites_without_qualifying_retirement(tmp_path: Path) -> None:
    fixture(tmp_path)
    report = collect(tmp_path, api_key="in-memory-only", inspect=inspect, probe=probe)
    assert report["schema"] == "marty.passport-beta-acceptance/v1"
    assert report["status"] == "blocked"
    assert report["release"]["source_commit"] == COMMIT
    assert report["release"]["stack_manifest_sha256"] == hashlib.sha256((tmp_path / "stack-manifest.json").read_bytes()).hexdigest()
    assert report["release"]["oci_digests"][REFERENCE.split("@")[0]] == OCI
    assert report["deployment"]["local_deployment_manifest_sha256"] == hashlib.sha256((tmp_path / "local-deployment-manifest.json").read_bytes()).hexdigest()
    assert report["deployment"]["source_manifest_sha256"] == hashlib.sha256((tmp_path / "source-manifest.json").read_bytes()).hexdigest()
    assert report["release"]["signed_manifest_verified"] is False
    assert report["probes"]["capabilities_http"]["verified"] is True
    assert report["probes"]["unauthenticated_denial"]["verified"] is True
    assert all(report["probes"][key] == {"verified": False, "evidence": None} for key in REQUIRED_PROBES)
    assert set(report["runtime_images"]) == set(SERVICES)
    assert "in-memory-only" not in json.dumps(report)


def test_attestation_result_is_bound_to_the_exact_manifest_and_images(tmp_path: Path) -> None:
    fixture(tmp_path)
    seen = []

    def attest(path: Path, digests: dict[str, str], source_commit: str) -> bool:
        seen.append((path, digests, source_commit))
        return True

    report = collect(tmp_path, api_key="in-memory-only", inspect=inspect, probe=probe, attest=attest)
    assert seen == [(tmp_path / "stack-manifest.json", report["release"]["oci_digests"], COMMIT)]
    assert report["release"]["signed_manifest_verified"] is True
    assert report["status"] == "blocked"


def test_optional_provider_ingress_must_match_signed_deployment_when_present(tmp_path: Path) -> None:
    _, _, deployment = fixture(tmp_path)
    deployment["images"].append({
        "service": "passport-provider-ingress", "container_id": "passport-provider-ingress-container",
        "compose_project": "elevenid-beta", "compose_service": "passport-provider-ingress",
        "image_id": IMAGE_ID, "configured_image": REFERENCE,
    })
    write(tmp_path / "local-deployment-manifest.json", deployment)
    report = collect(tmp_path, api_key="in-memory-only", inspect=inspect, probe=probe)
    assert set(report["runtime_images"]) == set(SERVICES)
    assert report["provider_ingress_runtime_image"]["oci_reference"] == REFERENCE
    deployment["images"][-1]["configured_image"] = "ghcr.io/foreign/provider@" + OCI
    write(tmp_path / "local-deployment-manifest.json", deployment)

    def foreign_inspect(container_id: str) -> dict:
        record = inspect(container_id)
        if container_id == "passport-provider-ingress-container":
            record["Config"]["Image"] = deployment["images"][-1]["configured_image"]
        return record

    with pytest.raises(EvidenceError, match="signed Marty services OCI"):
        collect(tmp_path, api_key="in-memory-only", inspect=foreign_inspect, probe=probe)


def test_attestation_checks_checksum_and_each_immutable_oci(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture(tmp_path)
    manifest_path = tmp_path / "stack-manifest.json"
    checksum = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (tmp_path / "SHA256SUMS").write_text(f"{checksum}  stack-manifest.json\n", encoding="utf-8")
    calls = []

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    oci_digests = {UI_URI: "sha256:" + "d" * 64, REFERENCE.split("@")[0]: OCI,
                   MIGRATIONS_URI: "sha256:" + "e" * 64}
    assert verify_attestations(manifest_path, oci_digests, COMMIT) is True
    assert len(calls) == 4
    assert calls[0][3] == str(manifest_path)
    assert {call[3] for call in calls[1:]} == {
        f"oci://{uri}@{digest}" for uri, digest in oci_digests.items()
    }
    for call in calls:
        assert call[call.index("--signer-workflow") + 1] == "ElevenID/marty-ui/.github/workflows/cd.yml"
        assert call[call.index("--source-digest") + 1] == COMMIT
        assert call[call.index("--source-ref") + 1] == "refs/heads/main"
        assert "--deny-self-hosted-runners" in call
    def rejected(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(1, args)
    monkeypatch.setattr(subprocess, "run", rejected)
    with pytest.raises(EvidenceError, match="attestation"):
        verify_attestations(manifest_path, oci_digests, COMMIT)
    (tmp_path / "SHA256SUMS").write_text(f"{'0' * 64}  stack-manifest.json\n", encoding="utf-8")
    with pytest.raises(EvidenceError, match="checksum"):
        verify_attestations(manifest_path, oci_digests, COMMIT)


@pytest.mark.parametrize("tamper", ["source", "image", "origin", "unsigned_image", "unauth", "manifest_hash", "self_signed_signer", "compose_owner"])
def test_refuses_drift_and_false_runtime_proof(tmp_path: Path, tamper: str) -> None:
    _, source, deployment = fixture(tmp_path)
    live_inspect = inspect
    live_probe = probe
    if tamper == "source":
        source["marty_ui_sha"] = "d" * 40
        write(tmp_path / "source-manifest.json", source)
    elif tamper == "image":
        deployment["images"][0]["image_id"] = "sha256:" + "d" * 64
        write(tmp_path / "local-deployment-manifest.json", deployment)
    elif tamper == "origin":
        deployment["beta_origin"] = "https://elevenidllc.com"
        write(tmp_path / "local-deployment-manifest.json", deployment)
    elif tamper == "unsigned_image":
        def wrong_image(container_id: str) -> dict:
            record = inspect(container_id)
            record["Config"]["Image"] = "ghcr.io/other/unsigned:latest"
            return record
        live_inspect = wrong_image
    elif tamper == "unauth":
        def open_capabilities(api_key: str | None) -> tuple[int, dict | None]:
            return 200, {"supported": True}
        live_probe = open_capabilities
    elif tamper == "manifest_hash":
        source["stack_manifest_sha256"] = "d" * 64
        write(tmp_path / "source-manifest.json", source)
    elif tamper == "self_signed_signer":
        def self_signed(api_key: str | None) -> tuple[int, dict | None]:
            status, body = probe(api_key)
            if body is not None:
                body["signer"]["mode"] = "SELF_SIGNED_TEST"
            return status, body
        live_probe = self_signed
    elif tamper == "compose_owner":
        deployment["images"][0]["compose_service"] = "other"
        write(tmp_path / "local-deployment-manifest.json", deployment)
    with pytest.raises(EvidenceError):
        collect(tmp_path, api_key="in-memory-only", inspect=live_inspect, probe=live_probe)
