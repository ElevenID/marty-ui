#!/usr/bin/env python3
"""Collect bounded, live beta passport evidence without claiming physical issuance.

This prerequisite collector only performs GET requests and Docker inspection. A
separate, protected acceptance run must supply the mutating ceremony, issuance,
simulator callback, recovery, demo, and production-isolation evidence before retirement.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

if __package__:
    from .probe_passport_beta_gateway import ProbeError, exercise
else:
    from probe_passport_beta_gateway import ProbeError, exercise


BETA_ORIGIN = "https://beta.elevenidllc.com"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SERVICES = ("gateway", "flow", "issuance-native", "signing-keys", "passport-callback-signer", "passport-beta-bureau")
PHYSICAL_SERVICES = ("gateway", "flow", "issuance-native", "signing-keys",
                     "passport-callback-signer-supported", "passport-provider-ingress")
PASSPORT_PROFILE_SERVICES = set(SERVICES) | set(PHYSICAL_SERVICES)
OPTIONAL_SERVICES = ("passport-provider-ingress",)
REQUIRED_PROBES = (
    "managed_csca_dsc_chain", "sod_signature", "simulator_material_receipt",
    "nine_route_gateway_flow",
    "packaged_image", "physical_bureau_submission", "physical_bureau_batch",
    "signed_bureau_callback",
    "legacy_drain", "production_isolation", "physical_claim_boundary",
    "recorded_demo",
)


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"Invalid evidence file: {path.name}") from exc
    require(isinstance(value, dict), f"Invalid evidence object: {path.name}")
    return value


def digest_file(path: Path) -> str:
    try:
        with path.open("rb") as source:
            checksum = hashlib.file_digest(source, "sha256").hexdigest()
    except OSError as exc:
        raise EvidenceError(f"Cannot hash evidence file: {path.name}") from exc
    return f"sha256:{checksum}"


def _production_digest_commitment(api_key: str, label: str, digest: str) -> str:
    require(isinstance(api_key, str) and len(api_key) >= 32
            and label in {"production-snapshot", "production-attachments"}
            and isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            "Production baseline commitment input is invalid")
    return hmac.new(api_key.encode("utf-8"),
                    f"{label}:{digest}".encode("ascii"),
                    hashlib.sha256).hexdigest()


def production_snapshot_commitment(api_key: str, snapshot_sha256: str) -> str:
    return _production_digest_commitment(api_key, "production-snapshot",
                                         snapshot_sha256)


def production_attachment_commitment(api_key: str, attachment_sha256: str) -> str:
    return _production_digest_commitment(api_key, "production-attachments",
                                         attachment_sha256)


def docker_inspect(container_id: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["docker", "inspect", container_id], check=True, capture_output=True,
            text=True, encoding="utf-8", timeout=20,
        )
        records = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        # Docker inspection contains secret environment values. Never emit it.
        raise EvidenceError("Docker inspection failed") from exc
    require(isinstance(records, list) and len(records) == 1 and isinstance(records[0], dict), "Docker inspection is ambiguous")
    return records[0]


def verify_attestations(manifest_path: Path, oci_digests: dict[str, str], source_commit: str) -> bool:
    require(SHA.fullmatch(source_commit) is not None, "Attestation source commit is invalid")
    checksums = manifest_path.parent / "SHA256SUMS"
    try:
        lines = checksums.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise EvidenceError("Official stack checksums are missing") from exc
    matching = [line for line in lines if re.fullmatch(r"[0-9a-f]{64}  \*?\.?/?stack-manifest\.json", line)]
    require(len(matching) == 1 and matching[0][:64] == digest_file(manifest_path).removeprefix("sha256:"), "Official stack checksum mismatch")
    targets = [str(manifest_path), *(f"oci://{uri}@{digest}" for uri, digest in sorted(oci_digests.items()))]
    for target in targets:
        try:
            subprocess.run(
                ["gh", "attestation", "verify", target, "--repo", "ElevenID/marty-ui",
                 "--signer-workflow", "ElevenID/marty-ui/.github/workflows/cd.yml",
                 "--source-digest", source_commit, "--source-ref", "refs/heads/main",
                 "--deny-self-hosted-runners"],
                check=True, capture_output=True, text=True, timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise EvidenceError("Official stack attestation verification failed") from exc
    return True


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def get_capabilities(api_key: str | None) -> tuple[int, dict[str, Any] | None]:
    url = f"{BETA_ORIGIN}/v1/passport/capabilities"
    headers = {"Accept": "application/json", "Cache-Control": "no-cache", "User-Agent": "passport-beta-acceptance/1"}
    if api_key:
        headers["x-api-key"] = api_key
    request = Request(url, headers=headers, method="GET")
    try:
        with build_opener(NoRedirect).open(request, timeout=20) as response:
            require(response.geturl() == url, "Passport capability probe redirected")
            raw = response.read(64 * 1024 + 1)
            require(len(raw) <= 64 * 1024, "Passport capability response is oversized")
            payload = json.loads(raw)
            return response.status, payload if isinstance(payload, dict) else None
    except HTTPError as exc:
        return exc.code, None
    except (OSError, URLError, ValueError) as exc:
        raise EvidenceError("Passport capability probe failed") from exc


def collect(
    artifact_dir: Path,
    *,
    api_key: str | None = None,
    inspect: Callable[[str], dict[str, Any]] = docker_inspect,
    probe: Callable[[str | None], tuple[int, dict[str, Any] | None]] = get_capabilities,
    attest: Callable[[Path, dict[str, str], str], bool] | None = None,
    list_ids: Callable[[str], list[str]] | None = None,
    probe_native: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    if (artifact_dir / "aggregate-deployment.json").is_file():
        if __package__:
            from .collect_passport_beta_aggregate_acceptance import collect_aggregate
        else:
            from collect_passport_beta_aggregate_acceptance import collect_aggregate
        kwargs = {"list_ids": list_ids} if list_ids is not None else {}
        if probe_native is not None:
            kwargs["probe_native"] = probe_native
        return collect_aggregate(artifact_dir, api_key=api_key, inspect=inspect,
                                 probe=probe, attest=attest, **kwargs)
    deployment_path = artifact_dir / "local-deployment-manifest.json"
    deployment = read_json(deployment_path)
    require(deployment.get("beta_origin") == BETA_ORIGIN, "Deployment is not the beta origin")
    require(deployment.get("source_kind") == "official-stack-release", "Deployment is not an official aggregate release")
    source_name = deployment.get("source_manifest")
    require(source_name == "source-manifest.json", "Unexpected source manifest path")
    source_path = artifact_dir / source_name
    source = read_json(source_path)
    require(source.get("source_kind") == "official-stack-release", "Source is not an official aggregate release")
    commit = deployment.get("marty_ui_sha")
    require(isinstance(commit, str) and SHA.fullmatch(commit) is not None, "Invalid deployed source commit")
    require(source.get("marty_ui_sha") == commit, "Source and deployment commits differ")
    require(source.get("release_version") == deployment.get("release_version"), "Source and deployment releases differ")
    manifest_name = deployment.get("official_stack_manifest")
    require(manifest_name == "stack-manifest.json", "Official stack manifest is missing")
    manifest_path = artifact_dir / manifest_name
    manifest = read_json(manifest_path)
    manifest_digest = digest_file(manifest_path)
    require(manifest.get("schema") == "marty.stack/v1", "Unsupported stack manifest")
    require(manifest.get("release") == f"marty-ui@{deployment.get('release_version')}", "Stack and deployment releases differ")
    require(deployment.get("official_stack_manifest_sha256") in (manifest_digest, manifest_digest.removeprefix("sha256:")), "Stack manifest digest mismatch")
    require(source.get("stack_manifest_sha256") in (manifest_digest, manifest_digest.removeprefix("sha256:")), "Source and stack manifest digests differ")
    ui = [component for component in manifest.get("components", []) if isinstance(component, dict) and component.get("name") == "marty-ui" and component.get("repository") == "ElevenID/marty-ui"]
    require(len(ui) == 1 and ui[0].get("commit") == commit, "Manifest UI source differs from deployed source")
    oci_digests = {
        artifact["uri"]: artifact["digest"]
        for artifact in ui[0].get("artifacts", [])
        if isinstance(artifact, dict) and artifact.get("type") == "oci"
        and isinstance(artifact.get("uri"), str) and isinstance(artifact.get("digest"), str)
    }
    require(oci_digests and all(DIGEST.fullmatch(value) for value in oci_digests.values()), "Stack OCI digests are incomplete")
    require(set(oci_digests) == {
        "ghcr.io/elevenid/marty-ui-oss/ui",
        "ghcr.io/elevenid/marty-ui-oss/services",
        "ghcr.io/elevenid/marty-ui-oss/migrations",
    }, "Stack UI OCI roles are incomplete or ambiguous")
    require(len([artifact for artifact in ui[0]["artifacts"] if isinstance(artifact, dict) and artifact.get("type") == "oci"]) == 3, "Stack UI OCI roles must be unique")
    service_images = {f"{uri}@{digest}": digest for uri, digest in oci_digests.items() if uri == "ghcr.io/elevenid/marty-ui-oss/services"}
    require(len(service_images) == 1, "Stack must name one immutable Marty services image")
    signed = attest(manifest_path, oci_digests, commit) if attest is not None else False
    require(isinstance(signed, bool), "Invalid attestation verification result")
    records = deployment.get("images")
    require(isinstance(records, list), "Deployment image records are missing")
    provider_mode = deployment.get("passport_provider_mode", "simulator")
    require(provider_mode in ("simulator", "physical"), "Passport provider mode is invalid")
    selected_services = PHYSICAL_SERVICES if provider_mode == "physical" else SERVICES
    selected_records = {record.get("service") for record in records if isinstance(record, dict)}
    profile_records = selected_records & PASSPORT_PROFILE_SERVICES
    expected = set(selected_services)
    if provider_mode == "simulator" and "passport-provider-ingress" in profile_records:
        expected.add("passport-provider-ingress")
    require(profile_records == expected,
            "Deployment passport service set does not match provider mode")
    runtime_images = {}
    provider_ingress_runtime_image = None
    for service in (*selected_services, *(OPTIONAL_SERVICES if provider_mode == "simulator"
                                         and "passport-provider-ingress" in profile_records else ())):
        matches = [record for record in records if isinstance(record, dict) and record.get("service") == service]
        require(len(matches) == 1, f"Deployment service {service} is missing or ambiguous")
        saved = matches[0]
        container_id = saved.get("container_id")
        require(isinstance(container_id, str) and bool(container_id), f"Missing {service} container ID")
        live = inspect(container_id)
        config = live.get("Config")
        state = live.get("State")
        require(isinstance(config, dict) and isinstance(state, dict), f"Invalid {service} runtime")
        labels = config.get("Labels")
        require(isinstance(labels, dict) and labels.get("com.docker.compose.project") == "elevenid-beta" and labels.get("com.docker.compose.service") == service, f"{service} is not the expected beta Compose service")
        require(saved.get("compose_project") == labels["com.docker.compose.project"] and saved.get("compose_service") == labels["com.docker.compose.service"], f"{service} Compose ownership drifted since deployment")
        require(state.get("Running") is True and state.get("Status") == "running", f"{service} is not running")
        if isinstance(state.get("Health"), dict):
            require(state["Health"].get("Status") == "healthy", f"{service} is unhealthy")
        image_id = live.get("Image")
        image_ref = config.get("Image")
        require(isinstance(image_id, str) and DIGEST.fullmatch(image_id) is not None, f"Invalid {service} image ID")
        require(saved.get("image_id") == image_id and saved.get("configured_image") == image_ref, f"{service} image drifted since deployment")
        require(isinstance(image_ref, str) and image_ref in service_images, f"{service} is not pinned to the signed Marty services OCI digest")
        projection = {"container_id": container_id, "image_id": image_id,
                      "oci_reference": image_ref, "oci_digest": service_images[image_ref]}
        if service == "passport-provider-ingress":
            provider_ingress_runtime_image = projection
        if provider_mode == "physical" or service != "passport-provider-ingress":
            runtime_images[service] = projection
    unauth_status, _ = probe(None)
    require(unauth_status in (401, 403), "Unauthenticated passport capability request was not denied")
    authenticated = {"verified": False, "evidence": None}
    if api_key:
        status, body = probe(api_key)
        require(status == 200 and isinstance(body, dict), "Authenticated passport capability request failed")
        require(body.get("supported") is True and body.get("encrypted_artifact_store") is True and body.get("bureau_configured") is True, "Native passport capability is not ready")
        require(isinstance(body.get("signer"), dict) and body["signer"].get("configured") is True and body["signer"].get("mode") == "MANAGED_ISSUER_PROFILE", "Passport signer is not using a managed issuer profile")
        require(body.get("blockers") == [] and body["signer"].get("blockers") == [], "Passport capability reports blockers")
        authenticated = {"verified": True, "evidence": {"http_status": status, "supported": True, "signer_mode": "MANAGED_ISSUER_PROFILE"}}
    probes = {key: {"verified": False, "evidence": None} for key in REQUIRED_PROBES}
    if provider_mode == "simulator" and provider_ingress_runtime_image is None:
        probes["physical_claim_boundary"] = {"verified": True, "evidence": {
            "physical_claim": "not_claimed", "booklet_verified": False,
        }}
    probes["capabilities_http"] = authenticated
    probes["unauthenticated_denial"] = {"verified": True, "evidence": {"http_status": unauth_status}}
    report = {
        "schema": "marty.passport-beta-acceptance/v1", "status": "blocked",
        "collected_at": datetime.now(timezone.utc).isoformat(), "beta_origin": BETA_ORIGIN,
        "physical_claim": "not_claimed",
        "release": {"source_commit": commit, "stack_manifest_sha256": manifest_digest.removeprefix("sha256:"), "oci_digests": oci_digests, "signed_manifest_verified": signed},
        "deployment": {"local_deployment_manifest_sha256": digest_file(deployment_path).removeprefix("sha256:"), "source_manifest_sha256": digest_file(source_path).removeprefix("sha256:"), "release_version": deployment["release_version"], "provider_mode": provider_mode},
        "runtime_images": runtime_images, "probes": probes,
    }
    if provider_ingress_runtime_image is not None:
        report["provider_ingress_runtime_image"] = provider_ingress_runtime_image
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-attestation", action="store_true", help="Verify stack checksum and GitHub attestations for manifest and every UI OCI image")
    parser.add_argument("--application-file", type=Path, help="Private beta-only test application; performs the authenticated lifecycle through Gateway")
    args = parser.parse_args()
    try:
        api_key = os.environ.get("PASSPORT_ACCEPTANCE_API_KEY")
        if args.application_file and not args.verify_attestation:
            raise EvidenceError("Mutating probes require verified official release attestations")
        report = collect(args.artifact_dir, api_key=api_key, attest=verify_attestations if args.verify_attestation else None)
        if args.application_file:
            require(report["probes"]["capabilities_http"]["verified"] is True and report["release"]["signed_manifest_verified"] is True, "Mutating probes require a ready signed beta release")
            application = read_json(args.application_file)
            report["probes"]["gateway_application_lifecycle"] = exercise(application, api_key)
            after = collect(args.artifact_dir, api_key=api_key, attest=verify_attestations)
            require(all(report[key] == after[key] for key in ("release", "deployment", "runtime_images")), "Beta release or runtime drifted during passport probes")
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (EvidenceError, ProbeError, OSError) as exc:
        args.output.write_text(json.dumps({"schema": "marty.passport-beta-acceptance/v1", "status": "blocked", "blocker": str(exc)}, indent=2) + "\n", encoding="utf-8")
        parser.exit(1, f"Passport beta evidence failed: {exc}\n")
    print(f"Wrote blocked passport beta prerequisite evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
