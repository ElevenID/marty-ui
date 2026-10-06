#!/usr/bin/env python3
"""Read-only KMS and certificate proof before the beta passport owner switch."""

from __future__ import annotations

import argparse
import base64
import binascii
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
from typing import Any, Callable

try:
    from .probe_passport_beta_chain import ChainProbeError, openssl_verify
    from .probe_passport_beta_host import HostProbeError, inspect
    from .probe_passport_beta_rust_owner_flow import signed_service
    from .probe_passport_beta_rust_owner_write import checked_application
    from .verify_passport_beta_issuer_profiles import (IssuerProfileEvidenceError,
                                                       verify_live_signatures)
except ImportError:
    from probe_passport_beta_chain import ChainProbeError, openssl_verify
    from probe_passport_beta_host import HostProbeError, inspect
    from probe_passport_beta_rust_owner_flow import signed_service
    from probe_passport_beta_rust_owner_write import checked_application
    from verify_passport_beta_issuer_profiles import (IssuerProfileEvidenceError,
                                                     verify_live_signatures)


CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
DOCKER_CONTEXT_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
CERTIFICATE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
KEY_REFERENCE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
SELECTION_FIELDS = {
    "organization_id", "csca_issuer_did", "csca_certificate_id", "dsc_issuer_did",
}
PRIVATE_PREFIX = "http://127.0.0.1:8017"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HostProbeError(message)


def checked_selection(path: Path) -> tuple[dict[str, str], str]:
    require(path.is_absolute(), "Issuer chain selection path must be absolute")
    try:
        raw = path.read_bytes()
        require(0 < len(raw) <= 4096, "Issuer chain selection is invalid")
        selection = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise HostProbeError("Issuer chain selection is unreadable") from exc
    require(isinstance(selection, dict) and set(selection) == SELECTION_FIELDS,
            "Issuer chain selection fields are invalid")
    require(isinstance(selection.get("organization_id"), str)
            and IDENTIFIER.fullmatch(selection["organization_id"]) is not None
            and isinstance(selection.get("csca_certificate_id"), str)
            and CERTIFICATE_ID.fullmatch(selection["csca_certificate_id"]) is not None,
            "Issuer chain selection identity is invalid")
    for field in ("csca_issuer_did", "dsc_issuer_did"):
        did = selection.get(field)
        require(isinstance(did, str) and did.startswith("did:")
                and len(did) <= 255 and not any(c in did for c in "\r\n\0"),
                "Issuer chain selection DID is invalid")
    require(selection["csca_issuer_did"] != selection["dsc_issuer_did"],
            "CSCA and DSC must use separate issuer identities")
    return selection, hashlib.sha256(raw).hexdigest()


def docker_bytes(command: list[str], payload: bytes = b"",
                 *, timeout: int = 30, context: str | None = None) -> bytes:
    require(len(command) >= 2 and command[0] == "docker",
            "Private beta Docker command is invalid")
    environment = os.environ.copy()
    if context is not None:
        require(DOCKER_CONTEXT_NAME.fullmatch(context) is not None,
                "Private beta Docker context is invalid")
        for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY",
                     "DOCKER_CERT_PATH"):
            environment.pop(name, None)
        command = ["docker", "--context", context, *command[1:]]
    try:
        result = subprocess.run(command, input=payload, env=environment,
                                capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostProbeError("Private beta KMS request failed") from exc
    require(result.returncode == 0 and len(result.stdout) <= 262144,
            "Private beta KMS request failed")
    return result.stdout


def docker_text(command: list[str], *, context: str | None = None) -> str:
    options = {} if context is None else {"context": context}
    return docker_bytes(command, **options).decode("utf-8").strip()


def docker_json(command: list[str], payload: bytes = b"",
                *, context: str | None = None) -> dict[str, Any]:
    try:
        options = {} if context is None else {"context": context}
        response = json.loads(docker_bytes(command, payload, **options))
    except (UnicodeError, ValueError) as exc:
        raise HostProbeError("Private beta KMS response is invalid") from exc
    require(isinstance(response, dict), "Private beta KMS response is invalid")
    return response


def checked_docker_context(plan: dict[str, Any]) -> str:
    docker = plan.get("docker")
    context = docker.get("context") if isinstance(docker, dict) else None
    daemon_id = docker.get("daemon_id") if isinstance(docker, dict) else None
    require(isinstance(context, str)
            and DOCKER_CONTEXT_NAME.fullmatch(context) is not None
            and isinstance(daemon_id, str) and 0 < len(daemon_id) <= 256
            and not any(character in daemon_id for character in "\r\n\0"),
            "Aggregate beta Docker identity is invalid")
    require(docker_text(["docker", "context", "show"]) == context
            and docker_text(["docker", "info", "--format", "{{.ID}}"],
                            context=context) == daemon_id,
            "Aggregate beta Docker context or daemon changed")
    return context


def private_signing_request(container: str, route: str,
                            body: dict[str, Any] | None = None,
                            *, context: str | None = None) -> dict[str, Any]:
    require(CONTAINER.fullmatch(container) is not None
            and (route in ("/internal/compat/resolve-issuer-did",
                           "/internal/compat/issuer-dids/sign")
                 or re.fullmatch(
                     r"/internal/documents/[A-Za-z0-9_-]{1,128}/csca-certificates/"
                     r"[A-Za-z0-9_.:-]{1,128}", route) is not None),
            "Private Signing Keys request input is invalid")
    method = "GET" if body is None else "POST"
    script = (
        'key="$(printenv SIGNING_KEYS_INTERNAL_API_KEY || true)"; '
        'path="$(printenv SIGNING_KEYS_INTERNAL_API_KEY_FILE || true)"; '
        'if [ -z "$key" ] && [ -n "$path" ]; then key="$(cat "$path")"; fi; '
        '[ -n "$key" ] || exit 4; '
        'exec curl --fail --silent --show-error --max-time 20 '
        '-H "Content-Type: application/json" -H "x-api-key: $key" '
        + ('--data-binary @- ' if method == "POST" else '')
        + '"$1"'
    )
    payload = (json.dumps(body, separators=(",", ":")).encode("utf-8")
               if body is not None else b"")
    options = {} if context is None else {"context": context}
    return docker_json(["docker", "exec", "-i", container, "sh", "-eu", "-c",
                        script, "sh", PRIVATE_PREFIX + route], payload, **options)


def resolve(container: str, organization: str, did: str,
            purpose: str, *, context: str | None = None) -> dict[str, Any]:
    require(isinstance(did, str) and did.startswith("did:")
            and purpose in ("csca", "x509_doc_signer"),
            "Private issuer resolution input is invalid")
    return private_signing_request(container,
                                   "/internal/compat/resolve-issuer-did", {
        "organization_id": organization, "issuer_did": did,
        "credential_format": "ICAO_EMRTD", "key_purpose": purpose,
        "algorithm": "ES256",
    }, context=context)


def sign(container: str, organization: str, did: str, purpose: str,
         challenge: bytes, *, context: str | None = None) -> dict[str, Any]:
    require(len(challenge) == 48, "Private issuer challenge is invalid")
    return private_signing_request(container,
                                   "/internal/compat/issuer-dids/sign", {
        "organization_id": organization, "issuer_did": did,
        "credential_format": "ICAO_EMRTD", "key_purpose": purpose,
        "algorithm": "ES256",
        "payload_b64": base64.urlsafe_b64encode(challenge).decode("ascii").rstrip("="),
    }, context=context)


def transit_key_version(container: str, reference: str,
                        *, context: str | None = None) -> int:
    require(CONTAINER.fullmatch(container) is not None
            and KEY_REFERENCE.fullmatch(reference) is not None,
            "Managed issuer key reference is invalid")
    script = (
        'export VAULT_ADDR=http://127.0.0.1:8200; '
        'export VAULT_TOKEN="$BAO_DEV_ROOT_TOKEN_ID"; '
        '[ -n "$VAULT_TOKEN" ] || exit 4; '
        'exec bao read -format=json "transit/keys/$1"'
    )
    options = {} if context is None else {"context": context}
    response = docker_json(["docker", "exec", container, "sh", "-eu", "-c",
                            script, "sh", reference], **options)
    metadata = response.get("data")
    require(isinstance(metadata, dict)
            and metadata.get("type") == "ecdsa-p256"
            and metadata.get("exportable") is False
            and type(metadata.get("latest_version")) is int
            and metadata["latest_version"] > 0,
            "Selected issuer key lacks nonexportable KMS custody")
    return metadata["latest_version"]


def current_openbao(plan: dict[str, Any],
                    runner: Callable[[list[str]], str]) -> str:
    old = plan.get("old_container_ids_by_service")
    container = old.get("openbao") if isinstance(old, dict) else None
    require(isinstance(container, str) and CONTAINER.fullmatch(container) is not None,
            "Preserved beta OpenBao identity is invalid")
    record = inspect(container, runner)
    config = record.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    state = record.get("State")
    require(record.get("Id") == container and isinstance(labels, dict)
            and labels.get("com.docker.compose.project") == "elevenid-beta"
            and labels.get("com.docker.compose.service") == "openbao"
            and isinstance(state, dict) and state.get("Running") is True
            and state.get("Status") == "running",
            "Preserved beta OpenBao changed before owner transition")
    return container


def same_binding(first: dict[str, Any], second: dict[str, Any]) -> bool:
    fields = ("ok", "organization_id", "issuer_did", "issuer_profile",
              "signing_service", "resolver", "public_jwk", "issuer_x5c",
              "verification_method_id")
    return all(first.get(field) == second.get(field) for field in fields)


def prove(
    plan: dict[str, Any], application: dict[str, str],
    selection: dict[str, str], application_sha256: str, selection_sha256: str,
    *, runner: Callable[[list[str]], str] = docker_text,
    resolver: Callable[[str, str, str, str], dict[str, Any]] = resolve,
    signer: Callable[[str, str, str, str, bytes], dict[str, Any]] = sign,
    get_csca: Callable[[str, str, str], dict[str, Any]] | None = None,
    key_version: Callable[[str, str], int] = transit_key_version,
) -> dict[str, Any]:
    source = plan.get("source_commit")
    require(plan.get("schema") == "marty.passport-beta-aggregate-compose-plan/v1"
            and isinstance(source, str) and SHA.fullmatch(source) is not None
            and selection["organization_id"] == application["organization_id"]
            and selection["dsc_issuer_did"] == application["issuer_did"],
            "Selected issuer chain differs from signed beta application")
    organization = selection["organization_id"]
    csca_did = selection["csca_issuer_did"]
    dsc_did = selection["dsc_issuer_did"]
    require(csca_did != dsc_did, "CSCA and DSC must use separate issuer identities")
    signing_keys = signed_service(plan, "signing-keys", runner)
    openbao = current_openbao(plan, runner)
    csca = resolver(signing_keys, organization, csca_did, "csca")
    dsc = resolver(signing_keys, organization, dsc_did, "x509_doc_signer")
    csca_profile = csca.get("issuer_profile") if isinstance(csca, dict) else None
    dsc_profile = dsc.get("issuer_profile") if isinstance(dsc, dict) else None
    require(isinstance(csca_profile, dict) and isinstance(dsc_profile, dict),
            "Selected issuer profiles are unavailable")
    csca_ref = csca_profile.get("signing_key_reference")
    dsc_ref = dsc_profile.get("signing_key_reference")
    require(isinstance(csca_ref, str) and isinstance(dsc_ref, str)
            and csca_ref != dsc_ref, "Selected issuer keys are not distinct")
    certificate = selection["csca_certificate_id"]
    if get_csca is None:
        def get_csca(container: str, org: str, cert: str) -> dict[str, Any]:
            return private_signing_request(
                container, f"/internal/documents/{org}/csca-certificates/{cert}")
    record = get_csca(signing_keys, organization, certificate)
    metadata = record.get("metadata") if isinstance(record, dict) else None
    csca_pem = record.get("cert_pem") if isinstance(record, dict) else None
    require(isinstance(record, dict) and record.get("status") == "VALID"
            and record.get("certificate_id") == certificate
            and isinstance(metadata, dict) and metadata.get("issuer_did") == csca_did
            and record.get("key_reference") == csca_ref
            and record.get("revoked_at") is None
            and isinstance(csca_pem, str) and "BEGIN CERTIFICATE" in csca_pem,
            "Selected active CSCA certificate differs from managed profile")
    x5c = dsc.get("issuer_x5c") if isinstance(dsc, dict) else None
    require(isinstance(x5c, list) and x5c and isinstance(x5c[0], str),
            "Selected DSC profile certificate is unavailable")
    try:
        dsc_der = base64.b64decode(x5c[0], validate=True)
        dsc_pem = ssl.DER_cert_to_PEM_cert(dsc_der)
        csca_hash, dsc_hash = openssl_verify(csca_pem, dsc_pem)
    except (ValueError, binascii.Error, ssl.SSLError, ChainProbeError) as exc:
        raise HostProbeError("Selected CSCA to DSC certificate chain is invalid") from exc
    versions = {"csca": key_version(openbao, csca_ref),
                "dsc": key_version(openbao, dsc_ref)}
    chain = {
        "csca_http_status": 200, "dsc_http_status": 200,
        "chain_verified_by": "openssl-x509-strict",
        "csca_certificate_sha256": csca_hash,
        "dsc_certificate_sha256": dsc_hash,
    }
    try:
        evidence = verify_live_signatures(
            organization, csca_did, dsc_did, csca, dsc, chain, csca_pem,
            secrets.token_urlsafe(32),
            signer=lambda org, did, purpose, challenge:
                signer(signing_keys, org, did, purpose, challenge),
        )
    except IssuerProfileEvidenceError as exc:
        raise HostProbeError("Current managed issuer signing proof failed") from exc
    require(evidence.get("managed_kms_custody_verified") is True
            and evidence.get("chain_verified") is True,
            "Current managed issuer signing proof is incomplete")
    require(signed_service(plan, "signing-keys", runner) == signing_keys
            and current_openbao(plan, runner) == openbao
            and same_binding(csca, resolver(signing_keys, organization, csca_did, "csca"))
            and same_binding(dsc, resolver(signing_keys, organization, dsc_did,
                                           "x509_doc_signer"))
            and key_version(openbao, csca_ref) == versions["csca"]
            and key_version(openbao, dsc_ref) == versions["dsc"],
            "Managed issuer binding changed during beta pretransition proof")
    return {
        "schema": "marty.passport-beta-aggregate-kms-pretransition/v1",
        "verified": True, "source_commit": source,
        "application_file_sha256": application_sha256,
        "issuer_chain_file_sha256": selection_sha256,
        "signing_keys_container_id": signing_keys,
        "openbao_container_id": openbao,
        "csca_certificate_sha256": csca_hash,
        "dsc_certificate_sha256": dsc_hash,
        "key_versions": versions,
        "managed_kms_custody_verified": True,
        "chain_verified": True, "private_key_exported": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--application-file", type=Path, required=True)
    parser.add_argument("--issuer-chain-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        application, application_hash = checked_application(args.application_file)
        selection, selection_hash = checked_selection(args.issuer_chain_file)
        context = checked_docker_context(plan)
        result = prove(
            plan, application, selection, application_hash, selection_hash,
            runner=partial(docker_text, context=context),
            resolver=partial(resolve, context=context),
            signer=partial(sign, context=context),
            get_csca=lambda container, org, cert: private_signing_request(
                container, f"/internal/documents/{org}/csca-certificates/{cert}",
                context=context),
            key_version=partial(transit_key_version, context=context),
        )
    except (OSError, ValueError, HostProbeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
