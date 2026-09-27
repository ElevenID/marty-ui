#!/usr/bin/env python3
"""Run governed beta CSCA/DSC ceremonies and verify their public X.509 chain."""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener


ORIGIN = "https://beta.elevenidllc.com"
CERTIFICATE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
COUNTRY = re.compile(r"[A-Z]{2}\Z")
SUBJECT_COMPONENT = re.compile(r"[A-Za-z0-9 ._-]{1,64}\Z")


class ChainProbeError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def post_beta(path: str, body: dict[str, Any], session_cookie: str) -> tuple[int, dict[str, Any]]:
    if path not in (
        "/v1/signing-keys/issuer-identities/csca-self-signed-certificate",
        "/v1/signing-keys/issuer-identities/dsc-certificate",
    ):
        raise ChainProbeError("Unexpected certificate route")
    if not session_cookie or any(character in session_cookie for character in "\r\n"):
        raise ChainProbeError("Governed operator session is unavailable")
    organization_id = body.get("organization_id")
    if not isinstance(organization_id, str) or not organization_id:
        raise ChainProbeError("Certificate organization is unavailable")
    url = ORIGIN + path + "?organization_id=" + quote(organization_id, safe="")
    upstream_body = {key: value for key, value in body.items() if key != "organization_id"}
    request = Request(
        url,
        data=json.dumps(upstream_body, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "Cache-Control": "no-cache", "User-Agent": "passport-beta-acceptance/1",
                 "Cookie": session_cookie},
        method="POST",
    )
    try:
        with build_opener(NoRedirect).open(request, timeout=120) as response:
            if response.geturl() != url:
                raise ChainProbeError("Certificate ceremony redirected")
            raw = response.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024:
                raise ChainProbeError("Certificate response is oversized")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ChainProbeError("Certificate route returned a non-object")
            return response.status, payload
    except HTTPError as exc:
        return exc.code, {}
    except (OSError, URLError, ValueError) as exc:
        raise ChainProbeError("Certificate ceremony request failed") from exc


def openssl_verify(csca_pem: str, dsc_pem: str) -> tuple[str, str]:
    try:
        csca_der = ssl.PEM_cert_to_DER_cert(csca_pem)
        dsc_der = ssl.PEM_cert_to_DER_cert(dsc_pem)
    except ValueError as exc:
        raise ChainProbeError("Certificate response is not PEM X.509") from exc
    if csca_der == dsc_der:
        raise ChainProbeError("CSCA and DSC certificates are identical")
    with tempfile.TemporaryDirectory(prefix="passport-beta-chain-") as directory:
        csca_path = Path(directory) / "csca.pem"
        dsc_path = Path(directory) / "dsc.pem"
        csca_path.write_text(csca_pem, encoding="ascii")
        dsc_path.write_text(dsc_pem, encoding="ascii")
        commands = [
            ["openssl", "verify", "-x509_strict", "-check_ss_sig", "-purpose", "any", "-CAfile", str(csca_path), str(csca_path)],
            ["openssl", "verify", "-x509_strict", "-check_ss_sig", "-purpose", "any", "-CAfile", str(csca_path), str(dsc_path)],
        ]
        try:
            for command in commands:
                subprocess.run(command, check=True, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ChainProbeError("CSCA to DSC certificate chain did not verify") from exc
    return hashlib.sha256(csca_der).hexdigest(), hashlib.sha256(dsc_der).hexdigest()


def validate_sessions(csca_session: str, dsc_session: str) -> None:
    if not csca_session or not dsc_session or csca_session == dsc_session:
        raise ChainProbeError("Separate governed operator sessions are required")
    if any(character in session for session in (csca_session, dsc_session) for character in "\r\n"):
        raise ChainProbeError("Governed operator session is invalid")


def validate_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict) or set(plan) != {"organization_id", "csca", "dsc"}:
        raise ChainProbeError("Certificate ceremony plan is incomplete")
    organization_id = plan.get("organization_id")
    csca = plan.get("csca")
    dsc = plan.get("dsc")
    if not isinstance(organization_id, str) or not organization_id.strip() or not isinstance(csca, dict) or not isinstance(dsc, dict):
        raise ChainProbeError("Certificate ceremony plan is incomplete")
    if set(csca) not in ({"issuer_did", "certificate_id", "credential_format", "country", "organization", "common_name", "validity_days"},
                        {"organization_id", "issuer_did", "certificate_id", "credential_format", "country", "organization", "common_name", "validity_days"}):
        raise ChainProbeError("CSCA ceremony fields are invalid")
    if set(dsc) not in ({"dsc_issuer_did", "csca_issuer_did", "csca_certificate_id", "credential_format", "country", "organization", "common_name", "validity_days", "idempotency_key"},
                       {"organization_id", "dsc_issuer_did", "csca_issuer_did", "csca_certificate_id", "credential_format", "country", "organization", "common_name", "validity_days", "idempotency_key"}):
        raise ChainProbeError("DSC ceremony fields are invalid")
    csca_did = csca.get("issuer_did")
    dsc_did = dsc.get("dsc_issuer_did")
    certificate_id = csca.get("certificate_id")
    if (not isinstance(csca_did, str) or not csca_did.startswith("did:")
            or not isinstance(dsc_did, str) or not dsc_did.startswith("did:")
            or not isinstance(certificate_id, str)
            or not CERTIFICATE_ID.fullmatch(certificate_id)):
        raise ChainProbeError("CSCA and DSC require separate issuer identities")
    if dsc.get("csca_issuer_did") != csca_did or dsc.get("csca_certificate_id") != certificate_id:
        raise ChainProbeError("DSC request does not bind the selected CSCA")
    for body, max_days in ((csca, 3650), (dsc, 90)):
        if body.get("credential_format") != "ICAO_EMRTD":
            raise ChainProbeError("Certificate ceremony must use ICAO_EMRTD")
        if body.get("organization_id") not in (None, organization_id):
            raise ChainProbeError("Certificate ceremony organization changed")
        if not isinstance(body.get("country"), str) or not COUNTRY.fullmatch(body["country"]):
            raise ChainProbeError("Certificate ceremony country is invalid")
        if any(not isinstance(body.get(field), str) or not SUBJECT_COMPONENT.fullmatch(body[field])
               or body[field].strip() != body[field] for field in ("organization", "common_name")):
            raise ChainProbeError("Certificate ceremony subject is invalid")
        if type(body.get("validity_days")) is not int or not 1 <= body["validity_days"] <= max_days:
            raise ChainProbeError("Certificate ceremony validity is invalid")
    if not isinstance(dsc.get("idempotency_key"), str) or not IDEMPOTENCY_KEY.fullmatch(dsc["idempotency_key"]):
        raise ChainProbeError("DSC idempotency key is invalid")
    if dsc["country"] != csca["country"] or dsc["validity_days"] >= csca["validity_days"]:
        raise ChainProbeError("DSC country or validity does not fit selected CSCA")


def exercise(
    plan: dict[str, Any],
    csca_session: str,
    dsc_session: str,
    *,
    request: Callable[[str, dict[str, Any], str], tuple[int, dict[str, Any]]] = post_beta,
    verify: Callable[[str, str], tuple[str, str]] = openssl_verify,
) -> dict[str, Any]:
    validate_sessions(csca_session, dsc_session)
    validate_plan(plan)
    organization_id = plan["organization_id"]
    csca = plan["csca"]
    dsc = plan["dsc"]
    csca_did = csca["issuer_did"]
    dsc_did = dsc["dsc_issuer_did"]
    certificate_id = csca["certificate_id"]
    csca_body = {**csca, "organization_id": organization_id}
    dsc_body = {**dsc, "organization_id": organization_id}
    csca_status, csca_result = request(
        "/v1/signing-keys/issuer-identities/csca-self-signed-certificate", csca_body, csca_session,
    )
    if csca_status != 200 or csca_result.get("status") != "issued" or csca_result.get("certificate_id") != certificate_id or csca_result.get("issuer_did") != csca_did:
        raise ChainProbeError("Governed CSCA ceremony did not issue the selected certificate")
    dsc_status, dsc_result = request(
        "/v1/signing-keys/issuer-identities/dsc-certificate", dsc_body, dsc_session,
    )
    if dsc_status != 200 or dsc_result.get("status") != "issued" or dsc_result.get("dsc_issuer_did") != dsc_did or dsc_result.get("csca_issuer_did") != csca_did:
        raise ChainProbeError("Governed DSC ceremony did not issue the selected chain")
    csca_pem = csca_result.get("certificate_pem")
    dsc_pem = dsc_result.get("certificate_pem")
    chain_pem = dsc_result.get("chain_pem")
    if not all(isinstance(pem, str) and "BEGIN CERTIFICATE" in pem for pem in (csca_pem, dsc_pem, chain_pem)):
        raise ChainProbeError("Certificate response has no public chain")
    csca_hash, dsc_hash = verify(csca_pem, dsc_pem)
    try:
        chain_der = ssl.PEM_cert_to_DER_cert(chain_pem)
    except ValueError as exc:
        raise ChainProbeError("DSC chain is not PEM X.509") from exc
    if chain_pem.count("-----BEGIN CERTIFICATE-----") != 1 or ssl.PEM_cert_to_DER_cert(csca_pem) != chain_der:
        raise ChainProbeError("DSC chain does not publish the selected CSCA")
    return {"verified": True, "evidence": {
        "csca_certificate_id": certificate_id,
        "csca_certificate_sha256": csca_hash,
        "dsc_certificate_sha256": dsc_hash,
        "csca_issuer_did_sha256": hashlib.sha256(csca_did.encode()).hexdigest(),
        "dsc_issuer_did_sha256": hashlib.sha256(dsc_did.encode()).hexdigest(),
        "csca_http_status": csca_status, "dsc_http_status": dsc_status,
        "chain_verified_by": "openssl-x509-strict",
    }}
