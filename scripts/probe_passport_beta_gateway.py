#!/usr/bin/env python3
"""Exercise the authenticated beta passport application lifecycle through Gateway.

The signed simulator callback and KMS/ICAO verification need separate probes.
This module deliberately records only the public job projection's state and
hashes, never applicant data, API keys, or response bodies.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener


ORIGIN = "https://beta.elevenidllc.com"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ProbeError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def request_beta(method: str, path: str, body: dict[str, Any] | None, api_key: str) -> tuple[int, dict[str, Any]]:
    if not path.startswith("/v1/passport/") or ".." in path:
        raise ProbeError("Unexpected passport route")
    url = ORIGIN + path
    headers = {"Accept": "application/json", "Cache-Control": "no-cache",
               "User-Agent": "passport-beta-acceptance/1", "x-api-key": api_key}
    encoded = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    try:
        with build_opener(NoRedirect).open(Request(url, data=encoded, headers=headers, method=method), timeout=60) as response:
            if response.geturl() != url:
                raise ProbeError("Passport route redirected")
            raw = response.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ProbeError("Passport response is oversized")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ProbeError("Passport route returned a non-object")
            return response.status, payload
    except HTTPError as exc:
        return exc.code, {}
    except (OSError, URLError, ValueError) as exc:
        raise ProbeError("Passport route request failed") from exc


def exercise(
    application: dict[str, Any],
    api_key: str,
    *,
    request: Callable[[str, str, dict[str, Any] | None, str], tuple[int, dict[str, Any]]] = request_beta,
    max_polls: int = 90,
    poll_interval_seconds: float = 10,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    organization_id = application.get("organization_id")
    issuer_did = application.get("issuer_did")
    if not isinstance(organization_id, str) or not organization_id or not isinstance(issuer_did, str) or not issuer_did.startswith("did:"):
        raise ProbeError("Application needs an organization and managed issuer DID")
    if not isinstance(api_key, str) or len(api_key) < 32:
        raise ProbeError("Organization API key is missing")
    if max_polls < 1 or max_polls > 180 or poll_interval_seconds < 0:
        raise ProbeError("Invalid bounded polling policy")
    input_sha256 = hashlib.sha256(json.dumps(application, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    outcomes = []
    job_id = None
    application_id = None

    def call(method: str, path: str, body: dict[str, Any] | None, expected_status: int) -> dict[str, Any]:
        nonlocal job_id, application_id
        status, payload = request(method, path, body, api_key)
        if status != expected_status:
            raise ProbeError(f"{method} {path.split('/')[-1]} returned {status}, expected {expected_status}")
        if payload.get("organization_id") != organization_id:
            raise ProbeError("Passport response organization changed")
        if job_id is None:
            job_id = payload.get("id")
            application_id = payload.get("application_id")
            if not isinstance(job_id, str) or not job_id or not isinstance(application_id, str) or not application_id:
                raise ProbeError("Passport create response has no job identity")
        elif payload.get("id") != job_id or payload.get("application_id") != application_id:
            raise ProbeError("Passport response job identity changed")
        outcomes.append({"method": method, "route": path.replace(quote(application_id, safe=""), "{application_id}"),
                         "http_status": status, "job_status": payload.get("status")})
        return payload

    created = call("POST", "/v1/passport/applications", application, 201)
    if created.get("status") != "DRAFT":
        raise ProbeError("Passport create state is unexpected")
    base = f"/v1/passport/applications/{quote(application_id, safe='')}"
    groups = call("POST", base + "/generate-data-groups", None, 200)
    if groups.get("status") != "DATA_GENERATED":
        raise ProbeError("Data-group state is unexpected")
    sod = call("POST", base + "/generate-sod", None, 200)
    if (sod.get("status") != "SOD_SIGNED" or not isinstance(sod.get("sod_sha256"), str)
            or not SHA256.fullmatch(sod["sod_sha256"])
            or sod.get("sod_signature_verified") is not True):
        raise ProbeError("SOD operation did not return verified signature evidence")
    submitted = call("POST", base + "/submit-personalization", None, 200)
    if submitted.get("sod_sha256") != sod["sod_sha256"]:
        raise ProbeError("Submitted SOD differs from the verified generated SOD")
    bureau_job_id = submitted.get("bureau_job_id")
    if not isinstance(bureau_job_id, str) or not bureau_job_id:
        raise ProbeError("Bureau submission has no durable job identity")
    status_body = None
    for poll_number in range(max_polls):
        status_body = call("GET", base + "/production-status", None, 200)
        if status_body.get("status") in ("QUALITY_CHECK", "READY_FOR_ACTIVATION"):
            break
        if status_body.get("status") in ("FAILED", "CANCELLED", "ACTIVE"):
            raise ProbeError("Bureau lifecycle reached an invalid acceptance state")
        if poll_number + 1 < max_polls:
            sleep(poll_interval_seconds)
    else:
        raise ProbeError("Bureau lifecycle did not reach quality check before the bound")
    quality = call("POST", base + "/quality-verify", {"passed": True, "failure_codes": []}, 200)
    if quality.get("status") != "READY_FOR_ACTIVATION" or not isinstance(quality.get("quality_result"), dict) or quality["quality_result"].get("passed") is not True:
        raise ProbeError("Quality verification was not persisted")
    active = call("POST", base + "/activate", None, 200)
    if active.get("status") != "ACTIVE" or not active.get("completed_at"):
        raise ProbeError("Passport activation did not persist")
    return {
        "verified": True,
        "evidence": {"application_input_sha256": input_sha256,
                     "job_id_sha256": hashlib.sha256(job_id.encode()).hexdigest(),
                     "application_id_sha256": hashlib.sha256(application_id.encode()).hexdigest(),
                     "bureau_job_id_sha256": hashlib.sha256(bureau_job_id.encode()).hexdigest(),
                     "sod_sha256": sod["sod_sha256"],
                     "sod_signature_verified": True, "routes": outcomes},
    }
