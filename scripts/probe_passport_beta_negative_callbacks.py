#!/usr/bin/env python3
"""Prove beta's selected native passport job survives two denied callbacks.

This probe emits commitments and fixed response projections only. It does not
qualify D-12 recording: separate uncut videos and privacy scans are required.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID, uuid4

try:
    from .collect_passport_beta_acceptance import (
        collect, production_attachment_commitment,
        production_snapshot_commitment, verify_attestations,
    )
    from .probe_passport_beta_batch import _identity_commit
    from .probe_passport_beta_gateway import request_beta as request_job
    from .probe_passport_beta_host import (
        production_attachment_sha256, production_snapshot,
    )
except ImportError:
    from collect_passport_beta_acceptance import (
        collect, production_attachment_commitment,
        production_snapshot_commitment, verify_attestations,
    )
    from probe_passport_beta_batch import _identity_commit
    from probe_passport_beta_gateway import request_beta as request_job
    from probe_passport_beta_host import (
        production_attachment_sha256, production_snapshot,
    )


ORIGIN = "https://beta.elevenidllc.com"
WEBHOOK = "/v1/passport/webhooks/personalization"
SIGNER_URL = "http://passport-callback-signer:8018/internal/documents"
SIGNATURE = re.compile(r"vault:v[0-9]+:[A-Za-z0-9+/]{43}=\Z")
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
ROOT = Path(__file__).resolve().parents[1]


class NegativeCallbackError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NegativeCallbackError(message)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _state(application_id: str, organization_id: str, source_job_id: str,
           bureau_job_id: str, api_key: str,
           request: Callable[..., tuple[int, dict[str, Any]]]) -> bytes:
    path = f"/v1/passport/applications/{quote(application_id, safe='')}/production-status"
    status, body = request("GET", path, None, api_key)
    require(status == 200 and isinstance(body, dict)
            and body.get("id") == source_job_id
            and body.get("application_id") == application_id
            and body.get("organization_id") == organization_id
            and body.get("bureau_job_id") == bureau_job_id
            and body.get("status") == "ACTIVE",
            "Selected beta passport job is not terminal and bound")
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _sign_foreign(bureau_container_id: str, organization_id: str,
                  body: bytes) -> str:
    require(CONTAINER.fullmatch(bureau_container_id) is not None,
            "Selected beta bureau container ID is invalid")
    request = json.dumps({"body_b64": base64.b64encode(body).decode("ascii")},
                         separators=(",", ":")).encode()
    # The internal credential expands only inside the isolated beta bureau.
    # Neither the credential nor the callback body is placed in process args.
    command = [
        "docker", "exec", "-i", bureau_container_id, "sh", "-eu", "-c",
        'exec curl --fail --silent --show-error --max-time 20 '
        '-H "Content-Type: application/json" '
        '-H "x-api-key: $SIGNING_KEYS_INTERNAL_API_KEY" '
        '--data-binary @- "$1/$2/passport-callbacks/sign"',
        "passport-negative-proof", SIGNER_URL, quote(organization_id, safe=""),
    ]
    try:
        result = subprocess.run(command, input=request, capture_output=True,
                                timeout=30, check=True)
        response = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise NegativeCallbackError("Isolated beta callback signing failed") from exc
    signature = response.get("signature") if isinstance(response, dict) else None
    require(isinstance(signature, str) and SIGNATURE.fullmatch(signature) is not None,
            "Isolated beta callback signer returned an invalid signature")
    return signature


def _post_callback(body: bytes, signature: str | None) -> tuple[int, dict[str, bool]]:
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "Cache-Control": "no-cache", "User-Agent": "passport-beta-negative-proof/1"}
    if signature is not None:
        headers["x-personalization-signature"] = signature
    url = ORIGIN + WEBHOOK
    try:
        with build_opener(NoRedirect).open(
            Request(url, data=body, headers=headers, method="POST"), timeout=20,
        ) as response:
            require(response.geturl() == url, "Beta callback redirected")
            return response.status, {}
    except HTTPError as exc:
        try:
            raw = exc.read(4097)
            require(len(raw) <= 4096, "Beta callback denial is oversized")
            denial = json.loads(raw)
        except (OSError, ValueError) as error:
            raise NegativeCallbackError("Beta callback denial is invalid") from error
        detail = denial.get("detail") if isinstance(denial, dict) else None
        return exc.code, {
            "missing_signature_header": (
                isinstance(detail, list) and len(detail) == 1
                and isinstance(detail[0], dict)
                and detail[0].get("type") == "missing"
                and detail[0].get("loc") == ["header", "x-personalization-signature"]),
            "webhook_job_not_found": detail == "Physical document job not found",
        }
    except (OSError, URLError) as exc:
        raise NegativeCallbackError("Beta callback denial request failed") from exc


def _check_production(api_key: str, deployment: dict[str, Any]) -> None:
    snapshot = production_snapshot()
    require(production_snapshot_commitment(api_key, snapshot.get("sha256"))
            == deployment.get("production_snapshot_commitment")
            and production_attachment_commitment(api_key,
                                                 production_attachment_sha256())
                == deployment.get("production_attachment_commitment"),
            "Production differs from the aggregate beta baseline")


def exercise(
    private: dict[str, str], api_key: str, bureau_container_id: str, *,
    request: Callable[..., tuple[int, dict[str, Any]]] = request_job,
    post: Callable[[bytes, str | None], tuple[int, dict[str, bool]]] = _post_callback,
    sign: Callable[[str, str, bytes], str] = _sign_foreign,
    foreign_organization: str | None = None,
) -> dict[str, Any]:
    required = {"schema", "source_commit", "stack_manifest_sha256", "organization_id",
                "flow_definition_id", "flow_instance_id", "application_id",
                "source_job_id", "bureau_job_id"}
    require(isinstance(private, dict) and set(private) == required
            and private.get("schema") == "marty.passport-beta-demo-private/v1"
            and all(isinstance(private.get(key), str) and private[key]
                    for key in required)
            and isinstance(api_key, str) and len(api_key) >= 32
            and isinstance(bureau_container_id, str)
            and CONTAINER.fullmatch(bureau_container_id) is not None,
            "Protected beta negative callback inputs are incomplete")
    try:
        bureau = UUID(private["bureau_job_id"])
    except ValueError as exc:
        raise NegativeCallbackError("Selected bureau job ID is invalid") from exc
    require(str(bureau) == private["bureau_job_id"],
            "Selected bureau job ID is not canonical")
    foreign = foreign_organization or f"marty-beta-foreign-{uuid4()}"
    require(isinstance(foreign, str) and foreign != private["organization_id"]
            and 1 <= len(foreign) <= 256 and "\r" not in foreign and "\n" not in foreign,
            "Foreign callback organization is invalid")
    organization = private["organization_id"]
    source_job = private["source_job_id"]
    bureau_job = private["bureau_job_id"]
    application = private["application_id"]
    before = _state(application, organization, source_job, bureau_job, api_key, request)
    state_commitment = hmac.new(api_key.encode(), b"job-state:" +
                                hashlib.sha256(before).hexdigest().encode(),
                                hashlib.sha256).hexdigest()
    common = {"provider_profile_id": "passport-beta-bureau",
              "bureau_job_id": bureau_job, "status": "SHIPPED",
              "tracking_number": "BETA-SIM-" + bureau.hex}
    unsigned_body = json.dumps({**common, "organization_id": organization},
                               separators=(",", ":")).encode()
    unsigned_status, unsigned_denial = post(unsigned_body, None)
    require(unsigned_status == 422
            and unsigned_denial.get("missing_signature_header") is True,
            "Selected beta unsigned callback was not denied")
    after_unsigned = _state(application, organization, source_job, bureau_job,
                            api_key, request)
    require(after_unsigned == before, "Unsigned callback changed the selected job")
    foreign_body = json.dumps({**common, "organization_id": foreign},
                              separators=(",", ":")).encode()
    signature = sign(bureau_container_id, foreign, foreign_body)
    require(isinstance(signature, str) and SIGNATURE.fullmatch(signature) is not None,
            "Foreign callback signature is invalid")
    foreign_status, foreign_denial = post(foreign_body, signature)
    require(foreign_status == 404
            and foreign_denial.get("webhook_job_not_found") is True,
            "Signed foreign-organization callback was not denied")
    after_foreign = _state(application, organization, source_job, bureau_job,
                           api_key, request)
    require(after_foreign == before, "Foreign callback changed the selected job")
    selected = {
        "source_job_commitment": _identity_commit(api_key, "source-job", source_job),
        "bureau_job_commitment": _identity_commit(api_key, "bureau-job", bureau_job),
    }
    return {"schema": "marty.passport-beta-negative-callbacks/v1",
            "verified": True, "physical_claim": "not_claimed",
            "unsigned": {"http_status": 422, "webhook_owner": "issuance-native",
                         "request_kind": "missing_signature_header",
                         "response_projection": {"missing_signature_header": True},
                         "organization_commitment": _identity_commit(
                             api_key, "organization", organization),
                         **selected, "job_state_before_commitment": state_commitment,
                         "job_state_after_commitment": state_commitment},
            "foreign": {"http_status": 404, "webhook_owner": "issuance-native",
                        "request_kind": "signed_foreign_organization",
                        "signature_valid": True, "foreign_organization": True,
                        "response_projection": {"webhook_job_not_found": True},
                        "organization_commitment": _identity_commit(
                            api_key, "organization", foreign),
                        **selected, "job_state_before_commitment": state_commitment,
                        "job_state_after_commitment": state_commitment}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-handoff", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.private_handoff.resolve().is_relative_to(ROOT),
                "Private callback handoff must be outside the source checkout")
        private = json.loads(args.private_handoff.read_text(encoding="utf-8"))
        api_key = os.environ.get("PASSPORT_ACCEPTANCE_API_KEY", "")
        require((args.artifact_dir / "aggregate-deployment.json").is_file(),
                "Negative callback proof requires the aggregate beta deployment")
        deployed = collect(args.artifact_dir, api_key=api_key,
                           attest=verify_attestations)
        bureau = deployed.get("runtime_images", {}).get("passport-beta-bureau")
        require(deployed.get("release", {}).get("signed_manifest_verified") is True
                and deployed.get("deployment", {}).get("provider_mode") == "simulator"
                and deployed["release"].get("source_commit") == private.get("source_commit")
                and deployed["release"].get("stack_manifest_sha256")
                    == private.get("stack_manifest_sha256")
                and isinstance(bureau, dict)
                and isinstance(bureau.get("container_id"), str),
                "Private callback handoff differs from signed aggregate beta")
        _check_production(api_key, deployed["deployment"])
        result = exercise(private, api_key, bureau["container_id"])
        _check_production(api_key, deployed["deployment"])
        after = collect(args.artifact_dir, api_key=api_key,
                        attest=verify_attestations)
        require(all(deployed[key] == after[key]
                    for key in ("release", "deployment", "runtime_images")),
                "Aggregate beta runtime changed during negative callback proof")
        result["release"] = {
            "source_commit": deployed["release"]["source_commit"],
            "stack_manifest_sha256": deployed["release"]["stack_manifest_sha256"],
        }
        result["deployment"] = {
            "aggregate_deployment_receipt_sha256":
                deployed["deployment"]["aggregate_deployment_receipt_sha256"],
            "aggregate_plan_sha256": deployed["deployment"]["aggregate_plan_sha256"],
        }
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
    except (OSError, ValueError, subprocess.SubprocessError):
        args.output.write_text(json.dumps({"schema": "marty.passport-beta-negative-callbacks/v1",
                                           "verified": False,
                                           "blocker": "Protected negative callback proof failed"}) + "\n",
                               encoding="utf-8")
        parser.exit(1, "Protected beta negative callback proof blocked\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
