#!/usr/bin/env python3
"""Run a redaction-safe, read-only contract check against hosted Canvas."""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


SUITE_NAME = "hosted_canvas_portability"
MAX_RESPONSE_BYTES = 1024 * 1024
REQUIRED_CONFIGURATION = (
    "HOSTED_CANVAS_MARTY_ORIGIN",
    "HOSTED_CANVAS_PLATFORM_ID",
    "HOSTED_CANVAS_MARTY_API_KEY",
    "HOSTED_CANVAS_ORIGIN",
    "HOSTED_CANVAS_API_TOKEN",
    "HOSTED_CANVAS_COURSE_ID",
    "HOSTED_CANVAS_EXTERNAL_TOOL_ID",
)
SENSITIVE_CONFIGURATION = REQUIRED_CONFIGURATION + (
    "HOSTED_CANVAS_LTI_CLIENT_ID",
    "HOSTED_CANVAS_EXPECTED_ACTIVE_KID",
    "HOSTED_CANVAS_EXPECTED_RETIRING_KID",
)
SECRET_CONFIGURATION = (
    "HOSTED_CANVAS_MARTY_API_KEY",
    "HOSTED_CANVAS_API_TOKEN",
)
AUTOMATED_CASE_IDS = (
    "gateway_management_auth_default",
    "marty_lti_jwks_rs256",
    "marty_registration_config_public_only",
    "marty_platform_portable_ready",
    "hosted_canvas_course_access",
    "hosted_canvas_lti_tool_installed",
    "hosted_canvas_sessionless_launch_available",
)
REQUIRED_OPERATOR_CASE_IDS = (
    "root_admin_installs_standard_lti_13_key",
    "instructor_deep_linking_placement",
    "learner_oidc_login_and_resource_launch",
    "ags_result_read_normalizes_evidence",
    "existing_assignment_submission_score_is_authoritative",
    "classic_quiz_assignment_submission_score_is_authoritative",
    "new_quiz_assignment_submission_score_is_authoritative",
    "module_based_course_completion_is_authoritative",
    "module_completion_with_student_context_is_authoritative",
    "roster_sync_creates_unsigned_pending_claim",
    "canvas_oauth_refresh_revoke_and_reconnect",
    "external_kms_claim_issues_and_verifies_open_badge",
    "pre_issuance_grade_correction_changes_decision",
    "post_issuance_grade_correction_creates_review_only",
    "rs256_rotation_keeps_retiring_key_for_seven_days",
    "cross_organization_resource_access_is_denied",
    "pilot_allowlist_and_global_kill_switch_fail_closed",
    "worker_retry_and_dead_letter_recovery_is_idempotent",
    "legacy_event_ingest_is_unavailable",
    "optional_canvas_credentials_mirror_preserves_provenance",
)
REQUIRED_PORTABILITY_EXCLUSIONS = {
    "canvas_source_patch",
    "custom_canvas_plugin",
    "rails_runner",
    "rails_console",
    "custom_event_ingest",
}
REQUIRED_ROLLOUT_MODES = ("shadow", "admin_approved", "auto", "background")
PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
PRIVATE_CONFIG_FIELDS = {
    "access_token",
    "api_key",
    "authorization",
    "client_secret",
    "cookie",
    "password",
    "private_jwk",
    "private_key",
    "refresh_token",
    "secret",
}
ALLOWED_RESULT_KEYS = {
    "schema_version",
    "suite",
    "status",
    "run_mode",
    "started_at",
    "completed_at",
    "missing_configuration",
    "cases",
}
ALLOWED_CASE_KEYS = {"id", "status", "reason_code"}
ALLOWED_CASE_STATUSES = {"passed", "failed", "skipped"}
ALLOWED_REASON_CODES = {
    "ok",
    "tenant_configuration_missing",
    "invalid_configuration",
    "network_error",
    "response_too_large",
    "unexpected_status",
    "invalid_json",
    "invalid_contract",
    "private_material_present",
    "expected_key_missing",
    "platform_not_ready",
    "tenant_resource_mismatch",
    "tool_disabled",
    "unsafe_launch_url",
    "internal_check_error",
}


class ContractConfigError(ValueError):
    """Raised when the checked-in acceptance contract is malformed."""


class CaseFailure(RuntimeError):
    """A failure represented by a fixed, non-sensitive reason code."""

    def __init__(self, reason_code: str):
        if reason_code not in ALLOWED_REASON_CODES:
            reason_code = "internal_check_error"
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ApiResponse:
    status: int
    body: Any


class HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    """Reject non-HTTPS redirects and never forward authorization cross-origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        if parsed.scheme != "https" or not parsed.netloc:
            raise URLError("unsafe_redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and _origin(req.full_url) != _origin(newurl):
            redirected.remove_header("Authorization")
            redirected.remove_header("X-api-key")
        return redirected


class HttpJsonClient:
    def __init__(self, timeout: int = 20, opener=None):
        self.timeout = timeout
        self.opener = opener or build_opener(HTTPSOnlyRedirectHandler())

    def get(self, url: str, headers: dict[str, str] | None = None) -> ApiResponse:
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "ElevenID-Hosted-Canvas-Contract/1.0",
            **(headers or {}),
        }
        request = Request(url, method="GET", headers=request_headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return ApiResponse(
                    status=int(response.status),
                    body=_parse_json(_read_limited(response)),
                )
        except HTTPError as error:
            return ApiResponse(
                status=int(error.code),
                body=_parse_json(_read_limited(error)),
            )
        except (OSError, TimeoutError, URLError) as error:
            raise CaseFailure("network_error") from error


@dataclass(frozen=True)
class ContractContext:
    values: dict[str, str]
    marty_origin: str
    canvas_origin: str
    client: Any


def _read_limited(response) -> bytes:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CaseFailure("response_too_large")
    return raw


def _parse_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _origin(value: str) -> str:
    parsed = urlparse(value)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def normalize_https_origin(value: str) -> str:
    try:
        parsed = urlparse(value.strip())
        _ = parsed.port
    except ValueError as error:
        raise CaseFailure("invalid_configuration") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise CaseFailure("invalid_configuration")
    return f"https://{parsed.netloc}".rstrip("/")


def load_contract(path: Path) -> dict[str, Any]:
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractConfigError("Could not read hosted Canvas acceptance contract") from error
    if not isinstance(contract, dict):
        raise ContractConfigError("Hosted Canvas acceptance contract must be an object")
    if contract.get("schema_version") != 1 or contract.get("suite") != SUITE_NAME:
        raise ContractConfigError("Hosted Canvas acceptance contract identity is invalid")

    automated = contract.get("automated_cases")
    if not isinstance(automated, list):
        raise ContractConfigError("automated_cases must be an array")
    automated_ids = tuple(
        str(item.get("id") or "") if isinstance(item, dict) else ""
        for item in automated
    )
    if automated_ids != AUTOMATED_CASE_IDS:
        raise ContractConfigError("Automated hosted Canvas case set is incomplete or out of order")
    if not all(item.get("required") is True and item.get("mutates_tenant") is False for item in automated):
        raise ContractConfigError("Automated hosted Canvas cases must be required and non-mutating")

    operator_cases = contract.get("operator_acceptance_cases")
    if not isinstance(operator_cases, list):
        raise ContractConfigError("operator_acceptance_cases must be an array")
    operator_ids = tuple(
        str(item.get("id") or "") if isinstance(item, dict) else ""
        for item in operator_cases
    )
    if operator_ids != REQUIRED_OPERATOR_CASE_IDS:
        raise ContractConfigError(
            "Operator hosted Canvas case set is incomplete or out of order"
        )
    for item in operator_cases[:-1]:
        if item.get("required") is not True or item.get("production_gate", True) is not True:
            raise ContractConfigError(
                "Core operator hosted Canvas cases must block the production gate"
            )
    optional_projection = operator_cases[-1]
    if (
        optional_projection.get("required") is not False
        or optional_projection.get("production_gate") is not False
    ):
        raise ContractConfigError(
            "Canvas Credentials projection must remain outside the production gate"
        )

    exclusions = set(contract.get("portability_exclusions") or [])
    if not REQUIRED_PORTABILITY_EXCLUSIONS.issubset(exclusions):
        raise ContractConfigError("Hosted Canvas portability exclusions are incomplete")

    rollout = contract.get("rollout_gates")
    if not isinstance(rollout, list):
        raise ContractConfigError("rollout_gates must be an array")
    rollout_modes = tuple(
        str(item.get("mode") or "") if isinstance(item, dict) else ""
        for item in rollout
    )
    if rollout_modes != REQUIRED_ROLLOUT_MODES:
        raise ContractConfigError("Hosted Canvas rollout modes are incomplete or out of order")

    artifact_policy = contract.get("artifact_policy")
    if not isinstance(artifact_policy, dict) or artifact_policy.get("fixed_schema_only") is not True:
        raise ContractConfigError("Hosted Canvas artifact policy must require a fixed schema")
    forbidden_artifact_features = (
        "include_response_bodies",
        "include_request_headers",
        "include_urls",
        "include_tenant_identifiers",
        "include_screenshots_or_traces",
    )
    if any(artifact_policy.get(key) is not False for key in forbidden_artifact_features):
        raise ContractConfigError("Hosted Canvas artifact policy permits sensitive output")
    return contract


def _url(origin: str, path: str, query: dict[str, str] | None = None) -> str:
    value = f"{origin}{path}"
    if query:
        value = f"{value}?{urlencode(query)}"
    return value


def _require_status(response: ApiResponse, expected: int = 200) -> Any:
    if response.status != expected:
        raise CaseFailure("unexpected_status")
    if response.body is None:
        raise CaseFailure("invalid_json")
    return response.body


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


def _walk_url_values(value: Any, parent_key: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_url_values(child, str(key).lower())
    elif isinstance(value, list):
        for child in value:
            yield from _walk_url_values(child, parent_key)
    elif isinstance(value, str) and ("url" in parent_key or "uri" in parent_key):
        yield value


def check_gateway_management_auth_default(context: ContractContext) -> None:
    response = context.client.get(
        _url(context.marty_origin, "/v1/integrations/canvas/platforms")
    )
    _require_status(response, 401)


def check_marty_lti_jwks_rs256(context: ContractContext) -> None:
    response = context.client.get(
        _url(context.marty_origin, "/v1/integrations/canvas/lti/jwks")
    )
    body = _require_status(response)
    if not isinstance(body, dict) or not isinstance(body.get("keys"), list) or not body["keys"]:
        raise CaseFailure("invalid_contract")

    kids: set[str] = set()
    for key in body["keys"]:
        if not isinstance(key, dict):
            raise CaseFailure("invalid_contract")
        if PRIVATE_JWK_FIELDS.intersection(key):
            raise CaseFailure("private_material_present")
        kid = key.get("kid")
        if (
            key.get("kty") != "RSA"
            or key.get("alg") != "RS256"
            or key.get("use") not in {None, "sig"}
            or not isinstance(kid, str)
            or not kid
            or not isinstance(key.get("n"), str)
            or not isinstance(key.get("e"), str)
            or kid in kids
        ):
            raise CaseFailure("invalid_contract")
        kids.add(kid)

    active_kid = context.values.get("HOSTED_CANVAS_EXPECTED_ACTIVE_KID", "").strip()
    retiring_kid = context.values.get("HOSTED_CANVAS_EXPECTED_RETIRING_KID", "").strip()
    if active_kid and active_kid not in kids:
        raise CaseFailure("expected_key_missing")
    if retiring_kid and (retiring_kid not in kids or retiring_kid == active_kid or len(kids) < 2):
        raise CaseFailure("expected_key_missing")


def check_marty_registration_config_public_only(context: ContractContext) -> None:
    platform_id = quote(context.values["HOSTED_CANVAS_PLATFORM_ID"], safe="")
    response = context.client.get(
        _url(
            context.marty_origin,
            f"/v1/integrations/canvas/platforms/{platform_id}/registration-config",
        )
    )
    body = _require_status(response)
    if not isinstance(body, dict) or not isinstance(body.get("developer_key_configuration"), dict):
        raise CaseFailure("invalid_contract")
    if PRIVATE_CONFIG_FIELDS.intersection(_walk_keys(body)):
        raise CaseFailure("private_material_present")

    url_values = list(_walk_url_values(body["developer_key_configuration"]))
    if len(url_values) < 2:
        raise CaseFailure("invalid_contract")
    for value in url_values:
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise CaseFailure("invalid_contract")


def check_marty_platform_portable_ready(context: ContractContext) -> None:
    platform_id = quote(context.values["HOSTED_CANVAS_PLATFORM_ID"], safe="")
    response = context.client.get(
        _url(
            context.marty_origin,
            f"/v1/integrations/canvas/platforms/{platform_id}/readiness",
        ),
        headers={"X-API-Key": context.values["HOSTED_CANVAS_MARTY_API_KEY"]},
    )
    body = _require_status(response)
    if not isinstance(body, dict) or body.get("ready") is not True:
        raise CaseFailure("platform_not_ready")
    checks = body.get("checks")
    if not isinstance(checks, list):
        raise CaseFailure("invalid_contract")
    for check in checks:
        if not isinstance(check, dict):
            raise CaseFailure("invalid_contract")
        if check.get("blocking") is True and str(check.get("status") or "").lower() not in {
            "ok",
            "pass",
            "ready",
        }:
            raise CaseFailure("platform_not_ready")


def _canvas_headers(context: ContractContext) -> dict[str, str]:
    return {"Authorization": f"Bearer {context.values['HOSTED_CANVAS_API_TOKEN']}"}


def check_hosted_canvas_course_access(context: ContractContext) -> None:
    course_id = quote(context.values["HOSTED_CANVAS_COURSE_ID"], safe="")
    response = context.client.get(
        _url(context.canvas_origin, f"/api/v1/courses/{course_id}"),
        headers=_canvas_headers(context),
    )
    body = _require_status(response)
    if not isinstance(body, dict) or str(body.get("id")) != context.values["HOSTED_CANVAS_COURSE_ID"]:
        raise CaseFailure("tenant_resource_mismatch")


def check_hosted_canvas_lti_tool_installed(context: ContractContext) -> None:
    course_id = quote(context.values["HOSTED_CANVAS_COURSE_ID"], safe="")
    tool_id = quote(context.values["HOSTED_CANVAS_EXTERNAL_TOOL_ID"], safe="")
    response = context.client.get(
        _url(
            context.canvas_origin,
            f"/api/v1/courses/{course_id}/external_tools/{tool_id}",
        ),
        headers=_canvas_headers(context),
    )
    body = _require_status(response)
    if not isinstance(body, dict) or str(body.get("id")) != context.values["HOSTED_CANVAS_EXTERNAL_TOOL_ID"]:
        raise CaseFailure("tenant_resource_mismatch")
    if str(body.get("workflow_state") or "").lower() in {"deleted", "disabled", "inactive"}:
        raise CaseFailure("tool_disabled")
    expected_client_id = context.values.get("HOSTED_CANVAS_LTI_CLIENT_ID", "").strip()
    observed_client_id = str(body.get("client_id") or "")
    if expected_client_id and observed_client_id and observed_client_id != expected_client_id:
        raise CaseFailure("tenant_resource_mismatch")


def check_hosted_canvas_sessionless_launch_available(context: ContractContext) -> None:
    course_id = quote(context.values["HOSTED_CANVAS_COURSE_ID"], safe="")
    response = context.client.get(
        _url(
            context.canvas_origin,
            f"/api/v1/courses/{course_id}/external_tools/sessionless_launch",
            query={"id": context.values["HOSTED_CANVAS_EXTERNAL_TOOL_ID"]},
        ),
        headers=_canvas_headers(context),
    )
    body = _require_status(response)
    launch_url = body.get("url") if isinstance(body, dict) else None
    if not isinstance(launch_url, str):
        raise CaseFailure("invalid_contract")
    parsed = urlparse(launch_url)
    allowed_origins = {context.canvas_origin.lower(), context.marty_origin.lower()}
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or _origin(launch_url) not in allowed_origins
    ):
        raise CaseFailure("unsafe_launch_url")


CASE_CHECKS: dict[str, Callable[[ContractContext], None]] = {
    "gateway_management_auth_default": check_gateway_management_auth_default,
    "marty_lti_jwks_rs256": check_marty_lti_jwks_rs256,
    "marty_registration_config_public_only": check_marty_registration_config_public_only,
    "marty_platform_portable_ready": check_marty_platform_portable_ready,
    "hosted_canvas_course_access": check_hosted_canvas_course_access,
    "hosted_canvas_lti_tool_installed": check_hosted_canvas_lti_tool_installed,
    "hosted_canvas_sessionless_launch_available": check_hosted_canvas_sessionless_launch_available,
}


def _timestamp(now: datetime | None = None) -> str:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _case_results(status: str, reason_code: str) -> list[dict[str, str]]:
    return [
        {"id": case_id, "status": status, "reason_code": reason_code}
        for case_id in AUTOMATED_CASE_IDS
    ]


def run_contract(
    contract: dict[str, Any],
    values: dict[str, str],
    *,
    client=None,
    now: datetime | None = None,
) -> dict[str, Any]:
    del contract  # The checked contract is validated by ``load_contract``.
    started_at = _timestamp(now)
    missing = [name for name in REQUIRED_CONFIGURATION if not values.get(name, "").strip()]
    if missing:
        return {
            "schema_version": 1,
            "suite": SUITE_NAME,
            "status": "skipped",
            "run_mode": "read_only",
            "started_at": started_at,
            "completed_at": _timestamp(now),
            "missing_configuration": missing,
            "cases": _case_results("skipped", "tenant_configuration_missing"),
        }

    try:
        for name in SECRET_CONFIGURATION:
            if len(values[name].strip()) < 12:
                raise CaseFailure("invalid_configuration")
        context = ContractContext(
            values=values,
            marty_origin=normalize_https_origin(values["HOSTED_CANVAS_MARTY_ORIGIN"]),
            canvas_origin=normalize_https_origin(values["HOSTED_CANVAS_ORIGIN"]),
            client=client or HttpJsonClient(),
        )
    except CaseFailure:
        return {
            "schema_version": 1,
            "suite": SUITE_NAME,
            "status": "failed",
            "run_mode": "read_only",
            "started_at": started_at,
            "completed_at": _timestamp(now),
            "missing_configuration": [],
            "cases": _case_results("failed", "invalid_configuration"),
        }

    cases: list[dict[str, str]] = []
    for case_id in AUTOMATED_CASE_IDS:
        try:
            CASE_CHECKS[case_id](context)
        except CaseFailure as error:
            cases.append({"id": case_id, "status": "failed", "reason_code": error.reason_code})
        except Exception:
            cases.append({"id": case_id, "status": "failed", "reason_code": "internal_check_error"})
        else:
            cases.append({"id": case_id, "status": "passed", "reason_code": "ok"})

    return {
        "schema_version": 1,
        "suite": SUITE_NAME,
        "status": "failed" if any(case["status"] == "failed" for case in cases) else "passed",
        "run_mode": "read_only",
        "started_at": started_at,
        "completed_at": _timestamp(now),
        "missing_configuration": [],
        "cases": cases,
    }


def verify_redacted_result(
    result: dict[str, Any],
    contract: dict[str, Any],
    values: dict[str, str],
) -> None:
    del contract
    if set(result) != ALLOWED_RESULT_KEYS:
        raise ContractConfigError("Hosted Canvas result contains fields outside the fixed schema")
    if result.get("schema_version") != 1 or result.get("suite") != SUITE_NAME:
        raise ContractConfigError("Hosted Canvas result identity is invalid")
    if result.get("status") not in {"passed", "failed", "skipped"}:
        raise ContractConfigError("Hosted Canvas result status is invalid")
    if result.get("run_mode") != "read_only":
        raise ContractConfigError("Hosted Canvas result mode is invalid")

    missing = result.get("missing_configuration")
    if not isinstance(missing, list) or any(name not in REQUIRED_CONFIGURATION for name in missing):
        raise ContractConfigError("Hosted Canvas result has invalid missing-configuration data")

    cases = result.get("cases")
    if not isinstance(cases, list) or tuple(case.get("id") for case in cases) != AUTOMATED_CASE_IDS:
        raise ContractConfigError("Hosted Canvas result case set is invalid")
    for case in cases:
        if not isinstance(case, dict) or set(case) != ALLOWED_CASE_KEYS:
            raise ContractConfigError("Hosted Canvas case contains fields outside the fixed schema")
        if case.get("status") not in ALLOWED_CASE_STATUSES:
            raise ContractConfigError("Hosted Canvas case status is invalid")
        if case.get("reason_code") not in ALLOWED_REASON_CODES:
            raise ContractConfigError("Hosted Canvas case reason is invalid")

    serialized = json.dumps(result, sort_keys=True)
    for name in SENSITIVE_CONFIGURATION:
        value = values.get(name, "").strip()
        if len(value) >= 8 and value in serialized:
            raise ContractConfigError("Hosted Canvas result contains configured tenant material")

    forbidden_key_pattern = re.compile(
        r"(?:authorization|body|cookie|header|password|private|response|secret|tenant_id|token|url)",
        re.IGNORECASE,
    )
    for key in _walk_keys(result):
        if forbidden_key_pattern.search(key):
            raise ContractConfigError("Hosted Canvas result contains a forbidden artifact field")


def _load_result(path: Path) -> dict[str, Any]:
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractConfigError("Could not read hosted Canvas result") from error
    if not isinstance(result, dict):
        raise ContractConfigError("Hosted Canvas result must be an object")
    return result


def _write_result(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def contract_exit_code(result: dict[str, Any], *, require_config: bool) -> int:
    """Return a gating exit code without suppressing the redacted skip artifact."""

    if result.get("status") == "failed":
        return 1
    if require_config and result.get("status") == "skipped":
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("deploy-config/catalog/hosted-canvas-acceptance.json"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-output", type=Path)
    parser.add_argument("--validate-config", action="store_true")
    parser.add_argument(
        "--require-config",
        action="store_true",
        help="Fail a gating run when protected hosted-tenant configuration is missing.",
    )
    parser.add_argument("--timeout", type=int, default=20)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    contract = load_contract(args.config)
    if args.validate_config:
        print("Hosted Canvas acceptance contract is valid.")
        return 0
    if args.verify_output:
        verify_redacted_result(_load_result(args.verify_output), contract, dict(os.environ))
        print("Hosted Canvas artifact passed fixed-schema redaction checks.")
        return 0
    if not args.output:
        raise ContractConfigError("--output is required when running the hosted Canvas contract")

    result = run_contract(
        contract,
        dict(os.environ),
        client=HttpJsonClient(timeout=max(1, args.timeout)),
    )
    verify_redacted_result(result, contract, dict(os.environ))
    _write_result(args.output, result)
    print(f"Hosted Canvas contract result: {result['status']}")
    for case in result["cases"]:
        print(f"- {case['id']}: {case['status']} ({case['reason_code']})")
    return contract_exit_code(result, require_config=args.require_config)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractConfigError as error:
        raise SystemExit(f"hosted Canvas contract configuration failed: {error}") from error
