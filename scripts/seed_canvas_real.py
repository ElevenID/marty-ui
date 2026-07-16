#!/usr/bin/env python3
"""Seed real Canvas + ElevenID Canvas platform/binding for local development.

What this script does:
1) Upserts an ElevenID Canvas platform and program binding against the issuance API.
2) Optionally creates Canvas LTI developer key with LTI 1.3 configuration when admin token provided.
3) Optionally seeds a Canvas course + learner enrollment + external tool when admin API token is provided.

The script is idempotent for platform creation (find by organization + canvas_account_id).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages"))

from marty_common.system_ids import (  # pylint: disable=import-error
    MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID,
    MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID,
    MARTY_DEFAULT_ORG_ID,
    MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID,
    MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID,
)


CANVAS_RAILS_RESULT_PREFIX = "__CANVAS_LTI_RESULT__"
CANVAS_RAILS_TOKEN_PREFIX = "__CANVAS_ADMIN_TOKEN__"
DEFAULT_CANVAS_LTI_CLIENT_ID = "canvas-real-client-id"
DEFAULT_CANVAS_LTI_DEPLOYMENT_ID = "canvas-real-deployment-id"
LTI_REQUIRED_SCOPES = [
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
    "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
    "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
]
CANVAS_INTEROPERABILITY_BADGE_SLUG = "canvas-interoperability-foundations-badge"
CANVAS_INTEROPERABILITY_BADGE_NAME = "Interoperable Credentials Foundations Badge"
CANVAS_INTEROPERABILITY_BADGE_DESCRIPTION = (
    "Open Badge 3.0 credential for completing the Interoperable Credentials Foundations "
    "learning check in Canvas."
)
CANVAS_INTEROPERABILITY_BADGE_VCT = (
    f"https://beta.elevenidllc.com/credentials/{CANVAS_INTEROPERABILITY_BADGE_SLUG}"
)
CANVAS_INTEROPERABILITY_BADGE_IMAGE_URL = f"{CANVAS_INTEROPERABILITY_BADGE_VCT}/image.svg"
CANVAS_INTEROPERABILITY_BADGE_CRITERIA_URL = f"{CANVAS_INTEROPERABILITY_BADGE_VCT}/criteria"
CANVAS_INTEROPERABILITY_BADGE_CRITERIA = (
    "Complete the Canvas learning activity and earn the configured passing score on the "
    "interoperability quiz. ElevenID issues the credential from the Marty organization "
    "using the canonical DID issuer and remote signing service."
)


def _load_dotenv(env_file: Path) -> None:
    if not env_file.exists():
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return database_url


def _resolve_database_url() -> str:
    database_url = _normalize_database_url((os.environ.get("DATABASE_URL") or "").strip())
    db_user = (os.environ.get("MARTY_DB_USER") or "marty").strip() or "marty"
    db_password = (os.environ.get("MARTY_DB_PASSWORD") or "marty_dev_password").strip() or "marty_dev_password"
    db_host = (
        os.environ.get("DATABASE_HOST")
        or os.environ.get("POSTGRES_HOST")
        or os.environ.get("MARTY_DB_HOST")
        or "localhost"
    ).strip() or "localhost"
    db_port = (
        os.environ.get("DATABASE_PORT")
        or os.environ.get("POSTGRES_PORT")
        or os.environ.get("POSTGRES_HOST_PORT")
        or os.environ.get("MARTY_DB_PORT")
        or "5433"
    ).strip() or "5433"
    db_name = (
        os.environ.get("DATABASE_NAME")
        or os.environ.get("POSTGRES_DB")
        or os.environ.get("MARTY_DB_NAME")
        or "marty"
    ).strip() or "marty"

    if database_url:
        parsed = urlparse(database_url)
        hostname = (parsed.hostname or "").strip().lower()
        use_local_compose_target = hostname in {"", "postgres", "marty-postgres", "localhost", "127.0.0.1"}
        effective_host = db_host if use_local_compose_target else hostname
        effective_port = db_port if use_local_compose_target else str(parsed.port or db_port)
        effective_user = db_user if use_local_compose_target else (parsed.username or db_user)
        effective_password = db_password if use_local_compose_target else (db_password or parsed.password or "")
        effective_name = db_name if use_local_compose_target else (parsed.path.lstrip("/") or db_name)
        return (
            f"postgresql+asyncpg://{quote(effective_user)}:{quote(effective_password)}"
            f"@{effective_host}:{effective_port}/{effective_name}"
        )

    return (
        f"postgresql+asyncpg://{quote(db_user)}:{quote(db_password)}"
        f"@{db_host}:{db_port}/{db_name}"
    )


async def _table_exists(conn: Any, qualified_name: str) -> bool:
    from sqlalchemy import text

    return bool(
        await conn.scalar(
            text("SELECT to_regclass(:qualified_name) IS NOT NULL"),
            {"qualified_name": qualified_name},
        )
    )


async def _column_exists(conn: Any, schema: str, table: str, column: str) -> bool:
    from sqlalchemy import text

    return bool(
        await conn.scalar(
            text(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_schema = :schema
                      AND table_name = :table
                      AND column_name = :column
                )
                """
            ),
            {"schema": schema, "table": table, "column": column},
        )
    )


def _json_request(
    method: str,
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> Any:
    body = None
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    req = Request(url=url, method=method, data=body, headers=request_headers)
    with urlopen(req, timeout=timeout) as resp:
        content = resp.read()
        if not content:
            return None
        return json.loads(content.decode("utf-8"))


def _signed_json_request(
    method: str,
    url: str,
    *,
    payload: dict[str, Any],
    secret: str,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> Any:
    raw_body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    timestamp = str(int(time.time()))
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode("utf-8") + raw_body,
        hashlib.sha256,
    ).hexdigest()
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Canvas-Timestamp": timestamp,
        "X-Canvas-Signature-256": f"sha256={digest}",
    }
    if headers:
        request_headers.update(headers)

    req = Request(url=url, method=method, data=raw_body, headers=request_headers)
    with urlopen(req, timeout=timeout) as resp:
        content = resp.read()
        if not content:
            return None
        return json.loads(content.decode("utf-8"))


def _form_request(
    method: str,
    url: str,
    *,
    form: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> Any:
    encoded = urlencode(form, doseq=True).encode("utf-8")
    request_headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        request_headers.update(headers)
    req = Request(url=url, method=method, data=encoded, headers=request_headers)
    with urlopen(req, timeout=timeout) as resp:
        content = resp.read()
        if not content:
            return None
        return json.loads(content.decode("utf-8"))


def _wait_for_http(base_url: str, path: str = "/", retries: int = 60, delay: float = 2.0) -> bool:
    probe_url = f"{base_url.rstrip('/')}{path}"
    for attempt in range(1, retries + 1):
        try:
            req = Request(url=probe_url, method="GET", headers={"Accept": "*/*"})
            with urlopen(req, timeout=10):
                return True
        except Exception:
            if attempt == retries:
                return False
            time.sleep(delay)
    return False


def _container_reachable_url(url: str) -> str:
    """Convert localhost-style URLs into host.docker.internal for container-to-host access."""
    parsed = urlparse(url)
    if parsed.hostname not in {"localhost", "127.0.0.1"}:
        return url.rstrip("/")

    netloc = "host.docker.internal"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    return urlunparse(
        (
            parsed.scheme or "http",
            netloc,
            parsed.path or "",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    ).rstrip("/")


def _lti_experience_login_url(connector_cfg: "ConnectorSeedConfig", platform_id: str) -> str:
    return (
        f"{connector_cfg.lti_tool_base_url.rstrip('/')}/v1/integrations/canvas/lti/platforms/"
        f"{platform_id}/experience-login"
    )


def _lti_experience_launch_url(connector_cfg: "ConnectorSeedConfig", platform_id: str) -> str:
    return (
        f"{connector_cfg.lti_tool_base_url.rstrip('/')}/v1/integrations/canvas/lti/platforms/"
        f"{platform_id}/experience"
    )


@dataclass
class ConnectorSeedConfig:
    issuance_base_url: str
    issuance_api_key: str
    organization_id: str
    canvas_account_id: str
    credential_template_id: str
    application_template_id: str
    display_name: str
    canvas_base_url: str
    lti_tool_base_url: str
    lti_client_id: str
    lti_deployment_id: str
    probe_after_upsert: bool
    program_binding_seed_enabled: bool
    program_binding_display_name: str
    program_binding_evidence_type: str
    program_binding_delivery_mode: str
    program_binding_auto_approve: bool
    program_binding_direct_issue: bool
    program_binding_score_threshold: int
    open_badge_scenario_enabled: bool
    demo_application_seed_enabled: bool
    demo_evidence_event_enabled: bool
    demo_wallet_claim_enabled: bool
    demo_mirror_publish_enabled: bool
    signing_keys_internal_base_url: str
    signing_keys_internal_api_key: str


@dataclass
class CanvasSeedConfig:
    enabled: bool
    api_base_url: str
    browser_base_url: str
    admin_token: str
    admin_email: str
    admin_password: str
    account_id: str
    container_name: str
    course_name: str
    course_code: str
    course_sis_id: str
    learner_name: str
    learner_email: str
    learner_password: str
    launch_seed_enabled: bool
    launch_module_name: str
    launch_item_title: str
    launch_assignment_name: str
    quiz_seed_enabled: bool
    quiz_title: str
    quiz_description: str
    quiz_passing_score_percent: int
    quiz_points_possible: int


def _canvas_demo_scope(
    *,
    course_id: str | int | None = None,
    quiz_id: str | int | None = None,
    assignment_id: str | int | None = None,
    module_id: str | int | None = None,
) -> dict[str, Any]:
    scope: dict[str, Any] = {}
    if course_id is not None:
        scope["course_id"] = str(course_id)
    if quiz_id is not None:
        scope["quiz_id"] = str(quiz_id)
    if assignment_id is not None:
        scope["assignment_id"] = str(assignment_id)
    if module_id is not None:
        scope["module_id"] = str(module_id)
    return scope


def _env_optional(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def _canvas_scope_from_admin_env() -> dict[str, Any]:
    """Read Canvas scope IDs supplied by an institution/admin import process."""

    return _canvas_demo_scope(
        course_id=_env_optional("CANVAS_PROGRAM_BINDING_COURSE_ID") or _env_optional("CANVAS_COURSE_ID"),
        quiz_id=_env_optional("CANVAS_PROGRAM_BINDING_QUIZ_ID") or _env_optional("CANVAS_QUIZ_ID"),
        assignment_id=(
            _env_optional("CANVAS_PROGRAM_BINDING_ASSIGNMENT_ID")
            or _env_optional("CANVAS_ASSIGNMENT_ID")
        ),
        module_id=_env_optional("CANVAS_PROGRAM_BINDING_MODULE_ID") or _env_optional("CANVAS_MODULE_ID"),
    )


def _canvas_open_badge_claims() -> list[dict[str, Any]]:
    return [
        {"name": "email", "display_name": "Learner email", "claim_type": "string", "required": True, "selectively_disclosable": True},
        {"name": "given_name", "display_name": "Given name", "claim_type": "string", "required": True, "selectively_disclosable": True},
        {"name": "family_name", "display_name": "Family name", "claim_type": "string", "required": True, "selectively_disclosable": True},
        {"name": "achievement_id", "display_name": "Achievement ID", "claim_type": "string", "required": True, "selectively_disclosable": False},
        {"name": "achievement_name", "display_name": "Achievement", "claim_type": "string", "required": True, "selectively_disclosable": True},
        {"name": "achievement_description", "display_name": "Achievement description", "claim_type": "string", "required": True, "selectively_disclosable": True},
        {"name": "achievement_criteria", "display_name": "Achievement criteria", "claim_type": "string", "required": True, "selectively_disclosable": False},
        {"name": "badge_image_url", "display_name": "Badge image", "claim_type": "image", "required": True, "selectively_disclosable": False},
        {"name": "course_name", "display_name": "Canvas course", "claim_type": "string", "required": True, "selectively_disclosable": True},
        {"name": "quiz_name", "display_name": "Canvas quiz", "claim_type": "string", "required": True, "selectively_disclosable": True},
        {"name": "score_percent", "display_name": "Score percent", "claim_type": "number", "required": True, "selectively_disclosable": True},
        {"name": "completion_date", "display_name": "Completion date", "claim_type": "date", "required": True, "selectively_disclosable": True},
        {"name": "institution_name", "display_name": "Institution", "claim_type": "string", "required": True, "selectively_disclosable": True},
        {"name": "certificate_id", "display_name": "Certificate ID", "claim_type": "string", "required": True, "selectively_disclosable": True},
        {"name": "organization_id", "display_name": "Issuer organization", "claim_type": "string", "required": True, "selectively_disclosable": False},
        {"name": "achievement", "display_name": "Open Badge achievement", "claim_type": "object", "required": True, "selectively_disclosable": False},
        {"name": "result", "display_name": "Canvas quiz result", "claim_type": "object", "required": True, "selectively_disclosable": True},
        {"name": "learning_context", "display_name": "Canvas learning context", "claim_type": "object", "required": True, "selectively_disclosable": True},
    ]


def _canvas_open_badge_achievement(*, score_threshold: int | None = None) -> dict[str, Any]:
    criteria = CANVAS_INTEROPERABILITY_BADGE_CRITERIA
    if score_threshold is not None:
        criteria = (
            f"Complete the Canvas learning activity and earn at least {score_threshold}% on the "
            "interoperability quiz. ElevenID issues the credential from the Marty organization "
            "using the canonical DID issuer and remote signing service."
        )
    return {
        "id": f"{CANVAS_INTEROPERABILITY_BADGE_VCT}#achievement",
        "type": ["Achievement"],
        "name": CANVAS_INTEROPERABILITY_BADGE_NAME,
        "description": CANVAS_INTEROPERABILITY_BADGE_DESCRIPTION,
        "criteria": {
            "id": CANVAS_INTEROPERABILITY_BADGE_CRITERIA_URL,
            "narrative": criteria,
        },
        "image": {
            "id": CANVAS_INTEROPERABILITY_BADGE_IMAGE_URL,
            "type": "Image",
            "caption": CANVAS_INTEROPERABILITY_BADGE_NAME,
        },
        "alignment": [
            {
                "targetName": "Open Badges 3.0",
                "targetDescription": "Portable achievement credential carried as a verifiable credential.",
            },
            {
                "targetName": "Marty Identity Protocol",
                "targetDescription": "MIP-governed issuance, status-list allocation, and destination projection.",
            },
        ],
    }


def _canvas_open_badge_evidence_requirement(
    cfg: ConnectorSeedConfig,
    canvas_scope: dict[str, Any] | None,
    *,
    verification_method: str = "SIGNED_AGS_SCORE",
) -> dict[str, Any]:
    return {
        "id": "canvas-quiz-score",
        "label": "Canvas quiz score",
        "evidence_type": "EXTERNAL_FACT",
        "provider": "canvas",
        "fact_type": cfg.program_binding_evidence_type,
        "verification_method": verification_method,
        "scope": dict(canvas_scope or {}),
        "pass_rule": {
            "path": "assertion.score_percent",
            "operator": ">=",
            "value": cfg.program_binding_score_threshold,
        },
        "required": True,
        "auto_issue_on_permit": cfg.program_binding_auto_approve,
    }


def _canvas_open_badge_remote_signing_config(connector_cfg: ConnectorSeedConfig) -> dict[str, Any]:
    return {
        "provider": "gateway-signing-key-registry",
        "issuer_profile_id": "ip-marty-vc-jwt-issuer",
        "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
        "verification_method_id": "did:web:beta.elevenidllc.com:orgs:marty#cred-issuer-marty-es256",
        "signing_service_id": "managed-openbao-transit",
        "signing_key_reference": "cred-issuer-marty-es256",
        "key_purpose": "vc_jwt_issuer",
        "credential_formats": ["sd_jwt_vc", "jwt_vc_json"],
        "secret_boundary": {
            "issuer_private_key_location": "external_remote_key_store",
            "beta_elevenidllc_com_private_key_material": "not_present",
            "canvas_private_key_material": "not_present",
        },
        "resolver": {
            "url": f"{connector_cfg.signing_keys_internal_base_url.rstrip('/')}/issuer-context",
            "api_key_source": "SIGNING_KEYS_INTERNAL_API_KEY",
        },
    }


async def _seed_canvas_open_badge_templates_async(
    cfg: ConnectorSeedConfig,
    *,
    canvas_scope: dict[str, Any] | None = None,
) -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(_resolve_database_url(), future=True)
    credential_template_payload = {
        "id": cfg.credential_template_id,
        "organization_id": cfg.organization_id,
        "name": CANVAS_INTEROPERABILITY_BADGE_NAME,
        "description": CANVAS_INTEROPERABILITY_BADGE_DESCRIPTION,
        "status": "active",
        "credential_type": "OpenBadgeCredential",
        "vct": CANVAS_INTEROPERABILITY_BADGE_VCT,
        "doctype": "org.openbadges.v3",
        "claims": json.dumps(_canvas_open_badge_claims(), separators=(",", ":")),
        "privacy_posture": "selective_disclosure",
        "selective_disclosure_fields": json.dumps(
            [
                "email",
                "given_name",
                "family_name",
                "achievement_name",
                "achievement_description",
                "course_name",
                "quiz_name",
                "score_percent",
                "completion_date",
                "institution_name",
                "certificate_id",
                "result",
                "learning_context",
            ],
            separators=(",", ":"),
        ),
        "zk_predicate_claims": json.dumps([], separators=(",", ":")),
        "derived_attributes": json.dumps([], separators=(",", ":")),
        "display_style": json.dumps(
            {
                "background_color": "#0B5F7A",
                "text_color": "#ffffff",
                "icon": "award",
                "logo_url": CANVAS_INTEROPERABILITY_BADGE_IMAGE_URL,
            },
            separators=(",", ":"),
        ),
        "validity_rules": json.dumps({"duration": "P1Y", "renewal_required": False}, separators=(",", ":")),
        "issuer_requirements": json.dumps(
            {
                "allowed_issuer_dids": ["did:web:beta.elevenidllc.com:orgs:marty"],
                "trust_tier_required": "organization_managed_remote_signing",
                "audit_level_required": "standard",
            },
            separators=(",", ":"),
        ),
        "supported_formats": json.dumps(["sd_jwt_vc"], separators=(",", ":")),
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "wallet_configs": json.dumps(
            [
                {"wallet_id": "waltid", "deep_link_scheme": "openid-credential-offer://", "format_variant": None},
                {"wallet_id": "spruceid", "deep_link_scheme": "spruceid://", "format_variant": "spruce-vc+sd-jwt"},
            ],
            separators=(",", ":"),
        ),
        "key_access_mode": "REMOTE_SIGNING",
        "issuer_key_id": "cred-issuer-marty-es256",
        "issuer_algorithm": "ES256",
        "remote_signing_config": json.dumps(_canvas_open_badge_remote_signing_config(cfg), separators=(",", ":")),
        "version": 1,
    }
    evidence_requirement = _canvas_open_badge_evidence_requirement(cfg, canvas_scope)
    application_template_payload = {
        "id": cfg.application_template_id,
        "organization_id": cfg.organization_id,
        "name": "Interoperable Credentials Foundations Application",
        "description": "Canvas-started application workflow for the interoperability Open Badge demonstration.",
        "credential_template_id": cfg.credential_template_id,
        "form_fields": json.dumps(
            [
                {"name": "email", "label": "Email", "type": "email", "required": True},
                {"name": "given_name", "label": "Given name", "type": "text", "required": True},
                {"name": "family_name", "label": "Family name", "type": "text", "required": True},
                {"name": "course_name", "label": "Canvas course", "type": "text", "required": True},
                {"name": "quiz_name", "label": "Canvas quiz", "type": "text", "required": True},
                {"name": "score_percent", "label": "Score percent", "type": "number", "required": True},
            ],
            separators=(",", ":"),
        ),
        "evidence_requirements": json.dumps([evidence_requirement], separators=(",", ":")),
        "claim_collection_rules": json.dumps([], separators=(",", ":")),
        "required_checks": json.dumps([], separators=(",", ":")),
        "approval_strategy": "policy",
        "approval_policy_set_id": None,
        "application_validity_days": 30,
        "auto_approval_rules": json.dumps([], separators=(",", ":")),
        "ui_config": json.dumps(
            {
                "scenario": "canvas_mip_quiz_open_badge",
                "provider": "canvas",
                "fact_type": cfg.program_binding_evidence_type,
                "scope": dict(canvas_scope or {}),
                "delivery_mode": cfg.program_binding_delivery_mode,
                "issuer_mode": "org_managed",
                "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
                "open_badge": {
                    "vct": CANVAS_INTEROPERABILITY_BADGE_VCT,
                    "name": CANVAS_INTEROPERABILITY_BADGE_NAME,
                    "image": CANVAS_INTEROPERABILITY_BADGE_IMAGE_URL,
                    "criteria": CANVAS_INTEROPERABILITY_BADGE_CRITERIA_URL,
                },
            },
            separators=(",", ":"),
        ),
        "notification_config": json.dumps({}, separators=(",", ":")),
        "status": "active",
    }

    try:
        async with engine.begin() as conn:
            if not await _table_exists(conn, "credential_template_service.credential_templates"):
                raise RuntimeError("credential_template_service.credential_templates does not exist")
            if not await _table_exists(conn, "issuance_service.application_templates"):
                raise RuntimeError("issuance_service.application_templates does not exist")

            has_remote_signing = await _column_exists(
                conn,
                "credential_template_service",
                "credential_templates",
                "remote_signing_config",
            )
            credential_columns = """
                id, organization_id, name, description, status,
                credential_type, vct, doctype, claims, privacy_posture,
                selective_disclosure_fields, zk_predicate_claims,
                derived_attributes, display_style, validity_rules,
                issuer_requirements, supported_formats,
                credential_payload_format, wallet_configs,
                version, created_at, updated_at
            """
            credential_values = """
                :id, :organization_id, :name, :description, :status,
                :credential_type, :vct, :doctype, CAST(:claims AS jsonb), :privacy_posture,
                CAST(:selective_disclosure_fields AS jsonb), CAST(:zk_predicate_claims AS jsonb),
                CAST(:derived_attributes AS jsonb), CAST(:display_style AS jsonb),
                CAST(:validity_rules AS jsonb), CAST(:issuer_requirements AS jsonb),
                CAST(:supported_formats AS jsonb), :credential_payload_format,
                CAST(:wallet_configs AS jsonb), :version, NOW(), NOW()
            """
            credential_update = """
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                status = EXCLUDED.status,
                credential_type = EXCLUDED.credential_type,
                vct = EXCLUDED.vct,
                doctype = EXCLUDED.doctype,
                claims = EXCLUDED.claims,
                privacy_posture = EXCLUDED.privacy_posture,
                selective_disclosure_fields = EXCLUDED.selective_disclosure_fields,
                zk_predicate_claims = EXCLUDED.zk_predicate_claims,
                derived_attributes = EXCLUDED.derived_attributes,
                display_style = EXCLUDED.display_style,
                validity_rules = EXCLUDED.validity_rules,
                issuer_requirements = EXCLUDED.issuer_requirements,
                supported_formats = EXCLUDED.supported_formats,
                credential_payload_format = EXCLUDED.credential_payload_format,
                wallet_configs = EXCLUDED.wallet_configs,
                updated_at = NOW()
            """
            if has_remote_signing:
                credential_columns = credential_columns.replace(
                    "version, created_at, updated_at",
                    "key_access_mode, issuer_key_id, issuer_algorithm, remote_signing_config, version, created_at, updated_at",
                )
                credential_values = credential_values.replace(
                    ":version, NOW(), NOW()",
                    ":key_access_mode, :issuer_key_id, :issuer_algorithm, CAST(:remote_signing_config AS jsonb), :version, NOW(), NOW()",
                )
                credential_update = credential_update.replace(
                    "updated_at = NOW()",
                    (
                        "key_access_mode = EXCLUDED.key_access_mode,\n"
                        "                issuer_key_id = EXCLUDED.issuer_key_id,\n"
                        "                issuer_algorithm = EXCLUDED.issuer_algorithm,\n"
                        "                remote_signing_config = EXCLUDED.remote_signing_config,\n"
                        "                updated_at = NOW()"
                    ),
                )

            await conn.execute(
                text(
                    f"""
                    INSERT INTO credential_template_service.credential_templates (
                        {credential_columns}
                    )
                    VALUES (
                        {credential_values}
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        {credential_update}
                    """
                ),
                credential_template_payload,
            )
            await conn.execute(
                text(
                    """
                    INSERT INTO issuance_service.application_templates (
                        id, organization_id, name, description, credential_template_id,
                        form_fields, evidence_requirements, claim_collection_rules,
                        required_checks, approval_strategy, approval_policy_set_id,
                        application_validity_days, auto_approval_rules, ui_config,
                        notification_config, status, created_at, updated_at
                    )
                    VALUES (
                        :id, :organization_id, :name, :description, :credential_template_id,
                        CAST(:form_fields AS jsonb), CAST(:evidence_requirements AS jsonb),
                        CAST(:claim_collection_rules AS jsonb), CAST(:required_checks AS jsonb),
                        :approval_strategy, :approval_policy_set_id, :application_validity_days,
                        CAST(:auto_approval_rules AS jsonb), CAST(:ui_config AS jsonb),
                        CAST(:notification_config AS jsonb), :status, NOW(), NOW()
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        credential_template_id = EXCLUDED.credential_template_id,
                        form_fields = EXCLUDED.form_fields,
                        evidence_requirements = EXCLUDED.evidence_requirements,
                        claim_collection_rules = EXCLUDED.claim_collection_rules,
                        required_checks = EXCLUDED.required_checks,
                        approval_strategy = EXCLUDED.approval_strategy,
                        approval_policy_set_id = EXCLUDED.approval_policy_set_id,
                        application_validity_days = EXCLUDED.application_validity_days,
                        auto_approval_rules = EXCLUDED.auto_approval_rules,
                        ui_config = EXCLUDED.ui_config,
                        notification_config = EXCLUDED.notification_config,
                        status = EXCLUDED.status,
                        updated_at = NOW()
                    """
                ),
                application_template_payload,
            )
    finally:
        await engine.dispose()


def _seed_canvas_open_badge_templates(
    cfg: ConnectorSeedConfig,
    *,
    canvas_scope: dict[str, Any] | None = None,
) -> None:
    asyncio.run(_seed_canvas_open_badge_templates_async(cfg, canvas_scope=canvas_scope))


def _connector_headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


def _lti_tool_domain(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.hostname:
        return parsed.hostname
    return base_url.rstrip("/").split("://")[-1].split("/", 1)[0]


def _resolve_canvas_container_name(container_name: str) -> str:
    try:
        completed = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return container_name

    if completed.returncode != 0:
        return container_name

    container_name = container_name.strip()
    names = [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]
    if container_name in names:
        return container_name

    suffixed_name = f"_{container_name}"
    for name in names:
        if name.endswith(suffixed_name):
            return name

    return container_name


def _docker_container_env_value(container_name: str, key: str) -> str:
    try:
        completed = subprocess.run(
            ["docker", "inspect", "--format", "{{json .Config.Env}}", container_name],
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0:
        return ""
    try:
        entries = json.loads((completed.stdout or "").strip() or "[]")
    except json.JSONDecodeError:
        return ""
    if not isinstance(entries, list):
        return ""
    prefix = f"{key}="
    for entry in entries:
        if isinstance(entry, str) and entry.startswith(prefix):
            return entry[len(prefix):]
    return ""


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _canvas_api_headers(cfg: CanvasSeedConfig) -> dict[str, str]:
    return {"Authorization": f"Bearer {cfg.admin_token}"}


def _refresh_canvas_platform_jwks(cfg: ConnectorSeedConfig, platform_id: str) -> dict[str, Any]:
    headers = _connector_headers(cfg.issuance_api_key)
    refresh_url = (
        f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/platforms/"
        f"{platform_id}/jwks-refresh"
    )
    refreshed = _json_request("POST", refresh_url, headers=headers)
    if not isinstance(refreshed, dict) or not isinstance(refreshed.get("platform"), dict):
        raise RuntimeError("Canvas platform JWKS refresh did not return a valid platform payload")
    return refreshed


def _upsert_canvas_platform(cfg: ConnectorSeedConfig) -> dict[str, Any]:
    headers = _connector_headers(cfg.issuance_api_key)
    list_url = (
        f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/platforms"
        f"?organization_id={cfg.organization_id}"
    )
    platforms = _json_request("GET", list_url, headers=headers)
    if not isinstance(platforms, list):
        raise RuntimeError("Unexpected Canvas platform list response from issuance API")

    existing = next(
        (
            item
            for item in platforms
            if isinstance(item, dict)
            and item.get("organization_id") == cfg.organization_id
            and item.get("canvas_account_id") == cfg.canvas_account_id
        ),
        None,
    )

    payload = {
        "organization_id": cfg.organization_id,
        "canvas_account_id": cfg.canvas_account_id,
        "display_name": cfg.display_name,
        "canvas_base_url": cfg.canvas_base_url,
        "lti_client_id": cfg.lti_client_id,
        "lti_deployment_id": cfg.lti_deployment_id,
        "enabled": True,
    }
    if isinstance(existing, dict):
        for key in (
            "lti_issuer",
            "lti_jwks_url",
            "lti_jwks_json",
            "lti_jwks_fetched_at",
            "lti_jwks_expires_at",
            "lti_openid_configuration",
        ):
            if key in existing and existing[key] is not None:
                payload[key] = existing[key]

    if existing and existing.get("id"):
        platform_id = str(existing["id"])
        url = f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/platforms/{platform_id}"
        platform = _json_request("PUT", url, payload=payload, headers=headers)
        action = "updated"
    else:
        url = f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/platforms"
        platform = _json_request("POST", url, payload=payload, headers=headers)
        action = "created"

    if not isinstance(platform, dict) or not platform.get("id"):
        raise RuntimeError("Canvas platform upsert did not return a valid platform payload")

    if cfg.probe_after_upsert:
        probe_url = (
            f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/platforms/"
            f"{platform.get('id')}/sandbox-probe"
        )
        probe_response = _json_request("POST", probe_url, payload={}, headers=headers)
        if isinstance(probe_response, dict) and isinstance(probe_response.get("platform"), dict):
            platform = probe_response["platform"]

    return {"action": action, "platform": platform}


def _canvas_program_binding_feature_flags(cfg: ConnectorSeedConfig) -> dict[str, bool]:
    mirror_enabled = cfg.program_binding_delivery_mode == "wallet_plus_canvas_mirror"
    return {
        "enable_canvas_evidence": True,
        "enable_canvas_lti": True,
        "enable_canvas_mirror_publish": mirror_enabled,
        "enable_canvas_mirror_ops": mirror_enabled,
        "enable_canvas_deep_linking": True,
        "enable_canvas_ags": True,
        "enable_canvas_nrps": True,
    }


def _canvas_program_binding_evidence_requirement(
    cfg: ConnectorSeedConfig,
    canvas_scope: dict[str, Any] | None,
) -> dict[str, Any]:
    requirement = {
        "evidence_type": "EXTERNAL_FACT",
        "provider": "canvas",
        "fact_type": cfg.program_binding_evidence_type,
        "verification_method": "SIGNED_AGS_SCORE" if cfg.program_binding_evidence_type.endswith("_score") else "SIGNED_WEBHOOK",
        "scope": dict(canvas_scope or {}),
        "auto_issue_on_permit": cfg.program_binding_auto_approve,
    }
    if cfg.program_binding_evidence_type.endswith("_score"):
        requirement["pass_rule"] = {
            "path": "assertion.score_percent",
            "operator": ">=",
            "value": cfg.program_binding_score_threshold,
        }
    else:
        requirement["pass_rule"] = {
            "path": "assertion.completed",
            "operator": "equals",
            "value": True,
        }
    return requirement


def _upsert_canvas_program_binding(
    cfg: ConnectorSeedConfig,
    platform: dict[str, Any],
    canvas_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    headers = _connector_headers(cfg.issuance_api_key)
    platform_id = str(platform.get("id") or "")
    if not platform_id:
        raise RuntimeError("Canvas program binding seed requires a platform ID")

    query = urlencode(
        {
            "organization_id": cfg.organization_id,
            "platform_id": platform_id,
            "application_template_id": cfg.application_template_id,
        }
    )
    list_url = f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/program-bindings?{query}"
    bindings = _json_request("GET", list_url, headers=headers)
    if not isinstance(bindings, list):
        raise RuntimeError("Unexpected Canvas program binding list response from issuance API")

    existing = next(
        (
            item
            for item in bindings
            if isinstance(item, dict)
            and item.get("credential_template_id") == cfg.credential_template_id
            and (item.get("canvas_scope") or {}) == dict(canvas_scope or {})
        ),
        None,
    )

    payload = {
        "application_template_id": cfg.application_template_id,
        "credential_template_id": cfg.credential_template_id,
        "display_name": cfg.program_binding_display_name,
        "flow_mode": "elevenid_orchestrated_canvas_evidence",
        "direct_issue_enabled": cfg.program_binding_direct_issue,
        "auto_approve_on_evidence": cfg.program_binding_auto_approve,
        "evidence_requirements": [_canvas_program_binding_evidence_requirement(cfg, canvas_scope)],
        "canvas_scope": dict(canvas_scope or {}),
        "delivery_mode": cfg.program_binding_delivery_mode,
        "issuer_mode": "org_managed",
        "approval_policy_set_id": None,
        "deployment_profile_id": None,
        "feature_flags": _canvas_program_binding_feature_flags(cfg),
        "enabled": True,
    }

    if existing and existing.get("id"):
        binding_id = str(existing["id"])
        url = f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/program-bindings/{binding_id}"
        binding = _json_request("PUT", url, payload=payload, headers=headers)
        action = "updated"
    else:
        url = (
            f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/platforms/"
            f"{platform_id}/program-bindings"
        )
        binding = _json_request("POST", url, payload=payload, headers=headers)
        action = "created"

    if not isinstance(binding, dict) or not binding.get("id"):
        raise RuntimeError("Canvas program binding upsert did not return a valid binding payload")
    return {"action": action, "binding": binding}


def _first_item(value: Any) -> dict[str, Any] | None:
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, dict):
            return first
    if isinstance(value, dict):
        return value
    return None


def _canvas_admin_exists(cfg: CanvasSeedConfig) -> bool:
    resolved_container_name = _resolve_canvas_container_name(cfg.container_name)
    command = [
        "docker",
        "exec",
        "-e",
        f"CANVAS_ADMIN_EMAIL={cfg.admin_email}",
        resolved_container_name,
        "bash",
        "-lc",
        (
            "cd /usr/src/app && bin/rails runner -e production "
            "'email=ENV.fetch(\"CANVAS_ADMIN_EMAIL\"); "
            "puts(Pseudonym.where(unique_id: email).exists? ? \"yes\" : \"no\")'"
        ),
    ]
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=90,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Docker CLI is not available; cannot inspect Canvas admin state") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Canvas admin state check timed out") from exc

    if completed.returncode != 0:
        combined_output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        raise RuntimeError(
            f"Canvas admin state check failed (exit {completed.returncode}): {combined_output or 'no output'}"
        )

    return any(line.strip() == "yes" for line in (completed.stdout or "").splitlines())


def _ensure_canvas_initial_data(cfg: CanvasSeedConfig) -> bool:
    if _canvas_admin_exists(cfg):
        return False

    resolved_container_name = _resolve_canvas_container_name(cfg.container_name)
    input_text = "\n".join(
        [
            cfg.admin_email,
            cfg.admin_email,
            cfg.admin_password,
            cfg.admin_password,
            "Marty Canvas Test",
            "3",
        ]
    ) + "\n"
    command = [
        "docker",
        "exec",
        "-i",
        resolved_container_name,
        "bash",
        "-lc",
        "cd /usr/src/app && bundle exec rake db:load_initial_data RAILS_ENV=production",
    ]
    try:
        completed = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=240,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Docker CLI is not available; cannot initialize Canvas admin account") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Canvas initial data setup timed out") from exc

    if completed.returncode != 0:
        combined_output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        raise RuntimeError(
            f"Canvas initial data setup failed (exit {completed.returncode}): {combined_output or 'no output'}"
        )

    if not _canvas_admin_exists(cfg):
        raise RuntimeError("Canvas initial data setup completed but admin login was not created")
    return True


def _mint_canvas_admin_token(cfg: CanvasSeedConfig) -> str:
    _ensure_canvas_initial_data(cfg)

    payload_b64 = base64.b64encode(
        json.dumps({"admin_email": cfg.admin_email}, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    resolved_container_name = _resolve_canvas_container_name(cfg.container_name)
    ruby_script = f"""
require "base64"
require "json"

payload = JSON.parse(Base64.decode64(ENV.fetch("CANVAS_ADMIN_TOKEN_SETUP_B64")))
pseudonym = Pseudonym.find_by!(unique_id: payload.fetch("admin_email"))
token = pseudonym.user.access_tokens.create!(purpose: "ElevenID Canvas demo seed")
token.workflow_state = "active" if token.respond_to?(:workflow_state=)
token.save! if token.changed?
puts {CANVAS_RAILS_TOKEN_PREFIX!r} + token.full_token
"""

    command = [
        "docker",
        "exec",
        "-i",
        "-e",
        f"CANVAS_ADMIN_TOKEN_SETUP_B64={payload_b64}",
        resolved_container_name,
        "bash",
        "-lc",
        "cat >/tmp/mint_canvas_admin_token.rb; cd /usr/src/app; bin/rails runner -e production /tmp/mint_canvas_admin_token.rb",
    ]
    try:
        completed = subprocess.run(
            command,
            input=ruby_script,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Docker CLI is not available; cannot mint Canvas admin token") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Canvas admin token minting timed out") from exc

    if completed.returncode != 0:
        combined_output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        raise RuntimeError(
            f"Canvas admin token minting failed (exit {completed.returncode}): {combined_output or 'no output'}"
        )

    for line in reversed((completed.stdout or "").splitlines()):
        if line.startswith(CANVAS_RAILS_TOKEN_PREFIX):
            token = line[len(CANVAS_RAILS_TOKEN_PREFIX):].strip()
            if token:
                return token

    raise RuntimeError("Canvas admin token minting completed but did not emit a token")


def _ensure_canvas_course(cfg: CanvasSeedConfig) -> dict[str, Any]:
    headers = _canvas_api_headers(cfg)
    courses_url = f"{cfg.api_base_url.rstrip('/')}/api/v1/accounts/{cfg.account_id}/courses"
    search_query = urlencode({"search_term": cfg.course_name})

    try:
        existing_courses = _json_request("GET", f"{courses_url}?{search_query}", headers=headers)
    except HTTPError:
        existing_courses = []

    if isinstance(existing_courses, list):
        for course in existing_courses:
            if not isinstance(course, dict):
                continue
            if (
                course.get("sis_course_id") == cfg.course_sis_id
                or course.get("course_code") == cfg.course_code
                or course.get("name") == cfg.course_name
            ):
                return course

    created = _form_request(
        "POST",
        courses_url,
        form={
            "course[name]": cfg.course_name,
            "course[course_code]": cfg.course_code,
            "course[sis_course_id]": cfg.course_sis_id,
            "offer": "true",
        },
        headers=headers,
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError("Failed to create Canvas course")
    return created


def _ensure_canvas_user(cfg: CanvasSeedConfig) -> dict[str, Any]:
    headers = _canvas_api_headers(cfg)
    users_url = f"{cfg.api_base_url.rstrip('/')}/api/v1/accounts/{cfg.account_id}/users"
    search_query = urlencode({"search_term": cfg.learner_email})
    try:
        existing_users = _json_request("GET", f"{users_url}?{search_query}", headers=headers)
    except HTTPError:
        existing_users = []

    if isinstance(existing_users, list):
        for user in existing_users:
            if not isinstance(user, dict):
                continue
            if user.get("login_id") == cfg.learner_email or user.get("sis_user_id") == cfg.learner_email:
                return user

    created = _form_request(
        "POST",
        users_url,
        form={
            "user[name]": cfg.learner_name,
            "pseudonym[unique_id]": cfg.learner_email,
            "pseudonym[password]": cfg.learner_password,
            "communication_channel[type]": "email",
            "communication_channel[address]": cfg.learner_email,
            "skip_confirmation": "true",
        },
        headers=headers,
    )

    user = _first_item(created)
    if not user:
        raise RuntimeError("Canvas user create did not return a user payload")
    return user


def _ensure_canvas_enrollment(cfg: CanvasSeedConfig, course_id: int | str, user_id: int | str) -> dict[str, Any] | None:
    headers = _canvas_api_headers(cfg)
    enrollments_url = f"{cfg.api_base_url.rstrip('/')}/api/v1/courses/{course_id}/enrollments"
    search_query = urlencode({"user_id[]": [str(user_id)], "type[]": ["StudentEnrollment"]}, doseq=True)
    try:
        existing_enrollments = _json_request("GET", f"{enrollments_url}?{search_query}", headers=headers)
    except HTTPError:
        existing_enrollments = []

    if isinstance(existing_enrollments, list):
        for enrollment in existing_enrollments:
            if not isinstance(enrollment, dict):
                continue
            if str(enrollment.get("user_id")) == str(user_id):
                return enrollment

    return _form_request(
        "POST",
        enrollments_url,
        form={
            "enrollment[user_id]": str(user_id),
            "enrollment[type]": "StudentEnrollment",
            "enrollment[enrollment_state]": "active",
            "notify": "false",
        },
        headers=headers,
    )


def _ensure_canvas_developer_key(
    cfg: CanvasSeedConfig,
    connector_cfg: ConnectorSeedConfig,
    platform_id: str,
) -> dict[str, Any]:
    """Create or update the Canvas LTI 1.3 developer key via Rails runner."""
    payload = {
        "account_id": str(cfg.account_id),
        "admin_email": cfg.admin_email,
        "client_id": connector_cfg.lti_client_id,
        "notes": f"ElevenID LTI Integration - {connector_cfg.lti_client_id}",
        "redirect_uri": _lti_experience_launch_url(connector_cfg, platform_id),
        "scopes": LTI_REQUIRED_SCOPES,
    }
    result = _run_canvas_rails_lti_setup(cfg, payload)
    developer_key = result.get("developer_key") if isinstance(result, dict) else None
    if not isinstance(developer_key, dict) or not developer_key.get("id"):
        raise RuntimeError("Developer key setup did not return a valid key payload")
    return {
        "action": developer_key.get("action", "updated"),
        "key": developer_key,
    }


def _ensure_canvas_public_domain(cfg: CanvasSeedConfig) -> dict[str, Any]:
    """Keep real Canvas browser-generated URLs on the public test hostname."""
    browser_host = urlparse(cfg.browser_base_url).hostname or ""
    if not browser_host:
        return {"action": "skipped", "domain": None, "accounts": []}

    payload = {
        "public_host": browser_host,
    }
    result = _run_canvas_rails_lti_setup(cfg, payload)
    domain = result.get("public_domain") if isinstance(result, dict) else None
    if not isinstance(domain, dict):
        raise RuntimeError("Canvas public domain setup did not return a valid payload")
    return {
        "action": domain.get("action", "updated"),
        "domain": domain.get("host"),
        "accounts": domain.get("accounts") or [],
    }


def _ensure_canvas_external_tool(
    cfg: CanvasSeedConfig,
    connector_cfg: ConnectorSeedConfig,
    platform_id: str,
    course_id: int | str,
    dev_key: dict[str, Any]
) -> dict[str, Any]:
    """Create or update the Canvas external LTI tool via Rails runner."""
    _ = dev_key
    payload = {
        "account_id": str(cfg.account_id),
        "course_id": str(course_id),
        "client_id": connector_cfg.lti_client_id,
        "display_name": connector_cfg.display_name,
        "tool_domain": _lti_tool_domain(connector_cfg.lti_tool_base_url),
        "tool_url": _lti_experience_login_url(connector_cfg, platform_id),
    }
    result = _run_canvas_rails_lti_setup(cfg, payload)
    external_tool = result.get("external_tool") if isinstance(result, dict) else None
    if not isinstance(external_tool, dict) or not external_tool.get("id"):
        raise RuntimeError("External tool setup did not return a valid tool payload")
    return {
        "action": external_tool.get("action", "updated"),
        "tool": external_tool,
    }


def _ensure_canvas_module(cfg: CanvasSeedConfig, course_id: int | str) -> dict[str, Any]:
    headers = _canvas_api_headers(cfg)
    modules_url = f"{cfg.api_base_url.rstrip('/')}/api/v1/courses/{course_id}/modules"
    modules = _json_request("GET", modules_url, headers=headers)
    if isinstance(modules, list):
        for module in modules:
            if isinstance(module, dict) and module.get("name") == cfg.launch_module_name:
                return {"action": "existing", "module": module}

    created = _form_request(
        "POST",
        modules_url,
        form={
            "module[name]": cfg.launch_module_name,
            "module[published]": "true",
        },
        headers=headers,
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError("Canvas module create did not return a module payload")
    return {"action": "created", "module": created}


def _create_canvas_module_item_with_retries(
    cfg: CanvasSeedConfig,
    items_url: str,
    form: dict[str, Any],
) -> dict[str, Any]:
    headers = _canvas_api_headers(cfg)
    attempts: list[dict[str, Any]] = [form]

    without_completion = {
        key: value
        for key, value in form.items()
        if not key.startswith("module_item[completion_requirement]")
    }
    if without_completion != form:
        attempts.append(without_completion)

    without_content_id = {
        key: value
        for key, value in form.items()
        if key != "module_item[content_id]"
    }
    if without_content_id != form:
        attempts.append(without_content_id)

    compact_form = {
        key: value
        for key, value in without_completion.items()
        if key != "module_item[content_id]"
    }
    if compact_form not in attempts:
        attempts.append(compact_form)

    last_error: HTTPError | None = None
    for attempt in attempts:
        try:
            created = _form_request("POST", items_url, form=attempt, headers=headers)
            if not isinstance(created, dict) or not created.get("id"):
                raise RuntimeError("Canvas module item create did not return an item payload")
            return created
        except HTTPError as exc:
            if exc.code not in {400, 422}:
                raise
            last_error = exc

    if last_error is not None:
        raise last_error
    raise RuntimeError("Canvas module item create failed before any request was attempted")


def _ensure_canvas_module_external_tool_item(
    cfg: CanvasSeedConfig,
    course_id: int | str,
    module_id: int | str,
    external_url: str,
    external_tool_id: int | str | None,
) -> dict[str, Any]:
    headers = _canvas_api_headers(cfg)
    items_url = f"{cfg.api_base_url.rstrip('/')}/api/v1/courses/{course_id}/modules/{module_id}/items"
    items = _json_request("GET", items_url, headers=headers)
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("title") == cfg.launch_item_title:
                if item.get("url") != external_url or item.get("published") is False:
                    item_id = item.get("id")
                    if item_id is None:
                        return {"action": "existing", "item": item}
                    form: dict[str, Any] = {
                        "module_item[title]": cfg.launch_item_title,
                        "module_item[external_url]": external_url,
                        "module_item[new_tab]": "false",
                        "module_item[published]": "true",
                    }
                    if external_tool_id is not None:
                        form["module_item[content_id]"] = str(external_tool_id)
                    updated = _form_request(
                        "PUT",
                        f"{items_url}/{item_id}",
                        form=form,
                        headers=headers,
                    )
                    return {"action": "updated", "item": updated}
                return {"action": "existing", "item": item}

    form: dict[str, Any] = {
        "module_item[title]": cfg.launch_item_title,
        "module_item[type]": "ExternalTool",
        "module_item[external_url]": external_url,
        "module_item[new_tab]": "false",
        "module_item[published]": "true",
        "module_item[completion_requirement][type]": "must_view",
    }
    if external_tool_id is not None:
        form["module_item[content_id]"] = str(external_tool_id)

    created = _create_canvas_module_item_with_retries(cfg, items_url, form)
    return {"action": "created", "item": created}


def _ensure_canvas_quiz(cfg: CanvasSeedConfig, course_id: int | str) -> dict[str, Any]:
    headers = _canvas_api_headers(cfg)
    quizzes_url = f"{cfg.api_base_url.rstrip('/')}/api/v1/courses/{course_id}/quizzes"
    search_query = urlencode({"search_term": cfg.quiz_title})
    quizzes = _json_request("GET", f"{quizzes_url}?{search_query}", headers=headers)
    if isinstance(quizzes, list):
        for quiz in quizzes:
            if isinstance(quiz, dict) and quiz.get("title") == cfg.quiz_title:
                return {"action": "existing", "quiz": quiz}

    created = _form_request(
        "POST",
        quizzes_url,
        form={
            "quiz[title]": cfg.quiz_title,
            "quiz[description]": cfg.quiz_description,
            "quiz[quiz_type]": "assignment",
            "quiz[published]": "true",
            "quiz[points_possible]": str(cfg.quiz_points_possible),
            "quiz[allowed_attempts]": "1",
            "quiz[scoring_policy]": "keep_highest",
        },
        headers=headers,
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError("Canvas quiz create did not return a quiz payload")
    return {"action": "created", "quiz": created}


def _ensure_canvas_module_quiz_item(
    cfg: CanvasSeedConfig,
    course_id: int | str,
    module_id: int | str,
    quiz_id: int | str,
) -> dict[str, Any]:
    headers = _canvas_api_headers(cfg)
    items_url = f"{cfg.api_base_url.rstrip('/')}/api/v1/courses/{course_id}/modules/{module_id}/items"
    title = cfg.quiz_title
    items = _json_request("GET", items_url, headers=headers)
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("title") == title:
                return {"action": "existing", "item": item}

    created = _create_canvas_module_item_with_retries(
        cfg,
        items_url,
        {
            "module_item[title]": title,
            "module_item[type]": "Quiz",
            "module_item[content_id]": str(quiz_id),
            "module_item[published]": "true",
            "module_item[completion_requirement][type]": "must_submit",
        },
    )
    return {"action": "created", "item": created}


def _ensure_canvas_external_tool_assignment(
    cfg: CanvasSeedConfig,
    course_id: int | str,
    external_url: str,
) -> dict[str, Any]:
    headers = _canvas_api_headers(cfg)
    assignments_url = f"{cfg.api_base_url.rstrip('/')}/api/v1/courses/{course_id}/assignments"
    search_query = urlencode({"search_term": cfg.launch_assignment_name})
    assignments = _json_request("GET", f"{assignments_url}?{search_query}", headers=headers)
    if isinstance(assignments, list):
        for assignment in assignments:
            if isinstance(assignment, dict) and assignment.get("name") == cfg.launch_assignment_name:
                assignment_id = assignment.get("id")
                if assignment_id is None:
                    return {"action": "existing", "assignment": assignment}
                updated = _form_request(
                    "PUT",
                    f"{assignments_url}/{assignment_id}",
                    form={
                        "assignment[name]": cfg.launch_assignment_name,
                        "assignment[published]": "true",
                        "assignment[points_possible]": "100",
                        "assignment[grading_type]": "points",
                        "assignment[submission_types][]": ["external_tool"],
                        "assignment[external_tool_tag_attributes][url]": external_url,
                        "assignment[external_tool_tag_attributes][new_tab]": "false",
                    },
                    headers=headers,
                )
                return {"action": "updated", "assignment": updated}

    created = _form_request(
        "POST",
        assignments_url,
        form={
            "assignment[name]": cfg.launch_assignment_name,
            "assignment[published]": "true",
            "assignment[points_possible]": "100",
            "assignment[grading_type]": "points",
            "assignment[submission_types][]": ["external_tool"],
            "assignment[external_tool_tag_attributes][url]": external_url,
            "assignment[external_tool_tag_attributes][new_tab]": "false",
        },
        headers=headers,
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError("Canvas assignment create did not return an assignment payload")
    return {"action": "created", "assignment": created}


def _run_canvas_rails_lti_setup(cfg: CanvasSeedConfig, payload: dict[str, Any]) -> dict[str, Any]:
    payload_b64 = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")
    resolved_container_name = _resolve_canvas_container_name(cfg.container_name)
    ruby_script = f"""
require \"base64\"
require \"json\"

payload = JSON.parse(Base64.decode64(ENV.fetch(\"CANVAS_LTI_SETUP_B64\")))

if payload[\"public_host\"]
  public_host = payload.fetch(\"public_host\").to_s.strip
  updated_accounts = []
  if public_host.present?
    Account.all.find_each do |account|
      next unless account.respond_to?(:add_domain!)

      begin
        before_count = account.csp_domains.where(domain: public_host, workflow_state: \"active\").count if account.respond_to?(:csp_domains)
        account.add_domain!(public_host)
        after_count = account.csp_domains.where(domain: public_host, workflow_state: \"active\").count if account.respond_to?(:csp_domains)
        updated_accounts << account.id if before_count != after_count
      rescue ActiveRecord::RecordNotUnique
        # Idempotent when another seed pass already inserted the domain.
      end
    end
  end

  puts {CANVAS_RAILS_RESULT_PREFIX!r} + JSON.generate({{
    public_domain: {{
      action: updated_accounts.empty? ? \"unchanged\" : \"updated\",
      host: public_host,
      default_host: HostUrl.default_host,
      accounts: Account.all.map {{ |account| {{ id: account.id, name: account.name, domain: account.domain }} }},
    }},
  }})
  exit
end

account = Account.find(payload.fetch(\"account_id\"))
client_id = payload.fetch(\"client_id\")

developer_key = DeveloperKey.find_or_initialize_by(name: client_id)
developer_key_action = developer_key.new_record? ? \"created\" : \"updated\"
developer_key.email = payload[\"admin_email\"] if payload[\"admin_email\"]
developer_key.scopes = payload.fetch(\"scopes\", developer_key.scopes || [])
developer_key.redirect_uris = [payload.fetch(\"redirect_uri\", developer_key.redirect_uris&.first)].compact
developer_key.notes = payload[\"notes\"] if payload[\"notes\"]
developer_key.is_lti_key = true if developer_key.respond_to?(:is_lti_key=)
if developer_key.respond_to?(:generate_rsa_keypair!) && developer_key.public_jwk.blank? && developer_key.public_jwk_url.blank?
  developer_key.generate_rsa_keypair!(overwrite: true)
end
developer_key.visible = true if developer_key.respond_to?(:visible=)
developer_key.require_scopes = true if developer_key.respond_to?(:require_scopes=)
developer_key.workflow_state = \"active\" if developer_key.respond_to?(:workflow_state=)
developer_key.save!

owner_binding = developer_key.owner_account.developer_key_account_bindings.where(developer_key: developer_key).first_or_initialize
owner_binding.workflow_state = "on" if owner_binding.respond_to?(:workflow_state=)
owner_binding.save! if owner_binding.new_record? || owner_binding.changed?

binding = developer_key.developer_key_account_bindings.where(account_id: account.id).first_or_initialize
binding.workflow_state = "on" if binding.respond_to?(:workflow_state=)
binding.save! if binding.new_record? || binding.changed?

result = {{
  developer_key: {{
    id: developer_key.id,
    action: developer_key_action,
        global_id: developer_key.global_id,
    name: developer_key.name,
    email: developer_key.email,
    redirect_uris: developer_key.redirect_uris,
    workflow_state: developer_key.workflow_state,
    visible: developer_key.visible,
    scopes: developer_key.scopes,
    notes: developer_key.notes,
        owner_binding_account_id: owner_binding.account_id,
        owner_binding_workflow_state: owner_binding.workflow_state,
        requested_binding_account_id: binding.account_id,
        requested_binding_workflow_state: binding.workflow_state,
  }},
}}

if payload[\"course_id\"]
  course = Course.find(payload.fetch(\"course_id\"))
  external_tool = ContextExternalTool.where(context: course).find_by(name: payload.fetch(\"display_name\"))
  external_tool ||= ContextExternalTool.where(context: course).find_by(consumer_key: client_id)
  external_tool ||= ContextExternalTool.new(context: course, name: payload.fetch(\"display_name\"))

  external_tool_action = external_tool.new_record? ? \"created\" : \"updated\"
  external_tool.name = payload.fetch(\"display_name\")
  external_tool.url = payload.fetch(\"tool_url\")
  external_tool.domain = payload.fetch(\"tool_domain\")
  external_tool.consumer_key = client_id
  external_tool.shared_secret = \"not-used-in-lti-1-3\"
  external_tool.workflow_state = \"public\" if external_tool.respond_to?(:workflow_state=)
  external_tool.privacy_level = \"public\" if external_tool.respond_to?(:privacy_level=)
  external_tool.developer_key = developer_key if external_tool.respond_to?(:developer_key=)
  external_tool.lti_version = \"1.3\" if external_tool.respond_to?(:lti_version=)
  external_tool.settings = (external_tool.settings || {{}}).merge({{
    \"platform\" => \"canvas\",
    \"privacy_level\" => \"public\",
    \"icon_url\" => nil,
    \"text\" => \"ElevenID Credential Issuance\",
  }})
  external_tool.save!

  result[:external_tool] = {{
    id: external_tool.id,
    action: external_tool_action,
    name: external_tool.name,
    url: external_tool.url,
    domain: external_tool.domain,
    consumer_key: external_tool.consumer_key,
        deployment_id: external_tool.respond_to?(:deployment_id) ? external_tool.deployment_id : nil,
    workflow_state: external_tool.workflow_state,
    developer_key_id: external_tool.developer_key_id,
    lti_version: external_tool.lti_version,
    settings: external_tool.settings,
  }}
end

puts {CANVAS_RAILS_RESULT_PREFIX!r} + JSON.generate(result)
"""

    command = [
        "docker",
        "exec",
        "-i",
        "-e",
        f"CANVAS_LTI_SETUP_B64={payload_b64}",
        resolved_container_name,
        "bash",
        "-lc",
        "cat >/tmp/ensure_canvas_lti_setup.rb; cd /usr/src/app; bin/rails runner -e production /tmp/ensure_canvas_lti_setup.rb",
    ]

    try:
        completed = subprocess.run(
            command,
            input=ruby_script,
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Docker CLI is not available; cannot run Canvas Rails setup fallback") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Canvas Rails setup timed out") from exc

    combined_output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if completed.returncode != 0:
        raise RuntimeError(
            f"Canvas Rails setup failed (exit {completed.returncode}): {combined_output or 'no output'}"
        )

    for line in reversed((completed.stdout or "").splitlines()):
        if line.startswith(CANVAS_RAILS_RESULT_PREFIX):
            payload_text = line[len(CANVAS_RAILS_RESULT_PREFIX):]
            return json.loads(payload_text)

    raise RuntimeError(
        "Canvas Rails setup completed but did not emit a parseable result. "
        f"Output: {combined_output or 'no output'}"
    )


def _maybe_seed_canvas(
    cfg: CanvasSeedConfig,
    connector_cfg: ConnectorSeedConfig,
    platform_id: str,
) -> dict[str, Any] | None:
    if not cfg.enabled:
        return None

    if not _wait_for_http(cfg.api_base_url, path="/", retries=90, delay=2.0):
        raise RuntimeError(f"Canvas did not become reachable at {cfg.api_base_url}")

    _ensure_canvas_initial_data(cfg)
    if not cfg.admin_token:
        cfg.admin_token = _mint_canvas_admin_token(cfg)

    try:
        return _seed_canvas_lms_objects(cfg, connector_cfg, platform_id)
    except HTTPError as exc:
        if exc.code not in {401, 403}:
            raise
        cfg.admin_token = _mint_canvas_admin_token(cfg)
        return _seed_canvas_lms_objects(cfg, connector_cfg, platform_id)


def _seed_canvas_lms_objects(
    cfg: CanvasSeedConfig,
    connector_cfg: ConnectorSeedConfig,
    platform_id: str,
) -> dict[str, Any]:
    public_domain = _ensure_canvas_public_domain(cfg)

    # Create course and learner
    course = _ensure_canvas_course(cfg)
    user = _ensure_canvas_user(cfg)
    enrollment = _ensure_canvas_enrollment(cfg, course_id=course["id"], user_id=user["id"])

    # Create Canvas LTI developer key
    dev_key = _ensure_canvas_developer_key(cfg, connector_cfg, platform_id)
    
    # Create external tool in course
    external_tool = _ensure_canvas_external_tool(
        cfg,
        connector_cfg,
        platform_id,
        course_id=course["id"],
        dev_key=dev_key["key"],
    )

    launch_surface: dict[str, Any] = {}
    quiz_surface: dict[str, Any] = {}
    if cfg.launch_seed_enabled:
        launch_url = _lti_experience_login_url(connector_cfg, platform_id)
        launch_module = _ensure_canvas_module(cfg, course_id=course["id"])
        module_item = _ensure_canvas_module_external_tool_item(
            cfg,
            course_id=course["id"],
            module_id=launch_module["module"]["id"],
            external_url=launch_url,
            external_tool_id=external_tool["tool"].get("id"),
        )
        launch_surface = {
            "module": {
                "id": launch_module["module"].get("id"),
                "name": launch_module["module"].get("name"),
                "action": launch_module["action"],
            },
            "module_item": {
                "id": module_item["item"].get("id"),
                "title": module_item["item"].get("title"),
                "html_url": module_item["item"].get("html_url"),
                "action": module_item["action"],
            },
        }
        try:
            assignment = _ensure_canvas_external_tool_assignment(
                cfg,
                course_id=course["id"],
                external_url=launch_url,
            )
            launch_surface["assignment"] = {
                "id": assignment["assignment"].get("id"),
                "name": assignment["assignment"].get("name"),
                "html_url": assignment["assignment"].get("html_url"),
                "action": assignment["action"],
            }
        except HTTPError as exc:
            launch_surface["assignment_error"] = f"Canvas assignment seed failed ({exc.code})"
        except Exception as exc:
            launch_surface["assignment_error"] = f"Canvas assignment seed failed: {exc}"

        if cfg.quiz_seed_enabled:
            try:
                quiz = _ensure_canvas_quiz(cfg, course_id=course["id"])
                quiz_item = _ensure_canvas_module_quiz_item(
                    cfg,
                    course_id=course["id"],
                    module_id=launch_module["module"]["id"],
                    quiz_id=quiz["quiz"]["id"],
                )
                quiz_surface = {
                    "id": quiz["quiz"].get("id"),
                    "title": quiz["quiz"].get("title"),
                    "html_url": quiz["quiz"].get("html_url"),
                    "action": quiz["action"],
                    "module_item": {
                        "id": quiz_item["item"].get("id"),
                        "title": quiz_item["item"].get("title"),
                        "html_url": quiz_item["item"].get("html_url"),
                        "action": quiz_item["action"],
                    },
                }
            except HTTPError as exc:
                quiz_surface = {"error": f"Canvas quiz seed failed ({exc.code})"}
            except Exception as exc:
                quiz_surface = {"error": f"Canvas quiz seed failed: {exc}"}

    result = {
        "public_domain": public_domain,
        "developer_key": {
            "id": dev_key["key"].get("id"),
            "name": dev_key["key"].get("name"),
            "client_id": str(dev_key["key"].get("global_id") or dev_key["key"].get("name") or ""),
            "action": dev_key["action"],
            "owner_binding_account_id": dev_key["key"].get("owner_binding_account_id"),
            "owner_binding_workflow_state": dev_key["key"].get("owner_binding_workflow_state"),
            "requested_binding_account_id": dev_key["key"].get("requested_binding_account_id"),
            "requested_binding_workflow_state": dev_key["key"].get("requested_binding_workflow_state"),
        },
        "course": {
            "id": course.get("id"),
            "name": course.get("name"),
            "course_code": course.get("course_code"),
            "sis_course_id": course.get("sis_course_id"),
        },
        "learner": {
            "id": user.get("id"),
            "name": user.get("name"),
            "login_id": user.get("login_id"),
        },
        "enrollment": enrollment,
        "external_tool": {
            "id": external_tool["tool"].get("id"),
            "name": external_tool["tool"].get("name"),
            "deployment_id": external_tool["tool"].get("deployment_id"),
            "action": external_tool["action"],
        },
    }
    if launch_surface:
        result["launch_surface"] = launch_surface
    if quiz_surface:
        result["quiz"] = quiz_surface
    return result


def _create_canvas_demo_application(
    connector_cfg: ConnectorSeedConfig,
    canvas_cfg: CanvasSeedConfig,
    *,
    canvas_seed: dict[str, Any] | None,
) -> dict[str, Any]:
    course = (canvas_seed or {}).get("course") or {}
    quiz = (canvas_seed or {}).get("quiz") or {}
    score_percent = max(
        connector_cfg.program_binding_score_threshold,
        canvas_cfg.quiz_passing_score_percent,
    )
    course_name = course.get("name") or canvas_cfg.course_name
    quiz_name = quiz.get("title") or canvas_cfg.quiz_title
    achievement = _canvas_open_badge_achievement(score_threshold=connector_cfg.program_binding_score_threshold)
    result = {
        "type": ["Result"],
        "source": "Canvas AGS score",
        "score": score_percent,
        "maximumScore": canvas_cfg.quiz_points_possible,
        "passingScore": connector_cfg.program_binding_score_threshold,
        "resultDescription": f"Completed {quiz_name} with a score of {score_percent}%.",
    }
    learning_context = {
        "provider": "canvas",
        "course": {
            "id": str(course.get("id") or ""),
            "name": course_name,
        },
        "activity": {
            "id": str(quiz.get("id") or ""),
            "type": "quiz",
            "name": quiz_name,
        },
        "canvas_account_id": connector_cfg.canvas_account_id,
    }
    applicant_data = {
        "_credential_type": "OpenBadgeCredential",
        "_vct": CANVAS_INTEROPERABILITY_BADGE_VCT,
        "email": canvas_cfg.learner_email,
        "given_name": canvas_cfg.learner_name.split(" ", 1)[0] if canvas_cfg.learner_name else "ElevenID",
        "family_name": canvas_cfg.learner_name.split(" ", 1)[1] if " " in canvas_cfg.learner_name else "Learner",
        "achievement_id": achievement["id"],
        "achievement_name": CANVAS_INTEROPERABILITY_BADGE_NAME,
        "achievement_description": CANVAS_INTEROPERABILITY_BADGE_DESCRIPTION,
        "achievement_criteria": achievement["criteria"]["narrative"],
        "badge_image_url": CANVAS_INTEROPERABILITY_BADGE_IMAGE_URL,
        "course_name": course_name,
        "quiz_name": quiz_name,
        "score_percent": score_percent,
        "completion_date": date.today().isoformat(),
        "institution_name": "Marty Organization",
        "certificate_id": f"interoperable-credentials-foundations-{date.today().isoformat()}",
        "organization_id": connector_cfg.organization_id,
        "achievement": achievement,
        "result": result,
        "learning_context": learning_context,
    }
    integration_context = {
        "scenario": "canvas_mip_quiz_open_badge",
        "credential_type": "OpenBadgeCredential",
        "credential_vct": CANVAS_INTEROPERABILITY_BADGE_VCT,
        "delivery_mode": connector_cfg.program_binding_delivery_mode,
        "delivery": {"mode": connector_cfg.program_binding_delivery_mode},
        "open_badge": {
            "vct": CANVAS_INTEROPERABILITY_BADGE_VCT,
            "name": CANVAS_INTEROPERABILITY_BADGE_NAME,
            "image": CANVAS_INTEROPERABILITY_BADGE_IMAGE_URL,
            "criteria": CANVAS_INTEROPERABILITY_BADGE_CRITERIA_URL,
        },
        "canvas": {
            "canvas_account_id": connector_cfg.canvas_account_id,
            "canvas_course_id": str(course.get("id") or ""),
            "canvas_quiz_id": str(quiz.get("id") or ""),
            "learner_email": canvas_cfg.learner_email,
        },
        "issuer": {
            "mode": "org_managed",
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
            "signing_service_id": "managed-openbao-transit",
            "signing_key_reference": "cred-issuer-marty-es256",
        },
    }
    payload = {
        "application_template_id": connector_cfg.application_template_id,
        "applicant_data": applicant_data,
        "integration_context": integration_context,
    }
    result = _json_request(
        "POST",
        f"{connector_cfg.issuance_base_url.rstrip('/')}/internal/applications",
        payload=payload,
        headers=_connector_headers(connector_cfg.issuance_api_key),
    )
    if not isinstance(result, dict) or not result.get("id"):
        raise RuntimeError("Demo application create did not return an application payload")
    return result


def _emit_canvas_demo_ags_score_event(
    connector_cfg: ConnectorSeedConfig,
    canvas_cfg: CanvasSeedConfig,
    *,
    canvas_seed: dict[str, Any] | None,
    application: dict[str, Any],
) -> dict[str, Any] | None:
    secret = (
        os.environ.get("CANVAS_CREDENTIALS_SHARED_SECRET", "").strip()
        or _docker_container_env_value("marty-issuance", "CANVAS_CREDENTIALS_SHARED_SECRET").strip()
    )
    if not secret:
        print("WARN: CANVAS_CREDENTIALS_SHARED_SECRET is not set; demo AGS event was not submitted.")
        return None

    course = (canvas_seed or {}).get("course") or {}
    learner = (canvas_seed or {}).get("learner") or {}
    enrollment = (canvas_seed or {}).get("enrollment") or {}
    quiz = (canvas_seed or {}).get("quiz") or {}
    score_percent = max(
        connector_cfg.program_binding_score_threshold,
        canvas_cfg.quiz_passing_score_percent,
    )
    payload = {
        "canvas_event_id": f"canvas-demo-ags-{application['id']}-{uuid.uuid4().hex[:8]}",
        "application_id": application["id"],
        "organization_id": connector_cfg.organization_id,
        "credential_template_id": connector_cfg.credential_template_id,
        "canvas_account_id": connector_cfg.canvas_account_id,
        "canvas_course_id": str(course.get("id") or ""),
        "canvas_course_name": course.get("name") or canvas_cfg.course_name,
        "canvas_user_id": str(learner.get("id") or ""),
        "canvas_enrollment_id": str((enrollment or {}).get("id") or ""),
        "learner_email": canvas_cfg.learner_email,
        "learner_name": canvas_cfg.learner_name,
        "evidence_type": connector_cfg.program_binding_evidence_type,
        "canvas_quiz_id": str(quiz.get("id") or ""),
        "line_item_label": quiz.get("title") or canvas_cfg.quiz_title,
        "activity_progress": "Completed",
        "grading_progress": "FullyGraded",
        "submitted": True,
        "completed": True,
        "passed": True,
        "score_given": score_percent,
        "score_maximum": 100,
        "score_percent": score_percent,
        "graded_at": date.today().isoformat(),
    }
    result = _signed_json_request(
        "POST",
        f"{connector_cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/ags/score-events",
        payload=payload,
        secret=secret,
    )
    return result if isinstance(result, dict) else None


def _extract_pre_authorized_code(credential_offer: dict[str, Any]) -> str:
    grants = credential_offer.get("grants") if isinstance(credential_offer, dict) else {}
    grant = (
        grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
        if isinstance(grants, dict)
        else None
    )
    if isinstance(grant, dict):
        for key in ("pre-authorized_code", "pre_authorized_code"):
            value = grant.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    for key in ("pre-authorized_code", "pre_authorized_code"):
        value = credential_offer.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise RuntimeError("Credential offer did not include a pre-authorized code")


def _credential_issuer_audience(connector_cfg: ConnectorSeedConfig) -> str:
    public_base = os.environ.get("PUBLIC_API_URL", "").strip() or connector_cfg.issuance_base_url
    return f"{public_base.rstrip('/')}/org/{connector_cfg.organization_id}"


def _claim_canvas_demo_wallet_credential(
    connector_cfg: ConnectorSeedConfig,
    *,
    transaction_id: str,
) -> dict[str, Any]:
    """Exercise the real OID4VCI pre-authorized flow as a demo wallet."""

    offer = _json_request(
        "GET",
        f"{connector_cfg.issuance_base_url.rstrip('/')}/v1/issuance/offers/{transaction_id}",
    )
    if not isinstance(offer, dict):
        raise RuntimeError("Credential offer endpoint did not return an object")

    token_response = _form_request(
        "POST",
        f"{connector_cfg.issuance_base_url.rstrip('/')}/v1/issuance/token",
        form={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": _extract_pre_authorized_code(offer),
        },
    )
    if not isinstance(token_response, dict) or not token_response.get("access_token"):
        raise RuntimeError("Token endpoint did not return an access token")

    try:
        import marty_rs  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("marty_rs is required to generate the OID4VCI wallet proof JWT") from exc

    nonce = str(token_response.get("c_nonce") or token_response.get("nonce") or "")
    if not nonce:
        raise RuntimeError("Token endpoint did not return a c_nonce")
    proof_jwt = marty_rs.oid4vci_create_proof_jwt(_credential_issuer_audience(connector_cfg), nonce)

    credential_response = _json_request(
        "POST",
        f"{connector_cfg.issuance_base_url.rstrip('/')}/v1/issuance/credential",
        payload={
            "format": "vc+sd-jwt",
            "credential_configuration_id": "OpenBadgeCredential#sd-jwt",
            "proofs": {"jwt": [proof_jwt]},
        },
        headers={"Authorization": f"Bearer {token_response['access_token']}"},
        timeout=60,
    )
    if not isinstance(credential_response, dict):
        raise RuntimeError("Credential endpoint did not return an object")
    compact = credential_response.get("credential")
    if not isinstance(compact, str) or not compact.strip():
        credentials = credential_response.get("credentials")
        if isinstance(credentials, list) and credentials:
            first = credentials[0]
            if isinstance(first, dict):
                compact = first.get("credential")
            elif isinstance(first, str):
                compact = first
    if not isinstance(compact, str) or not compact.strip():
        raise RuntimeError("Credential endpoint did not return a credential")

    return {
        "transaction_id": transaction_id,
        "credential_format": "vc+sd-jwt",
        "credential_size": len(compact),
        "credential_hash": hashlib.sha256(compact.encode("utf-8")).hexdigest(),
        "notification_id": credential_response.get("notification_id"),
    }


def _run_canvas_demo_mirror_publish(connector_cfg: ConnectorSeedConfig) -> dict[str, Any]:
    query = urlencode(
        {
            "organization_id": connector_cfg.organization_id,
            "limit": "25",
            "retry_failed": "true",
        }
    )
    response = _json_request(
        "POST",
        f"{connector_cfg.issuance_base_url.rstrip('/')}/v1/issuance/delivery-records/"
        f"canvas-credentials/run-automation-cycle?{query}",
        payload={},
        headers=_connector_headers(connector_cfg.issuance_api_key),
        timeout=60,
    )
    if not isinstance(response, dict):
        raise RuntimeError("Canvas mirror automation endpoint did not return an object")
    return response


def _resolve_issuer_context_summary(connector_cfg: ConnectorSeedConfig) -> dict[str, Any] | None:
    if not connector_cfg.signing_keys_internal_api_key:
        return None
    query = urlencode(
        {
            "organization_id": connector_cfg.organization_id,
            "credential_format": "sd_jwt_vc",
            "key_purpose": "vc_jwt_issuer",
        }
    )
    try:
        response = _json_request(
            "GET",
            f"{connector_cfg.signing_keys_internal_base_url.rstrip('/')}/issuer-context?{query}",
            headers={"X-API-Key": connector_cfg.signing_keys_internal_api_key},
        )
    except Exception:
        return None
    if not isinstance(response, dict):
        return None
    return {
        "issuer_profile_id": response.get("issuer_profile_id"),
        "issuer_did": response.get("issuer_did"),
        "signing_service_id": response.get("signing_service_id"),
        "signing_key_reference": response.get("signing_key_reference"),
        "verification_method_id": response.get("verification_method_id"),
    }


async def _lookup_canvas_demo_transition_async(application_id: str) -> dict[str, Any] | None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(_resolve_database_url(), future=True)
    try:
        async with engine.begin() as conn:
            row = (
                await conn.execute(
                    text(
                        """
                        SELECT
                            a.id AS application_id,
                            a.status AS application_status,
                            a.issuance_transaction_id,
                            t.credential_type,
                            t.credential_template_id,
                            t.status AS transaction_status,
                            t.issuer_profile_id,
                            t.issuer_mode,
                            t.issuer_did_override,
                            t.signing_service_id,
                            t.delivery_mode,
                            t.credential_payload_format,
                            t.pre_auth_code IS NOT NULL AS has_pre_auth_code
                        FROM issuance_service.applications a
                        LEFT JOIN issuance_service.issuance_transactions t
                          ON t.id = a.issuance_transaction_id
                        WHERE a.id = :application_id
                        """
                    ),
                    {"application_id": application_id},
                )
            ).mappings().first()
            if row is None:
                return None

            latest_fact = (
                await conn.execute(
                    text(
                        """
                        SELECT
                            provider,
                            fact_type,
                            scope,
                            assertion,
                            verification,
                            created_at
                        FROM issuance_service.evidence_facts
                        WHERE application_id = :application_id
                        ORDER BY created_at DESC
                        LIMIT 1
                        """
                    ),
                    {"application_id": application_id},
                )
            ).mappings().first()
            delivery_count = 0
            issued_credential = None
            delivery_records: list[dict[str, Any]] = []
            if row.get("issuance_transaction_id"):
                issued_credential = (
                    await conn.execute(
                        text(
                            """
                            SELECT
                                id,
                                subject_did,
                                issuer_did,
                                revocation_profile_id,
                                status_list_entries,
                                status,
                                issued_at,
                                expires_at
                            FROM issuance_service.issued_credentials
                            WHERE transaction_id = :transaction_id
                            ORDER BY issued_at DESC
                            LIMIT 1
                            """
                        ),
                        {"transaction_id": row["issuance_transaction_id"]},
                    )
                ).mappings().first()
                delivery_rows = (
                    await conn.execute(
                        text(
                            """
                            SELECT
                                id,
                                delivery_target,
                                delivery_mode,
                                status,
                                external_credential_id,
                                external_issuer_id,
                                last_error,
                                metadata,
                                updated_at
                            FROM issuance_service.credential_delivery_records
                            WHERE transaction_id = :transaction_id
                            ORDER BY created_at ASC
                            """
                        ),
                        {"transaction_id": row["issuance_transaction_id"]},
                    )
                ).mappings().all()
                delivery_records = [dict(item) for item in delivery_rows]
                delivery_count = int(
                    await conn.scalar(
                        text(
                            """
                            SELECT COUNT(*)
                            FROM issuance_service.credential_delivery_records
                            WHERE transaction_id = :transaction_id
                              AND delivery_target = 'canvas_credentials'
                            """
                        ),
                        {"transaction_id": row["issuance_transaction_id"]},
                    )
                    or 0
                )

            return {
                "application": dict(row),
                "latest_fact": dict(latest_fact) if latest_fact else None,
                "issued_credential": dict(issued_credential) if issued_credential else None,
                "delivery_records": delivery_records,
                "canvas_mirror_delivery_records": delivery_count,
            }
    finally:
        await engine.dispose()


def _lookup_canvas_demo_transition(application_id: str) -> dict[str, Any] | None:
    return asyncio.run(_lookup_canvas_demo_transition_async(application_id))


def _canvas_credentials_demo_base_url() -> str:
    configured = os.environ.get("CANVAS_CREDENTIALS_PUBLIC_BASE_URL", "").strip()
    if configured:
        return configured.rstrip("/")

    public_host = os.environ.get("CANVAS_SANDBOX_PUBLIC_HOST", "").strip()
    if public_host:
        scheme = os.environ.get("CANVAS_SANDBOX_SCHEME", "https").strip() or "https"
        return f"{scheme}://{public_host}".rstrip("/")

    host = os.environ.get("CANVAS_SANDBOX_HOST", "").strip()
    scheme = os.environ.get("CANVAS_SANDBOX_SCHEME", "https").strip() or "https"
    port = os.environ.get("CANVAS_SANDBOX_PORT", "8017").strip() or "8017"
    if host:
        if ":" in host:
            return f"{scheme}://{host}".rstrip("/")
        if host not in {"localhost", "127.0.0.1", "canvas-sandbox"}:
            return f"{scheme}://{host}".rstrip("/")
        return f"{scheme}://{host}:{port}".rstrip("/")

    host_port = os.environ.get("CANVAS_SANDBOX_HOST_PORT", "8017").strip() or "8017"
    return f"http://localhost:{host_port}"


def _canvas_credentials_display_url(external_credential_id: str) -> str:
    return f"{_canvas_credentials_demo_base_url()}/credentials/{quote(external_credential_id)}"


def _console_provenance_demo_url(connector_cfg: ConnectorSeedConfig, external_credential_id: str) -> str:
    public_base = os.environ.get("PUBLIC_API_URL", "").strip() or connector_cfg.issuance_base_url
    query = urlencode(
        {
            "external_credential_id": external_credential_id,
            "canvas_account_id": connector_cfg.canvas_account_id,
            "organization_id": connector_cfg.organization_id,
        }
    )
    return f"{public_base.rstrip('/')}/console/org/operate/verify?{query}"


def _print_canvas_demo_transition_summary(
    connector_cfg: ConnectorSeedConfig,
    application_id: str,
) -> None:
    summary = _lookup_canvas_demo_transition(application_id)
    if not summary:
        print("WARN: Demo transition verification could not find the application.")
        return

    app = summary.get("application") or {}
    fact = summary.get("latest_fact") or {}
    assertion = fact.get("assertion") if isinstance(fact.get("assertion"), dict) else {}
    verification = fact.get("verification") if isinstance(fact.get("verification"), dict) else {}
    delivery_records = summary.get("delivery_records") or []
    canvas_mirror_metadata: dict[str, Any] = {}
    for delivery in delivery_records:
        if isinstance(delivery, dict) and delivery.get("delivery_target") == "canvas_credentials":
            metadata = delivery.get("metadata")
            canvas_mirror_metadata = metadata if isinstance(metadata, dict) else {}
            break
    tx_id = app.get("issuance_transaction_id")
    print("  OK MIP transition verified")
    print(f"    evidence_provider:   {fact.get('provider')}")
    print(f"    evidence_fact_type:  {fact.get('fact_type')}")
    print(f"    evidence_status:     {verification.get('status')} via {verification.get('method')}")
    print(f"    score_percent:       {assertion.get('score_percent')}")
    print(f"    application_status:  {app.get('application_status')}")
    print(f"    transaction_id:      {tx_id}")
    print(f"    transaction_status:  {app.get('transaction_status')}")
    print(f"    credential_type:     {app.get('credential_type')}")
    print(f"    issuer_profile_id:   {app.get('issuer_profile_id')}")
    print(f"    issuer_did:          {app.get('issuer_did_override')}")
    print(f"    signing_service_id:  {app.get('signing_service_id')}")
    print(f"    delivery_mode:       {app.get('delivery_mode')}")
    print(f"    canvas_platform_id:  {canvas_mirror_metadata.get('canvas_platform_id')}")
    print(f"    canvas_binding_id:   {canvas_mirror_metadata.get('canvas_program_binding_id')}")
    print(f"    mirror_records:      {summary.get('canvas_mirror_delivery_records')}")
    issued = summary.get("issued_credential") or {}
    if issued:
        print(f"    issued_credential:   {issued.get('id')}")
        print(f"    credential_status:   {issued.get('status')}")
        print(f"    revocation_profile:  {issued.get('revocation_profile_id')}")
        status_entries = issued.get("status_list_entries") if isinstance(issued, dict) else None
        if isinstance(status_entries, list) and status_entries:
            first_entry = status_entries[0] if isinstance(status_entries[0], dict) else {}
            print(f"    status_list_index:   {first_entry.get('index')}")
            print(f"    status_list_uri:     {first_entry.get('status_list_uri')}")
        print(f"    subject_did:         {issued.get('subject_did')}")
    for record in delivery_records:
        if not isinstance(record, dict):
            continue
        target = record.get("delivery_target")
        print(
            "    delivery_record:    "
            f"{target} status={record.get('status')} external={record.get('external_credential_id')}"
        )
        if target == "canvas_credentials" and record.get("external_credential_id"):
            metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
            publish_response = (
                metadata.get("publish_response")
                if isinstance(metadata.get("publish_response"), dict)
                else {}
            )
            external_id = str(record.get("external_credential_id"))
            provider = str(metadata.get("provider") or publish_response.get("provider") or "").strip().lower()
            real_provider = provider in {"badgr_api", "canvas_credentials_api"}
            canvas_url = (
                metadata.get("credential_url")
                or metadata.get("open_badge_id")
                or publish_response.get("credential_url")
                or publish_response.get("openBadgeId")
            )
            if not canvas_url and not real_provider:
                canvas_url = _canvas_credentials_display_url(external_id)
            console_provenance_url = (
                metadata.get("console_provenance_url")
                or publish_response.get("console_provenance_url")
                or _console_provenance_demo_url(connector_cfg, external_id)
            )
            if canvas_url:
                print(f"      canvas_display:   {canvas_url}")
            else:
                print("      canvas_display:   not returned by Canvas Credentials provider")
            print(f"      console_provenance: {console_provenance_url}")
        if record.get("last_error"):
            print(f"      last_error:        {record.get('last_error')}")
    if tx_id:
        public_base = os.environ.get("PUBLIC_API_URL", "").strip() or connector_cfg.issuance_base_url
        print(f"    offer_endpoint:      {public_base.rstrip('/')}/v1/issuance/offers/{tx_id}")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Seed real Canvas LMS + ElevenID Canvas platform")
    parser.add_argument(
        "--env-file",
        default=".env.tunnel.beta.local",
        help="Env file to load before reading process environment (default: .env.tunnel.beta.local)",
    )
    parser.add_argument(
        "--skip-canvas-lms-seed",
        action="store_true",
        help="Skip Canvas API seeding (course/user/enrollment)",
    )
    parser.add_argument(
        "--probe-after-upsert",
        action="store_true",
        help="Call Canvas platform sandbox-probe after create/update",
    )
    return parser


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()

    _load_dotenv(Path(args.env_file))
    raw_issuance_api_key = os.environ.get("ISSUANCE_API_KEY", "").strip()
    raw_canvas_api_base_url = os.environ.get("CANVAS_API_BASE_URL", "http://localhost:8088").strip()
    raw_canvas_connector_base_url = os.environ.get("CANVAS_CONNECTOR_BASE_URL", "").strip()
    raw_lti_tool_base_url = (
        os.environ.get("CANVAS_LTI_EXPERIENCE_BASE_URL", "").strip()
        or os.environ.get("CANVAS_LTI_TOOL_BASE_URL", "").strip()
    )
    raw_canvas_browser_base_url = os.environ.get("CANVAS_BROWSER_BASE_URL", "").strip()
    raw_canvas_public_host = os.environ.get("CANVAS_REAL_PUBLIC_HOST", "").strip()
    inferred_canvas_base_url = raw_canvas_api_base_url.rstrip("/")
    inferred_lti_tool_base_url = os.environ.get("PUBLIC_API_URL", "").strip() or "http://localhost:8000"
    inferred_canvas_connector_base_url = (
        f"https://{raw_canvas_public_host}" if raw_canvas_public_host else inferred_canvas_base_url
    ).rstrip("/")
    inferred_canvas_browser_base_url = (
        raw_canvas_browser_base_url
        or (f"https://{raw_canvas_public_host}" if raw_canvas_public_host else raw_canvas_api_base_url)
    ).rstrip("/")
    open_badge_scenario_enabled = _bool_env("CANVAS_OPEN_BADGE_SCENARIO_ENABLED", True)
    default_credential_template_id = (
        MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID
        if open_badge_scenario_enabled
        else MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID
    )
    default_application_template_id = (
        MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID
        if open_badge_scenario_enabled
        else MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID
    )
    default_program_evidence_type = "canvas.quiz_score" if open_badge_scenario_enabled else "canvas.course_completion"
    default_program_delivery_mode = "wallet_plus_canvas_mirror" if open_badge_scenario_enabled else "wallet_only"

    connector_cfg = ConnectorSeedConfig(
        issuance_base_url=os.environ.get("ISSUANCE_API_BASE_URL", "http://localhost:8005"),
        issuance_api_key=raw_issuance_api_key or "dev-issuance-api-key",
        organization_id=os.environ.get("CANVAS_ORGANIZATION_ID", MARTY_DEFAULT_ORG_ID),
        canvas_account_id=os.environ.get("CANVAS_ACCOUNT_ID", "canvas-real-account-1"),
        credential_template_id=os.environ.get(
            "CANVAS_CREDENTIAL_TEMPLATE_ID",
            default_credential_template_id,
        ),
        application_template_id=os.environ.get(
            "CANVAS_APPLICATION_TEMPLATE_ID",
            default_application_template_id,
        ),
        display_name=os.environ.get("CANVAS_CONNECTOR_DISPLAY_NAME", "Canvas Real LMS"),
        canvas_base_url=raw_canvas_connector_base_url or inferred_canvas_connector_base_url,
        lti_tool_base_url=raw_lti_tool_base_url or inferred_lti_tool_base_url,
        lti_client_id=os.environ.get("CANVAS_LTI_CLIENT_ID", DEFAULT_CANVAS_LTI_CLIENT_ID),
        lti_deployment_id=os.environ.get("CANVAS_LTI_DEPLOYMENT_ID", DEFAULT_CANVAS_LTI_DEPLOYMENT_ID),
        probe_after_upsert=bool(args.probe_after_upsert or _bool_env("CANVAS_PROBE_AFTER_UPSERT", False)),
        program_binding_seed_enabled=_bool_env("CANVAS_PROGRAM_BINDING_SEED_ENABLED", True),
        program_binding_display_name=os.environ.get(
            "CANVAS_PROGRAM_BINDING_DISPLAY_NAME",
            os.environ.get("CANVAS_CONNECTOR_DISPLAY_NAME", "Marty Canvas Experiment"),
        ),
        program_binding_evidence_type=os.environ.get(
            "CANVAS_PROGRAM_BINDING_EVIDENCE_TYPE",
            default_program_evidence_type,
        ),
        program_binding_delivery_mode=os.environ.get(
            "CANVAS_PROGRAM_BINDING_DELIVERY_MODE",
            default_program_delivery_mode,
        ),
        program_binding_auto_approve=_bool_env("CANVAS_PROGRAM_BINDING_AUTO_APPROVE", True),
        program_binding_direct_issue=_bool_env("CANVAS_PROGRAM_BINDING_DIRECT_ISSUE", False),
        program_binding_score_threshold=int(os.environ.get("CANVAS_PROGRAM_BINDING_SCORE_THRESHOLD", "80")),
        open_badge_scenario_enabled=open_badge_scenario_enabled,
        demo_application_seed_enabled=_bool_env("CANVAS_DEMO_APPLICATION_SEED_ENABLED", True),
        demo_evidence_event_enabled=_bool_env("CANVAS_DEMO_EVIDENCE_EVENT_ENABLED", False),
        demo_wallet_claim_enabled=_bool_env("CANVAS_DEMO_WALLET_CLAIM_ENABLED", True),
        demo_mirror_publish_enabled=_bool_env("CANVAS_DEMO_MIRROR_PUBLISH_ENABLED", True),
        signing_keys_internal_base_url=os.environ.get(
            "SIGNING_KEYS_INTERNAL_BASE_URL",
            "http://localhost:8000/internal/signing-keys",
        ),
        signing_keys_internal_api_key=os.environ.get(
            "SIGNING_KEYS_INTERNAL_API_KEY",
            "dev-signing-keys-internal-api-key",
        ),
    )

    if not raw_issuance_api_key:
        print("INFO: ISSUANCE_API_KEY not set; using local default dev-issuance-api-key.")
    if not raw_canvas_connector_base_url:
        print(
            "INFO: CANVAS_CONNECTOR_BASE_URL not set; "
            f"using default {connector_cfg.canvas_base_url}."
        )
    if not raw_lti_tool_base_url:
        print(
            "INFO: CANVAS_LTI_EXPERIENCE_BASE_URL not set; "
            f"using default {connector_cfg.lti_tool_base_url}."
        )

    canvas_cfg = CanvasSeedConfig(
        enabled=(not args.skip_canvas_lms_seed) and _bool_env("CANVAS_LMS_SEED_ENABLED", True),
        api_base_url=raw_canvas_api_base_url,
        browser_base_url=inferred_canvas_browser_base_url,
        admin_token=os.environ.get("CANVAS_ADMIN_ACCESS_TOKEN", "").strip(),
        admin_email=os.environ.get("CANVAS_ADMIN_EMAIL", "admin@example.com").strip() or "admin@example.com",
        admin_password=os.environ.get("CANVAS_ADMIN_PASSWORD", "readystack123"),
        account_id=os.environ.get("CANVAS_ROOT_ACCOUNT_ID", "1"),
        container_name=os.environ.get("CANVAS_REAL_CONTAINER_NAME", "marty-canvas-real").strip() or "marty-canvas-real",
        course_name=os.environ.get("CANVAS_TEST_COURSE_NAME", "ElevenID LTI Test Course"),
        course_code=os.environ.get("CANVAS_TEST_COURSE_CODE", "ELEVENID-LTI-101"),
        course_sis_id=os.environ.get("CANVAS_TEST_COURSE_SIS_ID", "elevenid_lti_test"),
        learner_name=os.environ.get("CANVAS_TEST_LEARNER_NAME", "ElevenID Test Learner"),
        learner_email=os.environ.get("CANVAS_TEST_LEARNER_EMAIL", "learner+elevenid@example.edu"),
        learner_password=os.environ.get("CANVAS_TEST_LEARNER_PASSWORD", "ChangeMe123!"),
        launch_seed_enabled=_bool_env("CANVAS_LAUNCH_SEED_ENABLED", True),
        launch_module_name=os.environ.get("CANVAS_TEST_MODULE_NAME", "ElevenID Credential Launch"),
        launch_item_title=os.environ.get(
            "CANVAS_TEST_MODULE_ITEM_TITLE",
            "Launch ElevenID Credential Issuance",
        ),
        launch_assignment_name=os.environ.get(
            "CANVAS_TEST_ASSIGNMENT_NAME",
            "ElevenID Credential Issuance",
        ),
        quiz_seed_enabled=_bool_env("CANVAS_TEST_QUIZ_SEED_ENABLED", open_badge_scenario_enabled),
        quiz_title=os.environ.get("CANVAS_TEST_QUIZ_TITLE", "Interoperable Credentials Foundations Quiz"),
        quiz_description=os.environ.get(
            "CANVAS_TEST_QUIZ_DESCRIPTION",
            "Demo quiz used to issue an ElevenID Open Badge through MIP policy and remote DID signing.",
        ),
        quiz_passing_score_percent=int(os.environ.get("CANVAS_TEST_QUIZ_PASSING_SCORE_PERCENT", "92")),
        quiz_points_possible=int(os.environ.get("CANVAS_TEST_QUIZ_POINTS_POSSIBLE", "100")),
    )

    if connector_cfg.open_badge_scenario_enabled:
        print("==> Seeding Canvas MIP Open Badge template layer...")
        try:
            _seed_canvas_open_badge_templates(connector_cfg)
            print("  OK Credential template and application template seeded")
            print(f"    credential_template: {connector_cfg.credential_template_id}")
            print(f"    application_template:{connector_cfg.application_template_id}")
        except Exception as exc:
            print(f"ERROR: Canvas MIP Open Badge template seed failed: {exc}", file=sys.stderr)
            return 3

    print("==> Seeding ElevenID Canvas platform...")
    try:
        platform_result = _upsert_canvas_platform(connector_cfg)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        print(f"ERROR: Canvas platform seed failed ({exc.code}): {body or exc.reason}", file=sys.stderr)
        return 3
    except URLError as exc:
        print(f"ERROR: Canvas platform seed failed: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"ERROR: Canvas platform seed failed: {exc}", file=sys.stderr)
        return 3

    platform = platform_result["platform"]
    platform_id = platform.get("id")
    print(f"  OK Canvas platform {platform_result['action']}: {platform_id}")
    print(f"    organization_id:    {platform.get('organization_id')}")
    print(f"    canvas_account_id:  {platform.get('canvas_account_id')}")
    print(f"    canvas_base_url:    {platform.get('canvas_base_url')}")
    print(f"    lti_tool_base_url:  {connector_cfg.lti_tool_base_url}")

    canvas_lms_seeded = False
    canvas_seed: dict[str, Any] | None = None
    if canvas_cfg.enabled:
        print("==> Seeding Canvas LMS LTI infrastructure (dev key + course + learner + tool)...")
        try:
            canvas_seed = _maybe_seed_canvas(canvas_cfg, connector_cfg, str(platform_id))
            actual_lti_client_id = str(
                ((canvas_seed or {}).get("developer_key") or {}).get("client_id")
                or platform.get("lti_client_id")
                or connector_cfg.lti_client_id
            )
            actual_lti_deployment_id = str(
                ((canvas_seed or {}).get("external_tool") or {}).get("deployment_id")
                or platform.get("lti_deployment_id")
                or connector_cfg.lti_deployment_id
            )

            if (
                actual_lti_client_id != str(platform.get("lti_client_id") or "")
                or actual_lti_deployment_id != str(platform.get("lti_deployment_id") or "")
            ):
                print("==> Syncing Canvas platform with Canvas launch identifiers...")
                connector_cfg.lti_client_id = actual_lti_client_id
                connector_cfg.lti_deployment_id = actual_lti_deployment_id
                platform_result = _upsert_canvas_platform(connector_cfg)
                platform = platform_result["platform"]
                platform_id = platform.get("id") or platform_id
                print("  OK Canvas platform launch identifiers synced")
                print(f"    lti_client_id:     {platform.get('lti_client_id')}")
                print(f"    lti_deployment_id: {platform.get('lti_deployment_id')}")

            canvas_lms_seeded = True
            print("  OK Canvas LMS seeded")
            if canvas_seed:
                public_domain = canvas_seed.get("public_domain") or {}
                if public_domain:
                    print(f"    public_domain: {public_domain.get('action')} ({public_domain.get('domain')})")
                print(f"    developer_key: {canvas_seed['developer_key']['action']} (ID: {canvas_seed['developer_key']['id']})")
                print(f"      key_name:     {canvas_seed['developer_key']['name']}")
                print(f"      client_id:    {canvas_seed['developer_key']['client_id']}")
                print(
                    "      owner_binding:" \
                    f" {canvas_seed['developer_key'].get('owner_binding_account_id')}" \
                    f" ({canvas_seed['developer_key'].get('owner_binding_workflow_state')})"
                )
                print(
                    "      account_binding:" \
                    f" {canvas_seed['developer_key'].get('requested_binding_account_id')}" \
                    f" ({canvas_seed['developer_key'].get('requested_binding_workflow_state')})"
                )
                print(f"    course:  {canvas_seed['course']}")
                print(f"    learner: {canvas_seed['learner']}")
                print(f"    tool:    {canvas_seed['external_tool']['action']} (ID: {canvas_seed['external_tool']['id']})")
                print(f"      deployment_id:{canvas_seed['external_tool']['deployment_id']}")
                quiz = canvas_seed.get("quiz") or {}
                if quiz:
                    if quiz.get("error"):
                        print(f"    quiz:    skipped ({quiz.get('error')})")
                    else:
                        print(f"    quiz:    {quiz.get('action')} (ID: {quiz.get('id')})")
                        print(f"      title:       {quiz.get('title')}")
                        quiz_item = quiz.get("module_item") or {}
                        if quiz_item:
                            print(f"      module_item: {quiz_item.get('action')} (ID: {quiz_item.get('id')})")
                launch_surface = canvas_seed.get("launch_surface") or {}
                if launch_surface:
                    module = launch_surface.get("module") or {}
                    module_item = launch_surface.get("module_item") or {}
                    assignment = launch_surface.get("assignment") or {}
                    print(f"    module:  {module.get('action')} (ID: {module.get('id')})")
                    print(f"      name:        {module.get('name')}")
                    print(f"    module_item: {module_item.get('action')} (ID: {module_item.get('id')})")
                    print(f"      title:       {module_item.get('title')}")
                    if module_item.get("html_url"):
                        print(f"      html_url:    {module_item.get('html_url')}")
                    if assignment:
                        print(f"    assignment: {assignment.get('action')} (ID: {assignment.get('id')})")
                        print(f"      name:        {assignment.get('name')}")
                    elif launch_surface.get("assignment_error"):
                        print(f"    assignment: skipped ({launch_surface.get('assignment_error')})")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            print(f"WARN: Canvas LMS seed failed ({exc.code}): {body or exc.reason}", file=sys.stderr)
        except Exception as exc:
            print(f"WARN: Canvas LMS seed failed: {exc}", file=sys.stderr)
    else:
        print("==> Canvas LMS seeding skipped (platform seeded only).")

    print("==> Refreshing Canvas platform LTI trust metadata...")
    try:
        refresh_result = _refresh_canvas_platform_jwks(connector_cfg, str(platform_id))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        print(f"ERROR: Canvas platform JWKS refresh failed ({exc.code}): {body or exc.reason}", file=sys.stderr)
        return 3
    except URLError as exc:
        print(f"ERROR: Canvas platform JWKS refresh failed: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"ERROR: Canvas platform JWKS refresh failed: {exc}", file=sys.stderr)
        return 3

    platform = refresh_result["platform"]
    platform_id = platform.get("id") or platform_id
    jwks_keys = ((platform.get("lti_jwks_json") or {}).get("keys") or []) if isinstance(platform, dict) else []
    print(f"  OK Canvas platform trust refreshed: {refresh_result.get('refreshed', False)}")
    print(f"    lti_issuer:         {platform.get('lti_issuer')}")
    print(f"    lti_jwks_url:       {platform.get('lti_jwks_url')}")
    print(f"    jwks_key_count:     {len(jwks_keys)}")

    seeded_canvas_scope = _canvas_demo_scope(
        course_id=((canvas_seed or {}).get("course") or {}).get("id"),
        quiz_id=(
            ((canvas_seed or {}).get("quiz") or {}).get("id")
            if not ((canvas_seed or {}).get("quiz") or {}).get("error")
            else None
        ),
    )
    admin_canvas_scope = _canvas_scope_from_admin_env()
    canvas_scope = {**seeded_canvas_scope, **admin_canvas_scope}
    if admin_canvas_scope:
        print("==> Canvas scope supplied by admin/import environment...")
        print(f"  OK Canvas scope: {canvas_scope}")
    elif not canvas_scope:
        print("INFO: Canvas program binding scope is empty; it will match any Canvas launch/evidence for this platform.")
    if connector_cfg.open_badge_scenario_enabled:
        print("==> Updating Canvas MIP Open Badge evidence scope...")
        try:
            _seed_canvas_open_badge_templates(connector_cfg, canvas_scope=canvas_scope)
            print(f"  OK Evidence scope: {canvas_scope or '{}'}")
        except Exception as exc:
            print(f"ERROR: Canvas MIP Open Badge scoped template update failed: {exc}", file=sys.stderr)
            return 3

    if connector_cfg.program_binding_seed_enabled:
        print("==> Seeding Canvas platform and program binding...")
        try:
            binding_result = _upsert_canvas_program_binding(
                connector_cfg,
                platform,
                canvas_scope=canvas_scope,
            )
            print(f"  OK Canvas platform ready: {platform.get('id')}")
            print(f"    canvas_account_id:  {platform.get('canvas_account_id')}")
            print(f"  OK Canvas program binding {binding_result['action']}: {binding_result['binding'].get('id')}")
            print(f"    application_template:{binding_result['binding'].get('application_template_id')}")
            print(f"    credential_template: {binding_result['binding'].get('credential_template_id')}")
            print(f"    evidence_type:       {connector_cfg.program_binding_evidence_type}")
            print(f"    evidence_scope:      {binding_result['binding'].get('canvas_scope')}")
            print(f"    delivery_mode:       {binding_result['binding'].get('delivery_mode')}")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            print(f"ERROR: Canvas platform/program binding seed failed ({exc.code}): {body or exc.reason}", file=sys.stderr)
            return 3
        except URLError as exc:
            print(f"ERROR: Canvas platform/program binding seed failed: {exc}", file=sys.stderr)
            return 3
        except Exception as exc:
            print(f"ERROR: Canvas platform/program binding seed failed: {exc}", file=sys.stderr)
            return 3
    else:
        print("==> Canvas platform/program binding seeding skipped.")

    issuer_context = _resolve_issuer_context_summary(connector_cfg)
    if issuer_context:
        print("==> Remote issuer context resolved...")
        print(f"  issuer_profile_id:     {issuer_context.get('issuer_profile_id')}")
        print(f"  issuer_did:            {issuer_context.get('issuer_did')}")
        print(f"  signing_service_id:    {issuer_context.get('signing_service_id')}")
        print(f"  signing_key_reference: {issuer_context.get('signing_key_reference')}")
    else:
        print("WARN: Remote issuer context could not be resolved from the signing-key registry.")

    demo_application: dict[str, Any] | None = None
    demo_evidence_response: dict[str, Any] | None = None
    demo_wallet_claim_response: dict[str, Any] | None = None
    demo_mirror_publish_response: dict[str, Any] | None = None
    if connector_cfg.open_badge_scenario_enabled and connector_cfg.demo_application_seed_enabled:
        print("==> Creating Canvas MIP Open Badge demo application...")
        try:
            demo_application = _create_canvas_demo_application(
                connector_cfg,
                canvas_cfg,
                canvas_seed=canvas_seed,
            )
            print(f"  OK Application created: {demo_application.get('id')}")
            print(f"    status:              {demo_application.get('status')}")
            if connector_cfg.demo_evidence_event_enabled:
                demo_evidence_response = _emit_canvas_demo_ags_score_event(
                    connector_cfg,
                    canvas_cfg,
                    canvas_seed=canvas_seed,
                    application=demo_application,
                )
                if demo_evidence_response:
                    print("  OK Demo Canvas AGS evidence event submitted")
                    print(f"    application_status: {demo_evidence_response.get('application_status')}")
                    print(f"    policy_allowed:     {((demo_evidence_response.get('policy_decision') or {}).get('allowed'))}")
                    _print_canvas_demo_transition_summary(connector_cfg, str(demo_application.get("id")))
                    transition = _lookup_canvas_demo_transition(str(demo_application.get("id")))
                    tx_id = ((transition or {}).get("application") or {}).get("issuance_transaction_id")
                    if tx_id and connector_cfg.demo_wallet_claim_enabled:
                        print("==> Claiming demo Open Badge through OID4VCI wallet flow...")
                        demo_wallet_claim_response = _claim_canvas_demo_wallet_credential(
                            connector_cfg,
                            transaction_id=str(tx_id),
                        )
                        print("  OK Demo wallet credential claimed")
                        print(f"    transaction_id:     {demo_wallet_claim_response.get('transaction_id')}")
                        print(f"    credential_format:  {demo_wallet_claim_response.get('credential_format')}")
                        print(f"    credential_size:    {demo_wallet_claim_response.get('credential_size')}")
                        _print_canvas_demo_transition_summary(connector_cfg, str(demo_application.get("id")))
                        if connector_cfg.demo_mirror_publish_enabled:
                            print("==> Publishing pending Canvas credential mirror records...")
                            demo_mirror_publish_response = _run_canvas_demo_mirror_publish(connector_cfg)
                            publish_summary = (
                                demo_mirror_publish_response.get("publish")
                                if isinstance(demo_mirror_publish_response.get("publish"), dict)
                                else demo_mirror_publish_response
                            )
                            print("  OK Canvas mirror automation cycle completed")
                            print(f"    processed_count:    {demo_mirror_publish_response.get('processed_count')}")
                            print(f"    delivered_count:    {publish_summary.get('delivered_count')}")
                            print(f"    failed_count:       {demo_mirror_publish_response.get('failed_count')}")
                            print(f"    blocked_count:      {demo_mirror_publish_response.get('blocked_count')}")
                            _print_canvas_demo_transition_summary(connector_cfg, str(demo_application.get("id")))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            print(f"WARN: Demo application/evidence setup failed ({exc.code}): {body or exc.reason}", file=sys.stderr)
        except Exception as exc:
            print(f"WARN: Demo application/evidence setup failed: {exc}", file=sys.stderr)
    elif connector_cfg.open_badge_scenario_enabled:
        print("==> Demo application seeding skipped.")

    print("\nDone.")
    print("\n" + "="*70)
    print("CANVAS LTI 1.3 SETUP SUMMARY")
    print("="*70)
    
    if canvas_lms_seeded:
        print("\nOK Canvas LTI infrastructure has been automatically configured:")
        print("  - Developer key created")
        print("  - External tool installed in course")
        print("  - Test course and learner ready")
        if canvas_cfg.launch_seed_enabled:
            print("  - Launch module item created")
            print("  - Launch assignment created when Canvas accepted the assignment payload")
        if canvas_cfg.quiz_seed_enabled:
            print("  - Demo quiz created for Canvas AGS score evidence")
        if connector_cfg.open_badge_scenario_enabled:
            print("  - MIP Open Badge template, evidence policy, and Canvas mirror binding seeded")
            if demo_application:
                print(f"  - Demo application ready: {demo_application.get('id')}")
            if demo_evidence_response:
                print("  - Demo evidence event processed through MIP policy")
            if demo_wallet_claim_response:
                print("  - Demo Open Badge claimed through the OID4VCI wallet endpoint")
            if demo_mirror_publish_response:
                print("  - Canvas credential mirror publish cycle completed")
        print("\nNext steps:")
        print(f"  1. Log into Canvas: {canvas_cfg.browser_base_url.rstrip('/')}")
        print(f"  2. Open the '{canvas_cfg.course_name}' course")
        if canvas_cfg.launch_seed_enabled:
            print(f"  3. Open Modules and launch '{canvas_cfg.launch_item_title}'")
            print(f"  4. Or open Assignments and launch '{canvas_cfg.launch_assignment_name}' when present")
            if canvas_cfg.quiz_seed_enabled:
                print(f"  5. Open the '{canvas_cfg.quiz_title}' quiz to view the course/quiz evidence surface")
                print("  6. Submit a signed Canvas AGS score event when ready to auto-approve and issue")
                print("  7. For the automated demo, enable CANVAS_DEMO_EVIDENCE_EVENT_ENABLED=true")
        else:
            print("  3. Select the installed external tool from the course Apps/External Tools area")
        print("  Complete the LTI login into ElevenID")
    elif canvas_cfg.enabled:
        print("\nWARN: Canvas LMS seeding did not complete.")
        print("   Connector/platform/binding records were still seeded on the ElevenID side.")
        print("   Check the warning above, fix the Canvas-side issue, then rerun:")
        print("   cd marty-ui && python scripts/seed_canvas_real.py")
    else:
        print("\nWARN: Canvas LMS seeding was skipped. Connector/platform/binding records were seeded only.")
        print("   Rerun without --skip-canvas-lms-seed to bootstrap Canvas admin, token, course, tool, and launch surfaces.")
    
    print("\n" + "="*70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
