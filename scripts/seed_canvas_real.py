#!/usr/bin/env python3
"""Seed real Canvas + ElevenID Canvas connector for local development.

What this script does:
1) Upserts an ElevenID Canvas connector against the issuance API.
2) Optionally creates Canvas LTI developer key with LTI 1.3 configuration when admin token provided.
3) Optionally seeds a Canvas course + learner enrollment + external tool when admin API token is provided.

The script is idempotent for connector creation (find by organization + canvas_account_id).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


MARTY_DEFAULT_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
CANVAS_RAILS_RESULT_PREFIX = "__CANVAS_LTI_RESULT__"
DEFAULT_CANVAS_LTI_CLIENT_ID = "canvas-real-client-id"
DEFAULT_CANVAS_LTI_DEPLOYMENT_ID = "canvas-real-deployment-id"
LTI_REQUIRED_SCOPES = [
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
    "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
    "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
]


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


def _lti_experience_login_url(connector_cfg: "ConnectorSeedConfig", connector_id: str) -> str:
    return (
        f"{connector_cfg.lti_tool_base_url.rstrip('/')}/v1/integrations/canvas/lti/experience-login/"
        f"{connector_id}"
    )


def _lti_experience_launch_url(connector_cfg: "ConnectorSeedConfig", connector_id: str) -> str:
    return (
        f"{connector_cfg.lti_tool_base_url.rstrip('/')}/v1/integrations/canvas/lti/experience/"
        f"{connector_id}"
    )


@dataclass
class ConnectorSeedConfig:
    issuance_base_url: str
    issuance_api_key: str
    organization_id: str
    canvas_account_id: str
    credential_template_id: str
    display_name: str
    canvas_base_url: str
    lti_tool_base_url: str
    lti_client_id: str
    lti_deployment_id: str
    probe_after_upsert: bool


@dataclass
class CanvasSeedConfig:
    enabled: bool
    api_base_url: str
    admin_token: str
    admin_email: str
    account_id: str
    container_name: str
    course_name: str
    course_code: str
    course_sis_id: str
    learner_name: str
    learner_email: str
    learner_password: str


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


def _upsert_canvas_connector(cfg: ConnectorSeedConfig) -> dict[str, Any]:
    headers = _connector_headers(cfg.issuance_api_key)
    list_url = (
        f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/connectors"
        f"?organization_id={cfg.organization_id}"
    )
    connectors = _json_request("GET", list_url, headers=headers)
    if not isinstance(connectors, list):
        raise RuntimeError("Unexpected connector list response from issuance API")

    existing = next(
        (
            item
            for item in connectors
            if isinstance(item, dict)
            and item.get("organization_id") == cfg.organization_id
            and item.get("canvas_account_id") == cfg.canvas_account_id
        ),
        None,
    )

    lti_client_id = cfg.lti_client_id
    lti_deployment_id = cfg.lti_deployment_id
    if isinstance(existing, dict):
        existing_client_id = existing.get("lti_client_id")
        existing_deployment_id = existing.get("lti_deployment_id")
        if (
            lti_client_id == DEFAULT_CANVAS_LTI_CLIENT_ID
            and isinstance(existing_client_id, str)
            and existing_client_id.strip()
            and existing_client_id != DEFAULT_CANVAS_LTI_CLIENT_ID
        ):
            lti_client_id = existing_client_id
        if (
            lti_deployment_id == DEFAULT_CANVAS_LTI_DEPLOYMENT_ID
            and isinstance(existing_deployment_id, str)
            and existing_deployment_id.strip()
            and existing_deployment_id != DEFAULT_CANVAS_LTI_DEPLOYMENT_ID
        ):
            lti_deployment_id = existing_deployment_id

    payload = {
        "organization_id": cfg.organization_id,
        "canvas_account_id": cfg.canvas_account_id,
        "credential_template_id": cfg.credential_template_id,
        "display_name": cfg.display_name,
        "canvas_base_url": cfg.canvas_base_url,
        "lti_client_id": lti_client_id,
        "lti_deployment_id": lti_deployment_id,
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
        connector_id = str(existing["id"])
        url = f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/connectors/{connector_id}"
        connector = _json_request("PUT", url, payload=payload, headers=headers)
        action = "updated"
    else:
        url = f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/connectors"
        connector = _json_request("POST", url, payload=payload, headers=headers)
        connector_id = str((connector or {}).get("id") or "")
        action = "created"

    if not isinstance(connector, dict) or not connector_id:
        raise RuntimeError("Connector upsert did not return a valid connector payload")

    if cfg.probe_after_upsert:
        probe_url = (
            f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/connectors/"
            f"{connector_id}/sandbox-probe"
        )
        _json_request("POST", probe_url, payload={}, headers=headers)

    return {
        "action": action,
        "connector": connector,
    }


def _refresh_canvas_connector_jwks(cfg: ConnectorSeedConfig, connector_id: str) -> dict[str, Any]:
    headers = _connector_headers(cfg.issuance_api_key)
    refresh_url = (
        f"{cfg.issuance_base_url.rstrip('/')}/v1/integrations/canvas/connectors/"
        f"{connector_id}/jwks-refresh?organization_id={cfg.organization_id}"
    )
    refreshed = _json_request("POST", refresh_url, headers=headers)
    if not isinstance(refreshed, dict) or not isinstance(refreshed.get("connector"), dict):
        raise RuntimeError("Connector JWKS refresh did not return a valid connector payload")
    return refreshed


def _first_item(value: Any) -> dict[str, Any] | None:
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, dict):
            return first
    if isinstance(value, dict):
        return value
    return None


def _ensure_canvas_course(cfg: CanvasSeedConfig) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {cfg.admin_token}"}
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
    headers = {"Authorization": f"Bearer {cfg.admin_token}"}
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
    headers = {"Authorization": f"Bearer {cfg.admin_token}"}
    enrollments_url = f"{cfg.api_base_url.rstrip('/')}/api/v1/courses/{course_id}/enrollments"
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
    connector_id: str,
) -> dict[str, Any]:
    """Create or update the Canvas LTI 1.3 developer key via Rails runner."""
    payload = {
        "account_id": str(cfg.account_id),
        "admin_email": cfg.admin_email,
        "client_id": connector_cfg.lti_client_id,
        "notes": f"ElevenID LTI Integration - {connector_cfg.lti_client_id}",
        "redirect_uri": _lti_experience_launch_url(connector_cfg, connector_id),
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


def _ensure_canvas_external_tool(
    cfg: CanvasSeedConfig,
    connector_cfg: ConnectorSeedConfig,
    connector_id: str,
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
        "tool_url": _lti_experience_login_url(connector_cfg, connector_id),
    }
    result = _run_canvas_rails_lti_setup(cfg, payload)
    external_tool = result.get("external_tool") if isinstance(result, dict) else None
    if not isinstance(external_tool, dict) or not external_tool.get("id"):
        raise RuntimeError("External tool setup did not return a valid tool payload")
    return {
        "action": external_tool.get("action", "updated"),
        "tool": external_tool,
    }


def _run_canvas_rails_lti_setup(cfg: CanvasSeedConfig, payload: dict[str, Any]) -> dict[str, Any]:
    payload_b64 = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")
    resolved_container_name = _resolve_canvas_container_name(cfg.container_name)
    ruby_script = f"""
require \"base64\"
require \"json\"

payload = JSON.parse(Base64.decode64(ENV.fetch(\"CANVAS_LTI_SETUP_B64\")))

account = Account.find(payload.fetch(\"account_id\"))
client_id = payload.fetch(\"client_id\")

developer_key = DeveloperKey.find_or_initialize_by(name: client_id)
developer_key_action = developer_key.new_record? ? \"created\" : \"updated\"
developer_key.email = payload[\"admin_email\"] if payload[\"admin_email\"]
developer_key.scopes = payload.fetch(\"scopes\", developer_key.scopes || [])
developer_key.redirect_uris = [payload.fetch(\"redirect_uri\", developer_key.redirect_uris&.first)].compact
developer_key.notes = payload[\"notes\"] if payload[\"notes\"]
developer_key.is_lti_key = true if developer_key.respond_to?(:is_lti_key=)
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
    connector_id: str,
) -> dict[str, Any] | None:
    if not cfg.enabled:
        return None

    if not cfg.admin_token:
        raise RuntimeError(
            "Canvas LMS seeding enabled but CANVAS_ADMIN_ACCESS_TOKEN is empty"
        )

    if not _wait_for_http(cfg.api_base_url, path="/", retries=90, delay=2.0):
        raise RuntimeError(f"Canvas did not become reachable at {cfg.api_base_url}")

    # Create course and learner
    course = _ensure_canvas_course(cfg)
    user = _ensure_canvas_user(cfg)
    enrollment = _ensure_canvas_enrollment(cfg, course_id=course["id"], user_id=user["id"])

    # Create Canvas LTI developer key
    dev_key = _ensure_canvas_developer_key(cfg, connector_cfg, connector_id)
    
    # Create external tool in course
    external_tool = _ensure_canvas_external_tool(
        cfg,
        connector_cfg,
        connector_id,
        course_id=course["id"],
        dev_key=dev_key["key"],
    )

    return {
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


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Seed real Canvas LMS + ElevenID connector")
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
        help="Call connector sandbox-probe after create/update",
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
    inferred_canvas_base_url = raw_canvas_api_base_url.rstrip("/")
    inferred_lti_tool_base_url = os.environ.get("PUBLIC_API_URL", "").strip() or "http://localhost:8000"

    connector_cfg = ConnectorSeedConfig(
        issuance_base_url=os.environ.get("ISSUANCE_API_BASE_URL", "http://localhost:8005"),
        issuance_api_key=raw_issuance_api_key or "dev-issuance-api-key",
        organization_id=os.environ.get("CANVAS_ORGANIZATION_ID", MARTY_DEFAULT_ORG_ID),
        canvas_account_id=os.environ.get("CANVAS_ACCOUNT_ID", "canvas-real-account-1"),
        credential_template_id=os.environ.get(
            "CANVAS_CREDENTIAL_TEMPLATE_ID",
            MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID,
        ),
        display_name=os.environ.get("CANVAS_CONNECTOR_DISPLAY_NAME", "Canvas Real LMS"),
        canvas_base_url=raw_canvas_connector_base_url or inferred_canvas_base_url,
        lti_tool_base_url=raw_lti_tool_base_url or inferred_lti_tool_base_url,
        lti_client_id=os.environ.get("CANVAS_LTI_CLIENT_ID", DEFAULT_CANVAS_LTI_CLIENT_ID),
        lti_deployment_id=os.environ.get("CANVAS_LTI_DEPLOYMENT_ID", DEFAULT_CANVAS_LTI_DEPLOYMENT_ID),
        probe_after_upsert=bool(args.probe_after_upsert or _bool_env("CANVAS_PROBE_AFTER_UPSERT", False)),
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
        admin_token=os.environ.get("CANVAS_ADMIN_ACCESS_TOKEN", "").strip(),
        admin_email=os.environ.get("CANVAS_ADMIN_EMAIL", "admin@example.com").strip() or "admin@example.com",
        account_id=os.environ.get("CANVAS_ROOT_ACCOUNT_ID", "1"),
        container_name=os.environ.get("CANVAS_REAL_CONTAINER_NAME", "marty-canvas-real").strip() or "marty-canvas-real",
        course_name=os.environ.get("CANVAS_TEST_COURSE_NAME", "ElevenID LTI Test Course"),
        course_code=os.environ.get("CANVAS_TEST_COURSE_CODE", "ELEVENID-LTI-101"),
        course_sis_id=os.environ.get("CANVAS_TEST_COURSE_SIS_ID", "elevenid_lti_test"),
        learner_name=os.environ.get("CANVAS_TEST_LEARNER_NAME", "ElevenID Test Learner"),
        learner_email=os.environ.get("CANVAS_TEST_LEARNER_EMAIL", "learner+elevenid@example.edu"),
        learner_password=os.environ.get("CANVAS_TEST_LEARNER_PASSWORD", "ChangeMe123!"),
    )

    print("==> Seeding ElevenID Canvas connector...")
    try:
        connector_result = _upsert_canvas_connector(connector_cfg)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        print(f"ERROR: issuance connector seed failed ({exc.code}): {body or exc.reason}", file=sys.stderr)
        return 3
    except URLError as exc:
        print(f"ERROR: issuance connector seed failed: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"ERROR: issuance connector seed failed: {exc}", file=sys.stderr)
        return 3

    connector = connector_result["connector"]
    connector_id = connector.get("id")
    print(f"  ✓ Connector {connector_result['action']}: {connector_id}")
    print(f"    organization_id:    {connector.get('organization_id')}")
    print(f"    canvas_account_id:  {connector.get('canvas_account_id')}")
    print(f"    credential_template:{connector.get('credential_template_id')}")
    print(f"    canvas_base_url:    {connector.get('canvas_base_url')}")
    print(f"    lti_tool_base_url:  {connector_cfg.lti_tool_base_url}")

    print("==> Refreshing Canvas connector LTI trust metadata...")
    try:
        refresh_result = _refresh_canvas_connector_jwks(connector_cfg, str(connector_id))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        print(f"ERROR: connector JWKS refresh failed ({exc.code}): {body or exc.reason}", file=sys.stderr)
        return 3
    except URLError as exc:
        print(f"ERROR: connector JWKS refresh failed: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"ERROR: connector JWKS refresh failed: {exc}", file=sys.stderr)
        return 3

    connector = refresh_result["connector"]
    connector_id = connector.get("id") or connector_id
    jwks_keys = ((connector.get("lti_jwks_json") or {}).get("keys") or []) if isinstance(connector, dict) else []
    print(f"  ✓ Connector trust refreshed: {refresh_result.get('refreshed', False)}")
    print(f"    lti_issuer:         {connector.get('lti_issuer')}")
    print(f"    lti_jwks_url:       {connector.get('lti_jwks_url')}")
    print(f"    jwks_key_count:     {len(jwks_keys)}")

    if canvas_cfg.enabled:
        print("==> Seeding Canvas LMS LTI infrastructure (dev key + course + learner + tool)...")
        try:
            canvas_seed = _maybe_seed_canvas(canvas_cfg, connector_cfg, str(connector_id))
            actual_lti_client_id = str(
                ((canvas_seed or {}).get("developer_key") or {}).get("client_id")
                or connector.get("lti_client_id")
                or connector_cfg.lti_client_id
            )
            actual_lti_deployment_id = str(
                ((canvas_seed or {}).get("external_tool") or {}).get("deployment_id")
                or connector.get("lti_deployment_id")
                or connector_cfg.lti_deployment_id
            )

            if (
                actual_lti_client_id != str(connector.get("lti_client_id") or "")
                or actual_lti_deployment_id != str(connector.get("lti_deployment_id") or "")
            ):
                print("==> Syncing connector with Canvas launch identifiers...")
                connector_cfg.lti_client_id = actual_lti_client_id
                connector_cfg.lti_deployment_id = actual_lti_deployment_id
                connector_result = _upsert_canvas_connector(connector_cfg)
                connector = connector_result["connector"]
                connector_id = connector.get("id") or connector_id
                print("  ✓ Connector launch identifiers synced")
                print(f"    lti_client_id:     {connector.get('lti_client_id')}")
                print(f"    lti_deployment_id: {connector.get('lti_deployment_id')}")

            print("  ✓ Canvas LMS seeded")
            if canvas_seed:
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
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            print(f"WARN: Canvas LMS seed failed ({exc.code}): {body or exc.reason}", file=sys.stderr)
        except Exception as exc:
            print(f"WARN: Canvas LMS seed failed: {exc}", file=sys.stderr)
    else:
        print("==> Canvas LMS seeding skipped (connector seeded only).")

    print("\nDone.")
    print("\n" + "="*70)
    print("CANVAS LTI 1.3 SETUP SUMMARY")
    print("="*70)
    
    if canvas_cfg.enabled and canvas_cfg.admin_token:
        print("\n✓ Canvas LTI infrastructure has been automatically configured:")
        print("  - Developer key created")
        print("  - External tool installed in course")
        print("  - Test course and learner ready")
        print("\nNext steps:")
        print("  1. Log into Canvas: http://localhost:8088")
        print("  2. Go to the 'ElevenID LTI Test Course'")
        print("  3. Create an assignment or module item with LTI launch link")
        print("  4. Select the 'Canvas Real LMS' external tool")
        print("  5. Launch and complete LTI login")
    else:
        print("\n⚠ Canvas admin token not provided. Connector created on ElevenID side only.")
        print("\nTo enable Canvas LTI login, you need to:")
        print("\n1. Get Canvas admin token:")
        print("   Admin: admin@example.com")
        print("   Password: readystack123")
        print("   Generate token at: http://localhost:8088/profile/settings")
        print("\n2. Add to .env.tunnel.beta.local:")
        print("   CANVAS_ADMIN_ACCESS_TOKEN=<generated_token>")
        print("\n3. Run seed script again:")
        print("   cd marty-ui && python scripts/seed_canvas_real.py")
        print("\nOR manually configure Canvas:")
        print("\n1. Log into Canvas: http://localhost:8088")
        print("2. Go to Admin > Developer Keys")
        print("3. Create new developer key with:")
        print(f"   - Key name: {connector_cfg.lti_client_id}")
        print(f"   - Redirect URI: {_lti_experience_launch_url(connector_cfg, str(connector_id))}")
        print(f"   - Scopes: lineitem, lineitem.readonly, result.readonly, contextmembership.readonly")
        print("\n4. Enable key, then in target course:")
        print("5. Go to Settings > Apps")
        print("6. Add external tool manually (LTI 1.3)")
        print(f"   - Name: {connector_cfg.display_name}")
        print(f"   - URL: {_lti_experience_login_url(connector_cfg, str(connector_id))}")
    
    print("\n" + "="*70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
