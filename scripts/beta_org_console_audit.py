#!/usr/bin/env python3
"""
Live beta org-console audit.

This drives https://beta.elevenidllc.com with Playwright using the beta env
file in this repo. It intentionally uses UI selectors first and records
screenshots, failing requests, page errors, and concise step notes.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urljoin, urlparse
from uuid import UUID

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import expect, sync_playwright


ROOT = Path(__file__).resolve().parents[1]
_cleanup_spec = importlib.util.spec_from_file_location("demo_cleanup_evidence", ROOT / "scripts/demo_cleanup_evidence.py")
_cleanup_module = importlib.util.module_from_spec(_cleanup_spec)
_cleanup_spec.loader.exec_module(_cleanup_module)
owned_api_key_cleanup_proven = _cleanup_module.owned_api_key_cleanup_proven
ENV_FILE = ROOT / ".env.tunnel.beta.local"
ARTIFACT_ROOT = ROOT / "tests" / "artifacts"
RECORDING_VIEWPORT = {"width": 1920, "height": 1080}
CROSS_ORG_SENTINEL = "ffffffff-ffff-ffff-ffff-ffffffffffff"
CROSS_ORG_ADMIN_PATHS = {
    "/v1/credential-templates",
    "/v1/deployment-profiles",
    "/v1/presentation-policies",
    "/v1/trust-profiles",
}
SIGNING_CAPABILITY_SCHEMA = "marty.signing-capability/v1"
SIGNING_PURPOSES = ("vc_jwt_issuer", "oid4vp_request_signing")
KNOWN_SECRETS: set[str] = set()


SECRET_PATTERNS = [
    re.compile(r"mk_live_[A-Za-z0-9_-]*"),
    re.compile(r"mk_test_[A-Za-z0-9_-]*"),
    re.compile(r"pk_live_[A-Za-z0-9_-]*"),
    re.compile(r"pk_test_[A-Za-z0-9_-]*"),
    re.compile(r"whsec_[A-Za-z0-9_-]+"),
    re.compile(r"(\"key\"\s*:\s*\")([^\"\\]+)(\")"),
    re.compile(r"(\"secret\"\s*:\s*\")([^\"\\]+)(\")"),
    re.compile(r"(\"webhook_secret\"\s*:\s*\")([^\"\\]+)(\")"),
    re.compile(r"(\"fullKey\"\s*:\s*\")([^\"\\]+)(\")"),
    re.compile(r"(\"full_key\"\s*:\s*\")([^\"\\]+)(\")"),
]


def start_recorder_capture(required: bool):
    client_file = os.environ.get("DEMO_PYTHON_CAPTURE_CLIENT")
    if not client_file:
        if required:
            raise ValueError("D10 recording and functional qualification require recorder-owned live Python capture")
        return None
    path = Path(client_file)
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != os.environ.get("DEMO_PYTHON_CAPTURE_CLIENT_SHA256")):
        raise ValueError("Recorder-owned Python client source binding is invalid")
    spec = importlib.util.spec_from_file_location("recorder_python_live_evidence", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PythonCapture()


def bound_recorder_inputs(capture, signing_inputs, record_video, recording_pause_ms):
    scenario = capture.inputs["scenario"]
    expected_signing = {"endpoint": signing_inputs["endpoint"], "mount": signing_inputs["mount"],
                        "namespace": signing_inputs["namespace"], "keyReference": signing_inputs["key_reference"],
                        "caCertFile": signing_inputs.get("ca_cert_file", ""),
                        "validatorSha256": signing_inputs["validator_sha256"]}
    if (capture.inputs["origin"] != "https://beta.elevenidllc.com"
            or scenario.get("signing") != expected_signing or scenario.get("recordVideo") is not record_video
            or scenario.get("recordingPauseMs") != recording_pause_ms
            or not re.fullmatch(r"[0-9]{14}-[a-f0-9]{8}", str(scenario.get("runId") or ""))):
        raise ValueError("Actual D10 action inputs differ from recorder-acknowledged inputs")
    return scenario


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        values[key] = value
        os.environ.setdefault(key, value)
    return values


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def redact_sensitive(value: str) -> str:
    if not value:
        return value

    redacted = value
    for secret in sorted(KNOWN_SECRETS, key=len, reverse=True):
        for representation in {secret, json.dumps(secret)[1:-1]}:
            redacted = redacted.replace(representation, "[REDACTED]")
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 3:
            redacted = pattern.sub(r"\1[REDACTED]\3", redacted)
        else:
            redacted = pattern.sub("[REDACTED_API_KEY]", redacted)
    return redacted


def signing_validator_digest(path: str | Path) -> str:
    try:
        with Path(path).open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError:
        raise ValueError("The native signing validator executable is unreadable") from None


def load_signing_inputs(environment: dict[str, str] | None = None) -> dict[str, str]:
    """Resolve real, explicit OpenBao inputs before any browser or mutation."""
    environment = os.environ if environment is None else environment
    required = ["DEMO_D10_KMS_URL", "DEMO_D10_KMS_MOUNT", "DEMO_D10_KMS_KEY_REFERENCE",
                "DEMO_D10_KMS_TOKEN_FILE", "DEMO_SIGNING_CAPABILITY_BIN"]
    if any(not str(environment.get(name) or "").strip() for name in required):
        raise ValueError("D10 requires " + ", ".join(required) + "; no placeholder signer is permitted")
    endpoint = environment["DEMO_D10_KMS_URL"].strip().rstrip("/")
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    if (parsed.scheme != "https" or not host or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
            or host.endswith((".invalid", ".test", ".example"))
            or host in {"example.com", "example.org", "example.net"}):
        raise ValueError("DEMO_D10_KMS_URL must be the real HTTPS OpenBao origin, without credentials or a transit path")
    mount = environment["DEMO_D10_KMS_MOUNT"].strip()
    key_reference = environment["DEMO_D10_KMS_KEY_REFERENCE"].strip()
    namespace = str(environment.get("DEMO_D10_KMS_NAMESPACE") or "").strip()
    if (not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", mount)
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,255}", key_reference)
            or len(namespace) > 255 or any(ord(char) < 32 for char in namespace)):
        raise ValueError("D10 requires a valid transit mount, existing key name, and optional namespace")
    try:
        token_file = Path(environment["DEMO_D10_KMS_TOKEN_FILE"])
        if not token_file.is_file():
            raise ValueError("invalid token file")
        with token_file.open("rb") as stream:
            token_bytes = stream.read(4097)
        if len(token_bytes) > 4096:
            raise ValueError("invalid token file")
        token = token_bytes.decode("ascii").strip()
    except (OSError, ValueError, UnicodeError):
        raise ValueError("DEMO_D10_KMS_TOKEN_FILE must be a bounded readable token file") from None
    if not 16 <= len(token) <= 4096 or any(char.isspace() or ord(char) < 32 for char in token):
        raise ValueError("DEMO_D10_KMS_TOKEN_FILE does not contain a usable transit token")
    ca_cert_file = str(environment.get("DEMO_D10_KMS_CA_CERT_FILE") or "").strip()
    if ca_cert_file and (not ca_cert_file.startswith("/") or len(ca_cert_file) > 4096
                         or any(ord(char) < 32 for char in ca_cert_file)):
        raise ValueError("DEMO_D10_KMS_CA_CERT_FILE must be an absolute file path mounted on the beta signing server")
    KNOWN_SECRETS.add(token)
    validator = Path(environment["DEMO_SIGNING_CAPABILITY_BIN"]).resolve()
    try:
        if not validator.is_file():
            raise ValueError("missing validator")
        validator_sha256 = signing_validator_digest(validator)
        version = subprocess.run([str(validator), "--version"], capture_output=True,
                                 text=True, timeout=10, check=False)
        if (version.returncode != 0 or version.stdout.strip() != SIGNING_CAPABILITY_SCHEMA
                or signing_validator_digest(validator) != validator_sha256):
            raise ValueError("wrong validator")
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ValueError("Build and select the native validate-signing-capability binary before running D10") from None
    return {"endpoint": endpoint, "mount": mount, "namespace": namespace, "ca_cert_file": ca_cert_file,
            "key_reference": key_reference, "token": token, "validator": str(validator),
            "validator_sha256": validator_sha256}


def signing_capability_proven(report: dict[str, Any]) -> bool:
    """Active configuration labels alone never establish a working signer."""
    steps = report.get("steps") or []
    configured = [step.get("signing_configuration") for step in steps
                  if step.get("label") == "kms-service-configured"]
    if len(configured) != 1 or not isinstance(configured[0], dict):
        return False
    scope = configured[0]
    if any(not scope.get(key) for key in ("organization_id", "run_id", "default_service_id")):
        return False
    challenges: set[str] = set()
    for purpose, identity_label, proof_label in [
        ("vc_jwt_issuer", "issuer-identity-active", "issuer-signing-capability-verified"),
        ("oid4vp_request_signing", "verifier-issuer-identity-active", "verifier-signing-capability-verified"),
    ]:
        identities = [step.get("issuer_identity") for step in steps if step.get("label") == identity_label]
        proofs = [step.get("signing_capability") for step in steps if step.get("label") == proof_label]
        if len(identities) != 1 or len(proofs) != 1 or not isinstance(identities[0], dict) or not isinstance(proofs[0], dict):
            return False
        proof, identity = proofs[0], identities[0]
        if (proof.get("schema") != SIGNING_CAPABILITY_SCHEMA or proof.get("verified") is not True
                or proof.get("scope") != "EXACT_PUBLIC_SERVICE_SIGNING_CAPABILITY_ONLY"
                or proof.get("organization_id") != scope["organization_id"]
                or proof.get("run_id") != scope["run_id"]
                or proof.get("service_id") != scope["default_service_id"]
                or not identity.get("issuer_did") or proof.get("issuer_did") != identity["issuer_did"]
                or proof.get("key_purpose") != purpose or identity.get("key_purpose") != purpose
                or identity.get("status") != "active" or identity.get("credential_format") != "SD_JWT_VC"
                or identity.get("algorithm") != "ES256"
                or proof.get("credential_format") != "SD_JWT_VC" or proof.get("algorithm") != "ES256"):
            return False
        for key in ("challenge_sha256", "key_binding_sha256", "public_key_sha256", "signature_sha256",
                    "service_response_sha256", "identity_response_sha256", "signing_response_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(proof.get(key) or "")):
                return False
        challenges.add(proof["challenge_sha256"])
    return len(challenges) == 2


def visible(page: Page, selector: str, timeout: int = 800) -> bool:
    try:
        return page.locator(selector).first.is_visible(timeout=timeout)
    except Exception:
        return False


def text_visible(page: Page, text: str, timeout: int = 800) -> bool:
    try:
        return page.get_by_text(text, exact=False).first.is_visible(timeout=timeout)
    except Exception:
        return False


def body_excerpt(page: Page, limit: int = 1600) -> str:
    try:
        text = page.locator("body").inner_text(timeout=2000)
    except Exception as exc:
        return f"<unable to read body: {exc}>"
    text = re.sub(r"\s+", " ", text).strip()
    return redact_sensitive(text)[:limit]


def mask_api_key_fields(page: Page) -> None:
    try:
        page.evaluate(
            """
            () => {
              const secretPattern = /\b(?:mk|pk)_(?:live|test)_[A-Za-z0-9_-]+|\bwhsec_[A-Za-z0-9_-]+/g;
              for (const element of document.querySelectorAll('input, textarea')) {
                if (typeof element.value === 'string' && secretPattern.test(element.value)) {
                  element.value = element.value.replace(secretPattern, '[REDACTED_API_KEY]');
                  element.setAttribute('value', element.value);
                  secretPattern.lastIndex = 0;
                }
              }
            }
            """
        )
    except Exception:
        pass


def write_redacted_screenshot_placeholder(path: Path, title: str, detail: str) -> bool:
    """Replace a sensitive screenshot with a review-safe placeholder image."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
        return False

    image = Image.new("RGB", (1920, 1080), "#f8fafc")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    heading = redact_sensitive(title)
    lines = [heading, "", *wrap_text(redact_sensitive(detail), width=96)]
    y = 80
    for index, line in enumerate(lines):
        fill = "#0f172a" if index == 0 else "#334155"
        draw.text((80, y), line, fill=fill, font=font)
        y += 26
    image.save(path)
    return True


def wrap_text(value: str, width: int) -> list[str]:
    words = value.split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        candidate = " ".join([*current, word])
        if len(candidate) > width and current:
            lines.append(" ".join(current))
            current = [word]
        else:
            current.append(word)
    if current:
        lines.append(" ".join(current))
    return lines


def wait_for_creating_to_settle(page: Page, timeout: int = 15000) -> bool:
    try:
        page.wait_for_function(
            """
            () => {
              const text = document.body?.innerText || '';
              return !/\\bcreating(?:\\.{3}|\\u2026)/i.test(text);
            }
            """,
            timeout=timeout,
        )
        return True
    except PlaywrightTimeoutError:
        return False


def first_heading(page: Page) -> str:
    for selector in ["h1", "h2", "h3", "[role=heading]"]:
        loc = page.locator(selector)
        try:
            count = loc.count()
            for index in range(min(count, 5)):
                text = loc.nth(index).inner_text(timeout=500).strip()
                if text:
                    return re.sub(r"\s+", " ", text)
        except Exception:
            continue
    return ""


def response_error_code(entry: dict[str, Any]) -> str:
    code = entry.get("error_code")
    if code:
        return str(code)

    body = entry.get("body")
    if isinstance(body, str) and body:
        try:
            payload = json.loads(body)
        except Exception:
            return ""
        if isinstance(payload, dict):
            return str(payload.get("error") or payload.get("code") or "")

    return ""


def is_expected_audit_log_unavailable(entry: dict[str, Any]) -> bool:
    return (
        int(entry.get("status") or 0) == 501
        and "/audit-events" in str(entry.get("url") or "")
        and response_error_code(entry) == "audit_log_unavailable"
    )


def is_expected_entitlement_response(entry: dict[str, Any]) -> bool:
    return (
        int(entry.get("status") or 0) == 403
        and response_error_code(entry) == "plan_feature_unavailable"
    )


def is_expected_cross_org_admin_denial(entry: dict[str, Any]) -> bool:
    """Recognize only the audit's explicit cross-organization access probes."""
    if int(entry.get("status") or 0) != 403:
        return False
    parsed = urlparse(str(entry.get("url") or ""))
    return (
        parsed.path in CROSS_ORG_ADMIN_PATHS
        and parse_qs(parsed.query).get("organization_id") == [CROSS_ORG_SENTINEL]
    )


def is_loading_only_step(step: dict[str, Any]) -> bool:
    body = re.sub(r"\s+", " ", str(step.get("body_excerpt") or "")).strip().lower()
    return body in {
        "loading console...",
        "checking authentication...",
        "opening login...",
    }


def is_expected_navigation_abort(entry: dict[str, Any]) -> bool:
    if str(entry.get("method") or "").upper() != "GET":
        return False
    if str(entry.get("failure") or "") != "net::ERR_ABORTED":
        return False
    return str(entry.get("resource_type") or "") in {"fetch", "xhr"}


def evaluate_release_checks(report: dict[str, Any]) -> dict[str, Any]:
    """Classify beta audit output into release blockers and known degradations."""
    report_text = json.dumps(report, default=str)
    steps = report.get("steps") or []
    bad_responses = report.get("bad_responses") or []
    step_labels = {str(step.get("label") or "") for step in steps}
    required_step_labels = {
        "auth-probe",
        "post-org-probe",
        "kms-service-configured",
        "issuer-identity-active",
        "verifier-issuer-identity-active",
        "issuer-signing-capability-verified",
        "verifier-signing-capability-verified",
        "compliance-profile-available",
        "trust-profile-active",
        "revocation-profile-activated",
        "credential-template-activated",
        "application-template-activated",
        "presentation-policy-active",
        "deployment-profile-active",
        "issuance-flow-active",
        "verification-flow-active",
        "api-key-created",
        "resource-inventory-verified",
        "unauthorized-administration-denied",
    }

    blockers: list[dict[str, Any]] = []
    degraded: list[dict[str, Any]] = []
    expected_entitlements: list[dict[str, Any]] = []
    expected_cross_org_denials: list[dict[str, Any]] = []

    def add_blocker(code: str, message: str, **extra: Any) -> None:
        blockers.append({"code": code, "message": message, **extra})

    def add_degraded(code: str, message: str, **extra: Any) -> None:
        degraded.append({"code": code, "message": message, **extra})

    if "organization_id=null" in report_text:
        add_blocker("null_organization_request", "The audit observed an organization_id=null request.")

    if "/console/org/setup-wizard" in report_text:
        add_blocker("old_setup_wizard", "The retired org setup wizard route appeared in the audit.")

    if "Opening login" in report_text:
        add_blocker("login_interstitial", "The login interstitial appeared during the audit.")

    if "audit-exception" in step_labels:
        add_blocker("audit_exception", "The audit stopped before completing the expected flow.")

    missing_step_labels = sorted(required_step_labels - step_labels)
    if missing_step_labels:
        add_blocker(
            "audit_coverage_incomplete",
            "The audit did not reach all required production credential flow steps.",
            missing_steps=missing_step_labels,
        )

    if not signing_capability_proven(report):
        add_blocker(
            "signing_capability_unverified",
            "Both exact issuer purposes require a fresh, cryptographically verified public signing challenge.",
        )

    raw_secret_hits = [
        pattern.pattern
        for pattern in SECRET_PATTERNS[:5]
        if pattern.search(report_text)
    ]
    if raw_secret_hits:
        add_blocker(
            "raw_secret_in_report",
            "The report contains an unredacted API key or webhook secret pattern.",
            patterns=raw_secret_hits,
        )

    api_key_steps = [
        step for step in steps
        if step.get("label") == "api-key-created"
    ]
    if api_key_steps and not all(step.get("api_key_secret_screenshot_redacted") for step in api_key_steps):
        add_blocker(
            "api_key_screenshot_not_redacted",
            "The API key result step did not record that its screenshot was redacted.",
        )

    if any(is_loading_only_step(step) for step in steps[-2:]):
        add_blocker(
            "terminal_loading_state",
            "The audit ended on a loading/auth/login interstitial state.",
        )

    for response in bad_responses:
        status = int(response.get("status") or 0)
        if status == 503:
            add_blocker(
                "service_503",
                "The audit observed a 503 response.",
                url=response.get("url"),
                message_id=response.get("message_id"),
            )
        elif is_expected_audit_log_unavailable(response):
            add_blocker(
                "audit_log_unavailable",
                "Audit log storage is unavailable; organization audit events must be backed by real storage.",
                status=status,
                url=response.get("url"),
                message_id=response.get("message_id"),
            )
        elif is_expected_cross_org_admin_denial(response):
            expected_cross_org_denials.append(
                {
                    "status": status,
                    "url": response.get("url"),
                    "message_id": response.get("message_id"),
                }
            )
        elif is_expected_entitlement_response(response):
            expected_entitlements.append(
                {
                    "status": status,
                    "url": response.get("url"),
                    "error_code": response_error_code(response),
                }
            )
        elif status >= 400:
            add_blocker(
                "unexpected_bad_response",
                "The audit observed an unexpected 4xx/5xx response.",
                status=status,
                url=response.get("url"),
                message_id=response.get("message_id"),
                error_code=response_error_code(response),
            )

    failed_requests = report.get("failed_requests") or []
    expected_navigation_aborts = [
        entry for entry in failed_requests if is_expected_navigation_abort(entry)
    ]
    unexplained_failed_requests = [
        entry for entry in failed_requests if not is_expected_navigation_abort(entry)
    ]
    if unexplained_failed_requests:
        add_blocker(
            "unexpected_failed_request",
            "The audit observed an unexplained browser request failure.",
            count=len(unexplained_failed_requests),
            requests=unexplained_failed_requests[:10],
        )

    if report.get("page_errors"):
        add_blocker(
            "page_error",
            "The browser reported page errors.",
            count=len(report.get("page_errors") or []),
        )

    if not owned_api_key_cleanup_proven(report):
        add_blocker(
            "owned_api_key_cleanup_unverified",
            "Every run-created API key requires a successful revocation bound to its exact key and organization.",
        )

    transient_loading = [
        step.get("label")
        for step in steps
        if is_loading_only_step(step)
    ]

    return {
        "status": "blocked" if blockers else ("degraded" if degraded else "pass"),
        "blockers": blockers,
        "degraded": degraded,
        "observations": {
            "transient_loading_steps": transient_loading,
            "bad_response_count": len(bad_responses),
            "page_error_count": len(report.get("page_errors") or []),
            "failed_request_count": len(report.get("failed_requests") or []),
            "expected_navigation_aborts": expected_navigation_aborts,
            "expected_entitlement_responses": expected_entitlements,
            "expected_cross_org_admin_denials": expected_cross_org_denials,
            "api_key_secret_screenshot_redacted": bool(
                api_key_steps and all(step.get("api_key_secret_screenshot_redacted") for step in api_key_steps)
            ),
        },
    }


def organization_management_behavior_assertions(report: dict[str, Any]) -> dict[str, bool]:
    """Map the live audit evidence to the exact D-10 behavior contract."""
    labels = {str(step.get("label") or "") for step in report.get("steps") or []}
    return {
        "configure_organization": {"post-org-probe", "resource-inventory-verified"}.issubset(labels),
        "configure_issuer_profiles": {
            "kms-service-configured",
            "issuer-identity-active",
            "verifier-issuer-identity-active",
        }.issubset(labels) and signing_capability_proven(report),
        "configure_trust_and_mip_primitives": {
            "trust-profile-active",
            "revocation-profile-activated",
            "credential-template-activated",
            "application-template-activated",
            "presentation-policy-active",
            "deployment-profile-active",
            "issuance-flow-active",
            "verification-flow-active",
            "api-key-created",
            "resource-inventory-verified",
        }.issubset(labels),
        "unauthorized_administration_denied": "unauthorized-administration-denied" in labels,
    }


def resolve_artifact_dir(run_id: str) -> Path:
    configured = os.environ.get("DEMO_ARTIFACT_DIR", "").strip()
    return Path(configured).resolve() if configured else ARTIFACT_ROOT / f"beta-org-console-audit-{run_id}"


def report_artifact_path(path: Path, artifact_dir: Path) -> str:
    """Keep legacy repo-relative paths while allowing an external recorder directory."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path.relative_to(artifact_dir))


def verified_audit_lifecycle_environment(report: dict[str, Any]) -> dict[str, str]:
    """Return lifecycle IDs proven by one passing organization inventory audit."""
    if report.get("release_checks", {}).get("status") != "pass":
        raise ValueError("cannot export lifecycle resources from a non-passing audit")

    inventory_steps = [
        step
        for step in report.get("steps", [])
        if step.get("label") == "resource-inventory-verified"
    ]
    if len(inventory_steps) != 1:
        raise ValueError("passing audit must contain exactly one verified inventory")

    step = inventory_steps[0]
    required = {
        "BETA_AUDIT_ORG_ID": [str(step.get("organization_id") or "").strip()],
        "BETA_AUDIT_TEMPLATE_ID": [
            str(item.get("id") or "").strip()
            for item in step.get("inventory", [])
            if isinstance(item, dict)
            and item.get("resource_type") == "credential_template"
            and str(item.get("status") or "").lower() == "active"
        ],
        "BETA_AUDIT_POLICY_ID": [
            str(item.get("id") or "").strip()
            for item in step.get("inventory", [])
            if isinstance(item, dict)
            and item.get("resource_type") == "presentation_policy"
            and str(item.get("status") or "").lower() == "active"
        ],
    }
    environment: dict[str, str] = {}
    for name, values in required.items():
        nonempty_values = [value for value in values if value]
        if len(nonempty_values) != 1:
            raise ValueError(f"verified inventory must contain exactly one active {name}")
        value = nonempty_values[0]
        try:
            UUID(value)
        except ValueError as exc:
            raise ValueError(f"verified {name} must be a UUID") from exc
        environment[name] = value

    verifier_dids = [
        str(item.get("id") or "").strip()
        for item in step.get("inventory", [])
        if isinstance(item, dict)
        and item.get("resource_type") == "verifier_issuer_identity"
        and str(item.get("status") or "").lower() == "active"
    ]
    if len(verifier_dids) != 1:
        raise ValueError(
            "verified inventory must contain exactly one active "
            "BETA_AUDIT_VERIFIER_DID"
        )
    verifier_did = verifier_dids[0]
    if not re.fullmatch(r"did:[a-z0-9]+:\S+", verifier_did):
        raise ValueError("verified BETA_AUDIT_VERIFIER_DID must be a DID")
    environment["BETA_AUDIT_VERIFIER_DID"] = verifier_did
    return environment


def verified_audit_organization_id(report: dict[str, Any]) -> str:
    """Return the organization proven with the complete lifecycle inventory."""
    return verified_audit_lifecycle_environment(report)["BETA_AUDIT_ORG_ID"]


def export_audit_lifecycle_environment(
    report: dict[str, Any], github_env: Path
) -> dict[str, str]:
    """Bind later GitHub Actions steps to one verified lifecycle inventory."""
    environment = verified_audit_lifecycle_environment(report)
    with github_env.open("a", encoding="utf-8", newline="\n") as env_file:
        for name, value in environment.items():
            env_file.write(f"{name}={value}\n")
    return environment


def export_audit_organization(report: dict[str, Any], github_env: Path) -> str:
    """Compatibility wrapper returning the verified organization ID."""
    return export_audit_lifecycle_environment(report, github_env)[
        "BETA_AUDIT_ORG_ID"
    ]


class Audit:
    def __init__(
        self,
        page: Page,
        artifact_dir: Path,
        base_url: str,
        recording_pause_ms: int = 0,
    ):
        self.page = page
        self.artifact_dir = artifact_dir
        self.base_url = base_url.rstrip("/")
        self.recording_pause_ms = max(0, recording_pause_ms)
        self.steps: list[dict[str, Any]] = []
        self.console: list[dict[str, str]] = []
        self.failed_requests: list[dict[str, str]] = []
        self.bad_responses: list[dict[str, Any]] = []
        self.interesting_responses: list[dict[str, Any]] = []
        self.page_errors: list[str] = []
        self.created_api_keys: list[dict[str, str]] = []
        self.cleanup_actions: list[dict[str, str]] = []

    @property
    def is_recording(self) -> bool:
        return self.recording_pause_ms > 0

    def show_recording_step(self, label: str, note: str) -> None:
        if not self.is_recording:
            return
        try:
            self.page.evaluate(
                """
                ({ index, label, note }) => {
                  document.getElementById('marty-recording-step')?.remove();
                  const overlay = document.createElement('div');
                  overlay.id = 'marty-recording-step';
                  Object.assign(overlay.style, {
                    position: 'fixed',
                    zIndex: '2147483647',
                    left: '24px',
                    bottom: '24px',
                    maxWidth: '620px',
                    padding: '16px 20px',
                    borderRadius: '8px',
                    background: 'rgba(15, 23, 42, 0.96)',
                    color: '#f8fafc',
                    boxShadow: '0 16px 44px rgba(0, 0, 0, 0.32)',
                    fontFamily: 'Arial, sans-serif',
                    pointerEvents: 'none',
                  });
                  const eyebrow = document.createElement('div');
                  eyebrow.textContent = `MIP primitive management - Step ${index}`;
                  Object.assign(eyebrow.style, {
                    fontSize: '12px',
                    fontWeight: '700',
                    color: '#93c5fd',
                    textTransform: 'uppercase',
                  });
                  const title = document.createElement('div');
                  title.textContent = label;
                  Object.assign(title.style, {
                    marginTop: '5px',
                    fontSize: '24px',
                    fontWeight: '700',
                    lineHeight: '1.2',
                  });
                  const detail = document.createElement('div');
                  detail.textContent = note;
                  Object.assign(detail.style, {
                    marginTop: '7px',
                    fontSize: '15px',
                    lineHeight: '1.4',
                    color: '#e2e8f0',
                  });
                  overlay.append(eyebrow, title, detail);
                  document.body.appendChild(overlay);
                }
                """,
                {
                    "index": len(self.steps),
                    "label": label.replace("-", " ").title(),
                    "note": note or first_heading(self.page) or "Review the current UI state.",
                },
            )
            self.page.wait_for_timeout(self.recording_pause_ms)
        except Exception:
            pass
        finally:
            try:
                self.page.evaluate("() => document.getElementById('marty-recording-step')?.remove()")
            except Exception:
                pass

    def show_privacy_shield(self, title: str, detail: str) -> None:
        if not self.is_recording:
            return
        self.page.evaluate(
            """
            ({ title, detail }) => {
              document.getElementById('marty-recording-privacy-shield')?.remove();
              const shield = document.createElement('div');
              shield.id = 'marty-recording-privacy-shield';
              Object.assign(shield.style, {
                position: 'fixed',
                inset: '0',
                zIndex: '2147483647',
                display: 'grid',
                placeItems: 'center',
                background: '#0f172a',
                color: '#f8fafc',
                fontFamily: 'Arial, sans-serif',
                pointerEvents: 'none',
              });
              const content = document.createElement('div');
              Object.assign(content.style, { maxWidth: '680px', padding: '40px', textAlign: 'center' });
              const heading = document.createElement('div');
              heading.textContent = title;
              Object.assign(heading.style, { fontSize: '30px', fontWeight: '700' });
              const copy = document.createElement('div');
              copy.textContent = detail;
              Object.assign(copy.style, {
                marginTop: '12px',
                fontSize: '17px',
                lineHeight: '1.5',
                color: '#cbd5e1',
              });
              content.append(heading, copy);
              shield.appendChild(content);
              document.body.appendChild(shield);
            }
            """,
            {"title": title, "detail": detail},
        )

    def attach_events(self) -> None:
        self.page.on(
            "console",
            lambda msg: self.console.append(
                {
                    "type": msg.type,
                    "text": redact_sensitive(msg.text)[:1000],
                    "location": f"{msg.location.get('url', '')}:{msg.location.get('lineNumber', '')}",
                }
            )
            if msg.type in {"error", "warning"}
            else None,
        )
        self.page.on("pageerror", lambda err: self.page_errors.append(redact_sensitive(str(err))[:1500]))
        self.page.on(
            "requestfailed",
            self._record_failed_request,
        )
        self.page.on("response", self._record_response)

    def _request_failed_entry(self, req) -> dict[str, str]:
        failure = req.failure
        if isinstance(failure, dict):
            failure_text = failure.get("errorText", "")
        else:
            failure_text = str(failure or "")
        return {
            "method": req.method,
            "url": req.url,
            "failure": failure_text,
            "resource_type": req.resource_type,
        }

    def _record_failed_request(self, req) -> None:
        entry = self._request_failed_entry(req)
        url = entry["url"]
        if "/cdn-cgi/rum" in url:
            return
        if "/v1/notifications/events/push" in url and entry["failure"] == "net::ERR_ABORTED":
            return
        self.failed_requests.append(entry)

    def _record_response(self, response) -> None:
        try:
            status = response.status
            req = response.request
            if req.resource_type not in {"document", "xhr", "fetch"}:
                return

            should_trace = any(
                pattern in response.url
                for pattern in [
                    "/v1/credential-templates",
                    "/v1/trust-profiles",
                    "/v1/presentation-policies",
                    "/v1/deployment-profiles",
                    "/v1/flows",
                    "/v1/api-keys",
                    "/v1/signing-keys",
                    "/v1/organizations",
                    "/v1/me/preferences",
                ]
            )
            entry: dict[str, Any] = {
                "status": status,
                "method": req.method,
                "url": response.url,
                "resource_type": req.resource_type,
            }
            try:
                body = response.text()
                if body:
                    self._remember_created_api_key(req.method, response.url, body)
                    entry["body"] = redact_sensitive(body)[:2000]
                    self._record_response_envelope(entry, body)
            except Exception:
                pass
            try:
                post_data = req.post_data
                if post_data:
                    entry["post_data"] = redact_sensitive(post_data)[:3000]
            except Exception:
                pass
            if status >= 400:
                self.bad_responses.append(entry)
            if should_trace:
                self.interesting_responses.append(entry)
        except Exception:
            return

    def _record_response_envelope(self, entry: dict[str, Any], body: str) -> None:
        try:
            payload = json.loads(body)
        except Exception:
            return
        if not isinstance(payload, dict):
            return

        message_id = payload.get("message_id") or payload.get("messageId") or payload.get("request_id")
        if message_id:
            entry["message_id"] = str(message_id)

        error_description = payload.get("error_description")
        if isinstance(error_description, dict):
            error_code = error_description.get("error") or error_description.get("code")
            error_message = error_description.get("message") or error_description.get("user_message")
        else:
            error_code = payload.get("error") or payload.get("code")
            error_message = error_description

        if error_code:
            entry["error_code"] = str(error_code)
        if error_message:
            entry["error_message"] = redact_sensitive(str(error_message))[:500]

    def _remember_created_api_key(self, method: str, url: str, body: str) -> None:
        if method.upper() != "POST" or "/v1/api-keys" not in url:
            return
        try:
            payload = json.loads(body)
        except Exception:
            return
        key_id = payload.get("id")
        organization_id = payload.get("organization_id")
        if not key_id or not organization_id:
            return
        entry = {
            "id": str(key_id),
            "organization_id": str(organization_id),
            "name": str(payload.get("name") or ""),
        }
        if not any(existing["id"] == entry["id"] for existing in self.created_api_keys):
            self.created_api_keys.append(entry)

    def cleanup_created_api_keys(self) -> None:
        for api_key in self.created_api_keys:
            try:
                result = self.page.evaluate(
                    """
                    async ({ keyId, organizationId }) => {
                      const url = `/v1/api-keys/${encodeURIComponent(keyId)}?organization_id=${encodeURIComponent(organizationId)}`;
                      const response = await fetch(url, {
                        method: 'DELETE',
                        credentials: 'include',
                      });
                      return { status: response.status, ok: response.ok };
                    }
                    """,
                    {
                        "keyId": api_key["id"],
                        "organizationId": api_key["organization_id"],
                    },
                )
                self.cleanup_actions.append({
                    "type": "revoke_api_key",
                    "id": api_key["id"],
                    "organization_id": api_key["organization_id"],
                    "status": str(result.get("status")),
                    "ok": str(bool(result.get("ok"))).lower(),
                })
            except Exception as exc:
                self.cleanup_actions.append({
                    "type": "revoke_api_key",
                    "id": api_key["id"],
                    "organization_id": api_key["organization_id"],
                    "status": "error",
                    "ok": "false",
                    "error": str(exc)[:500],
                })

    def url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(f"{self.base_url}/", path.lstrip("/"))

    def goto(self, path: str, wait: str = "domcontentloaded") -> None:
        self.page.goto(self.url(path), wait_until=wait, timeout=45_000)
        self.settle()

    def settle(self, timeout: int = 3000) -> None:
        try:
            self.page.wait_for_load_state("networkidle", timeout=timeout)
        except PlaywrightTimeoutError:
            pass

    def snapshot(
        self,
        label: str,
        note: str = "",
        extra: dict[str, Any] | None = None,
        redact_screenshot: bool = False,
    ) -> None:
        note = redact_sensitive(note)
        filename = f"{len(self.steps) + 1:02d}-{slugify(label)[:80]}.png"
        screenshot = self.artifact_dir / filename
        scroll_position: dict[str, Any] | None = None
        try:
            scroll_position = self.page.evaluate("() => ({ x: window.scrollX, y: window.scrollY })")
            self.page.evaluate("() => window.scrollTo(0, 0)")
            self.page.wait_for_timeout(100)
            if redact_screenshot:
                redacted = write_redacted_screenshot_placeholder(
                    screenshot,
                    "Screenshot redacted",
                    "This step can display a one-time API key secret. The report keeps the step metadata "
                    "and redacted response details, but the screenshot is replaced to avoid storing live credentials.",
                )
                if not redacted:
                    screenshot = None
            else:
                self.page.screenshot(path=str(screenshot), full_page=True)
        except Exception:
            screenshot = None
        finally:
            if scroll_position:
                try:
                    self.page.evaluate(
                        "(pos) => window.scrollTo(pos.x || 0, pos.y || 0)",
                        scroll_position,
                    )
                except Exception:
                    pass
        self.steps.append(
            {
                "label": label,
                "note": note,
                "url": self.page.url,
                "heading": first_heading(self.page),
                "body_excerpt": body_excerpt(self.page),
                "screenshot": report_artifact_path(screenshot, self.artifact_dir) if screenshot else None,
                **(extra or {}),
            }
        )
        print(f"[audit] {label}: {note or first_heading(self.page) or self.page.url}")
        self.show_recording_step(label, note)

    def click_role(self, role: str, name: str | re.Pattern[str], timeout: int = 5000) -> bool:
        try:
            loc = self.page.get_by_role(role, name=name).first
            loc.wait_for(state="visible", timeout=timeout)
            loc.click(timeout=timeout)
            self.settle()
            return True
        except Exception:
            return False

    def click_text(self, pattern: str | re.Pattern[str], timeout: int = 3000) -> bool:
        try:
            loc = self.page.get_by_text(pattern, exact=False).first
            loc.wait_for(state="visible", timeout=timeout)
            loc.click(timeout=timeout)
            self.settle()
            return True
        except Exception:
            return False

    def click_test_id(self, test_id: str, timeout: int = 3000) -> bool:
        try:
            loc = self.page.get_by_test_id(test_id).first
            loc.wait_for(state="visible", timeout=timeout)
            loc.click(timeout=timeout)
            self.settle()
            return True
        except Exception:
            return False

    def select_mui_option(
        self,
        test_id: str,
        preferred: str | re.Pattern[str] | None = None,
        timeout: int = 3000,
    ) -> bool:
        try:
            container = self.page.get_by_test_id(test_id).first
            container.wait_for(state="visible", timeout=timeout)
            combobox = container if container.get_attribute("role") == "combobox" else container.get_by_role("combobox").first
            combobox.wait_for(state="visible", timeout=timeout)
            expect(combobox).to_be_enabled(timeout=timeout)
            combobox.click(timeout=timeout)
            if preferred is not None:
                option = self.page.get_by_role("option").filter(has_text=preferred).first
            else:
                option = self.page.get_by_role("option").filter(
                    has_not_text=re.compile(r"\b(default|none)\b", re.I)
                ).first
            option.wait_for(state="visible", timeout=timeout)
            option.click(timeout=timeout)
            self.settle()
            return True
        except Exception:
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return False

    def fill_label(self, label: str | re.Pattern[str], value: str, timeout: int = 5000) -> bool:
        try:
            loc = self.page.get_by_label(label).first
            loc.wait_for(state="visible", timeout=timeout)
            loc.fill(value, timeout=timeout)
            return True
        except Exception:
            return False

    def fill_textbox(self, name: str | re.Pattern[str], value: str, timeout: int = 5000) -> bool:
        try:
            loc = self.page.get_by_role("textbox", name=name).first
            loc.wait_for(state="visible", timeout=timeout)
            loc.fill(value, timeout=timeout)
            return True
        except Exception:
            return False

    def report(self) -> dict[str, Any]:
        screenshot_files = [
            step["screenshot"]
            for step in self.steps
            if step.get("screenshot")
        ]
        report = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "base_url": self.base_url,
            "artifact_dir": report_artifact_path(self.artifact_dir, self.artifact_dir),
            "summary": {
                "steps": len(self.steps),
                "screenshots": len(screenshot_files),
                "console_messages": len(self.console),
                "page_errors": len(self.page_errors),
                "failed_requests": len(self.failed_requests),
                "bad_responses": len(self.bad_responses),
                "interesting_responses": len(self.interesting_responses),
                "created_api_keys": len(self.created_api_keys),
                "cleanup_actions": len(self.cleanup_actions),
            },
            "screenshots": screenshot_files,
            "created_api_keys": [
                {k: v for k, v in entry.items() if k != "key"}
                for entry in self.created_api_keys
            ],
            "cleanup_actions": self.cleanup_actions,
            "steps": self.steps,
            "console_messages": self.console[-100:],
            "page_errors": self.page_errors[-50:],
            "failed_requests": self.failed_requests[-100:],
            "bad_responses": self.bad_responses[-200:],
            "interesting_responses": self.interesting_responses[-300:],
        }
        report["release_checks"] = evaluate_release_checks(report)
        report["behaviorAssertions"] = organization_management_behavior_assertions(report)
        report["releaseReady"] = (
            report["release_checks"]["status"] == "pass"
            and all(report["behaviorAssertions"].values())
        )
        return report


def log_in(audit: Audit, email: str, password: str) -> None:
    page = audit.page
    audit.goto("/console")

    # Landing/public app can redirect to Keycloak only after the sign-in button.
    if not visible(page, "#username, input[name='username'], input[type='email']", 1500):
        for name in [
            re.compile(r"sign in to continue", re.I),
            re.compile(r"sign in", re.I),
            re.compile(r"log in|login", re.I),
        ]:
            if audit.click_role("button", name, timeout=2500) or audit.click_role("link", name, timeout=1500):
                break

    # Either classic Keycloak or a two-step login.
    try:
        page.locator("#username, input[name='username'], input[type='email']").first.wait_for(
            state="visible", timeout=12_000
        )
    except PlaywrightTimeoutError:
        if "/login" in page.url and text_visible(page, "Opening login", timeout=1200):
            audit.snapshot(
                "login-interstitial-stuck",
                "Console /login stayed on the Opening login interstitial; bypassing through /v1/auth/login.",
            )
            audit.goto("/v1/auth/login?redirect_uri=/console", wait="domcontentloaded")
            page.locator("#username, input[name='username'], input[type='email']").first.wait_for(
                state="visible", timeout=20_000
            )
        elif text_visible(page, "Dashboard", timeout=1200) or "/console" in page.url:
            audit.snapshot("login-state", "No login form appeared; treating current state as authenticated or console-routed.")
            return
        else:
            raise

    page.locator("#username, input[name='username'], input[type='email']").first.fill(email)
    password_visible = visible(page, "#password, input[type='password']", 1000)
    if password_visible:
        page.locator("#password, input[type='password']").first.fill(password)
        page.locator("#kc-login, button[type='submit'], input[type='submit']").first.click()
    else:
        page.locator("#kc-login, button[type='submit'], input[type='submit'], button:has-text('Next'), button:has-text('Sign In')").first.click()
        page.locator("#password, input[type='password']").first.wait_for(state="visible", timeout=20_000)
        page.locator("#password, input[type='password']").first.fill(password)
        page.locator("#kc-login, button[type='submit'], input[type='submit'], button:has-text('Sign In')").first.click()

    try:
        page.wait_for_url(re.compile(r"/console|beta\.elevenidllc\.com"), timeout=30_000)
    except PlaywrightTimeoutError:
        pass
    audit.settle(5000)
    audit.snapshot("after-login", "Logged in or reached post-auth console state.")


def fetch_json_from_page(page: Page, paths: list[str]) -> dict[str, Any]:
    script = """
    async (paths) => {
      const out = {};
      for (const path of paths) {
        try {
          const res = await fetch(path, { credentials: 'include' });
          const text = await res.text();
          let body = text;
          try { body = JSON.parse(text); } catch (_) {}
          out[path] = { status: res.status, ok: res.ok, body };
        } catch (error) {
          out[path] = { error: String(error) };
        }
      }
      return out;
    }
    """
    return page.evaluate(script, paths)


def active_organization_id(page: Page) -> str:
    organization_id = page.evaluate("() => window.localStorage.getItem('activeOrgId') || ''")
    return str(organization_id or '').strip()


def require_created_organization(page: Page, name: str | None, before: dict[str, Any], after: dict[str, Any]) -> str:
    """Bind the public organization name and fresh active ID before installing credentials."""
    old_probe = before.get("/v1/organizations/mine") or {}
    new_probe = after.get("/v1/organizations/mine") or {}
    old, new = old_probe.get("body"), new_probe.get("body")
    if not name or old_probe.get("status") != 200 or new_probe.get("status") != 200 or not isinstance(old, list) or not isinstance(new, list):
        raise ValueError("D10 could not bind the newly created organization before signer setup")
    active = active_organization_id(page)
    matching = [item for item in new if isinstance(item, dict) and item.get("id") == active and item.get("name") == name]
    if (not active or len(matching) != 1
            or any(isinstance(item, dict) and item.get("id") == active for item in old)):
        raise ValueError("D10 signer setup requires the exact fresh organization created by this run")
    return active


def public_signing_post(page: Page, endpoint: str, organization_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Use the authenticated public Gateway; never call OpenBao from the driver."""
    request_path = f"{endpoint}?organization_id={quote(organization_id, safe='')}"
    return page.evaluate(
        """async ({path, body}) => {
          const response = await fetch(path, {method: 'POST', credentials: 'include',
            headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
          return {status: response.status, body: await response.json().catch(() => null)};
        }""", {"path": request_path, "body": body},
    )


def native_signing_capability(validator: str, mode: str, evidence: dict[str, Any], *,
                              expected_binary_sha256: str | None = None) -> dict[str, Any]:
    serialized = json.dumps(evidence, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > 64 * 1024:
        raise ValueError("Signing capability evidence exceeds its bounded native contract")
    try:
        before = signing_validator_digest(validator)
        if expected_binary_sha256 is not None and before != expected_binary_sha256:
            raise ValueError("native validator bytes changed")
        result = subprocess.run([validator, mode], input=serialized, text=True,
                                capture_output=True, timeout=15, check=False)
        if (result.returncode != 0 or len(result.stdout) > 64 * 1024
                or signing_validator_digest(validator) != before):
            raise ValueError("native rejection")
        receipt = json.loads(result.stdout)
        if not isinstance(receipt, dict) or receipt.get("schema") != SIGNING_CAPABILITY_SCHEMA:
            raise ValueError("invalid native receipt")
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ValueError(f"Native signing capability {mode} failed; no working-signer claim is permitted") from None
    return receipt


def verify_issuer_signing_capabilities(audit: Audit, run_id: str, inputs: dict[str, str]) -> None:
    """Prove both exact public identity tuples without creating a credential."""
    configured = [step.get("signing_configuration") for step in audit.steps if step.get("label") == "kms-service-configured"]
    if len(configured) != 1 or not isinstance(configured[0], dict):
        raise ValueError("No exact run-created signing service is available for the challenge")
    scope = configured[0]
    validator_sha256 = inputs.get("validator_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", str(validator_sha256 or "")):
        raise ValueError("The signing validator executable must be fingerprinted before setup")
    organization_id = active_organization_id(audit.page)
    if scope.get("organization_id") != organization_id or scope.get("run_id") != run_id:
        raise ValueError("Signing challenge organization changed after registration")
    for purpose, identity_label, proof_label in [
        ("vc_jwt_issuer", "issuer-identity-active", "issuer-signing-capability-verified"),
        ("oid4vp_request_signing", "verifier-issuer-identity-active", "verifier-signing-capability-verified"),
    ]:
        identities = [step.get("issuer_identity") for step in audit.steps if step.get("label") == identity_label]
        if len(identities) != 1 or not isinstance(identities[0], dict) or not identities[0].get("issuer_did"):
            raise ValueError("The run did not establish both exact active issuer identities")
        issuer_did = identities[0]["issuer_did"]
        tuple_request = {"organization_id": organization_id, "issuer_did": issuer_did,
                         "key_purpose": purpose, "credential_format": "SD_JWT_VC", "algorithm": "ES256"}
        evidence = {
            "expected": {"run_id": run_id, "nonce": secrets.token_hex(32), **tuple_request,
                         "service_id": scope["default_service_id"], "key_reference": inputs["key_reference"]},
            "service_response": public_signing_post(audit.page, "/v1/signing-keys/config/resolve", organization_id,
                                                    {"key_purpose": purpose, "algorithm": "ES256"}),
            "identity_response": public_signing_post(audit.page, "/v1/signing-keys/issuer-identities/resolve",
                                                     organization_id, tuple_request),
            "signing_response": None,
        }
        prepared = native_signing_capability(inputs["validator"], "prepare", evidence,
                                            expected_binary_sha256=validator_sha256)
        evidence["signing_response"] = public_signing_post(
            audit.page, f"/v1/signing-keys/services/{quote(scope['default_service_id'], safe='')}/sign",
            organization_id, prepared["request"],
        )
        receipt = native_signing_capability(inputs["validator"], "verify", evidence,
                                           expected_binary_sha256=validator_sha256)
        if receipt.get("verified") is not True:
            raise ValueError("Native signing capability did not confirm the signature")
        validator_provenance = {"sha256": validator_sha256, "contract_version": SIGNING_CAPABILITY_SCHEMA,
                                "scope": "LOCAL_EXECUTABLE_BYTES_NOT_DEPLOYED_BUILD_ATTESTATION"}
        artifact_json = json.dumps({"input": evidence, "receipt": receipt, "validator": validator_provenance}, indent=2) + "\n"
        if any(secret in artifact_json or json.dumps(secret)[1:-1] in artifact_json for secret in KNOWN_SECRETS):
            raise ValueError("The signing response contained credential material; refusing to retain the evidence")
        artifact = audit.artifact_dir / f"signing-capability-{purpose}.json"
        artifact.write_text(artifact_json, encoding="utf-8")
        audit.snapshot(proof_label,
            f"The configured service signed a fresh {purpose} challenge; Rust verified it against the exact public issuer key. No credential or wallet session was created.",
            {"signing_capability": receipt, "evidence_artifact": artifact.name,
             "validator": validator_provenance,
             "evidence_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()},
        )


def fetch_org_collection(page: Page, path: str, organization_id: str) -> dict[str, Any]:
    separator = '&' if '?' in path else '?'
    request_path = f"{path}{separator}organization_id={organization_id}"
    return fetch_json_from_page(page, [request_path]).get(request_path) or {}


def collection_items(probe: dict[str, Any]) -> list[dict[str, Any]]:
    body = probe.get("body")
    if isinstance(body, list):
        return [item for item in body if isinstance(item, dict)]
    if not isinstance(body, dict):
        return []
    for candidate in (
        body.get("data"),
        body.get("items"),
        body.get("identities"),
        body.get("profiles"),
        body.get("keys"),
        body.get("services"),
    ):
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
    nested_data = body.get("data")
    if isinstance(nested_data, dict) and isinstance(nested_data.get("items"), list):
        return [item for item in nested_data["items"] if isinstance(item, dict)]
    return []


def find_named_resource(probe: dict[str, Any], name: str) -> dict[str, Any] | None:
    return next((item for item in collection_items(probe) if item.get("name") == name), None)


def find_resource_with_name(probe: dict[str, Any], name_fragment: str) -> dict[str, Any] | None:
    return next(
        (
            item
            for item in collection_items(probe)
            if name_fragment in str(item.get("name") or "")
        ),
        None,
    )


def find_issuer_identity(
    probe: dict[str, Any],
    issuer_did: str,
    *,
    key_purpose: str = "vc_jwt_issuer",
    credential_format: str = "SD_JWT_VC",
    algorithm: str = "ES256",
) -> dict[str, Any] | None:
    return next(
        (
            item
            for item in collection_items(probe)
            if item.get("issuer_did") == issuer_did
            and item.get("key_purpose") == key_purpose
            and item.get("credential_format") == credential_format
            and item.get("algorithm") == algorithm
        ),
        None,
    )


def find_audit_issuer_identity(
    probe: dict[str, Any],
    run_id: str,
) -> dict[str, Any] | None:
    return next(
        (
            item
            for item in collection_items(probe)
            if str(item.get("issuer_did") or "").endswith(
                f":orgs:audit-production-flow-{run_id}"
            )
            and is_active(item)
        ),
        None,
    )


def is_active(resource: dict[str, Any] | None) -> bool:
    return bool(resource) and (
        str(resource.get("status") or "").strip().lower() == "active"
        or resource.get("is_active") is True
        or resource.get("enabled") is True
    )


def wait_for_named_resource(
    page: Page,
    path: str,
    organization_id: str,
    name: str,
    *,
    partial_name: bool = False,
    timeout: int = 15_000,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    deadline = time.monotonic() + (timeout / 1000)
    last_probe: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_probe = fetch_org_collection(page, path, organization_id)
        resource = (
            find_resource_with_name(last_probe, name)
            if partial_name
            else find_named_resource(last_probe, name)
        )
        if is_active(resource):
            return resource, last_probe
        page.wait_for_timeout(250)
    return None, last_probe


def wait_for_issuer_identity(
    page: Page,
    organization_id: str,
    issuer_did: str,
    *,
    key_purpose: str = "vc_jwt_issuer",
    credential_format: str = "SD_JWT_VC",
    algorithm: str = "ES256",
    timeout: int = 60_000,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    deadline = time.monotonic() + (timeout / 1000)
    last_probe: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_probe = fetch_org_collection(
            page,
            "/v1/signing-keys/issuer-identities",
            organization_id,
        )
        identity = find_issuer_identity(
            last_probe,
            issuer_did,
            key_purpose=key_purpose,
            credential_format=credential_format,
            algorithm=algorithm,
        )
        if is_active(identity):
            return identity, last_probe
        page.wait_for_timeout(250)
    return None, last_probe


def provision_verifier_issuer_identity(
    page: Page,
    organization_id: str,
    issuer_did: str,
    run_id: str,
) -> dict[str, Any]:
    """Ensure the public DID tuple required to sign OID4VP requests."""
    return page.evaluate(
        """
        async (payload) => {
          const response = await fetch('/v1/signing-keys/issuer-identities', {
            method: 'POST',
            credentials: 'include',
            headers: {
              'Content-Type': 'application/json',
              'Idempotency-Key': payload.idempotency_key,
            },
            body: JSON.stringify({
              organization_id: payload.organization_id,
              issuer_did: payload.issuer_did,
              key_purpose: 'oid4vp_request_signing',
              credential_format: 'SD_JWT_VC',
              algorithm: 'ES256',
            }),
          });
          const body = await response.json().catch(() => null);
          return {
            status: response.status,
            ok: response.ok,
            created: body?.created === true,
            error: response.ok ? null : body?.detail || body?.message || 'Provisioning failed.',
          };
        }
        """,
        {
            "organization_id": organization_id,
            "issuer_did": issuer_did,
            "idempotency_key": f"beta-audit-oid4vp-{run_id}",
        },
    )


def create_org(audit: Audit, run_id: str, email: str) -> str | None:
    page = audit.page
    slug = f"audit-prod-flow-{run_id}"
    display = f"Audit Production Flow {run_id}"
    audit.goto("/console/organizations/create")
    audit.snapshot("create-org-opened", "Opened the create organization screen.")

    if text_visible(page, "Organization creation is disabled", 1000):
        audit.snapshot("create-org-disabled", "Organization creation is disabled on this deployment.")
        return None

    filled = [
        audit.fill_label(re.compile(r"organization slug", re.I), slug),
        audit.fill_label(re.compile(r"display name", re.I), display),
        audit.fill_label(re.compile(r"description", re.I), "Playwright beta audit org for production credential-flow UX."),
        audit.fill_label(re.compile(r"contact email", re.I), email),
    ]
    try:
        form = page.locator("[data-testid='create-organization-form']")
        # MUI outlined labels can be brittle in automation because label text is
        # duplicated; fall back to visible form field order.
        text_inputs = form.locator("input:not([type='hidden'])")
        if text_inputs.count() >= 2:
            if not text_inputs.nth(0).input_value(timeout=500).strip():
                text_inputs.nth(0).fill(slug)
            if not text_inputs.nth(1).input_value(timeout=500).strip():
                text_inputs.nth(1).fill(display)
        textarea = form.locator("textarea").first
        if textarea.count() and not textarea.input_value(timeout=500).strip():
            textarea.fill("Playwright beta audit org for production credential-flow UX.")
    except Exception:
        pass
    if not any(filled):
        try:
            if page.locator("[data-testid='create-organization-form'] input:not([type='hidden'])").count() >= 2:
                filled = [True]
        except Exception:
            pass
    if not any(filled):
        audit.snapshot("create-org-fields-missing", "Could not fill organization form with accessible labels or form-order fallback.")
        return None

    audit.snapshot("create-org-filled", f"Filled org form for {slug}.")
    audit.click_role("button", re.compile(r"create organization", re.I), timeout=5000)
    try:
        page.wait_for_url(re.compile(r"/console/org|/console/organizations"), timeout=20_000)
    except PlaywrightTimeoutError:
        pass
    wait_for_creating_to_settle(page, timeout=25000)
    audit.settle(5000)
    audit.snapshot("create-org-submitted", "Submitted org creation.")
    return slug


def selected_signing_service(config: dict[str, Any]) -> dict[str, Any] | None:
    services = config.get("services")
    default_id = config.get("default_service_id")
    if not isinstance(services, list) or not isinstance(default_id, str):
        return None
    return next(
        (
            service
            for service in services
            if isinstance(service, dict)
            and service.get("id") == default_id
            and service.get("status") in {"active", "configured", "registered"}
        ),
        None,
    )


def create_key_service_if_possible(audit: Audit, run_id: str, inputs: dict[str, str]) -> None:
    """Register the declared real OpenBao service through the product controls."""
    page = audit.page
    organization_id = active_organization_id(page)
    if not organization_id:
        raise ValueError("D10 requires a fresh active organization before service registration")
    audit.goto("/console/org/deploy/key-management/services/new")
    audit.snapshot("kms-service-wizard-opened", "Opened Register Key Management Service.")
    if not audit.click_role("button", re.compile(r"^OpenBao Transit", re.I), timeout=3000):
        raise ValueError("The declared OpenBao Transit provider control is unavailable")
    audit.snapshot("kms-provider-selected", "Selected the declared OpenBao Transit provider.")
    if not audit.click_role("button", re.compile(r"^next$", re.I), timeout=3000):
        raise ValueError("The OpenBao connection step is unavailable")
    fields = [(r"^service name", f"Audit Transit Service {run_id}"),
              (r"^service url", inputs["endpoint"]), (r"^transit mount", inputs["mount"]),
              (r"^transit token", inputs["token"])]
    if inputs["namespace"]:
        fields.append((r"^namespace", inputs["namespace"]))
    if inputs.get("ca_cert_file"):
        fields.append((r"^TLS CA certificate file", inputs["ca_cert_file"]))
    if page.get_by_label(re.compile(r"^transit token", re.I)).first.get_attribute("type") != "password":
        raise ValueError("The deployed transit token field must mask its value before capture")
    for label, value in fields:
        if not audit.fill_label(re.compile(label, re.I), value):
            raise ValueError("A required OpenBao connection control is unavailable")
    # Password input masking protects the video. Playwright tracing has not yet
    # started: neither fill arguments nor request bodies containing this token
    # may be captured. Known token values are also excluded from audit logs.
    audit.snapshot("kms-connection-filled", "Entered the declared OpenBao connection; the token is hidden and this setup interval is excluded from the trace.")
    if not audit.click_role("button", re.compile(r"^next$", re.I), timeout=3000):
        raise ValueError("The declared OpenBao connection did not pass form validation")
    key_field = page.get_by_label(re.compile(r"^transit key name(?:\s*\*)?$", re.I))
    if key_field.count() != 1:
        raise ValueError("The real transit key selector is unavailable or ambiguous")
    key_field.fill(inputs["key_reference"], timeout=5000)
    for purpose in [r"^VC JWT \/ SD-JWT issuer(?:\s|$)", r"^OID4VP request signing(?:\s|$)"]:
        page.get_by_role("checkbox", name=re.compile(purpose, re.I)).check(timeout=3000)
    page.get_by_role("checkbox", name="Use as the default signing service", exact=True).check(timeout=3000)
    audit.snapshot("kms-key-access-filled", "Selected the existing ES256 key for credential issuance and OID4VP request signing.")
    if not audit.click_role("button", re.compile(r"^next$", re.I), timeout=3000):
        raise ValueError("The declared OpenBao key access did not pass form validation")
    audit.snapshot("kms-review", "Reviewed the real OpenBao registration before submission.")
    endpoint = f"/v1/signing-keys/config?organization_id={quote(organization_id, safe='')}"
    with page.expect_response(lambda response: response.request.method == "PATCH"
                              and response.url == audit.base_url + endpoint, timeout=30000) as observed:
        if not audit.click_role("button", re.compile(r"^register service$", re.I), timeout=5000):
            raise ValueError("The real service registration control is unavailable")
    if not observed.value.ok:
        raise ValueError("The public signing service registration did not succeed")
    # A full navigation discards the token-bearing form before starting tracing.
    audit.goto("/console/org/deploy/key-management/services")
    if active_organization_id(page) != organization_id:
        raise ValueError("Organization scope changed during signing service registration")
    probe = fetch_org_collection(page, "/v1/signing-keys/config", organization_id)
    config = probe.get("body") if isinstance(probe.get("body"), dict) else {}
    service = selected_signing_service(config)
    if (probe.get("status") != 200 or service is None
            or service.get("name") != f"Audit Transit Service {run_id}"
            or service.get("service_type") != "openbao-transit"
            or str(service.get("endpoint") or "").rstrip("/") != inputs["endpoint"]
            or service.get("mount") != inputs["mount"]
            or str(service.get("namespace") or "") != inputs["namespace"]
            or str(service.get("ca_cert_file") or "") != inputs.get("ca_cert_file", "")
            or service.get("key_reference") != inputs["key_reference"]
            or not set(SIGNING_PURPOSES).issubset(service.get("key_purposes") or [])
            or "ES256" not in (service.get("algorithms") or [])):
        raise ValueError("The exact run-created signing configuration was not selected")
    audit.snapshot("kms-service-configured",
        "Registered the real signing service; active metadata alone is not a capability result.",
        {"signing_configuration": {"organization_id": organization_id, "run_id": run_id,
         "default_service_id": service["id"], "service_count": len(config["services"])}},
    )


def create_issuer_identity(audit: Audit, run_id: str) -> None:
    page = audit.page
    audit.goto("/console/org/deploy/issuer-identity/new")
    audit.snapshot("issuer-identity-wizard-opened", "Opened issuer identity wizard.")

    if text_visible(page, "No key management service", 1000) or text_visible(page, "No signing service registered", 1000):
        audit.snapshot("issuer-identity-blocked", "Issuer identity creation is blocked because no signing service is registered.")
        return

    if text_visible(page, "No signing keys discovered", 1000):
        audit.snapshot("issuer-identity-recommendation", "Issuer identity wizard warned that the signing service has no keys yet.")
        if not audit.click_role("button", re.compile(r"use managed key creation|continue and create key", re.I), timeout=4000):
            audit.click_role("button", re.compile(r"continue anyway", re.I), timeout=3000)
        if not text_visible(page, "Choose a DID method", 1000) and text_visible(page, "No signing keys discovered", 1000):
            audit.snapshot("issuer-identity-continue-unavailable", "Continue Anyway was unavailable after the signing-key recommendation.")
            return

    issuer_did_input = page.get_by_label(re.compile(r"^Issuer DID", re.I)).first
    issuer_did = issuer_did_input.input_value(timeout=3000).strip()
    if not issuer_did.startswith("did:"):
        audit.snapshot("issuer-identity-invalid-did", "Issuer identity wizard did not provide a valid DID.")
        return
    audit.snapshot(
        "issuer-identity-filled",
        "Confirmed the provider-neutral issuer DID and signing tuple.",
        {"issuer_did": issuer_did},
    )
    if not audit.click_role(
        "button",
        re.compile(r"^create managed identity$", re.I),
        timeout=5000,
    ):
        audit.snapshot("issuer-identity-submit-blocked", "Create managed identity was unavailable.")
        return

    organization_id = active_organization_id(page)
    issuer, probe = wait_for_issuer_identity(page, organization_id, issuer_did)
    if not is_active(issuer):
        audit.snapshot(
            "issuer-identity-state-mismatch",
            "The run-created issuer identity did not become active through the public DID-first API.",
            {"issuer_did": issuer_did, "probe": probe},
        )
        return
    try:
        page.wait_for_url(
            re.compile(r"/console/org/deploy/issuer-identity/?$"),
            timeout=30_000,
        )
    except PlaywrightTimeoutError:
        audit.snapshot(
            "issuer-identity-submit-unsettled",
            "The public issuer identity became active, but the UI submission did not complete.",
            {"issuer_did": issuer_did},
        )
        return
    audit.snapshot(
        "issuer-identity-active",
        "Created an active issuer identity.",
        {
            "issuer_identity": {
                "issuer_did": issuer.get("issuer_did"),
                "key_purpose": issuer.get("key_purpose"),
                "credential_format": issuer.get("credential_format"),
                "algorithm": issuer.get("algorithm"),
                "status": issuer.get("status"),
            }
        },
    )

    verifier_result = provision_verifier_issuer_identity(
        page,
        organization_id,
        issuer_did,
        run_id,
    )
    verifier, verifier_probe = wait_for_issuer_identity(
        page,
        organization_id,
        issuer_did,
        key_purpose="oid4vp_request_signing",
        credential_format="SD_JWT_VC",
        algorithm="ES256",
    )
    if not verifier_result.get("ok") or not is_active(verifier):
        audit.snapshot(
            "verifier-issuer-identity-state-mismatch",
            "The public OID4VP request-signing identity did not become active.",
            {
                "provisioning": verifier_result,
                "issuer_did": issuer_did,
                "probe": verifier_probe,
            },
        )
        return
    audit.snapshot(
        "verifier-issuer-identity-active",
        "Created an active public OID4VP request-signing identity.",
        {
            "issuer_identity": {
                "issuer_did": verifier.get("issuer_did"),
                "key_purpose": verifier.get("key_purpose"),
                "credential_format": verifier.get("credential_format"),
                "algorithm": verifier.get("algorithm"),
                "status": verifier.get("status"),
            },
            "created": bool(verifier_result.get("created")),
        },
    )


def create_trust_profile(audit: Audit, run_id: str) -> None:
    page = audit.page
    audit.goto("/console/org/trust/profiles/new")
    audit.snapshot("trust-profile-wizard-opened", "Opened trust profile wizard.")

    name = f"Audit Trust Profile {run_id}"
    if not audit.fill_label(re.compile(r"name", re.I), name):
        audit.fill_textbox(re.compile(r"name", re.I), name)
    audit.fill_label(re.compile(r"description", re.I), "Trust profile created during beta UI audit.")
    audit.snapshot("trust-basics-filled", "Filled trust profile basics.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("trust-basics-next-blocked", "Next was unavailable after trust basics.")
        return

    organization_id = active_organization_id(page)
    identity_probe = fetch_org_collection(
        page,
        "/v1/signing-keys/issuer-identities",
        organization_id,
    )
    issuer = find_audit_issuer_identity(identity_probe, run_id)
    if issuer is None:
        audit.snapshot(
            "trust-managed-issuer-blocked",
            "Trust Profile creation stopped because the public issuer identity was unavailable.",
            {"issuer_identity_probe": identity_probe},
        )
        return

    try:
        page.get_by_test_id("wizard.trustProfile.issuerDid").fill(
            str(issuer["issuer_did"]),
            timeout=5000,
        )
        page.get_by_label(re.compile(r"^Name$", re.I)).first.fill(
            "Audit Issuer",
            timeout=3000,
        )
    except PlaywrightError as exc:
        audit.snapshot(
            "trust-issuer-did-fill-blocked",
            "The Trust Profile DID issuer fields were unavailable.",
            {"selector_error": repr(exc)},
        )
        return
    if not audit.click_test_id("wizard.trustProfile.addIssuer", timeout=5000):
        audit.snapshot("trust-issuer-add-blocked", "The audit issuer DID could not be added.")
        return
    audit.snapshot(
        "trust-source-added",
        "Added the public audit issuer DID as an explicit trust source.",
        {"issuer_did": issuer.get("issuer_did")},
    )

    if not audit.click_test_id("wizard.trustProfile.next", timeout=5000):
        audit.snapshot("trust-source-next-blocked", "Next was unavailable after adding the issuer DID.")
        return
    audit.snapshot("trust-validation-opened", "Reached the optional cryptographic policy step.")
    if not audit.click_test_id("wizard.trustProfile.skip", timeout=5000):
        audit.snapshot("trust-validation-skip-blocked", "The optional cryptographic policy step could not be skipped.")
        return
    audit.snapshot("trust-review-opened", "Reviewed the DID-scoped Trust Profile before activation.")
    if not audit.click_test_id("wizard.trustProfile.submit", timeout=5000):
        audit.snapshot("trust-profile-submit-blocked", "Create and Activate was unavailable.")
        return

    profile, probe = wait_for_named_resource(
        page,
        "/v1/trust-profiles",
        organization_id,
        name,
        timeout=60_000,
    )
    if not is_active(profile):
        audit.snapshot(
            "trust-profile-state-mismatch",
            "The run-created Trust Profile was not active.",
            {"trust_profile_probe": probe},
        )
        return
    audit.snapshot(
        "trust-profile-active",
        "Created an active Trust Profile.",
        {"trust_profile": {"id": profile.get("id"), "name": profile.get("name"), "status": profile.get("status")}},
    )


def create_revocation_profile(audit: Audit, run_id: str) -> None:
    page = audit.page
    audit.goto("/console/org/trust/revocation/new")
    audit.snapshot("revocation-profile-wizard-opened", "Opened Revocation Profile creation.")

    name = f"Audit Lifecycle Status {run_id}"
    if not audit.fill_label(re.compile(r"profile name", re.I), name):
        audit.fill_textbox(re.compile(r"profile name", re.I), name)
    audit.fill_label(
        re.compile(r"description", re.I),
        "Lifecycle status profile created during the beta organization audit.",
    )
    audit.snapshot("revocation-profile-filled", "Configured an always-check Status List profile.")

    if not audit.click_role("button", re.compile(r"create profile", re.I), timeout=5000):
        audit.snapshot("revocation-profile-create-blocked", "Create Profile was unavailable.")
        return
    try:
        page.wait_for_url(re.compile(r"/console/org/trust/revocation/[^/]+$"), timeout=20_000)
    except PlaywrightTimeoutError:
        audit.snapshot("revocation-profile-create-timeout", "Revocation Profile detail did not open.")
        return
    audit.settle(2000)
    audit.snapshot("revocation-profile-created", "Created a draft Revocation Profile.")

    if not audit.click_role("button", re.compile(r"^activate$", re.I), timeout=5000):
        audit.snapshot("revocation-profile-activation-blocked", "Activate was unavailable for the draft profile.")
        return
    try:
        expect(page.get_by_text(re.compile(r"^ACTIVE$", re.I)).first).to_be_visible(timeout=20_000)
    except (AssertionError, PlaywrightError):
        audit.snapshot("revocation-profile-activation-timeout", "Revocation Profile did not become active.")
        return
    audit.snapshot("revocation-profile-activated", "Created and activated the lifecycle status dependency.")


def create_credential_template(audit: Audit, run_id: str) -> None:
    page = audit.page
    audit.goto("/console/org/templates/credentials/new")
    audit.snapshot("credential-template-wizard-opened", "Opened credential template wizard.")

    name = f"Audit Employee Credential {run_id}"
    audit.fill_label(re.compile(r"template name", re.I), name)
    audit.fill_label(re.compile(r"vct|verifiable credential type", re.I), f"com.elevenid.audit.employee.{run_id}")
    audit.fill_label(re.compile(r"description", re.I), "Employee credential template created during beta UI audit.")
    audit.snapshot("template-basics-filled", "Filled template basics.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("template-basics-next-blocked", "Next unavailable after template basics.")
        return

    if not audit.click_role("button", re.compile(r"employee", re.I), timeout=2000):
        audit.fill_label(re.compile(r"claim name|name", re.I), "employee_id")
        audit.click_role("button", re.compile(r"add", re.I), timeout=1000)
    audit.snapshot("template-claims-filled", "Added credential claims.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("template-claims-next-blocked", "Next unavailable after claims.")
        return

    # If exactly one trust profile exists the app may auto-select it. Otherwise select the current run's profile.
    audit.select_mui_option(
        "template-trust-profile-select",
        re.compile(rf"Audit Trust Profile {run_id}|Audit Trust Profile|Marty", re.I),
        timeout=3000,
    )
    audit.snapshot("template-trust-selected", "Selected trust profile if required.")
    if not audit.select_mui_option(
        "template-compliance-profile-select",
        re.compile(r"OID4VC Core|OID4VC", re.I),
        timeout=5000,
    ):
        audit.snapshot("template-compliance-blocked", "The active system Compliance Profile was unavailable.")
        return
    audit.snapshot("compliance-profile-available", "Selected the active OID4VC system Compliance Profile.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("template-trust-next-blocked", "Next unavailable after trust selection.")
        return

    try:
        revocation_select = page.locator("#credential-template-revocation-profile").first
        revocation_select.wait_for(state="visible", timeout=10_000)
        expect(revocation_select).to_be_enabled(timeout=10_000)
        revocation_select.click(timeout=5000)
        revocation_option = page.get_by_role("option").filter(
            has_text=re.compile(rf"Audit Lifecycle Status {run_id}|Audit Lifecycle Status", re.I)
        ).first
        revocation_option.wait_for(state="visible", timeout=5000)
        revocation_option.click(timeout=5000)
        audit.snapshot("template-revocation-selected", "Selected the active Revocation Profile.")
    except Exception:
        audit.snapshot("template-revocation-selection-blocked", "The active Revocation Profile was unavailable.")
        return

    for index in range(5):
        if audit.click_role("button", re.compile(r"create|submit|activate", re.I), timeout=1200):
            break
        if audit.click_role("button", re.compile(r"skip", re.I), timeout=1200):
            audit.snapshot(f"template-skip-{index + 1}", "Skipped optional template step.")
            continue
        if not audit.click_role("button", re.compile(r"next", re.I), timeout=2000):
            break
        audit.snapshot(f"template-next-{index + 1}", "Advanced template wizard one step.")
    wait_for_creating_to_settle(page, timeout=15000)
    audit.settle(5000)
    try:
        expect(page.get_by_text(re.compile(r"now active", re.I)).first).to_be_visible(timeout=20_000)
    except (AssertionError, PlaywrightError):
        audit.snapshot("credential-template-activation-blocked", "Credential Template did not become active.")
        return

    organization_id = active_organization_id(page)
    probe = fetch_org_collection(page, "/v1/credential-templates", organization_id)
    template = find_named_resource(probe, name)
    if not template or str(template.get("status") or "").strip().lower() != "active":
        audit.snapshot(
            "credential-template-state-mismatch",
            "The UI reported success but the canonical Credential Template was not active.",
            {"credential_template_probe": probe},
        )
        return
    audit.snapshot(
        "credential-template-activated",
        "Created and activated the Credential Template.",
        {"credential_template": {"id": template.get("id"), "name": template.get("name"), "status": template.get("status")}},
    )


def create_application_template(audit: Audit, run_id: str) -> None:
    page = audit.page
    audit.goto("/console/org/templates/applications/new?mode=advanced")
    audit.snapshot("application-template-editor-opened", "Opened Application Template authoring.")

    try:
        credential_select = page.get_by_role(
            "combobox",
            name=re.compile(r"^credential template", re.I),
        ).first
        credential_select.wait_for(state="visible", timeout=10_000)
        expect(credential_select).to_be_enabled(timeout=10_000)
        credential_select.click(timeout=5000)
        option = page.get_by_role("option").filter(
            has_text=re.compile(rf"Audit Employee Credential {run_id}", re.I)
        ).first
        option.wait_for(state="visible", timeout=5000)
        option.click(timeout=5000)
    except Exception as exc:
        audit.snapshot(
            "application-template-credential-blocked",
            "The active Credential Template was unavailable.",
            {"selector_error": repr(exc)},
        )
        return

    audit.fill_label(re.compile(r"^name", re.I), f"Audit Employee Application {run_id}")
    audit.fill_label(
        re.compile(r"description", re.I),
        "Applicant contract created during the beta organization audit.",
    )
    audit.snapshot("application-template-filled", "Configured the Application Template contract.")

    if not audit.click_role("button", re.compile(r"save draft", re.I), timeout=5000):
        audit.snapshot("application-template-save-blocked", "Save Draft was unavailable.")
        return
    try:
        page.wait_for_url(re.compile(r"/console/org/templates/applications/[^/]+$"), timeout=30_000)
    except PlaywrightTimeoutError:
        audit.snapshot("application-template-save-timeout", "Application Template detail did not open.")
        return
    audit.settle(3000)

    activate = page.get_by_role("button", name=re.compile(r"^activate$", re.I)).first
    try:
        activate.wait_for(state="visible", timeout=20_000)
        expect(activate).to_be_enabled(timeout=20_000)
        activate.click(timeout=5000)
        expect(page.get_by_text(re.compile(r"^ACTIVE$", re.I)).first).to_be_visible(timeout=20_000)
    except (AssertionError, PlaywrightError, PlaywrightTimeoutError):
        audit.snapshot("application-template-activation-blocked", "Application Template did not become active.")
        return
    organization_id = active_organization_id(page)
    probe = fetch_org_collection(page, "/v1/application-templates", organization_id)
    template = find_named_resource(probe, f"Audit Employee Application {run_id}")
    if not is_active(template):
        audit.snapshot("application-template-state-mismatch", "The canonical Application Template was not active.")
        return
    audit.snapshot(
        "application-template-activated",
        "Created and activated the Application Template.",
        {"application_template": {"id": template.get("id"), "name": template.get("name"), "status": template.get("status")}},
    )


def create_policy_and_deployment(audit: Audit, run_id: str) -> None:
    page = audit.page

    audit.goto("/console/org/policies/presentation/new")
    audit.snapshot("presentation-policy-wizard-opened", "Opened presentation policy wizard.")
    if not audit.click_role("button", re.compile(rf"Select Audit Trust Profile {run_id}", re.I), timeout=3000):
        if not audit.click_role("button", re.compile(r"Audit Trust Profile|Marty|Trust Profile", re.I), timeout=3000):
            audit.click_text(re.compile(r"Audit Trust Profile|Marty", re.I), timeout=1500)
    audit.snapshot("policy-trust-selected", "Selected a trust profile if present.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=2500):
        audit.snapshot("policy-trust-next-blocked", "Next unavailable after selecting a trust profile.")
        return

    if not audit.click_role("button", re.compile(rf"Select Audit Employee Credential {run_id}", re.I), timeout=5000):
        if not audit.click_role("button", re.compile(r"Audit Employee Credential|Employee Access Verification|Custom Policy|Identity Verification", re.I), timeout=3000):
            audit.click_text(re.compile(r"Audit Employee Credential|Employee Access Verification|Custom Policy|Identity Verification", re.I), timeout=1500)
    audit.snapshot("policy-template-selected", "Selected the audit credential template or a fallback presentation policy template.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=2500):
        audit.snapshot("policy-template-next-blocked", "Next unavailable after selecting a policy template.")
        return

    audit.fill_label(re.compile(r"name", re.I), f"Audit Verification Policy {run_id}")
    audit.fill_label(re.compile(r"purpose", re.I), "Verify audit employee credential")
    # Add a required claim if UI requires it.
    audit.fill_label(re.compile(r"claim", re.I), "employee_id")
    audit.click_role("button", re.compile(r"add", re.I), timeout=1000)
    audit.snapshot("policy-claims-filled", "Filled policy claims where possible.")
    for index in range(4):
        if audit.click_role("button", re.compile(r"create|submit|finish", re.I), timeout=1200):
            break
        if audit.click_role("button", re.compile(r"skip", re.I), timeout=1200):
            continue
        if not audit.click_role("button", re.compile(r"next", re.I), timeout=1600):
            break
    audit.settle(5000)
    organization_id = active_organization_id(page)
    policy_name = f"Audit Verification Policy {run_id}"
    policy, policy_probe = wait_for_named_resource(
        page,
        "/v1/presentation-policies",
        organization_id,
        policy_name,
    )
    if not is_active(policy):
        audit.snapshot("presentation-policy-state-mismatch", "The run-created Presentation Policy was not active.")
        return
    audit.snapshot(
        "presentation-policy-active",
        "Created an active Presentation Policy bound to the audit credential.",
        {"presentation_policy": {"id": policy.get("id"), "name": policy.get("name"), "status": policy.get("status")}},
    )

    audit.goto("/console/org/deploy/profiles/new")
    audit.snapshot("deployment-profile-wizard-opened", "Opened deployment profile wizard.")
    audit.fill_label(re.compile(r"profile name", re.I), f"Audit API Deployment {run_id}")
    audit.fill_label(re.compile(r"description", re.I), "Deployment profile created during beta UI audit.")
    audit.snapshot("deployment-basics-filled", "Filled deployment basics.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("deployment-basics-next-blocked", "Next unavailable after deployment basics.")
        return
    audit.select_mui_option(
        "deployment-default-policy-select",
        re.compile(rf"Audit Verification Policy {run_id}|Audit Verification Policy", re.I),
        timeout=3000,
    )
    for label in [re.compile(r"issuance", re.I), re.compile(r"verification", re.I)]:
        try:
            page.get_by_label(label).first.check(timeout=1000)
        except Exception:
            pass
    audit.snapshot("deployment-runtime-filled", "Selected runtime policy/flows where possible.")
    for index in range(4):
        if audit.click_role("button", re.compile(r"create|submit|finish", re.I), timeout=1200):
            break
        if audit.click_role("button", re.compile(r"skip", re.I), timeout=1200):
            continue
        if not audit.click_role("button", re.compile(r"next", re.I), timeout=1600):
            break
    audit.settle(5000)
    deployment_name = f"Audit API Deployment {run_id}"
    deployment, deployment_probe = wait_for_named_resource(
        page,
        "/v1/deployment-profiles",
        organization_id,
        deployment_name,
    )
    if not is_active(deployment):
        audit.snapshot("deployment-profile-state-mismatch", "The run-created Deployment Profile was not active.")
        return
    audit.snapshot(
        "deployment-profile-active",
        "Created an active Deployment Profile.",
        {"deployment_profile": {"id": deployment.get("id"), "name": deployment.get("name"), "status": deployment.get("status")}},
    )


def create_flow(audit: Audit, run_id: str, flow_kind: str) -> None:
    page = audit.page
    verification = flow_kind == "verification"
    kind_label = "Verification" if verification else "Issuance"
    flow_name = f"Audit Production {kind_label} {run_id}"
    flow_type = "oid4vp_presentation" if verification else "oid4vci_pre_authorized"
    required_dependency_test_id = (
        "flow-binding-defaultPolicyId"
        if verification
        else "flow-binding-credentialTemplateId"
    )
    required_dependency_name = (
        re.compile(rf"Audit Verification Policy {run_id}", re.I)
        if verification
        else re.compile(rf"Audit Employee Credential {run_id}", re.I)
    )

    audit.goto("/console/org/flows/definitions/new")
    audit.snapshot(f"{flow_kind}-flow-wizard-opened", f"Opened {flow_kind} flow authoring.")
    if not audit.click_test_id(f"flow-type-{flow_type}", timeout=5000):
        audit.snapshot(f"{flow_kind}-flow-type-blocked", f"The {flow_type} capability was unavailable.")
        return
    if not audit.click_test_id("wizard.flow.next", timeout=5000):
        audit.snapshot(f"{flow_kind}-flow-type-next-blocked", "Next was unavailable after selecting the flow type.")
        return

    audit.fill_label(re.compile(r"flow name", re.I), flow_name)
    audit.fill_label(
        re.compile(r"description", re.I),
        f"Production {flow_kind} flow created during the beta organization audit.",
    )
    audit.snapshot(f"{flow_kind}-flow-definition-filled", f"Configured the fixed {flow_type} definition.")
    if not audit.click_test_id("wizard.flow.next", timeout=5000):
        audit.snapshot(f"{flow_kind}-flow-definition-next-blocked", "Next was unavailable after flow definition.")
        return

    if not audit.select_mui_option(required_dependency_test_id, required_dependency_name, timeout=7000):
        # Exactly one eligible dependency is auto-selected by the UI.
        dependency = page.get_by_test_id(required_dependency_test_id).first
        try:
            expect(dependency).not_to_have_text(re.compile(r"^\s*$"), timeout=5000)
        except (AssertionError, PlaywrightError):
            audit.snapshot(f"{flow_kind}-flow-dependency-blocked", "The required active dependency was unavailable.")
            return
    audit.select_mui_option(
        "flow-binding-selectedDeployment",
        re.compile(rf"Audit API Deployment {run_id}", re.I),
        timeout=5000,
    )
    audit.snapshot(f"{flow_kind}-flow-dependencies-filled", "Bound the active run-created dependencies.")
    if not audit.click_test_id("wizard.flow.next", timeout=5000):
        audit.snapshot(f"{flow_kind}-flow-dependencies-next-blocked", "Next was unavailable after dependencies.")
        return

    audit.snapshot(f"{flow_kind}-flow-review", "Reviewed the canonical draft-first flow contract.")
    if not audit.click_test_id("wizard.flow.submit", timeout=5000):
        audit.snapshot(f"{flow_kind}-flow-create-blocked", "Create draft was unavailable.")
        return
    try:
        page.wait_for_url(re.compile(r"/console/org/flows/definitions/[^/]+$"), timeout=20_000)
    except PlaywrightTimeoutError:
        audit.snapshot(f"{flow_kind}-flow-detail-timeout", "The created draft did not open its validation workspace.")
        return
    audit.settle(5000)
    audit.snapshot(f"{flow_kind}-flow-draft-created", "Created a draft and opened its validation workspace.")

    if not audit.click_role("button", re.compile(r"^validate$", re.I), timeout=5000):
        audit.snapshot(f"{flow_kind}-flow-validation-blocked", "Validate was unavailable for the draft.")
        return
    try:
        expect(page.get_by_text(re.compile(r"Validation:\s*passed", re.I)).first).to_be_visible(timeout=20_000)
    except (AssertionError, PlaywrightError):
        audit.snapshot(f"{flow_kind}-flow-validation-failed", "Flow validation did not pass.")
        return

    if not audit.click_role("button", re.compile(r"^activate$", re.I), timeout=5000):
        audit.snapshot(f"{flow_kind}-flow-activation-blocked", "Activate was unavailable for the validated draft.")
        return
    try:
        expect(page.get_by_text(re.compile(r"flow is active", re.I)).first).to_be_visible(timeout=20_000)
    except (AssertionError, PlaywrightError):
        audit.snapshot(f"{flow_kind}-flow-activation-failed", "The validated flow did not become active.")
        return

    organization_id = active_organization_id(page)
    probe = fetch_org_collection(page, "/v1/flows/definitions", organization_id)
    flow = find_named_resource(probe, flow_name)
    if not is_active(flow) or str(flow.get("flow_type") or "") != flow_type:
        audit.snapshot(f"{flow_kind}-flow-state-mismatch", "The canonical flow was not active with the expected type.")
        return
    audit.snapshot(
        f"{flow_kind}-flow-active",
        f"Created, validated, and activated the {flow_kind} flow.",
        {"flow": {"id": flow.get("id"), "name": flow.get("name"), "status": flow.get("status"), "flow_type": flow.get("flow_type")}},
    )


def create_api_key(audit: Audit, run_id: str) -> None:
    page = audit.page
    audit.goto("/console/org/api-keys")
    audit.snapshot("api-keys-page-opened", "Opened API keys page.")
    if not audit.click_role("button", re.compile(r"create api key", re.I), timeout=5000):
        audit.snapshot("api-key-create-button-missing", "Create API Key button not available.")
        return
    audit.fill_label(re.compile(r"key name", re.I), f"Audit Gateway Key {run_id}")
    local_expiry = page.evaluate(
        """() => {
            const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
            const pad = (value) => String(value).padStart(2, '0');
            return `${expiresAt.getFullYear()}-${pad(expiresAt.getMonth() + 1)}-${pad(expiresAt.getDate())}T${pad(expiresAt.getHours())}:${pad(expiresAt.getMinutes())}`;
        }"""
    )
    audit.fill_label(
        re.compile(r"expiration", re.I),
        local_expiry,
        timeout=1500,
    )
    # Turn callback off to test synchronous key creation without needing a real callback endpoint.
    try:
        cb = page.get_by_label(re.compile(r"provision associated callback", re.I)).first
        if cb.is_checked(timeout=1000):
            cb.uncheck(timeout=1000)
    except Exception:
        pass
    audit.snapshot("api-key-dialog-filled", "Filled API key dialog.")
    if audit.is_recording:
        audit.show_privacy_shield(
            "One-time API key hidden",
            "Playwright is creating and validating the integration key behind this shield. "
            "The secret is intentionally excluded from the recording.",
        )
    audit.click_role("button", re.compile(r"create integration key|create key", re.I), timeout=5000)
    wait_for_creating_to_settle(page, timeout=15000)
    audit.settle(5000)
    mask_api_key_fields(page)
    organization_id = active_organization_id(page)
    key_name = f"Audit Gateway Key {run_id}"
    api_key, probe = wait_for_named_resource(
        page,
        "/v1/api-keys",
        organization_id,
        key_name,
    )
    if audit.is_recording:
        audit.goto("/console/org/api-keys")
    if not api_key or api_key.get("enabled") is not True:
        audit.snapshot(
            "api-key-state-mismatch",
            "The run-created API key was not present and enabled.",
            redact_screenshot=True,
        )
        return
    audit.snapshot(
        "api-key-created",
        "Created an enabled organization API key.",
        {
            "api_key": {"id": api_key.get("id"), "name": api_key.get("name"), "enabled": True},
            "api_key_secret_screenshot_redacted": True,
        },
        redact_screenshot=True,
    )


def verify_resource_inventory(audit: Audit, run_id: str) -> None:
    page = audit.page
    organization_id = active_organization_id(page)
    specs = [
        ("compliance_profile", "/v1/compliance-profiles", "OID4VC Core", False),
        ("trust_profile", "/v1/trust-profiles", f"Audit Trust Profile {run_id}", False),
        ("revocation_profile", "/v1/revocation-profiles", f"Audit Lifecycle Status {run_id}", False),
        ("credential_template", "/v1/credential-templates", f"Audit Employee Credential {run_id}", False),
        ("application_template", "/v1/application-templates", f"Audit Employee Application {run_id}", False),
        ("presentation_policy", "/v1/presentation-policies", f"Audit Verification Policy {run_id}", False),
        ("deployment_profile", "/v1/deployment-profiles", f"Audit API Deployment {run_id}", False),
        ("issuance_flow", "/v1/flows/definitions", f"Audit Production Issuance {run_id}", False),
        ("verification_flow", "/v1/flows/definitions", f"Audit Production Verification {run_id}", False),
        ("api_key", "/v1/api-keys", f"Audit Gateway Key {run_id}", False),
    ]
    inventory: list[dict[str, Any]] = []
    missing: list[str] = []
    probes: dict[str, dict[str, Any]] = {}
    resources: dict[str, dict[str, Any]] = {}

    issuer_path = "/v1/signing-keys/issuer-identities"
    issuer_probe = fetch_org_collection(page, issuer_path, organization_id)
    issuer = find_audit_issuer_identity(issuer_probe, run_id)
    probes[issuer_path] = issuer_probe
    if issuer is None:
        missing.append("issuer_identity")
    else:
        resources["issuer_identity"] = issuer
        inventory.append({
            "resource_type": "issuer_identity",
            "id": issuer.get("issuer_did"),
            "name": issuer.get("issuer_did"),
            "status": issuer.get("status"),
        })

    verifier_issuer = None
    if issuer is not None:
        verifier_issuer = find_issuer_identity(
            issuer_probe,
            str(issuer.get("issuer_did") or ""),
            key_purpose="oid4vp_request_signing",
            credential_format="SD_JWT_VC",
            algorithm="ES256",
        )
    if verifier_issuer is None:
        missing.append("verifier_issuer_identity")
    else:
        resources["verifier_issuer_identity"] = verifier_issuer
        inventory.append({
            "resource_type": "verifier_issuer_identity",
            "id": verifier_issuer.get("issuer_did"),
            "name": verifier_issuer.get("issuer_did"),
            "status": verifier_issuer.get("status"),
        })

    for resource_type, path, name, partial_name in specs:
        if path not in probes:
            probes[path] = fetch_org_collection(page, path, organization_id)
        probe = probes[path]
        resource = find_resource_with_name(probe, name) if partial_name else find_named_resource(probe, name)
        if not is_active(resource):
            missing.append(resource_type)
            continue
        resources[resource_type] = resource
        inventory.append({
            "resource_type": resource_type,
            "id": resource.get("id"),
            "name": resource.get("name"),
            "status": resource.get("status") or ("active" if resource.get("enabled") else None),
        })

    config_probe = fetch_org_collection(page, "/v1/signing-keys/config", organization_id)
    config = config_probe.get("body") if isinstance(config_probe.get("body"), dict) else {}
    service = selected_signing_service(config)
    configured = [step.get("signing_configuration") for step in audit.steps
                  if step.get("label") == "kms-service-configured"]
    if (service is None or config_probe.get("status") != 200 or len(configured) != 1
            or not isinstance(configured[0], dict)
            or configured[0].get("organization_id") != organization_id
            or configured[0].get("run_id") != run_id
            or configured[0].get("default_service_id") != service.get("id")
            or not signing_capability_proven({"steps": audit.steps})):
        missing.append("signing_service")
    else:
        inventory.append({
            "resource_type": "signing_service",
            "id": service.get("id"),
            "name": service.get("name"),
            "status": service.get("status") or "configured",
        })

    dependency_errors: list[str] = []
    if not missing:
        compliance = resources["compliance_profile"]
        issuer = resources["issuer_identity"]
        trust = resources["trust_profile"]
        revocation = resources["revocation_profile"]
        credential = resources["credential_template"]
        application = resources["application_template"]
        policy = resources["presentation_policy"]
        deployment = resources["deployment_profile"]
        issuance_flow = resources["issuance_flow"]
        verification_flow = resources["verification_flow"]

        expected_links = [
            ("credential.compliance_profile_id", credential.get("compliance_profile_id"), compliance.get("id")),
            ("credential.issuer_did", credential.get("issuer_did"), issuer.get("issuer_did")),
            ("credential.trust_profile_id", credential.get("trust_profile_id"), trust.get("id")),
            ("credential.revocation_profile_id", credential.get("revocation_profile_id"), revocation.get("id")),
            ("application.credential_template_id", application.get("credential_template_id"), credential.get("id")),
            ("policy.trust_profile_id", policy.get("trust_profile_id"), trust.get("id")),
            ("deployment.trust_profile_id", deployment.get("trust_profile_id"), trust.get("id")),
            ("deployment.default_policy_id", deployment.get("default_policy_id"), policy.get("id")),
            ("issuance_flow.trust_profile_id", issuance_flow.get("trust_profile_id"), trust.get("id")),
            ("issuance_flow.credential_template_id", issuance_flow.get("credential_template_id"), credential.get("id")),
            ("verification_flow.trust_profile_id", verification_flow.get("trust_profile_id"), trust.get("id")),
            ("verification_flow.presentation_policy_id", verification_flow.get("presentation_policy_id"), policy.get("id")),
        ]
        dependency_errors.extend(
            label for label, actual, expected in expected_links if actual != expected
        )
        if policy.get("id") not in (deployment.get("presentation_policy_ids") or []):
            dependency_errors.append("deployment.presentation_policy_ids")
        for flow_label, flow in (("issuance_flow", issuance_flow), ("verification_flow", verification_flow)):
            if deployment.get("id") not in (flow.get("deployment_profile_ids") or []):
                dependency_errors.append(f"{flow_label}.deployment_profile_ids")
        credential_claim_ids = {
            requirement.get("credential_template_id") or requirement.get("credential_type")
            for requirement in [
                *(policy.get("credential_requirements") or []),
                *(policy.get("required_claims") or []),
            ]
            if isinstance(requirement, dict)
        }
        if credential.get("id") not in credential_claim_ids:
            dependency_errors.append("policy.credential_template")

    if missing or dependency_errors:
        audit.snapshot(
            "resource-inventory-incomplete",
            "The final canonical inventory was missing required active resources or dependency links.",
            {
                "organization_id": organization_id,
                "missing_resource_types": missing,
                "dependency_errors": dependency_errors,
                "inventory": inventory,
            },
        )
        return
    audit.snapshot(
        "resource-inventory-verified",
        "Verified every required run-created primitive in the fresh organization.",
        {"organization_id": organization_id, "inventory": inventory},
    )


def verify_unauthorized_administration_denied(audit: Audit) -> None:
    """Prove that this administrator cannot enumerate another organization's primitives."""
    probes = {
        path: fetch_org_collection(audit.page, path, CROSS_ORG_SENTINEL)
        for path in sorted(CROSS_ORG_ADMIN_PATHS)
    }
    statuses = {path: int(probe.get("status") or 0) for path, probe in probes.items()}
    if not all(status == 403 for status in statuses.values()):
        audit.snapshot(
            "unauthorized-administration-not-denied",
            "At least one cross-organization administration request was not denied with 403.",
            {"organization_id": CROSS_ORG_SENTINEL, "statuses": statuses},
        )
        return
    audit.snapshot(
        "unauthorized-administration-denied",
        "Cross-organization reads of credential, trust, policy, and deployment primitives were denied.",
        {"organization_id": CROSS_ORG_SENTINEL, "statuses": statuses},
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the live beta org-console audit with Playwright.",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Beta base URL to audit. Defaults to BETA_ORIGIN/BASE_URL or https://beta.elevenidllc.com.",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Run Chromium headed. PWDEBUG=1 also runs headed.",
    )
    parser.add_argument(
        "--record-video",
        action="store_true",
        help=(
            "Record a reviewable WebM video and Playwright trace in the audit artifact directory. "
            "The recorder's RECORD_VIDEO=0 override runs functional checks with a trace and no video."
        ),
    )
    parser.add_argument(
        "--recording-pause-ms",
        type=int,
        default=1300,
        help="How long each labeled recording step remains visible. Defaults to 1300 ms.",
    )
    parser.add_argument(
        "--github-env",
        type=Path,
        default=None,
        help=(
            "Append the verified organization ID to this GitHub Actions environment "
            "file for subsequent lifecycle steps."
        ),
    )
    args = parser.parse_args()
    functional_rerun = os.environ.get("RECORD_VIDEO") == "0"
    record_video = args.record_video and not functional_rerun
    # The D-10 recorder contract requires a trace in both modes. Functional
    # traces retain execution events without capturing screenshots or DOMs.
    record_trace = args.record_video or functional_rerun

    env = {} if os.environ.get("DEMO_PYTHON_CAPTURE_NONCE") else load_env_file(ENV_FILE)
    base_url = (
        args.base_url
        or os.environ.get("BETA_ORIGIN")
        or os.environ.get("BASE_URL")
        or env.get("BASE_URL")
        or "https://beta.elevenidllc.com"
    )
    if (base_url != "https://beta.elevenidllc.com" or os.environ.get("BETA_LOCAL_PROXY") == "1"
            or os.environ.get("NODE_TLS_REJECT_UNAUTHORIZED") not in {None, "1"}
            or os.environ.get("MARTY_UI_CANDIDATE_DIST")):
        print("D10 requires the exact beta HTTPS origin and verified deployed UI with normal TLS", file=sys.stderr)
        return 2

    email = os.environ.get("TEST_VENDOR_EMAIL") or os.environ.get("TEST_ADMIN_EMAIL")
    password = os.environ.get("TEST_VENDOR_PASSWORD") or os.environ.get("TEST_ADMIN_PASSWORD")
    if not email or not password:
        print("Missing TEST_VENDOR_EMAIL/TEST_VENDOR_PASSWORD or admin fallback in beta env.", file=sys.stderr)
        return 2
    KNOWN_SECRETS.add(password)

    try:
        signing_inputs = load_signing_inputs()
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        capture = start_recorder_capture(required=record_trace)
        acknowledged = bound_recorder_inputs(capture, signing_inputs, record_video, args.recording_pause_ms) if capture else None
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    run_id = acknowledged["runId"] if acknowledged else datetime.now().strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
    artifact_dir = resolve_artifact_dir(run_id)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not (args.headed or os.environ.get("PWDEBUG") == "1"))
        context_options: dict[str, Any] = {
            "base_url": base_url,
            "viewport": RECORDING_VIEWPORT,
            "ignore_https_errors": False,
        }
        if record_video:
            context_options.update({
                "record_video_dir": str(artifact_dir),
                "record_video_size": RECORDING_VIEWPORT,
            })
        context = browser.new_context(
            **context_options,
        )
        # Trace arguments and network bodies retain credentials even without
        # screenshots. Start only after login and KMS credential submission.
        trace_started = False
        page = context.new_page()
        if capture:
            capture.bind_page(page)
        page_video = page.video if record_video else None
        audit = Audit(
            page,
            artifact_dir,
            base_url,
            recording_pause_ms=args.recording_pause_ms if record_video else 0,
        )
        audit.attach_events()

        try:
            log_in(audit, email, password)
            auth_probe = fetch_json_from_page(page, ["/v1/auth/me", "/v1/organizations/mine"])
            audit.snapshot("auth-probe", "Fetched auth/session probes.", {"auth_probe": auth_probe})

            created_slug = create_org(audit, run_id, email)
            post_org_probe = fetch_json_from_page(page, ["/v1/auth/me", "/v1/organizations/mine"])
            organization_id = require_created_organization(page, created_slug, auth_probe, post_org_probe)
            audit.snapshot("post-org-probe", "Bound the exact fresh organization before signer setup.",
                           {"auth_probe": post_org_probe, "organization_id": organization_id})

            create_key_service_if_possible(audit, run_id, signing_inputs)
            if record_trace:
                context.tracing.start(
                    screenshots=record_video, snapshots=record_video, sources=record_video,
                )
                trace_started = True
            create_issuer_identity(audit, run_id)
            verify_issuer_signing_capabilities(audit, run_id, signing_inputs)
            create_trust_profile(audit, run_id)
            create_revocation_profile(audit, run_id)
            create_credential_template(audit, run_id)
            create_application_template(audit, run_id)
            create_policy_and_deployment(audit, run_id)
            create_flow(audit, run_id, "issuance")
            create_flow(audit, run_id, "verification")
            create_api_key(audit, run_id)
            verify_resource_inventory(audit, run_id)
            verify_unauthorized_administration_denied(audit)
        except Exception as exc:
            audit.snapshot("audit-exception", f"Audit stopped with exception: {exc!r}")
            # Do not re-emit an original Playwright exception chain that may
            # contain token/password fill arguments in process stderr.
            raise RuntimeError(f"D10 audit failed: {redact_sensitive(str(exc))}") from None
        finally:
            audit.cleanup_created_api_keys()
            report = audit.report()
            recording: dict[str, Any] | None = None
            if trace_started:
                trace_path = artifact_dir / "mip-primitives-management-trace.zip"
                context.tracing.stop(path=str(trace_path))
            if record_video:
                recording = {
                    "video": report_artifact_path(
                        artifact_dir / "mip-primitives-management.webm", artifact_dir
                    ),
                    "trace": report_artifact_path(trace_path, artifact_dir) if trace_started else None,
                }
            context.close()
            if page_video is not None:
                raw_video_path = Path(page_video.path())
                final_video_path = artifact_dir / "mip-primitives-management.webm"
                if raw_video_path != final_video_path:
                    final_video_path.unlink(missing_ok=True)
                    raw_video_path.replace(final_video_path)
            browser.close()
            if recording:
                report["recording"] = recording
            if functional_rerun:
                report.update({
                    "functional_rerun": True,
                    "capture_quality": {"status": "NOT_CAPTURED"},
                    "recording": None,
                    "trace": report_artifact_path(trace_path, artifact_dir) if trace_started else None,
                })
            if record_trace:
                report["trace_coverage"] = {
                    "status": "CAPTURED_AFTER_SENSITIVE_SETUP" if trace_started else "NOT_STARTED_SETUP_FAILED",
                    "starts_after": "kms-service-configured",
                    "omitted": ["authentication", "organization-creation", "kms-service-registration"],
                    "reason": "Credential entry and service submission are excluded from trace arguments and network payloads.",
                }
                if not trace_started:
                    report["releaseReady"] = False
            report_path = artifact_dir / "report.json"
            report_path.write_text(redact_sensitive(json.dumps(report, indent=2, default=str)), encoding="utf-8")
            print(f"[audit] report={report_path}")

    if args.github_env is not None and report["release_checks"]["status"] == "pass":
        environment = export_audit_lifecycle_environment(report, args.github_env)
        print(
            "[audit] exported_lifecycle_resources="
            f"organization:{environment['BETA_AUDIT_ORG_ID']},"
            f"template:{environment['BETA_AUDIT_TEMPLATE_ID']},"
            f"policy:{environment['BETA_AUDIT_POLICY_ID']},"
            f"verifier:{environment['BETA_AUDIT_VERIFIER_DID']}"
        )

    if capture and report["releaseReady"]:
        capture.complete()
    return 0 if report["releaseReady"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
