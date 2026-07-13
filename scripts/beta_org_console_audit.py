#!/usr/bin/env python3
"""
Live beta org-console audit.

This drives https://beta.elevenidllc.com with Playwright using the beta env
file in this repo. It intentionally uses UI selectors first and records
screenshots, failing requests, page errors, and concise step notes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import expect, sync_playwright


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.tunnel.beta.local"
ARTIFACT_ROOT = ROOT / "tests" / "artifacts"


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
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 3:
            redacted = pattern.sub(r"\1[REDACTED]\3", redacted)
        else:
            redacted = pattern.sub("[REDACTED_API_KEY]", redacted)
    return redacted


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

    image = Image.new("RGB", (1440, 900), "#f8fafc")
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
    }

    blockers: list[dict[str, Any]] = []
    degraded: list[dict[str, Any]] = []
    expected_entitlements: list[dict[str, Any]] = []

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
            "api_key_secret_screenshot_redacted": bool(
                api_key_steps and all(step.get("api_key_secret_screenshot_redacted") for step in api_key_steps)
            ),
        },
    }


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
                    "text": msg.text[:1000],
                    "location": f"{msg.location.get('url', '')}:{msg.location.get('lineNumber', '')}",
                }
            )
            if msg.type in {"error", "warning"}
            else None,
        )
        self.page.on("pageerror", lambda err: self.page_errors.append(str(err)[:1500]))
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
                "screenshot": str(screenshot.relative_to(ROOT)) if screenshot else None,
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
            "artifact_dir": str(self.artifact_dir.relative_to(ROOT)),
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


def create_key_service_if_possible(audit: Audit, run_id: str) -> None:
    page = audit.page
    audit.goto("/console/org/deploy/key-management/services/new")
    audit.snapshot("kms-service-wizard-opened", "Opened Register Key Management Service.")

    if text_visible(page, "Unable to load", 1000) or text_visible(page, "No active organization", 1000):
        return

    # Prefer a transit provider card if visible, otherwise select the first service card.
    if not audit.click_role("button", re.compile(r"openbao transit|hashicorp vault transit|custom transit", re.I), timeout=2500):
        try:
            page.locator("[role=button], .MuiPaper-root").filter(has_text=re.compile(r"Protocol:|Category:", re.I)).first.click(timeout=2500)
            audit.settle()
        except Exception:
            audit.snapshot("kms-service-no-selectable-provider", "No selectable KMS provider card was found.")
            return

    audit.snapshot("kms-provider-selected", "Selected a KMS provider.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("kms-provider-next-blocked", "Next was unavailable after selecting provider.")
        return

    audit.fill_label(re.compile(r"service name", re.I), f"Audit Transit Service {run_id}")
    # Field set varies by provider; fill likely required connection fields.
    audit.fill_label(re.compile(r"service url", re.I), "https://kms.audit.invalid/transit")
    audit.fill_label(re.compile(r"region|location", re.I), "us")
    audit.fill_label(re.compile(r"transit mount|mount", re.I), "transit")
    audit.fill_label(re.compile(r"credential reference", re.I), f"audit-secret-{run_id}")
    audit.snapshot("kms-connection-filled", "Filled KMS connection metadata.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("kms-connection-next-blocked", "Next was unavailable on connection step.")
        return

    audit.fill_label(re.compile(r"key reference|key arn|key id|key name|key identifier", re.I), f"audit-key-{run_id}")
    # Select a VC/issuer purpose when available.
    for label in [re.compile(r"vc.*issuer|issuer|sd-jwt|credential", re.I)]:
        try:
            page.get_by_label(label).first.check(timeout=1500)
            break
        except Exception:
            pass
    audit.snapshot("kms-key-access-filled", "Filled KMS key access metadata.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("kms-key-access-next-blocked", "Next was unavailable on key access step.")
        return

    audit.snapshot("kms-review", "Reached KMS review.")
    audit.click_role("button", re.compile(r"register service", re.I), timeout=5000)
    audit.settle(5000)
    audit.snapshot("kms-register-submitted", "Submitted KMS service registration.")

    organization_id = active_organization_id(page)
    probe = fetch_org_collection(page, "/v1/signing-keys/config", organization_id)
    config = probe.get("body") if isinstance(probe.get("body"), dict) else {}
    services = config.get("services") if isinstance(config, dict) else []
    if not config.get("hsm_enabled") or not isinstance(services, list) or not services:
        audit.snapshot("kms-service-state-mismatch", "The canonical signing configuration did not contain an enabled service.")
        return
    audit.snapshot(
        "kms-service-configured",
        "Configured a signing service for the fresh organization.",
        {"signing_configuration": {"hsm_enabled": True, "service_count": len(services)}},
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

    for choice in [re.compile(r"did:jwk", re.I), re.compile(r"did:key", re.I), re.compile(r"web", re.I)]:
        if audit.click_text(choice, timeout=1500):
            break
    audit.snapshot("issuer-method-selected", "Selected issuer DID method where possible.")
    audit.click_role("button", re.compile(r"next", re.I), timeout=3000)

    if text_visible(page, "Console key creation currently requires", 1000):
        audit.snapshot(
            "issuer-key-create-disabled",
            "Issuer identity wizard correctly disabled console key creation for an external-only signing service.",
        )
        audit.click_text(re.compile(r"existing", re.I), timeout=1500)
    else:
        for choice in [re.compile(r"create new", re.I), re.compile(r"existing", re.I)]:
            if audit.click_text(choice, timeout=1500):
                break
    audit.snapshot("issuer-key-source-selected", "Selected issuer key source where possible.")
    audit.click_role("button", re.compile(r"next", re.I), timeout=3000)

    audit.fill_label(re.compile(r"key name|name", re.I), f"Audit Issuer Key {run_id}")
    audit.snapshot("issuer-key-filled", "Filled issuer key data where possible.")
    # Walk remaining steps until submit or blocked.
    for index in range(4):
        if audit.click_role("button", re.compile(r"create|publish|finish|submit|save", re.I), timeout=1500):
            break
        if not audit.click_role("button", re.compile(r"next", re.I), timeout=1500):
            break
        audit.snapshot(f"issuer-step-{index + 1}", "Advanced issuer identity wizard one step.")
    wait_for_creating_to_settle(page, timeout=30000)
    audit.settle(5000)
    organization_id = active_organization_id(page)
    probe = fetch_org_collection(page, "/v1/signing-keys/issuer-profiles", organization_id)
    issuer = find_resource_with_name(probe, f"Audit Issuer Key {run_id}")
    if not is_active(issuer):
        audit.snapshot("issuer-identity-state-mismatch", "The run-created issuer identity was not active.")
        return
    audit.snapshot(
        "issuer-identity-active",
        "Created an active issuer identity.",
        {"issuer_identity": {"id": issuer.get("id"), "name": issuer.get("name"), "status": issuer.get("status")}},
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

    trusted_existing_identity = audit.select_mui_option(
        "wizard.trustProfile.existingIssuerProfile",
        re.compile(rf"Audit Issuer Key {run_id}|Audit Issuer|did:jwk|did:web", re.I),
        timeout=10_000,
    )
    if trusted_existing_identity:
        audit.click_test_id("wizard.trustProfile.useIssuerProfile", timeout=3000)
    else:
        audit.snapshot(
            "trust-managed-issuer-blocked",
            "Trust Profile creation stopped because the managed issuer identity was unavailable.",
        )
        return
    audit.snapshot("trust-source-added", "Added the audit issuer identity as a trust source if the form accepted it.")

    for index in range(4):
        if audit.click_role("button", re.compile(r"activate|create|submit|finish", re.I), timeout=1200):
            break
        if audit.click_role("button", re.compile(r"skip", re.I), timeout=1200):
            audit.snapshot(f"trust-skip-{index + 1}", "Skipped optional trust step.")
            continue
        if not audit.click_role("button", re.compile(r"next", re.I), timeout=2000):
            break
        audit.snapshot(f"trust-next-{index + 1}", "Advanced trust wizard one step.")
    wait_for_creating_to_settle(page, timeout=15000)
    audit.settle(5000)
    organization_id = active_organization_id(page)
    probe = fetch_org_collection(page, "/v1/trust-profiles", organization_id)
    profile = find_named_resource(probe, name)
    if not is_active(profile):
        audit.snapshot("trust-profile-state-mismatch", "The run-created Trust Profile was not active.")
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
        ("issuer_identity", "/v1/signing-keys/issuer-profiles", f"Audit Issuer Key {run_id}", True),
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
    if not config.get("hsm_enabled") or not isinstance(config.get("services"), list) or not config.get("services"):
        missing.append("signing_service")
    else:
        inventory.append({
            "resource_type": "signing_service",
            "id": config["services"][0].get("id"),
            "name": config["services"][0].get("name"),
            "status": config["services"][0].get("status") or "configured",
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
            ("credential.issuer_profile_id", credential.get("issuer_profile_id"), issuer.get("id")),
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the live beta org-console audit with Playwright.",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Beta base URL to audit. Defaults to BASE_URL from env or https://beta.elevenidllc.com.",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Run Chromium headed. PWDEBUG=1 also runs headed.",
    )
    parser.add_argument(
        "--record-video",
        action="store_true",
        help="Record a reviewable WebM video and Playwright trace in the audit artifact directory.",
    )
    parser.add_argument(
        "--recording-pause-ms",
        type=int,
        default=1300,
        help="How long each labeled recording step remains visible. Defaults to 1300 ms.",
    )
    args = parser.parse_args()

    env = load_env_file(ENV_FILE)
    base_url = args.base_url or os.environ.get("BASE_URL") or env.get("BASE_URL") or "https://beta.elevenidllc.com"
    if "beta.elevenidllc.com" not in base_url:
        base_url = "https://beta.elevenidllc.com"

    email = os.environ.get("TEST_VENDOR_EMAIL") or os.environ.get("TEST_ADMIN_EMAIL")
    password = os.environ.get("TEST_VENDOR_PASSWORD") or os.environ.get("TEST_ADMIN_PASSWORD")
    if not email or not password:
        print("Missing TEST_VENDOR_EMAIL/TEST_VENDOR_PASSWORD or admin fallback in beta env.", file=sys.stderr)
        return 2

    run_id = datetime.now().strftime("%Y%m%d%H%M%S")
    artifact_dir = ARTIFACT_ROOT / f"beta-org-console-audit-{run_id}"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not (args.headed or os.environ.get("PWDEBUG") == "1"))
        context_options: dict[str, Any] = {
            "base_url": base_url,
            "viewport": {"width": 1440, "height": 1100},
            "ignore_https_errors": True,
        }
        if args.record_video:
            context_options.update({
                "record_video_dir": str(artifact_dir),
                "record_video_size": {"width": 1440, "height": 1100},
            })
        context = browser.new_context(
            **context_options,
        )
        if args.record_video:
            context.tracing.start(screenshots=True, snapshots=True, sources=True)
        page = context.new_page()
        page_video = page.video if args.record_video else None
        audit = Audit(
            page,
            artifact_dir,
            base_url,
            recording_pause_ms=args.recording_pause_ms if args.record_video else 0,
        )
        audit.attach_events()

        try:
            log_in(audit, email, password)
            auth_probe = fetch_json_from_page(page, ["/v1/auth/me", "/v1/organizations/mine"])
            audit.snapshot("auth-probe", "Fetched auth/session probes.", {"auth_probe": auth_probe})

            create_org(audit, run_id, email)
            post_org_probe = fetch_json_from_page(page, ["/v1/auth/me", "/v1/organizations/mine"])
            audit.snapshot("post-org-probe", "Fetched session after org creation.", {"auth_probe": post_org_probe})

            create_key_service_if_possible(audit, run_id)
            create_issuer_identity(audit, run_id)
            create_trust_profile(audit, run_id)
            create_revocation_profile(audit, run_id)
            create_credential_template(audit, run_id)
            create_application_template(audit, run_id)
            create_policy_and_deployment(audit, run_id)
            create_flow(audit, run_id, "issuance")
            create_flow(audit, run_id, "verification")
            create_api_key(audit, run_id)
            verify_resource_inventory(audit, run_id)
        except Exception as exc:
            audit.snapshot("audit-exception", f"Audit stopped with exception: {exc!r}")
            raise
        finally:
            audit.cleanup_created_api_keys()
            report = audit.report()
            recording: dict[str, str] | None = None
            if args.record_video:
                trace_path = artifact_dir / "mip-primitives-management-trace.zip"
                context.tracing.stop(path=str(trace_path))
                recording = {
                    "video": str((artifact_dir / "mip-primitives-management.webm").relative_to(ROOT)),
                    "trace": str(trace_path.relative_to(ROOT)),
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
            report_path = artifact_dir / "report.json"
            report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            print(f"[audit] report={report_path}")

    return 0 if report["release_checks"]["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
