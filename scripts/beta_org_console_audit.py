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


def is_loading_only_step(step: dict[str, Any]) -> bool:
    body = re.sub(r"\s+", " ", str(step.get("body_excerpt") or "")).strip().lower()
    return body in {
        "loading console...",
        "checking authentication...",
        "opening login...",
    }


def evaluate_release_checks(report: dict[str, Any]) -> dict[str, Any]:
    """Classify beta audit output into release blockers and known degradations."""
    report_text = json.dumps(report, default=str)
    steps = report.get("steps") or []
    bad_responses = report.get("bad_responses") or []
    step_labels = {str(step.get("label") or "") for step in steps}
    required_step_labels = {
        "auth-probe",
        "post-org-probe",
        "kms-register-submitted",
        "issuer-identity-submitted-or-blocked",
        "trust-profile-submitted-or-blocked",
        "credential-template-submitted-or-blocked",
        "presentation-policy-submitted-or-blocked",
        "deployment-profile-submitted-or-blocked",
        "flow-submitted-or-blocked",
        "api-key-submitted-or-blocked",
    }

    blockers: list[dict[str, Any]] = []
    degraded: list[dict[str, Any]] = []

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
        if step.get("label") == "api-key-submitted-or-blocked"
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
        elif status >= 400:
            add_blocker(
                "unexpected_bad_response",
                "The audit observed an unexpected 4xx/5xx response.",
                status=status,
                url=response.get("url"),
                message_id=response.get("message_id"),
                error_code=response_error_code(response),
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
            "api_key_secret_screenshot_redacted": bool(
                api_key_steps and all(step.get("api_key_secret_screenshot_redacted") for step in api_key_steps)
            ),
        },
    }


class Audit:
    def __init__(self, page: Page, artifact_dir: Path, base_url: str):
        self.page = page
        self.artifact_dir = artifact_dir
        self.base_url = base_url.rstrip("/")
        self.steps: list[dict[str, Any]] = []
        self.console: list[dict[str, str]] = []
        self.failed_requests: list[dict[str, str]] = []
        self.bad_responses: list[dict[str, Any]] = []
        self.interesting_responses: list[dict[str, Any]] = []
        self.page_errors: list[str] = []
        self.created_api_keys: list[dict[str, str]] = []
        self.cleanup_actions: list[dict[str, str]] = []

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
            lambda req: self.failed_requests.append(self._request_failed_entry(req))
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
            trigger = self.page.get_by_test_id(test_id).first
            trigger.wait_for(state="visible", timeout=timeout)
            trigger.click(timeout=timeout)
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
    audit.snapshot("issuer-identity-submitted-or-blocked", "Issuer identity wizard final observed state.")


def create_trust_profile(audit: Audit, run_id: str) -> None:
    page = audit.page
    audit.goto("/console/org/trust/profiles/new")
    audit.snapshot("trust-profile-wizard-opened", "Opened trust profile wizard.")

    name = f"Audit Trust Profile {run_id}"
    did = f"did:web:audit-{run_id}.example.com"
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
        timeout=5000,
    )
    if trusted_existing_identity:
        audit.click_test_id("wizard.trustProfile.useIssuerProfile", timeout=3000)
    else:
        # Manual DID fallback. Use test IDs to avoid filling the source-type or
        # managed-identity controls that also contain "DID" in their labels.
        try:
            page.get_by_test_id("wizard.trustProfile.issuerDid").fill(did, timeout=3000)
        except Exception:
            audit.fill_textbox(re.compile(r"issuer did", re.I), did)
        audit.fill_label(re.compile(r"^name$", re.I), f"Audit Issuer {run_id}", timeout=1500)
        audit.fill_label(re.compile(r"country", re.I), "US", timeout=1500)
        audit.fill_label(re.compile(r"credential types", re.I), "VerifiableCredential|SD_JWT_VC", timeout=1500)
        audit.click_test_id("wizard.trustProfile.addIssuer", timeout=3000)
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
    audit.snapshot("trust-profile-submitted-or-blocked", "Trust profile wizard final observed state.")


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
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("template-trust-next-blocked", "Next unavailable after trust selection.")
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
    audit.snapshot("credential-template-submitted-or-blocked", "Credential template wizard final observed state.")


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
    audit.snapshot("presentation-policy-submitted-or-blocked", "Presentation policy final observed state.")

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
    audit.snapshot("deployment-profile-submitted-or-blocked", "Deployment profile final observed state.")


def create_flow(audit: Audit, run_id: str) -> None:
    page = audit.page
    before_bad_count = len(audit.bad_responses)
    audit.goto("/console/org/flows/definitions/new")
    audit.snapshot("flow-wizard-opened", "Opened issuance flow wizard.")
    if not audit.click_test_id("flow-type-issuance_oid4vci", timeout=3000):
        audit.click_role("button", re.compile(r"OID4VCI Issuance|OID4VCI|issuance", re.I), timeout=2500)
    audit.snapshot("flow-type-selected", "Selected issuance/OID4VCI flow type where possible.")
    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("flow-type-next-blocked", "Next unavailable after flow type.")
        return

    audit.fill_label(re.compile(r"flow name", re.I), f"Audit Production Issuance {run_id}")
    audit.fill_label(re.compile(r"description", re.I), "Production credential flow created during beta UI audit.")
    if audit.click_role("button", re.compile(r"use preset", re.I), timeout=2000):
        audit.click_text(re.compile(r"OID4VCI|QR|Standard|Pre-Authorized", re.I), timeout=2000)
    else:
        audit.click_role("button", re.compile(r"add step", re.I), timeout=1000)
    audit.snapshot("flow-steps-filled", "Configured issuance flow steps where possible.")

    if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
        audit.snapshot("flow-steps-next-blocked", "Next unavailable after configuring flow steps.")
        return

    if text_visible(page, "Preconditions", timeout=2000):
        audit.click_role("button", re.compile(r"next", re.I), timeout=3000)

    if text_visible(page, "Bind Deployment", timeout=3000):
        audit.click_text(re.compile(rf"Audit API Deployment {run_id}|Audit API Deployment", re.I), timeout=2000)
        audit.select_mui_option(
            "flow-binding-template-select",
            re.compile(rf"Audit Employee Credential {run_id}|Audit Employee Credential", re.I),
            timeout=3000,
        )
        audit.select_mui_option(
            "flow-binding-policy-select",
            re.compile(rf"Audit Verification Policy {run_id}|Audit Verification Policy", re.I),
            timeout=1500,
        )
        audit.snapshot("flow-binding-filled", "Selected deployment/template binding where possible.")
        if not audit.click_role("button", re.compile(r"next", re.I), timeout=3000):
            audit.snapshot("flow-binding-next-blocked", "Next unavailable after flow binding.")
            return

    for index in range(3):
        if audit.click_role("button", re.compile(r"create|submit|finish", re.I), timeout=1200):
            break
        if audit.click_role("button", re.compile(r"skip", re.I), timeout=1200):
            continue
        if not audit.click_role("button", re.compile(r"next", re.I), timeout=1600):
            break
    wait_for_creating_to_settle(page, timeout=25000)
    audit.settle(5000)
    after_bad_count = len(audit.bad_responses)
    audit.snapshot(
        "flow-submitted-or-blocked",
        "Flow wizard final observed state.",
        {"new_bad_responses_during_flow": audit.bad_responses[before_bad_count:after_bad_count]},
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
    audit.click_role("button", re.compile(r"create integration key|create key", re.I), timeout=5000)
    wait_for_creating_to_settle(page, timeout=15000)
    audit.settle(5000)
    mask_api_key_fields(page)
    audit.snapshot(
        "api-key-submitted-or-blocked",
        "API key creation final observed state.",
        {"api_key_secret_screenshot_redacted": True},
        redact_screenshot=True,
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
        context = browser.new_context(
            base_url=base_url,
            viewport={"width": 1440, "height": 1100},
            ignore_https_errors=True,
        )
        page = context.new_page()
        audit = Audit(page, artifact_dir, base_url)
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
            create_credential_template(audit, run_id)
            create_policy_and_deployment(audit, run_id)
            create_flow(audit, run_id)
            create_api_key(audit, run_id)
        except Exception as exc:
            audit.snapshot("audit-exception", f"Audit stopped with exception: {exc!r}")
            raise
        finally:
            audit.cleanup_created_api_keys()
            report_path = artifact_dir / "report.json"
            report_path.write_text(json.dumps(audit.report(), indent=2, default=str), encoding="utf-8")
            print(f"[audit] report={report_path}")
            context.close()
            browser.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
