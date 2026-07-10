from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_audit_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "beta_org_console_audit.py"
    spec = importlib.util.spec_from_file_location("beta_org_console_audit", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _required_steps():
    return [
        {"label": "auth-probe", "body_excerpt": "Dashboard"},
        {"label": "post-org-probe", "body_excerpt": "Dashboard"},
        {"label": "kms-register-submitted", "body_excerpt": "Key management"},
        {"label": "issuer-identity-submitted-or-blocked", "body_excerpt": "Issuer identity"},
        {"label": "trust-profile-submitted-or-blocked", "body_excerpt": "Trust profile"},
        {"label": "credential-template-submitted-or-blocked", "body_excerpt": "Credential template"},
        {"label": "presentation-policy-submitted-or-blocked", "body_excerpt": "Presentation policy"},
        {"label": "deployment-profile-submitted-or-blocked", "body_excerpt": "Deployment profile"},
        {"label": "flow-submitted-or-blocked", "body_excerpt": "Flow"},
        {
            "label": "api-key-submitted-or-blocked",
            "body_excerpt": "API Keys",
            "api_key_secret_screenshot_redacted": True,
        },
    ]


def test_release_checks_block_audit_log_501() -> None:
    audit = _load_audit_module()

    report = {
        "steps": _required_steps(),
        "bad_responses": [
            {
                "status": 501,
                "url": "https://beta.elevenidllc.com/v1/organizations/org-1/audit-events?limit=5",
                "error_code": "audit_log_unavailable",
                "message_id": "msg-audit-1",
            }
        ],
        "failed_requests": [],
        "page_errors": [],
    }

    checks = audit.evaluate_release_checks(report)

    assert checks["status"] == "blocked"
    assert checks["degraded"] == []
    assert checks["blockers"][0]["code"] == "audit_log_unavailable"
    assert checks["blockers"][0]["message_id"] == "msg-audit-1"


def test_release_checks_block_core_console_regressions() -> None:
    audit = _load_audit_module()

    report = {
        "steps": [
            {
                "label": "audit-exception",
                "body_excerpt": "Audit stopped",
            },
            {
                "label": "api-key-submitted-or-blocked",
                "body_excerpt": "Loading console...",
                "api_key_secret_screenshot_redacted": False,
            }
        ],
        "bad_responses": [
            {
                "status": 503,
                "url": "https://beta.elevenidllc.com/v1/organizations/mine",
                "message_id": "msg-org-503",
            }
        ],
        "failed_requests": [],
        "page_errors": ["boom"],
        "probe": "https://beta.elevenidllc.com/v1/trust-profiles?organization_id=null /console/org/setup-wizard Opening login mk_test_rawsecret",
    }

    checks = audit.evaluate_release_checks(report)
    blocker_codes = {entry["code"] for entry in checks["blockers"]}

    assert checks["status"] == "blocked"
    assert {
        "null_organization_request",
        "old_setup_wizard",
        "login_interstitial",
        "raw_secret_in_report",
        "api_key_screenshot_not_redacted",
        "terminal_loading_state",
        "service_503",
        "page_error",
        "audit_exception",
        "audit_coverage_incomplete",
    }.issubset(blocker_codes)


def test_release_checks_block_incomplete_audit_even_without_errors() -> None:
    audit = _load_audit_module()

    checks = audit.evaluate_release_checks({
        "steps": [{"label": "auth-probe", "body_excerpt": "Dashboard"}],
        "bad_responses": [],
        "failed_requests": [],
        "page_errors": [],
    })

    assert checks["status"] == "blocked"
    assert checks["blockers"][0]["code"] == "audit_coverage_incomplete"
    assert "api-key-submitted-or-blocked" in checks["blockers"][0]["missing_steps"]
