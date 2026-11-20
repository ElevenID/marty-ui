"""Clean-only frontend audit admission after the picomatch advisory withdrawal."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ui_dependency_audit_policy", ROOT / "scripts/ci/audit-ui-dependencies.py")
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


def historical_report(name):
    return json.loads((ROOT / f"tests/fixtures/ui-dependency-audit/{name}-picomatch.json").read_text(encoding="utf-8"))


def clean_report(name):
    if name == "bun":
        return {}
    return {"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {"vulnerabilities": {
        "info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0,
    }}}


def test_clean_reports_pass_with_both_existing_scanner_scopes_preserved(monkeypatch, capsys):
    calls = []
    def scan(command, root):
        calls.append((command, root))
        return clean_report(command[0]), 0
    monkeypatch.setattr(policy, "scan", scan)
    policy.audit(ROOT)
    assert calls == [
        (["bun", "audit", "--json", "--ignore", "GHSA-vfj7-8cjw-p6xm"], ROOT),
        (["npm", "audit", "--json", "--omit=optional", "--package-lock-only", "--audit-level=low"], ROOT),
    ]
    assert capsys.readouterr().out == "Frontend dependency audits passed without findings\n"


def test_clean_scans_need_no_source_hash_reapproval_or_expiring_exception(monkeypatch):
    monkeypatch.setattr(policy, "scan", lambda command, root: (clean_report(command[0]), 0))
    policy.audit(Path("no-reviewed-source-snapshot"))


@pytest.mark.parametrize("scanner", ["bun", "npm"])
def test_historical_picomatch_reports_are_rejected_instead_of_admitted(scanner):
    validator = policy.bun_findings if scanner == "bun" else policy.npm_findings
    with pytest.raises(policy.Refused, match="findings are not accepted"):
        validator(historical_report(scanner))


@pytest.mark.parametrize("scanner", ["bun", "npm"])
@pytest.mark.parametrize("severity", ["info", "low", "moderate", "high", "critical"])
def test_no_finding_has_an_advisory_or_severity_acceptance_path(scanner, severity):
    if scanner == "bun":
        report = {"new-package": [{"url": "https://example.invalid/advisory", "severity": severity}]}
        validator = policy.bun_findings
    else:
        report = clean_report("npm")
        report["vulnerabilities"] = {"new-package": {"name": "new-package", "severity": severity}}
        report["metadata"]["vulnerabilities"].update({severity: 1, "total": 1})
        validator = policy.npm_findings
    with pytest.raises(policy.Refused, match="findings are not accepted"):
        validator(report)


@pytest.mark.parametrize("scanner", ["bun", "npm"])
@pytest.mark.parametrize("status", [0, 1])
def test_audit_refuses_historical_findings_even_if_scanner_exit_status_claims_clean(monkeypatch, scanner, status):
    calls = []
    def scan(command, root):
        calls.append(command[0])
        return (historical_report(scanner), status) if command[0] == scanner else (clean_report(command[0]), 0)
    monkeypatch.setattr(policy, "scan", scan)
    with pytest.raises(policy.Refused):
        policy.audit(ROOT)
    assert calls == ["bun", "npm"]


@pytest.mark.parametrize("scanner", ["bun", "npm"])
def test_clean_documents_cannot_hide_a_failing_scanner_exit_status(monkeypatch, scanner):
    monkeypatch.setattr(policy, "scan", lambda command, root: (clean_report(command[0]), int(command[0] == scanner)))
    with pytest.raises(policy.Refused, match="Inconsistent"):
        policy.audit(ROOT)


@pytest.mark.parametrize("report", [[], None, {"error": "scanner unavailable"}, {"picomatch": []}])
def test_bun_malformed_or_error_documents_are_not_clean_reports(report):
    with pytest.raises(policy.Refused):
        policy.bun_findings(report)


@pytest.mark.parametrize("fault", [
    "missing-version", "wrong-version", "float-version", "error", "missing-rows", "rows-array",
    "missing-metadata", "metadata-array", "missing-counts", "counts-array", "missing-total",
    "false-total", "negative-total", "mismatched-total", "nonzero-severity", "unknown-severity",
])
def test_npm_malformed_incomplete_and_inconsistent_documents_are_not_clean_reports(fault):
    report = clean_report("npm")
    if fault == "missing-version":
        report.pop("auditReportVersion")
    elif fault == "wrong-version":
        report["auditReportVersion"] = 1
    elif fault == "float-version":
        report["auditReportVersion"] = 2.0
    elif fault == "error":
        report["error"] = {"code": "EFAIL"}
    elif fault == "missing-rows":
        report.pop("vulnerabilities")
    elif fault == "rows-array":
        report["vulnerabilities"] = []
    elif fault == "missing-metadata":
        report.pop("metadata")
    elif fault == "metadata-array":
        report["metadata"] = []
    elif fault == "missing-counts":
        report["metadata"].pop("vulnerabilities")
    elif fault == "counts-array":
        report["metadata"]["vulnerabilities"] = []
    elif fault == "missing-total":
        report["metadata"]["vulnerabilities"].pop("total")
    elif fault == "false-total":
        report["metadata"]["vulnerabilities"]["total"] = False
    elif fault == "negative-total":
        report["metadata"]["vulnerabilities"]["total"] = -1
    elif fault == "mismatched-total":
        report["metadata"]["vulnerabilities"]["total"] = 1
    elif fault == "nonzero-severity":
        report["metadata"]["vulnerabilities"]["high"] = 1
    else:
        report["metadata"]["vulnerabilities"]["unknown"] = 0
    with pytest.raises(policy.Refused):
        policy.npm_findings(report)


@pytest.mark.parametrize("raw", [
    '{"picomatch":[],"picomatch":[]}',
    '{"auditReportVersion":2,"vulnerabilities":{},"vulnerabilities":{}}',
    '{"metadata":{"vulnerabilities":{"total":1,"total":0}}}',
])
def test_duplicate_json_fields_are_not_accepted(raw):
    with pytest.raises(policy.Refused, match="Duplicate"):
        policy.document(raw)


@pytest.mark.parametrize("raw", ["[]", "null", "true", "not-json"])
def test_nonobject_or_invalid_json_cannot_become_an_empty_audit(raw):
    with pytest.raises(ValueError):
        policy.document(raw)


def test_scanner_execution_preserves_timeout_and_avoids_shell_or_inherited_input(monkeypatch):
    monkeypatch.setattr(policy.shutil, "which", lambda _: "/reviewed/scanner")
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="{}")
    monkeypatch.setattr(policy.subprocess, "run", run)
    assert policy.scan(["bun", "audit", "--json"], ROOT) == ({}, 0)
    assert calls == [(["/reviewed/scanner", "audit", "--json"], {
        "cwd": ROOT / "ui", "stdin": policy.subprocess.DEVNULL, "capture_output": True,
        "text": True, "encoding": "utf-8", "timeout": 120, "check": False,
    })]


def test_missing_scanner_fails_closed(monkeypatch):
    monkeypatch.setattr(policy.shutil, "which", lambda _: None)
    with pytest.raises(policy.Refused, match="Missing dependency scanner"):
        policy.scan(["bun", "audit"], ROOT)


@pytest.mark.parametrize("status", [-1, 2, 127])
def test_scanner_errors_do_not_become_clean_empty_audits(monkeypatch, status):
    monkeypatch.setattr(policy.shutil, "which", lambda _: "/reviewed/scanner")
    monkeypatch.setattr(policy.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=status, stdout="{}"))
    with pytest.raises(policy.Refused, match="scanner failed"):
        policy.scan(["bun", "audit"], ROOT)


def test_main_rejects_overrides_and_does_not_echo_untrusted_documents(monkeypatch, capsys):
    monkeypatch.setattr(policy.sys, "argv", ["audit", "--now=2026-11-17"])
    assert policy.main() == 1
    monkeypatch.setattr(policy.sys, "argv", ["audit"])
    def refuse(*args):
        raise policy.Refused("PRIVATE_SCANNER_CANARY")
    monkeypatch.setattr(policy, "audit", refuse)
    assert policy.main() == 1
    assert "PRIVATE_SCANNER_CANARY" not in capsys.readouterr().err
