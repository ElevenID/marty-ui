"""Admission tests for the expiring exact-advisory frontend risk disposition."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ui_dependency_audit_policy", ROOT / "scripts/ci/audit-ui-dependencies.py")
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)


def report(name):
    return json.loads((ROOT / f"tests/fixtures/ui-dependency-audit/{name}-picomatch.json").read_text(encoding="utf-8"))


def packages():
    return json.loads((ROOT / "ui/package-lock.json").read_text(encoding="utf-8"))["packages"]


@pytest.fixture
def context(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    source = root / "ui/src/view.js"
    source.parent.mkdir(parents=True)
    source.write_text("export const fixedPattern = '*.js';\n", encoding="utf-8")
    lock = root / "ui/package-lock.json"
    lock.write_bytes((ROOT / "ui/package-lock.json").read_bytes())
    hashes = {"ui/src": policy.tree_digest(source.parent),
              "ui/package-lock.json": hashlib.sha256(lock.read_bytes()).hexdigest()}
    monkeypatch.setattr(policy, "CONTEXT_SHA256", hashes)
    return root, hashes


def test_exact_reviewed_actual_context_and_real_scanner_shapes_are_accepted():
    locked = policy.reviewed_context(ROOT, NOW)
    assert policy.bun_findings(report("bun")) is True
    assert policy.npm_findings(report("npm"), locked) is True


@pytest.mark.parametrize("field,value", [
    ("id", 999), ("url", "https://example.test/unreviewed"),
    ("severity", "critical"), ("vulnerable_versions", "*"),
])
def test_bun_rejects_changed_advisory_identity_severity_or_range(field, value):
    data = report("bun")
    data["picomatch"][0][field] = value
    with pytest.raises(policy.Refused):
        policy.bun_findings(data)


@pytest.mark.parametrize("data", [
    {"picomatch": []}, {"other-package": [{}]}, {"error": {}},
    {"picomatch": [{"url": policy.ADVISORY_URL}]},
])
def test_bun_cannot_accept_missing_or_other_findings(data):
    with pytest.raises(policy.Refused):
        policy.bun_findings(data)


@pytest.mark.parametrize("field,value", [
    ("source", 999), ("url", "https://example.test/unreviewed"),
    ("severity", "critical"), ("range", "*"), ("dependency", "another-package"),
])
def test_npm_requires_the_exact_reviewed_advisory_root(field, value):
    data = report("npm")
    data["vulnerabilities"]["picomatch"]["via"][0][field] = value
    with pytest.raises(policy.Refused):
        policy.npm_findings(data, packages())


def test_a_second_even_low_severity_advisory_is_not_masked_by_the_reviewed_root():
    data = report("npm")
    extra = copy.deepcopy(data["vulnerabilities"]["picomatch"]["via"][0])
    extra.update(source=999, severity="low", url="https://example.test/second")
    data["vulnerabilities"]["picomatch"]["via"].append(extra)
    with pytest.raises(policy.Refused):
        policy.npm_findings(data, packages())


@pytest.mark.parametrize("fault", ["missing-cause", "empty-cause", "runtime-node", "missing-node", "reclassified-chain", "count"])
def test_transitive_chains_cannot_hide_unreviewed_or_runtime_exposure(fault):
    data, locked = report("npm"), packages()
    row = data["vulnerabilities"]["@storybook/react-vite"]
    if fault == "missing-cause":
        row["via"] = ["missing-dependency"]
    elif fault == "empty-cause":
        row["via"] = []
    elif fault == "runtime-node":
        locked[row["nodes"][0]]["dev"] = False
    elif fault == "missing-node":
        row["nodes"] = ["node_modules/missing"]
    elif fault == "reclassified-chain":
        row["severity"] = "critical"
    else:
        data["metadata"]["vulnerabilities"]["total"] += 1
    with pytest.raises(policy.Refused):
        policy.npm_findings(data, locked)


def test_npm_cycle_without_an_advisory_root_is_not_evidence_of_acceptance():
    data = report("npm")
    data["vulnerabilities"]["picomatch"]["via"] = ["vitest"]
    with pytest.raises(policy.Refused, match="cycle"):
        policy.npm_findings(data, packages())


@pytest.mark.parametrize("fault", ["edit", "add", "lock"])
def test_context_drift_requires_a_new_review(context, fault):
    root, _ = context
    if fault == "edit":
        (root / "ui/src/view.js").write_text("export const unreviewed = true;\n")
    elif fault == "add":
        (root / "ui/src/another.js").write_text("export const unreviewed = true;\n")
    else:
        path = root / "ui/package-lock.json"
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(policy.Refused, match="context changed"):
        policy.reviewed_context(root, NOW)


@pytest.mark.parametrize("field,value", [("dev", False), ("version", "4.0.6")])
def test_even_a_rehashed_lock_cannot_move_the_exception_to_runtime_or_another_version(context, field, value):
    root, hashes = context
    path = root / "ui/package-lock.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["packages"]["node_modules/picomatch"][field] = value
    path.write_text(json.dumps(data), encoding="utf-8")
    hashes["ui/package-lock.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(policy.Refused, match="dev-only|versions changed"):
        policy.reviewed_context(root, NOW)


def test_rehashed_lock_with_an_additional_picomatch_path_is_refused(context):
    root, hashes = context
    path = root / "ui/package-lock.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["packages"]["node_modules/other/node_modules/picomatch"] = {"version": "4.0.7", "dev": True}
    path.write_text(json.dumps(data), encoding="utf-8")
    hashes["ui/package-lock.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(policy.Refused, match="paths changed"):
        policy.reviewed_context(root, NOW)


def test_expiry_is_a_hard_utc_boundary_and_not_a_clock_argument(context):
    root, _ = context
    policy.reviewed_context(root, datetime(2026, 11, 23, 23, 59, 59, tzinfo=timezone.utc))
    with pytest.raises(policy.Refused, match="expired"):
        policy.reviewed_context(root, datetime(2026, 11, 24, tzinfo=timezone.utc))
    with pytest.raises(policy.Refused, match="Aware clock"):
        policy.reviewed_context(root, datetime(2026, 11, 17))


def test_actual_symlinked_source_is_refused_before_it_can_supply_reviewed_bytes(context):
    root, _ = context
    actual = root / "ui/src/view.js"
    saved = root / "saved.js"
    actual.rename(saved)
    try:
        actual.symlink_to(saved)
    except OSError:
        pytest.skip("OS does not permit unprivileged symlinks")
    with pytest.raises(policy.Refused, match="links"):
        policy.reviewed_context(root, NOW)


def test_duplicate_json_fields_are_not_accepted():
    with pytest.raises(policy.Refused, match="Duplicate"):
        policy.document('{"picomatch": [], "picomatch": []}')


def test_scanner_errors_do_not_become_clean_empty_audits(monkeypatch):
    monkeypatch.setattr(policy.shutil, "which", lambda _: "/reviewed/scanner")
    monkeypatch.setattr(policy.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=2, stdout="{}"))
    with pytest.raises(policy.Refused, match="scanner failed"):
        policy.scan(["bun", "audit"], ROOT)


def test_actual_both_scanner_shapes_pass_through_with_all_scopes_preserved(monkeypatch, capsys):
    calls = []
    def scan(command, root):
        calls.append(command)
        return report(command[0]), 1
    monkeypatch.setattr(policy, "scan", scan)
    policy.audit(ROOT, NOW)
    assert calls == [["bun", "audit", "--json", "--ignore", "GHSA-vfj7-8cjw-p6xm"],
                     ["npm", "audit", "--json", "--omit=optional", "--package-lock-only", "--audit-level=low"]]
    assert "CI/dev DoS risk remains" in capsys.readouterr().out


def test_no_findings_after_remediation_needs_no_extension_or_old_context(monkeypatch):
    def scan(command, root):
        return ({}, 0) if command[0] == "bun" else ({"auditReportVersion": 2, "vulnerabilities": {},
                                                    "metadata": {"vulnerabilities": {"total": 0}}}, 0)
    monkeypatch.setattr(policy, "scan", scan)
    policy.audit(Path("missing-reviewed-source"), datetime(2026, 11, 25, tzinfo=timezone.utc))


@pytest.mark.parametrize("status", [0, 1])
def test_scanner_status_must_agree_with_its_document(monkeypatch, status):
    monkeypatch.setattr(policy, "scan", lambda command, root: (report("bun"), 0) if status == 0 else ({}, 1))
    with pytest.raises(policy.Refused, match="Inconsistent Bun"):
        policy.audit(ROOT, NOW)


def test_main_rejects_clock_overrides_and_does_not_echo_untrusted_documents(monkeypatch, capsys):
    monkeypatch.setattr(policy.sys, "argv", ["audit", "--now=2026-11-17"])
    assert policy.main() == 1
    monkeypatch.setattr(policy.sys, "argv", ["audit"])
    def refuse(*args):
        raise policy.Refused("PRIVATE_SCANNER_CANARY")
    monkeypatch.setattr(policy, "audit", refuse)
    assert policy.main() == 1
    assert "PRIVATE_SCANNER_CANARY" not in capsys.readouterr().err


def test_expiry_is_checked_after_scanners_finish(monkeypatch):
    calls = []
    def scan(command, root):
        calls.append(command[0])
        return report(command[0]), 1
    class Clock:
        @staticmethod
        def now(zone):
            assert calls == ["bun", "npm"]
            return datetime(2026, 11, 24, tzinfo=zone)
    monkeypatch.setattr(policy, "scan", scan)
    monkeypatch.setattr(policy, "datetime", Clock)
    with pytest.raises(policy.Refused, match="expired"):
        policy.audit(ROOT)


def test_crossing_expiry_during_context_hashing_refuses_final_admission(monkeypatch):
    moments = [datetime(2026, 11, 23, 23, 59, 59, tzinfo=timezone.utc),
               datetime(2026, 11, 24, tzinfo=timezone.utc)]
    class Clock:
        @staticmethod
        def now(zone):
            return moments.pop(0)
    monkeypatch.setattr(policy, "scan", lambda command, root: (report(command[0]), 1))
    monkeypatch.setattr(policy, "datetime", Clock)
    with pytest.raises(policy.Refused, match="expired"):
        policy.audit(ROOT)
    assert not moments
