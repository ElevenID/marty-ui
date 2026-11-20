"""The application profile adds a strict npm scope without changing full audits."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("application_dependency_audit", ROOT / "scripts/ci/audit-application-dependencies.py")
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


@pytest.fixture
def profile(tmp_path: Path) -> Path:
    directory = tmp_path / audit.PROFILE
    directory.mkdir(parents=True)
    for name in audit.INPUTS:
        (directory / name).write_text('{"fixture":true}\n', encoding="utf-8")
    return tmp_path


def clean() -> dict:
    return {"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {"vulnerabilities": {
        "info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0,
    }}}


def scanner(monkeypatch: pytest.MonkeyPatch, payload: str, status: int = 0):
    calls = []
    monkeypatch.setattr(audit.shutil, "which", lambda name: "/fixture/npm" if name == "npm" else None)

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, status, stdout=payload, stderr="Untrusted scanner details")

    monkeypatch.setattr(audit.subprocess, "run", run)
    return calls


def test_profile_uses_the_existing_npm_scope_and_a_new_fixed_directory(profile, monkeypatch, capsys):
    calls = scanner(monkeypatch, json.dumps(clean()))
    monkeypatch.setenv("NODE_OPTIONS", "--require /unreviewed.js")
    monkeypatch.setenv("NODE_PATH", "/borrowed/modules")
    monkeypatch.setenv("npm_config_omit", "dev")
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://unreviewed.invalid")
    before = audit.snapshot(profile)
    audit.audit(profile)
    assert len(calls) == 1
    command, options = calls[0]
    assert command == ["/fixture/npm", "audit", "--json", "--omit=optional", "--package-lock-only", "--audit-level=low"]
    assert options["cwd"] == profile / "ui/profiles/application"
    assert options["timeout"] == 120
    assert options["stdin"] == subprocess.DEVNULL
    environment = options["env"]
    assert not {"NODE_OPTIONS", "NODE_PATH", "npm_config_omit", "NPM_CONFIG_REGISTRY"} & environment.keys()
    assert environment["npm_config_registry"] == "https://registry.npmjs.org"
    assert environment["npm_config_ignore_scripts"] == "true"
    assert not Path(environment["npm_config_cache"]).parent.exists()
    assert audit.snapshot(profile) == before
    assert capsys.readouterr().out == "Application dependency profile audit passed without findings\n"


@pytest.mark.parametrize("payload,status", [
    (json.dumps({**clean(), "vulnerabilities": {"picomatch": {"severity": "high"}},
                 "metadata": {"vulnerabilities": {"high": 1, "total": 1}}}), 1),
    (json.dumps({**clean(), "vulnerabilities": {"unknown": {}}, "metadata": {"vulnerabilities": {"total": 1}}}), 0),
    (json.dumps({**clean(), "error": {"message": "scanner failed"}}), 0),
    (json.dumps({**clean(), "auditReportVersion": True}), 0),
    (json.dumps({**clean(), "metadata": {"vulnerabilities": {"total": 0, "low": 1}}}), 0),
    (json.dumps({**clean(), "metadata": {"vulnerabilities": {"total": False}}}), 0),
    ('{"auditReportVersion":2,"vulnerabilities":{},"vulnerabilities":{},"metadata":{"vulnerabilities":{"total":0}}}', 0),
    ('{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"total":0,"total":0}}}', 0),
    ("not JSON", 0),
    ("[]", 0),
    (json.dumps(clean()), 1),
    (json.dumps(clean()), 2),
    (json.dumps(clean()), -9),
])
def test_findings_malformed_documents_and_status_mismatches_are_refused(profile, monkeypatch, capsys, payload, status):
    scanner(monkeypatch, payload, status)
    with pytest.raises((ValueError, TypeError)):
        audit.audit(profile)
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("name", audit.INPUTS)
def test_scanner_cannot_rewrite_profile_inputs(profile, monkeypatch, name):
    scanner(monkeypatch, json.dumps(clean()))

    def rewrite(command, **kwargs):
        with (profile / audit.PROFILE / name).open("a", encoding="utf-8") as target:
            target.write("\n")
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(clean()), stderr="")

    monkeypatch.setattr(audit.subprocess, "run", rewrite)
    with pytest.raises(audit.policy.Refused, match="changed a committed profile input"):
        audit.audit(profile)


def test_timeout_and_missing_scanner_fail_closed(profile, monkeypatch):
    scanner(monkeypatch, json.dumps(clean()))
    monkeypatch.setattr(audit.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("npm", 120)))
    with pytest.raises(subprocess.TimeoutExpired):
        audit.audit(profile)
    monkeypatch.setattr(audit.shutil, "which", lambda name: None)
    with pytest.raises(audit.policy.Refused, match="Missing dependency scanner"):
        audit.audit(profile)


@pytest.mark.parametrize("name", (".npmrc", ".npm-extension.mjs", ".npm-extension.cjs", "npm-shrinkwrap.json"))
def test_project_configuration_is_refused(profile, monkeypatch, name):
    calls = scanner(monkeypatch, json.dumps(clean()))
    (profile / audit.PROFILE / name).write_text("unreviewed", encoding="utf-8")
    with pytest.raises(audit.policy.Refused, match="configuration"):
        audit.audit(profile)
    assert calls == []


def test_symlink_input_and_profile_directory_cannot_select_another_scope(profile, monkeypatch, tmp_path):
    calls = scanner(monkeypatch, json.dumps(clean()))
    target = profile / audit.PROFILE / "package-lock.json"
    original = target.read_bytes()
    target.unlink()
    external = tmp_path / "other-lock.json"
    external.write_bytes(original)
    target.symlink_to(external)
    with pytest.raises(OSError):
        audit.audit(profile)
    target.unlink()
    target.write_bytes(original)
    directory = profile / audit.PROFILE
    directory.rename(directory.with_name("other"))
    directory.symlink_to(directory.with_name("other"), target_is_directory=True)
    with pytest.raises(audit.policy.Refused, match="not ordinary"):
        audit.audit(profile)
    assert calls == []


def test_cli_has_no_arbitrary_profile_or_skip_options(monkeypatch, capsys):
    monkeypatch.setattr(audit.sys, "argv", ["audit-application-dependencies.py", "--profile", "/other"])
    assert audit.main() == 1
    assert "accepts no arguments" in capsys.readouterr().err
