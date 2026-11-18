"""Private native rehearsal transport, including uncertain cleanup handling."""
import io
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[1]


def invoke(monkeypatch, payload, native):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    scope = runpy.run_path(str(ROOT / "scripts/rehearse_beta_migrations.py"))
    scope["main"].__globals__["operator_bytes"] = native
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)
    scope["main"]()
    return output.getvalue()


def test_private_payload_is_forwarded_and_only_completed_boolean_is_accepted(monkeypatch):
    calls = []
    def native(*args, **kwargs):
        calls.append((args, kwargs))
        return b'{"completed":true}'
    assert invoke(monkeypatch, b'{"source_id":"synthetic"}', native) == '{"completed": true}'
    assert calls[0][0][1:] == ("operator", "beta-rehearsal")
    assert calls[0][1]["input"] == b'{"source_id":"synthetic"}'
    with pytest.raises(SystemExit, match="live maintenance was not entered"):
        invoke(monkeypatch, b"{}", lambda *a, **k: b'{"completed":1}')


def test_oversized_payload_never_starts_operator(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("operator must not start")
    with pytest.raises(SystemExit, match="fixed bound"):
        invoke(monkeypatch, b"x" * (64 * 1024 + 1), forbidden)


def test_mutation_has_no_outer_kill_timeout_and_cleanup_status_is_preserved(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import selfhost_native_operator as operator
    calls = []
    monkeypatch.delenv("MARTY_DEPLOY_BIN", raising=False)
    def native(*args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(returncode=3, stdout=b"", stderr=b"Beta rehearsal cleanup requires inspection")
    monkeypatch.setattr(operator.subprocess, "run", native)
    with pytest.raises(operator.OperatorCleanupError, match="Beta rehearsal cleanup requires inspection"):
        operator.operator_bytes(ROOT, "operator", "beta-rehearsal", input=b"{}")
    assert calls[0]["timeout"] is None
    def uncertain(*args, **kwargs):
        raise operator.OperatorCleanupError("Beta rehearsal cleanup requires inspection")
    with pytest.raises(SystemExit, match="preserve run-owned resources"):
        invoke(monkeypatch, b"{}", uncertain)
