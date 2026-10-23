"""Native cleanup failures must survive every public provisioning entrypoint."""
import argparse
import importlib
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import selfhost_native_operator as native  # noqa: E402
from tests.test_selfhost_native_approle import approle_server as approle_server  # noqa: E402

ENTRYPOINTS = ("audit_identity", "evidence_identity", "renewal_identity", "ca_rotation_identity",
               "snapshot_identity", "snapshot_rotator", "audit_token", "custody_signer")


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("code,raw,expected", [
    (3, "AppRole bootstrap cleanup is incomplete", "AppRole bootstrap cleanup is incomplete"),
    (3, "AppRole leaf cleanup is unconfirmed", "AppRole leaf cleanup is unconfirmed"),
    (3, "untrusted diagnostic containing a synthetic-secret", "Rust operator cleanup is unconfirmed"),
    (2, "untrusted diagnostic containing a synthetic-secret", None),
])
def test_cli_preserves_only_sanitized_cleanup_diagnostics(
    tmp_path, monkeypatch, capsys, entrypoint, code, raw, expected,
):
    module = importlib.import_module(f"provision_selfhost_{entrypoint}")
    ca = tmp_path / "ca.crt"
    ca.write_text("synthetic public CA")
    root = tmp_path / "openbao-state" / "root.token"
    output = tmp_path / {"audit_identity": "audit-identity", "evidence_identity": "evidence-identity",
                         "snapshot_rotator": "snapshot-rotator-identity"}.get(entrypoint, "identity")
    values = dict(mode="bootstrap", bao_addr="https://127.0.0.1:18200", bao_ca=ca,
                  root_token_file=root, token_file=root, output=output,
                  current_secrets=tmp_path / "current", identity=None, rotator_identity=None,
                  retired_identity=None, kind=None, version=None, org_id="synthetic-org",
                  org_slug="synthetic", did="did:web:example.test", endpoint="https://127.0.0.1:18200",
                  state_root=root.parent, output_root=tmp_path / "secrets", project_name="synthetic",
                  refresh_token=False, identity_root=None)
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", lambda *_: SimpleNamespace(**values))
    monkeypatch.setattr(module, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(module, "Bao", lambda *_: object())
    if hasattr(module, "private_file"):
        monkeypatch.setattr(module, "private_file", lambda *_: "synthetic-root-01234567890123456789")
    if hasattr(module, "policy_for"):
        monkeypatch.setattr(module, "policy_for", lambda *_: ("synthetic policy", ()))
    monkeypatch.setattr(native, "operator_command", lambda *_: ["native-operator"])

    def run(*_args, **kwargs):
        assert kwargs["capture_output"] is True
        return SimpleNamespace(returncode=code, stderr=raw.encode(), stdout=b"")

    monkeypatch.setattr(native.subprocess, "run", run)

    def operation(*_args, **_kwargs):
        return native.operator_bytes(tmp_path, "operator", "approle-bootstrap", input=b"{}")

    monkeypatch.setattr(module, "provision" if entrypoint in ("audit_token", "custody_signer") else "bootstrap",
                        operation)
    assert module.main() == (3 if code == 3 else 2)
    output = capsys.readouterr()
    assert output.out == ""
    assert "synthetic-secret" not in output.err
    if expected:
        assert output.err == expected + "\n"
    else:
        assert "RuntimeError" in output.err
        assert "cleanup" not in output.err


def test_native_bootstrap_cleanup_failure_reaches_cli(approle_server, monkeypatch, capsys):
    module = importlib.import_module("provision_selfhost_snapshot_identity")
    state = approle_server
    bao, identity = state.prepare("snapshot", bootstrap=True)
    root = identity.parent / "root.token"
    root.write_text(bao.token)
    root.chmod(0o600)
    state.fail_path = "auth/selfhost-snapshot/role/raft-exporter/secret-id"
    state.cleanup = 500
    monkeypatch.setattr(sys, "argv", ["snapshot", "--bao-addr", bao.endpoint,
                                      "--bao-ca", str(bao.ca), "--root-token-file", str(root),
                                      "--output", str(identity)])
    assert module.main() == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "AppRole bootstrap cleanup is incomplete\n"
    assert len(state.deleted) == 3
    assert not list(identity.iterdir())


def test_native_leaf_revocation_failure_reaches_cli(approle_server, monkeypatch, capsys):
    module = importlib.import_module("provision_selfhost_evidence_identity")
    state = approle_server
    bao, identity = state.prepare("evidence")
    state.overrides["POST", "auth/token/lookup"] = 200, {"data": {"orphan": False}}
    state.overrides["POST", "auth/token/revoke-self"] = 500, {}
    output = identity.parent / "leaf.token"
    monkeypatch.setattr(sys, "argv", ["evidence", "--mode", "mint", "--bao-addr", bao.endpoint,
                                      "--bao-ca", str(bao.ca), "--identity", str(identity),
                                      "--output", str(output)])
    assert module.main() == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "AppRole leaf cleanup is unconfirmed\n"
    assert any(path == "auth/token/revoke-self" for _, path, _, _ in state.seen)
    assert not output.exists()
