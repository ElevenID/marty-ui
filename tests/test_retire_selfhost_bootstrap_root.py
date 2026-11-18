"""Root retirement must finish both scoped audits before dropping recovery state."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from urllib.error import HTTPError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import retire_selfhost_bootstrap_root as retirement  # noqa: E402


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner-private root file")
@pytest.mark.parametrize("already_revoked", [False, True])
def test_retirement_audits_before_and_after_root_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, already_revoked: bool,
) -> None:
    state = tmp_path / "openbao-state"
    state.mkdir(mode=0o700)
    token_file = state / "root.token"
    token_file.write_text("root-test-token-of-sufficient-length\n", encoding="ascii")
    token_file.chmod(0o400)
    args = argparse.Namespace(openbao_state_dir=state, bao_addr="https://127.0.0.1:8200",
                              bao_ca=tmp_path / "ca.crt")
    events: list[str] = []

    def audit(_args: argparse.Namespace) -> Path:
        events.append("audit")
        return tmp_path / f"snapshot-{len(events)}.zip"

    class Bao:
        def __init__(self, _addr: str, _ca: Path, token: str) -> None:
            assert token == "root-test-token-of-sufficient-length"
            self.valid = not already_revoked

        def request(self, method: str, path: str, body: dict | None = None) -> dict:
            if path == "auth/token/lookup-self":
                events.append("lookup")
                if not self.valid:
                    raise HTTPError("https://127.0.0.1:8200", 403, "denied", {}, None)
                return {"data": {"policies": ["root"]}}
            assert method == "POST" and path == "auth/token/revoke"
            assert body == {"token": "root-test-token-of-sufficient-length"}
            events.append("revoke")
            self.valid = False
            return {}

    monkeypatch.setattr(retirement, "audit", audit)
    monkeypatch.setattr(retirement, "Bao", Bao)
    before, after = retirement.retire(args)
    assert before.name == "snapshot-1.zip" and after.name.endswith(".zip")
    assert events == (["audit", "lookup", "audit"] if already_revoked else
                      ["audit", "lookup", "lookup", "revoke", "lookup", "audit"])
    assert not token_file.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner-private root file")
def test_failed_post_audit_keeps_revoked_root_file_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "openbao-state"
    state.mkdir(mode=0o700)
    token_file = state / "root.token"
    token_file.write_text("root-test-token-of-sufficient-length\n", encoding="ascii")
    token_file.chmod(0o400)
    args = argparse.Namespace(openbao_state_dir=state, bao_addr="https://127.0.0.1:8200",
                              bao_ca=tmp_path / "ca.crt")
    calls = 0

    def audit(_args: argparse.Namespace) -> Path:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("post-revocation scoped audit failed")
        return tmp_path / "before.zip"

    class Bao:
        valid = True

        def __init__(self, *_args: object) -> None:
            pass

        def request(self, method: str, path: str, _body: dict | None = None) -> dict:
            if path == "auth/token/lookup-self":
                if not self.valid:
                    raise HTTPError("https://127.0.0.1:8200", 403, "denied", {}, None)
                return {"data": {"policies": ["root"]}}
            assert method == "POST" and path == "auth/token/revoke"
            self.valid = False
            return {}

    monkeypatch.setattr(retirement, "audit", audit)
    monkeypatch.setattr(retirement, "Bao", Bao)
    with pytest.raises(RuntimeError, match="post-revocation"):
        retirement.retire(args)
    assert token_file.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner-private root file")
def test_root_file_requires_private_regular_path(tmp_path: Path) -> None:
    state = tmp_path / "openbao-state"
    state.mkdir(mode=0o700)
    token_file = state / "root.token"
    token_file.write_text("root-test-token-of-sufficient-length\n", encoding="ascii")
    token_file.chmod(0o644)
    with pytest.raises(ValueError, match="ownership or mode"):
        retirement.root_token(token_file, state)
    token_file.chmod(0o400)
    with pytest.raises(ValueError, match="outside owned"):
        retirement.root_token(token_file, tmp_path)
