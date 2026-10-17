"""Disposable audit access is exact, short-lived and recoverable."""

import os
import stat
import sys
from pathlib import Path
from urllib.error import HTTPError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_audit_token as audit  # noqa: E402


ORG = "00000000-0000-0000-0000-000000000001"
DID = f"did:web:localhost%3A19080:orgs:{ORG}"


def test_policy_uses_exact_managed_references() -> None:
    policy, paths = audit.policy_for(ORG, DID)
    assert len(paths) == 3
    assert paths[0].startswith("transit/keys/cred-issuer-")
    assert paths[1].startswith("transit/keys/oid4vp-verifier-")
    assert paths[2] == "transit/keys/selfhost-qualification-custody-v1"
    assert all(f'path "{path}" {{ capabilities = ["read"] }}' in policy
               for path in paths)
    assert "*" not in policy
    assert 'path "sys/capabilities-self" { capabilities = ["update"] }' in policy
    with pytest.raises(ValueError, match="organization"):
        audit.policy_for(ORG, f"did:web:foreign:orgs:{ORG[:-1]}2")


@pytest.mark.parametrize("orphan,excess,revoke_fails", [
    (True, False, False), (False, False, False), (True, True, False),
    (False, False, True),
])
def test_provision_validates_and_recovers_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    orphan: bool, excess: bool, revoke_fails: bool,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX private-file behavior")
    state = tmp_path / "state"
    output = tmp_path / "output"
    (state / "tls").mkdir(parents=True)
    output.mkdir()
    state.chmod(0o700)
    output.chmod(0o700)
    (state / "root.token").write_text("r" * 16, encoding="ascii")
    (state / "tls" / "ca.crt").write_text("ca", encoding="ascii")
    calls: list[tuple[str, str, dict | None]] = []
    _, allowed = audit.policy_for(ORG, DID)

    class FakeBao:
        def __init__(self, endpoint: str, ca: Path, token: str) -> None:
            assert endpoint == "https://127.0.0.1:18200"
            assert ca == state / "tls" / "ca.crt"
            self.token = token

        def request(self, method: str, path: str, body: dict | None = None) -> dict:
            calls.append((method, path, body))
            if path == "auth/token/create":
                assert self.token == "r" * 16
                assert body is not None
                assert body["no_parent"] is True
                assert body["no_default_policy"] is True
                return {"auth": {"client_token": "scoped"}}
            if path == "auth/token/lookup-self":
                assert self.token == "scoped"
                return {"data": {"policies": [audit.POLICY], "ttl": 3600,
                                 "orphan": orphan}}
            if path == "sys/capabilities-self":
                assert self.token == "scoped"
                assert body is not None
                access = {name: ["read"] for name in allowed}
                access.update({name: ["deny"] for name in body["paths"]
                               if name not in allowed})
                if excess:
                    access[f"transit/sign/{audit.SIGNER}"] = ["update"]
                return access
            if path == "auth/token/revoke" and revoke_fails:
                raise HTTPError("https://127.0.0.1", 503, "unavailable", {}, None)
            return {}

    monkeypatch.setattr(audit, "Bao", FakeBao)
    if orphan and not excess:
        audit.provision("https://127.0.0.1:18200", state, output, ORG, DID)
    elif revoke_fails:
        with pytest.raises(RuntimeError, match="operator recovery"):
            audit.provision("https://127.0.0.1:18200", state, output, ORG, DID)
    else:
        with pytest.raises(ValueError, match="not orphaned|capabilities"):
            audit.provision("https://127.0.0.1:18200", state, output, ORG, DID)
    token_file = output / "selfhost_audit_token"
    assert token_file.exists() is (orphan and not excess or revoke_fails)
    if token_file.exists():
        assert token_file.read_text(encoding="ascii") == "scoped"
        assert stat.S_IMODE(token_file.stat().st_mode) == 0o400
    assert any(path == "auth/token/revoke" for _, path, _ in calls) is not (
        orphan and not excess)


def test_existing_output_refuses_to_create_token(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("POSIX private-file behavior")
    state = tmp_path / "state"
    output = tmp_path / "output"
    (state / "tls").mkdir(parents=True)
    output.mkdir()
    state.chmod(0o700)
    output.chmod(0o700)
    (state / "root.token").write_text("r" * 16, encoding="ascii")
    (state / "tls" / "ca.crt").write_text("ca", encoding="ascii")
    (output / "selfhost_audit_token").write_text("old", encoding="ascii")
    with pytest.raises(ValueError, match="input or output"):
        audit.provision("https://127.0.0.1:18200", state, output, ORG, DID)
