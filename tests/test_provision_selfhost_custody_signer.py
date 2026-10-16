"""The disposable signer helper keeps operator secret material out of source."""

import sys
from pathlib import Path
from urllib.error import HTTPError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_custody_signer as signer


def test_refresh_revokes_old_token_before_replacement(tmp_path: Path) -> None:
    token_file = tmp_path / "selfhost_custody_signer_token"
    token_file.write_text("old", encoding="ascii")

    class BaoSuccess:
        def request(self, method: str, path: str, body: dict) -> None:
            assert (method, path, body["token"]) == (
                "POST", "auth/token/revoke", "old")
            assert token_file.read_text(encoding="ascii") == "old"

    signer.refresh_scoped_token(
        BaoSuccess(), token_file, "new",
        lambda path, value, mode: path.write_text(value, encoding="ascii"),
    )
    assert token_file.read_text(encoding="ascii") == "new"
    assert not token_file.with_name(token_file.name + ".new").exists()


def test_refresh_keeps_old_token_if_revocation_fails(tmp_path: Path) -> None:
    token_file = tmp_path / "selfhost_custody_signer_token"
    token_file.write_text("old", encoding="ascii")
    calls = []

    class BaoFailure:
        def request(self, method: str, path: str, body: dict) -> None:
            calls.append((method, path, body["token"]))
            if body["token"] == "old":
                raise HTTPError("https://127.0.0.1", 503, "unavailable", {}, None)

    def write(path: Path, value: str, mode: int) -> None:
        assert mode == 0o400
        path.write_text(value, encoding="ascii")

    with pytest.raises(HTTPError) as error:
        signer.refresh_scoped_token(BaoFailure(), token_file, "new", write)
    assert error.value.code == 503
    assert token_file.read_text(encoding="ascii") == "old"
    assert not token_file.with_name(token_file.name + ".new").exists()
    assert calls == [
        ("POST", "auth/token/revoke", "old"),
        ("POST", "auth/token/revoke", "new"),
    ]


def test_refresh_preserves_new_token_if_cleanup_fails(tmp_path: Path) -> None:
    token_file = tmp_path / "selfhost_custody_signer_token"
    token_file.write_text("old", encoding="ascii")

    class BaoFailure:
        def request(self, method: str, path: str, body: dict) -> None:
            raise HTTPError("https://127.0.0.1", 503, "unavailable", {}, None)

    with pytest.raises(RuntimeError, match="operator recovery"):
        signer.refresh_scoped_token(
            BaoFailure(), token_file, "new",
            lambda path, value, mode: path.write_text(value, encoding="ascii"),
        )
    assert token_file.read_text(encoding="ascii") == "old"
    assert token_file.with_name(token_file.name + ".new").read_text(encoding="ascii") == "new"


def test_operator_root_must_be_private_and_outside_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    candidate = source / "operator-secrets"
    candidate.mkdir(mode=0o700)
    monkeypatch.setattr(signer, "SOURCE_ROOT", source)
    with pytest.raises(ValueError, match="outside the source checkout"):
        signer.private_directory(candidate)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    assert signer.private_directory(outside) == outside.resolve()
    outside.chmod(0o755)
    with pytest.raises(ValueError, match="private directory"):
        signer.private_directory(outside)
