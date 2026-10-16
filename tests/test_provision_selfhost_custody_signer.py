"""The disposable signer helper keeps operator secret material out of source."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_custody_signer as signer


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
