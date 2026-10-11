"""Linux/amd64 preflight must bind every service to anonymously pulled bytes."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_selfhost_locked_image_platform import probe  # noqa: E402

IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
OTHER = "quay.io/openbao/openbao@sha256:" + "b" * 64


def lock(tmp_path: Path, services: dict[str, str] | None = None) -> Path:
    path = tmp_path / "lock.json"
    path.write_text(json.dumps({"schema": "marty.selfhost-image-lock/v1",
                                "services": services or {"gateway": IMAGE, "worker": IMAGE,
                                                         "openbao": OTHER}}), encoding="utf-8")
    return path


def test_exact_pull_platform_and_digest_association(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert kwargs == {"check": True, "capture_output": True, "text": True}
        if argv[1] == "pull":
            assert argv[2:4] == ["--platform", "linux/amd64"]
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 0, json.dumps({
            "Os": "linux", "Architecture": "amd64", "RepoDigests": [argv[3]]}), "")

    monkeypatch.setattr(subprocess, "run", run)
    result = probe(lock(tmp_path))
    assert result["qualification"] == "unqualified"
    assert result["platform"] == "linux/amd64"
    assert len(result["images"]) == 2
    assert len(calls) == 4


@pytest.mark.parametrize("os,arch,digests", [
    ("linux", "arm64", [IMAGE]),
    ("windows", "amd64", [IMAGE]),
    ("linux", "amd64", [OTHER]),
    ("linux", "amd64", []),
])
def test_rejects_wrong_platform_or_unbound_inspection(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        os: str, arch: str, digests: list[str]) -> None:
    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        output = "" if argv[1] == "pull" else json.dumps({
            "Os": os, "Architecture": arch, "RepoDigests": digests})
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ValueError):
        probe(lock(tmp_path, {"gateway": IMAGE}))


def test_rejects_pull_failure_and_mutable_reference(tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="exact service digests"):
        probe(lock(tmp_path, {"gateway": "ghcr.io/elevenid/marty-ui-oss/services:latest"}))

    def fail(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(ValueError, match="cannot anonymously pull"):
        probe(lock(tmp_path, {"gateway": IMAGE}))
