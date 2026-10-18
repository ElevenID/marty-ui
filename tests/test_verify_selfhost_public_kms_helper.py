"""Admission checks for the future qualified helper handoff (not activated)."""

from __future__ import annotations

import json
import os
import struct
import subprocess
from pathlib import Path

import pytest

from scripts import verify_selfhost_public_kms_helper as verifier
from scripts import record_selfhost_public_kms_helper as producer

SOURCE = "a" * 40
RUN = "123"


def _certificate(run: str = RUN, source: str = SOURCE) -> str:
    return json.dumps(
        [
            {
                "attestation": {},
                "verificationResult": {
                    "signature": {
                        "certificate": {
                            "runInvocationURI": f"https://github.com/ElevenID/marty-ui/actions/runs/{run}/attempts/1",
                            "runnerEnvironment": "github-hosted",
                            "githubWorkflowRepository": "ElevenID/marty-ui",
                            "githubWorkflowRef": "refs/heads/main",
                            "githubWorkflowSHA": source,
                        }
                    }
                },
            }
        ]
    )


def test_verified_certificate_requires_same_protected_run() -> None:
    verifier.verified_certificate(_certificate(), RUN, SOURCE)
    for result in (_certificate("124"), _certificate(source="b" * 40), "[]", "{}"):
        with pytest.raises(ValueError):
            verifier.verified_certificate(result, RUN, SOURCE)
    altered = json.loads(_certificate())
    altered[0]["verificationResult"]["signature"]["certificate"][
        "runnerEnvironment"
    ] = "self-hosted"
    with pytest.raises(ValueError, match="another run"):
        verifier.verified_certificate(json.dumps(altered), RUN, SOURCE)


def _run() -> dict:
    return {
        "id": 123,
        "repository": {"full_name": "ElevenID/marty-ui"},
        "status": "completed",
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": SOURCE,
        "run_attempt": 1,
        "workflow_id": 456,
    }


def test_verified_run_requires_successful_exact_workflow() -> None:
    def read(url: str) -> str:
        if url.endswith("/actions/runs/123"):
            return json.dumps(_run())
        assert url.endswith("/actions/workflows/456")
        return json.dumps({"path": ".github/workflows/cd.yml", "state": "active"})

    verifier.verified_run(RUN, SOURCE, read)
    for field, value in (
        ("conclusion", "failure"),
        ("run_attempt", 2),
        ("head_sha", "b" * 40),
        ("event", "pull_request"),
    ):
        changed = _run()
        changed[field] = value
        with pytest.raises(ValueError, match="not qualified"):
            verifier.verified_run(RUN, SOURCE, lambda _url: json.dumps(changed))


def test_bundle_verifier_uses_anonymous_isolated_gh_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GH_TOKEN", "must-not-forward")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-forward")
    captured: list[dict] = []

    def fake_run(*args, **kwargs):
        captured.append(kwargs)
        return subprocess.CompletedProcess(args[0], 0, "[]", "")

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)
    assert verifier.command(["gh", "attestation", "verify", "subject"]) == "[]"
    [call] = captured
    assert "GH_TOKEN" not in call["env"]
    assert "GITHUB_TOKEN" not in call["env"]
    assert call["env"]["GH_CONFIG_DIR"]
    assert call["timeout"] == 120


def test_both_attested_subjects_are_required_with_same_run(tmp_path) -> None:
    seen: list[str] = []

    def runner(args: list[str]) -> str:
        assert args[:3] == ["gh", "attestation", "verify"]
        assert args[args.index("--signer-workflow") + 1] == verifier.SIGNER
        assert args[args.index("--source-digest") + 1] == SOURCE
        assert (
            args[args.index("--predicate-type") + 1] == "https://slsa.dev/provenance/v1"
        )
        assert args[args.index("--bundle") + 1].endswith(".slsa-bundle.json")
        seen.append(args[3])
        return _certificate()

    binary = tmp_path / "public-kms-jwk"
    receipt = tmp_path / "selfhost-public-kms-jwk.json"
    verifier.verify_subject_attestations(binary, receipt, SOURCE, RUN, runner)
    assert seen == [str(binary), str(receipt)]
    with pytest.raises(ValueError, match="another run"):
        verifier.verify_subject_attestations(
            binary, receipt, SOURCE, RUN, lambda _args: _certificate("124")
        )


@pytest.mark.skipif(os.name != "posix", reason="private Linux extraction contract")
def test_owned_extraction_admission_and_abi_smoke(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "owned"
    directory.mkdir(mode=0o700)
    binary = directory / "public-kms-jwk"
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 16, 3)
    struct.pack_into("<H", header, 18, 62)
    binary.write_bytes(header)
    binary.chmod(0o700)
    monkeypatch.setattr(producer.platform, "system", lambda: "Linux")
    monkeypatch.setattr(producer.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        producer.platform,
        "freedesktop_os_release",
        lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"},
    )
    receipt = producer.record(binary, SOURCE, RUN)
    (directory / "selfhost-public-kms-jwk.json").write_text(
        json.dumps(receipt), encoding="utf-8"
    )

    def runner(args: list[str]) -> str:
        if args[:3] == ["gh", "attestation", "verify"]:
            return _certificate()
        assert args == ["ldd", str(binary)]
        return "/lib64/ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2"

    monkeypatch.setattr(
        verifier.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            _args[0], 1, b"", b"public key is not a supported SPKI PEM\n"
        ),
    )
    for name in (verifier.BINARY_BUNDLE, verifier.RECEIPT_BUNDLE):
        (directory / name).write_text("{}", encoding="ascii")

    def read(url: str) -> str:
        return (
            json.dumps(_run())
            if "actions/runs" in url
            else json.dumps({"path": verifier.WORKFLOW, "state": "active"})
        )

    assert verifier.verify_owned_helper(directory, SOURCE, RUN, runner, read) == binary
    directory.chmod(0o755)
    with pytest.raises(ValueError, match="private and exact"):
        verifier.verify_owned_helper(directory, SOURCE, RUN, runner, read)
