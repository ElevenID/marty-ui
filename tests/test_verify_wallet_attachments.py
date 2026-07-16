from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_wallet_attachments",
    ROOT / "scripts" / "verify_wallet_attachments.py",
)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class FakeResponse(io.BytesIO):
    def __init__(self, content: bytes, final_url: str):
        super().__init__(content)
        self.final_url = final_url

    def geturl(self) -> str:
        return self.final_url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class FakeOpener:
    def __init__(self, responses: dict[str, tuple[bytes, str]]):
        self.responses = responses
        self.requests = []

    def open(self, request, timeout: int):
        self.requests.append((request, timeout))
        content, final_url = self.responses[request.full_url]
        return FakeResponse(content, final_url)


def _fixture(final_scheme: str = "https"):
    payloads = {
        "recording": b"protected recording bytes",
        "request_capture": b"signed request capture",
    }
    attachments = []
    responses = {}
    for kind, content in payloads.items():
        uri = f"https://evidence.example.test/{kind}"
        attachments.append({
            "kind": kind,
            "uri": uri,
            "sha256": hashlib.sha256(content).hexdigest(),
        })
        responses[uri] = (content, f"{final_scheme}://storage.example.test/{kind}")
    return (
        {"schema_version": 2, "mip_version": "0.3.1", "attachments": attachments},
        {"schema_version": 2, "mip_version": "0.3.1", "required_attachment_kinds": list(payloads)},
        FakeOpener(responses),
    )


def test_verifies_downloaded_attachment_bytes(tmp_path: Path) -> None:
    evidence, requirements, opener = _fixture()

    result = VERIFIER.verify_attachments(
        evidence,
        requirements,
        tmp_path,
        bearer_token="protected-token",
        evidence_content_sha256="a" * 64,
        opener=opener,
    )

    assert result["evidence_content_sha256"] == "a" * 64
    assert {item["kind"] for item in result["attachments"]} == {"recording", "request_capture"}
    assert all(item["verified"] for item in result["attachments"])
    assert (tmp_path / "recording.evidence").read_bytes() == b"protected recording bytes"
    assert opener.requests[0][0].get_header("Authorization") == "Bearer protected-token"


def test_rejects_attachment_checksum_mismatch(tmp_path: Path) -> None:
    evidence, requirements, opener = _fixture()
    evidence["attachments"][0]["sha256"] = "0" * 64

    with pytest.raises(VERIFIER.AttachmentError, match="checksum mismatch"):
        VERIFIER.verify_attachments(
            evidence,
            requirements,
            tmp_path,
            evidence_content_sha256="a" * 64,
            opener=opener,
        )


def test_rejects_attachment_that_resolves_outside_https(tmp_path: Path) -> None:
    evidence, requirements, opener = _fixture(final_scheme="http")

    with pytest.raises(VERIFIER.AttachmentError, match="resolved outside HTTPS"):
        VERIFIER.verify_attachments(
            evidence,
            requirements,
            tmp_path,
            evidence_content_sha256="a" * 64,
            opener=opener,
        )
