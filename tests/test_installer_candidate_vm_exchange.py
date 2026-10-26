"""Root-held nonce-to-signed-grant rendezvous ordering tests."""
import json
import os
from pathlib import Path
import sys

import pytest

if sys.platform != "linux" or os.geteuid() != 0:
    pytest.skip("VM signed exchange requires Linux root", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_exchange as exchange
from installer_candidate_controller import ControllerLease
import installer_release as release


@pytest.fixture
def arranged(tmp_path, monkeypatch):
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    fixture = json.loads((Path(__file__).resolve().parents[1]
                          / "rust/crates/deployment-catalog/tests/fixtures/installer-candidate-records.json")
                         .read_text())
    grant = release.decode(fixture["authorization"].encode())
    expected = {key: grant[key] for key in release.CONTEXT_FIELDS}
    target = dict(guest_id="11111111-1111-4111-8111-111111111111",
                  disk_id="e" * 64, engine_id="test-engine-12345678",
                  installation_id="22222222-2222-4222-8222-222222222222")
    verified = dict(intent_sha256="a" * 64, receipt_sha256="b" * 64,
                    target=target)
    calls = []
    def verify(lease, _registry, **_kwargs):
        assert lease.parent is not None
        calls.append("verify")
        return verified
    monkeypatch.setattr(exchange, "verify_consumed_intent", verify)
    args = dict(client=object(), registry=registry,
                authorization=tmp_path / "candidate-authorization.json",
                assets=tmp_path / "assets", expected=expected,
                gh=tmp_path / "gh", cosign=tmp_path / "cosign",
                descriptor=tmp_path / "controller-transport.json",
                upload_output=tmp_path / "upload.json",
                grant_output=tmp_path / "grant", controller_user_id=101,
                clock=lambda: 100000)
    return args, verified, calls


def test_exchange_releases_lease_for_transport_and_reverifies(arranged):
    args, verified, calls = arranged
    def upload(**kwargs):
        calls.append("upload")
        with ControllerLease(args["registry"]):
            pass
        assert kwargs["ledger"] == args["registry"] / (args["expected"]["nonce"] + ".json")
        return dict(receipt_sha256=verified["receipt_sha256"],
                    context_sha256=release.candidate_context_sha256(args["expected"]))
    def receive(**kwargs):
        calls.append("receive")
        with ControllerLease(args["registry"]):
            pass
        assert release.decode(kwargs["context_file"].read_bytes()) == args["expected"]
        assert release.decode(kwargs["target_file"].read_bytes()) == verified["target"]
        return dict(receipt_sha256=verified["receipt_sha256"],
                    context_sha256=release.candidate_context_sha256(args["expected"]),
                    target_sha256=release.digest(release.encode(verified["target"])))
    result = exchange.exchange(**args, upload=upload, receive=receive)
    assert calls == ["verify", "upload", "receive", "verify"]
    assert result["guest_dispatched"] is False and result["acceptance"] is False
    assert result["intent_sha256"] == verified["intent_sha256"]


def test_uncertain_upload_stops_without_retrieval_or_retry(arranged):
    args, _, calls = arranged
    def upload(**_kwargs):
        calls.append("upload")
        (args["registry"] / "uncertain-upload-intent").write_text("retained")
        raise OSError("synthetic lost GitHub response")
    def receive(**_kwargs):
        pytest.fail("retrieved grant after uncertain upload")
    with pytest.raises(OSError, match="lost GitHub response"):
        exchange.exchange(**args, upload=upload, receive=receive)
    assert calls == ["verify", "upload"]
    assert (args["registry"] / "uncertain-upload-intent").read_text() == "retained"
    with pytest.raises(FileExistsError):
        exchange.exchange(**args, upload=upload, receive=receive)
    assert calls == ["verify", "upload", "verify"]


def test_mismatched_signed_grant_refuses_completion(arranged):
    args, verified, calls = arranged
    def upload(**_kwargs):
        calls.append("upload")
        return dict(receipt_sha256=verified["receipt_sha256"],
                    context_sha256=release.candidate_context_sha256(args["expected"]))
    def receive(**_kwargs):
        calls.append("receive")
        return dict(receipt_sha256="c" * 64,
                    context_sha256=release.candidate_context_sha256(args["expected"]),
                    target_sha256=release.digest(release.encode(verified["target"])))
    with pytest.raises(ValueError, match="signed execution grant differs"):
        exchange.exchange(**args, upload=upload, receive=receive)
    assert calls == ["verify", "upload", "receive"]
