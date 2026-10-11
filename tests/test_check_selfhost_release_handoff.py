"""Public handoff must fail before treating a stack-only release as installable."""

from pathlib import Path
import hashlib
import json
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_selfhost_release_handoff as handoff
from check_selfhost_release_handoff import audit, checksum_entries


def test_stack_only_release_does_not_pass_customer_handoff(tmp_path: Path) -> None:
    # The public v1.1.243 release has these stack assets but no self-host ZIP,
    # image lock or qualification evidence. The audit must fail before parsing
    # stack metadata or reporting an installable customer artifact.
    for name in ("SHA256SUMS", "release-transaction.json"):
        (tmp_path / name).write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="public self-host handoff assets missing") as error:
        audit(tmp_path, "v1.1.243")
    assert "selfhost-bundle.zip" in str(error.value)
    assert "selfhost-qualification.json" in str(error.value)


def test_checksum_manifest_rejects_duplicate_and_path_entries(tmp_path: Path) -> None:
    checksums = tmp_path / "SHA256SUMS"
    digest = "a" * 64
    for content in (f"{digest}  ../selfhost-bundle.zip\n",
                    f"{digest}  selfhost-bundle.zip\n{digest}  selfhost-bundle.zip\n"):
        checksums.write_text(content, encoding="ascii")
        with pytest.raises(ValueError, match="invalid or duplicate"):
            checksum_entries(checksums)


def test_exact_asset_handoff_binds_both_transaction_stages(tmp_path: Path, monkeypatch) -> None:
    source = "b" * 40
    archive_digest = "a" * 64
    receipt = {"run_id": "123", "archive_sha256": archive_digest,
               "image_lock_sha256": "c" * 64, "transaction_sha256": "e" * 64}
    receipt_bytes = json.dumps(receipt).encode()
    transaction = {"repository": "ElevenID/marty-ui", "version": "1.2.3",
                   "source_sha": source, "transaction_id": "same", "state": "promoted"}
    preparation = {**transaction, "state": "qualified"}
    values = {
        "selfhost-bundle.zip": b"ZIP fixture",
        "selfhost-images.json": b"{}",
        "selfhost-bundle-preparation.json": receipt_bytes,
        "selfhost-preparation-transaction.json": json.dumps(preparation).encode(),
        "prepared-selfhost-product-descriptor.json": b"{}",
        "selfhost-product-descriptor.json": json.dumps({
            "product": "organizational-platform", "source": {"commit": source},
            "artifact": {"digest": "sha256:" + archive_digest},
            "preparation": {
                "run_id": "123",
                "receipt_sha256": "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(),
                "image_lock_sha256": "sha256:" + "c" * 64,
                "transaction_sha256": "sha256:" + "e" * 64},
            "qualification": {"state": "qualified", "evidence": [
                "https://github.com/ElevenID/marty-ui/releases/download/v1.2.3/selfhost-qualification.json"]}}).encode(),
        "selfhost-qualification.json": json.dumps({
            "source_sha": source, "archive_sha256": archive_digest,
            "image_lock_sha256": "c" * 64, "transaction_sha256": "e" * 64,
            "run_id": "123", "integration_revision": "f" * 40,
            "qualification": "qualified",
            "steps": {step: {"status": "passed", "evidence_sha256": "d" * 64}
                      for step in handoff.JOURNEY_STEPS}}).encode(),
        "release-transaction.json": json.dumps(transaction).encode(),
    }
    for name, data in values.items():
        (tmp_path / name).write_bytes(data)
    (tmp_path / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in values.items()),
        encoding="ascii")
    monkeypatch.setattr(handoff, "validate_claim", lambda value: value)
    monkeypatch.setattr(handoff, "verify_receipt", lambda *args: receipt)
    monkeypatch.setattr(handoff, "verify_descriptor", lambda *args: None)
    monkeypatch.setattr(handoff, "validate_manifest", lambda *args: None)
    assert audit(tmp_path, "v1.2.3")["asset_closure"] == "present-and-checksummed"

    preparation["transaction_id"] = "other"
    (tmp_path / "selfhost-preparation-transaction.json").write_text(
        json.dumps(preparation), encoding="utf-8")
    values["selfhost-preparation-transaction.json"] = (
        tmp_path / "selfhost-preparation-transaction.json").read_bytes()
    (tmp_path / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in values.items()),
        encoding="ascii")
    with pytest.raises(ValueError, match="another release transaction"):
        audit(tmp_path, "v1.2.3")
