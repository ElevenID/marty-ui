"""Synthetic offline fixtures for the unqualified product descriptor."""

import copy
import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import release_transaction as transaction
from check_prepared_selfhost_consumer import verify_descriptor
from produce_selfhost_product_descriptor import produce
from record_selfhost_bundle_preparation import record


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


@pytest.fixture
def inputs(tmp_path):
    source = "b" * 40
    images = {role: uri + "@sha256:" + "a" * 64
              for role, uri in transaction.IMAGE_URIS.items()}
    image = images["services"]
    lock = tmp_path / "images.json"
    write_json(lock, {"schema": "marty.selfhost-image-lock/v1", "release": "marty-ui@1.2.3",
                      "openbao_didcomm_image": images["openbao_didcomm"],
                      "services": {"app": image, "db-migrate": images["migrations"]}})
    stack = tmp_path / "stack.json"
    write_json(stack, {"schema": "marty.stack-lock/v1", "release_state": "eligible",
                       "release": "marty-ui@1.2.3"})
    claim = transaction.create_claim(
        repository="ElevenID/marty-ui", tag="v1.2.3", source_sha=source,
        stack_lock=stack, claim_run_id="123", image_uris=transaction.IMAGE_URIS,
        tag_absent=True, release_absent=True,
        version_tags_absent={role: True for role in transaction.REQUIRED_IMAGE_ROLES})
    claim = transaction.record_digests(
        claim, {role: "sha256:" + "a" * 64 for role in transaction.REQUIRED_IMAGE_ROLES},
        build_run_id="124")
    claim = transaction.qualify(
        claim, {role: {"run_id": "125", "evidence_sha256": "sha256:" + "c" * 64}
                for role in transaction.REQUIRED_GATE_ROLES})
    claim_path = tmp_path / "transaction.json"
    write_json(claim_path, claim)
    files = {".marty-selfhost-images.json": lock.read_bytes(),
             "docker-compose.selfhost.openbao.yml": (
                 "services:\n  openbao-tls-init:\n    image: " + images["openbao_didcomm"] +
                 "\n  openbao:\n    image: " + images["openbao_didcomm"] +
                 "\n  openbao-unseal:\n    image: " + images["openbao_didcomm"] +
                 "\n  openbao-bootstrap:\n    image: " + images["openbao_didcomm"] + "\n").encode(),
             "docker-compose.yml": (f"services:\n  app:\n    image: {image}\n"
                                    f"  db-migrate:\n    image: {images['migrations']}\n").encode(),
             "README.md": b"experimental fixture\n"}
    marker = {"schema": "marty.selfhost-bundle-files/v1",
              "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
              "directories": [""]}
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bundle/", b"")
        for name, data in files.items():
            bundle.writestr("bundle/" + name, data)
        bundle.writestr("bundle/.marty-selfhost-bundle.json", json.dumps(marker))
    receipt_path = tmp_path / "receipt.json"
    write_json(receipt_path, record(archive, lock, claim_path, source, "126"))
    return archive, lock, claim_path, receipt_path


def test_produces_sparse_exact_unqualified_descriptor(inputs):
    descriptor = produce(*inputs)
    assert descriptor["artifact"]["uri"] == "urn:" + descriptor["artifact"]["digest"]
    assert descriptor["support_state"] == "experimental"
    assert descriptor["qualification"] == {"state": "unqualified", "evidence": []}
    assert descriptor["source"]["commit"] == "b" * 40
    assert descriptor["preparation"]["image_lock_sha256"] == transaction.file_digest(inputs[1])
    for unsupported in ("platform", "capabilities", "license", "sbom", "provenance",
                        "signature", "installation", "dependencies", "compatibility"):
        assert unsupported not in descriptor


def test_consumer_binds_downloaded_descriptor_to_exact_inputs(inputs, tmp_path):
    descriptor_path = tmp_path / "descriptor.json"
    descriptor = produce(*inputs)
    write_json(descriptor_path, descriptor)
    verify_descriptor(*inputs, descriptor_path)
    descriptor["artifact"]["digest"] = "sha256:" + "0" * 64
    write_json(descriptor_path, descriptor)
    with pytest.raises(ValueError, match="descriptor differs"):
        verify_descriptor(*inputs, descriptor_path)


@pytest.mark.parametrize("changed", ["archive", "lock", "transaction", "receipt"])
def test_rejects_changed_exact_input(inputs, changed):
    archive, lock, claim_path, receipt = inputs
    if changed == "archive":
        with archive.open("ab") as stream:
            stream.write(b"changed")
    elif changed == "lock":
        lock.write_bytes(lock.read_bytes() + b" ")
    elif changed == "transaction":
        claim_path.write_bytes(claim_path.read_bytes() + b" ")
    else:
        value = json.loads(receipt.read_text())
        value["archive_sha256"] = "0" * 64
        write_json(receipt, value)
    with pytest.raises(ValueError, match="receipt|lock|inventory|closure"):
        produce(*inputs)


def test_rejects_unqualified_stack_transaction(inputs):
    claim_path = inputs[2]
    claim = json.loads(claim_path.read_text())
    claim["state"] = "digests_recorded"
    claim["gates"] = {}
    write_json(claim_path, claim)
    receipt = record(inputs[0], inputs[1], claim_path, "b" * 40, "126")
    write_json(inputs[3], receipt)
    with pytest.raises(ValueError, match="stack qualification"):
        produce(*inputs)


def test_rejects_valid_but_other_release(inputs):
    lock = inputs[1]
    other = copy.deepcopy(json.loads(lock.read_text()))
    other["release"] = "marty-ui@9.9.9"
    write_json(lock, other)
    # The archive still embeds the original lock; exact input binding fails first.
    with pytest.raises(ValueError, match="embedded image lock"):
        produce(*inputs)


def test_rejects_lock_without_transaction_image_binding(inputs):
    archive, lock, claim_path, receipt_path = inputs
    value = json.loads(lock.read_text())
    value["services"]["app"] = "ghcr.io/elevenid/other@sha256:" + "a" * 64
    write_json(lock, value)
    # ZIP/receipt binding catches a changed lock before the transaction check.
    with pytest.raises(ValueError, match="embedded image lock"):
        produce(archive, lock, claim_path, receipt_path)


def test_rejects_consistent_receipt_with_unbound_transaction_image(inputs):
    archive, lock, claim_path, receipt_path = inputs
    claim = json.loads(claim_path.read_text())
    claim["images"]["services"]["digest"] = "sha256:" + "d" * 64
    write_json(claim_path, claim)
    write_json(receipt_path, record(archive, lock, claim_path, "b" * 40, "126"))
    with pytest.raises(ValueError, match="transaction services image"):
        produce(*inputs)


def test_rejects_consistent_receipt_with_unbound_openbao_image(inputs):
    archive, lock, claim_path, receipt_path = inputs
    claim = json.loads(claim_path.read_text())
    claim["images"]["openbao_didcomm"]["digest"] = "sha256:" + "d" * 64
    write_json(claim_path, claim)
    write_json(receipt_path, record(archive, lock, claim_path, "b" * 40, "126"))
    with pytest.raises(ValueError, match="transaction OpenBao DIDComm image"):
        produce(*inputs)
