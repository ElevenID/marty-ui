"""Durable controller dispatch tests; synthetic records are not acceptance."""
import json
import os
from pathlib import Path
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("controller dispatch registry requires Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_controller as controller


@pytest.fixture
def transaction(tmp_path):
    fixture = json.loads((Path(__file__).resolve().parents[1]
                          / "rust/crates/deployment-catalog/tests/fixtures/installer-candidate-records.json")
                         .read_text())
    authorization = fixture["authorization"].encode()
    inventory = fixture["inventory"].encode()
    record = json.loads(authorization)
    expected = {key: record[key] for key in ("source_sha", "release_tag", "operator_sha256",
                                            "phase", "nonce", "harness_source_sha", "run_id",
                                            "run_attempt")}
    registry = tmp_path / "controller"
    registry.mkdir(mode=0o700)
    return registry, authorization, inventory, dict(
        expected=expected, guest_id="d15c8075-a026-4e0e-ab9a-ec0fa3c39586", disk_id="d" * 64,
        engine_id="test-engine-12345678", installation_id="7b27ca49-c523-4a2b-9bac-60560cf25dbc",
        consumed_at=100001, now=100001)


def test_receipt_is_durable_and_replay_with_new_guest_is_refused(transaction):
    registry, authorization, inventory, options = transaction
    raw = controller.consume(registry, authorization, inventory, **options)
    saved = registry / (options["expected"]["nonce"] + ".json")
    assert saved.read_bytes() == raw
    assert saved.stat().st_mode & 0o777 == 0o600
    options["guest_id"] = "fb99a0d8-95fa-4356-a166-f2f50118a798"
    with pytest.raises(FileExistsError):
        controller.consume(registry, authorization, inventory, **options)
    assert saved.read_bytes() == raw


def test_failed_write_burns_dispatch_and_cannot_return_a_receipt(transaction, monkeypatch):
    registry, authorization, inventory, options = transaction
    original = os.fsync
    calls = 0

    def fail_file_sync(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic interrupted persistence")
        original(fd)

    with monkeypatch.context() as patch:
        patch.setattr(controller.os, "fsync", fail_file_sync)
        with pytest.raises(OSError):
            controller.consume(registry, authorization, inventory, **options)
    with pytest.raises(FileExistsError):
        controller.consume(registry, authorization, inventory, **options)


def test_partial_claim_and_registry_link_refuse(transaction):
    registry, authorization, inventory, options = transaction
    (registry / (options["expected"]["nonce"] + ".json")).touch(mode=0o600)
    with pytest.raises(FileExistsError):
        controller.consume(registry, authorization, inventory, **options)
    link = registry.parent / "link"
    link.symlink_to(registry, target_is_directory=True)
    with pytest.raises(OSError):
        controller.consume(link, authorization, inventory, **options)


def test_mismatched_context_does_not_consume(transaction):
    registry, authorization, inventory, options = transaction
    options["expected"]["run_attempt"] += 1
    with pytest.raises(ValueError):
        controller.consume(registry, authorization, inventory, **options)
    assert list(registry.iterdir()) == []


def test_concurrent_controller_owner_refuses_before_consumption(transaction):
    registry, authorization, inventory, options = transaction
    parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
    try:
        controller.fcntl.flock(parent, controller.fcntl.LOCK_EX | controller.fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            controller.consume(registry, authorization, inventory, **options)
        assert list(registry.iterdir()) == []
    finally:
        os.close(parent)
