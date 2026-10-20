"""Pinned registry content must survive tag drift and reject byte/child confusion."""
import hashlib
import json
import subprocess

import pytest

from scripts import check_canvas_oss_portability as checker


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fixture(monkeypatch, case="valid"):
    child = json.dumps({"schemaVersion": 2, "config": {}, "layers": []}).encode()
    descriptor = {"digest": digest(child), "platform": {"os": "linux", "architecture": "amd64"}}
    entries = [descriptor]
    if case == "foreign-child":
        entries = [{**descriptor, "digest": "sha256:" + "f" * 64}]
    elif case == "duplicate-child":
        entries = [descriptor, descriptor]
    elif case == "invalid-platform":
        entries = [{**descriptor, "platform": "linux/amd64"}]
    index = json.dumps({"schemaVersion": 2, "manifests": entries}).encode()
    if case == "invalid-json":
        index = b"not JSON"
    base = {"reference": "instructure/ruby-passenger:3.4-jammy",
            "index_digest": digest(index), "linux_amd64_digest": digest(child)}
    content = {base["index_digest"]: index, base["linux_amd64_digest"]: child}
    if case == "index-byte-mismatch":
        content[base["index_digest"]] += b" "
    if case == "child-byte-mismatch":
        content[base["linux_amd64_digest"]] += b" "
    calls = []

    def fetch(args, **kwargs):
        calls.append(args)
        assert args[:5] == ["docker", "buildx", "imagetools", "inspect", "--raw"]
        # A moved or unavailable mutable tag must never be consulted.
        assert args[5].startswith(base["reference"] + "@sha256:")
        assert kwargs == {"capture_output": True, "check": True, "timeout": 60}
        if case == "registry-failure":
            raise subprocess.CalledProcessError(1, args)
        raw = content[args[5].split("@", 1)[1]]
        return subprocess.CompletedProcess(args, 0, stdout=raw, stderr=b"")

    monkeypatch.setattr(checker.subprocess, "run", fetch)
    return {"image": {"base_image": base}}, calls


def test_moved_mutable_tag_cannot_change_the_verified_locked_base(monkeypatch):
    lock, calls = fixture(monkeypatch)
    assert checker.verify_base_image(lock) == lock["image"]["base_image"]
    assert len(calls) == 2


@pytest.mark.parametrize("case", ["foreign-child", "duplicate-child", "invalid-platform",
                                  "invalid-json", "index-byte-mismatch", "child-byte-mismatch",
                                  "registry-failure"])
def test_missing_confused_or_corrupt_registry_content_stays_denied(monkeypatch, case):
    lock, _ = fixture(monkeypatch, case)
    with pytest.raises(checker.ContractError):
        checker.verify_base_image(lock)
