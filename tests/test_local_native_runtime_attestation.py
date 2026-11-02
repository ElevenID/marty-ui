"""Focused loaded-process controls for the optional local issuer overlay."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import local_native_runtime_attestation as attestation  # noqa: E402


def test_loaded_process_uid_and_mount_must_match_reviewed_binary(tmp_path: Path, monkeypatch) -> None:
    project = "marty-conformance-test"
    image = "sha256:" + "d" * 64
    binaries = {role: tmp_path / binary for role, binary in attestation.ROLES.items()}
    for path in binaries.values():
        path.write_bytes(path.name.encode())
    (tmp_path / "binding.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(attestation, "load_binding", lambda _path: (binaries, image))
    uid = ["10001"]
    mount_source = [None]
    binary_hash = {role: hashlib.sha256(path.read_bytes()).hexdigest() for role, path in binaries.items()}

    def docker(*args: str) -> str:
        if args[0] == "ps":
            role = args[-1].rsplit("=", 1)[1]
            return (str(list(attestation.ROLES).index(role) + 1) * 64)[:64]
        cid = args[1]
        role = list(attestation.ROLES)[int(cid[0]) - 1]
        if args[0] == "inspect":
            return json.dumps([{"Id": cid, "Image": image,
                "State": {"Running": True, "Pid": 10, "StartedAt": "2026-11-01T00:00:00Z"},
                "Config": {"Labels": {"com.docker.compose.project": project,
                                      "com.docker.compose.service": role}},
                "Mounts": [{"Destination": f"/usr/local/bin/{attestation.ROLES[role]}",
                            "Source": mount_source[0] or attestation.daemon_source(binaries[role]),
                            "RW": False}]}])
        if args[0] == "exec" and args[2] == "cat":
            return f"Name:\tmarty\nUid:\t10001\t{uid[0]}\t10001\t10001\n"
        return binary_hash[role] + "  /proc/1/exe"

    monkeypatch.setattr(attestation, "_docker", docker)
    observed = attestation.observe(project, tmp_path / "binding.json")
    assert observed["releaseQualified"] is False and len(observed["roles"]) == 3
    uid[0] = "0"
    with pytest.raises(ValueError, match="effective UID"):
        attestation.observe(project, tmp_path / "binding.json")
    uid[0] = "10001"
    binary_hash["auth"] = "a" * 64
    with pytest.raises(ValueError, match="loaded binary"):
        attestation.observe(project, tmp_path / "binding.json")
    binary_hash["auth"] = hashlib.sha256(binaries["auth"].read_bytes()).hexdigest()
    mount_source[0] = "/run/desktop/mnt/host/c/unreviewed"
    with pytest.raises(ValueError, match="running binary mount"):
        attestation.observe(project, tmp_path / "binding.json")
    mount_source[0] = None
    original_hash = attestation._hash_file
    reads = [0]

    def changed_binding(path: Path) -> str:
        if path.name == "binding.json":
            reads[0] += 1
            if reads[0] == 2:
                return "0" * 64
        return original_hash(path)

    monkeypatch.setattr(attestation, "_hash_file", changed_binding)
    with pytest.raises(ValueError, match="binding changed"):
        attestation.observe(project, tmp_path / "binding.json")
