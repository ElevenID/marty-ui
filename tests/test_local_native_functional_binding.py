"""Focused controls for the optional local OIDF native binary overlay."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from local_native_functional_binding import ROLES, load_binding  # noqa: E402


IMAGE_ID = "sha256:" + "a" * 64


def _ref(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _binding(tmp_path: Path) -> Path:
    roles = {}
    for role, binary in ROLES.items():
        binary_path = tmp_path / binary
        binary_path.write_bytes((binary + "-candidate").encode())
        source_proof = tmp_path / (binary + "-source.json")
        if role == "auth":
            source = {"schema": "marty.d05-auth-native-overlay-source-proof/v1",
                      "sourceCommit": "b" * 40, "acceptedCommit": "c" * 40,
                      "executionHeld": True, "mutation": False,
                      "binary": {"path": str(binary_path), "sha256": _ref(binary_path)["sha256"],
                                 "target": "/usr/local/bin/marty-auth"}}
        else:
            source = {"state": "BUILD_SUCCEEDED", "uiRevision": "b" * 40,
                      "exitCode": 0, "oomKilled": False, "releaseQualified": False,
                      "roleBinaries": {role: binary},
                      "binaries": {binary: {"path": str(binary_path), "sha256": _ref(binary_path)["sha256"]}}}
            if role == "signing-keys":
                test_output = tmp_path / "focused-rust.stdout"
                test_output.write_text("test result: ok. 4 passed; 0 failed; 0 ignored\n", encoding="utf-8")
                source["focusedRustTest"] = {
                    "name": "current_issuer_validation_tests::", "exitCode": 0,
                    "stdout": {**_ref(test_output), "bytes": test_output.stat().st_size},
                }
        source_proof.write_text(json.dumps(source), encoding="utf-8")
        abi = tmp_path / (binary + "-abi.json")
        abi.write_text(json.dumps({
            "schema": 1, "state": "ELF_LOADER_UID_COMPATIBILITY_PASS",
            "candidateServiceEntrypointExecuted": False, "signingOrApi": False,
            "runtimeDeployed": False,
            "rows": [{"binary": binary, "sha256": _ref(binary_path)["sha256"],
                      "imageId": IMAGE_ID, "uid": 10001, "gid": 10001,
                      "exitCode": 0, "candidateReadableExecutable": True,
                      "loaderListSucceeded": True, "ownedContainerRemoved": True}],
        }), encoding="utf-8")
        roles[role] = {"binary": _ref(binary_path), "sourceRevision": "b" * 40,
                       "sourceProof": _ref(source_proof), "abiResult": _ref(abi)}
    path = tmp_path / "binding.json"
    path.write_text(json.dumps({"schema": "elevenid.local-native-functional-binding/v1",
                                "state": "FUNCTIONAL_ONLY", "roles": roles}), encoding="utf-8")
    return path


def test_exact_three_role_binding_uses_real_binary_and_same_image_loader_receipts(tmp_path: Path) -> None:
    path = _binding(tmp_path)
    binaries, image_id = load_binding(path, services_image_id=IMAGE_ID)
    assert set(binaries) == set(ROLES)
    assert image_id == IMAGE_ID

    (tmp_path / "marty-auth").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="sha256 mismatch"):
        load_binding(path, services_image_id=IMAGE_ID)


def test_wrong_image_or_role_is_refused_before_compose(tmp_path: Path) -> None:
    path = _binding(tmp_path)
    with pytest.raises(ValueError, match="cached services image differs"):
        load_binding(path, services_image_id="sha256:" + "c" * 64)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["roles"].pop("gateway")
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly auth"):
        load_binding(path)


def test_declared_source_or_foreign_role_proof_is_refused(tmp_path: Path) -> None:
    path = _binding(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["roles"]["gateway"]["sourceRevision"] = "d" * 40
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="source proof does not bind"):
        load_binding(path)


def test_signing_source_requires_four_real_focused_tests(tmp_path: Path) -> None:
    path = _binding(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    signing = data["roles"]["signing-keys"]
    proof = Path(signing["sourceProof"]["path"])
    body = json.loads(proof.read_text(encoding="utf-8"))
    stdout = Path(body["focusedRustTest"]["stdout"]["path"])
    stdout.write_text("test result: ok. 3 passed; 0 failed;\n", encoding="utf-8")
    body["focusedRustTest"]["stdout"] = {**_ref(stdout), "bytes": stdout.stat().st_size}
    proof.write_text(json.dumps(body), encoding="utf-8")
    signing["sourceProof"] = _ref(proof)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="source proof does not bind"):
        load_binding(path)

    path = _binding(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    signing = data["roles"]["signing-keys"]
    proof = Path(signing["sourceProof"]["path"])
    body = json.loads(proof.read_text(encoding="utf-8"))
    body["roleBinaries"] = {"gateway": "marty-signing-keys"}
    proof.write_text(json.dumps(body), encoding="utf-8")
    signing["sourceProof"] = _ref(proof)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="source proof does not bind"):
        load_binding(path)


def test_rendered_mounts_and_cached_image_are_checked_before_up(tmp_path: Path, monkeypatch) -> None:
    path = _binding(tmp_path)
    spec = importlib.util.spec_from_file_location(
        "conformance_stack_local_test", Path(__file__).resolve().parents[1] / "scripts/conformance_stack.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    image = "ghcr.io/elevenid/services@sha256:" + "d" * 64
    services = {
        role: {"image": image, "volumes": [{"type": "bind", "source": str(tmp_path / binary),
                                             "target": f"/usr/local/bin/{binary}", "read_only": True}]}
        for role, binary in ROLES.items()
    }
    calls = []

    def inspect(command, **_kwargs):
        calls.append(command)
        if command[1:3] == ["context", "inspect"]:
            return subprocess.CompletedProcess(command, 0, "npipe:////./pipe/docker_engine\n", "")
        return subprocess.CompletedProcess(command, 0, IMAGE_ID + "\n", "")

    monkeypatch.setattr(module.subprocess, "run", inspect)
    module.validate_local_functional_images_and_mounts({"services": services}, path)
    assert len(calls) == 2 and calls[1][:3] == ["docker", "image", "inspect"]
    services["gateway"]["volumes"][0]["read_only"] = False
    with pytest.raises(ValueError, match="not read-only"):
        module.validate_local_functional_images_and_mounts({"services": services}, path)
    assert len(calls) == 3  # Context read only; no image or service action after a changed mount.

    monkeypatch.setenv(module.LOCAL_NATIVE_FUNCTIONAL_ENV, str(path))
    assert module.runtime_up_arguments([], {}, "marty-conformance-test", resume=False) == [
        "up", "--detach", "--no-build", "--pull", "never"
    ]
