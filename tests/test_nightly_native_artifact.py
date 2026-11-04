from __future__ import annotations

import copy
import io
import json
import stat
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import nightly_native_artifact as native

IDENTITY = {"source_sha": "a" * 40, "tag": "v1.2.3-nightly.20261103.123",
            "run_id": "456", "attempt": "2"}
METADATA = {"id": 789, "name": "nightly-native-456-2", "expired": False,
            "workflow_run": {"id": 456, "head_sha": "a" * 40}}


@pytest.fixture
def sealed(tmp_path: Path):
    tools = [tmp_path / "packager", tmp_path / "operator"]
    for index, path in enumerate(tools):
        path.write_bytes(b"qualified native tool " + str(index).encode())
        path.chmod(0o755)
    archive = tmp_path / "native.zip"
    checksum = native.pack(*tools, archive, **IDENTITY)
    return archive, checksum


def restore(sealed, output: Path, *, metadata=None, **updates):
    archive, checksum = sealed
    return native.restore(archive, output, copy.deepcopy(METADATA) if metadata is None else metadata,
                          artifact_id="789", archive_sha256=checksum, **(IDENTITY | updates))


def test_exact_attempt_tools_restore_with_executable_permissions(sealed, tmp_path):
    output = tmp_path / "restored"
    result = restore(sealed, output)
    assert result["source_sha"] == IDENTITY["source_sha"]
    assert result["run_attempt"] == "2"
    assert {path.name for path in output.iterdir()} == {*native.FILES, native.MANIFEST}
    for index, name in enumerate(native.FILES):
        assert (output / name).read_bytes() == b"qualified native tool " + str(index).encode()
        assert stat.S_IMODE((output / name).stat().st_mode) == 0o755


@pytest.mark.parametrize("fault", ["id", "name", "expired", "producer", "source", "boolean-id"])
def test_foreign_artifact_metadata_is_rejected_before_output(sealed, tmp_path, fault):
    metadata = copy.deepcopy(METADATA)
    if fault == "id": metadata["id"] = 790
    elif fault == "boolean-id": metadata["id"] = True
    elif fault == "name": metadata["name"] = "nightly-native-456-1"
    elif fault == "expired": metadata["expired"] = True
    elif fault == "producer": metadata["workflow_run"]["id"] = 457
    elif fault == "source": metadata["workflow_run"]["head_sha"] = "b" * 40
    output = tmp_path / "rejected"
    with pytest.raises(ValueError):
        restore(sealed, output, metadata=metadata)
    assert not output.exists()


@pytest.mark.parametrize("update", [
    {"attempt": "3"}, {"source_sha": "b" * 40},
    {"tag": "v1.2.4-nightly.20261103.123"}, {"run_id": "457"},
])
def test_different_attempt_source_tag_or_run_is_not_relabelled(sealed, tmp_path, update):
    with pytest.raises(ValueError):
        restore(sealed, tmp_path / "rejected", **update)
    assert not (tmp_path / "rejected").exists()


def test_modified_archive_cannot_use_the_original_job_checksum(sealed, tmp_path):
    archive, checksum = sealed
    archive.write_bytes(archive.read_bytes() + b"changed after preparation")
    with pytest.raises(ValueError, match="digest"):
        restore((archive, checksum), tmp_path / "rejected")


@pytest.mark.parametrize("fault", ["missing", "extra", "duplicate", "traversal", "symlink",
                                   "mode", "tool-bytes", "manifest-attempt", "manifest-extra"])
def test_malformed_archive_never_creates_output(sealed, tmp_path, fault):
    archive, _ = sealed
    with zipfile.ZipFile(archive) as original:
        entries = [(item, original.read(item.filename)) for item in original.infolist()]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as rebuilt:
        for info, payload in entries:
            if fault == "missing" and info.filename == native.FILES[0]: continue
            if info.filename == native.FILES[0]:
                if fault == "traversal": info.filename = "../escape"
                elif fault == "symlink": info.external_attr = (stat.S_IFLNK | 0o777) << 16
                elif fault == "mode": info.external_attr = (stat.S_IFREG | 0o644) << 16
                elif fault == "tool-bytes": payload += b"unqualified"
            if info.filename == native.MANIFEST and fault.startswith("manifest-"):
                document = json.loads(payload)
                if fault == "manifest-attempt": document["run_attempt"] = "1"
                else: document["qualification_override"] = True
                payload = json.dumps(document).encode()
            rebuilt.writestr(info, payload)
        if fault == "extra": rebuilt.writestr("extra", b"foreign")
        if fault == "duplicate": rebuilt.writestr(entries[0][0], entries[0][1])
    archive.write_bytes(buffer.getvalue())
    with pytest.raises(ValueError):
        restore((archive, native.digest(buffer.getvalue())), tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()
    assert not (tmp_path / "escape").exists()


def test_restore_does_not_overwrite_an_existing_destination(sealed, tmp_path):
    output = tmp_path / "existing"
    output.mkdir()
    (output / "keep").write_bytes(b"preserve")
    with pytest.raises(ValueError, match="already exists"):
        restore(sealed, output)
    assert (output / "keep").read_bytes() == b"preserve"


def test_pack_rejects_nonexecutables_and_symlinks(tmp_path):
    packager = tmp_path / "packager"
    packager.write_bytes(b"tool")
    with pytest.raises(ValueError, match="executable"):
        native.pack(packager, packager, tmp_path / "native.zip", **IDENTITY)
    packager.chmod(0o755)
    linked = tmp_path / "linked"
    linked.symlink_to(packager)
    with pytest.raises(ValueError, match="regular"):
        native.pack(linked, packager, tmp_path / "native.zip", **IDENTITY)


def test_nightly_native_preparation_overlaps_images_but_packaging_joins_both():
    workflow = yaml.safe_load((ROOT / ".github/workflows/nightly-release.yml").read_text())
    jobs = workflow["jobs"]
    native_job = jobs["prepare-native"]
    assert native_job["needs"] == "admit"
    assert jobs["build-images"]["needs"] == "admit"
    assert set(jobs["prepare-installation"]["needs"]) == {"admit", "build-images", "prepare-native"}
    assert "packages" not in native_job["permissions"]
    preparation = "\n".join(step.get("run", "") for step in native_job["steps"])
    assert "cargo test --locked --manifest-path rust/Cargo.toml" in preparation
    assert "-p marty-deployment-catalog" in preparation
    assert "qualify-installer-compose-model.sh" in preparation
    steps = jobs["prepare-installation"]["steps"]
    download = next(step for step in steps if step.get("name") == "Download exact same-attempt native artifact")
    assert download["with"]["artifact-ids"] == "${{ needs.prepare-native.outputs.artifact_id }}"
    verify = next(step for step in steps if step.get("name") == "Verify native artifact producer, bytes and original attempt")
    assert "scripts/nightly_native_artifact.py restore" in verify["run"]
    assert '--attempt "$GITHUB_RUN_ATTEMPT"' in verify["run"]
    assert 'actions/artifacts/$NATIVE_ARTIFACT_ID' in verify["run"]
    assert steps.index(verify) < next(i for i, s in enumerate(steps) if s.get("name") == "Package digest-locked installation assets")
    assert not any("cargo build" in step.get("run", "") for step in steps)
