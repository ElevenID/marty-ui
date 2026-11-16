"""Cache-only source controls: no real Docker, cache writes or build admission."""
from copy import deepcopy
import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import seed_local_official_native_target as seed
import scoped_native_runtime as runtime
import scoped_native_build as build


def synthetic(tmp_path, monkeypatch):
    proof = dict(Name=seed.VOLUME, Driver="local", Scope="local", CreatedAt="synthetic",
                 Labels={"io.elevenid.demo-audit.owner": seed.OWNER}, Mountpoint="/synthetic")
    old = dict(state="COPIED_AND_READBACK_MATCHED", targetVolume=seed.VOLUME, volumeProof=proof,
               targetManifestSha256="1" * 64)
    prior = dict(state="PASSED", exitCode=0, oomKilled=False, canonicalAllServices=True,
        buildProfile="oid4vc-all-services", source="d2debf0fde2a0c826f8925aca648c9d3dabfbc9f",
        uiRevision="d2debf0fde2a0c826f8925aca648c9d3dabfbc9f",
        coreRevision="4320b5fa1c6f41231ee0aa2bc57d8008549f67ac",
        preparationSha256="c9b77a332139e5d7eb0e2684b5b54514ecad262531873e2f4c36dcd599da4c1a",
        binaries={str(n): {} for n in range(29)})
    a, b = tmp_path / "old.json", tmp_path / "prior.json"
    a.write_text(json.dumps(old))
    b.write_text(json.dumps(prior))
    monkeypatch.setattr(runtime, "read_ref", lambda ref: a if ref["sha256"] == seed.ORIGIN_SEED_SHA256 else b)
    dto = dict(schema="marty.local-native-target-cache-reuse/v1", state="MUTABLE_CACHE_REUSE_ONLY",
        targetVolume=seed.VOLUME, volumeProof=proof,
        originSeedReceipt={"path": str(a), "sha256": seed.ORIGIN_SEED_SHA256},
        priorBuildReceipt={"path": str(b), "sha256": seed.PRIOR_BUILD_SHA256},
        operatorSha256=seed.sha(Path(seed.__file__)), targetManifestSha256="2" * 64,
        fileCount=100, bytes=1000, cacheMountedReadOnly=True, targetCopyPerformed=False,
        binariesQualified=False, releaseQualified=False)
    return dto


def test_mutable_cache_provenance_does_not_reassert_old_copied_content(tmp_path, monkeypatch):
    dto = synthetic(tmp_path, monkeypatch)
    seed.validate_cache_reuse(dto)
    for change in (dict(state="COPIED_AND_READBACK_MATCHED"), dict(targetCopyPerformed=True),
                   dict(cacheMountedReadOnly=False), dict(binariesQualified=True),
                   dict(priorBuildReceipt={"path": "/foreign", "sha256": "f" * 64}),
                   dict(targetVolume="foreign"), dict(fileCount=False)):
        with pytest.raises(ValueError):
            seed.validate_cache_reuse(dto | change)
    changed = deepcopy(dto)
    changed["volumeProof"]["CreatedAt"] = "foreign"
    with pytest.raises(ValueError, match="CONTINUITY"):
        seed.validate_cache_reuse(changed)


def test_fresh_reuse_readback_rejects_changed_snapshot_without_retry(tmp_path, monkeypatch):
    dto = synthetic(tmp_path, monkeypatch)
    path = tmp_path / "reuse.json"
    path.write_text(json.dumps(dto))
    calls = []
    def observe(proof, output):
        calls.append((proof, output))
        return dict(manifestSha256=dto["targetManifestSha256"], fileCount=dto["fileCount"], bytes=dto["bytes"])
    monkeypatch.setattr(seed, "observe_target", observe)
    assert seed.inspect_reuse_target(path)["manifestSha256"] == "2" * 64
    monkeypatch.setattr(seed, "observe_target", lambda *args: dict(manifestSha256="3" * 64, fileCount=100, bytes=1000))
    with pytest.raises(ValueError, match="CHANGED_AFTER_SNAPSHOT"):
        seed.inspect_reuse_target(path)
    assert len(calls) == 1


def test_target_observer_is_readonly_bounded_and_retires_same_known_helper(tmp_path, monkeypatch):
    proof = dict(Name=seed.VOLUME, Driver="local", Scope="local", CreatedAt="synthetic",
                 Labels={"io.elevenid.demo-audit.owner": seed.OWNER}, Mountpoint="/synthetic")
    monkeypatch.setattr(Path, "is_relative_to", lambda *args: True)
    monkeypatch.setattr(seed, "transport", lambda: object())
    monkeypatch.setattr(seed, "docker_output", lambda client, *args: json.dumps([proof]) if args[:2] == ("volume", "inspect") else "")
    counts = []
    monkeypatch.setattr(seed, "writer_census", lambda client: counts.append("census"))
    monkeypatch.setattr(seed, "operator_mounts", lambda: [])
    def owned(client, name, mode, mounts, memory, intent, deadline):
        assert mode == "--inside-inspect" and memory == "256m" and deadline == 600
        assert mounts == [(seed.VOLUME, "/target", True)]
        return {"containerId": "synthetic-known", "stdout": json.dumps(dict(manifestSha256="a" * 64, fileCount=2, bytes=3))}
    monkeypatch.setattr(seed, "owned_helper", owned)
    monkeypatch.setattr(seed, "retire_helper", lambda client, row: counts.append(row["containerId"]))
    assert seed.observe_target(proof, tmp_path)["fileCount"] == 2
    assert counts == ["census", "synthetic-known", "census"]


def test_latest_release_cache_input_is_distinct_from_old_seed(monkeypatch):
    seen = []
    monkeypatch.setattr(seed, "validate_cache_reuse", lambda dto: seen.append(dto))
    scope = build.build_scope(build.LATEST_OFFICIAL_PROFILE)
    dto = dict(targetVolume=scope["volumes"][1])
    freeze = dict(productRevision=scope["uiRevision"], coreRevision=scope["coreRevision"], imagesBuilt=False, releaseQualified=False)
    script = " ".join("--bin " + binary for binary in scope["roles"].values())
    build.verify_official_inputs(freeze, dto, script, scope, script)
    assert seen == [dto]
    with pytest.raises(ValueError):
        build.verify_official_inputs(freeze, dto, script.replace("--bin marty-flow", "--bin foreign"), scope, script)
