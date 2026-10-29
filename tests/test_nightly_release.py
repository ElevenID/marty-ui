from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import nightly_claim  # noqa: E402
import nightly_release as nightly  # noqa: E402
import release_transaction as stable  # noqa: E402
from run_nightly_runtime_smoke import CASES, require_cases  # noqa: E402

SOURCE = "a" * 40
RUN_ID = "124"
POLICY = json.loads((ROOT / ".github/stack-tag-policy.json").read_text())


@pytest.fixture
def prepared(tmp_path):
    lock_path = tmp_path / "stack-lock.json"
    lock_path.write_bytes((ROOT / "release/stack-lock.json").read_bytes())
    lock = nightly.read(lock_path)
    version = lock["release"].split("@", 1)[1]
    runs = {"workflow_runs": [{"id": index + 10, "path": entry["path"],
        "event": "merge_group", "head_sha": SOURCE, "status": "completed", "conclusion": "success"}
        for index, entry in enumerate(POLICY["required_workflows"])]}
    claim = nightly_claim.create_claim(repository="ElevenID/marty-ui", version=version,
        date="20261024", run_id="123", source_sha=SOURCE, stack_lock=lock,
        workflow_runs=runs, policy=POLICY)
    run = {"id": 123, "path": nightly_claim.PREPARATION_WORKFLOW,
        "event": "workflow_dispatch", "head_branch": "main", "head_sha": SOURCE,
        "status": "completed", "conclusion": "success"}
    images = tmp_path / "images"
    images.mkdir()
    for index, (role, image) in enumerate(nightly.IMAGE_COORDINATES.items(), 1):
        directory = images / role
        directory.mkdir()
        (directory / "image.json").write_text(json.dumps({"role": role, "uri": image,
            "digest": "sha256:" + str(index) * 64, "source_sha": SOURCE,
            "version": claim["version"], "run_id": RUN_ID}))
    return lock_path, claim, run, images


def candidate(prepared):
    lock, claim, _, images = prepared
    return nightly.record(claim, lock, images, RUN_ID)


def test_nightly_release_notes_advertise_single_direct_candidate_trial(prepared):
    import package_nightly_installation as packaging

    value = candidate(prepared)
    guide = packaging.nightly_trial_guide(value)
    command = (
        f"bash -o pipefail -c 'curl -fsSL https://github.com/ElevenID/marty-ui/releases/download/{value['tag']}/install.sh | "
        f"sh -s -- --candidate-test {value['tag']}'"
    )
    assert guide.count(command) == 1
    assert "/absolute/disposable/path" not in guide
    assert "pipefail" in guide
    assert "signed inventory and operator before executing the operator" in guide
    assert "remaining payloads before runtime provisioning" in guide
    assert "rootful Docker socket" in guide
    assert "Ordinary uninstall" in guide and "purge is unsupported" in guide
    assert "reply to your inviter" in guide.lower()
    assert "stage_selfhost_disposable_preview" not in guide
    assert "sudo KMS" not in guide


@pytest.mark.skipif(not os.environ.get("NIGHTLY_TEST_PACKAGER"),
                    reason="explicit local Docker/compiled-packager qualification")
def test_actual_source_bundle_receipt_and_descriptor(prepared, tmp_path, monkeypatch):
    import package_nightly_installation as packaging
    from build_selfhost_image_lock import KEYCLOAK_SERVICES, _ownership, _repository
    from check_prepared_selfhost_consumer import verify_descriptor, verify_receipt

    value = candidate(prepared)
    value["source_sha"] = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    # Registry lookup is outside this packaging test. Use exact synthetic refs;
    # Compose rendering, Rust ZIP creation, ownership and consumer checks are real.
    _, owned = _ownership(ROOT / "docker-compose.selfhost.prod.yml",
                          ROOT / "docker-compose.selfhost.bundle.override.yml")
    monkeypatch.setattr(packaging, "pin_external_images", lambda model, source: {
        name: _repository(service["image"]) + "@sha256:" + "a" * 64
        for name, service in model["services"].items()
        if name not in owned and name not in KEYCLOAK_SERVICES})
    output = tmp_path / "prepared"
    compose = os.environ.get("MARTY_SELFHOST_BUNDLE_TEST_COMPOSE")
    packaging.package(ROOT, path, Path(os.environ["NIGHTLY_TEST_PACKAGER"]), output,
                      Path(compose) if compose else None)
    archive = output / "prepared-selfhost-bundle.zip"
    lock = output / "prepared-selfhost-images.json"
    transaction = output / "selfhost-preparation-transaction.json"
    receipt = output / "prepared-selfhost-bundle.json"
    descriptor = output / "prepared-selfhost-product-descriptor.json"
    verify_receipt(archive, lock, transaction, receipt, value["source_sha"], RUN_ID)
    verify_descriptor(archive, lock, transaction, receipt, descriptor)
    assert nightly.read(descriptor)["qualification"]["state"] == "unqualified"
    assert nightly.read(lock)["release"] == "marty-ui@" + value["version"]


@pytest.mark.parametrize("fault", [None, "digest", "extra", "missing", "empty"])
def test_signed_inventory_fails_closed(prepared, tmp_path, monkeypatch, fault):
    import publish_nightly_release as publishing

    assets = tmp_path / "signed"
    assets.mkdir()
    files = publishing.policy(ROOT)
    names = files + [name + ".sigstore.json" for name in files]
    for name in names:
        (assets / name).write_bytes(b"fixture")
    for name in publishing.provenance_files():
        (assets / name).write_bytes(b"fixture offline evidence")
    (assets / "RELEASE-SHA256SUMS").write_text("".join(
        nightly.file_digest(assets / name).removeprefix("sha256:") + "  " + name + "\n"
        for name in sorted(names)), encoding="ascii")
    commands = []
    value = candidate(prepared)
    monkeypatch.setattr(publishing, "validate", lambda *args: (value, files))
    monkeypatch.setattr(publishing, "command", lambda *args: commands.append(args))
    monkeypatch.setattr(publishing, "verify_installer_provenance", lambda *args: None)
    if fault == "digest":
        (assets / files[0]).write_bytes(b"changed")
    elif fault == "extra":
        (assets / "extra").write_bytes(b"foreign")
    elif fault == "missing":
        (assets / names[-1]).unlink()
    elif fault == "empty":
        (assets / names[-1]).write_bytes(b"")
    if fault:
        with pytest.raises(ValueError):
            publishing.verify_signed(assets, ROOT, value["tag"], RUN_ID, gh=tmp_path / "gh")
        assert not commands
    else:
        assert publishing.verify_signed(assets, ROOT, value["tag"], RUN_ID, gh=tmp_path / "gh") == value
        assert len(commands) == 19
        assert all(args[:2] == ("cosign", "verify-blob") for args in commands)


def test_runtime_uses_pinned_rust_override_for_entire_lifecycle():
    runner = (ROOT / "scripts/run_nightly_runtime_smoke.py").read_text(encoding="utf-8")
    assert '"--file", "docker-compose.yml", "--file", "docker-compose.rust-revocation.yml"' in runner
    for operation in ('"config"', '"up"', '"down"'):
        assert '[*compose, ' + operation in runner


@pytest.mark.parametrize("fault", [None, "unverified", "oversized", "empty", "existing"])
def test_offline_provenance_export_verifies_every_subject_before_output(tmp_path, monkeypatch, fault):
    import publish_nightly_release as publishing
    assets = tmp_path / "assets"
    assets.mkdir(mode=0o700)
    bundle = tmp_path / "action-bundle.jsonl"
    raw = b"mock attestation, not cryptographic evidence\n"
    if fault == "oversized":
        raw = b"x" * (publishing.PROVENANCE_LIMIT + 1)
    if fault == "empty":
        raw = b""
    bundle.write_bytes(raw)
    for name in publishing.INSTALLER_SUBJECTS:
        (assets / name).write_bytes(b"subject fixture")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    candidate = {"source_sha": SOURCE}
    monkeypatch.setattr(publishing, "verify_signed", lambda *a, **kw: candidate)
    observed = []
    def verify(subject, staged, **options):
        assert staged.read_bytes() == raw
        assert staged != bundle
        assert options == dict(gh=tmp_path / "gh", workflow=nightly.WORKFLOW,
                               source_sha=SOURCE, run_id=int(RUN_ID), run_attempt=2)
        observed.append(subject.name)
        if fault == "unverified" and len(observed) == 5:
            raise ValueError("wrong invocation")
    monkeypatch.setattr(publishing, "verify_subject", verify)
    if fault == "existing":
        # Export's normal verify_signed rejects this before any outputs. The
        # exclusive writer independently refuses replacement if state changes.
        (assets / sorted(publishing.provenance_files())[0]).write_bytes(b"preserve")
    if fault:
        with pytest.raises((ValueError, FileExistsError)):
            publishing.export_provenance(assets, ROOT, "v1.2.3", RUN_ID, bundle, tmp_path / "gh")
        sidecars = list(assets.glob("*.provenance.jsonl"))
        if fault == "existing":
            assert len(sidecars) == 1 and sidecars[0].read_bytes() == b"preserve"
        else:
            assert not sidecars
    else:
        publishing.export_provenance(assets, ROOT, "v1.2.3", RUN_ID, bundle, tmp_path / "gh")
        assert set(observed) == set(publishing.INSTALLER_SUBJECTS)
        assert {p.name for p in assets.glob("*.provenance.jsonl")} == publishing.provenance_files()
        assert all((assets / name).read_bytes() == raw for name in publishing.provenance_files())


@pytest.mark.parametrize("fault", ["missing", "oversized", "wrong-invocation"])
def test_publication_rejects_unusable_offline_provenance(tmp_path, monkeypatch, fault):
    import publish_nightly_release as publishing
    for name in publishing.provenance_files():
        (tmp_path / name).write_bytes(b"fixture")
    chosen = tmp_path / (publishing.INSTALLER_SUBJECTS[0] + ".provenance.jsonl")
    if fault == "missing":
        chosen.unlink()
    if fault == "oversized":
        chosen.write_bytes(b"x" * (publishing.PROVENANCE_LIMIT + 1))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    def reject(*args, **kwargs):
        raise ValueError("wrong producer invocation")
    monkeypatch.setattr(publishing, "verify_subject", reject)
    with pytest.raises(ValueError):
        publishing.verify_installer_provenance(tmp_path, {"source_sha": SOURCE}, RUN_ID, tmp_path / "gh")


def test_nightly_admission_keeps_claim_immutable_and_isolates_stable_transactions(prepared):
    lock, claim, run, _ = prepared
    before = copy.deepcopy(claim)
    assert nightly.admit(claim, run, SOURCE, POLICY, nightly.read(lock)) == claim
    record = candidate(prepared)
    assert record["schema"] != stable.SCHEMA
    assert nightly.validate_candidate(record) == record
    assert claim == before and claim["publication"] == "prohibited"
    with pytest.raises(stable.ReleaseTransactionError):
        stable.validate_claim(record)


@pytest.mark.parametrize("change", ["source", "run", "lock", "failed"])
def test_admission_rejects_wrong_source_or_unaccepted_evidence(prepared, change):
    lock, claim, run, _ = prepared
    if change == "source":
        run["head_sha"] = "b" * 40
    elif change == "run":
        run["id"] = 125
    elif change == "lock":
        value = nightly.read(lock)
        value["release"] = "marty-ui@0.0.0"
        lock.write_text(json.dumps(value))
    else:
        run["conclusion"] = "failure"
    with pytest.raises(ValueError):
        nightly.admit(claim, run, SOURCE, POLICY, nightly.read(lock))


@pytest.mark.parametrize("field,value", [
    ("source_sha", "b" * 40), ("run_id", "125"), ("version", "1.2.3"),
    ("uri", "ghcr.io/other/image"), ("digest", "sha256:bad"),
])
def test_images_must_match_same_run_source_version_and_role(prepared, field, value):
    path = prepared[3] / "services/image.json"
    data = nightly.read(path)
    data[field] = value
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        candidate(prepared)


def test_missing_and_duplicate_image_evidence_cannot_publish(prepared):
    path = prepared[3] / "keycloak/image.json"
    path.unlink()
    with pytest.raises(ValueError, match="incomplete"):
        candidate(prepared)
    duplicate = nightly.read(prepared[3] / "services/image.json")
    path.write_text(json.dumps(duplicate))
    with pytest.raises(ValueError, match="duplicate"):
        candidate(prepared)


def test_manifest_binds_nightly_base_lock_and_has_no_stable_release_identity(prepared):
    lock, claim, _, _ = prepared
    original = lock.read_bytes()
    value = candidate(prepared)
    manifest = nightly.product_manifest(value, lock, "2026-10-24T12:00:00+00:00")
    assert manifest["release"] == "marty-ui@" + claim["version"]
    assert manifest["components"][-1]["version"] == claim["version"]
    assert manifest["components"][-1]["commit"] == SOURCE
    assert len(manifest["components"][-1]["artifacts"]) == 5
    assert lock.read_bytes() == original
    lock.write_bytes(original + b" ")
    with pytest.raises(ValueError, match="lock changed"):
        nightly.product_manifest(value, lock, "2026-10-24T12:00:00+00:00")


def test_build_plan_reuses_existing_recipes_and_explicit_tester_profile(prepared):
    lock, claim, _, _ = prepared
    plan = nightly.build_plan(claim, nightly.read(lock))
    assert {item["role"] for item in plan} == set(nightly.IMAGE_COORDINATES)
    assert all((ROOT / item["dockerfile"]).is_file() for item in plan)
    assert all("MARTY_RELEASE_VERSION=" + claim["version"] in item["build_args"] for item in plan)
    tester = next(item for item in plan if item["role"] == "ui_selfhost")
    assert tester["target"] == "selfhost"
    assert "SELFHOST_PUBLIC_PROFILE=tester" in tester["build_args"]
    bad = nightly.read(lock)
    bad["components"][0]["version"] += "\nINJECTED=1"
    with pytest.raises(ValueError, match="multiline"):
        nightly.build_plan(claim, bad)


@pytest.mark.parametrize("outcome", ["passed", "skipped", "failure", "error", "missing", "duplicate"])
def test_happy_path_requires_actual_execution_of_all_five_cases(tmp_path, outcome):
    names = [case.rsplit("::", 1)[1] for case in CASES]
    if outcome == "missing":
        names.pop()
    elif outcome == "duplicate":
        names[-1] = names[0]
    nodes = [f'<testcase name="{name}">' +
             (f"<{outcome}/>" if outcome in {"skipped", "failure", "error"} and index == 0 else "") +
             "</testcase>" for index, name in enumerate(names)]
    report = tmp_path / "results.xml"
    report.write_text("<testsuites><testsuite>" + "".join(nodes) + "</testsuite></testsuites>")
    if outcome == "passed":
        require_cases(report)
    else:
        with pytest.raises(ValueError):
            require_cases(report)


def test_release_workflow_cannot_skip_runtime_signing_or_prerelease_separation():
    jobs = yaml.safe_load((ROOT / ".github/workflows/nightly-release.yml").read_text())["jobs"]
    assert "runtime-happy-path" in jobs["sign-release"]["needs"]
    assert "sign-release" in jobs["publish"]["needs"]
    assert jobs["publish"]["environment"] == "stack-release"
    assert jobs["build-images"]["runs-on"] == "ubuntu-24.04"
    for job in jobs.values():
        assert "continue-on-error" not in job
    workflow = (ROOT / ".github/workflows/nightly-release.yml").read_text()
    assert "e2e-tests.yml" not in workflow and "youtube" not in workflow.lower()
    assert ".github/workflows/cd.yml" not in workflow
    publisher = (ROOT / "scripts/publish_nightly_release.py").read_text()
    assert '"--prerelease", "--latest=false"' in publisher


@pytest.mark.parametrize("tag", ["v1.2.3", "v1.2.3-nightly.20261024.123"])
def test_authenticated_native_operator_accepts_exact_signed_release_identity(tmp_path, monkeypatch, tag):
    import hashlib
    from scripts import selfhost_native_operator as native

    binary = tmp_path / "operator"
    binary.write_bytes(b"owned fixture binary")
    monkeypatch.setenv("MARTY_DEPLOY_BIN", str(binary))
    monkeypatch.setenv("MARTY_DEPLOY_BIN_SHA256", hashlib.sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setenv("MARTY_DEPLOY_SOURCE_SHA", SOURCE)
    monkeypatch.setenv("MARTY_DEPLOY_RELEASE_TAG", tag)
    monkeypatch.setattr(native.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=SOURCE + ":" + tag))
    assert native.operator_command(tmp_path, "operator", "keycloak-provision") == [
        str(binary), "operator", "keycloak-provision"]
    monkeypatch.setenv("MARTY_DEPLOY_RELEASE_TAG", tag + ".changed")
    with pytest.raises(RuntimeError, match="RELEASE_TAG"):
        native.operator_command(tmp_path, "operator", "keycloak-provision")
