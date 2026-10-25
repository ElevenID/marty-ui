"""Stable producer binding; synthetic verifier calls are not crypto acceptance."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_release as release
import stable_installer_assets as stable


@pytest.fixture
def candidate(tmp_path):
    assets = tmp_path / "assets"
    assets.mkdir(mode=0o700)
    for name in release.ARTIFACTS:
        (assets / name).write_bytes(b"synthetic " + name.encode())
    lock = dict(schema="marty.selfhost-image-lock/v1", release="marty-ui@1.2.3",
                services={"gateway": "ghcr.io/elevenid/services@sha256:" + "a" * 64},
                openbao_didcomm_image="ghcr.io/elevenid/plugin@sha256:" + "b" * 64)
    (assets / "prepared-selfhost-images.json").write_bytes(release.encode(lock))
    record = release.inventory(assets, source_sha="a" * 40, release_tag="v1.2.3",
                               build_run_id=42, build_run_attempt=3, expected_services={"gateway"})
    (assets / "installer-inventory.json").write_bytes(release.encode(record))
    bundle = tmp_path / "action-bundle"
    bundle.write_bytes(b"synthetic offline proof")
    gh = tmp_path / "gh"
    gh.write_bytes(b"synthetic verifier")
    return assets, bundle, gh, dict(source_sha="a" * 40, tag="v1.2.3", run_id=42, run_attempt=3)


def test_export_authenticates_all_subjects_then_verifies_original_producer(candidate, monkeypatch):
    assets, bundle, gh, identity = candidate
    calls = []
    def verify(subject, proof, **policy):
        assert subject.parent != assets and subject.parent == proof.parent
        assert proof.read_bytes() == bundle.read_bytes()
        assert not list(assets.glob("*.provenance.jsonl")) or len(calls) >= 5
        calls.append((subject.name, policy))
    monkeypatch.setattr(stable.provenance, "verify_subject", verify)
    stable.export_provenance(assets, bundle=bundle, gh=gh, **identity)
    assert {p.name for p in assets.glob("*.provenance.jsonl")} == {
        name + ".provenance.jsonl" for name in stable.SUBJECTS}
    # No current-workflow run is supplied: the original inventory producer must
    # be authenticated again, even from a later publication/recovery workflow.
    stable.verify_published(assets, gh=gh, source_sha=identity["source_sha"], tag=identity["tag"])
    assert len(calls) == 10
    assert {name for name, _ in calls} == set(stable.SUBJECTS)
    for _, policy in calls:
        assert policy == dict(gh=gh, workflow=stable.WORKFLOW, source_sha="a" * 40,
                              run_id=42, run_attempt=3)
    with pytest.raises(ValueError, match="already exists"):
        stable.export_provenance(assets, bundle=bundle, gh=gh, **identity)


@pytest.mark.parametrize("failure_index", range(5))
def test_verifier_failure_never_exports_partial_sidecars(candidate, monkeypatch, failure_index):
    assets, bundle, gh, identity = candidate
    count = 0
    def verify(*args, **kwargs):
        nonlocal count
        if count == failure_index:
            raise ValueError("untrusted producer")
        count += 1
    monkeypatch.setattr(stable.provenance, "verify_subject", verify)
    with pytest.raises(ValueError, match="untrusted producer"):
        stable.export_provenance(assets, bundle=bundle, gh=gh, **identity)
    assert not list(assets.glob("*.provenance.jsonl"))


@pytest.mark.parametrize("field,value", [("run_id", 43), ("run_attempt", 4),
                                         ("source_sha", "b" * 40), ("tag", "v1.2.4")])
def test_current_input_mismatch_refuses(candidate, field, value):
    assets, _, _, identity = candidate
    identity[field] = value
    with pytest.raises(ValueError):
        stable.verify_inputs(assets, **identity)


@pytest.mark.parametrize("name", stable.SUBJECTS)
def test_published_payload_mutation_refuses_before_verifier(candidate, monkeypatch, name):
    assets, bundle, gh, identity = candidate
    monkeypatch.setattr(stable.provenance, "verify_subject", lambda *a, **kw: None)
    stable.export_provenance(assets, bundle=bundle, gh=gh, **identity)
    (assets / name).write_bytes(b"tampered")
    monkeypatch.setattr(stable.provenance, "verify_subject", lambda *a, **kw: pytest.fail("must not verify"))
    with pytest.raises(ValueError):
        stable.verify_published(assets, source_sha=identity["source_sha"], tag=identity["tag"], gh=gh)


def test_changed_original_producer_requires_matching_certificate(candidate, monkeypatch):
    assets, bundle, gh, identity = candidate
    monkeypatch.setattr(stable.provenance, "verify_subject", lambda *a, **kw: None)
    stable.export_provenance(assets, bundle=bundle, gh=gh, **identity)
    inventory = stable.read_inventory(assets)
    inventory["build_run_attempt"] = 4
    (assets / "installer-inventory.json").write_bytes(release.encode(inventory))
    def verify(*args, **policy):
        assert policy["run_attempt"] == 4
        raise ValueError("certificate invocation differs")
    monkeypatch.setattr(stable.provenance, "verify_subject", verify)
    with pytest.raises(ValueError, match="certificate invocation differs"):
        stable.verify_published(assets, source_sha=identity["source_sha"], tag=identity["tag"], gh=gh)


def test_oversized_bundle_and_changed_inputs_during_verification_refuse(candidate, monkeypatch):
    assets, bundle, gh, identity = candidate
    bundle.write_bytes(b"x" * (stable.PROVENANCE_LIMIT + 1))
    with pytest.raises(ValueError):
        stable.export_provenance(assets, bundle=bundle, gh=gh, **identity)
    assert not list(assets.glob("*.provenance.jsonl"))
    bundle.write_bytes(b"proof")
    def mutate(*args, **kwargs):
        (assets / "install.sh").write_bytes(b"changed")
    monkeypatch.setattr(stable.provenance, "verify_subject", mutate)
    with pytest.raises(ValueError):
        stable.export_provenance(assets, bundle=bundle, gh=gh, **identity)
    assert not list(assets.glob("*.provenance.jsonl"))


def test_result_without_complete_sidecars_refuses(candidate, monkeypatch):
    assets, _, gh, identity = candidate
    monkeypatch.setattr(stable.provenance, "verify_subject", lambda *a, **kw: pytest.fail("missing proof"))
    with pytest.raises(ValueError):
        stable.verify_published(assets, gh=gh, source_sha=identity["source_sha"], tag=identity["tag"])
