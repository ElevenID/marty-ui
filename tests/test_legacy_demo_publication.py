"""Legacy beta publication must stop before work on an application-only source."""

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from scripts import publish_passport_beta_demo as publisher
from tests.test_create_local_release_manifest import make_repo, commit_changes


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/legacy-demo-publication-source.json"
MANIFEST_FIXTURES = {
    "2026.07.0": ("2026.07.0.json", "6dad5711fee0adf41004ad74959886c83c88f990078c70ae8123e10757c611bd"),
    "2026.08.0": ("2026.08.0-nightly273.json", "3e643f3b471daac620c670aa506c654fb7894b940744c83169775fb643a655f1"),
}


def write(root, filename, content):
    target = root / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


def head(root):
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


@pytest.fixture
def legacy_source(tmp_path):
    root = tmp_path / "marty-ui"
    make_repo(root)
    fixture = json.loads(FIXTURE.read_bytes())
    assert fixture["source_commits"] == [
        "ca58b8bec939f5b26bebecd849edf55b5c4af5ae",
        "3ff1328d163f2dca38e369f17bda77b6334808eb",
    ]
    assert {row["path"] for row in fixture["files"]} == set(publisher.LEGACY_DEMO_SOURCE_FILES)
    for row in fixture["files"]:
        content = row["content"].encode()
        assert hashlib.sha256(content).hexdigest() == row["sha256"]
        write(root, row["path"], content)
    for version, (filename, digest) in MANIFEST_FIXTURES.items():
        content = (ROOT / "tests/fixtures/demo-manifests" / filename).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(content).hexdigest() == digest
        write(root, "ui/public/demos/manifests/" + version + ".json", content)
    commit_changes(root)
    return root


def test_real_signed_historical_layout_remains_accepted(legacy_source):
    publisher.require_legacy_demo_layout(legacy_source, head(legacy_source))


@pytest.mark.parametrize("missing", [
    "ui/src/variants/publicSite.public.jsx",
    "ui/src/components/pages/DemoPages.jsx",
    "ui/public/demos/manifests/index.json",
    "ui/public/demos/manifests/2026.08.0.json",
])
def test_missing_legacy_inputs_fail_with_website_ownership_guidance(legacy_source, missing):
    (legacy_source / missing).unlink()
    commit_changes(legacy_source)
    with pytest.raises(publisher.PublicationEvidenceError, match="website-owned publication"):
        publisher.require_legacy_demo_layout(legacy_source, head(legacy_source))


@pytest.mark.parametrize("change", ["producer", "default", "index", "manifest", "path"])
def test_restored_catalog_cannot_substitute_for_a_legacy_producer_or_valid_contract(legacy_source, change):
    if change == "producer":
        path = legacy_source / "docker/ui.Dockerfile"
        path.write_text(path.read_text().replace("FROM runtime-base AS public", "FROM runtime-base AS application"))
    elif change == "default":
        path = legacy_source / "ui/vite.config.ts"
        path.write_text(path.read_text().replace("process.env.MARTY_UI_SURFACE || 'combined'", "process.env.MARTY_UI_SURFACE || 'application'"))
    elif change in ("index", "path"):
        path = legacy_source / "ui/public/demos/manifests/index.json"
        value = json.loads(path.read_bytes())
        if change == "path":
            value["releases"][0]["stack_version"] = "../unreviewed"
        else:
            value["releases"][0]["manifest_url"] = "/another-source.json"
        path.write_text(json.dumps(value))
    else:
        path = legacy_source / "ui/public/demos/manifests/2026.08.0.json"
        value = json.loads(path.read_bytes())
        value["schema_version"] = -1
        path.write_text(json.dumps(value))
    commit_changes(legacy_source)
    with pytest.raises(publisher.PublicationEvidenceError, match="website-owned publication"):
        publisher.require_legacy_demo_layout(legacy_source, head(legacy_source))


@pytest.mark.parametrize("failure", ["git-error", "timeout"])
def test_git_failures_do_not_admit_or_substitute_checkout_inputs(legacy_source, monkeypatch, failure):
    revision = head(legacy_source)

    def fail(command, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 30)
        raise subprocess.CalledProcessError(128, command, stderr=b"Authentication failed")

    monkeypatch.setattr(publisher.subprocess, "run", fail)
    with pytest.raises(publisher.PublicationEvidenceError, match="Unable to verify"):
        publisher.require_legacy_demo_layout(legacy_source, revision)


def test_layout_reads_pinned_objects_without_replacements(legacy_source):
    original = head(legacy_source)
    (legacy_source / "ui/public/demos/manifests/index.json").unlink()
    commit_changes(legacy_source)
    removed = head(legacy_source)
    subprocess.run(["git", "-C", str(legacy_source), "replace", original, removed], check=True)
    publisher.require_legacy_demo_layout(legacy_source, original)
    with pytest.raises(publisher.PublicationEvidenceError, match="website-owned publication"):
        publisher.require_legacy_demo_layout(legacy_source, removed)


def test_post_removal_publisher_refuses_before_tools_oauth_or_recorder(legacy_source, tmp_path, monkeypatch):
    root = legacy_source
    legacy_index = (root / "ui/public/demos/manifests/index.json").read_bytes()
    (root / "ui/public/demos/manifests/index.json").unlink()
    commit_changes(root)
    revision = head(root)
    # An untracked copy cannot turn the signed application source into a legacy source.
    write(root, "ui/public/demos/manifests/index.json", legacy_index)
    monkeypatch.setattr(publisher, "__file__", str(root / "scripts/publish_passport_beta_demo.py"))
    monkeypatch.chdir(root)
    artifact_dir = tmp_path / "signed-aggregate"
    artifact_dir.mkdir()
    config = write(tmp_path, "reviewed.json", b"{}")
    video = write(tmp_path, "reviewed.mp4", b"reviewed")
    recorder = tmp_path / "recorder"
    recorder.mkdir()
    monkeypatch.setenv("PASSPORT_ACCEPTANCE_API_KEY", "k" * 32)
    admission = []

    def aggregate(path, **kwargs):
        assert path == artifact_dir
        assert kwargs["attest"] is publisher.verify_attestations
        admission.append("signed-aggregate")
        return {"release": {"source_commit": revision}}

    def unexpected(*args, **kwargs):
        pytest.fail("Legacy admission must precede tool/browser/OAuth/recorder/runtime work")

    monkeypatch.setattr(publisher, "collect_aggregate", aggregate)
    monkeypatch.setattr(publisher, "require_beta_deploy_config", lambda _: admission.append("reviewed-config"))
    monkeypatch.setattr(publisher.shutil, "which", unexpected)
    for name in ("require_node24", "require_browser", "require_oauth_files",
                 "production_snapshot", "production_attachment_sha256", "public_http"):
        monkeypatch.setattr(publisher, name, unexpected)
    with pytest.raises(publisher.PublicationEvidenceError, match="website-owned publication"):
        publisher.publish(artifact_dir, config, video, recorder, "a" * 40)
    assert admission == ["reviewed-config", "signed-aggregate"]


def test_signed_source_failure_still_precedes_legacy_admission(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    monkeypatch.setattr(publisher, "__file__", str(root / "scripts/publish_passport_beta_demo.py"))
    monkeypatch.chdir(root)
    config = write(tmp_path, "config.json", b"{}")
    video = write(tmp_path, "video.mp4", b"reviewed")
    recorder = tmp_path / "recorder"
    recorder.mkdir()
    monkeypatch.setattr(publisher, "require_beta_deploy_config", lambda _: None)

    def reject(*args):
        raise publisher.PublicationEvidenceError("signed evidence rejected")

    monkeypatch.setattr(publisher, "require_signed_ui_source", reject)
    monkeypatch.setattr(publisher, "require_legacy_demo_layout", lambda *_: pytest.fail("Attestation must precede layout admission"))
    with pytest.raises(publisher.PublicationEvidenceError, match="signed evidence rejected"):
        publisher.publish(tmp_path, config, video, recorder, "a" * 40)
