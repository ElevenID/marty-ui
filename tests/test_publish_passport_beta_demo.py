import subprocess

import pytest

from scripts import publish_passport_beta_demo as publisher
from scripts.probe_passport_beta_host import HostProbeError


def test_reviewed_publisher_uses_beta_environment_and_checks_production(
    tmp_path, monkeypatch
):
    (tmp_path / "scripts").mkdir()
    monkeypatch.setattr(
        publisher, "__file__", str(tmp_path / "scripts" / "publish_passport_beta_demo.py")
    )
    monkeypatch.chdir(tmp_path)
    recorder = tmp_path / "recorder"
    (recorder / "node_modules" / "@playwright" / "test").mkdir(parents=True)
    config = tmp_path / "reviewed.json"
    config.write_text("{}", encoding="utf-8")
    artifact_dir = tmp_path / "signed-aggregate"
    artifact_dir.mkdir()
    video = tmp_path / "reviewed.mp4"
    video.write_bytes(b"reviewed")
    monkeypatch.setattr(publisher, "require_beta_deploy_config", lambda _: None)
    monkeypatch.setattr(publisher, "require_signed_ui_source", lambda *_: None)
    monkeypatch.setattr(publisher, "require_oauth_files", lambda: None)
    monkeypatch.setattr(publisher.shutil, "which", lambda _: "/usr/bin/tool")
    monkeypatch.setenv("WSLENV", "OTHER/u")
    monkeypatch.setenv("BETA_ORIGIN", "https://wrong.example")
    observed = []

    def run(command, **options):
        observed.append((command, options))
        if command[0] == "git":
            return subprocess.CompletedProcess(
                command, 0, "a" * 40 if "rev-parse" in command else "", ""
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(publisher.subprocess, "run", run)
    baseline = {"sha256": "b" * 64, "container_counts": {"prod": 24}}
    monkeypatch.setattr(publisher, "production_snapshot", lambda: baseline)
    monkeypatch.setattr(publisher, "production_attachment_sha256", lambda: "c" * 64)
    checks = []
    monkeypatch.setattr(publisher, "public_http", lambda: checks.append("http"))
    publisher.publish(artifact_dir, config, video, recorder, "a" * 40)
    command, options = observed[-1]
    assert command[0] == "node"
    assert command[1] == str(recorder / "src" / "automatedPublication.js")
    assert options["cwd"] == tmp_path
    assert options["timeout"] == 75 * 60
    assert options["env"]["WSLENV"] == (
        "OTHER/u:ELEVENID_DEMO_MANIFEST/p:ELEVENID_DEMO_VIDEO_ID"
    )
    assert options["env"]["NODE_PATH"] == str(recorder / "node_modules")
    assert options["env"]["BETA_ORIGIN"] == publisher.BETA_ORIGIN
    assert checks == ["http", "http"]

    changed = {"sha256": "d" * 64, "container_counts": {"prod": 24}}
    snapshots = iter((baseline, changed))
    monkeypatch.setattr(publisher, "production_snapshot", lambda: next(snapshots))
    with pytest.raises(HostProbeError, match="Production container identity"):
        publisher.publish(artifact_dir, config, video, recorder, "a" * 40)


def test_publisher_requires_scripts_from_signed_aggregate_source(tmp_path, monkeypatch):
    artifact_dir = tmp_path / "signed-aggregate"
    artifact_dir.mkdir()
    monkeypatch.setenv("PASSPORT_ACCEPTANCE_API_KEY", "k" * 32)
    monkeypatch.setattr(publisher, "collect_aggregate", lambda *_, **__: {
        "release": {"source_commit": "a" * 40},
    })
    seen = []

    def run(command, **options):
        seen.append(command)
        if "rev-parse" in command:
            return subprocess.CompletedProcess(command, 0, "a" * 40, "")
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(publisher.subprocess, "run", run)
    publisher.require_signed_ui_source(artifact_dir, tmp_path)
    assert seen[-1] == ["git", "diff", "--quiet", "a" * 40, "--",
                        *publisher.REVIEWED_UI_FILES]

    def changed(command, **options):
        if "diff" in command:
            return subprocess.CompletedProcess(command, 1, b"", b"")
        return subprocess.CompletedProcess(command, 0, "a" * 40, "")

    monkeypatch.setattr(publisher.subprocess, "run", changed)
    with pytest.raises(publisher.PublicationEvidenceError, match="differs"):
        publisher.require_signed_ui_source(artifact_dir, tmp_path)


def test_publication_environment_rejects_conflicting_wsl_path_rule(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("WSLENV", "ELEVENID_DEMO_MANIFEST/u")
    with pytest.raises(publisher.PublicationEvidenceError, match="translation is invalid"):
        publisher.publication_environment(tmp_path)


def test_publication_environment_rejects_conflicting_video_id_rule(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("WSLENV", "ELEVENID_DEMO_VIDEO_ID/u")
    with pytest.raises(publisher.PublicationEvidenceError, match="translation is invalid"):
        publisher.publication_environment(tmp_path)
