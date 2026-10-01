import hashlib
import json
from pathlib import Path

import pytest

from scripts.read_protected_passport_artifact import (
    ProtectedArtifactError, read_artifact,
)


RUN = 12345
SOURCE = "a" * 40


def metadata(workflow):
    return {
        "id": RUN, "event": "workflow_dispatch",
        "path": f".github/workflows/{workflow}",
        "head_branch": "main", "head_sha": SOURCE,
        "run_attempt": 1, "status": "completed", "conclusion": "success",
        "run_started_at": "2026-10-01T12:00:00Z",
        "updated_at": "2026-10-01T12:10:00Z",
        "head_repository": {"full_name": "ElevenID/marty-ui"},
    }


def downloader(kind, *, run=None, artifact=None, extra=None):
    workflows = {
        "preliminary": ("passport-beta-preliminary.yml", "passport-beta-preliminary"),
        "soak": ("passport-beta-soak-sample.yml", "passport-beta-soak"),
        "publication": ("passport-beta-demo-publication.yml",
                        "passport-beta-demo-publication"),
    }
    workflow, prefix = workflows[kind]
    source = run or metadata(workflow)
    media = {}
    negative_runs = {}
    if kind == "preliminary":
        for case in ("unsigned", "foreign"):
            video_name = f"{case}-callback-uncut.webm"
            scan_name = f"{case}-callback-privacy-scan.json"
            video = f"{case} uncut synthetic video".encode()
            video_hash = hashlib.sha256(video).hexdigest()
            scan = json.dumps({
                "schemaVersion": 1, "passed": True, "findings": [],
                "videoSha256": video_hash, "frameSamplingFps": 2,
            }).encode()
            media[video_name] = video
            media[scan_name] = scan
            negative_runs[case] = {
                "video_sha256": video_hash,
                "privacy_scan_report_sha256": hashlib.sha256(scan).hexdigest(),
            }
    payload = artifact or ({
        "schema": "marty.passport-beta-preliminary/v1",
        "status": "qualified_for_recording", "negative_runs": negative_runs,
    } if kind == "preliminary" else {
        "schema": "marty.passport-beta-soak-sample/v1", "status": "observed",
        "protected_run": {"run_id": str(RUN), "workflow_commit": SOURCE},
    } if kind == "soak" else {
        "schema": "marty.passport-beta-demo-publication/v1",
        "status": "public_verified",
        "protected_run": {"run_id": str(RUN), "workflow_commit": SOURCE},
    })

    def execute(args):
        if args[:2] == ["gh", "api"]:
            return json.dumps(source)
        assert args[:3] == ["gh", "run", "download"]
        destination = Path(args[args.index("--dir") + 1])
        (destination / f"{prefix}-{RUN}.json").write_text(json.dumps(payload))
        for name, contents in media.items():
            (destination / name).write_bytes(contents)
        if extra is not None:
            (destination / extra).write_text("unexpected")
        return ""

    return execute


def test_reads_exact_protected_preliminary_soak_and_publication():
    preliminary = read_artifact("preliminary", RUN,
                                execute=downloader("preliminary"))
    assert preliminary["kind"] == "preliminary"
    assert len(preliminary["artifact_sha256"]) == 64
    assert len(preliminary["media_sha256"]) == 4
    soak = read_artifact("soak", RUN, execute=downloader("soak"))
    assert soak["workflow_commit"] == SOURCE
    assert soak["value"]["protected_run"]["run_id"] == str(RUN)
    publication = read_artifact("publication", RUN,
                                execute=downloader("publication"))
    assert publication["kind"] == "publication"
    assert publication["artifact_name"] == f"passport-beta-demo-publication-{RUN}"


def test_rejects_unprotected_run_or_bad_workflow():
    wrong_branch = metadata("passport-beta-preliminary.yml")
    wrong_branch["head_branch"] = "feature"
    with pytest.raises(ProtectedArtifactError, match="protected main"):
        read_artifact("preliminary", RUN,
                      execute=downloader("preliminary", run=wrong_branch))
    wrong_workflow = metadata("ci.yml")
    with pytest.raises(ProtectedArtifactError, match="protected main"):
        read_artifact("preliminary", RUN,
                      execute=downloader("preliminary", run=wrong_workflow))


def test_rejects_soak_artifact_with_wrong_run_binding():
    forged = {"schema": "marty.passport-beta-soak-sample/v1",
              "status": "observed", "protected_run": {
                  "run_id": str(RUN + 1), "workflow_commit": SOURCE}}
    with pytest.raises(ProtectedArtifactError, match="does not bind"):
        read_artifact("soak", RUN,
                      execute=downloader("soak", artifact=forged))


def test_rejects_publication_artifact_with_wrong_run_binding():
    forged = {"schema": "marty.passport-beta-demo-publication/v1",
              "status": "public_verified", "protected_run": {
                  "run_id": str(RUN + 1), "workflow_commit": SOURCE}}
    with pytest.raises(ProtectedArtifactError, match="D-12 publication artifact"):
        read_artifact("publication", RUN,
                      execute=downloader("publication", artifact=forged))


def test_rejects_preliminary_with_unexpected_file_or_bad_media():
    with pytest.raises(ProtectedArtifactError, match="shape"):
        read_artifact("preliminary", RUN,
                      execute=downloader("preliminary", extra="unexpected.txt"))
    with pytest.raises(ProtectedArtifactError, match="differs from its receipt"):
        read_artifact("preliminary", RUN,
                      execute=downloader("preliminary", artifact={
                          "schema": "marty.passport-beta-preliminary/v1",
                          "status": "qualified_for_recording",
                          "negative_runs": {
                              case: {"video_sha256": "0" * 64,
                                     "privacy_scan_report_sha256": "0" * 64}
                              for case in ("unsigned", "foreign")},
                      }))
