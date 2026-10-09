"""The post-deletion gate binds one protected run to the live fenced beta."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from scripts import collect_passport_beta_rust_readiness as producer
from scripts import verify_passport_beta_rust_readiness as verifier
from scripts.probe_passport_beta_cutover_snapshot import digest
from tests.test_probe_passport_beta_cutover_snapshot import evidence, collect_fixture


SOURCE = "a" * 40
DELETION = "b" * 40
RUN = 42


def fixture(tmp_path: Path):
    installation, observed, direct = evidence()
    installation["credentials_deletion_head"] = DELETION
    snapshot = collect_fixture(installation, observed, direct)
    receipt_path = tmp_path / f"passport-beta-fence-installation-{RUN}.json"
    snapshot_path = tmp_path / f"passport-beta-cutover-snapshot-{RUN}.json"
    report_path = tmp_path / f"passport-beta-rust-readiness-{RUN}.json"
    receipt_path.write_text(json.dumps(installation, sort_keys=True) + "\n")
    snapshot_path.write_text(json.dumps(snapshot, sort_keys=True) + "\n")
    report = producer.collect(
        source_commit=SOURCE, run_id=RUN, deletion_head=DELETION,
        snapshot=snapshot,
        snapshot_file_sha256=hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
        installation=installation,
        installation_file_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        checked_at=datetime(2026, 9, 29, 0, 0, 4, tzinfo=timezone.utc),
        lineage=lambda _approved, _current: None,
    )
    report_path.write_text(json.dumps(report, sort_keys=True) + "\n")
    return installation, snapshot, report, receipt_path, snapshot_path, report_path


def fake_gh(receipt_path, snapshot_path, report_path, *, workflow=producer.WORKFLOW,
            corrupt=None):
    sources = {path.stem: path for path in (receipt_path, snapshot_path, report_path)}
    calls = []

    def execute(args):
        calls.append(args)
        if args[:2] == ["gh", "api"]:
            if args[2].endswith("/pulls/305"):
                return json.dumps({
                    "state": "closed", "merged": True,
                    "head": {"sha": DELETION},
                })
            return json.dumps({
                "id": RUN, "status": "completed", "conclusion": "success",
                "event": "workflow_dispatch", "path": workflow,
                "head_branch": "main", "head_sha": SOURCE,
                "repository": {"full_name": verifier.REPOSITORY},
                "head_repository": {"full_name": verifier.REPOSITORY},
                "created_at": "2026-09-29T00:00:03Z",
                "updated_at": "2026-09-29T00:00:05Z",
            })
        if args[:3] == ["gh", "run", "download"]:
            name = args[args.index("--name") + 1]
            target = Path(args[args.index("--dir") + 1]) / f"{name}.json"
            target.write_bytes(sources[name].read_bytes()
                               if name != corrupt else b"tampered")
        return "verified"

    return execute, calls


def verify(installation, snapshot, receipt_path, snapshot_path, report_path,
           execute):
    return verifier.verify(
        report_path, source_commit=SOURCE, deletion_head=DELETION,
        snapshot=snapshot, snapshot_path=snapshot_path,
        snapshot_file_sha256=hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
        receipt=installation, receipt_path=receipt_path, execute=execute,
    )


def test_current_source_readiness_has_no_predeletion_run(tmp_path):
    installation, snapshot, report, receipt_path, snapshot_path, report_path = fixture(tmp_path)
    assert report["schema"] == "marty.passport-beta-rust-readiness/v1"
    assert "predeletion_acceptance_run_id" not in report
    execute, calls = fake_gh(receipt_path, snapshot_path, report_path)
    result = verify(installation, snapshot, receipt_path, snapshot_path,
                    report_path, execute)
    assert result["cutover_report_run_id"] == RUN
    assert len([call for call in calls if call[:3] == ["gh", "attestation", "verify"]]) == 3


def test_wrong_workflow_or_tampered_artifact_fails_closed(tmp_path):
    installation, snapshot, _, receipt_path, snapshot_path, report_path = fixture(tmp_path)
    wrong, _ = fake_gh(receipt_path, snapshot_path, report_path,
                       workflow=".github/workflows/passport-python-deletion-cutover.yml")
    with pytest.raises(producer.HostProbeError, match="protected main"):
        verify(installation, snapshot, receipt_path, snapshot_path, report_path, wrong)
    tampered, _ = fake_gh(receipt_path, snapshot_path, report_path,
                          corrupt=report_path.stem)
    with pytest.raises(producer.HostProbeError, match="artifact bytes differ"):
        verify(installation, snapshot, receipt_path, snapshot_path, report_path, tampered)


def test_changed_writer_or_unsafe_counts_fail_closed(tmp_path):
    installation, snapshot, _, receipt_path, snapshot_path, _ = fixture(tmp_path)
    changed = deepcopy(snapshot)
    changed["writer_generation"] += 1
    changed["snapshot_sha256"] = digest({
        key: value for key, value in changed.items() if key != "snapshot_sha256"
    })
    with pytest.raises(producer.HostProbeError, match="installed fence"):
        producer.collect(
            source_commit=SOURCE, run_id=RUN, deletion_head=DELETION,
            snapshot=changed, snapshot_file_sha256="c" * 64,
            installation=installation,
            installation_file_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            checked_at=datetime(2026, 9, 29, 0, 0, 4, tzinfo=timezone.utc),
            lineage=lambda _approved, _current: None,
        )
    unsafe = deepcopy(snapshot)
    unsafe["counts"]["active_passport_flow_count"] = 1
    unsafe["snapshot_sha256"] = digest({
        key: value for key, value in unsafe.items() if key != "snapshot_sha256"
    })
    with pytest.raises(producer.HostProbeError, match="installed fence"):
        producer.collect(
            source_commit=SOURCE, run_id=RUN, deletion_head=DELETION,
            snapshot=unsafe, snapshot_file_sha256="c" * 64,
            installation=installation,
            installation_file_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            checked_at=datetime(2026, 9, 29, 0, 0, 4, tzinfo=timezone.utc),
            lineage=lambda _approved, _current: None,
        )
