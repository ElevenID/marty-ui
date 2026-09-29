"""Protected certificate setup is scoped, exercised, and always cleaned."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

import pytest
import yaml

from scripts.passport_supported_certificate_rehearsal import (
    WORKFLOW_NAME, rehearse_certificates,
)
from scripts.passport_supported_infra_rehearsal import JOB_TIMEOUT, recover_infrastructure
from scripts.passport_supported_infra_images import qualified_images
from scripts.passport_supported_provisioning_producer import (
    CERTIFICATE_WORKFLOW_REF, ProducerError, protected_context,
)


NOW = datetime(2026, 9, 28, 17, tzinfo=timezone.utc)
SOURCE = "a" * 40
SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64


def plan(surface: str = "selfhost") -> dict:
    project = f"marty-passport-acceptance-{surface}-" + uuid.uuid4().hex[:12]
    return {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": surface, "project": project,
        "run_id": "123456", "source_commit": SOURCE,
        "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=110)).isoformat(),
        "services_reference": SERVICES,
        "migrations_reference": (
            "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "c" * 64),
        "legacy_reference": (
            "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "d" * 64),
        "infra_images": qualified_images(verify_registry=False),
        "owner_labels": {
            "com.marty.passport.acceptance.owner": "supported-consumer",
            "com.marty.passport.acceptance.run-id": "123456",
            "com.marty.passport.acceptance.source-commit": SOURCE,
            "com.marty.passport.acceptance.services-image": SERVICES,
        },
    }


def setup_report(selected: dict) -> dict:
    return {
        "schema": "marty.passport-supported-disposable-certificate-setup/v1",
        "status": "setup_only", "gateway_operator_authorization_verified": False,
        "project": selected["project"], "source_commit": SOURCE,
        "evidence": {"csca_certificate_sha256": "1" * 64,
                     "dsc_certificate_sha256": "2" * 64},
    }


def test_certificate_rehearsal_calls_setup_after_signer_and_cleans(
    tmp_path: Path,
) -> None:
    selected = plan()
    calls = []
    cleanup = []

    def run(args: list[str], env: dict[str, str], timeout: int) -> bool:
        calls.append((args, timeout))
        assert env["DOCKER_HOST"] == "unix:///var/run/docker.sock"
        if args[:2] == ["docker", "run"]:
            mount = next(value for value in args
                         if value.startswith("type=bind,src=")
                         and value.endswith(",dst=/work/secrets"))
            output_dir = Path(mount.removeprefix("type=bind,src=").removesuffix(
                ",dst=/work/secrets"))
            (output_dir / "bao_token").write_text("hvs.disposable-service-token")
            (output_dir / "callback_signer_bao_token").write_text(
                "hvs.disposable-callback-token")
        return True

    def setup(*args, **kwargs) -> dict:
        assert len(calls) == 3
        assert args[0] == selected and args[2] == 29877
        assert kwargs["now"] == NOW
        return setup_report(selected)

    def teardown(*args, **kwargs) -> bool:
        cleanup.append(kwargs)
        assert kwargs["workflow_ref"] == CERTIFICATE_WORKFLOW_REF
        return True

    report = rehearse_certificates(
        tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
        {}, 29877, now=NOW,
        deadline_lookup=lambda env: NOW + timedelta(minutes=60),
        verify=lambda *args, **kwargs: selected,
        preflight=lambda *args, **kwargs: selected,
        inspect=lambda args: "", run=run, setup=setup, teardown=teardown,
    )
    assert report["status"] == "setup_only"
    assert report["certificate_setup_passed"] is True
    assert report["gateway_operator_authorization_verified"] is False
    assert report["rollback_accepted"] is False
    assert calls[0][0][-9:] == [
        "up", "-d", "--no-deps", "--wait", "--wait-timeout", "120",
        "postgres", "redis", "openbao",
    ]
    assert calls[1][0][:2] == ["docker", "run"]
    assert calls[2][0][-6:] == [
        "up", "-d", "--wait", "--wait-timeout", "360", "signing-keys",
    ]
    assert "docker-compose.passport-supported-disposable-selfhost-ceremony.yml" in " ".join(
        calls[2][0])
    assert len(cleanup) == 1
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_failed_certificate_setup_forces_teardown(tmp_path: Path) -> None:
    selected = plan()
    cleanup = []

    def run(args, env, timeout):
        if args[:2] == ["docker", "run"]:
            mount = next(value for value in args
                         if value.startswith("type=bind,src=")
                         and value.endswith(",dst=/work/secrets"))
            output_dir = Path(mount.removeprefix("type=bind,src=").removesuffix(
                ",dst=/work/secrets"))
            (output_dir / "bao_token").write_text("hvs.disposable-service-token")
            (output_dir / "callback_signer_bao_token").write_text(
                "hvs.disposable-callback-token")
        return True

    with pytest.raises(ProducerError, match="setup evidence is invalid"):
        rehearse_certificates(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {}, 29877, now=NOW,
            deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            verify=lambda *args, **kwargs: selected,
            preflight=lambda *args, **kwargs: selected,
            inspect=lambda args: "", run=run,
            setup=lambda *args, **kwargs: {"status": "accepted"},
            teardown=lambda *args, **kwargs: cleanup.append(True) or True,
        )
    assert cleanup == [True]
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_preflight_or_surface_failure_never_starts_docker(tmp_path: Path) -> None:
    for selected, rejection in ((plan("base"), "requires selfhost"),
                                (plan(), "preflight rejected")):
        calls = []
        def preflight(*args, **kwargs):
            raise ProducerError("preflight rejected")
        with pytest.raises(ProducerError, match=rejection):
            rehearse_certificates(
                tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
                {}, 29877, now=NOW,
                deadline_lookup=lambda env: NOW + timedelta(minutes=60),
                verify=lambda *args, **kwargs: selected, preflight=preflight,
                inspect=lambda args: calls.append(args) or "",
                run=lambda *args: calls.append(args) or True,
                teardown=lambda *args, **kwargs: calls.append(args) or True,
            )
        assert calls == []
        assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_certificate_job_identity_and_workflow_cannot_trigger_attestor() -> None:
    root = Path(__file__).resolve().parents[1] / ".github/workflows"
    workflow = yaml.safe_load((root / "passport-supported-certificate-rehearsal.yml").read_text())
    trigger = workflow.get("on", workflow.get(True))
    assert set(trigger) == {"workflow_dispatch"}
    assert workflow["name"] == WORKFLOW_NAME
    job = workflow["jobs"]["certificates"]
    assert job["timeout-minutes"] == JOB_TIMEOUT.total_seconds() / 60
    assert job["environment"] == "beta-lifecycle"
    assert job["steps"][0]["with"]["persist-credentials"] is False
    prepare, rehearse, recover, upload = job["steps"][1:]
    assert 'and .head_sha == $sha' in prepare["run"]
    assert rehearse["id"] == "rehearse"
    assert "timeout --signal=INT --kill-after=30s 1200s" in rehearse["run"]
    assert "scripts/passport_supported_certificate_rehearsal.py" in rehearse["run"]
    assert recover["id"] == "recover"
    assert recover["if"] == "always() && steps.prepare.outcome == 'success'"
    assert "timeout --signal=INT --kill-after=10s 240s" in recover["run"]
    assert "--recover-only" in recover["run"]
    assert upload["if"] == (
        "steps.rehearse.outcome == 'success' && steps.recover.outcome == 'success'")
    for step in (prepare, rehearse, recover):
        assert subprocess.run(["bash", "-n"], input=step["run"].encode(),
                              capture_output=True).returncode == 0
    attestor = yaml.safe_load((root / "passport-supported-provisioning-record.yml").read_text())
    attestor_trigger = attestor.get("on", attestor.get(True))
    assert attestor_trigger["workflow_run"]["workflows"] == [
        "Passport Supported Disposable Provisioning Producer"]
    environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "ElevenID/marty-ui",
                   "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
                   "GITHUB_WORKFLOW_REF": CERTIFICATE_WORKFLOW_REF,
                   "GITHUB_SHA": SOURCE, "GITHUB_RUN_ID": "987654"}
    assert protected_context(environment, workflow_ref=CERTIFICATE_WORKFLOW_REF) == (
        SOURCE, "987654")


def test_certificate_recovery_uses_its_protected_workflow_and_erases_staging(
    tmp_path: Path,
) -> None:
    selected = plan()
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(selected), encoding="utf-8")
    root = Path(tempfile.gettempdir()) / selected["project"]
    (root / "secrets").mkdir(parents=True)
    (root / "secrets" / "bao_root_token").write_text("test-token", encoding="ascii")
    (root / "acceptance.env").write_text("test=value\n", encoding="ascii")
    calls = []

    def teardown(*args, **kwargs) -> bool:
        calls.append(kwargs)
        assert kwargs["workflow_ref"] == CERTIFICATE_WORKFLOW_REF
        return True

    try:
        recover_infrastructure(plan_path, tmp_path / "manifest.json", "123456",
                               {}, teardown=teardown,
                               workflow_ref=CERTIFICATE_WORKFLOW_REF)
        assert len(calls) == 1
        assert not root.exists()
    finally:
        if root.exists():
            (root / "secrets" / "bao_root_token").unlink(missing_ok=True)
            (root / "secrets").rmdir()
            (root / "acceptance.env").unlink(missing_ok=True)
            root.rmdir()


def test_certificate_job_deadline_requires_exact_attempt() -> None:
    from scripts import passport_supported_infra_rehearsal as infra

    environment = {"GITHUB_JOB": "certificates", "GITHUB_RUN_ID": "987654",
                   "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": SOURCE}
    job = {"name": "certificates", "workflow_name": WORKFLOW_NAME,
           "run_id": 987654, "run_attempt": 2, "head_sha": SOURCE,
           "status": "in_progress", "started_at": NOW.isoformat()}
    assert infra.protected_job_deadline(
        environment, lambda *args: {"total_count": 1, "jobs": [job]},
        job_name="certificates", workflow_name=WORKFLOW_NAME,
    ) == NOW + JOB_TIMEOUT
    with pytest.raises(ProducerError, match="job context"):
        infra.protected_job_deadline(
            {**environment, "GITHUB_JOB": "infra"},
            lambda *args: {"total_count": 1, "jobs": [job]},
            job_name="certificates", workflow_name=WORKFLOW_NAME,
        )
