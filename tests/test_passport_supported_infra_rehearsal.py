"""Disposable infrastructure rehearsal stops before passport acceptance."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

import pytest
import yaml

from scripts.passport_supported_infra_rehearsal import (
    JOB_TIMEOUT, MIN_JOB_BUDGET, MIN_TEARDOWN_LEASE,
    _local_docker_environment, protected_job_deadline, recover_infrastructure,
    rehearse_infrastructure,
)
from scripts.passport_supported_infra_images import qualified_images
from services.passport_disposable_identity import managed_key_reference
from scripts.passport_supported_provisioning_producer import (
    INFRA_WORKFLOW_REF, ProducerError,
)


NOW = datetime(2026, 9, 28, 17, tzinfo=timezone.utc)
SOURCE = "a" * 40
SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64


def plan() -> dict:
    project = "marty-passport-acceptance-base-" + uuid.uuid4().hex[:12]
    return {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": "base", "project": project,
        "run_id": "123456", "source_commit": SOURCE,
        "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=110)).isoformat(),
        "services_reference": SERVICES,
        "migrations_reference": (
            "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "c" * 64),
        "infra_images": qualified_images(verify_registry=False),
        "owner_labels": {
            "com.marty.passport.acceptance.owner": "supported-consumer",
            "com.marty.passport.acceptance.run-id": "123456",
            "com.marty.passport.acceptance.source-commit": SOURCE,
            "com.marty.passport.acceptance.services-image": SERVICES,
        },
    }


def test_infra_rehearsal_starts_only_private_infra_and_always_cleans(
    tmp_path: Path,
) -> None:
    selected = plan()
    calls = []
    cleanup = []
    environment = {"GITHUB_ACTIONS": "true"}

    def run(args: list[str], env: dict[str, str], timeout: int) -> bool:
        calls.append((args, env, timeout))
        assert env["DOCKER_HOST"] == "unix:///var/run/docker.sock"
        assert "DOCKER_CONTEXT" not in env
        if args[:2] == ["docker", "run"]:
            mount = next(value for value in args
                         if value.startswith("type=bind,src=")
                         and value.endswith(",dst=/work/secrets"))
            output_dir = Path(mount.removeprefix("type=bind,src=").removesuffix(
                ",dst=/work/secrets"))
            assert output_dir != Path(env["PASSPORT_ACCEPTANCE_SECRET_DIR"])
            (output_dir / "bao_token").write_text(
                "hvs.disposable-service-token", encoding="ascii")
            (output_dir / "callback_signer_bao_token").write_text(
                "hvs.disposable-callback-token", encoding="ascii")
        return True

    def teardown(*args, **kwargs) -> bool:
        cleanup.append((args, kwargs))
        assert Path(calls[0][1]["PASSPORT_ACCEPTANCE_SECRET_DIR"]).is_dir()
        assert kwargs["now"] == NOW
        return True

    result = rehearse_infrastructure(
        tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
        environment, 29876, now=NOW, deadline_lookup=lambda env: NOW + timedelta(minutes=60),
        verify=lambda *args, **kwargs: selected,
        preflight=lambda *args, **kwargs: selected,
        inspect=lambda args: "", run=run, teardown=teardown,
    )
    assert result == {
        "schema": "marty.passport-supported-infra-rehearsal/v1",
        "status": "blocked", "infra_rehearsal_passed": True,
        "project": selected["project"], "source_commit": SOURCE,
        "plan_run_id": "123456",
    }
    assert len(calls) == 2
    assert calls[0][0][-9:] == [
        "up", "-d", "--no-deps", "--wait", "--wait-timeout", "120",
        "postgres", "redis", "openbao",
    ]
    assert calls[1][0][:2] == ["docker", "run"]
    assert calls[1][0][2:5] == [
        "--rm", "--name", f"{selected['project']}-passport-openbao-bootstrap-1",
    ]
    assert calls[1][0][-2:] == [selected["infra_images"]["openbao"],
                               "/scripts/passport_supported_openbao_bootstrap.sh"]
    assert "PASSPORT_ACCEPTANCE_CSCA_KEY_REFERENCE=" + managed_key_reference(
        29876, "csca") in calls[1][0]
    assert "PASSPORT_ACCEPTANCE_DSC_KEY_REFERENCE=" + managed_key_reference(
        29876, "x509_doc_signer") in calls[1][0]
    assert [call[2] for call in calls] == [300, 180]
    assert len(cleanup) == 1
    assert not (Path(calls[0][1]["PASSPORT_ACCEPTANCE_SECRET_DIR"]).parent).exists()


def test_failed_startup_still_tears_down_partial_project(tmp_path: Path) -> None:
    selected = plan()
    cleanup = []
    with pytest.raises(ProducerError, match="startup failed"):
        rehearse_infrastructure(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {}, 29876, now=NOW, deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            verify=lambda *args, **kwargs: selected,
            preflight=lambda *args, **kwargs: selected,
            inspect=lambda args: "", run=lambda *args: False,
            teardown=lambda *args, **kwargs: cleanup.append(True) or True,
        )
    assert cleanup == [True]
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_independent_recovery_requires_verified_teardown_before_erasing_secrets(
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
        assert kwargs["workflow_ref"].endswith(
            "passport-supported-infra-rehearsal.yml@refs/heads/main")
        if len(calls) == 2:
            plan_path.write_text(json.dumps({**selected, "run_id": "different"}),
                                 encoding="utf-8")
        return len(calls) > 1

    try:
        with pytest.raises(ProducerError, match="recovery is unverified"):
            recover_infrastructure(plan_path, Path("manifest"), "123456", {},
                                   teardown=teardown)
        assert (root / "secrets" / "bao_root_token").is_file()
        with pytest.raises(ProducerError, match="plan changed"):
            recover_infrastructure(plan_path, Path("manifest"), "123456", {},
                                   teardown=teardown)
        assert (root / "secrets" / "bao_root_token").is_file()
        plan_path.write_text(json.dumps(selected), encoding="utf-8")
        recover_infrastructure(plan_path, Path("manifest"), "123456", {},
                               teardown=teardown)
        assert not root.exists()
    finally:
        if root.exists():
            (root / "secrets" / "bao_root_token").unlink(missing_ok=True)
            (root / "secrets").rmdir()
            (root / "acceptance.env").unlink(missing_ok=True)
            root.rmdir()


def test_failed_preflight_never_starts_docker(tmp_path: Path) -> None:
    selected = plan()
    calls = []

    def reject(*args, **kwargs) -> dict:
        raise ProducerError("synthetic preflight failure")

    with pytest.raises(ProducerError, match="preflight failure"):
        rehearse_infrastructure(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {}, 29876, now=NOW, deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            verify=lambda *args, **kwargs: selected, preflight=reject,
            inspect=lambda args: calls.append(args) or "",
            run=lambda *args: calls.append(args) or True,
            teardown=lambda *args, **kwargs: calls.append(args) or True,
        )
    assert calls == []


def test_existing_project_resources_block_startup_without_deletion(
    tmp_path: Path,
) -> None:
    selected = plan()
    calls = []
    with pytest.raises(ProducerError, match="already has live resources"):
        rehearse_infrastructure(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {}, 29876, now=NOW, deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            verify=lambda *args, **kwargs: selected,
            preflight=lambda *args, **kwargs: selected,
            inspect=lambda args: "1" * 64 if args[0] == "ps" else "",
            run=lambda *args: calls.append(args) or True,
            teardown=lambda *args, **kwargs: calls.append(args) or True,
        )
    assert calls == []
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_missing_bootstrap_tokens_force_teardown(tmp_path: Path) -> None:
    selected = plan()
    calls = []
    with pytest.raises(ProducerError, match="token file is missing"):
        rehearse_infrastructure(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {}, 29876, now=NOW, deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            verify=lambda *args, **kwargs: selected,
            preflight=lambda *args, **kwargs: selected,
            inspect=lambda args: "", run=lambda *args: True,
            teardown=lambda *args, **kwargs: calls.append(True) or True,
        )
    assert calls == [True]
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_short_lease_and_remote_docker_environment_are_rejected() -> None:
    selected = plan()
    selected["expires_at"] = (NOW + timedelta(minutes=89)).isoformat()
    with pytest.raises(ProducerError, match="insufficient teardown lease"):
        rehearse_infrastructure(
            Path("plan"), Path("manifest"), "123456", {}, 29876,
            now=NOW, deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            verify=lambda *args, **kwargs: selected,
        )
    local = _local_docker_environment({
        "DOCKER_HOST": "tcp://production:2376", "DOCKER_CONTEXT": "production",
        "DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "/tmp/certs",
    })
    assert local["DOCKER_HOST"] == "unix:///var/run/docker.sock"
    assert "DOCKER_CONTEXT" not in local
    assert "DOCKER_TLS_VERIFY" not in local
    assert "DOCKER_CERT_PATH" not in local


def test_delayed_preflight_cannot_start_after_teardown_budget_is_spent(
    tmp_path: Path,
) -> None:
    selected = plan()
    calls = []
    with pytest.raises(ProducerError, match="insufficient teardown lease"):
        rehearse_infrastructure(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {}, 29876, now=NOW, deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            clock=lambda: NOW + timedelta(minutes=21),
            verify=lambda *args, **kwargs: selected,
            preflight=lambda *args, **kwargs: selected,
            inspect=lambda args: "",
            run=lambda *args: calls.append(args) or True,
            teardown=lambda *args, **kwargs: calls.append(args) or True,
        )
    assert calls == []
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_late_job_cannot_start_even_while_plan_lease_is_valid(
    tmp_path: Path,
) -> None:
    selected = plan()
    calls = []
    with pytest.raises(ProducerError, match="job has insufficient teardown budget"):
        rehearse_infrastructure(
            tmp_path / "plan.json", tmp_path / "manifest.json", "123456",
            {}, 29876, now=NOW, deadline_lookup=lambda env: NOW + timedelta(minutes=60),
            clock=lambda: NOW + timedelta(minutes=16),
            verify=lambda *args, **kwargs: selected,
            preflight=lambda *args, **kwargs: selected,
            inspect=lambda args: "",
            run=lambda *args: calls.append(args) or True,
            teardown=lambda *args, **kwargs: calls.append(args) or True,
        )
    assert calls == []
    assert not (Path(tempfile.gettempdir()) / selected["project"]).exists()


def test_protected_job_timeout_leaves_lease_for_cleanup() -> None:
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows"
                / "passport-supported-infra-rehearsal.yml")
    job = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"]["infra"]
    assert job["timeout-minutes"] == JOB_TIMEOUT.total_seconds() / 60
    assert job["timeout-minutes"] <= MIN_TEARDOWN_LEASE.total_seconds() / 60 - 15
    assert MIN_JOB_BUDGET < MIN_TEARDOWN_LEASE


def test_job_deadline_is_bound_to_exact_run_attempt() -> None:
    environment = {"GITHUB_JOB": "infra", "GITHUB_RUN_ID": "987654",
                   "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": SOURCE}
    job = {"name": "infra",
           "workflow_name": "Passport Supported Disposable Infra Rehearsal",
           "run_id": 987654, "run_attempt": 2, "head_sha": SOURCE,
           "status": "in_progress", "started_at": NOW.isoformat()}
    response = {"total_count": 1, "jobs": [job]}
    observed = []

    def lookup(run_id: str, attempt: str) -> dict:
        observed.append((run_id, attempt))
        return response

    assert protected_job_deadline(environment, lookup) == NOW + JOB_TIMEOUT
    assert observed == [("987654", "2")]
    for mutation in ({**job, "head_sha": "b" * 40},
                     {**job, "run_attempt": 1},
                     {**job, "name": "other"},
                     {**job, "workflow_name": "Passport Supported Disposable Provisioning Producer"},
                     {**job, "status": "completed"}):
        with pytest.raises(ProducerError, match="job identity differs"):
            protected_job_deadline(
                environment, lambda *args: {"total_count": 1, "jobs": [mutation]})
    with pytest.raises(ProducerError, match="ambiguous"):
        protected_job_deadline(
            environment, lambda *args: {"total_count": 2, "jobs": [job, job]})
    with pytest.raises(ProducerError, match="start time is invalid"):
        protected_job_deadline(
            environment, lambda *args: {"total_count": 1, "jobs": [
                {**job, "started_at": "invalid"}]})


def test_infra_workflow_cannot_trigger_provisioning_record_attestor() -> None:
    root = Path(__file__).resolve().parents[1] / ".github/workflows"
    workflow = yaml.safe_load((root / "passport-supported-infra-rehearsal.yml").read_text(
        encoding="utf-8"))
    trigger = workflow.get("on", workflow.get(True))
    assert set(trigger) == {"workflow_dispatch"}
    assert set(trigger["workflow_dispatch"]["inputs"]) == {"plan_run_id", "release_tag"}
    assert workflow["name"] == "Passport Supported Disposable Infra Rehearsal"
    assert workflow["permissions"] == {"actions": "read", "contents": "read",
                                       "packages": "read"}
    job = workflow["jobs"]["infra"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "passport-beta-wsl2"]
    assert job["environment"] == "beta-lifecycle"
    assert job["steps"][0]["with"]["persist-credentials"] is False
    prepare, rehearse, recover, upload = job["steps"][1:]
    assert '.path == ".github/workflows/passport-supported-provisioning-plan.yml"' in prepare["run"]
    assert 'and .head_sha == $sha' in prepare["run"]
    assert "gh run download \"$PLAN_RUN_ID\"" in prepare["run"]
    assert "PASSPORT_INFRA_WORK=$work" in prepare["run"]
    assert "timeout --signal=INT --kill-after=30s 1200s" in rehearse["run"]
    assert "scripts/passport_supported_infra_rehearsal.py" in rehearse["run"]
    assert "passport-supported-infra-rehearsal-$GITHUB_RUN_ID.json" in rehearse["run"]
    assert recover["if"] == "always() && steps.prepare.outcome == 'success'"
    assert "timeout --signal=INT --kill-after=10s 240s" in recover["run"]
    assert "--recover-only" in recover["run"]
    assert upload["if"] == (
        "steps.rehearse.outcome == 'success' && steps.recover.outcome == 'success'")
    for step in (prepare, rehearse, recover):
        assert "docker " not in step["run"]
        assert subprocess.run(["bash", "-n"], input=step["run"].encode(),
                              capture_output=True, check=False).returncode == 0
    artifact = upload["with"]
    assert artifact["name"] == (
        "passport-supported-infra-rehearsal-${{ github.run_id }}-${{ github.run_attempt }}")
    assert artifact["if-no-files-found"] == "error"
    attestor = yaml.safe_load((root / "passport-supported-provisioning-record.yml").read_text(
        encoding="utf-8"))
    attestor_trigger = attestor.get("on", attestor.get(True))
    assert attestor_trigger["workflow_run"]["workflows"] == [
        "Passport Supported Disposable Provisioning Producer"]
    assert INFRA_WORKFLOW_REF.endswith(
        "passport-supported-infra-rehearsal.yml@refs/heads/main")
