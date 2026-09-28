"""Disposable infrastructure rehearsal stops before passport acceptance."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import uuid

import pytest
import yaml

from scripts.passport_supported_infra_rehearsal import (
    JOB_TIMEOUT, MIN_JOB_BUDGET, MIN_TEARDOWN_LEASE,
    _local_docker_environment, protected_job_deadline, rehearse_infrastructure,
)
from scripts.passport_supported_infra_images import qualified_images
from scripts.passport_supported_provisioning_producer import ProducerError


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
                / "passport-supported-provisioning-producer.yml")
    job = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"]["producer"]
    assert job["timeout-minutes"] == JOB_TIMEOUT.total_seconds() / 60
    assert job["timeout-minutes"] <= MIN_TEARDOWN_LEASE.total_seconds() / 60 - 15
    assert MIN_JOB_BUDGET < MIN_TEARDOWN_LEASE


def test_job_deadline_is_bound_to_exact_run_attempt() -> None:
    environment = {"GITHUB_JOB": "producer", "GITHUB_RUN_ID": "987654",
                   "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": SOURCE}
    job = {"name": "producer",
           "workflow_name": "Passport Supported Disposable Provisioning Producer",
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
