"""The producer remains blocked and only accepts exact protected provenance."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest
import yaml

from scripts.check_passport_supported_rollback_model import DISPOSABLE_SERVICES
from scripts.passport_supported_provisioning_producer import (
    ProducerError, WORKFLOW_REF, collect_record, destroy_disposable_project,
    issue_disposable_api_key,
    verify_plan_release,
)


NOW = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)
PROJECT = "marty-passport-acceptance-base-123456abcdef"
SOURCE = "a" * 40
SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64
LABELS = {
    "com.marty.passport.acceptance.owner": "supported-consumer",
    "com.marty.passport.acceptance.run-id": "123456",
    "com.marty.passport.acceptance.source-commit": SOURCE,
    "com.marty.passport.acceptance.services-image": SERVICES,
}
ENV = {
    "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "ElevenID/marty-ui",
    "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_WORKFLOW_REF": WORKFLOW_REF, "GITHUB_SHA": SOURCE,
    "GITHUB_RUN_ID": "987654",
}


def source_plan(tmp_path: Path) -> tuple[Path, Path, dict]:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text('{"schema":"marty.stack/v1"}', encoding="utf-8")
    inputs = {
        "source_commit": SOURCE,
        "stack_manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "services_reference": SERVICES,
        "migrations_reference": "migrations@sha256:" + "c" * 64,
        "legacy_reference": "legacy@sha256:" + "d" * 64,
        "infra_images": {"postgres": "postgres@sha256:" + "e" * 64},
    }
    plan = {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": "base", "project": PROJECT,
        "run_id": "123456", "owner_labels": LABELS,
        "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=55)).isoformat(),
        **inputs,
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path, manifest, plan


def verify(path: Path, manifest: Path, plan: dict, **kwargs) -> dict:
    inputs = {key: plan[key] for key in (
        "source_commit", "stack_manifest_sha256", "services_reference",
        "migrations_reference", "legacy_reference", "infra_images",
    )}
    return verify_plan_release(
        path, manifest, "123456", ENV,
        attest=kwargs.pop("attest", lambda *args: True),
        release=kwargs.pop("release", lambda *args: inputs),
        checkout=kwargs.pop("checkout", lambda: (SOURCE, False)),
        now=kwargs.pop("now", NOW), **kwargs,
    )


def test_protected_plan_release_gate_accepts_only_exact_short_lease(
    tmp_path: Path,
) -> None:
    path, manifest, plan = source_plan(tmp_path)
    assert verify(path, manifest, plan)["project"] == PROJECT
    for mutation, message in (
        (lambda item: item.update(source_commit="b" * 40), "source/run"),
        (lambda item: item.update(run_id="7"), "source/run"),
        (lambda item: item.update(expires_at=(NOW + timedelta(hours=5)).isoformat()),
         "lease"),
    ):
        bad = deepcopy(plan)
        mutation(bad)
        path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ProducerError, match=message):
            verify(path, manifest, plan)
    path.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(ProducerError, match="attestation"):
        verify(path, manifest, plan, attest=lambda *args: False)
    with pytest.raises(ProducerError, match="checkout"):
        verify(path, manifest, plan, checkout=lambda: (SOURCE, True))
    with pytest.raises(ProducerError, match="Official release differs"):
        verify(path, manifest, plan,
               release=lambda *args: {"services_reference": "other"})
    manifest.write_text("changed", encoding="utf-8")
    with pytest.raises(ProducerError, match="manifest differs"):
        verify(path, manifest, plan)


def test_record_assembly_uses_live_ids_then_requires_ownership(
    tmp_path: Path,
) -> None:
    path, _, plan = source_plan(tmp_path)
    containers = {name: format(index + 1, "064x")
                  for index, name in enumerate(sorted(DISPOSABLE_SERVICES))}
    network_id = "e" * 64
    network_name = PROJECT + "_private"
    volume = PROJECT + "_postgres_data"

    def docker(args):
        if args[0] == "ps":
            return "\n".join(containers.values())
        if args[:2] == ["network", "ls"]:
            return network_id
        if args[:2] == ["volume", "ls"]:
            return volume
        if args[:2] == ["container", "inspect"]:
            name = next(name for name, identifier in containers.items()
                        if identifier == args[2])
            return json.dumps([{"Config": {"Labels": {
                "com.docker.compose.service": name,
            }}}])
        if args[:2] == ["network", "inspect"]:
            return json.dumps([{"Name": network_name}])
        raise AssertionError(args)

    observed = []

    def ownership(record, surface, now, runner):
        observed.append((surface, now, runner))
        return {"live_ownership_verified": True, "rollback_accepted": False}

    record = collect_record(path, plan, "987654", tmp_path, NOW, docker,
                            ownership=ownership)
    assert record["containers"] == containers
    assert record["networks"] == {network_name: network_id}
    assert record["volumes"] == [volume]
    assert record["plan_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert record["producer_run_id"] == "987654"
    assert observed[0][:2] == ("base", NOW)
    with pytest.raises(ProducerError, match="ownership proof"):
        collect_record(path, plan, "987654", tmp_path, NOW, docker,
                       ownership=lambda *args: {"live_ownership_verified": False})


def test_disposable_api_key_is_extracted_only_after_live_ownership(
    tmp_path: Path,
) -> None:
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    container = "e" * 64
    record = {"disposable_root": str(tmp_path),
              "containers": {"organization": container}}
    calls = []

    def executor(args: list[str], output: object) -> bool:
        calls.append(args)
        if args[-2:] == ["cat", "/app/data/passport-acceptance-api-key"]:
            output.write(b"mk_test_" + b"a" * 43 + b"\n")
        return True

    def ownership(*args):
        assert calls == []
        return {"live_ownership_verified": True, "rollback_accepted": False}

    key = issue_disposable_api_key(record, "base", NOW,
                                   executor=executor, ownership=ownership)
    assert key == secrets / "passport_acceptance_api_key"
    assert key.read_bytes() == b"mk_test_" + b"a" * 43 + b"\n"
    if os.name == "posix":
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert calls == [
        ["exec", "--user", "10001:10001", container,
         "/usr/local/bin/marty-passport-acceptance-api-key"],
        ["exec", "--user", "10001:10001", container,
         "cat", "/app/data/passport-acceptance-api-key"],
        ["exec", "--user", "10001:10001", container,
         "rm", "-f", "/app/data/passport-acceptance-api-key"],
    ]
    with pytest.raises(ProducerError, match="ownership proof"):
        issue_disposable_api_key(record, "base", NOW, executor=executor,
                                 ownership=lambda *args: {"live_ownership_verified": False})
    assert len(calls) == 3


def test_disposable_api_key_failure_erases_container_copy_and_preserves_existing_file(
    tmp_path: Path,
) -> None:
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    record = {"disposable_root": str(tmp_path),
              "containers": {"organization": "e" * 64}}
    calls = []

    def executor(args: list[str], output: object) -> bool:
        calls.append(args)
        if args[-2:] == ["cat", "/app/data/passport-acceptance-api-key"]:
            output.write(b"invalid-key\n")
        return True

    def ownership(*args):
        return {"live_ownership_verified": True, "rollback_accepted": False}
    with pytest.raises(ProducerError, match="key output is invalid"):
        issue_disposable_api_key(record, "base", NOW,
                                 executor=executor, ownership=ownership,
                                 teardown=lambda *args: True)
    assert calls[-2][-2:] == ["/usr/local/bin/marty-passport-acceptance-api-key",
                            "--revoke-run"]
    assert calls[-1][-3:] == ["rm", "-f", "/app/data/passport-acceptance-api-key"]
    destination = secrets / "passport_acceptance_api_key"
    assert not destination.exists()
    destination.write_text("prior private key", encoding="utf-8")
    with pytest.raises(FileExistsError):
        issue_disposable_api_key(record, "base", NOW,
                                 executor=executor, ownership=ownership,
                                 teardown=lambda *args: True)
    assert destination.read_text(encoding="utf-8") == "prior private key"


def test_failed_issuer_still_erases_possible_container_output(tmp_path: Path) -> None:
    (tmp_path / "secrets").mkdir(mode=0o700)
    record = {"disposable_root": str(tmp_path),
              "containers": {"organization": "e" * 64}}
    calls = []

    def executor(args: list[str], output: object) -> bool:
        calls.append(args)
        return (args[-3:] == ["rm", "-f", "/app/data/passport-acceptance-api-key"]
                or args[-1] == "--revoke-run")

    with pytest.raises(ProducerError, match="issuer failed"):
        issue_disposable_api_key(
            record, "base", NOW, executor=executor,
            teardown=lambda *args: True,
            ownership=lambda *args: {"live_ownership_verified": True,
                                     "rollback_accepted": False})
    assert len(calls) == 3
    assert calls[-2][-1] == "--revoke-run"
    assert calls[-1][-3:] == ["rm", "-f", "/app/data/passport-acceptance-api-key"]
    assert not (tmp_path / "secrets" / "passport_acceptance_api_key").exists()


def test_uncertain_issuer_requires_proven_project_teardown(tmp_path: Path) -> None:
    (tmp_path / "secrets").mkdir(mode=0o700)
    record = {"disposable_root": str(tmp_path),
              "containers": {"organization": "e" * 64}}
    observed = []

    def executor(args: list[str], output: object) -> bool:
        return args[-1] != "/usr/local/bin/marty-passport-acceptance-api-key"

    def teardown(*args) -> bool:
        observed.append(args)
        return False

    with pytest.raises(ProducerError, match="teardown is unverified"):
        issue_disposable_api_key(
            record, "base", NOW, executor=executor, teardown=teardown,
            ownership=lambda *args: {"live_ownership_verified": True,
                                     "rollback_accepted": False})
    assert len(observed) == 1


def test_teardown_targets_only_recorded_disposable_resources() -> None:
    containers = {name: format(index + 1, "064x")
                  for index, name in enumerate(sorted(DISPOSABLE_SERVICES))}
    record = {"project": PROJECT, "containers": containers,
              "networks": {PROJECT + "_private": "e" * 64},
              "volumes": [PROJECT + "_postgres_data"]}
    calls = []

    def executor(args: list[str], output: object) -> bool:
        calls.append(args)
        return True

    def inspector(args: list[str]) -> str:
        return ""

    assert destroy_disposable_project(record, inspector, executor)
    assert calls == [
        ["container", "rm", "-f", *containers.values()],
        ["network", "rm", "e" * 64],
        ["volume", "rm", PROJECT + "_postgres_data"],
    ]
    assert not destroy_disposable_project(
        record, lambda args: "still-present", executor)

    def missing_labels_but_live_volume(args: list[str]) -> str:
        return record["volumes"][0] if args == ["volume", "ls", "-q"] else ""

    assert not destroy_disposable_project(
        record, missing_labels_but_live_volume, executor)


def test_host_key_unlink_failure_still_forces_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "secrets").mkdir(mode=0o700)
    record = {"disposable_root": str(tmp_path),
              "containers": {"organization": "e" * 64}}
    destination = tmp_path / "secrets" / "passport_acceptance_api_key"
    original_unlink = Path.unlink
    torn_down = []

    def fail_unlink(path: Path, *args, **kwargs) -> None:
        if path == destination:
            raise OSError("host unlink failed")
        original_unlink(path, *args, **kwargs)

    def executor(args: list[str], output: object) -> bool:
        if args[-2:] == ["cat", "/app/data/passport-acceptance-api-key"]:
            output.write(b"invalid\n")
        return True

    def teardown(*args) -> bool:
        torn_down.append(True)
        return True

    monkeypatch.setattr(Path, "unlink", fail_unlink)
    with pytest.raises(OSError, match="host unlink failed"):
        issue_disposable_api_key(
            record, "base", NOW, executor=executor, teardown=teardown,
            ownership=lambda *args: {"live_ownership_verified": True,
                                     "rollback_accepted": False})
    assert torn_down == [True]


def test_producer_workflow_is_protected_and_cannot_mutate_docker() -> None:
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows"
                / "passport-supported-provisioning-producer.yml")
    value = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    trigger = value.get("on", value.get(True))
    assert set(trigger) == {"workflow_dispatch"}
    job = value["jobs"]["producer"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "canvas-oss-wsl2"]
    assert job["environment"] == "beta-lifecycle"
    assert value["permissions"] == {"actions": "read", "contents": "read",
                                    "packages": "read"}
    assert job["steps"][0]["with"]["persist-credentials"] is False
    run = job["steps"][1]["run"]
    assert "scripts/passport_supported_provisioning_producer.py" in run
    assert "passport-supported-provisioning-plan-$PLAN_RUN_ID" in run
    assert '.path == ".github/workflows/passport-supported-provisioning-plan.yml"' in run
    assert 'and .head_sha == $sha' in run
    assert "gh run download \"$PLAN_RUN_ID\"" in run
    assert "docker compose" not in run and "docker run" not in run
    syntax = subprocess.run(["bash", "-n"], input=run.encode(),
                            capture_output=True, check=False)
    assert syntax.returncode == 0, syntax.stderr.decode()


@pytest.mark.parametrize("old,new", [
    ("github.ref == 'refs/heads/main'", "github.ref != 'refs/heads/main'"),
    ("beta-lifecycle", "production"),
    ("canvas-oss-wsl2", "ubuntu-latest"),
    ('and .head_sha == $sha', 'and .head_sha != $sha'),
    ('passport-supported-provisioning-plan.yml', 'any-plan.yml'),
    ('scripts/passport_supported_provisioning_producer.py', 'true'),
])
def test_producer_workflow_contract_rejects_unsafe_mutation(old: str, new: str) -> None:
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows"
                / "passport-supported-provisioning-producer.yml")
    source = workflow.read_text(encoding="utf-8")
    assert old in source
    changed = yaml.safe_load(source.replace(old, new))
    job = changed["jobs"]["producer"]
    run = job["steps"][1]["run"]
    with pytest.raises(AssertionError):
        assert job["if"] == "github.ref == 'refs/heads/main'"
        assert job["environment"] == "beta-lifecycle"
        assert job["runs-on"] == ["self-hosted", "linux", "x64", "canvas-oss-wsl2"]
        assert 'and .head_sha == $sha' in run
        assert '.path == ".github/workflows/passport-supported-provisioning-plan.yml"' in run
        assert "scripts/passport_supported_provisioning_producer.py" in run
