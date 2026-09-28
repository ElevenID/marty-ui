"""The producer remains blocked and only accepts exact protected provenance."""

from __future__ import annotations

from copy import deepcopy
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import uuid

import pytest
import yaml

from scripts import passport_supported_provisioning_producer as producer
from scripts.check_passport_supported_rollback_model import (
    DISPOSABLE_SERVICES, render_model, validate_planned_model,
)
from scripts.passport_supported_infra_images import qualified_images
from scripts.passport_supported_provisioning_producer import (
    ProducerError, WORKFLOW_REF, collect_record, destroy_disposable_project,
    destroy_partial_disposable_project,
    issue_disposable_api_key, stage_disposable_inputs,
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


def partial_teardown_context(tmp_path: Path) -> tuple[tuple, dict, dict]:
    path, manifest, plan = source_plan(tmp_path)
    official = {key: plan[key] for key in (
        "source_commit", "stack_manifest_sha256", "services_reference",
        "migrations_reference", "legacy_reference", "infra_images",
    )}
    gates = {"now": NOW, "attest": lambda *args: True,
             "release": lambda *args: official,
             "checkout": lambda: (SOURCE, False)}
    return (path, manifest, "123456", ENV), plan, gates


def input_plan() -> dict:
    project = "marty-passport-acceptance-base-" + uuid.uuid4().hex[:12]
    return {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": "base", "project": project,
        "run_id": "123456", "source_commit": SOURCE,
        "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=55)).isoformat(),
        "services_reference": SERVICES,
        "migrations_reference": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "c" * 64,
        "legacy_reference": "ghcr.io/elevenid/marty-credentials/issuance@sha256:" + "d" * 64,
        "infra_images": qualified_images(verify_registry=False),
        "owner_labels": LABELS,
    }


def test_disposable_inputs_are_fresh_private_and_plan_bound() -> None:
    plan = input_plan()
    project = plan["project"]
    root = Path(tempfile.gettempdir()) / project
    try:
        actual_root, env_file = stage_disposable_inputs(plan, 29876, now=NOW)
        assert actual_root == root
        assert env_file == root / "acceptance.env"
        secret_dir = root / "secrets"
        names = {item.name for item in secret_dir.iterdir()}
        assert names == {
            "bao_root_token", "marty_db_password", "signing_keys_internal_api_key",
            "dsc_issue_gateway_key", "csca_issue_gateway_key",
            "issuance_api_key", "callback_signer_api_key", "grpc_service_token",
            "bureau_database_url", "token_hmac_key", "integration_secret_master_key",
        }
        assert len((secret_dir / "bao_root_token").read_text(encoding="ascii")) == 64
        ceremony_keys = [(secret_dir / name).read_text(encoding="ascii") for name in (
            "dsc_issue_gateway_key", "csca_issue_gateway_key")]
        assert all(len(key) == 64 for key in ceremony_keys)
        assert len(set(ceremony_keys + [
            (secret_dir / "signing_keys_internal_api_key").read_text(encoding="ascii")])) == 3
        password = (secret_dir / "marty_db_password").read_text(encoding="ascii")
        assert (secret_dir / "bureau_database_url").read_text(encoding="ascii") == (
            f"postgresql://marty:{password}@postgres:5432/marty"
        )
        assert len(base64.b64decode(
            (secret_dir / "integration_secret_master_key").read_text(encoding="ascii"),
            validate=True,
        )) == 32
        env = dict(line.split("=", 1) for line in env_file.read_text(
            encoding="ascii").splitlines())
        assert env["PASSPORT_ACCEPTANCE_PROJECT"] == project
        assert env["PASSPORT_ACCEPTANCE_GATEWAY_PORT"] == "29876"
        assert env["PASSPORT_ACCEPTANCE_EXPIRES_AT"] == plan["expires_at"]
        assert env["PASSPORT_ACCEPTANCE_SECRET_DIR"] == secret_dir.as_posix()
        assert env["PASSPORT_ACCEPTANCE_DATABASE_URL"] == (
            f"postgresql+asyncpg://marty:{password}@postgres:5432/marty"
        )
        assert env["MARTY_SERVICES_IMAGE"] == SERVICES
        if os.name == "posix":
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
            assert stat.S_IMODE(secret_dir.stat().st_mode) == 0o700
            assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
            assert stat.S_IMODE((secret_dir / "bao_root_token").stat().st_mode) == 0o600
            assert all(stat.S_IMODE(path.stat().st_mode) == 0o644
                       for path in secret_dir.iterdir()
                       if path.name != "bao_root_token")
        with pytest.raises(FileExistsError):
            stage_disposable_inputs(plan, 29876, now=NOW)
    finally:
        secret_dir = root / "secrets"
        if secret_dir.is_dir():
            for item in secret_dir.iterdir():
                item.unlink()
            secret_dir.rmdir()
        (root / "acceptance.env").unlink(missing_ok=True)
        if root.is_dir():
            root.rmdir()


def test_disposable_input_guard_rejects_unbound_project_and_images() -> None:
    plan = input_plan()
    plan["project"] = "marty-selfhost-prod"
    with pytest.raises(ProducerError, match="project"):
        stage_disposable_inputs(plan, 29876)
    plan["project"] = "marty-passport-acceptance-base-" + uuid.uuid4().hex[:12]
    with pytest.raises(ProducerError, match="Gateway port"):
        stage_disposable_inputs(plan, 80)
    assert not (Path(tempfile.gettempdir()) / plan["project"]).exists()


def test_disposable_secret_bind_mount_is_readable_by_nonroot_only_when_mounted() -> None:
    if os.name != "posix" or shutil.which("docker") is None:
        pytest.skip("Linux Docker bind-mount permission check")
    image = qualified_images(verify_registry=False)["openbao"]
    plan = input_plan()
    root, _ = stage_disposable_inputs(plan, 29876, now=NOW)
    try:
        secret = root / "secrets" / "marty_db_password"
        root_token = root / "secrets" / "bao_root_token"
        commands = (
            (["--mount", f"type=bind,src={secret},dst=/tmp/marty_db_password,readonly"],
             "test -r /tmp/marty_db_password"),
            (["--mount", f"type=bind,src={root_token},dst=/tmp/bao_root_token,readonly"],
             "test ! -r /tmp/bao_root_token"),
            (["--mount", f"type=bind,src={root},dst=/private,readonly"],
             "test ! -r /private/secrets/marty_db_password"),
        )
        for mounts, check in commands:
            result = subprocess.run(
                ["docker", "run", "--rm", "--user", "10001:10001",
                 "--entrypoint", "/bin/sh", *mounts, image, "-c", check],
                capture_output=True, text=True, check=False, timeout=120,
            )
            assert result.returncode == 0, check
    finally:
        producer._remove_staged_inputs(root)


def test_disposable_input_write_failure_erases_only_its_new_root(monkeypatch) -> None:
    plan = input_plan()
    root = Path(tempfile.gettempdir()) / plan["project"]
    actual_write = producer._write_private
    writes = 0

    def fail_after_open(path: Path, value: bytes, *, mode: int = 0o600) -> None:
        nonlocal writes
        writes += 1
        if writes == 4:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            raise OSError("synthetic partial secret write")
        actual_write(path, value, mode=mode)

    monkeypatch.setattr(producer, "_write_private", fail_after_open)
    with pytest.raises(OSError, match="synthetic partial secret write"):
        stage_disposable_inputs(plan, 29876, now=NOW)
    assert not root.exists()


def test_staged_input_cleanup_includes_post_bootstrap_secrets() -> None:
    plan = input_plan()
    root, _ = stage_disposable_inputs(plan, 29876, now=NOW)
    for name in ("bao_token", "callback_signer_bao_token",
                 "passport_acceptance_api_key"):
        (root / "secrets" / name).write_text("disposable", encoding="ascii")
    for name in (".bao_token.Abc123", ".callback_signer_bao_token.Xyz789"):
        (root / "secrets" / name).write_text("partial-token", encoding="ascii")
    producer._remove_staged_inputs(root)
    assert not root.exists()


def test_disposable_inputs_reject_surface_and_label_mismatch_before_creation() -> None:
    plan = input_plan()
    root = Path(tempfile.gettempdir()) / plan["project"]
    plan["surface"] = "selfhost"
    with pytest.raises(ProducerError, match="project"):
        stage_disposable_inputs(plan, 29876, now=NOW)
    plan["surface"] = "base"
    plan["owner_labels"] = {**LABELS, "com.marty.passport.acceptance.run-id": "other"}
    with pytest.raises(ProducerError, match="owner labels"):
        stage_disposable_inputs(plan, 29876, now=NOW)
    assert not root.exists()


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI unavailable")
def test_staged_inputs_render_the_exact_disposable_compose_plan() -> None:
    plan = input_plan()
    root = Path(tempfile.gettempdir()) / plan["project"]
    try:
        _, env_file = stage_disposable_inputs(plan, 29876, now=NOW)
        model = render_model(
            "base", plan["project"], env_file, root, plan["services_reference"],
            owner_labels=plan["owner_labels"], plan_expires_at=plan["expires_at"],
        )
        assert validate_planned_model(model, plan, root)["model_safe"] is True
    finally:
        secret_dir = root / "secrets"
        if secret_dir.is_dir():
            for item in secret_dir.iterdir():
                item.unlink()
            secret_dir.rmdir()
        (root / "acceptance.env").unlink(missing_ok=True)
        if root.is_dir():
            root.rmdir()


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
    record = {"schema": "marty.passport-supported-compose-ownership/v1",
              "project": PROJECT, "run_id": "123456", "source_commit": "a" * 40,
              "services_reference": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64,
              "containers": containers,
              "networks": {PROJECT + "_private": "e" * 64},
              "volumes": [PROJECT + "_postgres_data"]}
    calls = []
    labels = {
        "com.docker.compose.project": PROJECT,
        "com.marty.passport.acceptance.owner": "supported-consumer",
        "com.marty.passport.acceptance.run-id": record["run_id"],
        "com.marty.passport.acceptance.source-commit": record["source_commit"],
        "com.marty.passport.acceptance.services-image": record["services_reference"],
    }

    def executor(args: list[str], output: object) -> bool:
        calls.append(args)
        return True

    def inspector(args: list[str]) -> str:
        if args[:2] == ["container", "inspect"]:
            service = next(name for name, identifier in containers.items()
                           if identifier == args[2])
            return json.dumps([{"Id": args[2], "Config": {"Labels": {
                **labels, "com.docker.compose.service": service}}}])
        if args[:2] == ["network", "inspect"]:
            return json.dumps([{"Id": args[2], "Name": PROJECT + "_private",
                                "Labels": labels}])
        if args[:2] == ["volume", "inspect"]:
            return json.dumps([{"Name": args[2], "Labels": labels}])
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

    stale_calls = []
    def stale_inspector(args: list[str]) -> str:
        response = inspector(args)
        if args[:2] == ["container", "inspect"]:
            item = json.loads(response)
            item[0]["Config"]["Labels"]["com.docker.compose.project"] = "other-project"
            return json.dumps(item)
        return response

    assert not destroy_disposable_project(
        record, stale_inspector,
        lambda args, output: stale_calls.append(args) or True)
    assert not stale_calls


def test_partial_teardown_removes_only_plan_owned_startup_resources(
    tmp_path: Path,
) -> None:
    arguments, plan, gates = partial_teardown_context(tmp_path)
    project = plan["project"]
    container = "1" * 64
    network = "2" * 64
    volume = project + "_openbao_data"
    present = {"containers": [container], "networks": [network],
               "volumes": [volume]}
    labels = {**plan["owner_labels"], "com.docker.compose.project": project}
    calls = []

    def inspector(args: list[str]) -> str:
        if args[:2] == ["container", "inspect"]:
            return json.dumps([{"Id": args[2], "Config": {"Labels": {
                **labels, "com.docker.compose.service": "openbao"}}}])
        if args[:2] == ["network", "inspect"]:
            return json.dumps([{"Id": args[2], "Name": project + "_private",
                                "Labels": labels}])
        if args[:2] == ["volume", "inspect"]:
            return json.dumps([{"Name": args[2], "Labels": labels}])
        if args[0] == "ps":
            return "\n".join(present["containers"])
        if args[:2] == ["network", "ls"]:
            return "\n".join(present["networks"])
        if args[:2] == ["volume", "ls"]:
            return "\n".join(present["volumes"])
        raise AssertionError(args)

    def executor(args: list[str], output: object) -> bool:
        calls.append(args)
        if args[:2] == ["container", "rm"]:
            present["containers"].clear()
        elif args[:2] == ["network", "rm"]:
            present["networks"].clear()
        elif args[:2] == ["volume", "rm"]:
            present["volumes"].clear()
        return True

    assert destroy_partial_disposable_project(
        *arguments, inspector, executor, **gates)
    assert calls == [
        ["container", "rm", "-f", container],
        ["network", "rm", network],
        ["volume", "rm", volume],
    ]
    assert destroy_partial_disposable_project(
        *arguments, inspector, executor, **gates)
    assert len(calls) == 3


def test_partial_teardown_fails_closed_before_mutating_unknown_resource(
    tmp_path: Path,
) -> None:
    arguments, plan, gates = partial_teardown_context(tmp_path)
    project = plan["project"]
    container = "1" * 64
    labels = {**plan["owner_labels"], "com.docker.compose.project": project}
    calls = []

    def inspector(args: list[str]) -> str:
        if args[0] == "ps":
            return container
        if args[:2] == ["container", "inspect"]:
            return json.dumps([{"Id": container, "Config": {"Labels": {
                **labels, "com.docker.compose.service": "unrelated-service"}}}])
        return ""

    assert not destroy_partial_disposable_project(
        *arguments, inspector,
        lambda args, output: calls.append(args) or True, **gates)
    assert calls == []
    with pytest.raises(ProducerError, match="attestation"):
        destroy_partial_disposable_project(
            *arguments, inspector, attest=lambda *args: False,
            release=gates["release"], checkout=gates["checkout"], now=NOW)
    with pytest.raises(ProducerError, match="lease"):
        destroy_partial_disposable_project(
            *arguments, inspector, **{**gates, "now": NOW + timedelta(hours=2)})
    assert calls == []
    bad = {**plan, "project": "marty-prod"}
    arguments[0].write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ProducerError, match="plan is invalid"):
        destroy_partial_disposable_project(*arguments, inspector, **gates)


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
