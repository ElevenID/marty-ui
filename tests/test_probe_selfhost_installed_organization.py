from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_selfhost_installed_organization as probe

IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "e" * 64
IMAGES = {
    "migrations": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "a" * 64,
    "postgres": "docker.io/library/postgres@sha256:" + "b" * 64,
    "redis": "docker.io/library/redis@sha256:" + "c" * 64,
    "openbao": "quay.io/openbao/openbao@sha256:" + "d" * 64,
}
PROJECT = "marty-selfhost-scoped-migrate-" + "1" * 16


def test_consumer_keeps_organization_after_prepared_provenance_and_signing():
    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/selfhost-prepared-consumer.yml"
    ).read_text(encoding="utf-8")
    assert (
        workflow.index("Bind the successful first-attempt producer")
        < workflow.index("Verify the exact unqualified archive")
        < workflow.index("Probe scoped migrations and signing runtime")
        < workflow.index("Probe scoped Organization runtime")
    )
    assert "selfhost-installed-organization.json" in workflow
    assert 'qualification == "unqualified"' in workflow


def fixture(tmp_path: Path) -> tuple[Path, dict[str, str], list[str]]:
    install = tmp_path / "bundle"
    (install / "docker").mkdir(parents=True)
    (install / "docker/openbao-init.sh").write_text("fixture", encoding="utf-8")
    for name in (
        "marty_db_password",
        "bao_root_token",
        "bao_service_token",
        "notification_openbao_token",
    ):
        (tmp_path / name).write_text(name + "-value", encoding="ascii")
    environment = {
        **os.environ,
        "PROBE_MIGRATIONS_IMAGE": IMAGES["migrations"],
        "PROBE_POSTGRES_IMAGE": IMAGES["postgres"],
        "PROBE_REDIS_IMAGE": IMAGES["redis"],
        "PROBE_OPENBAO_IMAGE": IMAGES["openbao"],
        "PROBE_SERVICES_IMAGE": IMAGE,
        "PROBE_SECRET_DIR": str(tmp_path),
        "PROBE_OPENBAO_START": str(probe.migrations.START.resolve()),
        "PROBE_OPENBAO_BOOTSTRAP": str(probe.migrations.BOOTSTRAP.resolve()),
        "PROBE_OPENBAO_INIT": str((install / "docker/openbao-init.sh").resolve()),
        "COMPOSE_PROFILES": "",
    }
    compose = [
        "docker",
        "compose",
        "--project-name",
        PROJECT,
        "-f",
        str(probe.migrations.COMPOSE),
        "-f",
        str(probe.COMPOSE),
    ]
    return install, environment, compose


def test_organization_image_comes_only_from_verified_lock(tmp_path):
    lock = tmp_path / "lock.json"
    roles = {"organization": IMAGE}
    lock.write_text(json.dumps({"services": roles}), encoding="utf-8")
    assert probe.locked_services_image(lock, {"images": roles}) == IMAGE
    with pytest.raises(probe.migrations.QualificationError):
        probe.locked_services_image(lock, {"images": {}})
    roles["organization"] = "ghcr.io/other/services@sha256:" + "e" * 64
    lock.write_text(json.dumps({"services": roles}), encoding="utf-8")
    with pytest.raises(probe.migrations.QualificationError):
        probe.locked_services_image(lock, {"images": roles})


@pytest.mark.skipif(shutil.which("docker") is None, reason="Compose CLI unavailable")
def test_exact_render_and_boundary_mutations(tmp_path):
    install, environment, compose = fixture(tmp_path)
    result = subprocess.run(
        [*compose, "config", "--format", "json"],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    model = json.loads(result.stdout)
    probe.validate_model(model, IMAGES, IMAGE, tmp_path, install, PROJECT)
    assert not any(
        service.get("ports") or service.get("build")
        for service in model["services"].values()
    )
    assert "bao_root_token" not in str(model["services"]["organization"])
    for mutate in (
        lambda item: item["services"]["organization"].update(ports=["8002:8002"]),
        lambda item: item["services"]["organization"].update(platform="linux/arm64"),
        lambda item: item["services"]["organization"]["secrets"].append(
            {"source": "bao_root_token", "target": "/run/secrets/bao_root_token"}
        ),
        lambda item: item["services"]["organization"]["environment"].update(
            DATABASE_URL_TEMPLATE="postgresql://marty:password@postgres:5432/marty"
        ),
        lambda item: item["services"]["organization"].update(
            entrypoint=["/bin/sh", "replacement"]
        ),
        lambda item: item["networks"]["private"].update(internal=False),
    ):
        changed = deepcopy(model)
        mutate(changed)
        with pytest.raises(probe.migrations.QualificationError):
            probe.validate_model(changed, IMAGES, IMAGE, tmp_path, install, PROJECT)


def test_business_read_requires_seed_and_denied_tokens():
    body = json.dumps([{"id": probe.ORG_ID, "name": "Marty", "status": "active"}])
    assert probe.validate_read(body + "\n200", 200) == 1
    assert probe.validate_read('{"detail":"unauthorized"}\n401', 401) == 0
    for raw, status in (
        ("[]\n200", 200),
        (body + "\n401", 200),
        (body + "\n200", 401),
        ("not-json\n200", 200),
    ):
        with pytest.raises(probe.migrations.QualificationError):
            probe.validate_read(raw, status)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Compose CLI unavailable")
@pytest.mark.parametrize("failure", [None, "read", "start"])
def test_runtime_reads_then_tears_down_even_on_failure(tmp_path, monkeypatch, failure):
    install, environment, compose = fixture(tmp_path)
    monkeypatch.setattr(probe.signing, "verify_local_image", lambda image: None)
    calls = []

    def run(args, env, timeout=90):
        calls.append(args)
        if args[-3:] == ["config", "--format", "json"]:
            return subprocess.run(args, env=env, capture_output=True, text=True)
        if failure == "start" and "up" in args:
            return subprocess.CompletedProcess(args, 1, "", "synthetic startup failure")
        if "exec" in args:
            script = args[-1]
            status = 401 if "wrong-token" in script or "--header" not in script else 200
            body = (
                "[]"
                if failure == "read"
                else json.dumps(
                    [{"id": probe.ORG_ID, "name": "Marty", "status": "active"}]
                )
            )
            return subprocess.CompletedProcess(args, 0, body + f"\n{status}", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def invoke():
        return probe.run_organization_runtime(
            compose[:6],
            environment,
            tmp_path,
            run,
            images=IMAGES,
            image=IMAGE,
            install_root=install,
        )

    if failure:
        with pytest.raises(probe.migrations.QualificationError):
            invoke()
    else:
        report = invoke()
        assert report["qualification"] == "unqualified"
        assert report["organization_count"] == 1
        assert report["missing_token_status"] == report["wrong_token_status"] == 401
    assert any("up" in args and "--no-deps" in args for args in calls)
    assert calls[-1][-2:] == ["down", "--volumes"]


def test_runtime_hook_after_two_migrations_remains_unqualified(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.migrations, "validate_scoped_model", lambda *args: None)
    monkeypatch.setattr(probe.migrations, "verify_local_platforms", lambda images: None)
    calls = []
    completed = (
        "Profile: selfhost-production (persistent=True)\n"
        "Marty KMS identity: ready\n"
        "Ensured non-exportable notification webhook envelope key\n"
        "All migrations completed successfully\n"
        "notification schema migrated\n"
    )

    def run(args, environment, timeout=90):
        calls.append(args)
        if args[-1] == "openbao-bootstrap":
            secret_dir = Path(environment["PROBE_SECRET_DIR"])
            (secret_dir / "bao_service_token").write_text("scoped-service")
            (secret_dir / "notification_openbao_token").write_text(
                "scoped-notification"
            )
        output = (
            "{}"
            if args[-3:] == ["config", "--format", "json"]
            else completed
            if args[-1] == "db-migrate"
            else "20260808_0002"
            if "psql" in args
            else "1"
            if "redis-cli" in args
            else ""
        )
        return subprocess.CompletedProcess(args, 0, output, "")

    def after_migrations(compose, environment, secret_dir, callback_run):
        assert sum(args[-1] == "db-migrate" for args in calls) == 2
        assert callback_run is run
        assert (secret_dir / "bao_service_token").is_file()
        return {"qualification": "unqualified", "service": "organization"}

    report = probe.migrations.probe(
        IMAGES,
        {"archive_sha256": "a", "image_lock_sha256": "b"},
        tmp_path,
        run=run,
        project=PROJECT,
        after_migrations=after_migrations,
    )
    assert report["runtime"]["service"] == "organization"
    assert report["qualification"] == "unqualified"
    assert any(args[-2:] == ["down", "--volumes"] for args in calls)
