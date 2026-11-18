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
import probe_selfhost_installed_signing_keys as probe
from qualify_selfhost_migrations import VERIFY_ONLY_CATALOG_QUERY

IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "e" * 64
IMAGES = {
    "migrations": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "a" * 64,
    "services": IMAGE,
    "postgres": "docker.io/library/postgres@sha256:" + "b" * 64,
    "redis": "docker.io/library/redis@sha256:" + "c" * 64,
    "openbao": "quay.io/openbao/openbao@sha256:" + "d" * 64,
}
PROJECT = "marty-selfhost-scoped-migrate-" + "1" * 16


def test_signing_image_comes_only_from_verified_lock(tmp_path):
    lock = tmp_path / "lock.json"
    roles = {"signing-keys": IMAGE}
    lock.write_text(json.dumps({"services": roles}), encoding="utf-8")
    assert probe.locked_services_image(lock, {"images": roles}) == IMAGE
    with pytest.raises(probe.migrations.QualificationError):
        probe.locked_services_image(lock, {"images": {}})
    roles["signing-keys"] = "ghcr.io/other/services@sha256:" + "e" * 64
    lock.write_text(json.dumps({"services": roles}), encoding="utf-8")
    with pytest.raises(probe.migrations.QualificationError):
        probe.locked_services_image(lock, {"images": roles})


@pytest.mark.parametrize("arch,digests", [
    ("amd64", [IMAGE]),
    ("arm64", [IMAGE]),
    ("amd64", ["ghcr.io/other/services@sha256:" + "e" * 64]),
])
def test_selected_local_image_requires_platform_and_digest(arch, digests):
    def run(args, **kwargs):
        assert kwargs == {"check": True, "capture_output": True, "text": True}
        output = "" if args[1] == "pull" else json.dumps({
            "Os": "linux", "Architecture": arch, "RepoDigests": digests})
        return subprocess.CompletedProcess(args, 0, output, "")

    if arch == "amd64" and digests == [IMAGE]:
        probe.verify_local_image(IMAGE, run)
    else:
        with pytest.raises(probe.migrations.QualificationError):
            probe.verify_local_image(IMAGE, run)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Compose CLI unavailable")
def test_exact_runtime_render_has_no_host_ports_or_root_secret(tmp_path):
    install = tmp_path / "bundle"
    (install / "docker").mkdir(parents=True)
    (install / "docker/openbao-init.sh").write_text("fixture", encoding="utf-8")
    environment = {**os.environ,
        "PROBE_MIGRATIONS_IMAGE": IMAGES["migrations"],
        "PROBE_POSTGRES_IMAGE": IMAGES["postgres"],
        "PROBE_REDIS_IMAGE": IMAGES["redis"],
        "PROBE_OPENBAO_IMAGE": IMAGES["openbao"],
        "PROBE_RUN_USER": probe.migrations.host_user(),
        "PROBE_SERVICES_IMAGE": IMAGE,
        "PROBE_SECRET_DIR": str(tmp_path),
        "PROBE_OPENBAO_START": str(probe.migrations.START.resolve()),
        "PROBE_OPENBAO_BOOTSTRAP": str(probe.migrations.BOOTSTRAP.resolve()),
        "PROBE_OPENBAO_INIT": str((install / "docker/openbao-init.sh").resolve()),
        "COMPOSE_PROFILES": "",
    }
    command = ["docker", "compose", "--project-name", PROJECT,
               "-f", str(probe.migrations.COMPOSE), "-f", str(probe.COMPOSE),
               "config", "--format", "json"]
    rendered = subprocess.run(command, env=environment, check=True,
                              capture_output=True, text=True)
    model = json.loads(rendered.stdout)
    probe.validate_model(model, IMAGES, IMAGE, tmp_path, install, PROJECT)
    assert not any(service.get("ports") or service.get("build")
                   for service in model["services"].values())
    assert "bao_root_token" not in str(model["services"]["signing-keys"])
    for mutate in (
        lambda item: item["services"]["signing-keys"].update(ports=["8017:8017"]),
        lambda item: item["services"]["signing-keys"]["secrets"].append(
            {"source": "bao_root_token", "target": "/run/secrets/bao_root_token"}),
        lambda item: item["services"]["signing-keys"].update(platform="linux/arm64"),
        lambda item: item["services"]["signing-keys"].update(build={"context": "."}),
        lambda item: item["networks"]["private"].update(internal=False),
    ):
        changed = deepcopy(model)
        mutate(changed)
        with pytest.raises(probe.migrations.QualificationError):
            probe.validate_model(changed, IMAGES, IMAGE, tmp_path, install, PROJECT)


def test_jwks_requires_seeded_public_keys_and_other_tenant_empty():
    tenant = probe.expected_kids(probe.ORG_ID)
    es256 = next(kid for kid in tenant if kid.endswith("-es256"))
    eddsa = next(kid for kid in tenant if kid.endswith("-eddsa"))
    valid = {"organization_id": probe.ORG_ID,
             "keys": [{"kid": es256, "kty": "EC", "x": "public"},
                      {"kid": eddsa, "kty": "OKP", "x": "public"}]}
    assert probe.validate_jwks(json.dumps(valid), organization_id=probe.ORG_ID,
                               present=True) == 2
    empty = {"organization_id": probe.OTHER_ORG, "keys": []}
    assert probe.validate_jwks(json.dumps(empty), organization_id=probe.OTHER_ORG,
                               present=False) == 0
    for changed in (
        {"organization_id": probe.ORG_ID, "keys": []},
        {"organization_id": probe.OTHER_ORG, "keys": valid["keys"]},
        {"organization_id": probe.ORG_ID,
         "keys": [{**valid["keys"][0], "d": "private"}]},
        {"organization_id": probe.ORG_ID,
         "keys": [{"kid": "unrelated", "kty": "OKP"}]},
        {"organization_id": probe.ORG_ID,
         "keys": [{"kid": "cred-issuer-marty-es256", "kty": "EC"},
                  {"kid": "cred-issuer-marty-eddsa", "kty": "OKP"}]},
    ):
        with pytest.raises(probe.migrations.QualificationError):
            probe.validate_jwks(json.dumps(changed),
                                organization_id=changed["organization_id"],
                                present=changed["organization_id"] == probe.ORG_ID)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Compose CLI unavailable")
def test_runtime_uses_private_service_and_tears_down_after_business_read(tmp_path, monkeypatch):
    install = tmp_path / "bundle"
    (install / "docker").mkdir(parents=True)
    (install / "docker/openbao-init.sh").write_text("fixture", encoding="utf-8")
    (tmp_path / "bao_service_token").write_text("scoped-openbao-token", encoding="ascii")
    (tmp_path / "sign_grant_verify_token").write_text("scoped-verify-token", encoding="ascii")
    (tmp_path / "signing_keys_openbao_token").write_text("scoped-signing-token", encoding="ascii")
    monkeypatch.setattr(probe, "verify_local_image", lambda image: None)
    environment = {**os.environ,
        "PROBE_MIGRATIONS_IMAGE": IMAGES["migrations"],
        "PROBE_POSTGRES_IMAGE": IMAGES["postgres"],
        "PROBE_REDIS_IMAGE": IMAGES["redis"],
        "PROBE_OPENBAO_IMAGE": IMAGES["openbao"],
        "PROBE_RUN_USER": probe.migrations.host_user(),
        "PROBE_SECRET_DIR": str(tmp_path),
        "PROBE_OPENBAO_START": str(probe.migrations.START.resolve()),
        "PROBE_OPENBAO_BOOTSTRAP": str(probe.migrations.BOOTSTRAP.resolve()),
        "PROBE_OPENBAO_INIT": str((install / "docker/openbao-init.sh").resolve()),
        "COMPOSE_PROFILES": "",
    }
    compose = ["docker", "compose", "--project-name", PROJECT,
               "-f", str(probe.migrations.COMPOSE)]
    calls = []

    def run(args, env, timeout=90):
        calls.append(args)
        if args[-3:] == ["config", "--format", "json"]:
            return subprocess.run(args, env=env, check=False,
                                  capture_output=True, text=True)
        if args[-1].endswith(probe.ORG_ID):
            output = json.dumps({"organization_id": probe.ORG_ID,
                                 "keys": [{"kid": next(kid for kid in probe.expected_kids(probe.ORG_ID) if kid.endswith("-es256")), "kty": "EC"},
                                          {"kid": next(kid for kid in probe.expected_kids(probe.ORG_ID) if kid.endswith("-eddsa")), "kty": "OKP"}]})
        elif args[-1].endswith(probe.OTHER_ORG):
            output = json.dumps({"organization_id": probe.OTHER_ORG, "keys": []})
        else:
            output = ""
        return subprocess.CompletedProcess(args, 0, output, "")

    result = probe.run_signing_runtime(compose, environment, tmp_path, run,
                                       images=IMAGES, image=IMAGE, install_root=install)
    assert result["qualification"] == "unqualified"
    assert result["public_jwk_count"] == 2
    assert any("up" in args and "--no-deps" in args and "--pull" in args
               and "never" in args for args in calls)
    assert any(args[-2:] == ["down", "--volumes"] for args in calls)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Compose CLI unavailable")
def test_failed_runtime_read_still_tears_down(tmp_path, monkeypatch):
    install = tmp_path / "bundle"
    (install / "docker").mkdir(parents=True)
    (install / "docker/openbao-init.sh").write_text("fixture", encoding="utf-8")
    (tmp_path / "bao_service_token").write_text("scoped-openbao-token", encoding="ascii")
    (tmp_path / "sign_grant_verify_token").write_text("scoped-verify-token", encoding="ascii")
    (tmp_path / "signing_keys_openbao_token").write_text("scoped-signing-token", encoding="ascii")
    monkeypatch.setattr(probe, "verify_local_image", lambda image: None)
    environment = {**os.environ,
        "PROBE_MIGRATIONS_IMAGE": IMAGES["migrations"],
        "PROBE_POSTGRES_IMAGE": IMAGES["postgres"],
        "PROBE_REDIS_IMAGE": IMAGES["redis"],
        "PROBE_SECRET_DIR": str(tmp_path),
        "PROBE_OPENBAO_IMAGE": IMAGES["openbao"],
        "PROBE_RUN_USER": probe.migrations.host_user(),
        "PROBE_OPENBAO_START": str(probe.migrations.START.resolve()),
        "PROBE_OPENBAO_BOOTSTRAP": str(probe.migrations.BOOTSTRAP.resolve()),
        "PROBE_OPENBAO_INIT": str((install / "docker/openbao-init.sh").resolve()),
        "COMPOSE_PROFILES": "",
    }
    compose = ["docker", "compose", "--project-name", PROJECT,
               "-f", str(probe.migrations.COMPOSE)]
    calls = []

    def run(args, env, timeout=90):
        calls.append(args)
        if args[-3:] == ["config", "--format", "json"]:
            return subprocess.run(args, env=env, check=False,
                                  capture_output=True, text=True)
        return subprocess.CompletedProcess(args, 0, json.dumps({
            "organization_id": probe.ORG_ID, "keys": []}), "")

    with pytest.raises(probe.migrations.QualificationError):
        probe.run_signing_runtime(compose, environment, tmp_path, run,
                                  images=IMAGES, image=IMAGE, install_root=install)
    assert calls[-1][-2:] == ["down", "--volumes"]


def test_runtime_hook_runs_after_two_migrations_and_retains_unqualified(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.migrations, "validate_scoped_model", lambda *args: None)
    monkeypatch.setattr(probe.migrations, "verify_local_platforms", lambda images: None)
    calls = []
    completed = '{"level":"INFO","message":"notification schema migrated"}\n'

    def run(args, environment, timeout=90):
        calls.append(args)
        if args[-1] == VERIFY_ONLY_CATALOG_QUERY:
            return subprocess.CompletedProcess(args, 0, "0\n", "")
        if args[-1] == "--verify-only":
            return subprocess.CompletedProcess(args, 1 if "--env" in args else 0,
                                               "", "")
        if args[-1] == "openbao-bootstrap":
            secret_dir = Path(environment["PROBE_SECRET_DIR"])
            (secret_dir / "bao_service_token").write_text("scoped-service")
            (secret_dir / "bao_bootstrap_token").write_text("scoped-bootstrap")
            (secret_dir / "notification_openbao_token").write_text("scoped-notification")
            (secret_dir / "sign_grant_verify_token").write_text("scoped-verifier")
            (secret_dir / "signing_keys_openbao_token").write_text("scoped-signing-keys")
        output = ("{}" if args[-3:] == ["config", "--format", "json"] else
                  completed if args[-1] == "db-migrate" else
                  "20260808_0002" if args[-1] == probe.migrations.HEAD else
                  "" if args[-1] in (probe.migrations.PRIVATE_KEY_SCHEMA_QUERY,
                                      probe.migrations.PRIVATE_KEY_CONTENT_QUERY) else
                  "1" if "redis-cli" in args else "")
        return subprocess.CompletedProcess(args, 0, output, "")

    def after_migrations(compose, environment, secret_dir, callback_run):
        assert sum(args[-1] == "db-migrate" for args in calls) == 2
        assert (secret_dir / "bao_service_token").is_file()
        assert callback_run is run
        return {"qualification": "unqualified", "service": "signing-keys"}

    report = probe.migrations.probe(
        IMAGES, {"archive_sha256": "a", "image_lock_sha256": "b"}, tmp_path,
        run=run, project=PROJECT, after_migrations=after_migrations)
    assert report["qualification"] == "unqualified"
    assert report["runtime"]["service"] == "signing-keys"
    assert sum(args[-1] == probe.migrations.PRIVATE_KEY_SCHEMA_QUERY for args in calls) == 2
    assert sum(args[-1] == probe.migrations.PRIVATE_KEY_CONTENT_QUERY for args in calls) == 2
    assert any(args[-2:] == ["down", "--volumes"] for args in calls)
