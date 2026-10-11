"""Fail-closed checks for the local-only scoped migration fixture."""

from copy import deepcopy
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_selfhost_installed_migrations as probe  # noqa: E402


IMAGES = {
    "migrations": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "a" * 64,
    "services": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "e" * 64,
    "postgres": "docker.io/library/postgres@sha256:" + "b" * 64,
    "redis": "docker.io/library/redis@sha256:" + "c" * 64,
    "openbao": "quay.io/openbao/openbao@sha256:" + "d" * 64,
}
PROJECT = "marty-selfhost-scoped-migrate-" + "1" * 16


def test_openbao_pin_has_explicit_scope_and_platform(tmp_path):
    policy = json.loads(probe.PIN.read_text(encoding="utf-8"))
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    index = {"manifests": [{"digest": "sha256:" + "0" * 64,
                            "platform": {"os": "linux", "architecture": "amd64"},
                            "annotations": {
                                "org.opencontainers.image.version": "2.5.2",
                                "org.opencontainers.image.revision":
                                    policy["source_revision"]}}]}
    assert probe.reviewed_openbao(path, lambda _: index) == probe.EXPECTED_PIN
    for mutation in (
        lambda item: item.update(scope="disposable-passport-acceptance-only"),
        lambda item: item.update(reference="quay.io/openbao/openbao:2"),
    ):
        changed = dict(policy)
        mutation(changed)
        path.write_text(json.dumps(changed), encoding="utf-8")
        with pytest.raises(probe.QualificationError):
            probe.reviewed_openbao(path, lambda _: index)
    path.write_text(json.dumps(policy), encoding="utf-8")
    index["manifests"][0]["platform"]["architecture"] = "arm64"
    with pytest.raises(probe.QualificationError):
        probe.reviewed_openbao(path, lambda _: index)


def test_bundle_roles_derive_only_from_verified_lock(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    (root / "docker").mkdir(parents=True)
    (root / "docker/openbao-init.sh").write_text("fixture", encoding="utf-8")
    lock = tmp_path / "lock.json"
    roles = {"db-migrate": IMAGES["migrations"], "issuance": IMAGES["services"],
             "issuance-migrations": IMAGES["services"],
             "postgres": IMAGES["postgres"], "redis": IMAGES["redis"]}
    lock.write_text(json.dumps({"services": roles}), encoding="utf-8")
    (root / ".marty-selfhost-images.json").write_bytes(lock.read_bytes())
    receipt = {"images": roles, "archive_sha256": "a", "image_lock_sha256": "b"}
    monkeypatch.setattr(probe, "verify_descriptor", lambda *args: None)
    monkeypatch.setattr(probe, "verify_receipt", lambda *args: receipt)
    monkeypatch.setattr(probe, "verify_extracted_bundle", lambda *args: None)
    images, found = probe.bundle_images(tmp_path / "archive", lock, tmp_path / "transaction",
                                        tmp_path / "receipt", tmp_path / "descriptor", root,
                                        "f" * 40, "123")
    assert images == {name: IMAGES[name]
                      for name in ("migrations", "services", "postgres", "redis")}
    assert found is receipt
    roles["db-migrate"] = "ghcr.io/other/migrations@sha256:" + "a" * 64
    lock.write_text(json.dumps({"services": roles}), encoding="utf-8")
    (root / ".marty-selfhost-images.json").write_bytes(lock.read_bytes())
    receipt["images"] = roles
    with pytest.raises(probe.QualificationError):
        probe.bundle_images(tmp_path / "archive", lock, tmp_path / "transaction",
                            tmp_path / "receipt", tmp_path / "descriptor", root,
                            "f" * 40, "123")
    roles["db-migrate"] = IMAGES["migrations"]
    roles["issuance-migrations"] = IMAGES["migrations"]
    lock.write_text(json.dumps({"services": roles}), encoding="utf-8")
    (root / ".marty-selfhost-images.json").write_bytes(lock.read_bytes())
    with pytest.raises(probe.QualificationError, match="runtime and migration images differ"):
        probe.bundle_images(tmp_path / "archive", lock, tmp_path / "transaction",
                            tmp_path / "receipt", tmp_path / "descriptor", root,
                            "f" * 40, "123")


def test_pulled_images_match_linux_amd64_and_exact_digest():
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert kwargs == {"check": True, "capture_output": True, "text": True}
        output = "" if args[1] == "pull" else json.dumps({
            "Os": "linux", "Architecture": "amd64", "RepoDigests": [args[3]]})
        return subprocess.CompletedProcess(args, 0, output, "")

    probe.verify_local_platforms(IMAGES, run)
    assert len(calls) == 10
    assert all(args[2] == "--platform" and args[3] == "linux/amd64"
               for args in calls if args[1] == "pull")


@pytest.mark.parametrize("platform,digests", [
    ("arm64", [IMAGES["migrations"]]),
    ("amd64", ["ghcr.io/other/migrations@sha256:" + "a" * 64]),
    ("amd64", []),
])
def test_pulled_image_rejects_wrong_platform_or_digest(platform, digests):
    def run(args, **kwargs):
        reference = args[3]
        affected = reference == IMAGES["migrations"]
        output = "" if args[1] == "pull" else json.dumps({
            "Os": "linux", "Architecture": platform if affected else "amd64",
            "RepoDigests": digests if affected else [reference]})
        return subprocess.CompletedProcess(args, 0, output, "")

    with pytest.raises(probe.QualificationError):
        probe.verify_local_platforms(IMAGES, run)


def test_official_docker_hub_alias_preserves_exact_postgres_binding():
    images = {**IMAGES, "postgres": "docker.io/library/postgres@sha256:" + "b" * 64}

    def run(args, **kwargs):
        digest = args[3]
        reported = ("postgres@" + digest.split("@", 1)[1]
                    if digest.startswith("docker.io/library/postgres@") else digest)
        output = "" if args[1] == "pull" else json.dumps({
            "Os": "linux", "Architecture": "amd64", "RepoDigests": [reported]})
        return subprocess.CompletedProcess(args, 0, output, "")

    probe.verify_local_platforms(images, run)


def test_platform_probe_fails_closed_on_pull_error():
    def fail(args, **kwargs):
        raise subprocess.CalledProcessError(1, args)

    with pytest.raises(probe.QualificationError, match="cannot be pulled"):
        probe.verify_local_platforms(IMAGES, fail)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Compose CLI unavailable")
def test_compose_render_is_scoped_and_rejects_root_in_migration(tmp_path):
    install = tmp_path / "bundle"
    (install / "docker").mkdir(parents=True)
    (install / "docker/openbao-init.sh").write_text("fixture", encoding="utf-8")
    environment = {**os.environ,
        "PROBE_MIGRATIONS_IMAGE": IMAGES["migrations"],
        "PROBE_SERVICES_IMAGE": IMAGES["services"],
        "PROBE_POSTGRES_IMAGE": IMAGES["postgres"],
        "PROBE_REDIS_IMAGE": IMAGES["redis"],
        "PROBE_OPENBAO_IMAGE": IMAGES["openbao"],
        "PROBE_SECRET_DIR": str(tmp_path),
        "PROBE_OPENBAO_START": str(probe.START.resolve()),
        "PROBE_OPENBAO_BOOTSTRAP": str(probe.BOOTSTRAP.resolve()),
        "PROBE_OPENBAO_INIT": str((install / "docker/openbao-init.sh").resolve()),
        "COMPOSE_PROFILES": "",
    }
    result = subprocess.run(
        ["docker", "compose", "--project-name", PROJECT, "-f", str(probe.COMPOSE),
         "config", "--format", "json"], env=environment, check=True,
        capture_output=True, text=True, encoding="utf-8")
    model = json.loads(result.stdout)
    probe.validate_scoped_model(model, IMAGES, tmp_path, install, PROJECT)
    for mutation in (
        lambda item: item["services"]["db-migrate"]["environment"].update(
            BAO_TOKEN_FILE="/run/secrets/bao_root_token"),
        lambda item: item["services"]["db-migrate"].update(
            secrets=[{"source": "bao_root_token",
                      "target": "/run/secrets/bao_root_token"}]),
        lambda item: item["services"]["openbao-bootstrap"].update(
            ports=["8200:8200"]),
        lambda item: item["services"]["db-migrate"].update(platform="linux/arm64"),
        lambda item: item["services"]["openbao"].pop("platform"),
        lambda item: item["services"]["native-schema-migrate"].update(
            image=IMAGES["migrations"]),
        lambda item: item["networks"]["private"].update(internal=False),
    ):
        changed = deepcopy(model)
        mutation(changed)
        with pytest.raises(probe.QualificationError):
            probe.validate_scoped_model(changed, IMAGES, tmp_path, install, PROJECT)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Compose CLI unavailable")
@pytest.mark.parametrize("failure", [None, "private_storage", "reused_token", "reused_verifier"])
def test_probe_uses_scoped_bootstrap_then_reruns_and_cleans(
    tmp_path, monkeypatch, failure,
):
    monkeypatch.setattr(probe, "verify_local_platforms", lambda images: None)
    install = tmp_path / "bundle"
    (install / "docker").mkdir(parents=True)
    (install / "docker/openbao-init.sh").write_text("fixture", encoding="utf-8")
    calls = []
    success = ("Profile: selfhost-production (persistent=True)\n"
               "Marty KMS identity: ready\n"
               "Ensured non-exportable notification webhook envelope key\n"
               "All migrations completed successfully\n"
               "notification schema migrated\n")

    def run(args, environment, timeout=90):
        calls.append(args)
        assert environment["PROBE_MIGRATIONS_IMAGE"] == IMAGES["migrations"]
        assert environment["PROBE_SERVICES_IMAGE"] == IMAGES["services"]
        if args[-3:] == ["config", "--format", "json"]:
            return subprocess.run(args, env=environment, capture_output=True,
                                  text=True, encoding="utf-8", check=False)
        if args[-1] == "openbao-bootstrap":
            secret_dir = Path(environment["PROBE_SECRET_DIR"])
            (secret_dir / "bao_service_token").write_text("scoped-service")
            (secret_dir / "notification_openbao_token").write_text(
                "scoped-service" if failure == "reused_token" else "scoped-notification"
            )
            (secret_dir / "sign_grant_verify_token").write_text(
                "scoped-service" if failure == "reused_verifier" else "scoped-verifier"
            )
            (secret_dir / "signing_keys_openbao_token").write_text("scoped-signing-keys")
        output = (success if args[-1] == "db-migrate" else
                  "table:issuer.signing_private_keys\n" if failure == "private_storage" and
                  probe.PRIVATE_KEY_SCHEMA_QUERY in args else
                  "" if probe.PRIVATE_KEY_SCHEMA_QUERY in args or
                  probe.PRIVATE_KEY_CONTENT_QUERY in args else
                  "20260808_0002\n" if "psql" in args else
                  "1\n" if "redis-cli" in args else "")
        return subprocess.CompletedProcess(args, 0, output, "")

    if failure:
        expected = "private-key storage" if failure == "private_storage" else "must be distinct"
        with pytest.raises(probe.QualificationError, match=expected):
            probe.probe(IMAGES, {"archive_sha256": "a", "image_lock_sha256": "b"},
                        install, run=run, project=PROJECT)
        assert any("down" in args and "--volumes" in args for args in calls)
        return
    report = probe.probe(IMAGES, {"archive_sha256": "a", "image_lock_sha256": "b"},
                         install, run=run, project=PROJECT)
    assert report["qualification"] == "unqualified"
    assert report["runs"] == 2
    assert report["services_image"] == IMAGES["services"]
    assert report["native_schemas"] == "verified"
    assert report["private_key_storage"] == "absent"
    assert sum(args[-1] == "openbao-bootstrap" for args in calls) == 1
    assert sum(args[-1] == "db-migrate" for args in calls) == 2
    assert sum(args[-1] == "native-schema-migrate" for args in calls) == 2
    assert any("down" in args and "--volumes" in args for args in calls)


def test_failed_bootstrap_still_tears_down(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(probe, "validate_scoped_model", lambda *args: None)
    monkeypatch.setattr(probe, "verify_local_platforms", lambda images: None)

    def run(args, environment, timeout=90):
        calls.append(args)
        return subprocess.CompletedProcess(
            args, 1 if args[-1] == "openbao-bootstrap" else 0,
            "{}" if args[-3:] == ["config", "--format", "json"] else "", "")

    with pytest.raises(probe.QualificationError, match="bootstrap failed"):
        probe.probe(IMAGES, {"archive_sha256": "a", "image_lock_sha256": "b"},
                    tmp_path, run=run, project=PROJECT)
    assert any("down" in args and "--volumes" in args for args in calls)


@pytest.mark.skipif(os.environ.get("MARTY_RUN_SCOPED_OPENBAO_PROBE") != "1",
                    reason="opt-in disposable Docker test")
def test_actual_scoped_openbao_bootstrap():
    image = probe.reviewed_openbao()
    with tempfile.TemporaryDirectory(prefix="marty-selfhost-openbao-check-") as temporary:
        secret_dir = Path(temporary)
        root = secrets.token_hex(32)
        (secret_dir / "bao_root_token").write_text(root, encoding="ascii")
        environment = {**os.environ,
            "PROBE_MIGRATIONS_IMAGE": IMAGES["migrations"],
            "PROBE_SERVICES_IMAGE": IMAGES["services"],
            "PROBE_POSTGRES_IMAGE": IMAGES["postgres"],
            "PROBE_REDIS_IMAGE": IMAGES["redis"],
            "PROBE_OPENBAO_IMAGE": image,
            "PROBE_SECRET_DIR": str(secret_dir),
            "PROBE_OPENBAO_START": str(probe.START.resolve()),
            "PROBE_OPENBAO_BOOTSTRAP": str(probe.BOOTSTRAP.resolve()),
            "PROBE_OPENBAO_INIT": str((probe.ROOT / "docker/openbao-init.sh").resolve()),
            "COMPOSE_PROFILES": "",
        }
        project = "marty-selfhost-scoped-migrate-" + "2" * 16
        compose = ["docker", "compose", "--project-name", project,
                   "-f", str(probe.COMPOSE)]
        probe._empty_project(project, environment, probe.command)
        try:
            probe._checked(probe.command([*compose, "up", "-d", "--wait",
                                          "--wait-timeout", "120", "openbao"],
                                         environment, 240), "OpenBao did not start")
            probe._checked(probe.command([*compose, "run", "--no-deps", "--rm",
                                          "openbao-bootstrap"], environment, 180),
                           "Scoped OpenBao bootstrap failed")
            service = (secret_dir / "bao_service_token").read_text(encoding="ascii")
            notification = (secret_dir / "notification_openbao_token").read_text(
                encoding="ascii")
            verifier = (secret_dir / "sign_grant_verify_token").read_text(
                encoding="ascii")
            signing_keys = (secret_dir / "signing_keys_openbao_token").read_text(
                encoding="ascii")
            assert service and notification and verifier and signing_keys
            assert len({root, service, notification, verifier, signing_keys}) == 5
        finally:
            probe._checked(probe.command([*compose, "down", "--volumes"],
                                         environment, 120), "OpenBao cleanup failed")
            probe._empty_project(project, environment, probe.command)
