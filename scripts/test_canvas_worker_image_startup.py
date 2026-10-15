"""Packaged native startup against the published schema and reviewed behavior."""

import json
import os
from contextlib import ExitStack, contextmanager
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from test_canvas_worker_image_entrypoint import docker, owned_container
from with_disposable_event_stream_kms import execute as with_disposable_tls_kms


ROOT = Path(__file__).resolve().parents[1]
DATABASE_NAME = "canvas_published_schema_test"
PASSWORD = "synthetic-local-only"
SECRETS = {
    "TOKEN_HMAC_KEY": "synthetic-startup-hmac-key",
    "ISSUANCE_API_KEY": "synthetic-startup-api-key",
    "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic-startup-api-key",
    "SIGNING_KEYS_ISSUER_SIGN_KEY": "synthetic-dedicated-issuer-sign-key-32-chars",
    "SIGNING_KEYS_INTEGRATION_SECRET_KEY": "synthetic-dedicated-integration-secret-key-32-chars",
    "MARTY_DB_PASSWORD": PASSWORD,
}
HARDENED = ("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges")
OPENBAO_IMAGE = "quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878"


def contract(name):
    return json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))


def mount(path, destination):
    return ("--mount", f"type=bind,source={path},target={destination},readonly")


def selected_pinned_dockerhub_image(reference):
    if os.name == "nt":
        # Windows Python cannot pass a Win32 path as a script argument to WSL bash.
        docker("pull", reference, timeout=120)
        return reference
    return subprocess.run(
        ["bash", str(ROOT / "scripts/ci/pull-pinned-dockerhub-image.sh"), reference],
        check=True, capture_output=True, text=True, timeout=120,
    ).stdout.strip()


@contextmanager
def owned_network():
    name = "canvas-worker-kms-" + secrets.token_hex(8)
    bao = os.environ["MARTY_TEST_SIGNING_KEYS_BAO_CONTAINER"]
    docker("network", "create", "--internal", name)
    try:
        docker("network", "connect", "--alias", "synthetic-secret-service", name, bao)
        yield name
    finally:
        subprocess.run(["docker", "network", "disconnect", "--force", name, bao],
                       capture_output=True, check=False, timeout=20)
        subprocess.run(["docker", "network", "rm", name],
                       capture_output=True, check=False, timeout=20)


def start_keyless_signer(stack, network, image):
    redis_image = selected_pinned_dockerhub_image(
        "redis:7.4-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
    )
    redis = stack.enter_context(owned_container(
        "--pull=never", "--network", network, "--network-alias", "signing-redis",
        redis_image,
    ))
    docker("start", redis)
    env = {
        "SIGNING_KEYS_INTERNAL_API_KEY": SECRETS["SIGNING_KEYS_INTERNAL_API_KEY"],
        "SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY": "synthetic-service-sign-gateway-key-32-chars",
        "SIGNING_KEYS_ISSUER_SIGN_KEY": SECRETS["SIGNING_KEYS_ISSUER_SIGN_KEY"],
        "SIGNING_KEYS_INTEGRATION_SECRET_KEY": SECRETS["SIGNING_KEYS_INTEGRATION_SECRET_KEY"],
        "SIGNING_KEYS_REDIS_URL": "redis://signing-redis:6379/2",
        "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE": "/verification/grant-token",
        "ISSUER_BASE_URL": "https://issuer.example",
        "BAO_ADDR": "https://127.0.0.1:8200",
        "BAO_CACERT": "/verification/bao-ca.crt",
        "BAO_TOKEN_FILE": "/verification/envelope-token",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE": "/verification/tls.crt",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_ADDR": "https://127.0.0.1:8200",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_CA_CERT_FILE": "/verification/bao-ca.crt",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_TOKEN_FILE": "/verification/tls-token",
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_NAME": os.environ["MARTY_TEST_SIGNING_KEYS_TLS_KMS_KEY_NAME"],
        "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_VERSION": "1",
    }
    mounts = (
        ("MARTY_TEST_SIGNING_KEYS_TLS_CERT", "/verification/tls.crt"),
        ("MARTY_TEST_SIGNING_KEYS_TLS_CA", "/verification/workload-ca.crt"),
        ("MARTY_TEST_SIGNING_KEYS_TLS_KMS_CA", "/verification/bao-ca.crt"),
        ("MARTY_TEST_SIGNING_KEYS_TLS_KMS_TOKEN_FILE", "/verification/tls-token"),
        ("MARTY_TEST_SIGNING_KEYS_ENVELOPE_TOKEN_FILE", "/verification/envelope-token"),
        ("MARTY_TEST_SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE", "/verification/grant-token"),
    )
    signer = stack.enter_context(owned_container(
        "--pull=never", "--network", f"container:{os.environ['MARTY_TEST_SIGNING_KEYS_BAO_CONTAINER']}",
        *HARDENED, *environment_arguments(env),
        *(part for source, target in mounts for part in mount(Path(os.environ[source]), target)),
        image,
    ))
    docker("start", signer)

    def remote_ready():
        assert running(signer), f"Rust Signing Keys exited: {docker('logs', signer)}"
        try:
            docker("exec", signer, "curl", "--fail", "--silent",
                   "--cacert", "/verification/workload-ca.crt",
                   "https://localhost:8018/health", timeout=5)
            return True
        except subprocess.CalledProcessError:
            return False

    wait_for(remote_ready, "keyless Rust Signing Keys integration-secret service", 30)


def environment_arguments(environment):
    return tuple(
        argument
        for key, value in environment.items()
        for argument in ("--env", f"{key}={value}")
    )


def running(container):
    return json.loads(
        docker("inspect", "--format", "{{json .State.Running}}", container)
    )


def wait_for(predicate, description, seconds=20):
    deadline = time.monotonic() + seconds
    while True:
        value = predicate()
        if value:
            return value
        assert time.monotonic() < deadline, f"Timed out waiting for {description}"
        time.sleep(0.1)


def query(postgres, sql):
    return docker(
        "exec",
        postgres,
        "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "oracle",
        "-d",
        DATABASE_NAME,
        "-At",
        "-c",
        sql,
        timeout=5,
    )


def configuration(case, mode):
    worker_id = f"image-{mode['name']}-{case['name']}"
    assert re.fullmatch(r"[a-z_-]+", worker_id)
    assert case["database_scheme"] in {"postgresql", "postgresql+asyncpg"}
    environment = {
        "SERVICE_NAME": mode["service"],
        "CANVAS_SYNC_WORKER_ID": worker_id,
        "CANVAS_SYNC_WORKER_POLL_SECONDS": "60",
        "CANVAS_PILOT_ORGANIZATION_IDS": "bootstrap-org",
        "SIGNING_KEYS_INTERNAL_URL": "http://synthetic-secret-service:8017/internal/signing-keys",
        # Startup must exercise the managed grant path. This idle-only probe
        # has no mint authority: an unexpected sign cannot read this file.
        "BAO_ADDR": "https://127.0.0.1:1",
        "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN_FILE": "/nonexistent/canvas-worker-image-grant",
        "INTEGRATION_SECRET_KMS_URL": "https://synthetic-secret-service:8018/internal",
        "INTEGRATION_SECRET_KMS_CA_FILE": "/synthetic-secrets/ca.crt",
        **case["environment"],
    }
    key_source = mode["key_source"]
    assert key_source in {"direct", "file"}
    for name, value in SECRETS.items():
        if name == "MARTY_DB_PASSWORD":
            continue
        if key_source == "file":
            environment[f"{name}_FILE"] = f"/synthetic-secrets/{name}"
        else:
            environment[name] = value
    assert mode["database_source"] in {"direct", "template"}
    if mode["database_source"] == "template":
        environment["MARTY_DB_PASSWORD_FILE"] = "/synthetic-secrets/MARTY_DB_PASSWORD"
        environment["DATABASE_URL_TEMPLATE"] = (
            f"{case['database_scheme']}://oracle:${{MARTY_DB_PASSWORD}}@127.0.0.1:5432/{DATABASE_NAME}"
        )
    else:
        environment["DATABASE_URL"] = (
            f"{case['database_scheme']}://oracle:{PASSWORD}@127.0.0.1:5432/{DATABASE_NAME}"
        )
    return worker_id, environment


def assert_observation(observed, case_name):
    expected = contract("canvas-worker-startup-expected.json")
    assert expected["schema"] == "marty.canvas-worker-startup-expected/v1"
    assert expected["alive_after_idle"] is True
    assert expected["job_count"] == 0
    assert expected["exit_code_after_interrupt"] == 130
    expected = {key: value for key, value in expected.items() if key != "schema"}
    assert observed == {"name": case_name, **expected}


def exercise(image, postgres, directory, case, mode):
    worker_id, environment = configuration(case, mode)
    with owned_container(
        "--pull=never",
        "--network",
        f"container:{postgres}",
        *HARDENED,
        "--no-healthcheck",
        *environment_arguments(environment),
        *mount(directory, "/synthetic-secrets"),
        image,
    ) as worker:
        docker("start", worker)

        def idle():
            assert running(worker), "Packaged worker exited before idle heartbeat"
            result = query(
                postgres,
                "SELECT json_build_object('role',role,'metadata',metadata)::text "
                "FROM issuance_service.canvas_worker_heartbeats "
                f"WHERE worker_id='{worker_id}' AND metadata->>'phase'='idle'",
            )
            return json.loads(result) if result else None

        heartbeat = wait_for(
            idle, f"packaged idle heartbeat {mode['name']}/{case['name']}"
        )
        alive = running(worker)
        docker("kill", "--signal=SIGINT", worker)
        status = int(docker("wait", worker, timeout=15))
        observed = {
            "name": case["name"],
            "heartbeat": heartbeat,
            "alive_after_idle": alive,
            "exit_code_after_interrupt": status,
            "job_count": int(
                query(
                    postgres,
                    "SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs",
                )
            ),
        }
        assert_observation(observed, case["name"])
        logs = docker("logs", worker)
        assert all(value not in logs for value in SECRETS.values()), (
            "Synthetic secret in startup logs"
        )
        print(f"Packaged worker startup {mode['name']}/{case['name']} passed")


def run(image, signing_image):
    spec = contract("canvas-worker-image-startup-scenarios.json")
    pins = contract(spec["schema_reference"])
    cases = contract(spec["startup_scenarios"])["cases"]
    assert len(cases) == 8
    assert len({case["name"] for case in cases}) == len(cases)
    for pin in (pins["observed_image"], pins["observed_postgres_image"]):
        assert re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", pin)
    docker("pull", pins["observed_image"], timeout=120)
    selected_postgres = selected_pinned_dockerhub_image(
        pins["observed_postgres_image"]
    )
    assert selected_postgres in {
        pins["observed_postgres_image"],
        f"mirror.gcr.io/library/{pins['observed_postgres_image']}",
    }
    with TemporaryDirectory(prefix="canvas-worker-image-startup-") as temporary, owned_network() as network:
        temporary_root = Path(temporary).resolve()
        temporary_root.chmod(0o755)
        directory = temporary_root / "worker-secrets"
        directory.mkdir(mode=0o755)
        for name, value in SECRETS.items():
            path = directory / name
            path.write_text(value + "\r\n", encoding="utf-8", newline="")
            path.chmod(0o444)
        shutil.copyfile(os.environ["MARTY_TEST_SIGNING_KEYS_TLS_CA"], directory / "ca.crt")
        (directory / "ca.crt").chmod(0o444)
        with owned_container(
            "--pull=never",
            "--network",
            network,
            "--tmpfs",
            "/var/lib/postgresql/data:rw",
            "--tmpfs",
            "/var/run/postgresql:rw",
            *environment_arguments(
                {
                    "POSTGRES_USER": "oracle",
                    "POSTGRES_PASSWORD": PASSWORD,
                    "POSTGRES_DB": DATABASE_NAME,
                }
            ),
            selected_postgres,
        ) as postgres:
            docker("start", postgres)

            def ready():
                assert running(postgres), "Owned PostgreSQL exited before readiness"
                try:
                    return query(postgres, "SELECT 1") == "1"
                except subprocess.CalledProcessError:
                    return False

            wait_for(ready, "owned PostgreSQL readiness", 30)
            with owned_container(
                "--pull=never",
                "--network",
                f"container:{postgres}",
                *HARDENED,
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--env",
                "TOKEN_HMAC_KEY=synthetic-schema-only-hmac-key",
                *mount(
                    ROOT / "scripts/prepare_canvas_published_schema.py",
                    "/verification/scripts/prepare_canvas_published_schema.py",
                ),
                *mount(
                    ROOT / "contracts" / spec["schema_reference"],
                    "/verification/contracts/canvas-worker-consumer-range-oracle.json",
                ),
                "--entrypoint",
                "python",
                pins["observed_image"],
                "/verification/scripts/prepare_canvas_published_schema.py",
            ) as migration:
                docker("start", migration)
                assert docker("wait", migration, timeout=90) == "0", (
                    "Official migration probe failed"
                )
                report = json.loads(docker("logs", migration))
                assert report["status"] == "passed"
                assert report["migration_revisions"] == pins["migration_revisions"]
                assert report["worker_sha256"] == pins["observed_source_sha256"]
            with ExitStack() as stack:
                start_keyless_signer(stack, network, signing_image)
                for mode in spec["modes"]:
                    for case in cases:
                        exercise(image, postgres, directory, case, mode)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("Expected the exact locally built issuance image and optional Signing Keys image")
    signing_image = sys.argv[2] if len(sys.argv) == 3 else "marty-signing-keys:ci"
    if "MARTY_TEST_SIGNING_KEYS_BAO_CONTAINER" not in os.environ:
        raise SystemExit(with_disposable_tls_kms(
            OPENBAO_IMAGE, [sys.executable, str(Path(__file__).resolve()), sys.argv[1], signing_image],
            profile="signing-keys-image",
        ))
    run(sys.argv[1], signing_image)
