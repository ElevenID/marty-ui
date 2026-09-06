"""Packaged native startup against the frozen published schema and observations."""

import json
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from test_canvas_worker_image_entrypoint import MASTER_KEY, docker, owned_container


ROOT = Path(__file__).resolve().parents[1]
DATABASE_NAME = "canvas_published_schema_test"
PASSWORD = "synthetic-local-only"
SECRETS = {
    "INTEGRATION_SECRET_MASTER_KEY": MASTER_KEY,
    "TOKEN_HMAC_KEY": "synthetic-startup-hmac-key",
    "ISSUANCE_API_KEY": "synthetic-startup-api-key",
    "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic-startup-api-key",
    "MARTY_DB_PASSWORD": PASSWORD,
}
HARDENED = ("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges")


def contract(name):
    return json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))


def mount(path, destination):
    return ("--mount", f"type=bind,source={path},target={destination},readonly")


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
        "SIGNING_KEYS_INTERNAL_URL": "http://127.0.0.1:1/internal/signing-keys",
        **case["environment"],
    }
    key_source = mode["key_source"]
    assert key_source in {"direct", "file", "environment"}
    for name, value in SECRETS.items():
        if name == "MARTY_DB_PASSWORD":
            continue
        if key_source == "file":
            environment[f"{name}_FILE"] = f"/synthetic-secrets/{name}"
        elif key_source == "environment" and name == "INTEGRATION_SECRET_MASTER_KEY":
            environment[f"{name}_ENV"] = "IMAGE_SELECTED_MASTER_KEY"
            environment["IMAGE_SELECTED_MASTER_KEY"] = value
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


def assert_observation(observed, expected):
    assert expected["exit_code_after_interrupt"] == -2
    # Same explicit native SIGINT mapping as the existing actual-process gate.
    assert observed == {**expected, "exit_code_after_interrupt": 130}


def exercise(image, postgres, directory, case, mode, expected):
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
        assert_observation(observed, expected)
        logs = docker("logs", worker)
        assert all(value not in logs for value in SECRETS.values()), (
            "Synthetic secret in startup logs"
        )
        print(f"Packaged worker startup {mode['name']}/{case['name']} passed")


def run(image):
    spec = contract("canvas-worker-image-startup-scenarios.json")
    pins = contract(spec["schema_reference"])
    cases = contract(spec["startup_scenarios"])["cases"]
    expected = {
        case["name"]: case for case in contract(spec["startup_reference"])["cases"]
    }
    assert set(expected) == {case["name"] for case in cases}
    for pin in (pins["observed_image"], pins["observed_postgres_image"]):
        assert re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", pin)
        docker("pull", pin, timeout=120)
    with TemporaryDirectory(prefix="canvas-worker-image-startup-") as temporary:
        directory = Path(temporary).resolve()
        directory.chmod(0o755)
        for name, value in SECRETS.items():
            path = directory / name
            path.write_text(value + "\r\n", encoding="utf-8", newline="")
            path.chmod(0o444)
        with owned_container(
            "--pull=never",
            "--network",
            "none",
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
            pins["observed_postgres_image"],
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
            for mode in spec["modes"]:
                for case in cases:
                    exercise(
                        image, postgres, directory, case, mode, expected[case["name"]]
                    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected the exact locally built issuance image")
    run(sys.argv[1])
