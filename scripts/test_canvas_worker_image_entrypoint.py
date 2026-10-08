"""Actual packaged worker selection/preflight; no database or deployment access."""

from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory


FORBIDDEN_VALUE = "synthetic-forbidden-local-secret"
SECRET_FILE = "/synthetic-secrets/signing-api-key"
STARTED = "Starting canonical Rust service:"


@dataclass(frozen=True)
class Case:
    name: str
    service: str
    environment: tuple[str, ...]
    exit_code: int
    message: str
    starts_worker: bool


CASES = (
    Case(
        "hyphen",
        "canvas-sync-worker",
        (f"INTEGRATION_SECRET_MASTER_KEY={FORBIDDEN_VALUE}",),
        1,
        "legacy integration-secret master-key configuration is forbidden",
        True,
    ),
    Case(
        "invalid_logging",
        "canvas-sync-worker",
        ("LOG_LEVEL=synthetic-invalid-operator-value",),
        1,
        "invalid Canvas worker LOG_LEVEL",
        True,
    ),
    Case(
        "underscore",
        "canvas_sync_worker",
        ("INTEGRATION_SECRET_MASTER_KEY_ENV=SYNTHETIC_LOCAL_KEY",),
        1,
        "legacy integration-secret master-key configuration is forbidden",
        True,
    ),
    Case(
        "invalid_database_url",
        "canvas-sync-worker",
        ("SIGNING_KEYS_INTERNAL_API_KEY=synthetic-api-key", "DATABASE_URL=not-a-url"),
        1,
        "Configuration(RelativeUrlWithoutBase)",
        True,
    ),
    Case(
        "raw_master_key_file",
        "canvas-sync-worker",
        ("INTEGRATION_SECRET_MASTER_KEY_FILE=/synthetic-secrets/missing",),
        1,
        "legacy integration-secret master-key configuration is forbidden",
        True,
    ),
    Case(
        "conflicting_api_key_sources",
        "canvas-sync-worker",
        (
            "SIGNING_KEYS_INTERNAL_API_KEY=synthetic-direct-api-key",
            f"SIGNING_KEYS_INTERNAL_API_KEY_FILE={SECRET_FILE}",
        ),
        1,
        "Both SIGNING_KEYS_INTERNAL_API_KEY and SIGNING_KEYS_INTERNAL_API_KEY_FILE are set; choose one.",
        False,
    ),
    Case(
        "missing_file",
        "canvas-sync-worker",
        ("SIGNING_KEYS_INTERNAL_API_KEY_FILE=/synthetic-secrets/missing",),
        1,
        "Secret file for SIGNING_KEYS_INTERNAL_API_KEY is not a regular file:",
        False,
    ),
    Case(
        "unknown_service",
        "not-a-service",
        (),
        64,
        "Unsupported SERVICE_NAME: not-a-service",
        False,
    ),
    Case("empty_service", "", (), 64, "Unsupported SERVICE_NAME: <empty>", False),
)


def docker(*arguments, timeout=30):
    result = subprocess.run(
        ["docker", *arguments],
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
    )
    return (
        result.stdout + result.stderr if arguments[0] == "logs" else result.stdout
    ).strip()


@contextmanager
def owned_container(*arguments):
    # Exact owned ID, never a deployment name or a broad label cleanup.
    container = docker(
        "create",
        "--label",
        "com.elevenid.test.canvas-worker-entrypoint=true",
        *arguments,
    )
    assert re.fullmatch(r"[0-9a-f]{64}", container), (
        "Docker must return an exact container ID"
    )
    try:
        yield container
    finally:
        docker("rm", "--force", container)


def exercise_case(image, case, directory):
    with owned_container(
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--no-healthcheck",
        "--env",
        f"SERVICE_NAME={case.service}",
        *(argument for value in case.environment for argument in ("--env", value)),
        "--mount",
        f"type=bind,source={directory},target=/synthetic-secrets,readonly",
        image,
    ) as container:
        docker("start", container)
        status = int(docker("wait", container, timeout=15))
        logs = docker("logs", container)
        # Logs for these fixed synthetic cases must never expose the key.
        assert FORBIDDEN_VALUE not in logs, f"{case.name}: synthetic key appeared in logs"
        assert "synthetic-invalid-operator-value" not in logs
        assert status == case.exit_code, f"{case.name}: unexpected exit {status}"
        assert case.message in logs, (
            f"{case.name}: expected preflight diagnostic missing"
        )
        assert (STARTED in logs) == case.starts_worker, (
            f"{case.name}: wrong launch order"
        )
        if case.starts_worker:
            assert f"{STARTED} {case.service}" in logs
        print(f"Packaged worker entrypoint {case.name} passed")


def run(image):
    # No credentials, DB URL or host environment are forwarded to containers.
    with TemporaryDirectory(prefix="canvas-worker-entrypoint-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        key = directory / "signing-api-key"
        key.write_text("synthetic-file-api-key\r\n", encoding="utf-8")
        key.chmod(0o444)
        for case in CASES:
            exercise_case(image, case, directory.resolve())


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected the exact locally built issuance image")
    run(sys.argv[1])
