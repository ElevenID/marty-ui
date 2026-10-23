"""Exercise the active beta PostgreSQL probe against an owned disposable server."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid

import pytest

from scripts.probe_passport_beta_host import beta_psql


CANONICAL_POSTGRES_IMAGE = (
    "postgres:15-alpine@sha256:"
    "fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c"
)
MIRRORED_POSTGRES_IMAGE = "mirror.gcr.io/library/" + CANONICAL_POSTGRES_IMAGE


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=90
    )


@pytest.mark.skipif(
    os.environ.get("BETA_FENCE_DISPOSABLE_DOCKER") != "1",
    reason="set BETA_FENCE_DISPOSABLE_DOCKER=1 for disposable PostgreSQL",
)
def test_beta_psql_multistatement_returns_only_selected_json() -> None:
    image = os.environ.get("BETA_FENCE_POSTGRES_IMAGE", CANONICAL_POSTGRES_IMAGE)
    assert image in {CANONICAL_POSTGRES_IMAGE, MIRRORED_POSTGRES_IMAGE}
    name = f"marty-beta-psql-test-{uuid.uuid4().hex[:12]}"
    docker(
        "run", "--rm", "-d", "--name", name, "--network", "none",
        "-e", "POSTGRES_PASSWORD=disposable-only", image,
    )
    try:
        for _ in range(60):
            ready = docker("exec", name, "pg_isready", "-U", "postgres", check=False)
            if ready.returncode == 0:
                created = docker(
                    "exec", name, "createdb", "-U", "postgres", "marty", check=False
                )
                if created.returncode == 0:
                    break
            time.sleep(0.25)
        else:
            pytest.fail("disposable PostgreSQL did not become ready")

        def runner(command: list[str]) -> str:
            return subprocess.run(
                command, capture_output=True, text=True, check=True, timeout=90
            ).stdout.strip()

        output = beta_psql(
            "SET application_name = 'marty_fence_probe'; "
            "DO $$ BEGIN NULL; END $$; "
            "SELECT json_build_object('ready', true)::text",
            runner,
            name,
        )
        assert json.loads(output) == {"ready": True}
    finally:
        docker("stop", name, check=False)
