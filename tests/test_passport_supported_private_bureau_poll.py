"""Private receipt reads require current ownership and hide the service token."""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

import pytest

from scripts.passport_supported_private_bureau_poll import (
    PrivateBureauProbeError, poll_owned_bureau,
)
from scripts.passport_supported_provisioning_producer import PARTIAL_ONLY_SERVICES


JOB = "be6bccf4-51eb-4985-a079-6424bf5c5685"
NOW = datetime(2026, 9, 28, 17, tzinfo=timezone.utc)


def staged():
    project = "marty-passport-acceptance-selfhost-" + uuid.uuid4().hex[:12]
    root = Path(tempfile.gettempdir()) / project
    root.mkdir(mode=0o700)
    secrets = root / "secrets"
    secrets.mkdir(mode=0o700)
    token = "a" * 64
    (secrets / "grpc_service_token").write_text(token, encoding="ascii")
    record = {
        "project": project, "disposable_root": str(root),
        "migrations_reference": (
            "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "b" * 64),
        "containers": {"passport-beta-bureau": "c" * 64},
        "owner_labels": {"com.marty.passport.acceptance.owner": "supported-consumer"},
    }
    return root, token, record


def cleanup(root: Path) -> None:
    assert root.parent == Path(tempfile.gettempdir())
    assert root.name.startswith("marty-passport-acceptance-selfhost-")
    (root / "secrets" / "grpc_service_token").unlink()
    (root / "secrets").rmdir()
    root.rmdir()


def test_private_poll_binds_owned_container_without_argv_secret() -> None:
    root, token, record = staged()
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command, 0, json.dumps({"status": 200, "body": {
                "status": "QUALITY_CHECK", "tracking_number": None,
                "callback_receipt_sha256": "d" * 64}}), "")
    try:
        status, body = poll_owned_bureau(
            record, "selfhost", JOB, now=NOW,
            inspector=lambda args: "",
            ownership=lambda *args: {"live_ownership_verified": True},
            run=run,
        )
        assert status == 200 and body["callback_receipt_sha256"] == "d" * 64
        assert "passport-bureau-poll" in PARTIAL_ONLY_SERVICES
        command, options = calls[0]
        assert "--network" in command
        assert "container:" + "c" * 64 in command
        assert token not in " ".join(command)
        assert JOB not in " ".join(command)
        assert json.loads(options["input"]) == {"bureau_job_id": JOB,
                                                "token": token}
        assert options["env"]["DOCKER_HOST"] == "unix:///var/run/docker.sock"
    finally:
        cleanup(root)


def test_unverified_or_invalid_private_scope_never_runs_docker() -> None:
    root, _, record = staged()
    commands = []
    try:
        with pytest.raises(PrivateBureauProbeError, match="ownership"):
            poll_owned_bureau(
                record, "selfhost", JOB, now=NOW,
                ownership=lambda *args: {"live_ownership_verified": False},
                run=lambda *args, **kwargs: commands.append(args),
            )
        with pytest.raises(PrivateBureauProbeError, match="job ID"):
            poll_owned_bureau(record, "selfhost", "other", now=NOW,
                              run=lambda *args, **kwargs: commands.append(args))
        (root / "secrets" / "grpc_service_token").write_text("short")
        with pytest.raises(PrivateBureauProbeError, match="token is invalid"):
            poll_owned_bureau(
                record, "selfhost", JOB, now=NOW,
                ownership=lambda *args: {"live_ownership_verified": True},
                run=lambda *args, **kwargs: commands.append(args),
            )
        assert commands == []
    finally:
        cleanup(root)
