#!/usr/bin/env python3
"""Read a signed-callback receipt from the owned disposable simulator only."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any, Callable
import uuid

if __package__:
    from .check_passport_supported_compose_ownership import (
        IDENTIFIER, MIGRATIONS_IMAGE, docker, verify as verify_ownership,
    )
    from .check_passport_supported_rollback_model import PROJECT
    from .passport_supported_disposable_ceremony import _local_docker_env
else:
    from check_passport_supported_compose_ownership import (
        IDENTIFIER, MIGRATIONS_IMAGE, docker, verify as verify_ownership,
    )
    from check_passport_supported_rollback_model import PROJECT
    from passport_supported_disposable_ceremony import _local_docker_env


TOKEN = re.compile(r"[0-9a-f]{64}\Z")
_POLL_SCRIPT = r'''
import json, sys
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None

payload = json.load(sys.stdin)
request = Request(
    "http://127.0.0.1:8020/v1/personalization/jobs/" + payload["bureau_job_id"],
    headers={"Authorization": "Bearer " + payload["token"],
             "Accept": "application/json"}, method="GET",
)
try:
    with build_opener(ProxyHandler({}), NoRedirect).open(request, timeout=20) as response:
        status, body = response.status, response.read(4097)
except HTTPError as error:
    status, body = error.code, error.read(4097)
if len(body) > 4096:
    sys.exit(2)
result = json.loads(body)
if not isinstance(result, dict):
    sys.exit(2)
projection = {key: result.get(key) for key in
              ("status", "tracking_number", "callback_receipt_sha256")}
sys.stdout.write(json.dumps({"status": status, "body": projection}))
'''


class PrivateBureauProbeError(ValueError):
    pass


def poll_owned_bureau(
    record: dict[str, Any], surface: str, bureau_job_id: str, *,
    now: datetime | None = None,
    inspector: Callable[[list[str]], str] = docker,
    ownership: Callable[..., dict] = verify_ownership,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[int, dict[str, Any]]:
    """Bind a private poll to the current project before using its service token."""
    try:
        parsed = uuid.UUID(bureau_job_id)
    except (TypeError, ValueError, AttributeError) as error:
        raise PrivateBureauProbeError("Disposable bureau job ID is invalid") from error
    if str(parsed) != bureau_job_id:
        raise PrivateBureauProbeError("Disposable bureau job ID is invalid")
    project = record.get("project")
    image = record.get("migrations_reference")
    containers = record.get("containers")
    if (not isinstance(project, str) or PROJECT.fullmatch(project) is None
        or not project.startswith(f"marty-passport-acceptance-{surface}-")
        or not isinstance(image, str) or MIGRATIONS_IMAGE.fullmatch(image) is None
        or not isinstance(containers, dict)):
        raise PrivateBureauProbeError("Disposable bureau project is invalid")
    bureau = containers.get("passport-beta-bureau")
    if not isinstance(bureau, str) or IDENTIFIER.fullmatch(bureau) is None:
        raise PrivateBureauProbeError("Disposable bureau container is invalid")
    proof = ownership(record, surface, now or datetime.now(timezone.utc), inspector)
    if proof.get("live_ownership_verified") is not True:
        raise PrivateBureauProbeError("Disposable bureau ownership is unverified")
    root = Path(tempfile.gettempdir()) / project
    secrets = root / "secrets"
    token_path = secrets / "grpc_service_token"
    try:
        info = secrets.lstat()
        token_info = token_path.lstat()
        if (record.get("disposable_root") != str(root)
            or root.resolve() != root or secrets.resolve() != secrets
            or secrets.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or token_path.is_symlink() or not stat.S_ISREG(token_info.st_mode)
            or (os.name == "posix" and (info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700))):
            raise PrivateBureauProbeError("Disposable bureau secret root is invalid")
        token = token_path.read_text(encoding="ascii")
    except OSError as error:
        raise PrivateBureauProbeError("Disposable bureau token is unavailable") from error
    if TOKEN.fullmatch(token) is None:
        raise PrivateBureauProbeError("Disposable bureau token is invalid")
    labels = {"com.docker.compose.project": project,
              "com.docker.compose.service": "passport-bureau-poll",
              **record["owner_labels"]}
    command = [
        "docker", "run", "--rm", "--pull", "never", "--interactive",
        "--read-only", "--cap-drop", "ALL", "--security-opt",
        "no-new-privileges", "--network", f"container:{bureau}",
        *(argument for key, value in sorted(labels.items())
          for argument in ("--label", f"{key}={value}")),
        "--entrypoint", "python3", image, "-c", _POLL_SCRIPT,
    ]
    try:
        result = run(
            command, input=json.dumps({"bureau_job_id": bureau_job_id,
                                       "token": token}),
            env=_local_docker_env(), text=True, capture_output=True,
            timeout=45, check=False,
        )
        if result.returncode != 0 or len(result.stdout) > 4096:
            raise PrivateBureauProbeError("Disposable bureau poll failed")
        response = json.loads(result.stdout)
        if (not isinstance(response, dict) or set(response) != {"status", "body"}
            or type(response["status"]) is not int
            or not isinstance(response["body"], dict)
            or set(response["body"]) != {
                "status", "tracking_number", "callback_receipt_sha256"}):
            raise PrivateBureauProbeError("Disposable bureau poll is invalid")
        return response["status"], response["body"]
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise PrivateBureauProbeError("Disposable bureau poll failed") from error
