#!/usr/bin/env python3
"""Exercise synthetic passport routes through an owned disposable HTTPS edge."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import tempfile
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

if __package__:
    from .check_passport_supported_compose_ownership import (
        _inspect, _status_origin, docker, verify as verify_ownership,
    )
    from .passport_supported_private_bureau_poll import poll_owned_bureau
    from .probe_passport_supported_routes import exercise
else:
    from check_passport_supported_compose_ownership import (
        _inspect, _status_origin, docker, verify as verify_ownership,
    )
    from passport_supported_private_bureau_poll import poll_owned_bureau
    from probe_passport_supported_routes import exercise

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.passport_disposable_identity import ORGANIZATION_ID, issuer_did


TEST_KEY = re.compile(r"mk_test_[A-Za-z0-9]{43}\n\Z")


class DisposableRouteProbeError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _private_inputs(record: dict[str, Any]) -> tuple[Path, str]:
    project = record.get("project")
    root = Path(tempfile.gettempdir()) / str(project)
    secret_dir = root / "secrets"
    key_file = secret_dir / "passport_acceptance_api_key"
    ca_file = secret_dir / "workload_identity_ca_cert"
    if record.get("disposable_root") != str(root) or root.resolve() != root:
        raise DisposableRouteProbeError("Disposable HTTPS project root is invalid")
    info = secret_dir.lstat()
    if (not stat.S_ISDIR(info.st_mode) or secret_dir.is_symlink()
        or (os.name == "posix" and (info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700))):
        raise DisposableRouteProbeError("Disposable HTTPS secret root is invalid")
    for path in (key_file, ca_file):
        item = path.lstat()
        if not stat.S_ISREG(item.st_mode) or path.is_symlink():
            raise DisposableRouteProbeError("Disposable HTTPS credential file is invalid")
    key_contents = key_file.read_text(encoding="ascii")
    if TEST_KEY.fullmatch(key_contents) is None:
        raise DisposableRouteProbeError("Disposable Organization API key is invalid")
    return ca_file, key_contents.removesuffix("\n")


def exercise_owned_disposable(
    record: dict[str, Any], surface: str, application: dict[str, Any], *,
    now: datetime | None = None,
    inspector: Callable[[list[str]], str] = docker,
    ownership: Callable[..., dict] = verify_ownership,
    private_poll: Callable[..., tuple[int, dict[str, Any]]] = poll_owned_bureau,
    max_polls: int = 36,
    poll_interval_seconds: float = 5,
) -> dict[str, Any]:
    """Use only the attested project's loopback TLS edge and same-job simulator."""
    current = now or datetime.now(timezone.utc)
    proof = ownership(record, surface, current, inspector)
    if proof.get("live_ownership_verified") is not True:
        raise DisposableRouteProbeError("Disposable passport ownership is unverified")
    try:
        expires = datetime.fromisoformat(record["expires_at"])
    except (KeyError, TypeError, ValueError) as error:
        raise DisposableRouteProbeError("Disposable passport lease is invalid") from error
    if expires.tzinfo is None:
        raise DisposableRouteProbeError("Disposable passport lease is invalid")
    deadline = expires - timedelta(minutes=10)

    def require_time_budget() -> None:
        if datetime.now(timezone.utc) >= deadline:
            raise DisposableRouteProbeError("Disposable passport teardown budget is exhausted")

    require_time_budget()
    edge_id = record["containers"]["edge"]
    origin = _status_origin(_inspect("container", edge_id, inspector))
    port = int(origin.rsplit(":", 1)[1])
    if (application.get("organization_id") != ORGANIZATION_ID
        or application.get("issuer_did") != issuer_did(port)):
        raise DisposableRouteProbeError("Disposable passport issuer scope is invalid")
    ca_file, key = _private_inputs(record)
    context = ssl.create_default_context(cafile=str(ca_file))
    opener = build_opener(ProxyHandler({}), NoRedirect, HTTPSHandler(context=context))

    def request(method: str, path: str, body: dict[str, Any] | None,
                authority: str) -> tuple[int, dict[str, Any]]:
        require_time_budget()
        if (method not in ("GET", "POST") or not path.startswith("/v1/passport/")
            or ".." in path or any(mark in path for mark in ("?", "#", "\\"))
            or authority not in (key, "")):
            raise DisposableRouteProbeError("Disposable passport route escaped scope")
        headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
        if authority:
            headers["x-api-key"] = authority
        encoded = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        url = origin + path
        try:
            with opener.open(Request(url, data=encoded, headers=headers,
                                     method=method), timeout=30) as response:
                if response.geturl() != url:
                    raise DisposableRouteProbeError("Disposable passport route redirected")
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise DisposableRouteProbeError("Disposable passport response is oversized")
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise DisposableRouteProbeError("Disposable passport response is invalid")
                return response.status, payload
        except HTTPError as error:
            return error.code, {}
        except (OSError, URLError, ValueError, ssl.SSLError) as error:
            raise DisposableRouteProbeError("Disposable passport request failed") from error

    def poll(bureau_job_id: str) -> tuple[int, dict[str, Any]]:
        require_time_budget()
        return private_poll(
            record, surface, bureau_job_id, now=datetime.now(timezone.utc),
            inspector=inspector, ownership=ownership,
        )

    report = exercise(
        application, key, request=request,
        private_poll=poll,
        max_polls=max_polls, poll_interval_seconds=poll_interval_seconds,
    )
    require_time_budget()
    finished = ownership(record, surface, datetime.now(timezone.utc), inspector)
    if finished.get("live_ownership_verified") is not True:
        raise DisposableRouteProbeError("Disposable passport ownership changed during probe")
    return report
