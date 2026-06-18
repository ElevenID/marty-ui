#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin


class ContractCheckError(RuntimeError):
    """Raised when the configured Canvas Credentials contract is not usable."""


@dataclass(frozen=True)
class ApiResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: Any


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        raise ContractCheckError(f"Env file does not exist: {path}")

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def merged_env(env_file: Path | None) -> dict[str, str]:
    values = dict(os.environ)
    if env_file:
        values.update(load_env_file(env_file))
    return values


def read_token(values: dict[str, str]) -> str:
    token_file = values.get("CANVAS_CREDENTIALS_API_TOKEN_FILE", "").strip()
    if token_file:
        token_path = Path(token_file)
        if not token_path.exists():
            raise ContractCheckError(f"CANVAS_CREDENTIALS_API_TOKEN_FILE does not exist: {token_path}")
        token = token_path.read_text(encoding="utf-8").strip()
    else:
        token = values.get("CANVAS_CREDENTIALS_API_TOKEN", "").strip()

    if not token:
        raise ContractCheckError(
            "Set CANVAS_CREDENTIALS_API_TOKEN or CANVAS_CREDENTIALS_API_TOKEN_FILE for the read-only contract check."
        )
    return token


def clean_base_url(value: str) -> str:
    base_url = value.strip() or "https://api.badgr.io"
    if not base_url.startswith(("https://", "http://")):
        raise ContractCheckError(f"CANVAS_CREDENTIALS_API_BASE_URL must be an absolute URL: {base_url}")
    return base_url.rstrip("/") + "/"


def entity_for_scope(values: dict[str, str], scope: str) -> tuple[str, str]:
    if scope == "badgeclasses":
        badgeclass_id = values.get("CANVAS_CREDENTIALS_BADGECLASS_ID", "").strip()
        if not badgeclass_id:
            raise ContractCheckError("CANVAS_CREDENTIALS_BADGECLASS_ID is required for badgeclasses scope.")
        return "badgeclass_id", badgeclass_id

    if scope == "issuers":
        issuer_id = values.get("CANVAS_CREDENTIALS_ISSUER_ID", "").strip()
        if not issuer_id:
            raise ContractCheckError("CANVAS_CREDENTIALS_ISSUER_ID is required for issuers scope.")
        return "issuer_id", issuer_id

    raise ContractCheckError(
        f"Unsupported CANVAS_CREDENTIALS_ASSERTION_SCOPE={scope!r}. Expected badgeclasses or issuers."
    )


def validation_path(scope: str, entity_id: str) -> str:
    if scope == "badgeclasses":
        return f"v2/badgeclasses/{entity_id}"
    return f"v2/issuers/{entity_id}"


def assertions_path(scope: str, entity_id: str) -> str:
    return f"v2/{scope}/{entity_id}/assertions"


def api_get(url: str, token: str, timeout: int) -> ApiResponse:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "ElevenID-CanvasCredentialsContractCheck/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return ApiResponse(
                url=url,
                status=response.status,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=parse_json(raw),
            )
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        return ApiResponse(
            url=url,
            status=error.code,
            headers={key.lower(): value for key, value in error.headers.items()},
            body=parse_json(raw),
        )
    except urllib.error.URLError as error:
        raise ContractCheckError(f"Failed to reach Canvas Credentials API at {url}: {error}") from error


def parse_json(raw: str) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw[:1000]}


def response_summary(response: ApiResponse) -> dict[str, Any]:
    body = response.body
    if isinstance(body, dict):
        body_keys: list[str] | None = sorted(body.keys())[:20]
        body_type = "object"
    elif isinstance(body, list):
        body_keys = None
        body_type = "array"
    elif body is None:
        body_keys = None
        body_type = "empty"
    else:
        body_keys = None
        body_type = type(body).__name__

    return {
        "url": response.url,
        "status": response.status,
        "request_id": response.headers.get("x-request-id")
        or response.headers.get("x-correlation-id")
        or response.headers.get("traceparent"),
        "body_type": body_type,
        "body_keys": body_keys,
    }


def require_success(response: ApiResponse, label: str) -> None:
    if 200 <= response.status < 300:
        return

    body = response.body
    detail = body
    if isinstance(body, dict):
        detail = body.get("error_description") or body.get("message") or body.get("error") or body
    raise ContractCheckError(f"{label} returned HTTP {response.status}: {detail}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a read-only Canvas Credentials API contract check for ElevenID mirror delivery."
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Optional env file to read after process env. Values in the file override process env.",
    )
    parser.add_argument(
        "--list-assertions",
        action="store_true",
        help="Also check the read-only assertions collection endpoint for the configured scope.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON only.",
    )
    return parser


def run_check(args: argparse.Namespace) -> dict[str, Any]:
    values = merged_env(args.env_file)
    token = read_token(values)
    base_url = clean_base_url(values.get("CANVAS_CREDENTIALS_API_BASE_URL", "https://api.badgr.io"))
    scope = values.get("CANVAS_CREDENTIALS_ASSERTION_SCOPE", "badgeclasses").strip() or "badgeclasses"
    entity_label, entity_id = entity_for_scope(values, scope)

    provider = values.get("CANVAS_CREDENTIALS_PROVIDER", "").strip() or "badgr_api"
    if provider != "badgr_api":
        raise ContractCheckError(
            f"CANVAS_CREDENTIALS_PROVIDER must be badgr_api for the real contract check, got {provider!r}."
        )

    validation_url = urljoin(base_url, validation_path(scope, entity_id))
    validation_response = api_get(validation_url, token, args.timeout)
    require_success(validation_response, "Canvas Credentials validation endpoint")

    result: dict[str, Any] = {
        "ok": True,
        "provider": provider,
        "base_url": base_url.rstrip("/"),
        "scope": scope,
        entity_label: entity_id,
        "validation": response_summary(validation_response),
    }

    if args.list_assertions:
        query = urlencode({"limit": "1"})
        assertions_url = urljoin(base_url, assertions_path(scope, entity_id)) + f"?{query}"
        assertions_response = api_get(assertions_url, token, args.timeout)
        require_success(assertions_response, "Canvas Credentials assertions collection endpoint")
        result["assertions_collection"] = response_summary(assertions_response)

    return result


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        result = run_check(args)
    except ContractCheckError as error:
        if args.json:
            print(json.dumps({"ok": False, "error": str(error)}, indent=2, sort_keys=True))
        else:
            print(f"Canvas Credentials contract check failed: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Canvas Credentials contract check passed.")
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
