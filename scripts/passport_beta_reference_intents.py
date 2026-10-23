#!/usr/bin/env python3
"""Durable, fail-closed Gateway writes for beta passport reference setup."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable
from uuid import uuid4


Request = Callable[[str, str, dict[str, Any] | None, dict[str, str]],
                   tuple[int, Any]]
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
CREATE = {
    "/v1/credential-templates": ("credential", 200),
    "/v1/application-templates": ("application", 200),
    "/v1/delivery-destinations": ("destination", 201),
    "/v1/flows/definitions": ("flow", 200),
}
ACTIVATE = re.compile(
    r"/v1/(credential-templates|application-templates|flows/definitions)"
    r"/([A-Za-z0-9_-]{1,128})/activate\Z"
)
PAGE_SIZE = 10


class ReferenceIntentError(ValueError):
    pass


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise ReferenceIntentError(message)


def _bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(_bytes(value))
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise ReferenceIntentError("Beta reference intent could not be sealed") from error


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise ReferenceIntentError("Beta reference intent is unreadable") from error
    _require(isinstance(value, dict), "Beta reference intent is invalid")
    return value


class DurableReferenceRequests:
    """Reconcile an attempted write by exact name; never replay an uncertain POST."""

    def __init__(self, request: Request, intent_dir: Path, *,
                 source_commit: str, gateway_container_id: str,
                 organization_id: str, allow_new: bool = True) -> None:
        _require(intent_dir.is_absolute()
                 and re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None
                 and re.fullmatch(r"[0-9a-f]{64}", gateway_container_id) is not None
                 and IDENTIFIER.fullmatch(organization_id) is not None,
                 "Beta reference intent context is invalid")
        self.request = request
        self.intent_dir = intent_dir
        self.source_commit = source_commit
        self.gateway_container_id = gateway_container_id
        self.organization_id = organization_id
        self.allow_new = allow_new

    def _call(self, method: str, path: str, body: dict[str, Any] | None,
              headers: dict[str, str], expected: int) -> Any:
        status, result = self.request(method, path, body, headers)
        _require(status == expected and isinstance(result, (dict, list)),
                 "Beta reference Gateway response is invalid")
        return result

    def _matches(self, path: str, name: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        if path == "/v1/delivery-destinations":
            query = f"?organization_id={self.organization_id}&active_only=false"
            result = self._call("GET", path + query, None, {}, 200)
            _require(isinstance(result, list), "Beta destination list is invalid")
            pages = [result]
        elif path == "/v1/application-templates":
            result = self._call("GET", path + f"?organization_id={self.organization_id}",
                                None, {}, 200)
            _require(isinstance(result, list), "Beta application list is invalid")
            pages = [result]
        else:
            pages = []
            for offset in range(0, 50_000, PAGE_SIZE):
                result = self._call(
                    "GET", path + f"?organization_id={self.organization_id}"
                    f"&limit={PAGE_SIZE}&offset={offset}", None, {}, 200,
                )
                _require(isinstance(result, list) and len(result) <= PAGE_SIZE,
                         "Beta reference page is invalid")
                pages.append(result)
                if len(result) < PAGE_SIZE:
                    break
            else:
                raise ReferenceIntentError("Beta reference list exceeds safe bound")
        for page in pages:
            for item in page:
                _require(isinstance(item, dict), "Beta reference list item is invalid")
                if item.get("name") == name:
                    matches.append(item)
        _require(len(matches) <= 1, "Beta reference name is ambiguous")
        return matches

    def _intent(self, key: str, expected: dict[str, Any]) -> bool:
        path = self.intent_dir / (key + ".json")
        if path.exists():
            _require(_read(path) == expected, "Beta reference intent changed")
            return True
        _write_new(path, expected)
        return False

    def _create(self, path: str, body: dict[str, Any],
                headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        key, status = CREATE[path]
        _require(body.get("organization_id") == self.organization_id
                 and isinstance(body.get("name"), str)
                 and bool(body["name"].strip()),
                 "Beta reference creation context is invalid")
        marker = self.intent_dir / (key + ".json")
        existing = marker.exists()
        destination_id = (_read(marker).get("destination_id") if existing
                          else str(uuid4())) if key == "destination" else None
        expected = {
            "schema": "marty.passport-beta-reference-intent/v1",
            "source_commit": self.source_commit,
            "gateway_container_id": self.gateway_container_id,
            "organization_id": self.organization_id,
            "path": path,
            "body_sha256": hashlib.sha256(_bytes(body)).hexdigest(),
            "headers_sha256": hashlib.sha256(_bytes(headers)).hexdigest(),
            "name": body["name"],
        }
        if destination_id is not None:
            expected["destination_id"] = destination_id
        if existing:
            _require(_read(marker) == expected, "Beta reference intent changed")
        matches = self._matches(path, body["name"])
        if existing:
            _require(len(matches) == 1, "Attempted beta reference has no unique row")
            result = matches[0]
        else:
            _require(self.allow_new, "New beta reference writes are closed")
            _require(not matches, "Unowned beta reference name already exists")
            self._intent(key, expected)
            posted = dict(body)
            if destination_id is not None:
                posted["id"] = destination_id
            result = self._call("POST", path, posted, headers, status)
            _require(isinstance(result, dict), "Beta reference create result is invalid")
            if key != "destination":
                _require(result.get("status") == "DRAFT",
                         "Fresh beta reference creation was not draft")
        _require(result.get("organization_id") == self.organization_id
                 and result.get("name") == body["name"]
                 and isinstance(result.get("id"), str)
                 and IDENTIFIER.fullmatch(result["id"]) is not None
                 and (destination_id is None or result["id"] == destination_id),
                 "Beta reference create identity drifted")
        if existing and key != "destination" and result.get("status") == "ACTIVE":
            activation_key = {
                "credential": "credential-templates-activate",
                "application": "application-templates-activate",
                "flow": "flows-definitions-activate",
            }[key]
            activation = self.intent_dir / (activation_key + ".json")
            expected_activation = {
                "schema": "marty.passport-beta-reference-activation-intent/v1",
                "source_commit": self.source_commit,
                "gateway_container_id": self.gateway_container_id,
                "organization_id": self.organization_id,
                "path": f"{path}/{result['id']}/activate",
                "id": result["id"],
            }
            _require(activation.is_file() and _read(activation) == expected_activation,
                     "Active beta reference has no activation intent")
        return status, result

    def _activate(self, path: str, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        match = ACTIVATE.fullmatch(path)
        _require(match is not None, "Beta reference activation route is invalid")
        item_path = path.removesuffix("/activate")
        current = self._call("GET", item_path, None, {}, 200)
        _require(isinstance(current, dict)
                 and current.get("id") == match.group(2)
                 and current.get("organization_id") == self.organization_id,
                 "Beta reference activation target drifted")
        key = match.group(1).replace("/", "-") + "-activate"
        expected = {
            "schema": "marty.passport-beta-reference-activation-intent/v1",
            "source_commit": self.source_commit,
            "gateway_container_id": self.gateway_container_id,
            "organization_id": self.organization_id,
            "path": path,
            "id": current["id"],
        }
        marker = self.intent_dir / (key + ".json")
        if marker.exists():
            _require(_read(marker) == expected and current.get("status") == "ACTIVE",
                     "Attempted beta reference activation is unresolved")
            return 200, current
        _require(self.allow_new, "New beta reference writes are closed")
        _require(current.get("status") == "DRAFT",
                 "Beta reference activation target is not draft")
        self._intent(key, expected)
        result = self._call("POST", path, None, headers, 200)
        _require(isinstance(result, dict) and result.get("id") == current["id"]
                 and result.get("status") == "ACTIVE",
                 "Beta reference activation response drifted")
        return 200, result

    def __call__(self, method: str, path: str, body: dict[str, Any] | None,
                 headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        _require(method in ("GET", "POST") and isinstance(headers, dict),
                 "Beta reference route is invalid")
        if method == "POST" and path in CREATE:
            _require(isinstance(body, dict), "Beta reference body is invalid")
            return self._create(path, body, headers)
        if method == "POST" and ACTIVATE.fullmatch(path):
            return self._activate(path, headers)
        _require(method == "GET" or (method == "POST" and path.endswith("/validate")),
                 "Beta reference route is invalid")
        result = self._call(method, path, body, headers, 200)
        _require(isinstance(result, dict), "Beta reference item response is invalid")
        return 200, result
