"""Exact-source CPython helper qualification; no database, HTTP, or real secrets.

Local mode loads a fixed immutable Git source. The pinned-image gate loads the
published module's source. Both require the same SHA256 and execute the original
selected AST nodes, not reimplementations. Full module import/network timeout
behavior is deliberately outside this helper boundary.
"""

import argparse
import ast
import asyncio
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import patch


SOURCE_SHA256 = "24f5c0f22c075af3a11abbb48be52bcc6535e0d4fc31e446f7fb218bfe40d679"
SOURCE_REF = "51f0a758a076777cb18a30b1db3f89c74ac23e01:services/issuance/infrastructure/adapters/canvas_credentials_adapter.py"
FUNCTIONS = {
    "_read_secret_value",
    "_canvas_credentials_metadata_sources",
    "_canvas_credentials_secret_reference",
    "_integration_secret_id_from_ref",
    "_canvas_credentials_secret_value",
}
CONSTANTS = {"_CANVAS_PUBLISH_TIMEOUT_SECONDS", "_CANVAS_STATUS_SYNC_TIMEOUT_SECONDS"}


def selected_code(source, names, node_type):
    tree = ast.parse(source)
    nodes = []
    found = set()
    for node in tree.body:
        if isinstance(node, node_type):
            name = (
                node.targets[0].id
                if isinstance(node, ast.Assign)
                and isinstance(node.targets[0], ast.Name)
                else getattr(node, "name", None)
            )
            if name in names:
                nodes.append(node)
                found.add(name)
    assert found == names, "exact source helper set must be present"
    future = ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0
    )
    return compile(
        ast.fix_missing_locations(ast.Module(body=[future, *nodes], type_ignores=[])),
        "published-canvas-provider-helpers",
        "exec",
    )


async def observe_secrets(source, cases):
    code = selected_code(source, FUNCTIONS, (ast.FunctionDef, ast.AsyncFunctionDef))
    observations = []
    for case in cases:
        file_calls, lookups = [], []

        def open_synthetic(path, mode, *, encoding):
            assert (
                path == "/synthetic/operator-token"
                and mode == "r"
                and encoding == "utf-8"
            )
            file_calls.append("operator-token")
            kind = case["file"]
            failures = {
                "missing": FileNotFoundError,
                "permission": PermissionError,
                "directory": IsADirectoryError,
            }
            if kind in failures:
                raise failures[kind]("synthetic file unavailable")
            if kind == "invalid_utf8":
                raise UnicodeDecodeError(
                    "utf-8", b"\xff", 0, 1, "synthetic invalid UTF-8"
                )
            return io.TextIOWrapper(
                io.BytesIO(
                    {
                        "value": "synthetic-file\n",
                        "empty": "",
                        "whitespace": "\x1c\u2003\n",
                        "unicode_value": "\x1c\u2003synthetic-file\u2003\x1c",
                        "mixed_newlines": " synthetic-first\r\nsecond\rthird\n ",
                    }[kind].encode("utf-8")
                ),
                encoding=encoding,
            )

        async def secret(organization, identifier):
            lookups.append({"organization_id": organization, "secret_id": identifier})
            return case.get("tenant_value")

        namespace = {"os": os, "open": open_synthetic}
        exec(code, namespace)
        environment = {}
        if "direct" in case:
            environment["CANVAS_CREDENTIALS_API_TOKEN"] = case["direct"]
        if "file" in case:
            environment["CANVAS_CREDENTIALS_API_TOKEN_FILE"] = (
                "/synthetic/operator-token"
            )
        with patch.dict(os.environ, environment, clear=True):
            try:
                value = await namespace["_canvas_credentials_secret_value"](
                    SimpleNamespace(
                        organization_id="org-review", metadata=case.get("metadata", {})
                    ),
                    default_secret_name="CANVAS_CREDENTIALS_API_TOKEN",
                    secret_resolver=secret,
                )
                result = {"value": value}
            except Exception as failure:
                result = {"error_class": type(failure).__name__}
        observations.append(
            {"name": case["name"], "files": file_calls, "secrets": lookups, **result}
        )
    return observations


def observe_timeouts(source, cases):
    code = selected_code(source, CONSTANTS, ast.Assign)
    observations = []
    for case in cases:
        environment = {}
        for key in ("publish", "status"):
            if key in case:
                name = "PUBLISH" if key == "publish" else "STATUS_SYNC"
                environment[f"CANVAS_CREDENTIALS_{name}_TIMEOUT_SECONDS"] = case[key]
        namespace = {"os": os}
        with patch.dict(os.environ, environment, clear=True):
            try:
                exec(code, namespace)
                result = {
                    "publish": namespace["_CANVAS_PUBLISH_TIMEOUT_SECONDS"].hex(),
                    "status": namespace["_CANVAS_STATUS_SYNC_TIMEOUT_SECONDS"].hex(),
                }
            except Exception as failure:
                result = {"error_class": type(failure).__name__}
        observations.append({"name": case["name"], **result})
    return observations


def run(source=None):
    if source is None:
        spec = importlib.util.find_spec(
            "issuance.infrastructure.adapters.canvas_credentials_adapter"
        )
        source = Path(spec.origin).read_text(encoding="utf-8")
    assert hashlib.sha256(source.encode()).hexdigest() == SOURCE_SHA256, (
        "published source provenance mismatch"
    )
    fixture = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "contracts/canvas-provider-configuration-scenarios.json"
        ).read_text(encoding="utf-8")
    )
    return {
        "source_sha256": SOURCE_SHA256,
        "boundary": "exact selected published AST helper bodies and ordered timeout assignments; synthetic environment, tenant resolver and file reader; no full module import or network timeout consumer",
        "secrets": asyncio.run(observe_secrets(source, fixture["secrets"])),
        "timeouts": observe_timeouts(source, fixture["timeouts"]),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repository", required=True)
    arguments = parser.parse_args()
    source = (
        subprocess.run(
            ["git", "show", SOURCE_REF],
            cwd=arguments.source_repository,
            check=True,
            capture_output=True,
        )
        .stdout.decode("utf-8")
        .replace("\r\n", "\n")
    )
    print(json.dumps(run(source), sort_keys=True))
