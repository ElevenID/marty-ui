#!/usr/bin/env python3
"""Exercise a built gateway's public contract without service startup or credentials."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_document(document, release_version, protocol_revision):
    require(document.get("openapi") == "3.1.0", "Wrong OpenAPI version")
    require(document.get("info", {}).get("version") == release_version, "Release label differs")
    require(document.get("x-marty-protocol-revision") == protocol_revision, "Protocol revision differs")
    schemes = document["components"]["securitySchemes"]
    require(all(schemes["apiKeyAuth"].get(k) == v for k, v in {
        "type": "apiKey", "in": "header", "name": "X-API-Key"}.items()), "API-key scheme differs")
    require(schemes["bearerAuth"].get("bearerFormat") == "Marty API key", "Bearer scheme misrepresents machine auth")
    operations = []
    for item in document["paths"].values():
        operations.extend(operation for method, operation in item.items()
                          if method in {"get", "post", "put", "patch", "delete", "head", "options", "trace"})
    identifiers = [operation["operationId"] for operation in operations]
    require(identifiers and len(set(identifiers)) == len(identifiers), "Operation IDs are empty or ambiguous")

    def walk(value):
        if isinstance(value, list):
            for child in value:
                walk(child)
        elif isinstance(value, dict):
            for key, child in value.items():
                if key == "$ref":
                    require(isinstance(child, str) and child.startswith("#/"), "Contract has an external reference")
                    target = document
                    try:
                        for part in unquote(child[2:]).split("/"):
                            part = part.replace("~1", "/").replace("~0", "~")
                            target = target[int(part)] if isinstance(target, list) else target[part]
                    except (KeyError, IndexError, ValueError, TypeError):
                        raise ValueError("Contract has an unresolved reference") from None
                else:
                    walk(child)

    walk(document)
    create = document["paths"]["/v1/api-keys"]["post"]
    require(create["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/runtime__api_key_create_request"}, "API-key request type differs")
    require("delete" in document["paths"]["/v1/api-keys/{key_id}"], "Key retirement is missing")
    return {
        "operations": len(operations), "schemas": len(document["components"]["schemas"]),
        "request_schema_not_marked_documented": sum(o.get("x-marty-request-schema-documented") is not True for o in operations),
        "response_schema_not_marked_documented": sum(o.get("x-marty-response-schema-documented") is not True for o in operations),
    }


def absent(result):
    return result.returncode != 0 and any(
        phrase in result.stderr.lower() for phrase in (b"no such object", b"no such container"))


def cleanup_owned(name, nonce):
    result = subprocess.run(["docker", "container", "inspect", name], capture_output=True, timeout=15, check=False)
    if absent(result):
        return
    require(result.returncode == 0, f"Cannot inspect owned contract probe {name}")
    details = json.loads(result.stdout)
    require(len(details) == 1 and (details[0]["Config"].get("Labels") or {}).get("io.marty.contract-export-probe") == nonce,
            f"Preserve unowned contract probe name {name}")
    subprocess.run(["docker", "stop", "--time", "1", name], capture_output=True, timeout=15, check=True)
    result = subprocess.run(["docker", "container", "inspect", name], capture_output=True, timeout=15, check=False)
    require(absent(result), f"Owned contract probe removal is unconfirmed: {name}")


def run_probe(image, extra=()):
    nonce = uuid4().hex
    name = "marty-contract-export-" + nonce
    # Deliberately invalid provider configuration catches moving export behind
    # ordinary startup. No credentials, mounts, ports or network are supplied.
    command = ["docker", "run", "--rm", "--name", name,
               "--label", "io.marty.contract-export-probe=" + nonce,
               "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop=ALL",
               "--security-opt", "no-new-privileges", "--cpus", "1", "--memory", "512m",
               "--env", "DATABASE_URL=invalid-contract-export-database",
               "--env", "BAO_ADDR=https://invalid-contract-export.invalid",
               "--env", "GATEWAY_SIGN_GRANT_MINT_TOKEN_FILE=/not-mounted/contract-export-token",
               "--entrypoint", "/usr/local/bin/marty-gateway", image, "--export-openapi", *extra]
    try:
        return subprocess.run(command, capture_output=True, timeout=30, check=False)
    finally:
        cleanup_owned(name, nonce)


def check_image(image, expected_version, expected_source, protocol_revision, output):
    require(not image.startswith("-") and not any(c.isspace() for c in image), "Invalid image reference")
    require(re.fullmatch(r"[a-f0-9]{40}", expected_source), "Invalid expected source")
    require(re.fullmatch(r"[a-f0-9]{40}", protocol_revision), "Invalid protocol revision")
    require(not output.exists(), "Export output must be new")
    result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=15, check=True)
    details = json.loads(result.stdout)
    require(len(details) == 1, "Image selection is ambiguous")
    selected = details[0]
    labels = selected["Config"].get("Labels") or {}
    require(labels.get("org.opencontainers.image.revision") == expected_source, "Image source differs")
    require(labels.get("org.opencontainers.image.version") == expected_version, "Image version differs")
    # Resolve a mutable local CI tag once; every probe uses this exact image ID.
    image_id = selected["Id"]
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", image_id), "Invalid image identity")
    first, second = run_probe(image_id), run_probe(image_id)
    require(first.returncode == second.returncode == 0, "Offline gateway contract export failed")
    require(first.stdout == second.stdout and len(first.stdout) <= 16 * 1024 * 1024,
            "Contract export is nondeterministic or oversized")
    document = json.loads(first.stdout)
    summary = validate_document(document, expected_version, protocol_revision)
    require(b"invalid-contract-export" not in first.stdout and b"/not-mounted/" not in first.stdout,
            "Provider fixture configuration entered public output")
    invalid = run_probe(image_id, ["unexpected"])
    require(invalid.returncode != 0 and not invalid.stdout
            and b"--export-openapi accepts no additional arguments" in invalid.stderr,
            "Invalid export arguments were not refused before startup")
    with output.open("xb") as stream:
        stream.write(first.stdout)
    print(json.dumps({"image_id": image_id, "source_sha": expected_source,
                      "release_version": expected_version, "protocol_revision": protocol_revision,
                      **summary, "gateway_qualification": False}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--protocol-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    check_image(args.image, args.expected_version, args.expected_source, args.protocol_revision, args.output)
