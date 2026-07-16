#!/usr/bin/env python3
"""Download protected wallet evidence attachments and verify their content hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


KIND_RE = re.compile(r"^[a-z0-9_]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024 * 1024


class AttachmentError(ValueError):
    pass


class HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme != "https":
            raise HTTPError(newurl, code, "Protected evidence redirect must remain HTTPS", headers, fp)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and urlparse(req.full_url).netloc != urlparse(newurl).netloc:
            redirected.remove_header("Authorization")
        return redirected


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttachmentError(f"Could not read JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AttachmentError(f"{path} must contain a JSON object")
    return value


def verify_attachments(
    evidence: dict[str, Any],
    requirements: dict[str, Any],
    output_dir: Path,
    *,
    bearer_token: str = "",
    evidence_content_sha256: str,
    opener=None,
) -> dict[str, Any]:
    if evidence.get("schema_version") != requirements.get("schema_version"):
        raise AttachmentError("Wallet evidence schema version mismatch")
    if evidence.get("mip_version") != requirements.get("mip_version"):
        raise AttachmentError("Wallet evidence MIP version mismatch")
    required_kinds = requirements.get("required_attachment_kinds") or []
    attachments = evidence.get("attachments") or []
    if not isinstance(attachments, list):
        raise AttachmentError("attachments must be an array")
    by_kind: dict[str, dict[str, Any]] = {}
    for attachment in attachments:
        if not isinstance(attachment, dict):
            raise AttachmentError("Each protected attachment must be an object")
        kind = str(attachment.get("kind") or "")
        if not KIND_RE.fullmatch(kind):
            raise AttachmentError(f"Invalid protected attachment kind: {kind}")
        if kind in by_kind:
            raise AttachmentError(f"Duplicate protected attachment: {kind}")
        by_kind[kind] = attachment
    if set(by_kind) != set(required_kinds):
        raise AttachmentError("Protected attachment set does not match requirements")

    output_dir.mkdir(parents=True, exist_ok=True)
    client = opener or build_opener(HTTPSOnlyRedirectHandler())
    verified: list[dict[str, Any]] = []
    for kind in required_kinds:
        attachment = by_kind[kind]
        uri = str(attachment.get("uri") or "")
        expected_sha = str(attachment.get("sha256") or "")
        if urlparse(uri).scheme != "https" or not urlparse(uri).netloc:
            raise AttachmentError(f"Attachment {kind} must use HTTPS")
        if not SHA256_RE.fullmatch(expected_sha):
            raise AttachmentError(f"Attachment {kind} SHA-256 is invalid")

        headers = {"User-Agent": "ElevenID-Wallet-Evidence-Verifier/1.0"}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        request = Request(uri, headers=headers)
        destination = output_dir / f"{kind}.evidence"
        temporary = output_dir / f".{kind}.part"
        digest = hashlib.sha256()
        size = 0
        try:
            with client.open(request, timeout=120) as response, temporary.open("wb") as output:
                if urlparse(response.geturl()).scheme != "https":
                    raise AttachmentError(f"Attachment {kind} resolved outside HTTPS")
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_ATTACHMENT_BYTES:
                        raise AttachmentError(f"Attachment {kind} exceeds the 5 GiB safety limit")
                    digest.update(chunk)
                    output.write(chunk)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        actual_sha = digest.hexdigest()
        if not size:
            temporary.unlink(missing_ok=True)
            raise AttachmentError(f"Attachment {kind} is empty")
        if actual_sha != expected_sha:
            temporary.unlink(missing_ok=True)
            raise AttachmentError(f"Attachment {kind} checksum mismatch")
        temporary.replace(destination)
        verified.append({
            "kind": kind,
            "uri": uri,
            "sha256": actual_sha,
            "size_bytes": size,
            "verified": True,
        })

    return {
        "schema_version": 1,
        "evidence_content_sha256": evidence_content_sha256,
        "attachments": verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    evidence = _load_object(args.evidence)
    requirements = _load_object(args.requirements)
    result = verify_attachments(
        evidence,
        requirements,
        args.output_dir,
        bearer_token=os.environ.get("WALLET_EVIDENCE_BEARER_TOKEN", ""),
        evidence_content_sha256=hashlib.sha256(args.evidence.read_bytes()).hexdigest(),
    )
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AttachmentError as exc:
        raise SystemExit(f"wallet attachment verification failed: {exc}") from exc
