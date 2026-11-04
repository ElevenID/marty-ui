#!/usr/bin/env python3
"""Transfer qualified native nightly tools within one producer run and attempt."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path

from stack_tag_gate import classify_release_tag

SCHEMA = "marty.nightly-native/v1"
FILES = ("package-selfhost-bundle", "marty-deploy-linux-amd64")
MANIFEST = "native-build.json"
LIMIT = 256 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def identity(source_sha: str, tag: str, run_id: str, attempt: str) -> dict:
    require(isinstance(source_sha, str) and re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None,
            "invalid native source")
    require(isinstance(run_id, str) and re.fullmatch(r"[1-9][0-9]*", run_id) is not None,
            "invalid native run ID")
    require(isinstance(attempt, str) and re.fullmatch(r"[1-9][0-9]*", attempt) is not None,
            "invalid native run attempt")
    require(classify_release_tag(tag)[0] == "nightly", "native transfer requires a nightly tag")
    return {"schema": SCHEMA, "repository": "ElevenID/marty-ui", "source_sha": source_sha,
            "tag": tag, "run_id": run_id, "run_attempt": attempt}


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pack(packager: Path, operator: Path, output: Path, *, source_sha: str,
         tag: str, run_id: str, attempt: str) -> str:
    document = identity(source_sha, tag, run_id, attempt)
    payloads = {}
    for name, path in zip(FILES, (packager, operator), strict=True):
        require(path.is_file() and not path.is_symlink(), "native tool must be a regular file")
        require(0 < path.stat().st_size <= LIMIT // 2, "invalid native tool size")
        require(bool(path.stat().st_mode & 0o111), "native tool is not executable")
        payloads[name] = path.read_bytes()
        require(0 < len(payloads[name]) <= LIMIT // 2, "invalid native tool snapshot")
    document["files"] = {name: {"sha256": digest(data), "size": len(data), "mode": 0o755}
                         for name, data in payloads.items()}
    payloads[MANIFEST] = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    # Exclusive output prevents a retry from overwriting another artifact.
    with output.open("xb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in payloads.items():
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | (0o644 if name == MANIFEST else 0o755)) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
    return digest(output.read_bytes())


def restore(archive_path: Path, output: Path, metadata: dict, *, artifact_id: str,
            archive_sha256: str, source_sha: str, tag: str, run_id: str, attempt: str) -> dict:
    expected = identity(source_sha, tag, run_id, attempt)
    require(isinstance(artifact_id, str) and re.fullmatch(r"[1-9][0-9]*", artifact_id) is not None,
            "invalid native artifact ID")
    require(isinstance(metadata, dict), "native artifact metadata must be an object")
    require(type(metadata.get("id")) is int and metadata["id"] == int(artifact_id),
            "native artifact ID differs")
    require(metadata.get("name") == f"nightly-native-{run_id}-{attempt}",
            "native artifact attempt or name differs")
    require(metadata.get("expired") is False, "native artifact is expired")
    producer = metadata.get("workflow_run")
    require(isinstance(producer, dict) and type(producer.get("id")) is int
            and producer["id"] == int(run_id) and producer.get("head_sha") == source_sha,
            "native artifact source or producer run differs")
    require(isinstance(archive_sha256, str) and
            re.fullmatch(r"sha256:[0-9a-f]{64}", archive_sha256) is not None,
            "invalid native archive digest")
    require(archive_path.is_file() and not archive_path.is_symlink(), "native archive is not regular")
    require(0 < archive_path.stat().st_size <= LIMIT, "native archive is too large or empty")
    data = archive_path.read_bytes()
    require(len(data) <= LIMIT and digest(data) == archive_sha256, "native archive digest differs")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        require(len(entries) == 3 and {item.filename for item in entries} == {*FILES, MANIFEST},
                "native archive inventory differs")
        require(sum(item.file_size for item in entries) <= LIMIT, "native expanded archive is too large")
        for item in entries:
            expected_mode = stat.S_IFREG | (0o644 if item.filename == MANIFEST else 0o755)
            require(item.create_system == 3 and item.external_attr >> 16 == expected_mode
                    and not item.flag_bits & 1, "native archive entry type or mode differs")
            require(0 < item.file_size <= (65536 if item.filename == MANIFEST else LIMIT // 2),
                    "native archive entry size is invalid")
        document = json.loads(archive.read(MANIFEST))
        require(isinstance(document, dict) and set(document) == set(expected) | {"files"},
                "native manifest fields differ")
        require(all(document.get(key) == value for key, value in expected.items()),
                "native manifest source or attempt differs")
        inventory = document["files"]
        require(isinstance(inventory, dict) and set(inventory) == set(FILES), "native manifest inventory differs")
        payloads = {name: archive.read(name) for name in FILES}
        for name, payload in payloads.items():
            require(inventory[name] == {"sha256": digest(payload), "size": len(payload), "mode": 0o755},
                    "native tool bytes or mode differ")
    require(not output.exists() and not output.is_symlink(), "native output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix=".nightly-native-", dir=output.parent))
    try:
        for name, payload in payloads.items():
            path = staged / name
            path.write_bytes(payload)
            path.chmod(0o755)
        (staged / MANIFEST).write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
        # The destination is owned by this job and must stay absent until all
        # bytes, source identity and original attempt have been admitted.
        require(not output.exists() and not output.is_symlink(), "native output appeared during restore")
        staged.rename(output)
    finally:
        if staged.exists():
            shutil.rmtree(staged)
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    pack_parser = sub.add_parser("pack")
    pack_parser.add_argument("--packager", type=Path, required=True)
    pack_parser.add_argument("--operator", type=Path, required=True)
    restore_parser = sub.add_parser("restore")
    restore_parser.add_argument("--archive", type=Path, required=True)
    restore_parser.add_argument("--artifact-json", type=Path, required=True)
    restore_parser.add_argument("--artifact-id", required=True)
    restore_parser.add_argument("--archive-sha256", required=True)
    for command in (pack_parser, restore_parser):
        command.add_argument("--source-sha", required=True)
        command.add_argument("--tag", required=True)
        command.add_argument("--run-id", required=True)
        command.add_argument("--attempt", required=True)
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    common = {name: getattr(args, name) for name in ("source_sha", "tag", "run_id", "attempt")}
    try:
        if args.operation == "pack":
            print(pack(args.packager, args.operator, args.output, **common))
        else:
            metadata = json.loads(args.artifact_json.read_bytes())
            restore(args.archive, args.output, metadata, artifact_id=args.artifact_id,
                    archive_sha256=args.archive_sha256, **common)
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(1, f"Nightly native transfer failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
