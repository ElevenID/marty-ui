#!/usr/bin/env python3
"""Stage an idempotent bootstrap repair for one pinned legacy image.

This tool only writes two patched source files to a new local directory. It does
not build an image, connect to a database, or modify a running service.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess


IMAGE = "sha256:ad580a7eb66b452e631c16e537dbd1f1952672f9903d1dbac119ac9fe0f87a6b"
INPUT_HASHES = {
    "main.py": "c501ac5db031118bf33f38c34193efaa63ddc519a4c9f0652c2de01ac45bfb09",
    "postgres_adapter.py": "6cc02591dc59fabf3c8a5c2f143708a1227afa81dcf12d2668200638f50682f6",
}


class GuardError(Exception):
    pass


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise GuardError("SOURCE_ANCHOR_MISMATCH")
    return source.replace(old, new, 1)


def transform(image: str, inputs: dict[str, bytes]) -> dict[str, bytes]:
    if image != IMAGE or set(inputs) != set(INPUT_HASHES):
        raise GuardError("IMAGE_OR_SOURCE_SET_MISMATCH")
    for name, expected in INPUT_HASHES.items():
        if hashlib.sha256(inputs[name]).hexdigest() != expected:
            raise GuardError("DEPLOYED_SOURCE_HASH_MISMATCH")
    line_endings = {}
    sources = {}
    for name, payload in inputs.items():
        raw = payload.decode("utf-8")
        if raw.count("\n") != raw.count("\r\n"):
            raise GuardError("DEPLOYED_LINE_ENDINGS_CHANGED")
        line_endings[name] = "\r\n"
        sources[name] = raw.replace("\r\n", "\n")
    main, adapter = sources["main.py"], sources["postgres_adapter.py"]
    adapter = replace_once(adapter, "from sqlalchemy import delete, select\n",
                           "from sqlalchemy import delete, select, text\n")

    save_signature = '    async def save(self, profile: "RevocationProfile") -> None:\n'
    session_anchor = "        async with self._session_factory() as session:\n"
    if adapter.count(save_signature) != 1 or adapter.count(session_anchor) < 1:
        raise GuardError("SOURCE_ANCHOR_MISMATCH")
    save_start = adapter.index(save_signature)
    session_start = adapter.index(session_anchor, save_start)
    serializer = adapter[save_start + len(save_signature):session_start]
    if serializer.count("        row_data = {\n") != 1:
        raise GuardError("SERIALIZER_SHAPE_MISMATCH")
    replacement = (
        '    @staticmethod\n'
        '    def _profile_row_data(profile: "RevocationProfile") -> dict:\n'
        + serializer
        + '        return row_data\n\n'
        + save_signature
        + '        row_data = self._profile_row_data(profile)\n\n'
    )
    adapter = adapter[:save_start] + replacement + adapter[session_start:]

    ensure_method = '''    async def ensure_system_default(self, profile: "RevocationProfile") -> bool:
        """Insert once for the legacy system scope; preserve any existing rows."""
        if profile.organization_id != "system" or profile.name != "Auto Revocation (Default)":
            raise ValueError("SYSTEM_DEFAULT_SCOPE_MISMATCH")
        async with self._session_factory() as session:
            async with session.begin():
                await session.execute(text("SET LOCAL lock_timeout = '10s'"))
                await session.execute(text("SELECT pg_advisory_xact_lock(735119, 1)"))
                existing_id = await session.scalar(
                    select(revocation_profiles_table.c.id).where(
                        revocation_profiles_table.c.organization_id == "system",
                        revocation_profiles_table.c.name == "Auto Revocation (Default)",
                    ).limit(1)
                )
                if existing_id is not None:
                    return False
                row_data = self._profile_row_data(profile)
                row_data["id"] = profile.id
                row_data["created_at"] = profile.created_at
                await session.execute(revocation_profiles_table.insert().values(**row_data))
                return True

'''
    adapter = replace_once(adapter, '    async def get(self, profile_id: str) -> "RevocationProfile | None":\n',
                           ensure_method + '    async def get(self, profile_id: str) -> "RevocationProfile | None":\n')

    startup_old = '''    await _repo.save(default_profile)
    logger.info(f"Created default RevocationProfile: {default_profile.id}")
'''
    startup_new = '''    if isinstance(_repo, InMemoryRevocationProfileRepository):
        created = not any(
            p.name == default_profile.name for p in await _repo.list(default_profile.organization_id)
        )
        if created:
            await _repo.save(default_profile)
    else:
        created = await _repo.ensure_system_default(default_profile)
    logger.info("Ensured default RevocationProfile (created=%s)", created)
'''
    main = replace_once(main, startup_old, startup_new)
    ast.parse(main, filename="main.py")
    ast.parse(adapter, filename="postgres_adapter.py")
    return {"main.py": main.replace("\n", line_endings["main.py"]).encode("utf-8"),
            "postgres_adapter.py": adapter.replace("\n", line_endings["postgres_adapter.py"]).encode("utf-8")}


def check_local_image() -> None:
    try:
        result = subprocess.run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"],
                                capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardError("PINNED_IMAGE_INSPECTION_UNKNOWN") from exc
    if result.returncode or result.stdout.strip() != IMAGE:
        raise GuardError("PINNED_IMAGE_NOT_PRESENT")


def stage(source_dir: Path, output_dir: Path) -> dict:
    check_local_image()
    if not source_dir.is_dir() or source_dir.is_symlink():
        raise GuardError("SOURCE_DIRECTORY_INVALID")
    if output_dir.exists() or output_dir.is_symlink():
        raise GuardError("OUTPUT_ALREADY_EXISTS")
    if any(not (source_dir / name).is_file() or (source_dir / name).is_symlink()
           for name in INPUT_HASHES):
        raise GuardError("SOURCE_FILE_INVALID")
    try:
        inputs = {name: (source_dir / name).read_bytes() for name in INPUT_HASHES}
    except OSError as exc:
        raise GuardError("SOURCE_READ_UNKNOWN") from exc
    outputs = transform(IMAGE, inputs)
    output_dir.mkdir(mode=0o700)
    for name, payload in outputs.items():
        with (output_dir / name).open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    receipt = {"image": IMAGE, "inputSha256": INPUT_HASHES,
               "outputSha256": {name: hashlib.sha256(payload).hexdigest()
                                for name, payload in outputs.items()},
               "productionMutation": False, "imageBuilt": False}
    with (output_dir / "receipt.json").open("x", encoding="utf-8") as handle:
        json.dump(receipt, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return receipt


def main_cli() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = stage(args.source_dir, args.output_dir)
    except GuardError as exc:
        print(json.dumps({"state": str(exc), "mutation": False}))
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
