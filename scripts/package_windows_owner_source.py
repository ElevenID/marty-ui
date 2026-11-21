#!/usr/bin/env python3
"""Package or inspect an inert, exact-commit Windows owner source handoff.

This developer tool reads Git objects, never the working tree or deployment
inputs. It does not install source, execute exported code, update tasks, or
establish Windows custody, selected-anchor replay, or recovery admission.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

SCHEMA = "marty.windows-owner-source/v1"
MANIFEST = ".marty-windows-owner-source.json"
CATALOG = "deploy-config/bundles/selfhost.json"
EXTRA_ASSETS = (
    CATALOG,
    "scripts/recover-marty-after-reboot.ps1",
    "scripts/install-marty-boot-recovery.ps1",
    "scripts/deploy_website.py",
    "scripts/recover_product_services.py",
    "scripts/website_host_owner.py",
    "docs/windows-compose-recovery.md",
    "docs/windows-renewal-activation.md",
)
REQUIRED_MODULES = (
    "scripts/selfhost_windows_inputs.py",
    "scripts/selfhost_windows_renewal.py",
    "scripts/selfhost_windows_renewal_native.py",
    "scripts/selfhost_windows_selection.py",
    "scripts/selfhost_windows_recovery.py",
    "scripts/selfhost_windows_expired_origin.py",
)
LIMITS = {"files": 2048, "file_bytes": 4 * 1024 * 1024, "total_bytes": 64 * 1024 * 1024}
MAX_ARCHIVE_BYTES = LIMITS["total_bytes"] + 2 * 1024 * 1024
BOUNDARIES = {
    "release_authenticated": False,
    "windows_custody_qualified": False,
    "original_anchor_replayed": False,
    "active_callers_migrated": False,
    "credential_admission": False,
    "runtime_admission": False,
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def packed(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "Duplicate JSON key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def exact_sha(value, length):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value),
            "A full lowercase object digest is required")
    return value


def safe_name(value):
    require(type(value) is str and 0 < len(value) <= 240
            and re.fullmatch(r"[A-Za-z0-9_./-]+", value), "Unsafe source asset path")
    for part in value.split("/"):
        require(part not in {"", ".", ".."} and not part.endswith(".")
                and part.split(".", 1)[0].upper() not in
                {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                 *(f"LPT{i}" for i in range(1, 10))}, "Unsafe Windows source asset path")
    return value


def closed_names(names):
    require(0 < len(names) <= LIMITS["files"], "Source inventory exceeds file limit")
    seen = set()
    for name in names:
        key = safe_name(name).casefold()
        require(key != MANIFEST.casefold() and not key.startswith(MANIFEST.casefold() + "/"),
                "Source asset overlaps the reserved manifest namespace")
        require(key not in seen, "Duplicate or case-colliding source asset")
        seen.add(key)
    require(all(not any("/".join(name.split("/")[:n]) in seen
                        for n in range(1, len(name.split("/")))) for name in seen),
            "Source file overlaps a directory")


def git(repository, *arguments, input_bytes=None):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(repository), *arguments],
                            input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=environment, timeout=60, check=False)
    require(result.returncode == 0, "Exact Git source object is unavailable")
    return result.stdout


def object_inventory(repository, commit):
    exact_sha(commit, 40)
    require(git(repository, "cat-file", "-t", commit).strip() == b"commit",
            "Source must name a commit, not a tag or tree")
    tree = git(repository, "rev-parse", commit + "^{tree}").decode("ascii").strip()
    exact_sha(tree, 40)
    entries = {}
    for item in git(repository, "ls-tree", "-rlz", "--full-tree", commit).split(b"\0"):
        if not item:
            continue
        metadata, name = item.split(b"\t", 1)
        mode, kind, oid, size = metadata.split()
        name = name.decode("utf-8")
        require(name not in entries, "Duplicate Git tree path")
        entries[name] = {"mode": mode.decode("ascii"), "kind": kind.decode("ascii"),
                         "git_blob": oid.decode("ascii"),
                         "bytes": int(size) if size != b"-" else -1}
    return tree, entries


def read_blobs(repository, entries):
    closed_names(entries)
    require(all(item["mode"] in {"100644", "100755"} and item["kind"] == "blob"
                and type(item["bytes"]) is int and 0 <= item["bytes"] <= LIMITS["file_bytes"]
                for item in entries.values()), "Source contains a special or oversized Git asset")
    require(sum(item["bytes"] for item in entries.values()) <= LIMITS["total_bytes"],
            "Source payload exceeds size limit")
    for item in entries.values():
        exact_sha(item["git_blob"], 40)
    request = "".join(item["git_blob"] + "\n" for item in entries.values()).encode("ascii")
    response = io.BytesIO(git(repository, "cat-file", "--batch", input_bytes=request))
    bodies = {}
    for name, item in entries.items():
        expected = f'{item["git_blob"]} blob {item["bytes"]}\n'.encode("ascii")
        require(response.readline() == expected, "Git blob inventory changed")
        raw = response.read(item["bytes"])
        require(len(raw) == item["bytes"] and response.read(1) == b"\n", "Truncated Git blob")
        require(blob_digest(raw) == item["git_blob"], "Git blob digest differs")
        bodies[name] = raw
    require(response.read(1) == b"", "Unexpected Git blob response")
    return bodies


def blob_digest(raw):
    # This is Git's SHA-1 object identifier, not a release/authentication proof.
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def selected_assets(catalog_raw, names):
    catalog = strict_json(catalog_raw)
    require(type(catalog) is dict and type(catalog.get("schema_version")) is int
            and catalog["schema_version"] == 1 and catalog.get("name") == "selfhost"
            and type(catalog.get("assets")) is list, "Unsupported selfhost asset catalog")
    declared = catalog["assets"]
    closed_names(declared)
    selected = set()
    for name in declared:
        matches = {item for item in names if item == name or item.startswith(name + "/")}
        require(matches, "Selfhost catalog asset is absent from source")
        require(not (matches & selected), "Overlapping source asset declarations")
        selected.update(matches)
    selected.update(EXTRA_ASSETS)
    require(set(REQUIRED_MODULES) <= selected and selected <= set(names),
            "Windows owner entrypoint or wrapper is absent")
    closed_names(selected)
    return sorted(selected)


def local_imports(bodies, known_modules):
    """Match the existing selfhost catalog's static local-module closure rule."""
    result = {}
    for name, raw in bodies.items():
        if not name.startswith("scripts/") or not name.endswith(".py"):
            continue
        source = ast.parse(raw, filename=name)
        imports = set()
        for node in ast.walk(source):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            elif isinstance(node, ast.Import):
                modules = [item.name for item in node.names]
            else:
                continue
            for module in modules:
                candidate = "scripts/" + module.split(".", 1)[0] + ".py"
                if candidate in known_modules:
                    require(candidate in bodies, "Selfhost catalog omits a local Python import")
                    imports.add(candidate)
        result[name] = sorted(imports)
    return result


def archive_bytes(repository, commit):
    tree, entries = object_inventory(repository, commit)
    require(CATALOG in entries, "Selfhost catalog is absent")
    catalog = read_blobs(repository, {CATALOG: entries[CATALOG]})[CATALOG]
    names = selected_assets(catalog, entries)
    bodies = read_blobs(repository, {name: entries[name] for name in names})
    imports = local_imports(bodies, entries)
    manifest = {
        "schema": SCHEMA, "source_commit": commit, "source_tree": tree,
        "catalog": {"path": CATALOG, "sha256": digest(catalog)},
        "extra_assets": list(EXTRA_ASSETS), "local_imports": imports,
        "files": {name: {"git_blob": entries[name]["git_blob"], "mode": entries[name]["mode"],
                          "bytes": len(raw), "sha256": digest(raw)} for name, raw in bodies.items()},
        "boundaries": BOUNDARIES,
    }
    return zip_bytes(commit, {**bodies, MANIFEST: packed(manifest)},
                     {**{name: entries[name]["mode"] for name in bodies}, MANIFEST: "100644"})


def zip_bytes(commit, bodies, modes):
    prefix = "windows-owner-source-" + commit + "/"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(bodies.items()):
            member = zipfile.ZipInfo(prefix + name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = int(modes[name], 8) << 16
            archive.writestr(member, raw)
    raw = buffer.getvalue()
    require(len(raw) <= MAX_ARCHIVE_BYTES, "Source archive exceeds size limit")
    return raw


def inspect_archive(raw, expected_sha256, expected_commit):
    exact_sha(expected_sha256, 64)
    exact_sha(expected_commit, 40)
    require(type(raw) is bytes and len(raw) <= MAX_ARCHIVE_BYTES
            and digest(raw) == expected_sha256, "Source archive digest differs")
    prefix = "windows-owner-source-" + expected_commit + "/"
    bodies, modes = {}, {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(not archive.comment and len(archive.infolist()) <= LIMITS["files"] + 1,
                "Unexpected or excessive source archive members")
        total = 0
        for member in archive.infolist():
            require(member.filename.startswith(prefix), "Source archive has a different commit root")
            name = safe_name(member.filename[len(prefix):])
            mode = member.external_attr >> 16
            require(name not in bodies and not member.is_dir() and not member.extra and not member.comment
                    and member.create_system == 3 and mode in {stat.S_IFREG | 0o644, stat.S_IFREG | 0o755}
                    and member.compress_type == zipfile.ZIP_STORED and not member.flag_bits
                    and member.date_time == (1980, 1, 1, 0, 0, 0)
                    and member.file_size == member.compress_size
                    and member.file_size <= LIMITS["file_bytes"], "Invalid source archive member")
            total += member.file_size
            require(total <= LIMITS["total_bytes"] + LIMITS["file_bytes"], "Source archive payload is too large")
            bodies[name] = archive.read(member)
            modes[name] = format(mode, "06o")
    require(MANIFEST in bodies, "Source manifest is absent")
    manifest_raw = bodies.pop(MANIFEST)
    require(modes.pop(MANIFEST) == "100644", "Source manifest mode differs")
    closed_names(bodies)
    require(sum(map(len, bodies.values())) <= LIMITS["total_bytes"], "Source payload exceeds size limit")
    manifest = strict_json(manifest_raw)
    require(type(manifest) is dict and set(manifest) == {
        "schema", "source_commit", "source_tree", "catalog", "extra_assets", "local_imports", "files", "boundaries"}
        and manifest_raw == packed(manifest) and manifest["schema"] == SCHEMA
        and manifest["source_commit"] == expected_commit, "Invalid or stale source manifest")
    exact_sha(manifest["source_tree"], 40)
    require(manifest["boundaries"] == BOUNDARIES
            and all(value is False for value in manifest["boundaries"].values())
            and manifest["extra_assets"] == list(EXTRA_ASSETS)
            and type(manifest["files"]) is dict and set(manifest["files"]) == set(bodies),
            "Source manifest inventory or admission boundary differs")
    require(CATALOG in bodies and manifest["catalog"] == {"path": CATALOG, "sha256": digest(bodies[CATALOG])},
            "Source catalog binding differs")
    require(selected_assets(bodies[CATALOG], bodies) == sorted(bodies), "Source archive inventory is incomplete")
    require(manifest["local_imports"] == local_imports(bodies, bodies), "Source import inventory differs")
    for name, body in bodies.items():
        require(manifest["files"][name] == {"git_blob": blob_digest(body), "mode": modes[name],
                    "bytes": len(body), "sha256": digest(body)}
                and type(manifest["files"][name].get("bytes")) is int,
                "Source file differs from exact inventory")
    require(raw == zip_bytes(expected_commit, {**bodies, MANIFEST: manifest_raw},
                             {**modes, MANIFEST: "100644"}), "Source ZIP is not canonical")
    return {"schema": SCHEMA, "source_commit": expected_commit, "source_tree": manifest["source_tree"],
            "archive_sha256": expected_sha256, "manifest_sha256": digest(manifest_raw),
            "files": len(bodies), "payload_bytes": sum(map(len, bodies.values())),
            "boundaries": BOUNDARIES}


def create(repository, commit, output):
    raw = archive_bytes(repository, commit)
    result = inspect_archive(raw, digest(raw), commit)
    # This is a public-source artifact, not a private NTFS installation. Refuse
    # existing output (including links); do not replace or remove partial output.
    with Path(output).open("xb") as destination:
        destination.write(raw)
        destination.flush()
        os.fsync(destination.fileno())
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    build = actions.add_parser("create")
    build.add_argument("--repository", type=Path, required=True)
    build.add_argument("--commit", required=True)
    build.add_argument("--output", type=Path, required=True)
    inspect = actions.add_parser("verify")
    inspect.add_argument("--archive", type=Path, required=True)
    inspect.add_argument("--expected-sha256", required=True)
    inspect.add_argument("--expected-commit", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "create":
            result = create(args.repository, args.commit, args.output)
        else:
            with args.archive.open("rb") as source:
                raw = source.read(MAX_ARCHIVE_BYTES + 1)
            result = inspect_archive(raw, args.expected_sha256, args.expected_commit)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, SyntaxError,
            subprocess.SubprocessError, zipfile.BadZipFile) as error:
        parser.exit(1, f"Windows owner source handoff refused: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
