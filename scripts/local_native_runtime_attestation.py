"""Observe only the three loaded binaries in an isolated local issuer project."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from local_native_functional_binding import ROLES, load_binding
from scoped_native_runtime import daemon_source

HEX64 = re.compile(r"^[0-9a-f]{64}$")
PROJECT = re.compile(r"^marty-conformance-[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])?$")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _docker(*args: str) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("local native process observation unavailable") from None
    if result.returncode:
        raise ValueError("local native process observation unavailable")
    return result.stdout.strip()


def observe(project: str, binding_path: Path) -> dict:
    if not PROJECT.fullmatch(project):
        raise ValueError("local issuer project is invalid")
    binding_sha = _hash_file(binding_path)
    binaries, image_id = load_binding(binding_path)
    rows = {}
    for role, binary in ROLES.items():
        ids = _docker("ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={project}",
                      "--filter", f"label=com.docker.compose.service={role}").splitlines()
        if len(ids) != 1 or not HEX64.fullmatch(ids[0]):
            raise ValueError(f"{role} has no unique owned container")
        cid = ids[0]
        record = json.loads(_docker("inspect", cid))
        if not isinstance(record, list) or len(record) != 1:
            raise ValueError(f"{role} inspect is ambiguous")
        item = record[0]
        state = item["State"]
        if (item["Id"] != cid or item["Image"] != image_id or state["Running"] is not True
                or type(state["Pid"]) is not int or state["Pid"] <= 0):
            raise ValueError(f"{role} container identity is not live")
        if item["Config"]["Labels"].get("com.docker.compose.project") != project or item["Config"]["Labels"].get("com.docker.compose.service") != role:
            raise ValueError(f"{role} ownership labels changed")
        expected_target = f"/usr/local/bin/{binary}"
        mounts = [mount for mount in item["Mounts"] if mount.get("Destination") == expected_target]
        if (len(mounts) != 1 or mounts[0].get("RW") is not False
                or mounts[0].get("Source") != daemon_source(binaries[role].resolve())):
            raise ValueError(f"{role} running binary mount differs from binding")
        status_lines = _docker("exec", cid, "cat", "/proc/1/status").splitlines()
        uid_fields = [line.split() for line in status_lines if line.startswith("Uid:")]
        uid = uid_fields[0][2] if len(uid_fields) == 1 and len(uid_fields[0]) == 5 else ""
        if uid != "10001":
            raise ValueError(f"{role} effective UID differs from ABI")
        # /proc/1/exe binds the observed process, not merely the mounted file.
        digest_line = _docker("exec", cid, "sha256sum", "/proc/1/exe")
        loaded_sha = digest_line.split(maxsplit=1)[0]
        expected_sha = _hash_file(binaries[role])
        if loaded_sha != expected_sha:
            raise ValueError(f"{role} loaded binary differs from reviewed file")
        rows[role] = {"cid": cid, "imageId": image_id, "startedAt": state["StartedAt"],
                      "pid": state["Pid"],
                      "binarySha256": loaded_sha, "uid": 10001, "mountReadOnly": True}
    if _hash_file(binding_path) != binding_sha:
        raise ValueError("local native binding changed during process attestation")
    return {"schema": "elevenid.local-native-runtime-attestation/v1", "project": project,
            "state": "FUNCTIONAL_ONLY", "releaseQualified": False,
            "bindingSha256": binding_sha, "roles": rows}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = observe(args.project, args.binding)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    args.output.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
