"""Source-bound local EUDI library facade, mounted into the pinned JRE."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

RUNTIME = "eclipse-temurin:17-jre@sha256:92999aea37688157a53a40bfcb187c30f317422e028045fd5fc5c548fde9e626"
MODULE_PREFIX = "services/eudi-wallet-harness/"


def compilation_inputs(repository, revision):
    """Read the complete tracked module from Git objects, never host worktree bytes."""
    assert re.fullmatch("[0-9a-f]{40}", revision)
    records = subprocess.check_output(
        [
            "git",
            "-C",
            str(repository),
            "ls-tree",
            "-r",
            "-z",
            revision,
            "--",
            MODULE_PREFIX,
        ]
    )
    inputs = {}
    for record in records.split(b"\0"):
        if not record:
            continue
        header, raw_name = record.split(b"\t", 1)
        mode, kind, _oid = header.split()
        assert mode in (b"100644", b"100755") and kind == b"blob", (
            "EUDI module must contain regular Git blobs"
        )
        name = raw_name.decode("utf-8")
        assert name.startswith(MODULE_PREFIX)
        relative = name.removeprefix(MODULE_PREFIX)
        assert relative and relative not in inputs
        assert (
            not PurePosixPath(relative).is_absolute()
            and ".." not in PurePosixPath(relative).parts
        )
        assert not any(value in relative for value in ("\\", "\r", "\n", "\0"))
        raw = subprocess.check_output(
            ["git", "-C", str(repository), "show", revision + ":" + name]
        )
        inputs[relative] = hashlib.sha256(raw).hexdigest()
    assert inputs, "Tracked EUDI facade inputs are missing"
    return inputs


def validate_compilation_inputs(artifact, actual_inputs):
    """One host/runtime reuse contract; preserve the truthful compiled source."""
    assert artifact["state"] == "PASSED" and artifact["exitCode"] == 0
    assert artifact["sourceReadbackMatched"] is True
    assert re.fullmatch("[0-9a-f]{40}", artifact["source"])
    assert isinstance(artifact.get("sourceFiles"), dict) and artifact["sourceFiles"]
    assert actual_inputs == artifact["sourceFiles"], (
        "EUDI facade inputs differ; compile this source instead of reusing it"
    )
    return artifact["source"]


def validate(artifact, base, source):
    checkout = base / "harness"
    assert (
        subprocess.check_output(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
        ).strip()
        == source
    )
    assert not subprocess.check_output(
        ["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=all"],
        text=True,
    ).strip()
    inputs = compilation_inputs(checkout, source)
    validate_compilation_inputs(artifact, inputs)
    # Close real Linux worktree bytes separately from the host's Git-object
    # proof. Python fixture-only changes do not relabel the compiled commit.
    for name, expected in inputs.items():
        path = checkout / MODULE_PREFIX / name
        assert path.is_file() and not path.is_symlink()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    dist = Path(artifact["linuxPath"])
    assert dist.resolve().is_relative_to(base.resolve()) and not dist.is_symlink()
    files = artifact["distFiles"]
    assert files and "bin/eudi-wallet-harness" in files
    actual = {}
    for path in dist.rglob("*"):
        assert not path.is_symlink(), "Local EUDI distribution contains a symlink"
        if path.is_file():
            actual[path.relative_to(dist).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
        else:
            assert path.is_dir()
    assert actual == files, "Local EUDI distribution changed after compilation"
    for name in files:
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and ".." not in relative.parts
    return dist


def write_override(artifact, base, source, destination):
    dist = validate(artifact, base, source)
    # !reset removes the canonical build recipe only in this explicit local
    # developer overlay. Original sources and official libraries are untouched.
    destination.write_text(
        "services:\n  eudi-wallet-kit:\n    build: !reset null\n"
        f"    image: {RUNTIME}\n    working_dir: /app\n"
        '    entrypoint: ["/app/bin/eudi-wallet-harness"]\n'
        "    healthcheck:\n"
        '      test: ["CMD", "curl", "-sf", "http://localhost:9090/health"]\n'
        "      interval: 10s\n      timeout: 5s\n      retries: 3\n      start_period: 30s\n"
        "    volumes:\n      - type: bind\n"
        f"        source: {json.dumps(str(dist))}\n"
        "        target: /app\n        read_only: true\n"
    )


def readback(artifact, state, base, source, project):
    validate(artifact, base, source)
    assert project.startswith("eudi-reference-local-")
    rows = json.loads(
        subprocess.check_output(["docker", "inspect", project + "-eudi-wallet-kit-1"])
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["Config"]["Labels"]["com.docker.compose.project"] == project
    assert row["Config"]["Labels"]["com.docker.compose.service"] == "eudi-wallet-kit"
    assert row["Config"]["Image"] == RUNTIME
    expected = subprocess.check_output(
        ["docker", "image", "inspect", "--format", "{{.Id}}", RUNTIME], text=True
    ).strip()
    assert row["Image"] == expected
    mounts = [m for m in row["Mounts"] if m["Destination"] == "/app"]
    assert (
        len(mounts) == 1
        and not mounts[0]["RW"]
        and mounts[0]["Source"] == artifact["linuxPath"]
    )
    files = artifact["distFiles"]
    result = subprocess.check_output(
        ["docker", "exec", row["Id"], "sha256sum", *("/app/" + name for name in files)],
        text=True,
    )
    actual = {}
    for line in result.splitlines():
        digest, name = line.split(maxsplit=1)
        actual[name.removeprefix("/app/")] = digest
    assert actual == files, (
        "Actual EUDI runtime bytes do not match compiled distribution"
    )
    state["nativeEudiHarness"] = dict(
        scope="LOCAL_COMPILED_LIBRARY_FACADE_OVER_PINNED_JRE",
        source=source,
        compiledSource=artifact["source"],
        compilationInputsMatched=True,
        container=row["Id"],
        runtimeImageId=expected,
        distFiles=files,
        readbackMatched=True,
        imageBuilt=False,
    )
