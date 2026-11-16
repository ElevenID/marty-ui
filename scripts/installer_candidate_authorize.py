"""Verify exact candidate inputs and exclusively write an UNSIGNED acceptance authorization.

Workflow caller authenticates the API run snapshot and verifier binary pins.
This does not sign, consume a dispatch, observe a guest, or report acceptance.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import stat
import time
import installer_release as release
import verify_installer_provenance as provenance


def read_record(path: Path) -> bytes:
    provenance.local_file(path, private=True, maximum=65536)
    with path.open("rb") as stream:
        raw = stream.read(65537)
    release.decode(raw)
    return raw


def write_exclusive(path: Path, raw: bytes) -> None:
    # Linux workflow only; leave every partial file in place on uncertainty.
    release.require(os.name == "posix" and path.is_absolute() and ".." not in path.parts,
                    "private absolute Linux output required")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parent.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            release.require(info.st_uid in (0, os.geteuid()) and
                            (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                            "untrusted output ancestor")
        info = os.fstat(parent)
        release.require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                        "output parent must be private")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            os.fsync(parent)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
            os.fsync(parent)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def authorize(*, assets: Path, acceptance_run: Path, gh: Path, cosign: Path,
              source_sha: str, release_tag: str, build_run_id: int, build_run_attempt: int,
              harness_source_sha: str, run_id: int, run_attempt: int, output: Path,
              phase="staged", hosting_input: Path | None = None,
              acme_staging_roots: Path | None = None,
              clock=time.time, runner=provenance.command) -> dict:
    with ExitStack() as stack:
        held = (stack.enter_context(release.candidate_hosting.HeldInput(hosting_input))
                if hosting_input is not None else None)
        roots = (stack.enter_context(release.candidate_hosting.HeldInput(acme_staging_roots,
                 release.candidate_hosting.MAX_ROOTS_BYTES)) if acme_staging_roots is not None else None)
        release.require(held is not None or roots is None, "staging trust requires explicit hosting input")
        if held is None:
            release.candidate_hosting.check_file({}, output.parent)
        return _authorize(assets=assets, acceptance_run=acceptance_run, gh=gh, cosign=cosign,
                          source_sha=source_sha, release_tag=release_tag, build_run_id=build_run_id,
                          build_run_attempt=build_run_attempt, harness_source_sha=harness_source_sha,
                          run_id=run_id, run_attempt=run_attempt, output=output, phase=phase,
                          held_hosting=held, held_roots=roots, clock=clock, runner=runner)


def _authorize(*, assets, acceptance_run, gh, cosign, source_sha, release_tag,
               build_run_id, build_run_attempt, harness_source_sha, run_id, run_attempt,
               output, phase, held_hosting, held_roots, clock, runner) -> dict:
    """Caller-supplied API snapshot is authoritative, never taken from an artifact.

    Verifier binaries must be pinned by the workflow before invocation. Private
    staging must have no concurrent writer; rechecks detect ordinary replacement.
    """
    expected = dict(source_sha=source_sha, release_tag=release_tag,
                    build_run_id=build_run_id, build_run_attempt=build_run_attempt)
    release.require(phase in ("staged", "published"), "invalid candidate phase")
    run_bytes = read_record(acceptance_run)
    run = release.decode(run_bytes)
    release.require(run.get("head_sha") == harness_source_sha and run.get("id") == run_id
                    and run.get("run_attempt") == run_attempt, "acceptance invocation differs")
    for number in (run_id, run_attempt):
        release.positive(number)
    release.sha(harness_source_sha)
    inventory_path = assets / "installer-inventory.json"
    inventory = read_record(inventory_path)
    # Prevalidate run and inventory before spending time in verifier subprocesses.
    release.candidate_authorization(inventory, **expected, acceptance_run=run,
                                    phase=phase, now=int(clock()),
                                    hosting_input=None if held_hosting is None else held_hosting.check(),
                                    staging_roots=None if held_roots is None else held_roots.check())
    tier, _ = release.classify_release_tag(release_tag)
    workflow = ".github/workflows/nightly-release.yml" if tier == "nightly" else ".github/workflows/cd.yml"
    record = release.verify_inventory_assets(assets, **expected)
    for name in ["installer-inventory.json", *sorted(release.ARTIFACTS)]:
        subject = assets / name
        provenance.local_file(subject, private=True,
            maximum=65536 if name == "installer-inventory.json" else release.ARTIFACT_MAX_BYTES[name])
        provenance.verify_subject(subject, assets / (name + ".provenance.jsonl"), gh=gh,
            workflow=workflow, source_sha=source_sha, run_id=build_run_id, run_attempt=build_run_attempt,
            cosign=cosign, signature_bundle=assets / (name + ".sigstore.json"), runner=runner)
    release.require(read_record(inventory_path) == inventory and read_record(acceptance_run) == run_bytes,
                    "verified inputs changed")
    release.require(release.verify_inventory_assets(assets, **expected) == record, "candidate assets changed")
    result = release.candidate_authorization(inventory, **expected, acceptance_run=run,
                                           phase=phase, now=int(clock()),
                                           hosting_input=None if held_hosting is None else held_hosting.check(),
                                           staging_roots=None if held_roots is None else held_roots.check())
    if held_hosting is not None:
        for name, held in [(release.candidate_hosting.NAME, held_hosting),
                           (release.candidate_hosting.ROOTS_NAME, held_roots)]:
            if held is not None:
                destination = output.parent / name
                if destination != held.path:
                    write_exclusive(destination, held.check())
        release.candidate_hosting.check_file(result, output.parent)
        held_hosting.check()
        if held_roots is not None:
            held_roots.check()
    write_exclusive(output, release.encode(result))
    if held_hosting is not None:
        held_hosting.check()
        release.candidate_hosting.check_file(result, output.parent)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("assets", "acceptance-run", "gh", "cosign", "output"):
        parser.add_argument("--" + flag, required=True, type=Path)
    for flag in ("source-sha", "release-tag", "harness-source-sha"):
        parser.add_argument("--" + flag, required=True)
    for flag in ("build-run-id", "build-run-attempt", "run-id", "run-attempt"):
        parser.add_argument("--" + flag, required=True, type=int)
    parser.add_argument("--phase", choices=("staged", "published"), default="staged")
    parser.add_argument("--hosting-input", type=Path)
    parser.add_argument("--acme-staging-roots", type=Path)
    args = vars(parser.parse_args(argv))
    try:
        authorize(**args)
    except (ValueError, OSError):
        parser.exit(1, "Candidate authorization refused; preserve any partial output.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
