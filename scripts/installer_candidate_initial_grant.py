"""Acquire an initial signed candidate grant without consuming or dispatching it.

The caller supplies independent acceptance/build identity and already-staged
original build assets. A fresh VM observation and durable controller consume
must occur separately after this read-only authentication boundary.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import stat
import time
import zipfile

import installer_candidate_dispatch as dispatch
import installer_candidate_grant_receive as archive_transport
import installer_candidate_receipt_upload as uploader
import installer_candidate_rendezvous as transport
import installer_promote as promotion
import installer_release as release
import verify_installer_provenance as provenance
from installer_candidate_authorize import read_record, write_exclusive

NAMES = {"candidate-authorization.json",
         "candidate-authorization.json.sigstore.json",
         "candidate-authorization.json.provenance.jsonl",
         "controller-transport.json"}


def acquire(*, client, assets: Path, gh: Path, cosign: Path, output: Path,
            phase: str, source_sha: str, release_tag: str, build_run_id: int,
            build_run_attempt: int, harness_source_sha: str, run_id: int,
            run_attempt: int, controller_user_id: int, clock=time.time,
            sleep=time.sleep, verifier=provenance.command,
            downloader=archive_transport.download_archive):
    release.require(os.name == "posix" and phase in ("staged", "published"),
                    "Linux candidate phase required")
    release.identity(source_sha, release_tag, build_run_id, build_run_attempt)
    release.sha(harness_source_sha)
    transport.controller_id(controller_user_id)
    name = f"installer-{phase}-grant-{run_id}-{run_attempt}"
    deadline = int(clock()) + 900
    chosen = None
    while int(clock()) < deadline:
        run = client.request("GET", transport.REPO + "/actions/runs/" + str(run_id))
        promotion.check_run(run, run_id=run_id, attempt=run_attempt,
            workflow=release.acceptance.WORKFLOW, source=harness_source_sha, active=True)
        listing = client.request("GET", transport.REPO + f"/actions/runs/{run_id}/artifacts?per_page=100")
        chosen = archive_transport.selected_artifact(listing, run_id=run_id,
            run_attempt=run_attempt, harness_source_sha=harness_source_sha, name=name)
        if chosen is not None:
            break
        sleep(min(5, max(0, deadline - int(clock()))))
    release.require(chosen is not None and int(clock()) < deadline,
                    "initial candidate grant deadline expired")
    held = dispatch._directory(output.parent)
    try:
        dispatch.registry_unchanged(held, output.parent)
        archive = Path(str(output) + ".archive.zip")
        release.require(not output.exists() and not archive.exists(),
                        "initial grant staging already exists")
        downloader(gh, client.token, chosen["id"], archive, held)
        dispatch.registry_unchanged(held, output.parent)
        archive_fd = os.open(archive.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=held)
        try:
            info = os.fstat(archive_fd)
            release.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                            and info.st_size == chosen["size_in_bytes"],
                            "initial grant archive file differs")
            digest, size = archive_transport.hash_fd(archive_fd, chosen["size_in_bytes"])
            release.require(size == chosen["size_in_bytes"] and "sha256:" + digest == chosen["digest"],
                            "initial grant archive digest differs")
            with os.fdopen(archive_fd, "rb", closefd=False) as stream:
                stream.seek(0)
                archive_transport.extract_exact(stream, output, held, NAMES)
            again, again_size = archive_transport.hash_fd(archive_fd, chosen["size_in_bytes"])
            release.require(again == digest and again_size == size
                            and os.fstat(archive_fd).st_size == size,
                            "initial grant archive changed during extraction")
        finally:
            os.close(archive_fd)
        dispatch.registry_unchanged(held, output.parent)
        snapshot = {entry: dispatch.private_file(output / entry, 1048576) for entry in NAMES}
        authorization = output / "candidate-authorization.json"
        inventory = assets / "installer-inventory.json"
        a, i = uploader.authenticate(authorization, inventory, assets, gh, cosign, runner=verifier)
        _, _, context, grant = transport.inputs(authorization, inventory,
            harness_source_sha=harness_source_sha, run_id=run_id,
            run_attempt=run_attempt, now=int(clock()))
        release.require(grant["phase"] == phase and grant["source_sha"] == source_sha
                        and grant["release_tag"] == release_tag
                        and grant["build_run_id"] == build_run_id
                        and grant["build_run_attempt"] == build_run_attempt,
                        "independent candidate selection differs")
        release.require(grant["expires_at"] - int(clock()) > transport.RESERVE,
                        "initial grant expires too soon")
        owned = transport.bound_descriptor(output / "controller-transport.json", a, i,
                                            context, grant, controller_user_id)
        fresh = client.request("GET", transport.REPO + "/actions/artifacts/" + str(chosen["id"]))
        release.require(archive_transport.selected_artifact(
            {"total_count": 1, "artifacts": [fresh]}, run_id=run_id,
            run_attempt=run_attempt, harness_source_sha=harness_source_sha, name=name) == chosen,
            "initial grant artifact changed")
        promotion.check_run(client.request("GET", transport.REPO + "/actions/runs/" + str(run_id)),
            run_id=run_id, attempt=run_attempt, workflow=release.acceptance.WORKFLOW,
            source=harness_source_sha, active=True)
        release.require(grant["expires_at"] - int(clock()) > transport.RESERVE
                        and read_record(authorization) == a
                        and read_record(inventory) == i,
                        "initial grant expired or inputs changed")
        dispatch.registry_unchanged(held, output.parent)
        release.require({entry: dispatch.private_file(output / entry, 1048576) for entry in NAMES} == snapshot,
                        "initial grant files changed")
        result = dict(schema="elevenid.installer-initial-grant-acquisition/v1",
                      artifact=chosen, archive_sha256=digest, phase=phase,
                      release_id=owned["id"], authorization_sha256=release.digest(a),
                      inventory_sha256=release.digest(i),
                      context_sha256=release.candidate_context_sha256(context),
                      acquired_at=int(clock()), nonce_consumed=False,
                      guest_dispatched=False, acceptance=False)
        write_exclusive(Path(str(output) + ".verified.json"), release.encode(result))
        dispatch.registry_unchanged(held, output.parent)
        return result
    finally:
        os.close(held)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("assets", "gh", "cosign", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-sha", "release-tag", "harness-source-sha"):
        parser.add_argument("--" + name, required=True)
    for name in ("build-run-id", "build-run-attempt", "run-id", "run-attempt", "controller-user-id"):
        parser.add_argument("--" + name, type=int, required=True)
    parser.add_argument("--phase", choices=("staged", "published"), required=True)
    try:
        acquire(**vars(parser.parse_args(argv)), client=transport.Client(os.environ.get("GH_TOKEN")))
    except (ValueError, OSError, TypeError, KeyError, zipfile.BadZipFile):
        parser.exit(1, "Initial candidate grant refused or uncertain; preserve staging.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
