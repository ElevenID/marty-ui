"""Acquire exact published nightly inputs on the controller, without guest action.

This is not guest anonymous-acquisition evidence. The guest must later fetch the
public release independently before its operator can run.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
from urllib.parse import quote
import time

import installer_candidate_dispatch as dispatch
import installer_candidate_public_bootstrap as public_bootstrap
import installer_candidate_public_release as public_release
import installer_candidate_rendezvous as transport
import installer_promote as promotion
import installer_release as release
import verify_installer_provenance as provenance

SCHEMA = "elevenid.installer-controller-published-assets/v1"


def write_held(parent_fd, name, raw):
    release.require("/" not in name and ".." not in name and name,
                    "invalid controller record name")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent_fd)
    try:
        os.fsync(parent_fd)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fsync(parent_fd)
    finally:
        os.close(fd)


def acquire(*, client, output: Path, gh: Path, cosign: Path,
            source_sha: str, release_tag: str, build_run_id: int,
            build_run_attempt: int, clock=time.time, verifier=provenance.command,
            downloader=public_bootstrap.download):
    release.require(os.name == "posix", "Linux controller required")
    release.identity(source_sha, release_tag, build_run_id, build_run_attempt)
    release.require(release.classify_release_tag(release_tag)[0] == "nightly",
                    "published controller inputs require a nightly")
    build = client.request("GET", transport.REPO + "/actions/runs/" + str(build_run_id))
    promotion.check_run(build, run_id=build_run_id, attempt=build_run_attempt,
        workflow=".github/workflows/nightly-release.yml", source=source_sha)
    def api(path):
        return client.request("GET", transport.REPO + "/" + path)
    observed = public_release.observe(api, release_tag, source_sha)
    limits = public_release.expected_assets()
    release.require({item["name"] for item in observed["assets"]} == set(limits),
                    "published controller asset closure differs")
    parent = dispatch._directory(output.parent)
    held = None
    try:
        dispatch.registry_unchanged(parent, output.parent)
        release.require(not output.exists() and not Path(str(output) + ".intent.json").exists()
                        and not Path(str(output) + ".release.json").exists(),
                        "published acquisition already exists")
        base = dict(schema=SCHEMA, scope="controller-acquisition-only", source_sha=source_sha,
                    release_tag=release_tag, build_run_id=build_run_id,
                    build_run_attempt=build_run_attempt, release_id=observed["release_id"],
                    release_observation_sha256=release.digest(release.encode(observed)),
                    started_at=int(clock()), guest_acquisition=False, acceptance=False)
        write_held(parent, output.name + ".intent.json", release.encode(base))
        write_held(parent, output.name + ".release.json", release.encode(observed))
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
        held = public_bootstrap.private_directory(output)
        for item in observed["assets"]:
            name = item["name"]
            url = ("https://github.com/ElevenID/marty-ui/releases/download/"
                   + quote(release_tag, safe="") + "/" + quote(name, safe=""))
            downloader(url, output / name, held, item["size"])
            public_bootstrap.same_directory(held, output)
        dispatch.registry_unchanged(parent, output.parent)
        public_release.verify_downloads(observed, output)
        snapshot = {name: dispatch.private_file(output / name, limits[name])
                    for name in sorted(limits)}
        tool_snapshot = {}
        for name, path in (("gh", gh), ("cosign", cosign)):
            actual = dispatch.private_file(path, dispatch.TOOLS[name][1], executable=True)
            release.require(actual == dispatch.TOOLS[name], "controller verifier pin differs")
            tool_snapshot[path] = actual
        expected = dict(source_sha=source_sha, release_tag=release_tag,
                        build_run_id=build_run_id, build_run_attempt=build_run_attempt)
        inventory_bytes = public_bootstrap.private_file(output / "installer-inventory.json", 65536)
        inventory = release.verify_inventory_assets(output, **expected)
        for name in dispatch.SUBJECTS:
            provenance.verify_subject(output / name, output / (name + ".provenance.jsonl"),
                gh=gh, cosign=cosign, signature_bundle=output / (name + ".sigstore.json"),
                workflow=".github/workflows/nightly-release.yml", source_sha=source_sha,
                run_id=build_run_id, run_attempt=build_run_attempt, runner=verifier)
        release.require(release.verify_inventory_assets(output, **expected) == inventory,
                        "published candidate inventory changed")
        release.require(public_release.observe(api, release_tag, source_sha) == observed,
                        "published release identity changed")
        promotion.check_run(client.request("GET", transport.REPO + "/actions/runs/" + str(build_run_id)),
            run_id=build_run_id, attempt=build_run_attempt,
            workflow=".github/workflows/nightly-release.yml", source=source_sha)
        public_release.verify_downloads(observed, output)
        release.require({name: dispatch.private_file(output / name, limits[name])
                         for name in sorted(limits)} == snapshot,
                        "published controller assets changed")
        release.require(public_bootstrap.private_file(output / "installer-inventory.json", 65536)
                        == inventory_bytes, "published inventory changed")
        release.require({path: dispatch.private_file(path, dispatch.TOOLS[path.name][1], executable=True)
                         for path in tool_snapshot} == tool_snapshot,
                        "published verifier tool changed")
        public_bootstrap.same_directory(held, output)
        dispatch.registry_unchanged(parent, output.parent)
        release.require(public_bootstrap.private_file(output.parent / (output.name + ".release.json"), 65536)
                        == release.encode(observed), "published release observation changed")
        result = dict(base, inventory_sha256=release.digest(inventory_bytes),
                      verified_at=int(clock()), artifact_count=len(limits))
        write_held(parent, output.name + ".verified.json", release.encode(result))
        public_bootstrap.same_directory(held, output)
        dispatch.registry_unchanged(parent, output.parent)
        return result
    finally:
        if held is not None:
            os.close(held)
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "gh", "cosign"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-sha", "release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("build-run-id", "build-run-attempt"):
        parser.add_argument("--" + name, type=int, required=True)
    try:
        acquire(**vars(parser.parse_args(argv)), client=transport.Client(os.environ.get("GH_TOKEN")))
    except (ValueError, OSError, TypeError, KeyError):
        parser.exit(1, "Published controller asset acquisition refused or uncertain; preserve staging.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
