"""Retrieve and authenticate one same-run signed controller execution grant.

This is read-only with respect to the guest and nonce registry. It never
dispatches, retries an uncertain invocation, or reports installed acceptance.
"""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import tempfile
import time
import zipfile

import installer_candidate_dispatch as dispatch
import installer_candidate_receipt_upload as uploader
import installer_candidate_rendezvous as transport
import installer_promote as promotion
import installer_release as release
import verify_installer_provenance as provenance
from installer_candidate_authorize import read_record, write_exclusive

ARCHIVE_MAX = 8 * 1024 * 1024
EXPANDED_MAX = 8 * 1024 * 1024
NAMES = {name + suffix for name in ("candidate-authorization.json", "controller-consumption.json")
         for suffix in dispatch.SUFFIXES} | {"controller-consumption.json.transport.json",
                                              "controller-transport.json"}


def hash_fd(fd, maximum):
    os.lseek(fd, 0, os.SEEK_SET)
    hashed = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, min(65536, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        release.require(total <= maximum, "held file exceeds bound")
        hashed.update(chunk)
    return hashed.hexdigest(), total


def selected_artifact(value, *, run_id, run_attempt, harness_source_sha):
    name = f"installer-candidate-execution-grant-{run_id}-{run_attempt}"
    release.require(isinstance(value, dict) and value.get("total_count") is not None
                    and type(value["total_count"]) is int and 0 <= value["total_count"] <= 100
                    and isinstance(value.get("artifacts"), list)
                    and len(value["artifacts"]) == value["total_count"], "artifact listing differs")
    matches = [item for item in value["artifacts"] if isinstance(item, dict) and item.get("name") == name]
    release.require(len(matches) <= 1, "ambiguous execution grant artifact")
    if not matches:
        return None
    item = matches[0]
    release.require(isinstance(item.get("workflow_run"), dict), "artifact run binding missing")
    bound = item["workflow_run"]
    size = item.get("size_in_bytes")
    digest = item.get("digest")
    release.require(item.get("expired") is False and type(size) is int and 0 < size <= ARCHIVE_MAX
                    and isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                    and bound.get("id") == run_id and bound.get("repository_id") == 1140864197
                    and bound.get("head_repository_id") == 1140864197
                    and bound.get("head_branch") == "main" and bound.get("head_sha") == harness_source_sha,
                    "execution grant artifact identity differs")
    transport.positive_id(item.get("id"))
    return {key: item[key] for key in ("id", "name", "size_in_bytes", "digest", "expired", "created_at", "updated_at")}


def download_archive(gh, token, artifact_id, destination, parent_fd, maximum=ARCHIVE_MAX, timeout=90):
    """Use the pinned GitHub CLI for its authenticated API/storage redirect boundary."""
    release.require(isinstance(token, str) and token, "GitHub authentication unavailable")
    tool_fd = os.open(gh, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(tool_fd)
        release.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
                        and info.st_size == dispatch.TOOLS["gh"][1], "GitHub CLI file differs")
        actual, size = hash_fd(tool_fd, info.st_size)
        current = os.stat(gh, follow_symlinks=False)
        release.require(actual == dispatch.TOOLS["gh"][0] and size == info.st_size
                        and (current.st_dev, current.st_ino, current.st_size)
                        == (info.st_dev, info.st_ino, info.st_size), "GitHub CLI trust anchor differs")
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
        try:
            os.fsync(parent_fd)
            with tempfile.TemporaryDirectory(prefix="marty-grant-api-") as home:
                env = {"GH_TOKEN": token, "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1",
                       "GH_CONFIG_DIR": home, "HOME": home, "XDG_CONFIG_HOME": home,
                       "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
                def limit_file():
                    resource.setrlimit(resource.RLIMIT_FSIZE, (maximum + 1, maximum + 1))
                process = None
                try:
                    process = subprocess.Popen([str(gh), "api", "--method", "GET",
                        f"repos/ElevenID/marty-ui/actions/artifacts/{artifact_id}/zip"],
                        executable=f"/proc/self/fd/{tool_fd}", pass_fds=(tool_fd,),
                        stdout=fd, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                        env=env, cwd=home, start_new_session=True, preexec_fn=limit_file)
                    deadline = time.monotonic() + timeout
                    while os.waitid(os.P_PID, process.pid,
                            os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                        release.require(time.monotonic() < deadline,
                                        "execution grant download timed out")
                        time.sleep(0.01)
                except (OSError, subprocess.SubprocessError):
                    raise ValueError("execution grant download failed or is uncertain") from None
                finally:
                    if process is not None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        status = process.wait()
            os.fsync(fd)
            os.fsync(parent_fd)
            release.require(status == 0 and 0 < os.fstat(fd).st_size <= maximum,
                            "execution grant download failed or exceeded bound")
        finally:
            os.close(fd)
    finally:
        os.close(tool_fd)


def extract_exact(archive_stream, directory, parent_fd):
    release.require(not directory.exists(), "grant extraction directory already exists")
    os.mkdir(directory.name, mode=0o700, dir_fd=parent_fd)
    os.fsync(parent_fd)
    held = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                   dir_fd=parent_fd)
    try:
      with zipfile.ZipFile(archive_stream) as bundle:
        entries = bundle.infolist()
        release.require(len(entries) == len(NAMES) and {entry.filename for entry in entries} == NAMES,
                        "execution grant archive closure differs")
        total = 0
        for entry in entries:
            mode = entry.external_attr >> 16
            release.require(not entry.is_dir() and not entry.flag_bits & 1
                            and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                            and entry.file_size > 0 and entry.file_size <= 1048576,
                            "execution grant archive member differs")
            total += entry.file_size
            release.require(total <= EXPANDED_MAX, "execution grant expansion exceeds bound")
            with bundle.open(entry, "r") as stream:
                raw = stream.read(entry.file_size + 1)
                release.require(len(raw) == entry.file_size and not stream.read(1),
                                "execution grant archive member changed")
            fd = os.open(entry.filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=held)
            try:
                os.fsync(held)
                with os.fdopen(fd, "wb", closefd=False) as output:
                    output.write(raw)
                    output.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
      os.fsync(held)
      dispatch.registry_unchanged(held, directory)
      release.require({path.name for path in directory.iterdir()} == NAMES,
                      "extracted execution grant closure differs")
    finally:
      os.close(held)


def receive(*, client, authorization, inventory, assets, descriptor, ledger,
            context_file, target_file, gh, cosign, output, harness_source_sha,
            run_id, run_attempt, controller_user_id, clock=time.time, sleep=time.sleep,
            verifier=provenance.command, downloader=download_archive):
    release.require(os.name == "posix", "Linux controller required")
    a, i = uploader.authenticate(authorization, inventory, assets, gh, cosign, runner=verifier)
    _, _, context, grant = transport.inputs(authorization, inventory,
        harness_source_sha=harness_source_sha, run_id=run_id, run_attempt=run_attempt, now=int(clock()))
    release.require(context == release.decode(read_record(context_file)), "independent context differs")
    target = release.decode(read_record(target_file))
    release.exact(target, dispatch.TARGET_FIELDS, "independent controller target")
    approved = transport.controller_id(controller_user_id)
    transport.bound_descriptor(descriptor, a, i, context, grant, approved)
    raw_ledger = read_record(ledger)
    receipt = release.decode(raw_ledger)
    release.require(ledger.name == context["nonce"] + ".json", "controller ledger name differs")
    bound = release.bind_controller_consumption(raw_ledger, a, i, expected=context,
        expected_engine=target["engine_id"], now=int(clock()))
    release.require(all(bound[key] == target[key] for key in dispatch.TARGET_FIELDS),
                    "controller target differs from ledger")
    deadline = min(int(clock()) + 900, grant["expires_at"] - transport.RESERVE)
    selected = None
    while int(clock()) < deadline:
        run = client.request("GET", transport.REPO + "/actions/runs/" + str(run_id))
        promotion.check_run(run, run_id=run_id, attempt=run_attempt,
            workflow=release.acceptance.WORKFLOW, source=harness_source_sha, active=True)
        listing = client.request("GET", transport.REPO + f"/actions/runs/{run_id}/artifacts?per_page=100")
        selected = selected_artifact(listing, run_id=run_id, run_attempt=run_attempt,
                                     harness_source_sha=harness_source_sha)
        if selected is not None:
            break
        sleep(min(5, max(0, deadline - int(clock()))))
    release.require(selected is not None and int(clock()) < deadline, "signed grant artifact deadline expired")
    held = dispatch._directory(output.parent)
    try:
        return _receive_archive(client=client, selected=selected, output=output, held=held,
            gh=gh, downloader=downloader, a=a, i=i, raw_ledger=raw_ledger,
            descriptor=descriptor, approved=approved, context=context, target=target,
            assets=assets, ledger=ledger, cosign=cosign, verifier=verifier,
            run_id=run_id, run_attempt=run_attempt, harness_source_sha=harness_source_sha,
            clock=clock, deadline=deadline)
    finally:
        os.close(held)


def _receive_archive(*, client, selected, output, held, gh, downloader, a, i,
                     raw_ledger, descriptor, approved, context, target, assets,
                     ledger, cosign, verifier, run_id, run_attempt,
                     harness_source_sha, clock, deadline):
    dispatch.registry_unchanged(held, output.parent)
    release.require(not output.exists() and not Path(str(output) + ".archive.zip").exists(),
                    "execution grant staging already exists")
    archive = Path(str(output) + ".archive.zip")
    downloader(gh, client.token, selected["id"], archive, held)
    dispatch.registry_unchanged(held, output.parent)
    archive_fd = os.open(archive.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held)
    try:
        info = os.fstat(archive_fd)
        release.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
                        and info.st_size == selected["size_in_bytes"], "execution grant archive file differs")
        archive_sha, total = hash_fd(archive_fd, selected["size_in_bytes"])
        release.require(total == selected["size_in_bytes"], "execution grant archive size differs")
        with os.fdopen(archive_fd, "rb", closefd=False) as stream:
            release.require("sha256:" + archive_sha == selected["digest"],
                            "execution grant archive digest differs")
            stream.seek(0)
            extract_exact(stream, output, held)
        after_sha, after_size = hash_fd(archive_fd, selected["size_in_bytes"])
        release.require(after_sha == archive_sha and after_size == selected["size_in_bytes"]
                            and os.fstat(archive_fd).st_size == selected["size_in_bytes"],
                            "execution grant archive changed during extraction")
    finally:
        os.close(archive_fd)
    dispatch.registry_unchanged(held, output.parent)
    snapshot = {name: dispatch.private_file(output / name, 1048576) for name in NAMES}
    release.require(read_record(output / "candidate-authorization.json") == a
                    and read_record(output / "controller-consumption.json") == raw_ledger
                    and read_record(output / "controller-transport.json") == read_record(descriptor),
                    "execution grant bytes differ from original controller inputs")
    evidence = release.decode(read_record(output / "controller-consumption.json.transport.json"))
    release.require(evidence.get("receipt_sha256") == release.digest(raw_ledger)
                    and evidence.get("authorization_sha256") == release.digest(a)
                    and evidence.get("inventory_sha256") == release.digest(i)
                    and evidence.get("context_sha256") == release.candidate_context_sha256(context)
                    and evidence.get("controller_user_id") == approved,
                    "hosted controller transport evidence differs")
    dispatch.verify(assets=assets, grants=output, context=context, target=target,
                    ledger=ledger, gh=gh, cosign=cosign, now=int(clock()), runner=verifier)
    fresh = client.request("GET", transport.REPO + "/actions/artifacts/" + str(selected["id"]))
    release.require(selected_artifact({"total_count": 1, "artifacts": [fresh]},
                    run_id=run_id, run_attempt=run_attempt,
                    harness_source_sha=harness_source_sha) == selected,
                    "execution grant artifact changed")
    promotion.check_run(client.request("GET", transport.REPO + "/actions/runs/" + str(run_id)),
        run_id=run_id, attempt=run_attempt, workflow=release.acceptance.WORKFLOW,
        source=harness_source_sha, active=True)
    release.require(int(clock()) < deadline and read_record(ledger) == raw_ledger,
                    "execution grant expired or controller ledger changed")
    dispatch.registry_unchanged(held, output.parent)
    release.require({name: dispatch.private_file(output / name, 1048576) for name in NAMES} == snapshot,
                    "verified grant files changed")
    result = dict(schema="elevenid.installer-execution-grant-retrieval/v1", artifact=selected,
                  archive_sha256=archive_sha, authorization_sha256=release.digest(a),
                  receipt_sha256=release.digest(raw_ledger), context_sha256=release.candidate_context_sha256(context),
                  target_sha256=release.digest(release.encode(target)), verified_at=int(clock()),
                  guest_dispatched=False, acceptance=False)
    write_exclusive(Path(str(output) + ".verified.json"), release.encode(result))
    dispatch.registry_unchanged(held, output.parent)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("authorization", "inventory", "assets", "descriptor", "ledger", "context-file",
                 "target-file", "gh", "cosign", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--harness-source-sha", required=True)
    for name in ("run-id", "run-attempt", "controller-user-id"):
        parser.add_argument("--" + name, type=int, required=True)
    try:
        receive(**vars(parser.parse_args(argv)), client=transport.Client(os.environ.get("GH_TOKEN")))
    except (ValueError, OSError, TypeError, KeyError, zipfile.BadZipFile):
        parser.exit(1, "Execution grant retrieval refused or uncertain; preserve staging and ledger.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
