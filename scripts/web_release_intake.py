#!/usr/bin/env python3
"""Fetch fixed web evidence from an exact successful original producer attempt.

GitHub API metadata binds repository/workflow/run/source before download. The
downloaded ZIP is inert: only the fixed receipt files are read, then their original
signatures and source certificates are verified. No downloaded script is executed.
"""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile

import installer_release as installer
import package_web_composition as composition
import stable_installer_assets as stable
import ui_release as ui
import website_provenance as proof
import website_release as web

MAX_ARCHIVE = 32 * 1024 * 1024


def attempt_identity(value: dict, *, repository: str, run_id: str, attempt: str) -> dict:
    ui.require(repository in web.REPOSITORIES and all(isinstance(x, str) and ui.RUN.fullmatch(x) for x in (run_id, attempt)),
               "invalid original producer selection")
    workflow = ui.WORKFLOW if repository == ui.REPOSITORY else ui.COMMERCE_WORKFLOW
    ui.require(isinstance(value, dict) and value.get("id") == int(run_id) and value.get("run_attempt") == int(attempt)
               and value.get("status") == "completed" and value.get("conclusion") == "success"
               and value.get("event") == "workflow_dispatch" and value.get("head_branch") == "main"
               and value.get("path") in {workflow, workflow + "@main", workflow + "@refs/heads/main"},
               "selected producer attempt was not a successful protected-main release")
    repo = value.get("repository", {})
    ui.require(repo.get("full_name") == repository and str(repo.get("id")) == web.REPOSITORIES[repository],
               "selected producer repository differs")
    source = web.full_sha(value.get("head_sha"))
    return proof.validate_producer({"repository": repository, "workflow": workflow, "ref": web.REF,
                                    "source_sha": source, "run_id": run_id, "run_attempt": attempt})


def archive_selection(value: dict, *, kind: str, producer: dict) -> dict:
    ui.require(kind in {"website", "application"}, "unsupported web evidence kind")
    name = f"web-{kind}-{producer['run_id']}-{producer['run_attempt']}"
    ui.require(isinstance(value, dict) and value.get("total_count") == 1 and isinstance(value.get("artifacts"), list)
               and len(value["artifacts"]) == 1, "one exact producer evidence artifact is required")
    artifact = value["artifacts"][0]
    run = artifact.get("workflow_run", {})
    ui.require(artifact.get("name") == name and artifact.get("expired") is False
               and type(artifact.get("id")) is int and artifact["id"] > 0
               and type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE
               and run.get("id") == int(producer["run_id"]) and run.get("head_sha") == producer["source_sha"]
               and run.get("head_branch") == "main"
               and str(run.get("repository_id")) == web.REPOSITORIES[producer["repository"]],
               "producer evidence artifact owner or bounds differ")
    web.image_digest(artifact.get("digest"))
    return artifact


def download_archive(args: list[str]) -> bytes:
    # The API's checked size bounds this authenticated hosted artifact; the byte
    # count/digest and expanded ZIP closure are checked again before any extraction.
    result = subprocess.run(args, capture_output=True, timeout=180, check=False)
    ui.require(result.returncode == 0 and 0 < len(result.stdout) <= MAX_ARCHIVE, "producer artifact download failed")
    return result.stdout


def extract_receipt(raw: bytes, *, kind: str, destination: Path) -> None:
    expected = set(composition.WEBSITE_FILES if kind == "website" else composition.APPLICATION_FILES)
    ui.require(0 < len(raw) <= MAX_ARCHIVE, "producer archive exceeds limit")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        ui.require(len(entries) == len(expected) and {entry.filename for entry in entries} == expected,
                   "producer evidence archive has unexpected or duplicate files")
        total = 0
        for entry in entries:
            mode = entry.external_attr >> 16
            maximum = proof.PROOF_LIMIT if entry.filename.endswith((".provenance.jsonl", ".sigstore.json")) else proof.JSON_LIMIT
            ui.require(not entry.is_dir() and not stat.S_ISLNK(mode) and stat.S_IFMT(mode) in {0, stat.S_IFREG}
                       and not entry.flag_bits & 1 and 0 < entry.file_size <= maximum, "unsafe producer evidence entry")
            total += entry.file_size
        ui.require(total <= MAX_ARCHIVE, "expanded producer evidence exceeds limit")
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        for entry in entries:
            target = destination / entry.filename
            with target.open("xb") as stream:
                stream.write(archive.read(entry))
            target.chmod(0o600)


def fetch(kind: str, *, repository: str, run_id: str, attempt: str, destination: Path,
          gh: Path, cosign: Path, runner=proof.verifier.command, downloader=download_archive) -> dict:
    ui.require(kind in {"website", "application"} and repository in web.REPOSITORIES
               and all(isinstance(x, str) and ui.RUN.fullmatch(x) for x in (run_id, attempt)),
               "invalid original producer selection")
    proof.verifier.local_file(gh)
    prefix = f"repos/{repository}/actions"
    api = [str(gh), "api", "--hostname", "github.com", "-H", "X-GitHub-Api-Version: 2022-11-28"]
    attempt_record = proof.parse_verified_json(runner(api + [f"{prefix}/runs/{run_id}/attempts/{attempt}"]))
    producer = attempt_identity(attempt_record, repository=repository, run_id=run_id, attempt=attempt)
    name = f"web-{kind}-{run_id}-{attempt}"
    listed = proof.parse_verified_json(runner(api + [f"{prefix}/runs/{run_id}/artifacts?name={name}&per_page=100"]))
    artifact = archive_selection(listed, kind=kind, producer=producer)
    raw = downloader(api + [f"{prefix}/artifacts/{artifact['id']}/zip"])
    ui.require(len(raw) == artifact["size_in_bytes"] and ui.digest(raw) == artifact["digest"],
               "producer artifact bytes differ from GitHub metadata")
    ui.require(not destination.exists(), "web evidence destination already exists")
    with tempfile.TemporaryDirectory(prefix=".web-intake-", dir=destination.parent) as temporary:
        held = Path(temporary) / "receipt"
        extract_receipt(raw, kind=kind, destination=held)
        if kind == "website":
            release = proof.verify_website(held, gh=gh, cosign=cosign)
            actual = release["producer"]
        else:
            release, compatibility = proof.verify_application(held, gh=gh, cosign=cosign)
            actual = compatibility["producer"]
        ui.require(actual == producer, "original evidence does not belong to the selected producer attempt")
        files = composition.WEBSITE_FILES if kind == "website" else composition.APPLICATION_FILES
        composition.copy_inputs(held, files, destination)
    return release


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        ui.require(parsed.scheme == "https" and parsed.hostname in {"github.com", "release-assets.githubusercontent.com",
                   "objects.githubusercontent.com", "github-releases.githubusercontent.com"}
                   and not parsed.username and not parsed.password, "unexpected backend release redirect")
        return super().redirect_request(request, fp, code, message, headers, newurl)


def backend(tag: str, *, destination: Path, opener=None) -> None:
    ui.require(isinstance(tag, str) and ui.VERSION.fullmatch(tag.removeprefix("v")) and tag.startswith("v"),
               "an exact stable backend tag is required")
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReleaseRedirect()).open
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in composition.BACKEND_FILES:
        maximum = 1024 * 1024 if name.endswith(".provenance.jsonl") else installer.ARTIFACT_MAX_BYTES.get(name, 65536)
        request = urllib.request.Request(f"https://github.com/{ui.REPOSITORY}/releases/download/{tag}/{name}",
                                         headers={"User-Agent": "marty-web-composition/1"})
        with opener(request, timeout=60) as response, (destination / name).open("xb") as stream:
            total = 0
            while chunk := response.read(min(1024 * 1024, maximum + 1 - total)):
                total += len(chunk)
                ui.require(total <= maximum, "backend subject exceeds limit")
                stream.write(chunk)
            ui.require(total > 0, "empty backend subject")
        (destination / name).chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("website", "application", "backend"))
    parser.add_argument("--repository", choices=tuple(web.REPOSITORIES))
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--gh", type=Path)
    parser.add_argument("--cosign", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--source-sha")
    args = parser.parse_args()
    if args.kind == "backend":
        ui.require(args.tag and args.source_sha and args.gh, "backend needs exact source/tag and pinned verifier")
        backend(args.tag, destination=args.assets.absolute())
        stable.verify_published(args.assets.absolute(), source_sha=args.source_sha, tag=args.tag, gh=args.gh.absolute())
    else:
        ui.require(args.repository and args.run_id and args.run_attempt and args.gh and args.cosign,
                   "producer selection and pinned verifiers are required")
        fetch(args.kind, repository=args.repository, run_id=args.run_id, attempt=args.run_attempt,
              destination=args.assets.absolute(), gh=args.gh.absolute(), cosign=args.cosign.absolute())


if __name__ == "__main__":
    main()
