#!/usr/bin/env python3
"""Push an exact late release tag with local GitHub credentials, never CI secrets.

Use only after the Stack release run has uploaded its promotion-complete
checkpoint. The first run intentionally stops at the tag gate; resume from
that checkpoint after this command succeeds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__:
    from .release_transaction import IMAGE_URIS, validate_resume
else:
    from release_transaction import IMAGE_URIS, validate_resume

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "ElevenID/marty-ui"


def command(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=check)


def output(*args: str) -> str:
    return command(*args).stdout.strip()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def promotion_artifact(run_id: str, name: str) -> tuple[int, str]:
    listing = json.loads(output(
        "gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100",
    ))
    matches = [artifact for artifact in listing["artifacts"]
               if artifact["name"] == name and not artifact["expired"]]
    require(len(matches) == 1, "Expected exactly one unexpired promotion checkpoint")
    artifact = matches[0]
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest", "")) is not None,
            "Promotion checkpoint has no valid immutable digest")
    return artifact["id"], artifact["digest"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--promotion-run-id", required=True)
    parser.add_argument("--claim-run-id", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[1-9][0-9]*", args.promotion_run_id) is not None,
            "Invalid promotion run ID")
    require(re.fullmatch(r"[1-9][0-9]*", args.claim_run_id) is not None,
            "Invalid claim run ID")
    require(not output("git", "status", "--porcelain"), "Checkout must be clean")
    require(output("git", "branch", "--show-current") == "main",
            "Use a clean main checkout")
    official_urls = {"https://github.com/ElevenID/marty-ui.git",
                     "https://github.com/ElevenID/marty-ui",
                     "git@github.com:ElevenID/marty-ui.git"}
    require(output("git", "remote", "get-url", "origin") in official_urls and
            output("git", "remote", "get-url", "--push", "origin") in official_urls,
            "origin fetch and push URLs must target the official release repository")
    source = output("git", "rev-parse", "HEAD^{commit}")
    remote_main = output("git", "ls-remote", "origin", "refs/heads/main").split()[0]
    require(source == remote_main, "Checkout must equal current protected main")

    run = json.loads(output("gh", "api", f"repos/{REPOSITORY}/actions/runs/{args.promotion_run_id}"))
    require(run.get("path") == ".github/workflows/cd.yml", "Checkpoint run is not Stack release")
    require(run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main",
            "Checkpoint run was not dispatched from main")
    require(run.get("head_sha") == source, "Checkpoint run differs from current main")
    require(run.get("run_attempt") == 1 and run.get("status") == "completed"
            and run.get("conclusion") == "failure",
            "Expected the completed first-attempt handoff run")
    jobs = json.loads(output("gh", "api", f"repos/{REPOSITORY}/actions/runs/"
                        f"{args.promotion_run_id}/jobs?per_page=100"))["jobs"]
    publishers = [job for job in jobs if job["name"] == "publish-manifest"]
    require(len(publishers) == 1 and publishers[0]["run_attempt"] == 1,
            "Expected one first-attempt publication job")
    require(all(job["conclusion"] in {"success", "skipped"}
                for job in jobs if job["name"] != "publish-manifest"),
            "Another release job failed or did not finish")
    steps = publishers[0]["steps"]
    handoff = [step for step in steps
               if step["name"] == "Create or verify the late annotated source tag"]
    require(len(handoff) == 1 and handoff[0]["conclusion"] == "failure",
            "Publication did not stop at the local tag handoff")
    artifact = f"stack-release-promotion-complete-{args.promotion_run_id}"
    artifact_identity = promotion_artifact(args.promotion_run_id, artifact)
    with tempfile.TemporaryDirectory(prefix="marty-promoted-tag-") as directory:
        command("gh", "run", "download", args.promotion_run_id,
                "--repo", REPOSITORY, "--name", artifact, "--dir", directory)
        path = Path(directory) / "release-transaction.json"
        require(path.is_file() and len(list(Path(directory).iterdir())) == 1,
                "Promotion artifact has unexpected contents")
        require(path.stat().st_size <= 65536, "Promotion transaction is oversized")
        transaction = validate_resume(
            json.loads(path.read_text(encoding="utf-8")), repository=REPOSITORY,
            source_sha=source, stack_lock=ROOT / "release/stack-lock.json",
            claim_run_id=args.claim_run_id, required_state="promoted",
        )
    require(promotion_artifact(args.promotion_run_id, artifact) == artifact_identity,
            "Promotion checkpoint changed while downloading")
    tag = transaction["tag"]
    require(not output("git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}",
                       f"refs/tags/{tag}^{{}}"), "Release tag already exists")
    release = command("gh", "api", "-i", f"repos/{REPOSITORY}/releases/tags/{tag}", check=False)
    require(release.stdout.startswith("HTTP/2.0 404") or
            release.stdout.startswith("HTTP/2 404") or
            release.stdout.startswith("HTTP/1.1 404"),
            "Release lookup did not confirm absence")
    version = transaction["version"]
    for role, image in IMAGE_URIS.items():
        raw = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", "--raw", f"{image}:{version}"],
            cwd=ROOT, capture_output=True, check=True,
        ).stdout
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        require(digest == transaction["images"][role]["digest"],
                f"Promoted {role} digest differs from the checkpoint")

    message = (f"Release {version}\n\n"
               f"Release-Transaction: {transaction['transaction_id']}\n"
               f"Claim-Run: {args.claim_run_id}\n"
               f"Source-SHA: {source}\n")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as file:
        file.write(message)
        message_file = Path(file.name)
    try:
        command("git", "tag", "-a", tag, source, "-F", str(message_file))
    finally:
        message_file.unlink(missing_ok=True)
    try:
        command("gh", "auth", "setup-git")
        require(output("git", "ls-remote", "origin", "refs/heads/main").split()[0]
                == source, "Protected main advanced before the tag push")
        # Include an unchanged main ref in the atomic push. If main advances
        # during this final check, the non-fast-forward main update rejects
        # the entire transaction, including the new tag.
        command("git", "push", "--atomic", "origin", f"{source}:refs/heads/main",
                f"refs/tags/{tag}:refs/tags/{tag}")
    except subprocess.CalledProcessError:
        command("git", "tag", "-d", tag, check=False)
        raise
    print(f"Pushed {tag}. Resume Stack release with claim_run_id={args.claim_run_id}, "
          f"resume_run_id={args.promotion_run_id}, resume_artifact={artifact}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Late release tag refused: {error}", file=sys.stderr)
        raise SystemExit(1) from error
