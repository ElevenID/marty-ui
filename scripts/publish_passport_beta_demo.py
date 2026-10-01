#!/usr/bin/env python3
"""Launch a reviewed D-12 publication on beta while watching production."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

if __package__:
    from .collect_passport_beta_acceptance import EvidenceError, verify_attestations
    from .collect_passport_beta_aggregate_acceptance import collect_aggregate
    from .probe_passport_beta_host import (
        HostProbeError,
        assert_production_unchanged,
        production_attachment_sha256,
        production_snapshot,
    )
    from .produce_passport_beta_demo_publication import (
        PublicationEvidenceError,
        public_http,
        require,
        require_beta_deploy_config,
    )
else:
    from collect_passport_beta_acceptance import EvidenceError, verify_attestations
    from collect_passport_beta_aggregate_acceptance import collect_aggregate
    from probe_passport_beta_host import (
        HostProbeError,
        assert_production_unchanged,
        production_attachment_sha256,
        production_snapshot,
    )
    from produce_passport_beta_demo_publication import (
        PublicationEvidenceError,
        public_http,
        require,
        require_beta_deploy_config,
    )


SHA = re.compile(r"[0-9a-f]{40}\Z")
BETA_ORIGIN = "https://beta.elevenidllc.com"
NODE_VERSION = re.compile(r"v([0-9]+)\.[0-9]+\.[0-9]+\Z")
REVIEWED_UI_FILES = (
    "scripts/publish_passport_beta_demo.py",
    "scripts/produce_passport_beta_demo_publication.py",
    "scripts/deploy-passport-demo-content-beta.ps1",
    "scripts/deploy-demo-content.ps1",
    "tests/scripts/smoke-beta-demo-publication.js",
)


def publication_environment(recorder_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    entries = [entry for entry in env.get("WSLENV", "").split(":") if entry]
    for name, rule in (
        ("ELEVENID_DEMO_MANIFEST", "ELEVENID_DEMO_MANIFEST/p"),
        ("ELEVENID_DEMO_VIDEO_ID", "ELEVENID_DEMO_VIDEO_ID"),
    ):
        existing = [entry for entry in entries
                    if entry.split("/", 1)[0] == name]
        require(not existing or existing == [rule],
                f"WSL {name} translation is invalid")
        if not existing:
            entries.append(rule)
    env["WSLENV"] = ":".join(entries)
    env["NODE_PATH"] = str(recorder_root / "node_modules")
    env["BETA_ORIGIN"] = BETA_ORIGIN
    return env


def require_oauth_files() -> None:
    for name in ("YOUTUBE_OAUTH_CLIENT_FILE", "YOUTUBE_OAUTH_TOKEN_FILE"):
        candidate = Path(os.environ.get(name, ""))
        require(candidate.is_absolute() and candidate.is_file()
                and not candidate.is_symlink(),
                "Protected YouTube OAuth files are unavailable")
        if name.endswith("TOKEN_FILE"):
            require(candidate.stat().st_mode & 0o777 == 0o600,
                    "Protected YouTube token permissions changed")


def require_node24() -> None:
    try:
        version = subprocess.run(
            ["node", "--version"], check=True, capture_output=True,
            text=True, timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublicationEvidenceError("Node.js 24 or later is unavailable") from exc
    match = NODE_VERSION.fullmatch(version)
    require(match is not None and int(match.group(1)) >= 24,
            "Node.js 24 or later is required by the pinned recorder")


def require_browser(recorder_root: Path, repo_root: Path) -> None:
    probe = (
        "const {chromium}=require('@playwright/test');"
        "chromium.launch({headless:true})"
        ".then(browser=>browser.close())"
        ".catch(error=>{console.error(error.message);process.exitCode=1});"
    )
    try:
        subprocess.run(
            ["node", "-e", probe], cwd=repo_root,
            env=publication_environment(recorder_root),
            check=True, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublicationEvidenceError(
            "Pinned Chromium or its WSL dependencies are unavailable"
        ) from exc


def require_signed_ui_source(artifact_dir: Path, repo_root: Path) -> None:
    api_key = os.environ.get("PASSPORT_ACCEPTANCE_API_KEY", "")
    require(artifact_dir.is_absolute() and artifact_dir.is_dir()
            and len(api_key) >= 32,
            "Signed aggregate artifacts or organization key are unavailable")
    live = collect_aggregate(artifact_dir, api_key=api_key,
                             attest=verify_attestations)
    source = live["release"]["source_commit"]
    require(SHA.fullmatch(source) is not None,
            "Signed aggregate source is invalid")
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        content = subprocess.run(
            ["git", "diff", "--quiet", source, "--", *REVIEWED_UI_FILES],
            cwd=repo_root, check=False, capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublicationEvidenceError("Signed UI checkout is unavailable") from exc
    require(head == source and content.returncode == 0,
            "Publisher or beta deployment code differs from the signed UI source")


def publish(artifact_dir: Path, config: Path, video: Path, recorder_root: Path,
            recorder_commit: str) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    require(Path.cwd().resolve() == repo_root,
            "D-12 publisher must launch from the reviewed UI checkout")
    require(config.is_absolute() and config.is_file() and not config.is_symlink()
            and video.is_absolute() and video.is_file() and not video.is_symlink()
            and recorder_root.is_absolute() and recorder_root.is_dir()
            and not recorder_root.is_symlink()
            and SHA.fullmatch(recorder_commit) is not None,
            "Reviewed D-12 publication inputs are unavailable")
    require_beta_deploy_config(config)
    require_signed_ui_source(artifact_dir, repo_root)
    require(shutil.which("powershell.exe") is not None
            and shutil.which("node") is not None
            and (recorder_root / "node_modules" / "@playwright" / "test").is_dir(),
            "WSL publication tools or locked browser are unavailable")
    require_node24()
    require_browser(recorder_root, repo_root)
    require_oauth_files()
    try:
        head = subprocess.run(
            ["git", "-C", str(recorder_root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(recorder_root), "status", "--porcelain"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublicationEvidenceError("Pinned recorder checkout is unavailable") from exc
    require(head == recorder_commit and not dirty,
            "Pinned recorder revision changed before publication")

    before = production_snapshot()
    attachments_before = production_attachment_sha256()
    public_http()
    failure: Exception | None = None
    try:
        subprocess.run(
            ["node", str(recorder_root / "src" / "automatedPublication.js"),
             "--config", str(config), "--video", str(video)],
            cwd=repo_root, env=publication_environment(recorder_root),
            check=True, capture_output=True, text=True, timeout=75 * 60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        failure = exc
    finally:
        after = production_snapshot()
        attachments_after = production_attachment_sha256()
        assert_production_unchanged(before, after)
        require(attachments_before == attachments_after,
                "Production network attachments changed during D-12 publication")
        public_http()
    if failure is not None:
        raise PublicationEvidenceError("Reviewed D-12 beta publication failed") from failure


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--video", type=Path, required=True)
    parser.add_argument("--recorder-root", type=Path, required=True)
    parser.add_argument("--recorder-commit", required=True)
    args = parser.parse_args()
    try:
        publish(args.artifact_dir, args.config, args.video,
                args.recorder_root, args.recorder_commit)
    except (PublicationEvidenceError, HostProbeError, EvidenceError) as exc:
        parser.exit(1, f"{exc}\n")
    print("Reviewed D-12 beta publication completed; production baseline unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
