from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHECKOUT = ROOT / "scripts" / "checkout_local_passport_demo_recorder.py"
RECORDER_URL = "https://github.com/ElevenID/marty-demo-recorder.git"
TIP = "022c8238c64972cf48873a8f4efcf73ae7329577"


def test_protected_passport_workflows_use_local_reviewed_recorder_source() -> None:
    workflows = {
        "passport-beta-preliminary.yml": "3ff56936f31899840e190eba066b57be2d1f2d1d",
        "passport-beta-demo-publication.yml": TIP,
        "passport-beta-final-acceptance.yml": TIP,
    }
    for name, revision in workflows.items():
        text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        assert "PASSPORT_DEMO_SOURCE_READ_TOKEN" not in text
        assert "gh repo clone ElevenID/marty-demo-recorder" not in text
        workflow = yaml.safe_load(text)
        job = next(iter(workflow["jobs"].values()))
        assert job["env"]["PASSPORT_DEMO_RECORDER_COMMIT"] == revision
        assert job["env"]["PASSPORT_DEMO_RECORDER_SOURCE_TIP"] == TIP
        checkouts = [
            step for step in job["steps"]
            if "checkout_local_passport_demo_recorder.py" in step.get("run", "")
        ]
        assert len(checkouts) == 1
        assert checkouts[0]["env"]["RECORDER_SOURCE_DIR"] == (
            "${{ vars.PASSPORT_DEMO_RECORDER_SOURCE_DIR }}"
        )


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def test_local_recorder_checkout_uses_reviewed_revision_and_rejects_stale_cache(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(source)], check=True, capture_output=True)
    git(source, "config", "user.name", "Recorder Test")
    git(source, "config", "user.email", "recorder@example.invalid")
    git(source, "remote", "add", "origin", RECORDER_URL)
    (source / "scanner.txt").write_text("reviewed scanner\n", encoding="utf-8")
    git(source, "add", "scanner.txt")
    git(source, "commit", "-m", "scanner")
    scanner = git(source, "rev-parse", "HEAD")
    (source / "verifier.txt").write_text("reviewed verifier\n", encoding="utf-8")
    git(source, "add", "verifier.txt")
    git(source, "commit", "-m", "verifier")
    tip = git(source, "rev-parse", "HEAD")
    git(source, "update-ref", "refs/remotes/origin/main", tip)

    def checkout(destination: Path, source_tip: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(CHECKOUT),
                "--source",
                str(source),
                "--source-tip",
                source_tip,
                "--revision",
                scanner,
                "--destination",
                str(destination),
            ],
            text=True,
            capture_output=True,
        )

    destination = tmp_path / "checked-out-scanner"
    result = checkout(destination, tip)
    assert result.returncode == 0, result.stderr
    assert git(destination, "rev-parse", "HEAD") == scanner
    assert (destination / "scanner.txt").read_text(encoding="utf-8") == "reviewed scanner\n"
    assert not (destination / "verifier.txt").exists()
    assert git(destination, "status", "--porcelain") == ""

    git(source, "update-ref", "refs/remotes/origin/main", scanner)
    rejected = checkout(tmp_path / "must-not-exist", tip)
    assert rejected.returncode != 0
    assert not (tmp_path / "must-not-exist").exists()
