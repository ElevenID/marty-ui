"""Exercise the PowerShell intent gate used by recovery preflight and resume."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


HELPER = Path(__file__).resolve().parents[1] / "scripts/beta-passport-fence-recovery-intent.ps1"


def invoke(tmp_path: Path, marker: str | None, mutation: bool, installed: str):
    if shutil.which("powershell") is None:
        pytest.skip("PowerShell is required for Windows beta recovery gate")
    fence_path = tmp_path / "fence.pending"
    mutation_path = tmp_path / "mutation.pending"
    if marker is not None:
        fence_path.write_text(marker, encoding="utf-8")
    if mutation:
        mutation_path.write_text("mutation pending\n", encoding="utf-8")
    script = tmp_path / "check.ps1"
    script.write_text(
        "param($Helper,$Fence,$Mutation,$Installed)\n"
        "$ErrorActionPreference='Stop'\n"
        ". $Helper\n"
        "$intent=Assert-BetaPassportFenceRecoveryIntent "
        "-FenceMarkerPath $Fence -MutationMarkerPath $Mutation\n"
        "Assert-BetaPassportFenceRecoveryTiming -IntentAt $intent "
        "-InstalledAt ([DateTimeOffset]::Parse($Installed))\n"
        "'verified'\n",
        encoding="utf-8",
    )
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-File", str(script),
         str(HELPER), str(fence_path), str(mutation_path), installed],
        capture_output=True, text=True, timeout=15,
    )


def test_recovery_intent_allows_measured_host_clock_skew(tmp_path: Path) -> None:
    result = invoke(
        tmp_path, "passport fence intent 2026-10-10T06:27:48.2422571Z\n",
        True, "2026-10-10T06:27:47.859Z",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "verified"


@pytest.mark.parametrize("marker,mutation,installed", [
    (None, True, "2026-10-10T06:27:47.859Z"),
    ("passport fence intent 2026-10-10T06:27:48.2422571Z\n", False,
     "2026-10-10T06:27:47.859Z"),
    ("unbound fence intent\n", True, "2026-10-10T06:27:47.859Z"),
    ("passport fence intent 2026-10-10T06:27:48.2422571Z\n", True,
     "2026-10-10T06:27:42.000Z"),
    ("passport fence intent 2026-10-10T06:27:48.2422571Z\n", True,
     "2026-10-10T06:38:00.000Z"),
])
def test_recovery_intent_rejects_missing_or_out_of_window_inputs(
    tmp_path: Path, marker: str | None, mutation: bool, installed: str,
) -> None:
    result = invoke(tmp_path, marker, mutation, installed)
    assert result.returncode != 0
    assert "verified" not in result.stdout
