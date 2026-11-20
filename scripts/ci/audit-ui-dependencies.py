"""Require clean frontend dependency audits at the existing scanner scopes.

The withdrawn picomatch advisory has no acceptance path. See the reviewed
retirement evidence in docs/dependency-maintenance-exceptions.md.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
# Existing optional-prerenderer disposition, unchanged by this policy.
LEGACY_BUN_IGNORE = "GHSA-vfj7-8cjw-p6xm"


class Refused(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refused(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate audit JSON field")
        result[key] = value
    return result


def document(raw: str) -> dict:
    result = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(result, dict), "Unsupported audit document")
    return result


def bun_findings(report: dict) -> bool:
    require(isinstance(report, dict), "Unsupported Bun audit report")
    require("error" not in report, "Bun audit failed")
    require(not report, "Frontend dependency findings are not accepted")
    return False


def npm_findings(report: dict) -> bool:
    require(isinstance(report, dict) and type(report.get("auditReportVersion")) is int
            and report["auditReportVersion"] == 2 and "error" not in report,
            "Unsupported npm audit report")
    rows = report.get("vulnerabilities")
    require(isinstance(rows, dict), "Missing npm findings")
    metadata = report.get("metadata")
    require(isinstance(metadata, dict), "Missing npm metadata")
    counts = metadata.get("vulnerabilities")
    require(isinstance(counts, dict) and "total" in counts
            and set(counts) <= {"info", "low", "moderate", "high", "critical", "total"}
            and all(type(count) is int and count >= 0 for count in counts.values()),
            "Unsupported npm vulnerability counts")
    require(counts["total"] == len(rows), "Incomplete npm findings")
    require(not rows, "Frontend dependency findings are not accepted")
    require(all(count == 0 for count in counts.values()), "Inconsistent npm vulnerability counts")
    return False


def scan(command: list[str], root: Path) -> tuple[dict, int]:
    executable = shutil.which(command[0])
    require(executable is not None, "Missing dependency scanner")
    result = subprocess.run([executable, *command[1:]], cwd=root / "ui", stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, encoding="utf-8", timeout=120, check=False)
    require(result.returncode in (0, 1), "Dependency scanner failed")
    return document(result.stdout), result.returncode


def audit(root: Path) -> None:
    bun, bun_status = scan(["bun", "audit", "--json", "--ignore", LEGACY_BUN_IGNORE], root)
    npm, npm_status = scan(["npm", "audit", "--json", "--omit=optional", "--package-lock-only",
                            "--audit-level=low"], root)
    bun_present = bun_findings(bun)
    require(bun_present == (bun_status == 1), "Inconsistent Bun audit result")
    npm_present = npm_findings(npm)
    require(npm_present == (npm_status == 1), "Inconsistent npm audit result")
    print("Frontend dependency audits passed without findings")


def main() -> int:
    if len(sys.argv) != 1:
        print("Frontend dependency audit accepts no arguments", file=sys.stderr)
        return 1
    try:
        audit(ROOT)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        # Scanner documents and stderr are untrusted; never echo source fragments.
        print("Frontend dependency audit refused; inspect scanner findings", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
