"""Audit every frontend finding; bound one reviewed dev-only ReDoS disposition.

Owner: Marty platform maintainers. Tracking: marty-ui PR #1987.
This accepts temporary CI/development CPU-denial risk, not a security fix.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
import sys

ADVISORY = "GHSA-fc5q-39xc-vjpf"
ADVISORY_URL = "https://github.com/advisories/" + ADVISORY
ADVISORY_NUMBER = 1247710
EXPIRY = datetime(2026, 11, 24, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[2]
# Existing optional-prerenderer disposition, unchanged by this policy.
LEGACY_BUN_IGNORE = "GHSA-vfj7-8cjw-p6xm"
# Exact reviewed UI/source and dev graph. Any context drift requires new review.
CONTEXT_SHA256 = {
    "ui/package.json": "a931316e175a08b6911baada7d8d0fc638d1f1562f4d8f99b0291263909d1b97",
    "ui/package-lock.json": "6f5876841760be8417e96d2ff71c3d24958bf7bdd7fecb0ef8414ff6014f7978",
    "ui/bun.lock": "4437f4ccf2392d58795a4b9b80a4d0af10fb7c0fbb6598c8c7a16fc282b015a0",
    "ui/vite.config.ts": "336e294f0b1472813f629afded5ab0d7224ad0e20234252337be0c61a2ad1b6f",
    "ui/Dockerfile.prod": "d6637ef8f748274d468400217d7c8b8e52d925bb43748a11dbc6d7fea9ce2cec",
    "ui/nginx.prod.conf": "89849952a76018c440bf46ded2988cbbeb9dfd820e9de25b9c413b6dbb6a6ad7",
    "ui/nginx.website.conf": "1685be43d03e871ee63190a7f8bc5bac971b58fb7620537beaf296352dc2cb7b",
    "ui/nginx.spa.conf": "43dc99ed4dee55641067354e0822e19710a622121219655c0fb87850ebe3d5c6",
    "ui/nginx.website.headers.conf": "f7c774d68b35302f0483e6c28aaf93a0be1de537297470ff077681a3b973a4c4",
    "ui/src": "ac36b01251eeaed20b3416d6a6ed461f56c833ded38d3a68f7dc97414887eb05",
    "ui/scripts": "6fd96f39473a8af2d4ea3fba1dfc23895035e40bbb838da2d59cc4c9f2223c4b",
    "ui/.storybook": "7c2f2cc2136d9906393f83d850c2b24fe1cf70d2d87993924d01c340e2cd8d10"
}
TREE_PATHS = {"ui/src", "ui/scripts", "ui/.storybook"}


class Refused(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refused(message)


def no_link(path: Path) -> None:
    require(not path.is_symlink() and not path.is_junction(), "Source links are not reviewed")


def tree_digest(base: Path) -> str:
    no_link(base)
    require(base.is_dir(), "Missing reviewed source tree")
    digest = hashlib.sha256()
    for path in sorted(base.rglob("*"), key=lambda p: p.relative_to(base).as_posix()):
        no_link(path)
        if path.is_file():
            name = path.relative_to(base).as_posix().encode()
            digest.update(len(name).to_bytes(8, "big"))
            digest.update(name)
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        else:
            require(path.is_dir(), "Unsupported source entry")
    return digest.hexdigest()


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


def admission_time(now: datetime) -> None:
    require(now.tzinfo is not None and now.utcoffset() is not None, "Aware clock required")
    require(now.astimezone(timezone.utc) < EXPIRY, "Dev-only advisory disposition expired")


def reviewed_context(root: Path, now: datetime) -> dict:
    admission_time(now)
    for relative, expected in CONTEXT_SHA256.items():
        path = root / relative
        require(path.resolve().is_relative_to(root.resolve()), "Reviewed source escapes repository")
        for component in (path, *path.parents):
            no_link(component)
            if component == root:
                break
        require(path.is_dir() if relative in TREE_PATHS else path.is_file(), "Missing reviewed input")
        actual = tree_digest(path) if relative in TREE_PATHS else hashlib.sha256(path.read_bytes()).hexdigest()
        require(actual == expected, "Reviewed frontend context changed")
    lock = document((root / "ui/package-lock.json").read_text(encoding="utf-8"))
    require(lock.get("lockfileVersion") == 3 and isinstance(lock.get("packages"), dict),
            "Unsupported dependency lock")
    nodes = {name: row for name, row in lock["packages"].items()
             if name.endswith("node_modules/picomatch")}
    require(set(nodes) == {"node_modules/picomatch", "node_modules/micromatch/node_modules/picomatch"},
            "Picomatch dependency paths changed")
    require(all(isinstance(row, dict) and row.get("dev") is True for row in nodes.values()),
            "Picomatch must remain dev-only")
    require(nodes["node_modules/picomatch"].get("version") == "4.0.7"
            and nodes["node_modules/micromatch/node_modules/picomatch"].get("version") == "2.3.2",
            "Picomatch versions changed")
    return lock["packages"]


def known_advisory(row: dict, *, bun: bool) -> bool:
    return (row.get("url") == ADVISORY_URL and row.get("severity") == "high"
            and row.get("id" if bun else "source") == ADVISORY_NUMBER
            and row.get("vulnerable_versions" if bun else "range") == "<=4.0.7"
            and (bun or (row.get("name") == "picomatch" and row.get("dependency") == "picomatch")))


def bun_findings(report: dict) -> bool:
    require("error" not in report, "Bun audit failed")
    for name, rows in report.items():
        require(name == "picomatch" and isinstance(rows, list) and bool(rows),
                "Unreviewed frontend advisory")
        require(all(isinstance(row, dict) and known_advisory(row, bun=True) for row in rows),
                "Unreviewed frontend advisory")
    return bool(report)


def npm_findings(report: dict, packages: dict) -> bool:
    require(report.get("auditReportVersion") == 2 and "error" not in report,
            "Unsupported npm audit report")
    rows = report.get("vulnerabilities")
    require(isinstance(rows, dict), "Missing npm findings")
    counts = report.get("metadata", {}).get("vulnerabilities", {})
    require(counts.get("total") == len(rows), "Incomplete npm findings")
    for name, row in rows.items():
        require(isinstance(row, dict) and row.get("name") == name and row.get("severity") == "high",
                "Malformed or reclassified npm finding")
        nodes = row.get("nodes")
        require(isinstance(nodes, list) and bool(nodes)
                and all(isinstance(n, str) and isinstance(packages.get(n), dict)
                        and packages[n].get("dev") is True for n in nodes),
                "Advisory chain must remain dev-only")
        via = row.get("via")
        require(isinstance(via, list) and bool(via), "Missing npm advisory cause")
        for cause in via:
            require((isinstance(cause, str) and cause in rows)
                    or (isinstance(cause, dict) and name == "picomatch" and known_advisory(cause, bun=False)),
                    "Unreviewed frontend advisory")
    # npm can report cycles (Vitest/UI/coverage). Traverse every cause, requiring
    # an actual reviewed root; cycles alone never establish an accepted finding.
    for name in rows:
        pending, seen, roots = [name], set(), 0
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            for cause in rows[current]["via"]:
                if isinstance(cause, str):
                    pending.append(cause)
                else:
                    roots += 1
        require(roots > 0, "Unresolved npm advisory cycle")
    return bool(rows)


def scan(command: list[str], root: Path) -> tuple[dict, int]:
    executable = shutil.which(command[0])
    require(executable is not None, "Missing dependency scanner")
    result = subprocess.run([executable, *command[1:]], cwd=root / "ui", stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, encoding="utf-8", timeout=120, check=False)
    require(result.returncode in (0, 1), "Dependency scanner failed")
    return document(result.stdout), result.returncode


def audit(root: Path, now: datetime | None = None) -> None:
    bun, bun_status = scan(["bun", "audit", "--json", "--ignore", LEGACY_BUN_IGNORE], root)
    npm, npm_status = scan(["npm", "audit", "--json", "--omit=optional", "--package-lock-only",
                            "--audit-level=low"], root)
    bun_present = bun_findings(bun)
    require(bun_present == (bun_status == 1), "Inconsistent Bun audit result")
    npm_rows = npm.get("vulnerabilities")
    require(isinstance(npm_rows, dict), "Missing npm findings")
    # Context/expiry checks are needed only while this advisory is present.
    # Removing the exposure and all findings can pass without extending debt.
    packages = (reviewed_context(root, datetime.now(timezone.utc) if now is None else now)
                if bun_present or npm_rows else {})
    npm_present = npm_findings(npm, packages)
    require(npm_present == (npm_status == 1), "Inconsistent npm audit result")
    if bun_present or npm_present:
        # Scans and hashing can cross midnight; sample actual UTC again at the
        # final admission boundary. A fixed clock is for direct unit calls only.
        admission_time(datetime.now(timezone.utc) if now is None else now)
        print("Accepted exact dev-only picomatch disposition until 2026-11-24 UTC; CI/dev DoS risk remains")
    else:
        print("Frontend dependency audits passed without the temporary disposition")


def main() -> int:
    if len(sys.argv) != 1:
        print("Frontend dependency audit accepts no arguments", file=sys.stderr)
        return 1
    try:
        audit(ROOT)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        # Scanner documents and stderr are untrusted; never echo source fragments.
        print("Frontend dependency audit refused; inspect the reviewed policy and scanner findings", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
