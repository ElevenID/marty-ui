"""Replay the deleted packager against synthetic, exact-owned local fixtures only."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import ntpath
import os
import posixpath
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

REVISION = "31287d26676872736820f97ae6d6d30d0d8e65f1"
SOURCE = "scripts/package-selfhost-bundle.py"
BLOB = "77c04ba60f7a31432d210526f50e136f6bde0545"
ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "contracts/selfhost-bundle-python-reference.json"
PATH_REFERENCE = ROOT / "contracts/selfhost-bundle-path-reference.json"


def capture_paths():
    # Execute pathlib's real method with its real concrete flavour parser. Pure
    # instances supply the same parsed state without host-platform construction.
    # No path resolution or filesystem/account writes occur in these captures.
    from pathlib import __file__ as pathlib_source

    windows = [
        (
            "current",
            "~/bundle",
            {"USERPROFILE": "C:/Users/current", "USERNAME": "current"},
        ),
        (
            "named-current",
            "~current/bundle",
            {"USERPROFILE": "C:/custom/profile", "USERNAME": "current"},
        ),
        (
            "named-sibling",
            "~other/bundle",
            {"USERPROFILE": "C:/Users/current", "USERNAME": "current"},
        ),
        (
            "named-mismatch",
            "~other/bundle",
            {"USERPROFILE": "C:/custom/profile", "USERNAME": "current"},
        ),
        ("named-no-username", "~other/bundle", {"USERPROFILE": "C:/Users/current"}),
        ("homepath-only", "~/bundle", {"HOMEPATH": "C:/Users/current"}),
        (
            "drive-homepath",
            "~/bundle",
            {"HOMEDRIVE": "C:", "HOMEPATH": r"\Users\current"},
        ),
        (
            "profile-precedence",
            "~/bundle",
            {"USERPROFILE": "C:/profile", "HOMEPATH": "C:/ignored"},
        ),
        ("empty-profile", "~/bundle", {"USERPROFILE": ""}),
        ("missing-home", "~/bundle", {}),
        ("ordinary", "./bundle", {}),
        ("retained-traversal", "~/../outside", {"USERPROFILE": "C:/Users/current"}),
        (
            "named-empty-profile-current",
            "~current/bundle",
            {"USERPROFILE": "", "USERNAME": "current"},
        ),
        (
            "named-empty-profile-empty-username",
            "~other/bundle",
            {"USERPROFILE": "", "USERNAME": ""},
        ),
        (
            "named-profile-trailing-separator",
            "~other/bundle",
            {"USERPROFILE": "C:/Users/current/", "USERNAME": "current"},
        ),
        (
            "dot-named",
            "./~other/bundle",
            {"USERPROFILE": "C:/Users/current", "USERNAME": "current"},
        ),
        (
            "rooted-homepath-keeps-drive",
            "~/bundle",
            {"HOMEDRIVE": "D:/ignored", "HOMEPATH": r"\Users\current"},
        ),
    ]
    posix = [
        ("home", "~/bundle", {"HOME": "/homes/current"}, {}),
        ("empty-home", "~/bundle", {"HOME": ""}, {}),
        ("uid-home", "~/bundle", {}, {"uid": "/accounts/current"}),
        ("missing-uid", "~/bundle", {}, {}),
        ("named", "~other/bundle", {"HOME": "/ignored"}, {"other": "/accounts/other"}),
        ("named-trailing-slash", "~other/bundle", {}, {"other": "/accounts/other///"}),
        ("named-missing", "~absent/bundle", {}, {}),
        ("ordinary", "./bundle", {}, {}),
        ("retained-traversal", "~/../outside", {"HOME": "/homes/current"}, {}),
    ]
    observations = []
    for platform, rows, path_type in [
        ("windows", windows, PureWindowsPath),
        ("posix", posix, PurePosixPath),
    ]:
        for row in rows:
            name, value, environment = row[:3]
            accounts = row[3] if platform == "posix" else {}

            def lookup(key):
                if key not in accounts:
                    raise KeyError(key)
                return SimpleNamespace(pw_dir=accounts[key])

            provider = SimpleNamespace(
                getpwuid=lambda _: lookup("uid"), getpwnam=lookup
            )
            with (
                patch.dict(os.environ, environment, clear=True),
                patch.dict(sys.modules, {"pwd": provider}),
                patch.object(os, "getuid", lambda: 10001, create=True),
            ):
                try:
                    result = {"expanded": str(Path.expanduser(path_type(value)))}
                except RuntimeError as error:
                    result = {"error": type(error).__name__, "message": str(error)}
            observations.append(
                {
                    "platform": platform,
                    "name": name,
                    "input": value,
                    "environment": environment,
                    "accounts": accounts,
                    **result,
                }
            )
    return {
        "schema": "marty.selfhost-bundle-path-reference/v1",
        "packager_source_blob": BLOB,
        "python": sys.version.split()[0],
        "stdlib_sources": {
            Path(source).name: hashlib.sha256(Path(source).read_bytes()).hexdigest()
            for source in [pathlib_source, ntpath.__file__, posixpath.__file__]
        },
        "scope": "Actual pathlib.Path.expanduser with real Windows/POSIX flavour state, cleared synthetic environment and controlled read-only pwd results; no resolve, account lookup or filesystem writes.",
        "cases": observations,
    }


def capture():
    process = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{REVISION}:{SOURCE}"],
        capture_output=True,
        check=True,
        timeout=30,
    )
    raw = process.stdout
    assert (
        hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        == BLOB
    )
    namespace = {"__name__": "frozen_selfhost_packager", "__file__": SOURCE}
    exec(compile(raw, SOURCE, "exec"), namespace)
    cases = []
    for function, inputs in {
        "strip_build_blocks": [
            "services:\n  a:\n    build:\n      context: .\n      args:\n        X: y\n    image: example:v1\n",
            "services:\n  a:\n    build: .\n\n    image: example:v1\n",
            "services:\n  a:\n    image: example:v1\n",
        ],
        "image_uses_mutable_tag": [
            "example:latest",
            "example:prod@sha256:123",
            "example:main",
            "example:dev",
            "example:v1",
            "example@sha256:123",
            "example:${TAG:-latest}",
            "example:${TAG:?required}",
            "example:LATEST",
            "registry:5000/example:v1",
        ],
        "validate_image_based_compose": [
            "services:\n  a:\n    image: example:v1\n",
            "services:\n  a:\n    build: .\n    image: example:v1\n",
            "services:\n  a:\n    image: example:latest\n",
            "services:\n  a:\n    command: echo\n",
            "services:\n  b:\n    command: echo\n  a:\n    command: echo\n",
        ],
    }.items():
        for value in inputs:
            try:
                observation = {"value": namespace[function](value)}
            except (RuntimeError, ValueError) as error:
                observation = {"error": type(error).__name__, "message": str(error)}
            cases.append({"function": function, "input": value, **observation})
    with TemporaryDirectory(prefix="selfhost-packager-reference-") as temporary:
        owned = Path(temporary)
        repo, output = owned / "source", owned / "bundle"
        repo.mkdir()
        assets = [
            "SELFHOST_BUNDLE.md",
            "scripts/launch.sh",
            "config/example.bin",
            "docker-compose.selfhost.prod.yml",
            "docker-compose.selfhost.bundle.override.yml",
        ]
        for asset in assets:
            target = repo / asset
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(
                b"\xff\x00" if asset.endswith(".bin") else b"synthetic content\n"
            )
        manifest = repo / "deploy-config/bundles/selfhost.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"assets": assets}), encoding="utf-8")
        namespace["stage_bundle"](repo, output)
        calls = []

        def render(argv, **kwargs):
            calls.append({"argv": argv, "cwd_is_output": kwargs["cwd"] == output})
            return SimpleNamespace(
                stdout=(
                    "services:\n  app:\n    build:\n      context: .\n    image: example:v1\n"
                    f"    volumes:\n      - type: bind\n        source: {output / 'scripts/launch.sh'}\n        target: /launch.sh\n"
                    f"secrets:\n  operator:\n    file: {output}/"
                    + "${SECRET_DIR}/key\n"
                )
            )

        with patch.object(namespace["subprocess"], "run", render):
            namespace["render_bundle_compose"](output)
        namespace["remove_source_compose_inputs"](output)
        namespace["validate_customer_output"](output)
        directory = {
            path.relative_to(output).as_posix(): path.read_bytes().hex()
            for path in sorted(output.rglob("*"))
            if path.is_file()
        }
        archive = namespace["shutil"].make_archive(
            str(owned / "archive"), "zip", root_dir=output.parent, base_dir=output.name
        )
        with zipfile.ZipFile(archive) as zipped:
            members = {
                item.filename: zipped.read(item).hex()
                for item in zipped.infolist()
                if not item.is_dir()
            }
            archive_directories = sorted(
                item.filename for item in zipped.infolist() if item.is_dir()
            )
        staging = {
            "assets": assets,
            "directory_hex": directory,
            "archive_files_hex": members,
            "archive_directories": archive_directories,
            "render_calls": calls,
            "top_level_shell_executable": bool(
                (output / "scripts/launch.sh").stat().st_mode & 0o111
            ),
        }
    return {
        "schema": "marty.selfhost-bundle-python-reference/v1",
        "reference": {
            "revision": REVISION,
            "source": SOURCE,
            "blob": BLOB,
            "scope": "Original pure transformations and synthetic directory/ZIP with controlled Compose renderer; no deployed stack or image provenance proof. ZIP bytes/timestamps and host permission representation are not portable parity claims.",
        },
        "cases": cases,
        "staging": staging,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--path-reference", action="store_true")
    args = parser.parse_args()
    observed = capture_paths() if args.path_reference else capture()
    reference = PATH_REFERENCE if args.path_reference else REFERENCE
    if args.check:
        assert observed == json.loads(reference.read_text(encoding="utf-8"))
        print(
            "PASS: actual pathlib Windows/POSIX expansion with controlled account/environment inputs"
            if args.path_reference
            else "PASS: deleted self-host packager reference, controlled renderer and actual synthetic directory/ZIP"
        )
    else:
        print(json.dumps(observed, indent=2))


if __name__ == "__main__":
    main()
