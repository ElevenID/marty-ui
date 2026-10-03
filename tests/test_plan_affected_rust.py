"""The shadow planner must broaden when Cargo ownership is insufficient."""

from __future__ import annotations

from pathlib import Path
from contextlib import redirect_stdout
import io
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import plan_affected_rust as planner  # noqa: E402


class AffectedRustPlannerTests(unittest.TestCase):
    def metadata(self, root: Path) -> dict:
        def package(name: str, directory: str, dependencies: list[dict]) -> dict:
            return {
                "id": name,
                "name": name,
                "manifest_path": str(root / directory / "Cargo.toml"),
                "dependencies": dependencies,
            }

        packages = [
            package("core", "rust/crates/core", []),
            package("nested", "rust/crates/core/nested", []),
            package(
                "service",
                "rust/services/service",
                [{"name": "core", "rename": "local_core", "kind": "dev"}],
            ),
            package(
                "acceptance",
                "rust/crates/acceptance",
                [{"name": "service", "kind": "build"}],
            ),
        ]
        return {"packages": packages, "workspace_members": [p["id"] for p in packages]}

    def test_package_inputs_select_alias_dev_and_build_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = planner.plan(
                ["rust/crates/core/fixtures/ü spaced.json"], self.metadata(root), root
            )
            self.assertFalse(result["all"])
            self.assertEqual(result["direct"], ["core"])
            self.assertEqual(
                result["packages"], ["acceptance", "core", "service"]
            )

    def test_longest_package_root_owns_nested_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = planner.plan(
                ["rust/crates/core/nested/src/lib.rs"], self.metadata(root), root
            )
            self.assertEqual(result["packages"], ["nested"])

    def test_shared_and_unowned_inputs_request_full_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in (
                "rust/Cargo.lock",
                "rust/third_party/ssi-jwt/src/lib.rs",
                "rust/deleted-crate/fixture.json",
                "contracts/canvas-worker-oracle.json",
                "proto/candidate.proto",
                "services/Dockerfile",
                ".github/workflows/ci.yml",
            ):
                with self.subTest(path=path):
                    result = planner.plan([path], self.metadata(root), root)
                    self.assertTrue(result["all"])
                    self.assertEqual(len(result["packages"]), 4)

    def test_empty_diff_is_explicit_and_does_not_change_current_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = planner.plan([], self.metadata(Path(directory)), Path(directory))
            self.assertEqual(result["packages"], [])
            self.assertFalse(result["all"])

    def test_empty_metadata_does_not_prove_no_affected_packages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "no workspace packages"):
                planner.plan(
                    ["rust/crates/core/src/lib.rs"],
                    {"packages": [], "workspace_members": []},
                    Path(directory),
                )

    def test_missing_diff_revision_reports_full_selection(self) -> None:
        output = io.StringIO()
        with patch.dict("os.environ", {"BASE_SHA": "", "HEAD_SHA": ""}):
            with redirect_stdout(output):
                self.assertEqual(planner.main(), 0)
        result = json.loads(output.getvalue().removeprefix("affected-rust-shadow: "))
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], ["*"])

    def test_git_diff_keeps_deleted_and_moved_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args: str) -> str:
                return subprocess.run(
                    ["git", *args],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            (root / "rust" / "crates" / "core").mkdir(parents=True)
            old = root / "rust" / "crates" / "core" / "ü old.json"
            old.write_text("fixture", encoding="utf-8")
            deleted = root / "rust" / "crates" / "core" / "deleted.json"
            deleted.write_text("deleted", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "before")
            base = git("rev-parse", "HEAD")
            old.rename(root / "rust" / "crates" / "core" / "new.json")
            deleted.unlink()
            git("add", "-A")
            git("commit", "-qm", "after")
            with patch.object(planner, "ROOT", root):
                paths = planner.changed_paths(base, "HEAD")
            self.assertEqual(
                set(paths),
                {
                    "rust/crates/core/ü old.json",
                    "rust/crates/core/new.json",
                    "rust/crates/core/deleted.json",
                },
            )


if __name__ == "__main__":
    unittest.main()
