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
                "rust/crates/service",
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
            self.assertEqual(result["packages"], ["acceptance", "core", "service"])

    def test_longest_package_root_owns_nested_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = planner.plan(
                ["rust/crates/core/nested/src/lib.rs"], self.metadata(root), root
            )
            self.assertEqual(result["packages"], ["nested"])

    def test_service_runtime_consumers_fail_closed_beyond_cargo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = self.metadata(root)
            notification = {
                "id": "marty-notification",
                "name": "marty-notification",
                "manifest_path": str(root / "rust/services/notification/Cargo.toml"),
                "dependencies": [{"name": "core", "kind": None}],
            }
            metadata["packages"].append(notification)
            metadata["workspace_members"].append(notification["id"])
            trust_profile = {
                "id": "marty-trust-profile",
                "name": "marty-trust-profile",
                "manifest_path": str(root / "rust/services/trust-profile/Cargo.toml"),
                "dependencies": [],
            }
            metadata["packages"].append(trust_profile)
            metadata["workspace_members"].append(trust_profile["id"])
            for path in (
                "rust/services/notification/src/main.rs",
                "rust/services/trust-profile/src/lib.rs",
                "rust/crates/core/src/lib.rs",
            ):
                with self.subTest(path=path):
                    result = planner.plan([path], metadata, root)
                    self.assertTrue(result["all"])
                    self.assertEqual(len(result["packages"]), 6)
                    self.assertIn("non-Cargo runtime consumers", result["reason"])

    def test_notification_runtime_edges_are_observed_without_narrowing(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        result = planner.plan(
            ["rust/services/notification/src/main.rs"], metadata, ROOT
        )
        self.assertTrue(result["all"])
        self.assertEqual(result["packages"], sorted(packages))
        self.assertEqual(
            {edge["package"] for edge in result["observed_non_cargo_consumers"]},
            {"marty-applicant", "marty-gateway", "marty-selfhost-bundle"},
        )
        for edge in result["observed_non_cargo_consumers"]:
            with self.subTest(consumer=edge["package"]):
                self.assertEqual(edge["producer"], "marty-notification")
                self.assertIn(edge["package"], packages)
                self.assertIn(
                    edge["binding"],
                    (ROOT / edge["evidence"]).read_text(encoding="utf-8"),
                )
                if "runtime_evidence" in edge:
                    self.assertIn(
                        edge["runtime_marker"],
                        (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8"),
                    )
                self.assertNotIn(
                    "marty-notification",
                    {dep["name"] for dep in packages[edge["package"]]["dependencies"]},
                )

    def test_notification_edge_diagnostic_does_not_replace_unknown_service_fallback(
        self,
    ) -> None:
        metadata = planner.cargo_metadata()
        result = planner.plan(
            [
                "rust/services/notification/src/main.rs",
                "rust/services/gateway/src/config.rs",
            ],
            metadata,
            ROOT,
        )
        self.assertTrue(result["all"])
        self.assertIn("unmapped non-Cargo runtime consumers", result["reason"])
        self.assertEqual(len(result["packages"]), len(metadata["workspace_members"]))

    def test_auth_outbound_runtime_edges_are_observed_without_narrowing(self) -> None:
        metadata = planner.cargo_metadata()
        members = set(metadata["workspace_members"])
        packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
        auth_dependencies = {
            dep["name"] for dep in packages["marty-auth"]["dependencies"]
        }
        providers = {
            "marty-flow": "rust/services/flow/src/lib.rs",
            "marty-organization": "rust/services/organization/src/lib.rs",
            "marty-applicant": "rust/services/applicant/src/lib.rs",
            "marty-issuance-service": "rust/services/issuance/src/lib.rs",
        }
        for provider, path in providers.items():
            with self.subTest(provider=provider):
                self.assertNotIn(provider, auth_dependencies)
                self.assertTrue((ROOT / path).is_file())
                result = planner.plan([path], metadata, ROOT)
                self.assertTrue(result["all"])
                self.assertEqual(result["packages"], sorted(packages))
                edges = [
                    edge
                    for edge in result["observed_non_cargo_consumers"]
                    if edge["producer"] == provider and edge["package"] == "marty-auth"
                ]
                self.assertEqual(len(edges), 1)
                edge = edges[0]
                self.assertIn(
                    edge["binding"],
                    (ROOT / edge["evidence"]).read_text(encoding="utf-8"),
                )
                self.assertIn(
                    edge["runtime_marker"],
                    (ROOT / edge["runtime_evidence"]).read_text(encoding="utf-8"),
                )

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
