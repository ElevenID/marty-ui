"""Pure per-role Compose preview controls; no runtime or Redis operations."""
import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_beta_binary_overlay as overlay


class SigningOverlayTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        binaries = {}
        services = {}
        for role in ["signing-keys", "gateway", "flow"]:
            name = "marty-" + role
            services[role] = {"image": "sha256:" + "a" * 64, "user": "10001:10001",
                "environment": {"KEEP": "unchanged"}, "volumes": [{"type": "bind", "source": "/old/" + name,
                "target": "/usr/local/bin/" + name, "read_only": True, "bind": {"create_host_path": False}}]}
            if role != "flow":
                p = Path(temporary.name) / name
                p.write_bytes(b"source-only-fixture")
                binaries[role] = {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        return {"name": "elevenid-beta", "services": services}, binaries

    def test_each_existing_role_model_changes_only_its_binary_source(self):
        before, binaries = self.fixture()
        for role in binaries:
            after = copy.deepcopy(before)
            after["services"][role]["volumes"][0]["source"] = binaries[role]["path"]
            overlay.validate_delta(before, after, binaries, "d02-signing-cas", [role])
            rendered = overlay.binary_overlay(binaries, "d02-signing-cas", [role])
            self.assertEqual(set(rendered["services"]), {role})

    def test_unselected_image_env_mount_and_other_binary_are_immutable(self):
        before, binaries = self.fixture()
        for change in [lambda d: d["services"]["flow"].update(image="foreign"),
                       lambda d: d["services"]["gateway"]["environment"].update(KEEP="drift"),
                       lambda d: d["services"]["gateway"]["volumes"][0].update(source=binaries["gateway"]["path"]),
                       lambda d: d["services"]["signing-keys"]["volumes"][0].update(read_only=False)]:
            after = copy.deepcopy(before)
            after["services"]["signing-keys"]["volumes"][0]["source"] = binaries["signing-keys"]["path"]
            change(after)
            with self.assertRaises(ValueError):
                overlay.validate_delta(before, after, binaries, "d02-signing-cas", ["signing-keys"])

    def test_role_set_is_closed_and_nonempty_without_silent_duplicate(self):
        for roles in [[], ["flow"], ["gateway", "gateway"], ["gateway", "issuance"]]:
            with self.assertRaises(ValueError):
                overlay.overlay_roles("d02-signing-cas", roles)
        with self.assertRaises(ValueError):
            overlay.overlay_roles(None, ["gateway"])

    def test_missing_original_executable_or_service_fails_closed(self):
        before, binaries = self.fixture()
        for delete_service in [True, False]:
            bad = copy.deepcopy(before)
            if delete_service:
                del bad["services"]["gateway"]
            else:
                bad["services"]["gateway"]["volumes"] = []
            with self.assertRaises(ValueError):
                overlay.validate_delta(bad, copy.deepcopy(bad), binaries, "d02-signing-cas", ["gateway"])

    def test_candidate_hash_ref_is_verified_without_docker(self):
        _, binaries = self.fixture()
        Path(binaries["gateway"]["path"]).write_bytes(b"changed")
        with self.assertRaises(ValueError):
            overlay.binary_overlay(binaries, "d02-signing-cas", ["gateway"])

    def test_recreate_is_one_selected_service_no_dependencies_build_or_pull(self):
        args = ["docker", "compose", "-p", "elevenid-beta", "--project-directory", "/owned/project", "-f", "/owned/base.json"]
        command = overlay.compose_recreate_arguments(args, "/owned/new.json", "d02-signing-cas", ["gateway"])
        self.assertEqual(command[-1], "gateway")
        self.assertNotIn("signing-keys", command)
        self.assertNotIn("flow", command)
        self.assertIn("--no-deps", command)
        self.assertIn("--no-build", command)
        self.assertEqual(command[command.index("--pull") + 1], "never")
        with self.assertRaises(ValueError):
            overlay.compose_recreate_arguments(args + ["up", "foreign"], "/owned/new.json", "d02-signing-cas", ["gateway"])


if __name__ == "__main__":
    unittest.main()
