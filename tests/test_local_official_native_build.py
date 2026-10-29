"""Source-only controls for the frozen all-service KMS build profile."""
import importlib
import subprocess
import tempfile
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
build = importlib.import_module("scoped_native_build")
profiles = importlib.import_module("scoped_native_profiles")
prepare = importlib.import_module("prepare_local_official_native_build")
launcher = importlib.import_module("run_local_official_native_build")


class OfficialNativeBuildTests(unittest.TestCase):
    def setUp(self):
        self.profile = profiles.OFFICIAL_ALL_SERVICES
        self.scope = build.build_scope(self.profile.name)
        self.freeze = {"productRevision": self.profile.ui_revision,
                       "coreRevision": "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac",
                       "imagesBuilt": False, "releaseQualified": False}
        self.seed = {"state": "COPIED_AND_READBACK_MATCHED",
                     "targetVolume": self.profile.volumes[1],
                     "sourceTarget": "marty-demo-native-cache-20261021/target",
                     "copyKind": "ordinary-byte-copy-no-hardlinks",
                     "sourceManifestSha256": "a" * 64,
                     "targetManifestSha256": "a" * 64,
                     "sourceBeforeAfterMatched": True,
                     "sourceMountedReadOnly": True,
                     "targetHardlinksToSource": False}
        self.script = (Path(__file__).resolve().parents[1] / "scripts/build-rust-service-binaries.sh").read_text()

    def test_canonical_29_release_outputs_and_kms_proof_are_required(self):
        build.verify_official_inputs(self.freeze, self.seed, self.script, self.scope)
        recipe = build.render_recipe(self.profile.name)
        self.assertEqual(len(self.scope["roles"]), 29)
        self.assertIn("sh /build/tool.sh default --offline -j1 --message-format=json", recipe)
        self.assertIn("CARGO_BUILD_JOBS=1 CARGO_NET_OFFLINE=true", recipe)
        self.assertIn("/target/release/", recipe)
        self.assertIn("guard.FORBIDDEN_FEATURES", recipe)
        self.assertIn("'kms-only' in features", recipe)
        self.assertIn("compiler-artifacts.jsonl", recipe)
        for delimiter in ("LOCK_BOUNDARY", "BOUNDARY", "ARTIFACTS"):
            code = recipe.split("<<'" + delimiter + "'\n", 1)[1].split("\n" + delimiter, 1)[0]
            compile(code, delimiter, "exec")

    def test_wrong_lineage_or_seed_refuses_before_compiler(self):
        for field, value in (("productRevision", "f" * 40), ("coreRevision", "f" * 40),
                             ("imagesBuilt", True), ("releaseQualified", True)):
            bad = dict(self.freeze, **{field: value})
            with self.assertRaisesRegex(ValueError, "EXACT_OFFICIAL_SOURCE_FREEZE_REQUIRED"):
                build.verify_official_inputs(bad, self.seed, self.script, self.scope)
        for field, value in (("targetVolume", "d05-rust-target-20261026"),
                             ("targetHardlinksToSource", True),
                             ("targetManifestSha256", "b" * 64),
                             ("sourceBeforeAfterMatched", False)):
            bad = dict(self.seed, **{field: value})
            with self.assertRaisesRegex(ValueError, "ISOLATED_TARGET_SEED_REQUIRED"):
                build.verify_official_inputs(self.freeze, bad, self.script, self.scope)
        script = self.script.replace("--bin marty-flow", "--bin marty-gateway")
        with self.assertRaisesRegex(ValueError, "CANONICAL_ALL_SERVICES_SET_CHANGED"):
            build.verify_official_inputs(self.freeze, self.seed, script, self.scope)
        with self.assertRaisesRegex(ValueError, "BUILD_TOOL_BINARY_SET_CHANGED"):
            build.verify_official_inputs(self.freeze, self.seed, self.script,
                                         self.scope, script)

    def test_resource_probe_uses_isolated_pair_then_restores_shared_defaults(self):
        observations = []
        helper = SimpleNamespace(VOLUMES=build.VOLUMES)
        with build.selected_resource_volumes(helper, self.profile.volumes):
            observations.append(helper.VOLUMES)
        self.assertEqual(observations, [self.profile.volumes])
        self.assertEqual(helper.VOLUMES, build.VOLUMES)
        with self.assertRaisesRegex(RuntimeError, "probe failed"):
            with build.selected_resource_volumes(helper, self.profile.volumes):
                raise RuntimeError("probe failed")
        self.assertEqual(helper.VOLUMES, build.VOLUMES)

    def test_pinned_engine_uuid_and_debug_artifact_directory(self):
        launcher.require_build_identifiers("11111111-1111-4111-8111-111111111111",
                                           "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341")
        with self.assertRaisesRegex(ValueError, "OWNED_BUILD_IDENTIFIERS_REQUIRED"):
            launcher.require_build_identifiers("11111111-1111-4111-8111-111111111111", "f" * 64)
        self.assertEqual(build.artifact_directory(), "debug")
        self.assertEqual(build.artifact_directory("d02-signing-cas"), "debug")
        self.assertEqual(build.artifact_directory(self.profile.name), "release")

    def test_official_profile_requires_explicit_desktop_journal(self):
        for journal in ({"backend": "UBUNTU_PRIVATE_JOURNAL_V1"},
                        {"backend": "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1"},
                        {"backend": "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1",
                         "desktop": {"engineId": "f" * 64, "volumeProof": {"Name": "x"}}}):
            with self.assertRaisesRegex(ValueError, "DURABLE_DESKTOP_JOURNAL_REQUIRED"):
                launcher.require_official_journal(journal)
        launcher.require_official_journal({"backend": "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1",
            "desktop": {"engineId": "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341",
                        "volumeProof": {"Name": "marty-d02-journal-owned"}}})

    def test_compiler_mounts_only_distinct_target_and_read_only_source(self):
        run_id = "11111111-1111-4111-8111-111111111111"
        plan = {"buildProfile": self.profile.name, "uiRevision": self.profile.ui_revision,
                "coreRevision": self.freeze["coreRevision"], "roleBinaries": dict(self.profile.roles),
                "releaseQualified": False, "recordingQualified": False,
                "profileSourceSha256": build.sha(Path(profiles.__file__)),
                "runId": run_id, "containerName": self.profile.container_prefix + run_id,
                "sources": {"ui": {"directory": "C:/owned/ui"}, "core": {"directory": "C:/owned/core"}},
                "outputDirectory": "C:/owned/out", "recipe": {"path": "C:/owned/build.sh"},
                "buildTool": {"path": "C:/owned/tool.sh"},
                "builderImage": "sha256:" + "a" * 64}
        args = build.build_arguments(plan, self.profile.name)
        mounts = [args[i + 1] for i, value in enumerate(args) if value == "--mount"]
        self.assertIn("type=volume,src=" + self.profile.volumes[1] + ",dst=/target", mounts)
        self.assertNotIn("type=volume,src=d05-rust-target-20261026,dst=/target", mounts)
        self.assertTrue(all(m.endswith(",readonly") for m in mounts if "/src/ui" in m or "/build/core" in m or "/build.sh" in m or "/build/tool.sh" in m))
        for field, value in (("--memory", "2g"), ("--memory-swap", "4g"), ("--cpus", "1")):
            self.assertEqual(args[args.index(field) + 1], value)
        self.assertEqual(args[args.index("--network") + 1], "none")

    def test_export_rejects_archive_escape_and_links(self):
        for path, kind in (("../escape", b"0"), ("/absolute", b"0"),
                           ("x\\y", b"0"), ("valid", b"2")):
            with self.assertRaises(ValueError):
                prepare.safe_member(path, kind)
        self.assertEqual(prepare.safe_member("nested/source.rs", b"0"),
                         Path("nested/source.rs"))

    def test_export_preserves_exact_git_blob_bytes_under_text_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / ".gitattributes").write_bytes(b"* text eol=crlf\n")
            (repo / "source.txt").write_bytes(b"line one\nline two\n")
            (repo / "scripts").mkdir()
            operator = repo / "scripts/scoped_native_build.py"
            operator.write_bytes(b"print('source')\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
            revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            destination = Path(tmp) / "export"
            receipt = prepare.export(repo, revision, destination)
            blob = subprocess.check_output(["git", "-C", str(repo), "show", revision + ":source.txt"])
            self.assertEqual((destination / "source.txt").read_bytes(), blob)
            self.assertEqual(receipt["fileCount"], 3)
            operator.write_bytes(b"print('source')\r\n")
            staged = Path(tmp) / "staged-operator.py"
            bound = prepare.stage_operator(repo, revision, "scoped_native_build.py", staged)
            self.assertEqual(staged.read_bytes(), b"print('source')\n")
            self.assertEqual(bound["bytes"], len(staged.read_bytes()))


if __name__ == "__main__":
    unittest.main()
