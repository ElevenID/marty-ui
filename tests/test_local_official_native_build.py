"""Historical receipt audits, build retirement and current compiler controls."""
import importlib
import json
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "ci"))
build = importlib.import_module("scoped_native_build")
profiles = importlib.import_module("scoped_native_profiles")
prepare = importlib.import_module("prepare_local_official_native_build")
launcher = importlib.import_module("run_local_official_native_build")
lock_guard = importlib.import_module("check_core_localized_lock")


REFERENCE_PATH = Path(__file__).resolve().parents[1] / "contracts/scoped-full-build-legacy-reference.json"
REFERENCE_BYTES = REFERENCE_PATH.read_bytes().replace(b"\r\n", b"\n")
assert hashlib.sha256(REFERENCE_BYTES).hexdigest() == "c181b530debdf5714c3bf909f6f2227cf1d85bf68235412886d70cb8433d5063"
LEGACY_REFERENCE = json.loads(REFERENCE_BYTES)


def legacy_reference(name):
    data = dict(LEGACY_REFERENCE["profiles"][name])
    data["roles"] = tuple(tuple(row) for row in data["roles"])
    data["packages"] = tuple(data["packages"])
    data["volumes"] = tuple(data["volumes"])
    return SimpleNamespace(**data)


def legacy_scope(profile):
    return {"uiRevision": profile.ui_revision, "coreRevision": profile.core_revision,
            "roles": dict(profile.roles), "packages": profile.packages,
            "prefix": profile.container_prefix, "owner": profile.owner,
            "volumes": profile.volumes, "cargoProfile": profile.cargo_profile}


class OfficialNativeBuildTests(unittest.TestCase):
    def setUp(self):
        self.profile = legacy_reference(build.OFFICIAL_PROFILE)
        self.scope = legacy_scope(self.profile)
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
        # Modeled parser input for the closed profile, not a historical script.
        self.script = "cargo build " + " ".join(
            f"--bin {binary}" for _, binary in self.profile.roles
        )

    def test_closed_profile_union_preserves_core_target_and_journal_dispatch(self):
        expected = (
            ("d02-signing-cas", "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac", "dev", "d05-rust-target-20261026"),
            ("d02-signing-cas-no-transform", "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac", "dev", "d05-rust-target-20261026"),
        )
        plan = {"runId": "SOURCE_ONLY", "journalBackend": {"backend": "SOURCE_ONLY"}}
        private = Path("SOURCE_ONLY")
        with mock.patch("scoped_linux_journal.LinuxBuildJournal") as factory:
            for name, core, cargo, target in expected:
                scope = build.build_scope(name)
                self.assertEqual(scope["coreRevision"], core)
                self.assertEqual(scope["cargoProfile"], cargo)
                self.assertEqual(scope["volumes"], ("ui-canvas-cargo", target))
                self.assertIs(build.build_journal(plan, private, name), factory.return_value)
            self.assertEqual(factory.call_count, 2)
            factory.reset_mock()
            for unsupported in (None, "unreviewed-profile", "canvas-issuer-scoped-jobs", *build.OFFICIAL_PROFILES):
                with self.assertRaisesRegex(ValueError, "LINUX_JOURNAL_REVIEWED_PROFILE_REQUIRED"):
                    build.build_journal(plan, private, unsupported)
            factory.assert_not_called()
        for selection in (profiles.reviewed_profile, build.build_scope, build.cargo_arguments):
            with self.assertRaisesRegex(ValueError, "UNKNOWN_REVIEWED_BUILD_PROFILE"):
                selection("canvas-issuer-scoped-jobs")
        with self.assertRaisesRegex(ValueError, "UNKNOWN_REVIEWED_BUILD_PROFILE"):
            build.build_journal({}, private, "canvas-issuer-scoped-jobs")

    def test_legacy_manifest_is_auditable_but_cannot_emit_a_build_recipe(self):
        build.verify_official_inputs(self.freeze, self.seed, self.script, self.scope)
        self.assertEqual(len(self.scope["roles"]), 29)
        for profile in build.OFFICIAL_PROFILES:
            for action in (profiles.reviewed_profile, build.build_scope, build.cargo_arguments,
                           build.render_recipe, prepare.selected_sources):
                with self.assertRaisesRegex(ValueError, "RETIRED_BUILD_PROFILE"):
                    action(profile)
            with self.assertRaisesRegex(ValueError, "RETIRED_BUILD_PROFILE"):
                build.build_journal({}, Path("unused"), profile)

    def test_current_build_outputs_cannot_enter_the_frozen_profile(self):
        current = (Path(__file__).resolve().parents[1] / "scripts/build-rust-service-binaries.sh").read_text()
        self.assertIn("--bin marty-installer-organization-api-key", current)
        with self.assertRaisesRegex(ValueError, "CANONICAL_ALL_SERVICES_SET_CHANGED"):
            build.verify_official_inputs(self.freeze, self.seed, current, self.scope)
        with self.assertRaisesRegex(ValueError, "BUILD_TOOL_BINARY_SET_CHANGED"):
            build.verify_official_inputs(self.freeze, self.seed, self.script,
                                         self.scope, current)

    def test_localized_lock_allows_only_two_exact_unused_core_patch_source_removals(self):
        core_source = "git+https://github.com/ElevenID/marty-core?rev=4320b5fa1c6f41231ee0aa2bc57d8008549f67ac#4320b5fa1c6f41231ee0aa2bc57d8008549f67ac"
        ssi_source = "git+https://github.com/ElevenID/ssi-elevenid?rev=234723638447c30f90cf499bce1d6b092f865e9d#234723638447c30f90cf499bce1d6b092f865e9d"

        def lock(localized=False, ssi_version="0.16.0"):
            rows = ["version = 4\n"]
            for number in range(9):
                rows.append(f'[[package]]\nname = "marty-core-{number}"\nversion = "1.0.0"\n')
                if not localized:
                    rows.append(f'source = "{core_source}"\n')
            rows.append('[[package]]\nname = "other"\nversion = "2.0.0"\n')
            for name, version, source in (("bls12_381_plus", "0.8.18", core_source),
                                          ("elliptic-curve", "0.13.8", core_source),
                                          ("ssi", ssi_version, ssi_source)):
                rows.append(f'[[patch.unused]]\nname = "{name}"\nversion = "{version}"\n')
                if not localized or source != core_source:
                    rows.append(f'source = "{source}"\n')
            return "\n".join(rows)

        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original.toml"
            localized = Path(tmp) / "localized.toml"
            original.write_text(lock(), encoding="utf-8")
            localized.write_text(lock(localized=True), encoding="utf-8")
            proof = lock_guard.verify_files(original, localized)
            self.assertEqual(proof["corePackagesLocalized"], 9)
            self.assertEqual(proof["unusedCorePatchesLocalized"], 2)
            localized.write_text(lock(localized=True, ssi_version="0.16.1"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "LOCK_PATCH_DELTA_CHANGED"):
                lock_guard.verify_files(original, localized)
            localized.write_text(lock(localized=True).replace('version = "0.8.18"',
                                                               'version = "0.8.19"'), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "LOCK_PATCH_DELTA_CHANGED"):
                lock_guard.verify_files(original, localized)
            localized.write_text(lock(localized=True).replace('version = "2.0.0"',
                                                               'version = "2.0.1"'), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "LOCK_PACKAGE_DELTA_CHANGED"):
                lock_guard.verify_files(original, localized)
            original.write_text(lock().replace(core_source, core_source.replace("4320b5fa", "ffffffff")),
                                encoding="utf-8")
            localized.write_text(lock(localized=True), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "LOCK_CORE_SOURCE_CHANGED"):
                lock_guard.verify_files(original, localized)
            original.write_text(lock().replace('name = "other"\nversion = "2.0.0"',
                                               'name = "other"\nversion = "2.0.0"\nchecksum = "' + "a" * 64 + '"'),
                                encoding="utf-8")
            localized.write_text(lock(localized=True).replace('name = "other"\nversion = "2.0.0"',
                                                                'name = "other"\nversion = "2.0.0"\nchecksum = "' + "b" * 64 + '"'),
                                 encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "LOCK_PACKAGE_DELTA_CHANGED"):
                lock_guard.verify_files(original, localized)
            original.write_text(lock(), encoding="utf-8")
            localized.write_text(lock(localized=True) + '\n[[patch.unused]]\nname = "extra"\nversion = "1.0.0"\n',
                                 encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "LOCK_PATCH_SET_CHANGED"):
                lock_guard.verify_files(original, localized)

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

    def test_retired_profiles_cannot_start_or_finish_through_current_builder(self):
        helper = mock.Mock()
        for profile in build.OFFICIAL_PROFILES:
            for action in (build.start, build.finish):
                with self.assertRaisesRegex(ValueError, "RETIRED_BUILD_PROFILE"):
                    action({}, helper, mock.Mock(), profile)
        helper.assert_not_called()
        self.assertEqual(helper.mock_calls, [])

    def test_retired_source_preparation_stops_before_any_git_or_export(self):
        with mock.patch.object(prepare, "git") as reader:
            for profile in build.OFFICIAL_PROFILES:
                with self.assertRaisesRegex(ValueError, "RETIRED_BUILD_PROFILE"):
                    prepare.selected_sources(profile)
        reader.assert_not_called()

    def test_retired_launcher_stops_before_seed_plan_or_resource_reads(self):
        for profile in build.OFFICIAL_PROFILES:
            with mock.patch.object(launcher, "source_export", return_value={"buildProfile": profile}), \
                    mock.patch.object(launcher, "read_exact") as reader, \
                    mock.patch.object(launcher, "helper_module") as helper:
                with self.assertRaisesRegex(ValueError, "RETIRED_BUILD_PROFILE"):
                    launcher.prepare(Path("unused"), "unused", Path("unused"), "unused", Path("unused"), "unused", "unused")
                with self.assertRaisesRegex(ValueError, "RETIRED_BUILD_PROFILE"):
                    launcher.execute("start", Path("unused"), "unused", "unused")
                reader.assert_not_called()
                helper.assert_not_called()

    def test_legacy_reference_is_hash_bound_and_cannot_register_a_build_profile(self):
        with self.assertRaisesRegex(ValueError, "UNKNOWN_LEGACY_BUILD_REFERENCE"):
            profiles.legacy_profile_reference("caller-supplied-profile")
        with tempfile.TemporaryDirectory(prefix="legacy-build-reference-test-") as tmp:
            root = Path(tmp).resolve()
            self.assertTrue(root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
            contract = root / "contracts/scoped-full-build-legacy-reference.json"
            contract.parent.mkdir()
            contract.write_bytes(REFERENCE_BYTES)
            with mock.patch.object(profiles, "__file__", str(root / "operator/scoped_native_profiles.py")):
                old = profiles.legacy_profile_reference(build.OFFICIAL_PROFILE)
                self.assertEqual(old.roles, self.profile.roles)
                with self.assertRaisesRegex(ValueError, "RETIRED_BUILD_PROFILE"):
                    profiles.reviewed_profile(old.name)
                contract.write_bytes(b'{"profiles":{}}')
                with self.assertRaisesRegex(ValueError, "LEGACY_BUILD_REFERENCE_CHANGED"):
                    profiles.legacy_profile_reference(build.OFFICIAL_PROFILE)

    def test_pinned_engine_uuid_and_debug_artifact_directory(self):
        launcher.require_build_identifiers("11111111-1111-4111-8111-111111111111",
                                           "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341")
        with self.assertRaisesRegex(ValueError, "OWNED_BUILD_IDENTIFIERS_REQUIRED"):
            launcher.require_build_identifiers("11111111-1111-4111-8111-111111111111", "f" * 64)
        self.assertEqual(build.artifact_directory(), "debug")
        self.assertEqual(build.artifact_directory("d02-signing-cas"), "debug")
        with self.assertRaisesRegex(ValueError, "RETIRED_BUILD_PROFILE"):
            build.artifact_directory(self.profile.name)

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
        profile = profiles.D12_PASSPORT_CURRENT
        run_id = "11111111-1111-4111-8111-111111111111"
        plan = {"buildProfile": profile.name, "uiRevision": profile.ui_revision,
                "coreRevision": profile.core_revision, "roleBinaries": dict(profile.roles),
                "releaseQualified": False, "recordingQualified": False,
                "profileSourceSha256": build.sha(Path(profiles.__file__)),
                "runId": run_id, "containerName": profile.container_prefix + run_id,
                "sources": {"ui": {"directory": "C:/owned/ui"}, "core": {"directory": "C:/owned/core"}},
                "outputDirectory": "C:/owned/out", "recipe": {"path": "C:/owned/build.sh"},
                "buildTool": {"path": "C:/owned/tool.sh"},
                "lockGuard": {"path": "C:/owned/lock_guard.py"},
                "builderImage": "sha256:" + "a" * 64}
        args = build.build_arguments(plan, profile.name)
        mounts = [args[i + 1] for i, value in enumerate(args) if value == "--mount"]
        self.assertIn("type=volume,src=" + profile.volumes[1] + ",dst=/target", mounts)
        self.assertNotIn("type=volume,src=d05-rust-target-20261026,dst=/target", mounts)
        self.assertTrue(all(m.endswith(",readonly") for m in mounts if "/src/ui" in m or "/build/core" in m or "/build.sh" in m or "/build/tool.sh" in m or "/build/lock_guard.py" in m))
        for field, value in (("--memory", "1g"), ("--memory-swap", "4g"), ("--cpus", "1")):
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
            (repo / "scripts/ci").mkdir()
            operator = repo / "scripts/scoped_native_build.py"
            operator.write_bytes(b"print('source')\n")
            (repo / "scripts/ci/check_core_localized_lock.py").write_bytes(b"print('guard')\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
            revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            destination = Path(tmp) / "export"
            receipt = prepare.export(repo, revision, destination)
            blob = subprocess.check_output(["git", "-C", str(repo), "show", revision + ":source.txt"])
            self.assertEqual((destination / "source.txt").read_bytes(), blob)
            self.assertEqual(receipt["fileCount"], 4)
            operator.write_bytes(b"print('source')\r\n")
            staged = Path(tmp) / "staged-operator.py"
            bound = prepare.stage_operator(repo, revision, "scoped_native_build.py", staged)
            self.assertEqual(staged.read_bytes(), b"print('source')\n")
            self.assertEqual(bound["bytes"], len(staged.read_bytes()))
            nested = Path(tmp) / "staged-lock-guard.py"
            bound_guard = prepare.stage_operator(repo, revision,
                                                  "ci/check_core_localized_lock.py", nested)
            self.assertEqual(nested.read_bytes(), b"print('guard')\n")
            self.assertEqual(bound_guard["bytes"], len(nested.read_bytes()))


if __name__ == "__main__":
    unittest.main()
