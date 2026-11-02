"""Source-only controls for the frozen all-service KMS build profile."""
import importlib
import json
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
        # Modeled parser input for the closed profile, not a historical script.
        self.script = "cargo build " + " ".join(
            f"--bin {binary}" for _, binary in self.profile.roles
        )

    def test_closed_profile_union_preserves_core_target_and_journal_dispatch(self):
        expected = (
            ("d02-signing-cas", "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac", "dev", "d05-rust-target-20261026"),
            ("d02-signing-cas-no-transform", "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac", "dev", "d05-rust-target-20261026"),
            ("canvas-issuer-scoped-jobs", "44040270000f93b7e7499cbec31b3bb3dd7e3df1", "dev", "d05-rust-target-20261026"),
            (self.profile.name, "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac", "release", "marty-oid4vc-native-d2de-target-20261028"),
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
            self.assertEqual(factory.call_count, 4)
            factory.reset_mock()
            for unsupported in (None, "unreviewed-profile"):
                with self.assertRaisesRegex(ValueError, "LINUX_JOURNAL_REVIEWED_PROFILE_REQUIRED"):
                    build.build_journal(plan, private, unsupported)
            factory.assert_not_called()

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
        self.assertIn("python3 /build/lock_guard.py /out/original-cargo-lock.toml /out/localized-cargo-lock.toml", recipe)
        for delimiter in ("BOUNDARY", "ARTIFACTS"):
            code = recipe.split("<<'" + delimiter + "'\n", 1)[1].split("\n" + delimiter, 1)[0]
            compile(code, delimiter, "exec")

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

    def test_verified_target_seed_survives_start_and_terminal_receipt(self):
        cache_prefix = "targetReuse" if self.profile.name == build.LATEST_OFFICIAL_PROFILE else "targetSeed"
        # SOURCE-ONLY: typed transport/journal mocks never dispatch Docker.
        seed_module = importlib.import_module("seed_local_official_native_target")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output"
            output.mkdir()
            cid = "b" * 64
            image = "sha256:" + "a" * 64
            run_id = "11111111-1111-4111-8111-111111111111"
            verified = {"sourceOnly": True, "manifestSha256": "c" * 64,
                        "entries": 17, "targetVolume": self.profile.volumes[1]}
            proof = {"fileFsync": True, "parentDirectory": {"supported": True, "synced": True}}

            class Journal:
                def exclusive(self, name, value):
                    with (root / name).open("x", encoding="utf-8") as stream:
                        json.dump(value, stream)
                    return proof

                def state(self, value):
                    (root / "build-state.json").write_text(json.dumps(value), encoding="utf-8")
                    return proof

                def read(self, name):
                    return json.loads((root / name).read_bytes())

            plan = {"buildProfile": self.profile.name, "uiRevision": self.profile.ui_revision,
                    "coreRevision": self.freeze["coreRevision"], "roleBinaries": dict(self.profile.roles),
                    "releaseQualified": False, "recordingQualified": False,
                    "profileSourceSha256": build.sha(Path(profiles.__file__)),
                    "executionOperatorSha256": build.sha(Path(build.__file__)),
                    "runId": run_id, "engineId": "SOURCE_ONLY", "builderImage": image,
                    "containerName": self.profile.container_prefix + run_id,
                    "sources": {"ui": {"directory": "/owned/ui"}, "core": {"directory": "/owned/core"}},
                    "outputDirectory": str(output), "recipe": {"path": "/owned/build.sh"},
                    "buildTool": {"path": "/owned/tool.sh"}, "lockGuard": {"path": "/owned/lock_guard.py"},
                    cache_prefix + "Receipt": {"path": str(root / "seed.json")}}
            prepared = root / "prepared.json"
            prepared.write_text(json.dumps(plan), encoding="utf-8")
            dispatches = []

            def run(*args):
                if "info" in args:
                    return SimpleNamespace(stdout="SOURCE_ONLY")
                if args[1:3] == ("volume", "inspect"):
                    return SimpleNamespace(stdout=json.dumps([{"Name": self.profile.volumes[1],
                        "Labels": {"io.elevenid.demo-audit.owner": "root-local-oid4vc-current-source-20261028"}}]))
                if args[1:3] == ("image", "inspect"):
                    return SimpleNamespace(stdout=json.dumps([{"Id": image, "Os": "linux", "Architecture": "amd64"}]))
                if "run" in args:
                    before = Journal().read("build-state.json")
                    self.assertEqual(before["state"], "BUILD_CREATE_INTENT")
                    self.assertEqual(before[cache_prefix + "Probe"]["outcome"], "READBACK_MATCHED")
                    self.assertEqual(before[cache_prefix + "Readback"], verified)
                    dispatches.append(args)
                    return SimpleNamespace(stdout=cid)
                if args[1] == "inspect":
                    mounts = [{"Destination": destination, "Type": "volume", "Name": volume}
                              for destination, volume in zip(("/cargo", "/target"), self.profile.volumes)]
                    mounts += [{"Destination": destination, "RW": False} for destination in
                               ("/src/ui", "/build/core", "/build.sh", "/build/tool.sh", "/build/lock_guard.py")]
                    return SimpleNamespace(stdout=json.dumps([{"Id": cid, "Image": image,
                        "Config": {"Labels": {"elevenid.run": run_id, "elevenid.owner": self.scope["owner"]}},
                        "State": {"Status": "exited", "ExitCode": 101, "OOMKilled": False}, "Mounts": mounts}]))
                self.fail("Unexpected source-test transport operation")

            helper = SimpleNamespace(__file__="SOURCE_ONLY_HELPER", VOLUMES=build.VOLUMES,
                                     run=run, resources=lambda *args: {"sourceOnly": True})
            original_sha = build.sha
            with mock.patch.object(build, "verify", return_value=(root, output)), \
                    mock.patch.object(build, "build_journal", return_value=Journal()), \
                    mock.patch.object(build, "sha", side_effect=lambda path:
                        build.REVIEWED_BUILD_HELPER_SHA256 if str(path) == helper.__file__ else original_sha(path)), \
                    mock.patch.object(seed_module, "inspect_reuse_target" if cache_prefix == "targetReuse" else "inspect_target", return_value=verified) as readback, \
                    mock.patch.dict(os.environ, {"DOCKER_CONTEXT": "desktop-linux"}):
                running = build.start(build.ref(prepared), helper, lambda args: b"", self.profile.name)
                self.assertEqual(running["state"], "BUILD_RUNNING")
                self.assertEqual(running[cache_prefix + "Readback"], verified)
                self.assertEqual(running[cache_prefix + "Probe"]["outcome"], "READBACK_MATCHED")
                result = build.finish(build.ref(prepared), helper, lambda args: b"", self.profile.name)
            self.assertEqual(len(dispatches), 1)
            readback.assert_called_once_with(Path(plan[cache_prefix + "Receipt"]["path"]))
            self.assertEqual(result["state"], "BUILD_FAILED_RETAINED")
            receipt = Journal().read("build-receipt.json")
            self.assertEqual(receipt[cache_prefix + "Readback"], verified)
            self.assertEqual(receipt[cache_prefix + "Probe"], running[cache_prefix + "Probe"])

    def test_verified_latest_cache_reuse_survives_start_and_terminal_receipt(self):
        self.profile = profiles.LATEST_ALL_SERVICES
        self.scope = build.build_scope(self.profile.name)
        self.test_verified_target_seed_survives_start_and_terminal_receipt()

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
                "lockGuard": {"path": "C:/owned/lock_guard.py"},
                "builderImage": "sha256:" + "a" * 64}
        args = build.build_arguments(plan, self.profile.name)
        mounts = [args[i + 1] for i, value in enumerate(args) if value == "--mount"]
        self.assertIn("type=volume,src=" + self.profile.volumes[1] + ",dst=/target", mounts)
        self.assertNotIn("type=volume,src=d05-rust-target-20261026,dst=/target", mounts)
        self.assertTrue(all(m.endswith(",readonly") for m in mounts if "/src/ui" in m or "/build/core" in m or "/build.sh" in m or "/build/tool.sh" in m or "/build/lock_guard.py" in m))
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
