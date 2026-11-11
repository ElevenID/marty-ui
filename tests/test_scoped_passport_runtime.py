"""Pure source/temporary Git controls; no Docker, SQL, KMS or beta fixture."""
import copy
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
import os

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
build = importlib.import_module("scoped_native_build")
shared = importlib.import_module("scoped_native_runtime")
overlay = importlib.import_module("scoped_beta_binary_overlay")


def selected():
    return {"uiRevision": shared.UI_REVISION, "coreRevision": shared.CORE_REVISION,
            "roleBinaries": dict(shared.ROLE_BINARIES), "releaseQualified": False, "recordingQualified": False}


def models():
    before = {"name": "elevenid-beta", "services": {}}
    binaries = {}
    for role, name in {**shared.ROLE_BINARIES, "issuance": "marty-issuance-service"}.items():
        before["services"][role] = {"image": "sha256:" + "a" * 64, "environment": {"UNCHANGED": "SOURCE_ONLY"},
            "volumes": [{"type": "bind", "source": "/old/" + name, "target": "/usr/local/bin/" + name,
                         "read_only": True, "bind": {"create_host_path": False}}]}
        if role in shared.ROLE_BINARIES:
            binaries[role] = {"path": "/owned/new/" + name, "sha256": "b" * 64}
    after = copy.deepcopy(before)
    for role, binary in binaries.items():
        after["services"][role]["volumes"][0]["source"] = binary["path"]
    return before, after, binaries


def runtime_rows():
    names = sorted(shared.MARTY_CLIENTS | {"gateway", "signing-keys", "passport-callback-signer", "canvas-sandbox", "ui-prod"})
    before = {"roles": []}
    _, _, binaries = models()
    for index, role in enumerate(names):
        name = shared.ROLE_BINARIES.get(role, "marty-source-only")
        before["roles"].append({"role": role, "binary": name, "containerId": f"{index+1:064x}", "imageId": "sha256:" + "a" * 64,
            "hostPid": index + 100, "startedAt": "2026-10-27T15:00:00Z", "health": "healthy", "effectiveUid": 1000, "configuredRuntimeUid": 1000,
            "source": "SOURCE_ONLY_OLD", "coreSource": "SOURCE_ONLY_OLD_CORE", "sha256": "a" * 64, "processExecutableSha256": "a" * 64,
            "executablePath": "/usr/local/bin/" + name, "project": "elevenid-beta", "kind": "native",
            "binaryMounts": [{"type": "bind", "source": "/old/" + name, "destination": "/usr/local/bin/" + name, "writable": False}]})
    after = copy.deepcopy(before)
    for index, row in enumerate(after["roles"]):
        if row["role"] in binaries:
            row.update(containerId=f"{index+101:064x}", source=shared.UI_REVISION, coreSource=shared.CORE_REVISION,
                       kind="SCOPED_NATIVE_FUNCTIONAL_OVERLAY", sha256="b" * 64,
                       processExecutableSha256="b" * 64, startedAt="2026-10-27T16:00:00Z", hostPid=index+500)
            row["binaryMounts"][0]["source"] = binaries[row["role"]]["path"]
    return before, after, binaries


class ScopeTests(unittest.TestCase):
    def test_exact_source_and_three_roles_never_old_core_or_promotion(self):
        shared.selected_sources(selected())
        for edit in [lambda p: p.update(coreRevision="44040270000f93b7e7499cbec31b3bb3dd7e3df1"),
                     lambda p: p["roleBinaries"].update(issuance="marty-issuance-service"),
                     lambda p: p.update(releaseQualified=True)]:
            p = selected()
            edit(p)
            with self.assertRaises(ValueError):
                shared.selected_sources(p)

    def test_build_plan_has_only_three_real_packages_and_bounded_owned_worker(self):
        p = selected()
        p.update(runId="11111111-1111-4111-8111-111111111111", containerName="marty-d12-11111111-1111-4111-8111-111111111111",
                 sources={"ui": {"directory": "C:/owned/ui"}, "core": {"directory": "D:/owned/core"}},
                 outputDirectory="C:/owned/out", recipe={"path": "C:/owned/build.sh"}, builderImage="sha256:" + "a" * 64)
        args = build.build_arguments(p)
        self.assertEqual(args[args.index("--memory")+1], "2g")
        self.assertEqual(args[args.index("--memory-swap")+1], "4g")
        self.assertEqual(args[args.index("--network")+1], "none")
        self.assertEqual(args[args.index("--cpus")+1], "1")
        self.assertEqual(args[args.index("--pull")+1], "never")
        self.assertEqual(build.CARGO_ARGV.count("--bin"), 3)
        self.assertNotIn("--features", build.CARGO_ARGV)
        self.assertNotIn("--no-default-features", build.CARGO_ARGV)
        p["containerName"] = "other-owner"
        with self.assertRaises(ValueError):
            build.build_arguments(p)

    def test_recipe_boundary_and_artifact_python_is_valid(self):
        recipe = build.render_recipe()
        for delimiter in ("BOUNDARY", "ARTIFACTS"):
            code = recipe.split("<<'" + delimiter + "'\n", 1)[1].split("\n" + delimiter, 1)[0]
            compile(code, "source-only-" + delimiter, "exec")
        self.assertIn("release: 1.95.0", recipe)
        self.assertIn("assert not features&guard.FORBIDDEN_FEATURES", recipe)

    def test_daemon_paths_are_narrow_and_never_mount_option_injection(self):
        self.assertEqual(shared.daemon_source(r"D:\owned\binary"), "/run/desktop/mnt/host/d/owned/binary")
        for path in ["C:/owned/../secret", "C:/owned,readonly", "C:/owned\nsecret", "/mnt/host/c/client", "relative/path", "E:/unknown/file"]:
            with self.assertRaises(ValueError):
                shared.daemon_source(path)

    def test_export_uses_real_git_blob_bytes_not_self_consistent_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, exported = root / "repo", root / "export"
            repo.mkdir()
            exported.mkdir()
            (repo / "file.txt").write_bytes(b"source-only\n")
            def git(args):
                return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)
            git(["init", str(repo)])
            git(["-C", str(repo), "add", "file.txt"])
            git(["-C", str(repo), "-c", "user.name=Source control", "-c", "user.email=source@example.test", "commit", "-m", "source-only"])
            revision = git(["-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
            file = exported / "file.txt"
            file.write_bytes(b"source-only\n")
            inventory = root / "inventory.json"
            def freeze():
                inventory.write_text(json.dumps([{"path": "file.txt", "bytes": file.stat().st_size, "sha256": shared.sha(file)}]))
                return shared.ref(inventory)
            build.verify_export(repo, revision, exported, freeze(), git)
            # Even an inventory updated to match drift cannot change selected Git bytes.
            for raw in [b"source-only\r\n", b"foreign-source\n"]:
                file.write_bytes(raw)
                with self.assertRaises(ValueError):
                    build.verify_export(repo, revision, exported, freeze(), git)


    def test_build_unknown_dispatch_keeps_one_shot_intent_and_does_not_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "out"
            output.mkdir()
            plan = selected()
            plan.update(privateDirectory=str(root), outputDirectory=str(output), runId="11111111-1111-4111-8111-111111111111",
                        containerName="marty-d12-11111111-1111-4111-8111-111111111111", engineId="SOURCE_ONLY_ENGINE",
                        sources={"ui": {"directory": str(root / "ui")}, "core": {"directory": str(root / "core")}},
                        recipe={"path": str(root / "recipe")}, builderImage="sha256:"+"a"*64,
                        executionOperatorSha256=shared.sha(Path(build.__file__)))
            prepared = root / "prepared.json"
            prepared.write_text(json.dumps(plan))
            bound = shared.ref(prepared)
            calls = []
            def run(*args):
                if "info" in args:
                    return SimpleNamespace(stdout="SOURCE_ONLY_ENGINE")
                if "inspect" in args:
                    return SimpleNamespace(stdout=json.dumps([{"Id": plan["builderImage"], "Os": "linux", "Architecture": "amd64"}]))
                intent = json.loads((root / "build-apply-intent.json").read_bytes())
                journal = json.loads((root / "build-state.json").read_bytes())
                self.assertEqual(intent["state"], "BUILD_CREATE_INTENT")
                self.assertTrue(journal["intentDurability"]["fileFsync"])
                self.assertIn("supported", journal["intentDurability"]["parentDirectory"])
                calls.append(args)
                raise TimeoutError("source-only dispatched outcome unknown")
            helper = SimpleNamespace(__file__="SOURCE_ONLY_VERIFIED_HELPER", VOLUMES=build.VOLUMES, run=run,
                                     resources=lambda *args: {"scope": "SOURCE_ONLY_RESOURCE_FIXTURE"})
            real_sha = build.sha
            with mock.patch.object(build, "verify", return_value=(root, output)), mock.patch.object(build, "sha", side_effect=lambda p: build.REVIEWED_BUILD_HELPER_SHA256 if str(p)==helper.__file__ else real_sha(p)), mock.patch.dict(os.environ, {"DOCKER_CONTEXT": "desktop-linux"}), mock.patch.object(shared, "sync_parent", return_value={"supported": True, "synced": True}):
                with self.assertRaises(TimeoutError):
                    build.start(bound, helper, lambda args: b"")
                self.assertEqual(len(calls), 1)
                journal = json.loads((root / "build-state.json").read_bytes())
                self.assertEqual(journal["state"], "BUILD_DISPATCH_UNKNOWN_RECONCILE_EXACT_LABELS")
                self.assertTrue((root / "build-apply-intent.json").is_file())
                with self.assertRaises(FileExistsError):
                    build.start(bound, helper, lambda args: b"")
                self.assertEqual(len(calls), 1)
            # A distinct SOURCE_ONLY intent with unsupported parent sync cannot dispatch.
            for file in (root / "build-apply-intent.json", root / "build-state.json"):
                file.unlink()
            calls.clear()
            with mock.patch.object(build, "verify", return_value=(root, output)), mock.patch.object(build, "sha", side_effect=lambda p: build.REVIEWED_BUILD_HELPER_SHA256 if str(p)==helper.__file__ else real_sha(p)), mock.patch.dict(os.environ, {"DOCKER_CONTEXT": "desktop-linux"}), mock.patch.object(shared, "sync_parent", return_value={"supported": False, "reason": "SOURCE_ONLY_UNSUPPORTED"}):
                with self.assertRaisesRegex(ValueError, "DURABLE_INTENT_AND_JOURNAL_REQUIRED"):
                    build.start(bound, helper, lambda args: b"")
                self.assertEqual(calls, [])
                self.assertEqual(json.loads((root / "build-state.json").read_bytes())["state"], "BUILD_DURABILITY_BLOCKED_NO_DOCKER_DISPATCH")

    def test_changed_prepared_build_bytes_refuse_before_any_helper_call(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "prepared.json"
            file.write_text(json.dumps(selected()))
            bound = shared.ref(file)
            file.write_text(json.dumps({**selected(), "injected": True}))
            with self.assertRaisesRegex(ValueError, "BOUND_FILE_CHANGED"):
                build.start(bound, None, None)


class OverlayTests(unittest.TestCase):
    def test_only_three_existing_readonly_executable_sources_change(self):
        before, after, binaries = models()
        original = copy.deepcopy(before)
        overlay.validate_delta(before, after, binaries)
        self.assertEqual(before, original)
        edits = [lambda a: a["services"]["issuance"]["volumes"][0].update(source="/foreign"),
                 lambda a: a["services"]["gateway"]["environment"].update(EXPANDED="no"),
                 lambda a: a["services"]["flow"]["volumes"][0].update(read_only=False),
                 lambda a: a["services"]["issuance-native"]["volumes"][0].update(target="/other"),
                 lambda a: a.update(name="foreign-project")]
        for edit in edits:
            invalid = copy.deepcopy(after)
            edit(invalid)
            with self.assertRaises(ValueError):
                overlay.validate_delta(before, invalid, binaries)

    def test_maintenance_requires_all_shared_role_clients_and_exact_reviewed_sql(self):
        with tempfile.TemporaryDirectory() as temp:
            plan = selected()
            sql = {}
            for name in overlay.SQL_FILES:
                # Temporary source-only fixture materializes reviewed LF Git bytes.
                raw = (SCRIPTS / "sql" / name).read_bytes().replace(b"\r\n", b"\n")
                file = Path(temp) / name
                file.write_bytes(raw)
                sql[name] = shared.ref(file)
            plan.update(databaseClientRoles=list(shared.MARTY_CLIENTS), requiresSeparateMaintenanceReview=True,
                        migrationNames=list(shared.MIGRATIONS), issuance0009LedgerCheckRequired=True,
                        sqlFiles=sql, noHistoricalJobMutation=True, noAutomaticRollback=True)
            overlay.maintenance_contract(plan)
            for edit in [lambda p: p.update(databaseClientRoles=list(shared.ROLE_BINARIES)),
                         lambda p: p.update(requiresSeparateMaintenanceReview=False),
                         lambda p: p.update(noHistoricalJobMutation=False),
                         lambda p: p.update(issuance0009LedgerCheckRequired=False),
                         lambda p: p["sqlFiles"][overlay.SQL_FILES[0]].update(sha256="c"*64)]:
                invalid = copy.deepcopy(plan)
                edit(invalid)
                with self.assertRaises(ValueError):
                    overlay.maintenance_contract(invalid)

    def test_fenced_acl_never_allows_live_clients_or_immutable_field_updates(self):
        expected = {"databaseIdentity": {"system": "123", "oid": "456"}, "fenceEpoch": 7}
        proof = {**expected, "phase": "fully_fenced", "martyCanLogin": False, "migratorCanLogin": False,
                 "activeMartyConnections": 0, "activeMigratorConnections": 0,
                 "flowIntentUpdateColumns": list(overlay.FLOW_MUTABLE_COLUMNS),
                 "appSchemaCreateDenied": True, "cancellationHistoryMutationsDenied": True}
        overlay.validate_fenced_observation(proof, expected)
        for edit in [lambda p: p.update(activeMartyConnections=1), lambda p: p.update(activeMartyConnections=False),
                     lambda p: p.update(martyCanLogin=True), lambda p: p["flowIntentUpdateColumns"].append("definition_snapshot"),
                     lambda p: p.update(cancellationHistoryMutationsDenied=False), lambda p: p.update(fenceEpoch=8)]:
            invalid = copy.deepcopy(proof)
            edit(invalid)
            with self.assertRaises(ValueError):
                overlay.validate_fenced_observation(invalid, expected)

    def test_unselected_roles_are_exact_and_restart_generations_are_explicit(self):
        before, after, binaries = runtime_rows()
        result = overlay.validate_runtime_after(before, after, binaries, [])
        self.assertFalse(result["acceptedByExistingFunctionalRuntimeV2"])
        self.assertFalse(result["releaseQualified"])
        changed = copy.deepcopy(after)
        row = next(r for r in changed["roles"] if r["role"] == "auth")
        row.update(hostPid=9999, startedAt="2026-10-27T16:01:00Z")
        with self.assertRaises(ValueError):
            overlay.validate_runtime_after(before, changed, binaries, [])
        result = overlay.validate_runtime_after(before, changed, binaries, ["auth"])
        self.assertEqual(result["maintenanceRestartRoles"], ["auth"])
        row["sha256"] = "c" * 64
        with self.assertRaises(ValueError):
            overlay.validate_runtime_after(before, changed, binaries, ["auth"])

    def test_omitting_selected_or_baseline_role_from_both_snapshots_never_qualifies(self):
        for omitted in ["flow", "gateway", "issuance-native", "ui-prod", "auth"]:
            before, after, binaries = runtime_rows()
            for snapshot in (before, after):
                row = next(r for r in snapshot["roles"] if r["role"] == omitted)
                row["role"] = "foreign-replacement"
            with self.assertRaisesRegex(ValueError, "EXACT_22_ROLE_SET_REQUIRED"):
                overlay.validate_runtime_after(before, after, binaries, [])

    def test_foreign_selected_image_uid_lineage_or_inode_never_becomes_overlay(self):
        before, after, binaries = runtime_rows()
        for field, value in [("imageId", "sha256:"+"c"*64), ("effectiveUid", 0), ("source", "wrong"),
                             ("coreSource", "44040270000f93b7e7499cbec31b3bb3dd7e3df1"), ("kind", "native"),
                             ("processExecutableSha256", "c"*64), ("startedAt", "not-a-time"), ("project", "foreign"),
                             ("requiredObservation", {"legacy": True})]:
            changed = copy.deepcopy(after)
            row = next(r for r in changed["roles"] if r["role"] == "flow")
            row[field] = value
            with self.assertRaises(ValueError):
                overlay.validate_runtime_after(before, changed, binaries, [])

    def test_compose_arguments_do_not_build_pull_or_recreate_primary_issuance(self):
        args = overlay.compose_recreate_arguments(["docker", "compose", "-p", "elevenid-beta", "--project-directory", "/owned/project", "-f", "/owned/frozen.json"], "/owned/overlay.json")
        self.assertEqual(args[-3:], ["flow", "issuance-native", "gateway"])
        self.assertIn("--no-build", args)
        self.assertEqual(args[args.index("--pull")+1], "never")


    def test_compose_base_rejects_subcommands_options_foreign_project_and_bad_paths(self):
        base = ["docker", "compose", "-p", "elevenid-beta", "--project-directory", "/owned/project", "-f", "/owned/frozen.json"]
        invalid = [base + ["ps"], base + ["--profile", "foreign"], base + ["up", "/foreign"],
                   [*base[:3], "production", *base[4:]], base + ["--project-directory", "/other"],
                   [*base[:-1], "--help"], [*base[:-1], "/owned/../foreign"]]
        for args in invalid:
            with self.assertRaises(ValueError):
                overlay.compose_recreate_arguments(args, "/owned/overlay.json")

    def test_private_writer_flushes_parent_after_create_and_replace(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "journal.json"
            events = []
            real_replace = shared.os.replace
            def sync(path):
                self.assertTrue(Path(path).exists())
                events.append("parent-sync")
                return {"supported": True, "synced": True}
            def replace(source, target):
                events.append("replace")
                return real_replace(source, target)
            with mock.patch.object(shared, "sync_parent", side_effect=sync), mock.patch.object(shared.os, "replace", side_effect=replace):
                proof = shared.save_exclusive(file, {"state": "INTENT"})
                self.assertTrue(proof["fileFsync"])
                shared.save_state(file, {"state": "ACK"})
            self.assertEqual(events, ["parent-sync", "parent-sync", "replace", "parent-sync"])
            self.assertEqual(json.loads(file.read_bytes())["state"], "ACK")


if __name__ == "__main__":
    unittest.main()
