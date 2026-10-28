"""All22-role source-only controls; no Docker process, SQL, job or secret."""
import copy
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
maintenance = importlib.import_module("scoped_passport_maintenance")
shared = importlib.import_module("scoped_native_runtime")
overlay = importlib.import_module("scoped_beta_binary_overlay")


def fixture(directory):
    before = {"roles": []}
    contracts = {}
    compose = {project: {"name": project, "services": {}} for project in maintenance.PROJECTS}
    for index, role in enumerate(sorted(shared.RUNTIME_ROLES)):
        row = {"role": role, "project": maintenance.ROLE_PROJECTS[role], "containerId": f"{index+1:064x}", "imageId": "sha256:"+"a"*64, "source": "1"*40,
               "sha256": "b"*64, "binaryMounts": [], "hostPid": index+100, "startedAt": "2026-10-27T15:00:00Z",
               "running": True, "paused": False, "state": "running", "containerExitCode": 0, "oomKilled": False}
        before["roles"].append(row)
        proof = directory / (role+"-source.json")
        proof.write_text(json.dumps({"schema": "marty.graceful-shutdown-source-proof/v1", "role": role,
            "sourceRevision": row["source"], "elfSha256": row["sha256"], "supportedSignals": ["SIGINT"]}))
        policy = directory / (role+"-stop.json")
        policy.write_text(json.dumps({"schema": "marty.reviewed-graceful-stop/v1", "role": role,
            "containerId": row["containerId"], "sourceRevision": row["source"], "elfSha256": row["sha256"],
            "signal": "SIGINT", "allowedExitCodes": [0], "noAutomaticSigkill": True, "sourceProof": shared.ref(proof)}))
        contracts[role] = shared.ref(policy)
        compose[maintenance.ROLE_PROJECTS[role]]["services"][role] = {"depends_on": {}}
    compose["elevenid-beta"]["services"]["gateway"]["depends_on"] = {"flow": {}, "issuance-native": {}}
    plan = {"uiRevision": shared.UI_REVISION, "coreRevision": shared.CORE_REVISION,
            "roleBinaries": dict(shared.ROLE_BINARIES), "releaseQualified": False, "recordingQualified": False,
            "stopContracts": contracts, "composeModels": {}}
    freeze_models(plan, compose, directory)
    stopped = copy.deepcopy(before)
    for row in stopped["roles"]:
        row.update(running=False, hostPid=0, state="exited")
    outcomes = {role: {"terminal": True, "exitCode": 0, "stopAcknowledged": True} for role in shared.RUNTIME_ROLES}
    return plan, before, stopped, outcomes, compose


def freeze_models(plan, models, directory):
    for project, model in models.items():
        file = directory / (project + "-model.json")
        file.write_text(json.dumps(model))
        plan["composeModels"][project] = shared.ref(file)


class MaintenanceControls(unittest.TestCase):
    def test_preview_requires_all22_and_gateway_first_without_automatic_kill(self):
        with tempfile.TemporaryDirectory() as temp:
            plan, before, _, _, compose = fixture(Path(temp))
            value = maintenance.preview(plan, before, compose)
            self.assertEqual(set(value["allStopRoles"]), shared.RUNTIME_ROLES)
            self.assertEqual(value["allStopRoles"][0], "gateway")
            self.assertEqual(len(value["additionalUnselectedRestartRoles"]), 19)
            self.assertTrue(value["noApplyAuthority"])
            self.assertTrue(value["durableOneShotIntentRequiredBeforeFirstStop"])
            for step in value["stopSteps"]:
                self.assertEqual(step["argv"][step["argv"].index("--timeout")+1], "-1")
                self.assertEqual(step["requireExitCode"], 0)
            # A missing or crash-stop-only handler cannot silently get permission.
            del plan["stopContracts"]["passport-beta-bureau"]
            with self.assertRaisesRegex(ValueError, "ALL_22_STOP_CONTRACTS"):
                maintenance.preview(plan, before, compose)

    def test_foreign_source_or_signal_contract_refuses_before_rendering_stops(self):
        with tempfile.TemporaryDirectory() as temp:
            plan, before, _, _, compose = fixture(Path(temp))
            file = Path(plan["stopContracts"]["flow"]["path"])
            policy = json.loads(file.read_bytes())
            policy["signal"] = "SIGKILL"
            file.write_text(json.dumps(policy))
            plan["stopContracts"]["flow"] = shared.ref(file)
            with self.assertRaisesRegex(ValueError, "SOURCE_BACKED_GRACEFUL"):
                maintenance.preview(plan, before, compose)
            policy["signal"] = "SIGTERM"
            file.write_text(json.dumps(policy))
            plan["stopContracts"]["flow"] = shared.ref(file)
            with self.assertRaisesRegex(ValueError, "SOURCE_PROOF_MISMATCH"):
                maintenance.preview(plan, before, compose)

    def test_three_stopped_roles_never_satisfy_database_quiescence(self):
        with tempfile.TemporaryDirectory() as temp:
            _, before, stopped, outcomes, _ = fixture(Path(temp))
            self.assertTrue(maintenance.validate_quiescent(before, stopped, outcomes)["all22Quiescent"])
            for role in ("auth", "ui-prod", "canvas-sync-worker"):
                changed = copy.deepcopy(stopped)
                row = next(row for row in changed["roles"] if row["role"] == role)
                row.update(running=True, hostPid=500, state="running")
                with self.assertRaisesRegex(ValueError, "NOT_CLEANLY_QUIESCENT"):
                    maintenance.validate_quiescent(before, changed, outcomes)

    def test_timeout_failed_exit_pause_or_generation_drift_blocks_sql_and_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            _, before, stopped, outcomes, _ = fixture(Path(temp))
            unknown = copy.deepcopy(outcomes)
            unknown["flow"]["terminal"] = False
            with self.assertRaisesRegex(ValueError, "UNKNOWN_STOP_OUTCOME"):
                maintenance.validate_quiescent(before, stopped, unknown)
            with self.assertRaisesRegex(ValueError, "UNRESOLVED_STOP"):
                maintenance.restore_commands(before, stopped, unknown, sorted(shared.RUNTIME_ROLES))
            for edit in [lambda r: r.update(paused=True), lambda r: r.update(containerExitCode=137),
                         lambda r: r.update(oomKilled=True), lambda r: r.update(startedAt="2026-10-27T16:00:00Z")]:
                changed = copy.deepcopy(stopped)
                edit(changed["roles"][0])
                with self.assertRaises(ValueError):
                    maintenance.validate_quiescent(before, changed, outcomes)

    def test_abort_restore_renders_one_start_pass_then_health_without_recreate_or_desktop(self):
        with tempfile.TemporaryDirectory() as temp:
            _, before, stopped, outcomes, _ = fixture(Path(temp))
            value = maintenance.restore_commands(before, stopped, outcomes, sorted(shared.RUNTIME_ROLES))
            self.assertEqual(len(value["startPass"]), 22)
            self.assertTrue(value["healthWaitAfterEntirePass"])
            self.assertTrue(value["noDesktopCommand"])
            self.assertTrue(value["noRecreateResetPruneOrMigration"])
            self.assertTrue(all(step["argv"][-2] == "start" for step in value["startPass"]))
            row = stopped["roles"][0]
            row["containerExitCode"] = 137
            with self.assertRaisesRegex(ValueError, "NOT_POSITIVELY_RECONCILED"):
                maintenance.restore_commands(before, stopped, outcomes, sorted(shared.RUNTIME_ROLES))

    def test_dependency_cycle_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as temp:
            plan, before, _, _, compose = fixture(Path(temp))
            compose["elevenid-beta"]["services"]["flow"]["depends_on"] = {"gateway": {}}
            freeze_models(plan, compose, Path(temp))
            with self.assertRaisesRegex(ValueError, "DEPENDENCY_CYCLE"):
                maintenance.preview(plan, before, compose)

    def test_explicit_all19_restart_generation_scope_is_recorded_without_v2_promotion(self):
        # Existing runtime adapter accepts every explicitly declared unselected
        # generation only; this is still not a v2 profile or execution authority.
        from test_scoped_passport_runtime import runtime_rows
        before, after, binaries = runtime_rows()
        roles = shared.RUNTIME_ROLES - set(shared.ROLE_BINARIES)
        for row in after["roles"]:
            if row["role"] in roles:
                row.update(startedAt="2026-10-27T16:00:00Z", hostPid=row["hostPid"]+1000)
        result = overlay.validate_runtime_after(before, after, binaries, roles)
        self.assertEqual(set(result["maintenanceRestartRoles"]), roles)
        self.assertFalse(result["acceptedByExistingFunctionalRuntimeV2"])


    def test_real_two_project_topology_rejects_missing_extra_and_misassociated_models(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            plan, before, _, _, models = fixture(directory)
            value = maintenance.preview(plan, before, models)
            self.assertEqual(value["composeProjects"], ["elevenid-beta", "elevenid-beta-ui"])
            ui = next(step for step in value["stopSteps"] if step["role"] == "ui-prod")
            self.assertEqual(ui["project"], "elevenid-beta-ui")
            for change in [lambda m: m.pop("elevenid-beta-ui"), lambda m: m.update(production={"services": {}}),
                           lambda m: m["elevenid-beta-ui"]["services"].update(foreign={}),
                           lambda m: m["elevenid-beta"]["services"].pop("flow")]:
                changed = copy.deepcopy(models)
                change(changed)
                with self.assertRaises(ValueError):
                    maintenance.preview(plan, before, changed)
            wrong = copy.deepcopy(before)
            next(row for row in wrong["roles"] if row["role"] == "ui-prod")["project"] = "elevenid-beta"
            with self.assertRaises(ValueError):
                maintenance.preview(plan, wrong, models)

    def test_cross_project_dependency_requires_exact_hash_bound_review(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            plan, before, _, _, models = fixture(directory)
            models["elevenid-beta-ui"]["services"]["ui-prod"]["depends_on"] = {"gateway": {}}
            freeze_models(plan, models, directory)
            with self.assertRaisesRegex(ValueError, "UNREVIEWED_CROSS_PROJECT"):
                maintenance.preview(plan, before, models)
            proof = directory / "cross-project.json"
            proof.write_text(json.dumps({"schema": "marty.reviewed-cross-project-dependency/v1", "fromRole": "ui-prod",
                "toRole": "gateway", "fromProject": "elevenid-beta-ui", "toProject": "elevenid-beta"}))
            plan["reviewedCrossProjectDependencies"] = [{"fromRole": "ui-prod", "toRole": "gateway", "proof": shared.ref(proof)}]
            value = maintenance.preview(plan, before, models)
            self.assertLess(value["restoreOrder"].index("gateway"), value["restoreOrder"].index("ui-prod"))

    def test_state_projection_does_not_copy_env_arguments_or_legacy_expectations(self):
        with tempfile.TemporaryDirectory() as temp:
            _, before, _, _, _ = fixture(Path(temp))
            inspections = []
            for row in before["roles"]:
                row["Env"] = ["SOURCE_ONLY_UNEXPECTED_PAYLOAD"]
                row["requiredObservation"] = {"legacy": True}
                inspections.append({"Id": row["containerId"], "Image": row["imageId"], "Mounts": [],
                    "Config": {"Env": ["SOURCE_ONLY_UNEXPECTED_PAYLOAD"]},
                    "State": {"Running": True, "Paused": False, "Pid": row["hostPid"], "Status": "running",
                              "ExitCode": 0, "StartedAt": row["startedAt"], "OOMKilled": False}})
            value = maintenance.with_observed_state(before, inspections)
            encoded = json.dumps(value)
            self.assertNotIn("SOURCE_ONLY_UNEXPECTED_PAYLOAD", encoded)
            self.assertNotIn("requiredObservation", encoded)
            self.assertTrue(value["sourceFactsBoundToPriorReceiptNotNewElfProbe"])
            self.assertFalse(value["releaseQualified"])


if __name__ == "__main__":
    unittest.main()
