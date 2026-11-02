import copy, importlib.util, json, sys, tempfile, types, unittest
from pathlib import Path
UI = Path(__file__).resolve().parents[2]
HERE = UI / "scripts"
sys.path.insert(0, str(HERE))
import scoped_mdoc_config as reps


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

m = module("northstar", HERE / "scoped_northstar_fixture.py")


def original():
    return dict(Id="b" * 64, Name="/elevenid-beta-northstar-admissions-1", Image=m.IMAGE,
        Path="docker-entrypoint.sh", Args=["node", "src/server.mjs"],
        Config=dict(Image=m.IMAGE, Hostname="b" * 12, Env=["PORT=4175"], Labels={
            "com.docker.compose.project": "elevenid-beta", "com.docker.compose.service": m.ROLE,
            "org.opencontainers.image.revision": m.SOURCE,
            "com.docker.compose.config-hash": "old-hash", "com.docker.compose.replace": "a" * 64,
            "com.docker.compose.project.config_files": "/owned/original.json",
            "com.docker.compose.project.working_dir": "/owned", "com.docker.compose.version": "2.40.0"}),
        HostConfig=dict(Init=None, Binds=None, Mounts=[dict(Type="bind", Source="/owned/fixture.json",
            Target=m.TARGET, ReadOnly=True, BindOptions={"CreateMountpoint": False})],
            ReadonlyRootfs=True, CapDrop=["ALL"], SecurityOpt=["no-new-privileges:true"]),
        Mounts=[dict(Type="bind", Source="/owned/fixture.json", Destination=m.TARGET,
            RW=False, Mode="ro", Propagation="rprivate")],
        NetworkSettings={"Networks": {"elevenid-beta-network": dict(NetworkID="1" * 64,
            EndpointID="", Aliases=[m.ROLE], IPAMConfig=None, Links=None, IPAddress="", DNSNames=[])}},
        State=dict(Running=False, Status="exited", Pid=0, OOMKilled=False, Restarting=False,
            ExitCode=137, StartedAt="2026-11-01T14:00:00Z", FinishedAt="2026-11-01T20:00:00Z"))


def original_model():
    return dict(name="elevenid-beta", services={m.ROLE: dict(image=m.IMAGE, read_only=True,
        pull_policy="never", secrets=[dict(source="northstar_run", target="northstar_run")])},
        secrets={"northstar_run": {"file": "/owned/fixture.json"}},
        networks={"beta": {"external": True, "name": "elevenid-beta-network"}})


class Scenario:
    def __init__(self, root, *, startup=False):
        self.core = module("core_" + root.name, HERE / "repair_beta_release_metadata.py")
        self.cls = m.execution_type(self.core); self.root = root; self.calls = []; self.external = []
        self.old = original(); self.rows = {}; self.counter = 0
        self.old_fixture = root / "old.json"; self.old_fixture.write_text("{}")
        self.new_fixture = root / "new.json"; self.new_fixture.write_text("{}")
        self.old["Mounts"][0]["Source"] = reps.daemon_source(str(self.old_fixture))
        self.old["HostConfig"]["Mounts"][0]["Source"] = reps.daemon_source(str(self.old_fixture))
        self.rows[self.old["Id"]] = copy.deepcopy(self.old)
        old_model = original_model(); old_model["secrets"]["northstar_run"]["file"] = str(self.old_fixture)
        server = UI / "demo-apps/northstar-admissions/src/server.mjs"
        new_model = copy.deepcopy(old_model); new_model["secrets"]["northstar_run"]["file"] = str(self.new_fixture)
        new_model["services"][m.ROLE].update(init=True, volumes=[dict(type="bind", source=str(server),
            target=m.SERVER_TARGET, read_only=True, bind={"create_host_path": False})])
        provenance = {k: v for k, v in self.old["Config"]["Labels"].items() if k in (
            "com.docker.compose.config-hash", "com.docker.compose.project.config_files",
            "com.docker.compose.project.working_dir", "com.docker.compose.version")}
        provenance["com.docker.compose.config-hash"] = "new-hash"
        self.provenance = provenance
        cases = [{"signal": "SIGTERM", "init": False}, {"signal": "SIGINT", "init": True}]
        proof_input = self.save("signal-input.json", dict(scope="LOCAL_SOURCE_CONTROLS_ONLY", image=m.IMAGE,
            server=self.core.ref(server), cases=cases, executeAuthorized=True, sourceSha256="a" * 64))
        proof_intent = self.save("signal-intent.json", dict(inputSha256=proof_input["sha256"], sourceSha256="a" * 64))
        proof_result = self.save("signal-result.json", dict(state="ISOLATED_SHUTDOWN_SOURCE_CONTROLS_PASS",
            allIdsUnchanged=True, betaOrProdStarted=False, imageBuilt=False, demoQualified=False,
            results=[dict(**case, cid=char * 64, exit=0, serverCloseCompletion=True, removed=True)
                     for case, char in zip(cases, ("c", "d"))]))
        identities = {}; snapshots = {}
        for i in range(22):
            role = "retained-" + str(i); row = copy.deepcopy(self.old); row["Id"] = f"{100+i:064x}"
            row["Config"]["Labels"]["com.docker.compose.service"] = role
            row["State"]["ExitCode"] = 0; self.rows[row["Id"]] = row
            identities[role] = dict(containerId=row["Id"], imageId=row["Image"], reference=m.IMAGE, project="elevenid-beta")
            snapshots[role] = self.save(role + ".json", row)
        self.config = dict(scope="FUNCTIONAL_ONLY", sourceRevision=m.SOURCE, imageSource=m.SOURCE,
            runId="source-only-control", sourceSha256="reviewed-source", oldCids={m.ROLE: self.old["Id"]},
            originalContainer=self.save("original.json", self.old),
            oldModels={m.ROLE: self.save("old-model.json", old_model)},
            newModels={m.ROLE: self.save("new-model.json", new_model)},
            oldFixture=self.core.ref(self.old_fixture), newFixture=self.core.ref(self.new_fixture),
            oldPublicManifest=self.core.ref(self.old_fixture), publicManifest=self.core.ref(self.new_fixture),
            provenance={"apply": provenance, "rollback": provenance}, retainedContainers=snapshots,
            codeOverlay=dict(sourceRevision=m.CODE_SOURCE, server=self.core.ref(server),
                signalProof=dict(input=proof_input, intent=proof_intent, result=proof_result,
                    terminals=[self.save("terminal-"+char+".json", dict(Id=char*64, Image=m.IMAGE,
                        State=dict(Running=False, Pid=0, OOMKilled=False, ExitCode=0, Restarting=False)))
                        for char in ("c", "d")])),
            shutdown=dict(result=self.save("stop-result.json", dict(state="BETA_AND_SELFHOST_PRODUCTION_STOPPED",
                restartAutomatically=False, forcedStatelessNodeContainer=self.old["Id"])),
                after=self.save("stop-after.json", {self.old["Id"]: self.old})),
            functionalStartupAuthorized=startup, preflightAuthorized=True, executeAuthorized=True, rollbackAuthorized=True)
        self.g = types.SimpleNamespace(engine=lambda: None, inspect=self.inspect, old_guard=self.old_guard,
            observe=self.observe, observe_lines=self.lines, command=self.command, compose=self.compose,
            IMAGE_IDS={}, IMAGE_CONFIG={}, NETWORK_IDS={})
        self.identities = identities; self.operation = self.new_operation("apply-output")

    def save(self, name, value):
        p = self.root / name; p.write_text(json.dumps(value)); return self.core.ref(p)

    def new_operation(self, name):
        p = self.root / name; p.mkdir()
        return self.cls(self.config, p, transport=self.g, identities=self.identities,
            representations=reps, observe_external=lambda *a, **kw: self.external.append((a, kw)) or {"verified": True})

    def inspect(self, cid): return copy.deepcopy(self.rows[cid])
    def old_guard(self, expected, *, running):
        row = self.inspect(expected["Id"])
        assert row["State"]["Running"] is running
        for field in ("Id", "Image", "Config", "HostConfig", "Mounts", "NetworkSettings"):
            assert row[field] == expected[field], field
        return row
    def observe(self, args, stem):
        if args[:2] == ["image", "inspect"]:
            return [dict(Id=m.IMAGE, Config={"Labels": {"org.opencontainers.image.revision": m.SOURCE}})]
        if args[:2] == ["network", "inspect"]: return [dict(Id="1" * 64)]
        raise AssertionError(args)
    def lines(self, args, stem):
        if "--filter" in args:
            return [cid for cid, row in self.rows.items() if row["Config"]["Labels"]["com.docker.compose.service"] == m.ROLE]
        return list(self.rows)
    def command(self, args, stem, **kwargs):
        self.calls.append(args); row = self.rows[args[-1]]
        if args[0] == "start":
            assert row["HostConfig"].get("Init") is True, "LEGACY_START_FORBIDDEN"
            row["State"].update(Running=True, Status="running", Pid=9000, ExitCode=0,
                StartedAt="2026-11-02T00:00:00Z", FinishedAt="0001-01-01T00:00:00Z", Health={"Status": "healthy"})
        elif args[0] == "stop":
            row["State"].update(Running=False, Status="exited", Pid=0, ExitCode=0, FinishedAt="2026-11-02T00:00:01Z")
        else: raise AssertionError(args)
    def compose(self, args, stem, *, model_path, **kwargs):
        self.calls.append(["compose", *args]); assert args[:2] == ["up", "--no-start"]
        model = json.loads(Path(model_path).read_text()); service = model["services"][m.ROLE]
        replaced_cid = None
        for cid in list(self.rows):
            if self.rows[cid]["Config"]["Labels"]["com.docker.compose.service"] == m.ROLE:
                replaced_cid = cid; del self.rows[cid]
        self.counter += 1; row = copy.deepcopy(self.old); row["Id"] = ("f" if self.counter == 1 else "e") * 64
        row["Config"]["Hostname"] = row["Id"][:12]; row["Config"]["Labels"].update(self.provenance)
        row["Config"]["Labels"]["com.docker.compose.replace"] = replaced_cid
        source = reps.daemon_source(model["secrets"]["northstar_run"]["file"])
        row["Mounts"][0]["Source"] = source; row["HostConfig"]["Mounts"][0]["Source"] = source
        if service.get("init") is True:
            row["HostConfig"]["Init"] = True; source = reps.daemon_source(service["volumes"][0]["source"])
            row["Mounts"].append(dict(Type="bind", Source=source, Destination=m.SERVER_TARGET, RW=False, Mode="", Propagation="rprivate"))
            row["HostConfig"]["Mounts"].append(dict(Type="bind", Source=source, Target=m.SERVER_TARGET, ReadOnly=True, BindOptions={}))
        row["State"].update(Running=False, Status="created", Pid=0, ExitCode=0,
            StartedAt="0001-01-01T00:00:00Z", FinishedAt="0001-01-01T00:00:00Z")
        self.rows[row["Id"]] = row

    def execute(self):
        preflight = self.operation.preflight(); self.config["preflightResult"] = self.save("preflight.json", preflight)
        return self.operation.execute(preflight)
    def recover(self, *, failed_start=False, missing_start=False, original_only=False):
        if not original_only:
            if failed_start:
                assert self.config["functionalStartupAuthorized"] is True
                def failed_command(args, stem, **kwargs):
                    assert args[0] == "start"
                    self.calls.append(args)
                    self.rows[args[-1]]["State"].update(Status="exited", Running=False, Pid=0, ExitCode=1,
                        StartedAt="2026-11-02T00:00:00Z", FinishedAt="2026-11-02T00:00:01Z")
                    raise ValueError("SYNTHETIC_START_FAILED")
                self.g.command = failed_command
                try:self.execute()
                except ValueError as error:assert str(error)=="SYNTHETIC_START_FAILED"
                else:raise AssertionError("start fault was not reached")
            else:self.execute()
        else:
            pre = self.operation.preflight(); self.config["preflightResult"] = self.save("preflight.json", pre)
            self.operation.state["before"] = self.save("before.json", {m.ROLE: self.old})
        failed = copy.deepcopy(self.operation.state)
        if failed_start:
            row = self.rows[failed["newCids"][m.ROLE]]
            row["State"].update(Status="exited", Running=False, Pid=0, ExitCode=1,
                StartedAt="2026-11-02T00:00:00Z", FinishedAt="2026-11-02T00:00:01Z")
            if missing_start: failed["pending"] = None
        self.config["recoveryState"] = self.save("failure.json", failed)
        operation = self.new_operation("recovery-output")
        return operation.recover(failed)


class Controls(unittest.TestCase):
    def scenario(self, root, **kwargs): return Scenario(Path(root), **kwargs)
    def recovered_successor(self, root):
        scenario = self.scenario(root, startup=True)
        dispatcher = Path(root) / "dispatcher.py"
        dispatcher.write_text("# source-only dispatcher control")
        scenario.config["sourceSha256"] = scenario.core.ref(dispatcher)["sha256"]
        scenario.operation.state["sourceSha256"] = scenario.config["sourceSha256"]
        result = scenario.recover()
        previous = copy.deepcopy(scenario.config)
        previous["executeAuthorized"] = False
        input_ref = scenario.save("prior-recovery-input.json", previous)
        invocation = scenario.save("prior-invocation.json", dict(mode="rollback", input=input_ref,
            sourceSha256=previous["sourceSha256"]))
        row = scenario.core.load(result["recovered"])[m.ROLE]
        config = copy.deepcopy(previous)
        config.update(originalContainer=scenario.save("recovered-original.json", row),
            oldCids={m.ROLE:row["Id"]}, globalCohortPreimage=scenario.save("allids.json", result["allIds"]),
            recoveredOffAuthority=dict(input=input_ref, invocation=invocation,
                result=scenario.save("recovery-result.json", result), dispatcher=scenario.core.ref(dispatcher)))
        return scenario, config, row

    def test_completed_recovery_authorizes_exact_never_started_successor_and_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            s, config, row = self.recovered_successor(tmp)
            self.assertEqual(m.stopped_authority(config, s.core, reps), row)
            self.assertEqual(row["State"]["Status"], "created")
            s.config = config
            operation = s.new_operation("next-preflight")
            preflight = operation.preflight()
            self.assertEqual(preflight["state"], "D11_REBIND_PREFLIGHT_PASSED")
            self.assertEqual(preflight["oldExternal"]["state"], "ORIGINAL_CONFIGURATION_OFF")
            self.assertEqual(preflight["oldExternal"]["actualExitCode"], 0)
            self.assertEqual(len([call for call in s.calls if call[0] == "start"]), 1)

    def test_recovery_authority_rejects_unrelated_created_stale_result_and_prior_source(self):
        for kind in ("cid", "created", "result", "source", "cohort", "model"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                s, config, row = self.recovered_successor(tmp)
                if kind == "cid":config["oldCids"][m.ROLE] = "a" * 64
                elif kind == "created":config["originalContainer"] = s.save("foreign-created.json", dict(row, Id="a"*64))
                elif kind == "result":
                    result = s.core.load(config["recoveredOffAuthority"]["result"])
                    result["served"]["cid"] = "a"*64
                    config["recoveredOffAuthority"]["result"] = s.save("stale.json", result)
                elif kind == "source":config["recoveredOffAuthority"]["dispatcher"]["sha256"] = "0"*64
                elif kind == "cohort":config["globalCohortPreimage"] = s.save("wrong-allids.json", [])
                else:config["oldModels"][m.ROLE] = s.save("wrong-model.json", {})
                with self.assertRaises(ValueError):m.stopped_authority(config, s.core, reps)

    def test_default_hooks_preserve_metadata_behavior(self):
        core = module("defaults", HERE / "repair_beta_release_metadata.py")
        self.assertTrue(core.Operation.preimage_running(None, "gateway", "apply"))
        self.assertTrue(core.Operation.should_start_created(None, "gateway", "rollback"))
        self.assertEqual(core.Operation.stop_exit_codes(None, "gateway"), (0,))
        self.assertEqual(core.Operation.stop_arguments(None, "gateway", "known", "SIGTERM"), ["kill", "--signal", "SIGTERM", "known"])
    def test_actual_shared_execute_creates_repaired_off_without_stop_or_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.scenario(tmp); result = s.execute()
            self.assertEqual(result["state"], "D11_REPAIRED_ASSET_CREATED_OFF")
            self.assertTrue(all(call[0] == "compose" for call in s.calls)); self.assertFalse(s.external)
            observed = json.loads((s.operation.output / ("apply-already-stopped-" + m.ROLE + ".json")).read_text())
            self.assertEqual(observed["State"]["ExitCode"], 137)
            self.assertNotIn("apply-stop-" + m.ROLE, s.operation.state["operations"])
            self.assertIs(s.cls.create_start, s.core.Operation.create_start)
            self.assertIs(s.cls.stop_generation, s.core.Operation.stop_generation)
    def test_explicit_startup_starts_only_repaired_asset_with_separate_lineage(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.scenario(tmp, startup=True); result = s.execute()
            self.assertEqual(result["state"], "D11_REPAIRED_ASSET_RUNNING_NOT_FEATURE_QUALIFIED")
            self.assertEqual([c[0] for c in s.calls].count("start"), 1)
            self.assertEqual(s.external[0][1]["image_source"], m.SOURCE)
            self.assertEqual(s.external[0][1]["code_overlay"]["sourceRevision"], m.CODE_SOURCE)
    def test_created_and_failed_start_recovery_restore_off_never_start_legacy(self):
        for failed_start in (False, True):
            with self.subTest(failed_start=failed_start), tempfile.TemporaryDirectory() as tmp:
                s = self.scenario(tmp, startup=failed_start); result = s.recover(failed_start=failed_start)
                self.assertEqual(result["state"], "D11_NORTHSTAR_ORIGINAL_CONFIGURATION_RESTORED_OFF")
                self.assertEqual([c[0] for c in s.calls].count("start"), int(failed_start)); self.assertFalse(s.external)
                self.assertEqual(result["served"]["state"], "ORIGINAL_CONFIGURATION_OFF")
    def test_original_only_rollback_is_no_effect_and_preserves_137(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.scenario(tmp); result = s.recover(original_only=True)
            self.assertFalse(s.calls); self.assertEqual(result["served"]["actualExitCode"], 137)
    def test_unbound_exited_or_unknown_create_refuses_before_recovery_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.scenario(tmp, startup=True)
            with self.assertRaises(ValueError): s.recover(failed_start=True, missing_start=True)
            self.assertEqual(len(s.calls), 2)
    def test_running_repaired_candidate_recovery_stops_zero_and_restores_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.scenario(tmp, startup=True); result = s.recover()
            self.assertEqual(result["served"]["state"], "ORIGINAL_CONFIGURATION_OFF")
            self.assertEqual([c[0] for c in s.calls].count("start"), 1)
            self.assertEqual([c[0] for c in s.calls].count("stop"), 1)
            stop = next(c for c in s.calls if c[0] == "stop")
            self.assertEqual(stop[1:5], ["--signal", "SIGTERM", "--timeout", "-1"])
            self.assertFalse(any(r["State"]["Running"] for r in s.rows.values()))
    def test_unknown_create_has_no_automatic_adoption_or_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.scenario(tmp); pre = s.operation.preflight()
            s.config["preflightResult"] = s.save("preflight.json", pre)
            failed = copy.deepcopy(s.operation.state)
            failed.update(before=s.save("before.json", {m.ROLE:s.old}), pending="apply-create-"+m.ROLE)
            s.config["recoveryState"] = s.save("failure.json",failed)
            with self.assertRaises(ValueError):s.new_operation("recovery-output").recover(failed)
            self.assertFalse(s.calls)
    def test_valid_hash_but_failed_proof_or_non137_shutdown_is_rejected(self):
        for change in ("exit", "removed", "source", "shutdown", "oom", "pid"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                s=self.scenario(tmp)
                if change in ("oom", "pid"):
                    proof=s.config["codeOverlay"]["signalProof"]
                    value=s.core.load(proof["terminals"][0])
                    value["State"]["OOMKilled" if change=="oom" else "Pid"]=True if change=="oom" else 99
                    proof["terminals"][0]=s.save("changed-terminal.json",value)
                elif change=="shutdown":
                    changed=copy.deepcopy(s.old);changed["State"]["ExitCode"]=143
                    s.config["originalContainer"]=s.save("original-changed.json",changed)
                    s.config["shutdown"]["after"]=s.save("after-changed.json",{changed["Id"]:changed})
                else:
                    proof=s.config["codeOverlay"]["signalProof"]
                    value=s.core.load(proof["result"])
                    if change=="exit":value["results"][0]["exit"]=143
                    elif change=="removed":value["results"][0]["removed"]=False
                    else:value["state"]="FAILED"
                    proof["result"]=s.save("changed-proof.json",value)
                with self.assertRaises(ValueError):s.new_operation("invalid")
                self.assertFalse(s.calls)
    def test_running_candidate_without_bound_start_intent_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=self.scenario(tmp);s.execute();failed=copy.deepcopy(s.operation.state)
            row=s.rows[failed["newCids"][m.ROLE]]
            row["State"].update(Running=True,Status="running",Pid=7000,StartedAt="2026-11-02T00:00:00Z")
            s.config["recoveryState"]=s.save("failure.json",failed)
            with self.assertRaises(ValueError):s.new_operation("recovery-output").recover(failed)
            self.assertEqual(len(s.calls),1)
    def test_wrong_asset_commit_hash_proof_or_shutdown_refuses(self):
        mutations = [lambda c:c["codeOverlay"].update(sourceRevision="a" * 40),
            lambda c:c["codeOverlay"]["server"].update(sha256="a" * 64),
            lambda c:c["codeOverlay"]["signalProof"]["result"].update(sha256="a" * 64),
            lambda c:c["shutdown"]["after"].update(sha256="a" * 64),
            lambda c:c.update(imageSource=m.CODE_SOURCE), lambda c:c.update(functionalStartupAuthorized=1)]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as tmp:
                s = self.scenario(tmp); mutate(s.config)
                with self.assertRaises(ValueError): s.new_operation("invalid")
                self.assertFalse(s.calls)
    def test_model_and_candidate_reject_wrong_writable_duplicate_asset_or_extra_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.scenario(tmp); s.execute(); candidate = s.inspect(s.operation.state["newCids"][m.ROLE])
            mutations = [lambda r:r["Mounts"][1].update(Source="/foreign/server.mjs"),
                lambda r:r["Mounts"][1].update(RW=True), lambda r:r["Mounts"].append(copy.deepcopy(r["Mounts"][1])),
                lambda r:r["HostConfig"]["Mounts"][1].update(BindOptions={"Unreviewed": True}),
                lambda r:r["HostConfig"].update(Init=False), lambda r:r["Config"]["Env"].append("OTHER=changed"),
                lambda r:r["Config"]["Labels"].update({"com.docker.compose.replace":"wrong"}),
                lambda r:r.update(Image="sha256:"+"0"*64),
                lambda r:next(iter(r["NetworkSettings"]["Networks"].values())).update(NetworkID="wrong")]
            for mutate in mutations:
                row=copy.deepcopy(candidate);mutate(row)
                with self.assertRaises(ValueError): s.operation.verify_container(row, s.operation.changed[m.ROLE], running=False)
            old=s.core.load(s.config["oldModels"][m.ROLE]);new=s.core.load(s.config["newModels"][m.ROLE])
            new["services"][m.ROLE]["volumes"][0]["read_only"]=False
            with self.assertRaises(ValueError):m.model_delta(old,new,s.new_fixture,s.operation.server)
    def test_retained_off_generation_or_state_drift_refuses_before_create(self):
        with tempfile.TemporaryDirectory() as tmp:
            s=self.scenario(tmp);cid=next(iter(s.identities.values()))["containerId"]
            s.rows[cid]["State"]["StartedAt"]="2026-11-02T00:00:00Z"
            with self.assertRaises(ValueError):s.operation.preflight()
            self.assertFalse(s.calls)


class CreatedRepresentationControls(unittest.TestCase):
    def candidate(self, directory):
        scenario = Scenario(Path(directory))
        scenario.execute()
        cid = scenario.operation.state["newCids"][m.ROLE]
        return scenario, copy.deepcopy(scenario.rows[cid])

    def verify(self, scenario, row):
        scenario.operation.verify_container(row, scenario.operation.changed[m.ROLE], running=False)

    def test_exact_compose_retained_name_env_order_and_disabled_default_representations(self):
        with tempfile.TemporaryDirectory() as directory:
            s, row = self.candidate(directory)
            s.operation.original["Config"]["Labels"].update({"com.docker.compose.container-number":"1", "com.docker.compose.replace":m.ROLE+"-1"})
            # The verifier loads its immutable original from its exact bound snapshot.
            original = copy.deepcopy(s.old)
            original["Config"]["Labels"].update(s.operation.original["Config"]["Labels"])
            original["Config"]["Env"] = ["PORT=4175", "SECOND=value=with=equals"]
            original["HostConfig"].update(Dns=[], DnsOptions=[], DnsSearch=[], OomKillDisable=None)
            s.config["originalContainer"] = s.save("representation-original.json", original)
            row["Config"]["Labels"].update({"com.docker.compose.container-number":"1", "com.docker.compose.replace":m.ROLE+"-1"})
            row["Config"]["Env"] = list(reversed(original["Config"]["Env"]))
            row["HostConfig"].update(Dns=None, DnsOptions=None, DnsSearch=None, OomKillDisable=False)
            baseline = copy.deepcopy(row); self.verify(s, row); self.assertEqual(row, baseline)
            for change in (
                lambda v:v["Config"]["Labels"].update({"com.docker.compose.replace":"foreign-1"}),
                lambda v:v["Config"]["Labels"].update({"com.docker.compose.container-number":"2"}),
                lambda v:v["Config"].update(Env=["PORT=4175", "PORT=4175", "SECOND=value=with=equals"]),
                lambda v:v["Config"].update(Env=["PORT=4176", "SECOND=value=with=equals"]),
                lambda v:v["HostConfig"].update(Dns=["192.0.2.1"]),
                lambda v:v["HostConfig"].update(DnsOptions=["ndots:1"]),
                lambda v:v["HostConfig"].update(DnsSearch=["example.test"]),
                lambda v:v["HostConfig"].update(OomKillDisable=True)):
                altered = copy.deepcopy(baseline);change(altered)
                with self.assertRaises(ValueError):self.verify(s, altered)

    def test_windows_server_source_uses_existing_daemon_reader_without_other_mount_changes(self):
        before=original();actual=copy.deepcopy(before);actual["Id"]="c"*64
        actual["Config"]["Hostname"]="c"*12
        actual["Config"]["Labels"]["com.docker.compose.replace"]=before["Id"]
        actual["HostConfig"]["Init"]=True
        actual["State"].update(Status="created",ExitCode=0,StartedAt="0001-01-01T00:00:00Z",FinishedAt="0001-01-01T00:00:00Z")
        fixture=Path("C:/owned/fixture.json");before["Mounts"][0]["Source"]=reps.daemon_source(str(fixture));before["HostConfig"]["Mounts"][0]["Source"]=reps.daemon_source(str(fixture));actual["Mounts"][0]["Source"]=reps.daemon_source(str(fixture));actual["HostConfig"]["Mounts"][0]["Source"]=reps.daemon_source(str(fixture))
        server=Path("C:/owned/server.mjs");source=str(server)
        actual["Mounts"].append(dict(Type="bind",Source=source,Destination=m.SERVER_TARGET,RW=False,Mode="",Propagation="rprivate"))
        actual["HostConfig"]["Mounts"].append(dict(Type="bind",Source=source,Target=m.SERVER_TARGET,ReadOnly=True,BindOptions={}))
        provenance={k:v for k,v in before["Config"]["Labels"].items() if k.startswith("com.docker.compose.") and k not in ("com.docker.compose.project","com.docker.compose.service","com.docker.compose.replace")}
        def check(value):m.candidate_guard(before,value,fixture=fixture,provenance=provenance,running=False,host_mounts=reps.host_mounts,daemon_source=reps.daemon_source,server=server,replaced_cid=before["Id"])
        check(actual)
        for change in (lambda v:v["Mounts"][-1].update(RW=True),lambda v:v["Mounts"][-1].update(Source="C:/owned/foreign.mjs")):
            altered=copy.deepcopy(actual);change(altered)
            with self.assertRaises(ValueError):check(altered)

if __name__ == "__main__": unittest.main()
