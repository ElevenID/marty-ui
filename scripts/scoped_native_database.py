"""Closed beta database phase shared by four-role and current D12 windows.

Call only from the reviewed host while it owns both locks and all22 are stopped.
Import/check perform no operations. This is not a historical SQL handoff runner:
business migrations execute the selected Rust binaries; only fixed operational
SQL is streamed from the shared source renderer. Unknown outcomes never retry.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import threading
import time
import os
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from scoped_native_runtime import daemon_source, durable_barrier, read_executable_ref, read_ref, require, sha
from scoped_native_maintenance import (SOURCE, CORE, ROLE_BINARIES, PROFILE,
    select_canonical_binaries, validate_compatibility)
from scoped_linux_journal import LinuxBuildJournal
from scoped_signing_successor import environment

ENGINE = "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341"
IMAGE = "sha256:c994bb48935acaeda16f2275e89e0342e5eea7414d404781510f73618f4a88bf"
PG_BEFORE = "7edeffa3c4cbc10d02010dd0bfbd2e84e2cf4cf149e1c8d5bf7e834a5aedf075"
BUILD_RECEIPT_SHA = "bfad815173696a165dee9c915aa7d41e5f735aaf34e54d53b2d0566ceb04159e"
SCHEMA_ROLES = ("flow", "issuance-native")
NODE = r"""const fs=require('node:fs'),cp=require('node:child_process'),crypto=require('node:crypto');
const [file,sha,request,docker]=process.argv.slice(1);
if(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==sha)throw Error('METADATA_SOURCE_CHANGED');
const r=JSON.parse(fs.readFileSync(request));
if(r.profile==='d12-passport-current-functional'){
 const shared=file.replace('native-maintenance-metadata.js','functional-debug-runtime.js');
 if(!r.functionalRuntimeModule||r.functionalRuntimeModule.path!==shared||
    crypto.createHash('sha256').update(fs.readFileSync(shared)).digest('hex')!==r.functionalRuntimeModule.sha256)
    throw Error('D12_SHARED_RUNTIME_SOURCE_CHANGED');
}
const m=require(file);let out;
if(r.mode==='render')out={argv:['psql','-X','-U','postgres','-d','marty','-At','-v','ON_ERROR_STOP=1','-f','-'],pgOptions:m.sessionOptions(r.settings),stdin: m.operationalSql(r.name,r.sqlSources).toString('base64')};
else if(r.mode==='json')out=m.sqlOutput(require(file.replace('native-maintenance-metadata.js','functional-debug-runtime.js')).boundBytes(r.stdout),r.schema);
else if(r.mode==='digest')out=m.migrationDigest(r.sources);
else if(r.mode==='baseline')out=m.currentDatabaseBaseline(r.refs,r.approvedBefore,r.approvedEngine);
else if(r.mode==='catalog')out=m.observeCatalog(r.inputs,{readDocker:a=>cp.execFileSync(docker,['--context','desktop-linux',...a],{encoding:'utf8',env:process.env,timeout:150000,maxBuffer:1048576})});
else if(r.mode==='verify')out=m.validateProof(r.proof,r.commands,r.context);
else if(r.mode==='runtime'){
 const source=fs.readFileSync(r.module.path);
 if(crypto.createHash('sha256').update(source).digest('hex')!==r.module.sha256)throw Error('D12_RUNTIME_READER_CHANGED');
 out=require(r.module.path).observe(r.inputs,{readDocker:a=>cp.execFileSync(docker,['--context','desktop-linux',...a],{encoding:'utf8',env:process.env,timeout:150000,maxBuffer:1048576})});
}
else throw Error('METADATA_OPERATION_REFUSED');process.stdout.write(JSON.stringify(out));"""


def bounded_run(argv, *, env, input=None, timeout=150, stdout_limit=1024 * 1024,
                stderr_limit=65536, stdout_file=None):
    """Bound owned child output while reading; never stop a Docker container.

    An output/clock/read failure terminates only this newly owned CLI process.
    A remote Docker operation may still be unknown: callers keep pending state.
    """
    process = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stop = threading.Event()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    sizes = {"stdout": 0, "stderr": 0}
    failures = []

    def reader(name, pipe, limit, target=None):
        try:
            while True:
                chunk = pipe.read(65536)
                if not chunk:
                    break
                remaining = limit - sizes[name]
                accepted = chunk[:max(remaining, 0)]
                if target is None:
                    buffers[name].extend(accepted)
                else:
                    require(target.write(accepted) == len(accepted), "BOUNDED_OUTPUT_SHORT_WRITE")
                sizes[name] += len(accepted)
                if len(chunk) > remaining:
                    failures.append(name + "_limit")
                    stop.set()
                    break
        except BaseException:
            failures.append(name + "_read_or_write")
            stop.set()
        finally:
            pipe.close()

    def writer():
        try:
            process.stdin.write(input)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    threads = [threading.Thread(target=reader, args=("stdout", process.stdout, stdout_limit, stdout_file), daemon=True),
               threading.Thread(target=reader, args=("stderr", process.stderr, stderr_limit), daemon=True)]
    if input is not None:
        threads.append(threading.Thread(target=writer, daemon=True))
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    while process.poll() is None and not stop.is_set() and time.monotonic() < deadline:
        time.sleep(0.02)
    timed_out = process.poll() is None and not stop.is_set()
    if process.poll() is None:
        try:
            process.kill()  # only this Popen-owned host CLI, never a service/container
        except OSError:
            failures.append("owned_cli_termination_unknown")
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        failures.append("owned_cli_exit_unknown")
    for thread in threads:
        thread.join(timeout=2)
        if thread.is_alive():
            failures.append("owned_pipe_outcome_unknown")
    result = subprocess.CompletedProcess(argv, process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    result.observation = {"ownedPid": process.pid, "timedOut": timed_out, "failures": failures,
        "stdoutBytesRetained": sizes["stdout"], "stderrBytesRetained": sizes["stderr"]}
    return result


def schema_input_contract(inputs):
    required = {"runId", "executables", "metadataModule", "sqlSources", "migrationSetSha256", "databaseNetwork", "selection"}
    require(required.issubset(inputs), "FROZEN_SCHEMA_ADAPTER_INPUT_CONTRACT_REQUIRED")
    return json.loads(read_ref(inputs["selection"]).read_bytes())


def schema_url(raw, command):
    """SQLx consumes URL options, not an assumed libpq PGOPTIONS environment."""
    value = urlsplit(raw.strip())
    require(value.scheme in ("postgres", "postgresql") and value.username == "postgres"
            and value.hostname == "postgres" and value.port in (None, 5432)
            and value.path == "/marty" and not value.query and not value.fragment,
            "EXACT_PRIVATE_SCHEMA_DATABASE_URL_REQUIRED")
    require(command in ("migrate", "verify-owned-schema"), "EXACT_SCHEMA_COMMAND_REQUIRED")
    role = "postgres" if command == "migrate" else "marty"
    return urlunsplit((value.scheme, value.netloc, value.path, urlencode({"options[role]": role}), ""))


class NativeDatabasePhase:
    SCHEMA_BINARIES = {role: ROLE_BINARIES[role] for role in SCHEMA_ROLES}
    role_binaries = ROLE_BINARIES
    source_revision = SOURCE
    core_revision = CORE
    rollout_profile = PROFILE
    helper_image = IMAGE
    engine_id = ENGINE
    expected_database_before = PG_BEFORE
    expected_build_receipt = BUILD_RECEIPT_SHA
    select_binaries = staticmethod(select_canonical_binaries)
    check_compatibility = staticmethod(validate_compatibility)
    operation_schema = "marty.native-four-role-operation-state/v1"
    scope_error = "CLOSED_FOUR_ROLE_DATABASE_SCOPE_REQUIRED"
    selection_error = "EXACT_FOUR_ROLE_SELECTION_REQUIRED"

    """Reuse the frozen host command/save/guard and original private journal."""
    def __init__(self, context, inputs, store):
        require(type(store) is LinuxBuildJournal, "ORIGINAL_LINUX_JOURNAL_REQUIRED")
        require(inputs["rolloutProfile"] == self.rollout_profile and inputs["sourceRevision"] == self.source_revision
                and inputs["coreRevision"] == self.core_revision
                and inputs["databaseBefore"]["sha256"] == self.expected_database_before,
                self.scope_error)
        require(read_ref(inputs["executorSource"]).resolve() == Path(__file__).resolve(), "DATABASE_EXECUTOR_SOURCE_CHANGED")
        self.g, self.i, self.store = context, inputs, store
        self.identity = json.loads(read_ref(inputs["databaseBefore"]).read_bytes())["databaseIdentity"]
        self.selection = schema_input_contract(inputs)
        require(self.selection["roleBinaries"] == self.role_binaries
                and self.selection["sourceRevision"] == self.source_revision
                and self.selection["coreRevision"] == self.core_revision
                and self.selection["canonicalBuildReceipt"]["sha256"] == self.expected_build_receipt,
                self.selection_error)
        self.state = {"schema": self.operation_schema, "phase": "NOT_STARTED",
            "runId": inputs["runId"], "sourceRevision": self.source_revision, "coreRevision": self.core_revision,
            "selectionSha256": inputs["selection"]["sha256"], "databaseIdentity": self.identity,
            "executorSource": inputs["executorSource"], "operations": []}
        self.sql_receipts, self.commands, self.projections = {}, [], {}
        self.epoch = None
        self.command_index = 0
        self.schema_records = {}

    def result(self, args, *, input=None):
        self.g["assert_inputs"](rollback=False)
        require(args and args[0] == "docker", "EXACT_DOCKER_COMMAND_REQUIRED")
        docker = read_executable_ref(self.i["executables"]["docker"])
        self.command_index += 1
        result = bounded_run([str(docker), "--context", "desktop-linux", *args[1:]],
            input=input, env=self.g["env"], timeout=150)
        prefix = "database-command-" + str(self.command_index)
        self.g["save_bytes"](prefix + ".stdout", result.stdout)
        self.g["save_bytes"](prefix + ".stderr", result.stderr)
        self.g["save"](prefix + ".terminal.json", {"argv": args, "exitCode": result.returncode, "observation": result.observation})
        require(result.returncode == 0 and not result.observation["timedOut"] and not result.observation["failures"], "DATABASE_COMMAND_NONZERO_RECONCILE")
        return result

    def command(self, args, **kwargs):
        return self.result(args, **kwargs).stdout

    def node(self, mode, **payload):
        self.g["assert_inputs"](rollback=False)
        request = self.g["save"]("metadata-request-" + mode + "-" + str(len(self.state["operations"])) + ".json",
            {"mode": mode, "profile": self.rollout_profile,
             **({"functionalRuntimeModule": self.i["functionalRuntimeModule"]}
                if self.rollout_profile == "d12-passport-current-functional" else {}), **payload})
        module = self.i["metadataModule"]
        read_ref(module)
        result = bounded_run([self.g["nodeExecutable"], "-e", NODE, module["path"], module["sha256"],
            request["path"], self.i["executables"]["docker"]["path"]], env=self.g["env"],
            timeout=600 if mode == "runtime" else 180)
        self.g["save_bytes"]("metadata-" + mode + "-" + str(len(self.state["operations"])) + ".stderr", result.stderr)
        self.g["save_bytes"]("metadata-" + mode + "-" + str(len(self.state["operations"])) + ".stdout", result.stdout[:1024 * 1024])
        self.g["save"]("metadata-" + mode + "-" + str(len(self.state["operations"])) + ".terminal.json", result.observation)
        require(result.returncode == 0 and not result.observation["timedOut"] and not result.observation["failures"], "SOURCE_BOUND_METADATA_READER_FAILED")
        return json.loads(result.stdout)

    def guard(self):
        require(self.command(["docker", "info", "--format", "{{.ID}}"]).decode().strip() == self.engine_id,
                "ENGINE_CHANGED")
        row = json.loads(self.command(["docker", "inspect", self.identity["containerId"]]))[0]
        require(row["Id"] == self.identity["containerId"] and row["Image"] == self.identity["imageId"]
                and row["State"]["Running"] and row["State"]["StartedAt"] == self.identity["startedAt"]
                and row["State"]["Pid"] == self.identity["hostPid"]
                and row["Config"]["Labels"]["com.docker.compose.project"] == "elevenid-beta"
                and row["Config"]["Labels"]["com.docker.compose.service"] == "postgres", "DATABASE_IDENTITY_CHANGED")
        return row

    def persist(self):
        proof = self.store.state(self.state)
        require(durable_barrier(proof), "DURABLE_DATABASE_STATE_REQUIRED")
        return proof

    def verify_quiescence(self):
        self.g["verify_all22_quiescent"](self.i["quiescence"])

    def database_url(self, command):
        return schema_url(read_ref(self.i["databaseAdminUrl"], 8192).read_text(), command)

    def step(self, step_id, operation):
        self.guard()
        self.verify_quiescence()
        index = len(self.state["operations"])
        self.state.update(phase="DATABASE_OPERATION_PENDING", pendingStep=step_id, pendingRequest=None)
        intent = self.persist()
        started = datetime.now(timezone.utc).isoformat()
        # Exceptions deliberately preserve the pending journal. Never rerun.
        row = operation()
        reference = self.g["save"]("database-step-" + step_id + ".json", row)
        entry = {"stepId": step_id, "state": "SUCCEEDED", "unknownOutcome": False, "exitCode": 0,
            "sequence": index + 1, "intentSequence": index * 2 + 1, "terminalSequence": index * 2 + 2,
            "intentDurability": intent, "startedAt": started,
            "finishedAt": datetime.now(timezone.utc).isoformat(), "receipt": reference,
            "request": self.state.get("pendingRequest")}
        self.state["operations"].append(entry)
        self.state.update(phase="DATABASE_OPERATION_TERMINAL", pendingStep=None, pendingRequest=None)
        entry["terminalDurability"] = self.persist()
        if row.get("role") in SCHEMA_ROLES:
            self.retire_schema_helper(row["containerId"])
        return reference, row

    def target_settings(self):
        target = getattr(self, "current_database_target", None)
        value = {"marty.passport_beta_verified_project": "elevenid-beta",
            "marty.passport_beta_expected_system_identifier": target["systemIdentifier"] if target else "7698090346923700258",
            "marty.passport_beta_expected_database_oid": target["databaseOid"] if target else "16387"}
        if self.epoch is not None:
            value.update({"marty.passport_beta_expected_fence_epoch": str(self.epoch),
                "marty.passport_beta_expected_source_commit": self.source_revision,
                "marty.passport_beta_expected_native_migration_sha256": self.i["migrationSetSha256"]})
        return value

    def sql(self, name, *, transition=None):
        settings = self.target_settings()
        if transition is not None:
            settings["marty.passport_beta_expected_transition_txid"] = str(transition)
        descriptor = self.node("render", name=name, sqlSources=self.i["sqlSources"], settings=settings)
        stdin = base64.b64decode(descriptor["stdin"], validate=True)
        args = ["docker", "exec", "-i", "-e", "PGOPTIONS=" + descriptor["pgOptions"], self.identity["containerId"], *descriptor["argv"]]
        stdin_ref = self.g["save_bytes"](name + ".stdin", stdin)
        self.state["pendingRequest"] = {"kind": "PSQL", "source": self.i["sqlSources"][name],
            "stdin": stdin_ref, "pgOptions": descriptor["pgOptions"],
            "transportArgv": ["docker", "--context", "desktop-linux", *args[1:]]}
        self.persist()
        result = self.result(args, input=stdin)
        self.guard()
        return {"runId": self.i["runId"], "databaseIdentity": self.identity,
            "source": self.i["sqlSources"][name], "argv": descriptor["argv"],
            "transportArgv": ["docker", "--context", "desktop-linux", *args[1:]], "pgOptions": descriptor["pgOptions"],
            "stdin": stdin_ref,
            "stdout": self.g["save_bytes"](name + ".stdout", result.stdout),
            "stderr": self.g["save_bytes"](name + ".stderr", result.stderr), "state": "exited", "exitCode": 0, "oomKilled": False}

    def catalog(self):
        return self.node("catalog", inputs={"runId": self.i["runId"], "databaseBefore": self.i["databaseBefore"],
            "sql": self.i["catalogSql"], "rolloutProfile": self.rollout_profile,
            "sourceRevision": self.source_revision, "coreRevision": self.core_revision,
            **({"baseline": self.baseline_refs} if hasattr(self, "baseline_refs") else {}),
            "approvedDatabaseBeforeSha256": self.expected_database_before,
            "approvedEngineId": self.engine_id})

    def backup(self):
        self.g["assert_inputs"](rollback=False)
        docker = read_executable_ref(self.i["executables"]["docker"])
        path = Path(self.g["root"]) / "quiesced-database.dump"
        self.state["pendingBackup"] = str(path)
        self.persist()
        with path.open("xb") as target:
            result = bounded_run([str(docker), "--context", "desktop-linux", "exec", self.identity["containerId"],
                "pg_dump", "-U", "postgres", "-d", "marty", "--format=custom", "--lock-wait-timeout=10000"],
                env=self.g["env"], timeout=150, stdout_limit=512 * 1024 * 1024, stdout_file=target)
            target.flush()
            os.fsync(target.fileno())
        self.g["save_bytes"]("database-backup.stderr", result.stderr)
        self.g["save"]("database-backup.observation.json", {"exitCode": result.returncode, **result.observation})
        require(result.returncode == 0 and not result.observation["timedOut"] and not result.observation["failures"]
                and 0 < path.stat().st_size <= 512 * 1024 * 1024, "BOUNDED_DATABASE_BACKUP_UNKNOWN_NO_RETRY")
        return {"runId": self.i["runId"], "databaseIdentity": self.identity,
            "phase": "QUIESCED_FENCED_DATABASE_BACKUP", "quiescenceSha256": self.i["quiescence"]["sha256"],
            "catalogSha256": self.projections["beforeCatalog"]["sha256"],
            "backupFile": self.g["ref"](path)}

    def schema(self, role, command):
        require(schema_input_contract(self.i) == self.selection, "SCHEMA_SELECTION_CHANGED")
        require(role in self.SCHEMA_BINARIES and command in ("migrate", "verify-owned-schema"), "CLOSED_SCHEMA_COMMAND_REQUIRED")
        binary = self.SCHEMA_BINARIES[role]
        bound = self.selection["binaries"][role]
        path = read_ref(bound, 512 * 1024 * 1024)
        url = self.database_url(command)
        url_ref = self.g["save_bytes"](role + "-" + command + ".url.private", url.encode())
        env_ref = self.g["save_bytes"](role + "-" + command + ".env.private", ("DATABASE_URL=" + url + "\n").encode())
        name = "marty-native-schema-" + self.i["runId"] + "-" + role + "-" + command
        args = ["docker", "create", "--pull=never", "--name", name, "--network", self.i["databaseNetwork"],
            "--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--cpus", "0.25", "--memory", "256m", "--memory-swap", "256m",
            "--label", "elevenid.owner=native-maintenance-schema", "--label", "elevenid.run=" + self.i["runId"],
            "--env-file", env_ref["path"], "--mount", "type=bind,src=" + daemon_source(path) + ",dst=/usr/local/bin/" + binary + ",readonly",
            "--entrypoint", "/usr/local/bin/" + binary, self.helper_image, command]
        self.state["pendingRequest"] = {"kind": "RUST_SCHEMA_HELPER", "createArgv": args,
            "binary": bound, "environment": env_ref, "databaseUrl": url_ref}
        self.persist()
        cid = self.command(args).decode().strip()
        require(re.fullmatch(r"[a-f0-9]{64}", cid), "SCHEMA_CREATE_OUTCOME_UNKNOWN")
        self.state["pendingContainerId"] = cid
        self.persist()
        self.schema_records[cid] = {"name": name, "binary": binary, "command": command, "url": url, "bound": bound}
        self.validate_schema(cid, created=True)
        read_ref(bound, 512 * 1024 * 1024)
        result = self.result(["docker", "start", "--attach", cid])
        actual = json.loads(self.command(["docker", "inspect", cid]))[0]
        require(actual["Id"] == cid and actual["State"]["Status"] == "exited" and actual["State"]["ExitCode"] == 0
                and not actual["State"]["OOMKilled"] and actual["State"]["Pid"] == 0, "SCHEMA_COMMAND_NOT_TERMINAL_SUCCESS")
        return {"runId": self.i["runId"], "selectionSha256": self.i["selection"]["sha256"],
            "role": role, "command": command, "sourceRevision": self.source_revision, "coreRevision": self.core_revision,
            "databaseIdentity": self.identity, "databaseRole": parse_qs(urlsplit(url).query)["options[role]"][0],
            "databaseLoginRole": "postgres", "databaseUrl": url_ref,
            "imageId": self.helper_image, "elfSha256": bound["sha256"], "containerId": cid,
            "argv": ["/usr/local/bin/" + binary, command], "state": "exited", "exitCode": 0, "oomKilled": False,
            "stdout": self.g["save_bytes"](role + "-" + command + ".stdout", result.stdout),
            "stderr": self.g["save_bytes"](role + "-" + command + ".stderr", result.stderr)}

    def validate_schema(self, cid, *, created, expected_exit=0, ownership_only=False):
        require(expected_exit in (0, 1), "CLOSED_SCHEMA_CONTROL_EXIT_REQUIRED")
        expected = self.schema_records[cid]
        row = json.loads(self.command(["docker", "inspect", cid]))[0]
        config, host, state = row["Config"], row["HostConfig"], row["State"]
        require(row["Id"] == cid and row["Name"] == "/" + expected["name"] and row["Image"] == self.helper_image
                and config["Labels"].get("elevenid.owner") == "native-maintenance-schema"
                and config["Labels"].get("elevenid.run") == self.i["runId"], "SCHEMA_HELPER_OWNERSHIP_CHANGED")
        require(config["User"] == "10001:10001" and config["Entrypoint"] == ["/usr/local/bin/" + expected["binary"]]
                and config["Cmd"] == [expected["command"]], "SCHEMA_HELPER_ENTRYPOINT_CHANGED")
        image = json.loads(self.command(["docker", "image", "inspect", self.helper_image]))[0]
        wanted = environment(image["Config"].get("Env") or [])
        wanted["DATABASE_URL"] = expected["url"]
        require(environment(config["Env"]) == wanted, "SCHEMA_HELPER_ENVIRONMENT_CHANGED")
        require(host["ReadonlyRootfs"] and not host["Privileged"] and host["Memory"] == 268435456
                and host["MemorySwap"] == 268435456 and host["NanoCpus"] == 250000000
                and host["NetworkMode"] == self.i["databaseNetwork"], "SCHEMA_HELPER_RESOURCES_CHANGED")
        require({x.removeprefix("CAP_") for x in host.get("CapDrop") or []} == {"ALL"}
                and not host.get("CapAdd") and host.get("SecurityOpt") in (["no-new-privileges"], ["no-new-privileges:true"])
                and not host.get("Binds") and not host.get("PortBindings") and not host.get("PublishAllPorts")
                and host.get("RestartPolicy", {}).get("Name") == "no" and not host.get("AutoRemove"), "SCHEMA_HELPER_SECURITY_CHANGED")
        mounts = row["Mounts"]
        require(len(mounts) == 1 and mounts[0]["Type"] == "bind" and not mounts[0]["RW"]
                and mounts[0]["Destination"] == "/usr/local/bin/" + expected["binary"]
                and daemon_source(mounts[0]["Source"]) == daemon_source(expected["bound"]["path"]), "SCHEMA_HELPER_MOUNT_CHANGED")
        if ownership_only:
            require(not state["Paused"] and state["Status"] in ("created", "running", "exited")
                    and (state["Pid"] > 0 if state["Running"] else state["Pid"] == 0), "SCHEMA_HELPER_STATE_UNKNOWN")
        else:
            require(not state["Running"] and not state["Paused"] and not state["OOMKilled"]
                    and state["Status"] == ("created" if created else "exited")
                    and state["Pid"] == 0 and (created or state["ExitCode"] == expected_exit), "SCHEMA_HELPER_NOT_OWNED_TERMINAL")
            database = self.guard()
            network = database["NetworkSettings"]["Networks"].get(self.i["databaseNetwork"])
            require(network is not None and network["NetworkID"] == self.i["databaseNetworkId"]
                    and "postgres" in (network.get("Aliases") or []), "SCHEMA_DATABASE_NETWORK_CHANGED")
        self.g["save"]("schema-" + cid + ("-ownership-" + str(self.command_index) if ownership_only else "-created" if created else "-terminal-" + str(self.command_index)) + ".json", row)
        return row

    def retire_schema_helper(self, cid, *, expected_exit=0):
        self.guard()
        self.validate_schema(cid, created=False, expected_exit=expected_exit)
        self.state["pendingCleanup"] = cid
        self.persist()
        self.command(["docker", "rm", cid])
        ids = self.command(["docker", "ps", "-aq", "--no-trunc"]).decode().split()
        require(cid not in ids, "SCHEMA_HELPER_CLEANUP_NOT_OBSERVED")
        self.state["pendingCleanup"] = None
        self.state["pendingContainerId"] = None
        self.persist()

    def run(self):
        require(self.g["dispatch_enabled"] is True, "DATABASE_DISPATCH_DISABLED")
        require(self.select_binaries(self.selection["preparedSource"], self.selection["canonicalBuildReceipt"], self.g["build_journal"]) == self.selection, "ORIGINAL_SELECTED_BUILD_CHANGED")
        self.check_compatibility(self.selection, self.i["compatibility"]["plan"], self.i["compatibility"]["result"])
        admin = read_ref(self.i["databaseAdminUrl"], 8192).read_text()
        for command in ("migrate", "verify-owned-schema"):
            schema_url(admin, command)
        self.g["verify_all22_quiescent"](self.i["quiescence"])
        require(self.node("digest", sources=self.i["migrationSources"]) == self.i["migrationSetSha256"], "EXACT_MIGRATION_SET_DIGEST_REQUIRED")
        prior = self.store.read("build-state.json")
        require(prior.get("phase") == "ALL22_QUIESCENT" and prior.get("runId") == self.i["runId"]
                and prior.get("quiescenceSha256") == self.i["quiescence"]["sha256"], "UNUSED_DATABASE_PHASE_REQUIRED")
        intent = self.store.read("build-apply-intent.json")
        require(intent["runId"] == self.i["runId"] and intent["selectionSha256"] == self.i["selection"]["sha256"]
                and intent["executorSource"] == self.i["executorSource"], "ORIGINAL_MAINTENANCE_INTENT_REQUIRED")
        order = [("FENCE_INSTALL", "passport-beta-fence-install.sql"), ("FENCE_VERIFY", "passport-beta-fence-verify.sql"),
            ("MAINTENANCE_START", "passport-beta-db-maintenance-start.sql")]
        for step_id, name in order:
            reference, row = self.step(step_id, lambda name=name: self.sql(name))
            self.sql_receipts[name] = reference
            if step_id == "FENCE_VERIFY":
                self.epoch = self.node("json", stdout=row["stdout"], schema="marty.passport-beta-fence-verification/v1")["epoch"]
        self.projections["beforeCatalog"], _ = self.step("CATALOG_BEFORE_SCHEMA", self.catalog)
        backup, _ = self.step("DATABASE_BACKUP", self.backup)
        for step_id, role in (("FLOW_MIGRATE", "flow"), ("ISSUER_MIGRATE", "issuance-native")):
            _, row = self.step(step_id, lambda role=role: self.schema(role, "migrate"))
            self.commands.append(row)
        self.sql_receipts["passport-beta-batch-acl-finalize.sql"], _ = self.step("ACL_FINALIZE", lambda: self.sql("passport-beta-batch-acl-finalize.sql"))
        for step_id, role in (("FLOW_VERIFY", "flow"), ("ISSUER_VERIFY", "issuance-native")):
            _, row = self.step(step_id, lambda role=role: self.schema(role, "verify-owned-schema"))
            self.commands.append(row)
        transition = None
        for step_id, name in (("NATIVE_ATTESTATION", "passport-beta-native-attestation.sql"),
            ("ENABLE_APP_LOGIN", "passport-beta-db-enable-app-login.sql"),
            ("RUST_OWNER_TRANSITION", "passport-beta-rust-owner-transition.sql"),
            ("RUST_OWNER_VERIFY", "passport-beta-rust-owner-verify.sql")):
            reference, row = self.step(step_id, lambda name=name: self.sql(name, transition=transition if step_id == "RUST_OWNER_VERIFY" else None))
            self.sql_receipts[name] = reference
            if step_id == "RUST_OWNER_TRANSITION":
                transition = self.node("json", stdout=row["stdout"], schema="marty.passport-beta-rust-owner-transition/v1")["transition_txid"]
        self.projections["afterCatalog"], _ = self.step("CATALOG_BEFORE_START", self.catalog)
        self.state["phase"] = "DATABASE_MAINTENANCE_COMPLETED"
        self.persist()
        return {"schema": "marty.native-maintenance-metadata-proof/v1", "databaseBefore": self.i["databaseBefore"],
            **self.projections, "sqlSources": self.i["sqlSources"], "sqlReceipts": self.sql_receipts,
            "migrationSources": self.i["migrationSources"], "databaseBackup": backup,
            "operationState": self.g["save"]("database-operation-state.json", self.state)}


def reviewed_database_baseline_refs(inputs, authority):
    """Bind the shared metadata validator to exact reviewed observation refs."""
    refs = inputs.get("databaseBaseline")
    require(type(refs) is dict and set(refs) == {"catalog", "proof", "job"},
            "D12_CURRENT_DATABASE_BASELINE_REFS_REQUIRED")
    require(authority.get("approvedBaselineCatalogSha256") == refs["catalog"]["sha256"]
            and authority.get("approvedBaselineProofSha256") == refs["proof"]["sha256"]
            and authority.get("approvedBaselineJobSha256") == refs["job"]["sha256"],
            "D12_REVIEWED_DATABASE_BASELINE_REQUIRED")
    return refs


def consume_current_database_target(target):
    require(type(target) is dict and set(target) == {"database", "systemIdentifier", "databaseOid"}
            and all(type(value) is str for value in target.values()) and target["database"] == "marty",
            "D12_BASELINE_DATABASE_TARGET_INVALID")
    return {"systemIdentifier": target["systemIdentifier"], "databaseOid": target["databaseOid"]}


class D12CurrentDatabasePhase(NativeDatabasePhase):
    """Same fenced SQL and Rust CLI sequence, bound to the distinct current 3-role build."""

    operation_schema = "marty.native-d12-current-operation-state/v1"
    scope_error = "CLOSED_D12_CURRENT_DATABASE_SCOPE_REQUIRED"
    selection_error = "EXACT_D12_CURRENT_SELECTION_REQUIRED"

    def __init__(self, context, inputs, store):
        from scoped_native_profiles import D12_PASSPORT_CURRENT
        from scoped_passport_successor import CURRENT_PROFILE, select_current_binaries
        self.source_revision = D12_PASSPORT_CURRENT.ui_revision
        self.core_revision = D12_PASSPORT_CURRENT.core_revision
        self.rollout_profile = CURRENT_PROFILE
        self.role_binaries = dict(D12_PASSPORT_CURRENT.roles)
        self.SCHEMA_BINARIES = {role: self.role_binaries[role] for role in SCHEMA_ROLES}
        self.select_binaries = select_current_binaries
        self.check_compatibility = self._check_current_compatibility
        authority = json.loads(read_ref(inputs["d12Authority"], 65536).read_bytes())
        require(authority.get("schema") == "marty.d12-current-native-authority/v1"
                and context["operation_lock_held"]() is True
                and context["recording_lock_held"]() is True
                and context["authorization_verified"](inputs["d12Authority"]) is True
                and authority.get("sourceRevision") == self.source_revision
                and authority.get("coreRevision") == self.core_revision
                and authority.get("scope") == "FUNCTIONAL_ONLY"
                and authority.get("releaseQualified") is False
                and authority.get("recordingQualified") is False
                and authority.get("runId") == inputs["runId"]
                and authority.get("approvedDatabaseBeforeSha256") == inputs["databaseBefore"]["sha256"]
                and authority.get("approvedSelectionSha256") == inputs["selection"]["sha256"]
                and authority.get("approvedDatabaseExecutorSha256") == inputs["executorSource"]["sha256"]
                and authority.get("approvedMetadataModuleSha256") == inputs["metadataModule"]["sha256"]
                and authority.get("approvedFunctionalRuntimeSha256")
                    == inputs["functionalRuntimeModule"]["sha256"]
                and authority.get("approvedProfileSourceSha256")
                    == sha(Path(__file__).with_name("scoped_native_profiles.py"))
                and authority.get("approvedRuntimeBeforeSha256") == inputs["runtimeBefore"]["sha256"]
                and isinstance(authority.get("approvedBuildReceiptSha256"), str)
                and re.fullmatch(r"[a-f0-9]{64}", authority["approvedBuildReceiptSha256"])
                and authority.get("schemaHelperImageId") == IMAGE
                and isinstance(authority.get("engineId"), str)
                and re.fullmatch(r"[a-f0-9-]{36}", authority["engineId"])
                and authority.get("dispatchAuthorized") is True,
                "EXACT_D12_CURRENT_AUTHORITY_REQUIRED")
        self.expected_database_before = authority["approvedDatabaseBeforeSha256"]
        self.baseline_refs = reviewed_database_baseline_refs(inputs, authority)
        self.expected_build_receipt = authority["approvedBuildReceiptSha256"]
        self.helper_image = IMAGE
        self.engine_id = authority["engineId"]
        self.runtime_before = inputs["runtimeBefore"]
        self.authority = inputs["d12Authority"]
        super().__init__(context, inputs, store)
        self.current_database_target = consume_current_database_target(self.node("baseline",
            refs=self.baseline_refs, approvedBefore=self.expected_database_before,
            approvedEngine=self.engine_id))
        require(self.selection["scope"] == "FUNCTIONAL_ONLY"
                and self.selection["releaseQualified"] is False
                and self.selection["recordingQualified"] is False,
                "D12_FUNCTIONAL_ONLY_SELECTION_REQUIRED")

    def _check_current_compatibility(self, selection, plan_ref, result_ref):
        from scoped_passport_successor import _validate_compatibility
        plan = json.loads(read_ref(plan_ref).read_bytes())
        require(plan.get("beforeBinding", {}).get("sha256") == self.runtime_before["sha256"],
                "FRESH_D12_RUNTIME_PREIMAGE_FOR_COMPATIBILITY_REQUIRED")
        before = json.loads(read_ref(self.runtime_before).read_bytes())
        prior = {row["role"]: row for row in before["roles"]}
        require(len(before["roles"]) == len(prior) == 22, "EXACT_22_ROLE_SET_REQUIRED")
        proof = _validate_compatibility(selection, plan_ref, result_ref, self.role_binaries, 10001)
        rows = json.loads(read_ref(result_ref).read_bytes())["rows"]
        for role, binary in self.role_binaries.items():
            row = next(row for row in rows if row["binary"] == binary)
            require(row.get("imageId") == prior[role]["imageId"],
                    "D12_RUNTIME_IMAGE_COMPATIBILITY_REQUIRED")
        return proof
