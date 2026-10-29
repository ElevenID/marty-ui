"""One synthetic, source-bound stock-PG rehearsal; never a beta target.

No beta/domain rows are copied. Canonical fresh schemas come from the selected
Rust CLIs. Full pinned operational SQL is exercised with explicitly synthetic
beta-guard settings. Windows evidence is non-authoritative; no runtime profile
or beta migration receipt can be produced by this operator.
"""
from __future__ import annotations
import argparse
import importlib.util
from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
import sys
import uuid
from scoped_native_database import NativeDatabasePhase, schema_url, ENGINE, BUILD_RECEIPT_SHA, bounded_run
from scoped_native_runtime import read_ref, ref, require, save_state, MIGRATIONS
from scoped_signing_successor import environment
from scoped_native_maintenance import SOURCE, CORE, ROLE_BINARIES, operational_sql_sources
from prepare_local_official_native_build import git

DISPATCH_ENABLED = False
PG_IMAGE = "sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c"
OWNER = "native-schema-rehearsal"
LOCK = Path("C:/Users/maree/OneDrive/Glthub/marty-workspace/marty-demo-recorder/artifacts/.recording.lock")
SCHEMA = "marty.synthetic-native-schema-rehearsal/v1"
STAGES = ("bootstrap-flow", "bootstrap-issuer", "install", "fence", "maintenance", "migrate-flow", "migrate-issuer",
    "reject-flow-before-acl", "reject-issuer-before-acl", "acl", "verify-flow", "verify-issuer", "reject-admin-issuer", "attest", "login", "owner", "owner-verify")

OPERATOR_FILES = ('scripts/rehearse_native_schema_commands.py', 'scripts/scoped_native_database.py', 'scripts/scoped_native_runtime.py', 'scripts/scoped_native_profiles.py', 'scripts/scoped_native_maintenance.py', 'scripts/scoped_passport_successor.py', 'scripts/scoped_linux_journal.py', 'scripts/scoped_signing_successor.py', 'scripts/prepare_local_official_native_build.py', 'scripts/scoped_native_build.py', 'tests/scripts/native-maintenance-metadata.js', 'tests/scripts/functional-debug-runtime.js')


class Rehearsal(NativeDatabasePhase):
    def __init__(self, context, inputs):
        self.g, self.i = context, inputs
        self.fixture_run = inputs["runId"]
        self.stage = "prepare"
        self.command_index = 0
        self.schema_records = {}
        self.selection = {"binaries": {role: inputs["binaries"][role] for role in ("flow", "issuance-native")}}
        self.state = {"schema": SCHEMA, "phase": "PREPARING", "runId": self.fixture_run, "operations": [],
            "sourceRevision": SOURCE, "coreRevision": CORE, "betaDatabaseAccessed": False,
            "sourceSqlBetaGuardSettingsAreSynthetic": True, "durableAuthorityClaimed": False}
        self.identity = None
        self.epoch = None
        self.bootstrap = False
        self.baseline = None
        self.network_id = None
        self.pg_cid = None
        self.helpers = []
        self.rejections = []
        self.positive = []
        self.admin_control = False

    def persist(self):
        # This fixture is rebuildable/non-authority. Never impersonate a Linux
        # journal barrier or pass this state to the production profile producer.
        return save_state(Path(self.g["root"]) / "rehearsal-state.json", self.state)

    def verify_quiescence(self):
        self.guard()  # owned fixture isolation only; no claim about beta all22

    def database_url(self, command):
        selected = "verify-owned-schema" if self.bootstrap else "migrate" if self.admin_control else command
        return schema_url(read_ref(self.i["databaseAdminUrl"], 8192).read_text(), selected)

    def target_settings(self):
        value = {"marty.passport_beta_verified_project": "elevenid-beta",
            "marty.passport_beta_expected_system_identifier": self.identity["systemIdentifier"],
            "marty.passport_beta_expected_database_oid": self.identity["databaseOid"]}
        if self.epoch is not None:
            value.update({"marty.passport_beta_expected_fence_epoch": str(self.epoch),
                "marty.passport_beta_expected_source_commit": SOURCE,
                "marty.passport_beta_expected_native_migration_sha256": self.i["migrationSetSha256"]})
        return value

    def stage_intent(self, stage):
        self.stage = stage
        self.i["runId"] = self.i["stageIds"][stage]
        self.state.update(phase="REHEARSAL_PENDING", pendingStage=stage)
        self.persist()

    def guard(self):
        require(self.command(["docker", "info", "--format", "{{.ID}}"]).decode().strip() == ENGINE, "ENGINE_CHANGED")
        require(self.pg_cid is not None and self.pg_cid != "f37ec29f5810b5ec0564ed47658c092eb73ed68496044d155ea75549a375745d"
                and self.i["databaseNetwork"] == "marty-schema-rehearsal-" + self.fixture_run, "OWNED_FIXTURE_NOT_STARTED")
        row = json.loads(self.command(["docker", "inspect", self.pg_cid]))[0]
        require(row["Id"] == self.pg_cid and row["Image"] == PG_IMAGE
                and row["Config"]["Labels"].get("elevenid.owner") == OWNER
                and row["Config"]["Labels"].get("elevenid.run") == self.fixture_run
                and "com.docker.compose.project" not in row["Config"]["Labels"]
                and row["State"]["Running"] and not row["State"]["Paused"], "OWNED_PG_FIXTURE_CHANGED")
        require(set(row["NetworkSettings"]["Networks"]) == {self.i["databaseNetwork"]}
                and row["NetworkSettings"]["Networks"][self.i["databaseNetwork"]]["NetworkID"] == self.network_id,
                "FIXTURE_NETWORK_CHANGED")
        return row

    def fixture_psql(self, sql):
        self.guard()
        return self.command(["docker", "exec", "-i", self.pg_cid, "psql", "-X", "-U", "postgres", "-d", "marty", "-qAt", "-v", "ON_ERROR_STOP=1", "-f", "-"], input=sql.encode())

    def create_fixture(self):
        require(self.command(["docker", "info", "--format", "{{.ID}}"]).decode().strip() == ENGINE, "ENGINE_CHANGED")
        self.baseline = set(self.command(["docker", "ps", "-aq", "--no-trunc"]).decode().split())
        names = self.command(["docker", "ps", "-a", "--format", "{{.Names}}"]).decode().splitlines()
        require(self.i["postgresName"] not in names, "FIXTURE_CONTAINER_NAME_ALREADY_EXISTS")
        networks = self.command(["docker", "network", "ls", "--format", "{{.Name}}"]).decode().splitlines()
        require(self.i["databaseNetwork"] not in networks, "FIXTURE_NETWORK_NAME_ALREADY_EXISTS")
        self.state["pendingResource"] = "CREATE_INTERNAL_NETWORK"
        self.persist()
        self.network_id = self.command(["docker", "network", "create", "--internal", "--driver", "bridge",
            "--label", "elevenid.owner=" + OWNER, "--label", "elevenid.run=" + self.fixture_run,
            self.i["databaseNetwork"]]).decode().strip()
        require(len(self.network_id) == 64, "FIXTURE_NETWORK_CREATE_UNKNOWN")
        self.i["databaseNetworkId"] = self.network_id
        password = secrets.token_urlsafe(32)
        env = self.g["save_bytes"]("postgres.env.private", ("POSTGRES_DB=marty\nPOSTGRES_USER=postgres\nPOSTGRES_PASSWORD=" + password
            + "\nPGDATA=/var/lib/postgresql/data/owned-" + self.fixture_run + "\n").encode())
        admin = self.g["save_bytes"]("postgres-admin.url.private", ("postgres://postgres:" + password + "@postgres:5432/marty").encode())
        self.i["databaseAdminUrl"] = admin
        self.state["pendingResource"] = "CREATE_OWNED_POSTGRES"
        self.persist()
        self.pg_cid = self.command(["docker", "create", "--pull=never", "--name", self.i["postgresName"],
            "--network", self.i["databaseNetwork"], "--network-alias", "postgres", "--user", "postgres",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", "0.5",
            "--memory", "512m", "--memory-swap", "512m", "--env-file", env["path"],
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=268435456,mode=1777",
            "--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,size=16777216,mode=1777",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16777216,mode=1777",
            "--label", "elevenid.owner=" + OWNER, "--label", "elevenid.run=" + self.fixture_run, PG_IMAGE]).decode().strip()
        row = json.loads(self.command(["docker", "inspect", self.pg_cid]))[0]
        require(row["Id"] == self.pg_cid and row["Image"] == PG_IMAGE and row["State"]["Status"] == "created"
                and row["Config"]["User"] == "postgres" and not row["HostConfig"]["Privileged"]
                and row["HostConfig"]["Memory"] == 536870912 and row["HostConfig"]["NanoCpus"] == 500000000
                and row["HostConfig"]["ReadonlyRootfs"] and not row["HostConfig"].get("CapAdd")
                and {m["Type"] for m in row["Mounts"]} <= {"tmpfs"}
                and not row["HostConfig"].get("PortBindings"), "CREATED_PG_FIXTURE_REFUSED")
        image = json.loads(self.command(["docker", "image", "inspect", PG_IMAGE]))[0]
        wanted = environment(image["Config"].get("Env") or [])
        wanted.update(POSTGRES_DB="marty", POSTGRES_USER="postgres", POSTGRES_PASSWORD=password, PGDATA="/var/lib/postgresql/data/owned-" + self.fixture_run)
        require(row["Name"] == "/" + self.i["postgresName"] and row["Config"]["Labels"].get("elevenid.owner") == OWNER
                and row["Config"]["Labels"].get("elevenid.run") == self.fixture_run
                and row["HostConfig"]["NetworkMode"] == self.i["databaseNetwork"]
                and row["Config"]["Entrypoint"] == image["Config"]["Entrypoint"]
                and row["Config"]["Cmd"] == image["Config"]["Cmd"]
                and environment(row["Config"]["Env"]) == wanted, "OWNED_PG_CONFIGURATION_REFUSED_BEFORE_START")
        network = json.loads(self.command(["docker", "network", "inspect", self.network_id]))[0]
        require(network["Id"] == self.network_id and network["Internal"] and network["Labels"]["elevenid.owner"] == OWNER,
                "CREATED_INTERNAL_NETWORK_REFUSED")
        self.g["save"]("postgres-created.json", row)
        require(set(row["HostConfig"].get("Tmpfs") or {}) == {"/var/lib/postgresql/data", "/var/run/postgresql", "/tmp"}
                and row["HostConfig"]["MemorySwap"] == 536870912
                and {x.removeprefix("CAP_") for x in row["HostConfig"].get("CapDrop") or []} == {"ALL"}
                and row["HostConfig"].get("SecurityOpt") in (["no-new-privileges"], ["no-new-privileges:true"])
                and "com.docker.compose.project" not in row["Config"]["Labels"], "FIXTURE_ISOLATION_REFUSED_BEFORE_START")
        self.state.update(pgContainerId=self.pg_cid, networkId=self.network_id, pendingResource="START_OWNED_POSTGRES")
        self.persist()
        self.command(["docker", "start", self.pg_cid])
        self.command(["docker", "exec", self.pg_cid, "sh", "-c",
            "i=0; while [ $i -lt 120 ]; do pg_isready -h 127.0.0.1 -p 5432 -U postgres -d marty && exit 0; i=$((i+1)); sleep 0.5; done; exit 1"])
        self.identity = json.loads(self.fixture_psql("SELECT json_build_object('databaseOid',(SELECT oid::text FROM pg_database WHERE datname='marty'),'systemIdentifier',(SELECT system_identifier::text FROM pg_control_system()));"))
        self.identity["containerId"] = self.pg_cid
        self.fixture_psql("CREATE ROLE marty LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT; ALTER DATABASE marty OWNER TO marty;")

    def sql_stage(self, stage, name, *, transition=None):
        self.stage_intent(stage)
        row = self.sql(name, transition=transition)
        self.g["save"]("sql-receipt.json", row)
        return row

    def schema_stage(self, stage, role, command, *, expect_failure=False, bootstrap=False, admin_control=False):
        self.stage_intent(stage)
        self.bootstrap = bootstrap
        self.admin_control = admin_control
        try:
            row = self.schema(role, command)
        except ValueError:
            require(expect_failure and self.state.get("pendingContainerId"), "UNEXPECTED_SCHEMA_FAILURE")
            cid = self.state["pendingContainerId"]
            diagnostic = Path(self.g["root"]) / (self.stage + "-database-command-" + str(self.command_index) + ".stderr")
            expected = "fenced physical start intent access is incomplete" if role == "flow" else "fenced passport application requires marty append-only cancellation access"
            require(expected in diagnostic.read_text(encoding="utf-8", errors="replace").lower(), "EXPECTED_ACL_OR_ROLE_DENIAL_NOT_OBSERVED")
            self.validate_schema(cid, created=False, expected_exit=1)
            self.retire_schema_helper(cid, expected_exit=1)
            self.helpers.append(cid)
            self.rejections.append(stage)
            self.g["save"]("expected-rejection.json", {"containerId": cid, "expectedExitCode": 1, "actualTerminalVerified": True})
            return
        require(not expect_failure, "SCHEMA_NEGATIVE_CONTROL_UNEXPECTEDLY_SUCCEEDED")
        self.retire_schema_helper(row["containerId"])
        self.helpers.append(row["containerId"])
        self.positive.append(stage)
        self.g["save"]("schema-receipt.json", row)

    def run(self):
        self.create_fixture()
        self.schema_stage("bootstrap-flow", "flow", "migrate", bootstrap=True)
        self.schema_stage("bootstrap-issuer", "issuance-native", "migrate", bootstrap=True)
        self.sql_stage("install", "passport-beta-fence-install.sql")
        row = self.sql_stage("fence", "passport-beta-fence-verify.sql")
        self.epoch = self.node("json", stdout=row["stdout"], schema="marty.passport-beta-fence-verification/v1")["epoch"]
        self.sql_stage("maintenance", "passport-beta-db-maintenance-start.sql")
        self.schema_stage("migrate-flow", "flow", "migrate")
        self.schema_stage("migrate-issuer", "issuance-native", "migrate")
        self.schema_stage("reject-flow-before-acl", "flow", "verify-owned-schema", expect_failure=True)
        self.schema_stage("reject-issuer-before-acl", "issuance-native", "verify-owned-schema", expect_failure=True)
        self.sql_stage("acl", "passport-beta-batch-acl-finalize.sql")
        self.schema_stage("verify-flow", "flow", "verify-owned-schema")
        self.schema_stage("verify-issuer", "issuance-native", "verify-owned-schema")
        # A privileged session must not substitute for the application's guard.
        self.schema_stage("reject-admin-issuer", "issuance-native", "verify-owned-schema", expect_failure=True, admin_control=True)
        self.sql_stage("attest", "passport-beta-native-attestation.sql")
        self.sql_stage("login", "passport-beta-db-enable-app-login.sql")
        row = self.sql_stage("owner", "passport-beta-rust-owner-transition.sql")
        txid = self.node("json", stdout=row["stdout"], schema="marty.passport-beta-rust-owner-transition/v1")["transition_txid"]
        self.sql_stage("owner-verify", "passport-beta-rust-owner-verify.sql", transition=txid)
        require(self.rejections == ["reject-flow-before-acl", "reject-issuer-before-acl", "reject-admin-issuer"]
                and len(self.positive) == 6 and len(set(self.helpers)) == 9, "EXACT_SCHEMA_REHEARSAL_ASSERTIONS_REQUIRED")
        self.guard()
        self.state.update(phase="STOP_OWNED_FIXTURE", pendingResource="STOP_OWNED_POSTGRES")
        self.persist()
        self.command(["docker", "stop", "--signal", "SIGINT", "--timeout", "-1", self.pg_cid])
        row = json.loads(self.command(["docker", "inspect", self.pg_cid]))[0]
        require(row["State"]["Status"] == "exited" and row["State"]["ExitCode"] == 0 and not row["State"]["OOMKilled"], "PG_FIXTURE_NOT_CLEANLY_STOPPED")
        self.command(["docker", "rm", self.pg_cid])
        require(self.pg_cid not in self.command(["docker", "ps", "-aq", "--no-trunc"]).decode().split(), "PG_FIXTURE_STILL_REGISTERED")
        network = json.loads(self.command(["docker", "network", "inspect", self.network_id]))[0]
        require(not network["Containers"] and network["Labels"].get("elevenid.run") == self.fixture_run, "FIXTURE_NETWORK_HAS_CONSUMERS")
        require(self.command(["docker", "info", "--format", "{{.ID}}"]).decode().strip() == ENGINE, "ENGINE_CHANGED_BEFORE_REMOVAL")
        self.command(["docker", "network", "rm", self.network_id])
        require(self.network_id not in self.command(["docker", "network", "ls", "--no-trunc", "--format", "{{.ID}}"]).decode().split(), "FIXTURE_NETWORK_STILL_REGISTERED")
        remaining = set(self.command(["docker", "ps", "-aq", "--no-trunc"]).decode().split())
        require(remaining == self.baseline and not remaining.intersection(self.helpers), "BASELINE_OR_HELPER_ABSENCE_CHANGED")
        self.state.update(phase="SYNTHETIC_SCHEMA_REHEARSAL_PASSED", pendingResource=None,
            pgFixtureRemoved=True, ownedSchemaHelpersRemoved=True, helperContainerIds=self.helpers,
            expectedRejectedStages=self.rejections, positiveStages=self.positive, baselineIdsUnchanged=True,
            runtimeDeployed=False, releaseQualified=False, recordingQualified=False)
        self.persist()
        return self.state


def load(name, bound):
    path = read_ref(bound)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def validate_inputs(path, digest):
    require(ref(path)["sha256"] == digest, "REHEARSAL_INPUT_CHANGED")
    value = json.loads(Path(path).read_bytes())
    require(value["schema"] == SCHEMA and value["controllerSource"] == ref(Path(__file__))
            and value["sourceRevision"] == SOURCE and value["coreRevision"] == CORE,
            "EXACT_SYNTHETIC_SOURCE_SCOPE_REQUIRED")
    parsed = uuid.UUID(value["runId"])
    require(parsed.version == 4 and str(parsed) == value["runId"], "UUID4_REHEARSAL_RUN_REQUIRED")
    run_id = str(parsed)
    require(not set(value).intersection({"databaseBefore", "baseProfile", "beforeBinding", "runtimeProfile", "quiescence"}), "BETA_CONTEXT_FORBIDDEN_IN_REHEARSAL")
    root = Path(value["privateRoot"])
    require(root.name == "native-schema-rehearsal-" + run_id and root.is_dir() and not root.is_symlink(), "OWNED_REHEARSAL_ROOT_REQUIRED")
    require(value["postgresName"] == "marty-schema-rehearsal-" + run_id
            and value["databaseNetwork"] == "marty-schema-rehearsal-" + run_id,
            "EXACT_FRESH_RESOURCE_NAMES_REQUIRED")
    require(set(value["stageIds"]) == set(STAGES) and len(set(value["stageIds"].values())) == len(STAGES), "EXACT_SYNTHETIC_STAGES_REQUIRED")
    require(all(uuid.UUID(v).version == 4 and str(uuid.UUID(v)) == v and v != run_id for v in value["stageIds"].values()), "UUID4_STAGES_REQUIRED")
    require(value["buildReceipt"]["sha256"] == BUILD_RECEIPT_SHA, "ACTUAL_BFAD_BUILD_RECEIPT_REQUIRED")
    receipt = json.loads(read_ref(value["buildReceipt"]).read_bytes())
    require(receipt["state"] == "PASSED" and receipt["source"] == SOURCE and receipt["coreRevision"] == CORE,
            "ACTUAL_BFAD_SOURCE_REQUIRED")
    for role in ("flow", "issuance-native"):
        bound = value["binaries"][role]
        require(bound == receipt["binaries"][ROLE_BINARIES[role]], "ACTUAL_SCHEMA_ELF_REQUIRED")
        read_ref(bound, 512 * 1024 * 1024)
    require(set(value["migrationSources"]) == {"rust/services/" + name + ".sql" for name in MIGRATIONS}, "EXACT_RUST_MIGRATION_SOURCES_REQUIRED")
    expected_files = set(OPERATOR_FILES) | {"scripts/sql/" + name for name in operational_sql_sources()} | set(value["migrationSources"])
    require(set(value["operatorFiles"]) == expected_files, "COMPLETE_EXECUTED_SOURCE_CLOSURE_REQUIRED")
    producer = Path(value["producerRepository"])
    require(git(producer, "remote", "get-url", "origin").decode().strip() == "https://github.com/ElevenID/marty-ui.git", "CANONICAL_PRODUCER_REQUIRED")
    for name, item in value["operatorFiles"].items():
        raw = read_ref(item).read_bytes()
        if name == "scripts/rehearse_native_schema_commands.py" and DISPATCH_ENABLED:
            require(raw.count(b"DISPATCH_ENABLED = True") == 1, "ONLY_DISPATCH_FLAG_MAY_CHANGE")
            raw = raw.replace(b"DISPATCH_ENABLED = True", b"DISPATCH_ENABLED = False", 1)
        require(raw == git(producer, "show", value["producerRevision"] + ":" + name), "REHEARSAL_OPERATOR_GIT_BLOB_CHANGED")
    require(set(value["guardModules"]) == {"beta_haip_guard", "beta_private_acl", "beta_operation_lock"}, "EXACT_EXISTING_GUARDS_REQUIRED")
    for item in value["guardModules"].values():
        read_ref(item)
    for item in value["guardFiles"].values():
        read_ref(item)
    for item in value["executables"].values():
        read_ref(item, 512 * 1024 * 1024)
    require(set(value["sqlSources"]) == set(operational_sql_sources()), "CLOSED_OPERATIONAL_SQL_SET_REQUIRED")
    for name, expected in operational_sql_sources().items():
        require(value["sqlSources"][name]["sha256"] == expected, "FIXED_SQL_SOURCE_CHANGED")
        read_ref(value["sqlSources"][name])
    require(value["metadataModule"] == value["operatorFiles"]["tests/scripts/native-maintenance-metadata.js"], "METADATA_GIT_BINDING_REQUIRED")
    for name, digest in value["dockerConfigFiles"].items():
        require(ref(Path(value["dockerConfig"]) / name)["sha256"] == digest, "FROZEN_DOCKER_CONTEXT_CHANGED")
    program = "const fs=require('node:fs');process.stdout.write(require(process.argv[1]).migrationDigest(JSON.parse(fs.readFileSync(0))))"
    observed = bounded_run([value["executables"]["node"]["path"], "-e", program, value["metadataModule"]["path"]],
        env=closed_environment(value), input=json.dumps(value["migrationSources"]).encode(), timeout=20, stdout_limit=4096)
    require(observed.returncode == 0 and not observed.observation["failures"] and not observed.observation["timedOut"]
            and observed.stdout.decode() == value["migrationSetSha256"], "EXACT_SOURCE_MIGRATION_DIGEST_REQUIRED")
    return value


def closed_environment(inputs):
    env = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "COMSPEC", "PATHEXT"}}
    env.update(PATH=";".join([str(Path(inputs["executables"]["docker"]["path"]).parent), "C:/Windows/System32"]),
        DOCKER_CONFIG=inputs["dockerConfig"], DOCKER_CONTEXT="desktop-linux")
    return env


def context_for(path, digest, inputs):
    root = Path(inputs["privateRoot"])
    modules = {name: load(name, inputs["guardModules"][name]) for name in ("beta_haip_guard", "beta_private_acl", "beta_operation_lock")}
    modules["beta_private_acl"].private_acl(root, "v258", initialize=False)
    env = closed_environment(inputs)
    active = {}
    def save_bytes(name, data):
        require(Path(name).name == name, "PRIVATE_BASENAME_REQUIRED")
        prefix = active["operator"].stage if "operator" in active else "prepare"
        output = root / (prefix + "-" + name)
        with output.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return ref(output)
    def save(name, value):
        return save_bytes(name, (json.dumps(value, indent=2) + "\n").encode())
    def assert_inputs(**kwargs):
        # The mutable in-memory fixture IDs never alter the frozen input file.
        require(ref(path)["sha256"] == digest, "REHEARSAL_INPUT_CHANGED")
        for item in inputs["operatorFiles"].values():
            read_ref(item)
        for item in inputs["executables"].values():
            read_ref(item, 512 * 1024 * 1024)
        for item in [*inputs["guardModules"].values(), *inputs["guardFiles"].values()]:
            read_ref(item)
    context = {"root": root, "save": save, "save_bytes": save_bytes, "ref": ref, "env": env,
        "assert_inputs": assert_inputs, "nodeExecutable": inputs["executables"]["node"]["path"]}
    operator = Rehearsal(context, deepcopy(inputs))
    active["operator"] = operator
    return modules, context, operator


def capacity(context, inputs):
    command = "$o=Get-CimInstance Win32_OperatingSystem;[long]$o.FreePhysicalMemory*1024"
    result = bounded_run([inputs["executables"]["powershell"]["path"], "-NoProfile", "-NonInteractive", "-Command", command], env=context["env"], timeout=20, stdout_limit=4096)
    require(result.returncode == 0 and not result.observation["failures"] and not result.observation["timedOut"], "PHYSICAL_CAPACITY_UNKNOWN")
    free = int(result.stdout.decode().strip())
    require(free >= 4 * 1024 ** 3, "PHYSICAL_4GIB_REQUIRED")
    return free


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "run"))
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--inputs-sha256", required=True)
    args = parser.parse_args()
    inputs = validate_inputs(args.inputs, args.inputs_sha256)
    if args.mode == "check":
        print(json.dumps({"state": "SYNTHETIC_REHEARSAL_INPUTS_CHECKED", "dispatchEnabled": DISPATCH_ENABLED, "dockerDispatched": False}))
        return
    require(DISPATCH_ENABLED, "REHEARSAL_DISPATCH_DISABLED")
    modules, context, operator = context_for(args.inputs, args.inputs_sha256, inputs)
    with modules["beta_operation_lock"].operation_lock(LOCK, "native-schema-rehearsal-" + inputs["runId"]):
        require(not (Path(inputs["privateRoot"]) / "rehearsal-state.json").exists(), "REHEARSAL_ALREADY_CONSUMED_NO_RETRY")
        require(not (Path(inputs["privateRoot"]) / "prepare-invocation.json").exists(), "REHEARSAL_INVOCATION_ALREADY_CONSUMED")
        context["save"]("invocation.json", {"inputsSha256": args.inputs_sha256, "ownedPid": os.getpid(), "betaDatabaseAccessed": False})
        try:
            capacity(context, inputs)
            output = operator.run()
            result = context["save"]("result.json", output)
            print(json.dumps({"state": output["phase"], "result": result, "betaDatabaseAccessed": False, "runtimeDeployed": False}))
        except BaseException as error:
            context["save"]("failure.json", {"errorClass": type(error).__name__, "state": operator.state,
                "ownedPostgresId": operator.pg_cid, "ownedNetworkId": operator.network_id,
                "noRetry": True, "betaDatabaseAccessed": False})
            print(json.dumps({"state": "REHEARSAL_FAILED_RECONCILIATION_REQUIRED", "errorClass": type(error).__name__}))
            raise SystemExit(1)


if __name__ == "__main__":
    main()
