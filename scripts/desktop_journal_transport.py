"""Explicit Desktop transport for the existing Linux metadata worker; no WSL fallback."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
from scoped_native_runtime import JOURNAL_FILES, JOURNAL_RESPONSE_MAXIMUM

ENGINE = "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341"
IMAGE = "sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1"
DOCKER = "C:/Program Files/Docker/Docker/resources/bin/docker.EXE"
DOCKER_SHA = "0f97bc1111f59d859766ba938691ee07ed4e58d5fdaeb6f4dfb10a5ef5394753"
PRIVATE_PARENT = "/home/canvasrunner/.codex/private"
OWNER = "d02-private-journal"


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(file):
    return hashlib.sha256(Path(file).read_bytes()).hexdigest()


def validate_spec(spec, run_id):
    require(set(spec) == {"docker", "configDirectory", "context", "engineId", "image", "volumeName", "transportSha256", "volumeProof"}, "DESKTOP_JOURNAL_SPEC_FIELDS")
    require(spec["docker"] == {"path": DOCKER, "sha256": DOCKER_SHA} and spec["engineId"] == ENGINE and spec["image"] == IMAGE and spec["context"] == "desktop-linux", "DESKTOP_JOURNAL_FROZEN_TRANSPORT")
    require(re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", run_id), "DESKTOP_JOURNAL_RUN_ID")
    require(spec["volumeName"] == "marty-d02-journal-" + run_id, "DESKTOP_JOURNAL_VOLUME_ALIAS")
    require(re.fullmatch(r"[a-f0-9]{64}", spec["transportSha256"]), "DESKTOP_JOURNAL_SOURCE_PIN")


def exact_capabilities(values, expected):
    values = values or []
    require(isinstance(values, list) and all(isinstance(v, str) for v in values), "DESKTOP_JOURNAL_CAPABILITY_SHAPE")
    normalized = [value.removeprefix("CAP_") for value in values]
    require(len(set(normalized)) == len(normalized) and set(normalized) == set(expected), "DESKTOP_JOURNAL_CAPABILITY_SCOPE")


def exact_security_options(values):
    require(values in (["no-new-privileges"], ["no-new-privileges:true"]), "DESKTOP_JOURNAL_SECURITY_SCOPE")


def helper_arguments(spec, run_id, name, command, readonly_files=(), *, root_setup=False):
    validate_spec(spec, run_id)
    require(name.startswith("d02-journal-" + run_id + "-"), "DESKTOP_JOURNAL_HELPER_ALIAS")
    args = ["create", "--name", name, "--label", "elevenid.owner=" + OWNER, "--label", "elevenid.run=" + run_id,
            "--network", "none", "--memory", "64m", "--memory-swap", "64m", "--cpus", ".25", "--pids-limit", "16",
            "--read-only", "--pull=never", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "0:0" if root_setup else "1000:1000"]
    if root_setup:
        require(not readonly_files, "ROOT_SETUP_MUST_NOT_MOUNT_HOST_FILES")
        args += ["--cap-add", "CHOWN"]
    else:
        require(len(readonly_files) == 3 and {row["role"] for row in readonly_files} == {"worker", "shared", "request"}, "EXACT_THREE_READONLY_WORKER_FILES")
    args += ["--mount", "type=volume,src=" + spec["volumeName"] + ",dst=" + PRIVATE_PARENT]
    for row in readonly_files:
        require(set(row) == {"role", "path", "alias", "sha256"} and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]), "DESKTOP_WORKER_FILE_SCHEMA")
        require(row["alias"].startswith("/mnt/c/Users/maree/.codex/private/") and not re.search(r"[\x00-\x1f\x7f,]", row["path"] + row["alias"]), "DESKTOP_WORKER_FILE_SCOPE")
        require(all(part not in (".", "..") for part in row["alias"].split("/")), "DESKTOP_WORKER_ALIAS_TRAVERSAL")
        args += ["--mount", "type=bind,src=" + row["path"] + ",dst=" + row["alias"] + ",readonly"]
    return [*args, "--entrypoint", "/usr/bin/env", IMAGE, "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/canvasrunner",
            "USER=canvasrunner", "LOGNAME=canvasrunner", *command]


class DesktopPrivateJournalTransport:
    def __init__(self, private, run_id, spec):
        require(os.name == "nt", "DESKTOP_JOURNAL_WINDOWS_CONTROLLER")
        validate_spec(spec, run_id)
        self.private, self.run_id, self.spec = Path(private).resolve(), run_id, spec
        require(sha(__file__) == spec["transportSha256"] and sha(DOCKER) == DOCKER_SHA, "DESKTOP_JOURNAL_EXECUTABLE_CHANGED")
        context = Path(spec["configDirectory"]).resolve()
        require(context == self.private / "docker-config" and context.is_dir(), "DESKTOP_JOURNAL_PRIVATE_CONTEXT")
        paths = list(context.rglob("*"))
        require(all(not p.is_symlink() and not p.is_junction() for p in paths), "DESKTOP_JOURNAL_CONTEXT_LINK")
        files = [p for p in paths if p.is_file()]
        metas = list((context / "contexts/meta").glob("*/meta.json"))
        require(len(metas) == 1, "DESKTOP_JOURNAL_CONTEXT_SET")
        metadata = json.loads(metas[0].read_bytes())
        require(metadata["Name"] == "desktop-linux" and set(metadata["Endpoints"]) == {"docker"} and metadata["Endpoints"]["docker"] == {"Host": "npipe:////./pipe/dockerDesktopLinuxEngine", "SkipTLSVerify": False}, "DESKTOP_JOURNAL_CONTEXT_ENDPOINT")
        for file in files:
            if file == metas[0]:
                continue
            require(file == context / "config.json", "DESKTOP_JOURNAL_CONTEXT_EXTRA")
            data = json.loads(file.read_bytes())
            require(not any(data.get(k) for k in ("auths", "proxies", "credsStore", "credHelpers")), "DESKTOP_JOURNAL_CONTEXT_AUTHORITY")
        self.context_hashes = {str(p): sha(p) for p in files}
        self.base = [DOCKER, "--config", str(context), "--context", "desktop-linux"]
        self.env = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "COMSPEC", "PATHEXT"}}
        self.env["PATH"] = "C:/Program Files/Docker/Docker/resources/bin;C:/Windows/System32"

    def _record(self, role, value):
        file = self.private / ("desktop-journal-" + role + "-" + str(uuid.uuid4()) + ".private.json")
        with file.open("xb") as stream:
            raw = (json.dumps(value, indent=2) + "\n").encode()
            require(stream.write(raw) == len(raw), "DESKTOP_JOURNAL_RECORD_SHORT_WRITE")
            stream.flush()
            os.fsync(stream.fileno())

    def _command(self, args, timeout=20, check=True):
        require(sha(DOCKER) == DOCKER_SHA and all(sha(p) == h for p, h in self.context_hashes.items()), "DESKTOP_JOURNAL_TRANSPORT_CHANGED")
        if getattr(self, "deadline", None) is not None:
            remaining = self.deadline - time.monotonic()
            require(remaining > 0, "DESKTOP_JOURNAL_HELPER_OUTCOME_UNKNOWN_NO_RETRY")
            timeout = min(timeout, remaining)
        result = subprocess.run([*self.base, *args], env=self.env, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        require(len(result.stdout) <= JOURNAL_RESPONSE_MAXIMUM and len(result.stderr) <= 64 * 1024, "DESKTOP_JOURNAL_RESPONSE_BOUND")
        require(not check or result.returncode == 0, "DESKTOP_JOURNAL_COMMAND_NONZERO")
        return result

    def _engine(self):
        require(self._command(["info", "--format", "{{.ID}}"]).stdout.decode().strip() == ENGINE, "DESKTOP_JOURNAL_ENGINE_CHANGED")
        image = json.loads(self._command(["image", "inspect", IMAGE]).stdout)[0]
        require(image["Id"] == IMAGE and image["Architecture"] == "amd64" and image["Os"] == "linux" and not image["Config"].get("Volumes"), "DESKTOP_JOURNAL_IMAGE_CHANGED")

    def _volume(self):
        row = json.loads(self._command(["volume", "inspect", self.spec["volumeName"]]).stdout)[0]
        require(row["Name"] == self.spec["volumeName"] and row["Driver"] == "local" and row["Scope"] == "local" and not row.get("Options"), "DESKTOP_JOURNAL_VOLUME_DRIVER")
        require(row["Labels"] == {"elevenid.owner": OWNER, "elevenid.run": self.run_id}, "DESKTOP_JOURNAL_VOLUME_OWNER")
        proof = {k: row[k] for k in ("Name", "Driver", "Scope", "CreatedAt", "Labels", "Mountpoint")}
        if self.spec["volumeProof"] is not None:
            require(proof == self.spec["volumeProof"], "DESKTOP_JOURNAL_VOLUME_REPLACED")
        return proof

    def _consumers(self):
        return self._command(["ps", "-aq", "--no-trunc", "--filter", "volume=" + self.spec["volumeName"]]).stdout.decode().split()

    def _helper(self, command, readonly_files=(), *, root_setup=False):
        self.deadline = time.monotonic() + 60
        self._engine()
        self._volume()
        require(not self._consumers(), "DESKTOP_JOURNAL_FOREIGN_OR_UNRECONCILED_CONSUMER")
        nonce = str(uuid.uuid4())
        name = "d02-journal-" + self.run_id + "-" + nonce
        args = helper_arguments(self.spec, self.run_id, name, command, readonly_files, root_setup=root_setup)
        self._record("helper-intent", {"name": name, "argsSha256": hashlib.sha256(json.dumps(args).encode()).hexdigest(), "rootSetup": root_setup, "parentDirectoryDurabilityClaimed": False})
        cid = self._command(args).stdout.decode().strip()
        require(re.fullmatch(r"[a-f0-9]{64}", cid), "DESKTOP_JOURNAL_CREATED_ID")
        row = json.loads(self._command(["inspect", cid]).stdout)[0]
        host = row["HostConfig"]
        require(row["Id"] == cid and row["Name"] == "/" + name and row["Image"] == IMAGE and row["Config"]["Labels"]["elevenid.owner"] == OWNER and row["Config"]["Labels"]["elevenid.run"] == self.run_id, "DESKTOP_JOURNAL_HELPER_IDENTITY")
        require(row["Config"]["User"] == ("0:0" if root_setup else "1000:1000") and row["Config"]["Entrypoint"] == ["/usr/bin/env"] and row["Config"]["Cmd"] == args[args.index(IMAGE) + 1:], "DESKTOP_JOURNAL_HELPER_COMMAND")
        require(host["NetworkMode"] == "none" and host["Memory"] == host["MemorySwap"] == 67108864 and host["NanoCpus"] == 250000000 and host["PidsLimit"] == 16 and host["ReadonlyRootfs"] is True and host["Privileged"] is False  , "DESKTOP_JOURNAL_HELPER_LIMITS")
        exact_capabilities(host["CapDrop"], {"ALL"})
        exact_capabilities(host["CapAdd"], {"CHOWN"} if root_setup else set())
        exact_security_options(host["SecurityOpt"])
        require(self._consumers() == [cid], "DESKTOP_JOURNAL_CONCURRENT_CONSUMER")
        mounts = row["Mounts"]
        require(len(mounts) == 1 + len(readonly_files), "DESKTOP_JOURNAL_HELPER_MOUNT_COUNT")
        volume = [m for m in mounts if m["Type"] == "volume"]
        require(len(volume) == 1 and volume[0]["Name"] == self.spec["volumeName"] and volume[0]["Destination"] == PRIVATE_PARENT and volume[0]["RW"] is True and volume[0]["Source"] == self.spec["volumeProof"]["Mountpoint"], "DESKTOP_JOURNAL_HELPER_VOLUME")
        for source in readonly_files:
            require(sha(source["path"]) == source["sha256"], "DESKTOP_JOURNAL_WORKER_SOURCE_CHANGED")
            match = [m for m in mounts if m["Destination"] == source["alias"]]
            require(len(match) == 1 and match[0]["Type"] == "bind" and match[0]["RW"] is False, "DESKTOP_JOURNAL_HELPER_READONLY_FILE")
            host_source = source["path"].replace("\\", "/")
            require(host_source.startswith("C:/Users/maree/.codex/private/") and match[0]["Source"] == "/run/desktop/mnt/host/c/" + host_source[3:], "DESKTOP_JOURNAL_HELPER_HOST_SOURCE")
        self._record("created", {"containerId": cid, "name": name, "mounts": mounts, "rootSetup": root_setup})
        self._command(["start", cid])
        deadline = time.monotonic() + 30
        while True:
            row = json.loads(self._command(["inspect", cid]).stdout)[0]
            require(row["Id"] == cid and row["Image"] == IMAGE and row["Config"]["Labels"]["elevenid.run"] == self.run_id, "DESKTOP_JOURNAL_HELPER_REPLACED")
            if not row["State"]["Running"]:
                break
            require(time.monotonic() < deadline, "DESKTOP_JOURNAL_HELPER_OUTCOME_UNKNOWN_NO_RETRY")
            time.sleep(.1)
        result = self._command(["logs", cid], check=False)
        self._record("terminal", {"containerId": cid, "exitCode": row["State"]["ExitCode"], "oomKilled": row["State"]["OOMKilled"], "logsCommandExitCode": result.returncode, "stdout": result.stdout.decode("utf8", errors="replace"), "stderr": result.stderr.decode("utf8", errors="replace")})
        self._engine()
        self._volume()
        fresh = json.loads(self._command(["inspect", cid]).stdout)[0]
        require(fresh["Id"] == cid and fresh["Name"] == "/" + name and fresh["Image"] == IMAGE and fresh["Config"]["Labels"]["elevenid.owner"] == OWNER and fresh["Config"]["Labels"]["elevenid.run"] == self.run_id, "DESKTOP_JOURNAL_CLEANUP_IDENTITY")
        require(fresh["State"]["Status"] == "exited" and not fresh["State"]["Running"] and not fresh["State"]["OOMKilled"] and fresh["State"]["ExitCode"] == row["State"]["ExitCode"], "DESKTOP_JOURNAL_CLEANUP_TERMINAL_REQUIRED")
        require(self._consumers() == [cid], "DESKTOP_JOURNAL_CLEANUP_CONSUMER_SCOPE")
        require(self._command(["rm", cid]).stdout.decode().strip() == cid, "DESKTOP_JOURNAL_HELPER_CLEANUP_UNKNOWN")
        require(not self._command(["ps", "-aq", "--no-trunc", "--filter", "id=" + cid]).stdout.strip() and not self._consumers(), "DESKTOP_JOURNAL_HELPER_ABSENCE_UNCONFIRMED")
        self._record("retired", {"containerId": cid, "removed": True, "consumersAfter": []})
        self.deadline = None
        return subprocess.CompletedProcess(args, row["State"]["ExitCode"], result.stdout, result.stderr)

    def prepare_volume(self):
        self._engine()
        existing = self._command(["volume", "ls", "--format", "{{.Name}}"]).stdout.decode().split()
        require(self.spec["volumeName"] not in existing, "DESKTOP_JOURNAL_VOLUME_EXISTS_NO_RETRY")
        intent = self.private / "desktop-journal-bootstrap-intent.private.json"
        with intent.open("xb") as stream:
            stream.write((json.dumps({"volumeName": self.spec["volumeName"], "runId": self.run_id, "scope": "NEW_METADATA_VOLUME_ONLY", "windowsParentDurabilityClaimed": False}) + "\n").encode());stream.flush();os.fsync(stream.fileno())
        require(self._command(["volume", "create", "--driver", "local", "--label", "elevenid.owner=" + OWNER, "--label", "elevenid.run=" + self.run_id, self.spec["volumeName"]]).stdout.decode().strip() == self.spec["volumeName"], "DESKTOP_JOURNAL_VOLUME_CREATE_UNKNOWN")
        self.spec["volumeProof"] = self._volume()
        code = "import os,json,stat;p='/home/canvasrunner/.codex/private';f=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fchmod(f,0o700);os.fchown(f,1000,1000);os.fsync(f);s=os.fstat(f);print(json.dumps({'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode),'synced':True}));os.close(f)"
        result = self._helper(["/usr/bin/python3", "-I", "-c", code], root_setup=True)
        require(result.returncode == 0 and json.loads(result.stdout) == {"uid": 1000, "mode": 448, "synced": True}, "DESKTOP_JOURNAL_PARENT_OWNERSHIP")
        return self.spec["volumeProof"]

    def execute(self, request_file, request_sha, worker_file, shared_file, aliases):
        require(isinstance(self.spec["volumeProof"], dict), "DESKTOP_JOURNAL_VOLUME_PROOF_REQUIRED")
        for file in (request_file, worker_file, shared_file):
            file = Path(file)
            require(file.is_file() and not file.is_symlink() and file.resolve() == file and file.is_relative_to(self.private), "DESKTOP_JOURNAL_EXACT_PRIVATE_FILE_REQUIRED")
        readonly = [{"role": role, "path": str(file), "alias": aliases(file), "sha256": request_sha if role == "request" else sha(file)}
                    for role, file in (("worker", worker_file), ("shared", shared_file), ("request", request_file))]
        require(all(sha(row["path"]) == row["sha256"] for row in readonly), "DESKTOP_JOURNAL_REQUEST_CHANGED")
        request = json.loads(Path(request_file).read_bytes())
        operation, name = request.get("operation"), request.get("name")
        require(operation in {"initialize", "exclusive", "state", "read"}, "DESKTOP_JOURNAL_OPERATION_REFUSED")
        if operation == "initialize":
            require(name is None, "DESKTOP_JOURNAL_INITIALIZATION_NAME")
        else:
            require(name in JOURNAL_FILES, "DESKTOP_JOURNAL_FILENAME_REFUSED")
            require(operation != "state" or name == "build-state.json", "DESKTOP_JOURNAL_STATE_FILENAME_REFUSED")
            require(operation != "exclusive" or name != "build-state.json", "DESKTOP_JOURNAL_EXCLUSIVE_FILENAME_REFUSED")
        return self._helper(["/usr/bin/python3", "-I", aliases(worker_file), "--worker", aliases(request_file), request_sha], readonly)
