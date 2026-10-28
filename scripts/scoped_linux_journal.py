"""D02-only durable metadata store; never executes Docker, Cargo or a shell."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types
import uuid

HOME = Path("/home/canvasrunner")
UUID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}")
MAXIMUM = 256 * 1024
FILES = {"build-apply-intent.json", "build-state.json", "build-receipt.json"}


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(file):
    with Path(file).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def root_path(run_id):
    require(isinstance(run_id, str) and UUID.fullmatch(run_id), "JOURNAL_RUN_INVALID")
    return HOME / ".codex/private" / ("d02-build-journal-" + run_id)


def validate_root(proof, run_id):
    require(isinstance(proof, dict) and set(proof) == {"root", "device", "inode", "uid", "mode"}, "JOURNAL_ROOT_PROOF_INVALID")
    require(proof["root"] == str(root_path(run_id)) and proof["uid"] == 1000 and proof["mode"] == 0o700,
            "JOURNAL_ROOT_SCOPE_CHANGED")
    require(all(type(proof[k]) is int and proof[k] > 0 for k in ("device", "inode", "uid", "mode")), "JOURNAL_ROOT_IDENTITY_INVALID")


def validate_request(request):
    require(isinstance(request, dict) and set(request) == {"schema", "runId", "operation", "name", "value", "rootProof", "workerSha256", "sharedSha256"}, "JOURNAL_REQUEST_SCHEMA")
    require(request["schema"] == 1 and isinstance(request["runId"], str) and UUID.fullmatch(request["runId"]), "JOURNAL_REQUEST_RUN")
    operation, name = request["operation"], request["name"]
    require(isinstance(operation, str) and operation in {"initialize", "exclusive", "state", "read"}, "JOURNAL_OPERATION_REFUSED")
    require(all(isinstance(request[k], str) and re.fullmatch(r"[a-f0-9]{64}", request[k]) for k in ("workerSha256", "sharedSha256")), "JOURNAL_SOURCE_REQUIRED")
    if operation == "initialize":
        require(name is None and request["value"] is None and request["rootProof"] is None, "JOURNAL_INITIALIZATION_SCHEMA")
    else:
        validate_root(request["rootProof"], request["runId"])
        require(name in FILES, "JOURNAL_FILENAME_REFUSED")
        require(operation != "state" or name == "build-state.json", "JOURNAL_STATE_FILENAME_REFUSED")
        require(operation != "exclusive" or name != "build-state.json", "JOURNAL_EXCLUSIVE_FILENAME_REFUSED")
        require(request["value"] is None if operation == "read" else isinstance(request["value"], dict), "JOURNAL_VALUE_SCHEMA")


def actual_root(proof, run_id):
    validate_root(proof, run_id)
    root = root_path(run_id)
    info = root.lstat()
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root, "JOURNAL_ROOT_LINK")
    require((info.st_dev, info.st_ino, info.st_uid, info.st_mode & 0o777) ==
            (proof["device"], proof["inode"], 1000, 0o700), "JOURNAL_ROOT_REPLACED")
    return root


def worker(request_file, expected_sha):
    require(os.name == "posix" and os.getuid() == 1000 and Path.home() == HOME, "JOURNAL_LINUX_OWNER")
    request_file = Path(request_file)
    require(request_file.is_relative_to(Path("/mnt/c/Users/maree/.codex/private")) and
            request_file.resolve() == request_file and request_file.is_file() and not request_file.is_symlink(), "JOURNAL_REQUEST_PATH")
    with request_file.open("rb") as stream:
        raw = stream.read(MAXIMUM + 1)
    require(0 < len(raw) <= MAXIMUM and hashlib.sha256(raw).hexdigest() == expected_sha, "JOURNAL_REQUEST_CHANGED")
    request = json.loads(raw)
    validate_request(request)
    source = Path(__file__)
    shared_file = source.with_name("scoped_native_runtime.py")
    shared_bytes = shared_file.read_bytes()
    require(sha(source) == request["workerSha256"] and hashlib.sha256(shared_bytes).hexdigest() == request["sharedSha256"], "JOURNAL_SOURCE_CHANGED")
    shared = types.ModuleType("reviewed_journal_shared")
    shared.__file__ = str(shared_file)
    exec(compile(shared_bytes, str(shared_file), "exec"), shared.__dict__)
    if request["operation"] == "initialize":
        root = root_path(request["runId"])
        parent = root.parent
        require(parent.resolve() == parent and parent.is_dir() and parent.stat().st_uid == 1000 and
                parent.stat().st_mode & 0o777 == 0o700, "JOURNAL_PRIVATE_PARENT")
        root.mkdir(mode=0o700)
        barrier = shared.sync_parent(root)
        require(barrier.get("supported") is True and barrier.get("synced") is True, "JOURNAL_BOOTSTRAP_BARRIER")
        info = root.stat()
        proof = {"root": str(root), "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "mode": info.st_mode & 0o777}
        validate_root(proof, request["runId"])
        return {"ok": True, "rootProof": proof, "bootstrapParent": barrier}
    root = actual_root(request["rootProof"], request["runId"])
    target = root / request["name"]
    operation = request["operation"]
    if operation == "exclusive":
        barrier = shared.save_exclusive(target, request["value"])
    elif operation == "state":
        require(not target.is_symlink(), "JOURNAL_TARGET_LINK")
        if target.exists():
            require(target.is_file() and not target.is_symlink(), "JOURNAL_TARGET_LINK")
        barrier = shared.save_state(target, request["value"])
    else:
        require(target.is_file() and not target.is_symlink() and target.stat().st_size <= MAXIMUM, "JOURNAL_READ_TARGET")
        barrier = None
    require(operation == "read" or shared.durable_barrier(barrier), "JOURNAL_WRITE_BARRIER")
    require(target.is_file() and not target.is_symlink(), "JOURNAL_TARGET_CHANGED")
    value = json.loads(target.read_bytes())
    require(operation == "read" or value == request["value"], "JOURNAL_REOPEN_CHANGED")
    return {"ok": True, "rootProof": request["rootProof"], "name": request["name"],
            "sha256": sha(target), "value": value, "barrier": barrier}


def client_path(file):
    text = str(Path(file).resolve()).replace("\\", "/")
    require(text.startswith("C:/Users/maree/.codex/private/") or text.startswith("C:/Users/maree/OneDrive/Glthub/marty-workspace/"), "JOURNAL_CLIENT_PATH_REFUSED")
    require(not re.search(r"[\x00-\x1f\x7f]", text) and all(p not in {".", ".."} for p in text.split("/")), "JOURNAL_CLIENT_PATH_REFUSED")
    return "/mnt/c/" + text[3:]


class LinuxBuildJournal:
    def __init__(self, private, run_id, specification, *, initializing=False):
        require(os.name == "nt", "JOURNAL_WINDOWS_CONTROLLER_REQUIRED")
        self.private = Path(private).resolve()
        require(self.private.is_relative_to(Path.home() / ".codex/private") and self.private.is_dir() and not self.private.is_symlink()
                and not self.private.is_junction(), "JOURNAL_WINDOWS_PRIVATE_ROOT")
        self.run_id, self.specification = run_id, specification
        require(set(specification) == {"schema", "backend", "workerSha256", "sharedSha256", "rootProof", "bootstrapParent"}
                and specification["schema"] == 1 and specification["backend"] == "UBUNTU_PRIVATE_JOURNAL_V1", "JOURNAL_BACKEND_SCHEMA")
        require(specification["workerSha256"] == sha(Path(__file__)) and
                specification["sharedSha256"] == sha(Path(__file__).with_name("scoped_native_runtime.py")), "JOURNAL_BACKEND_SOURCE_CHANGED")
        if initializing:
            require(specification["rootProof"] is None and specification["bootstrapParent"] is None,
                    "JOURNAL_INITIALIZATION_SCHEMA")
            root_path(run_id)
        else:
            require(specification["bootstrapParent"].get("supported") is True and specification["bootstrapParent"].get("synced") is True, "JOURNAL_BOOTSTRAP_REQUIRED")
            validate_root(specification["rootProof"], run_id)

    def invoke(self, operation, name, value=None):
        require(not getattr(self, "pending", False) and not list(self.private.glob("linux-journal-request-*.json")),
                "LINUX_JOURNAL_PENDING_REQUEST_REQUIRES_RECONCILIATION")
        specification = self.specification
        request = {"schema": 1, "runId": self.run_id, "operation": operation, "name": name, "value": value,
                   "rootProof": specification["rootProof"], "workerSha256": specification["workerSha256"], "sharedSha256": specification["sharedSha256"]}
        validate_request(request)
        raw = encoded(request)
        require(len(raw) <= MAXIMUM, "JOURNAL_REQUEST_TOO_LARGE")
        file = self.private / ("linux-journal-request-" + str(uuid.uuid4()) + ".json")
        with file.open("xb") as stream:
            require(stream.write(raw) == len(raw), "JOURNAL_REQUEST_SHORT_WRITE")
            stream.flush()
            os.fsync(stream.fileno())
        self.pending = True
        args = ["C:/Windows/System32/wsl.exe", "--distribution", "Ubuntu-24.04", "--user", "canvasrunner",
                "--exec", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=/home/canvasrunner", "USER=canvasrunner", "LOGNAME=canvasrunner",
                "/usr/bin/python3", "-I", client_path(Path(__file__)), "--worker", client_path(file), hashlib.sha256(raw).hexdigest()]
        environment = {k: v for k, v in os.environ.items() if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "COMSPEC", "PATHEXT"}}
        try:
            result = subprocess.run(args, env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("LINUX_JOURNAL_OUTCOME_UNKNOWN_NO_RETRY") from error
        require(result.returncode == 0 and len(result.stdout) <= MAXIMUM and len(result.stderr) <= 4096, "LINUX_JOURNAL_REFUSED_RETAIN_REQUEST")
        response = json.loads(result.stdout)
        require(response.get("ok") is True, "LINUX_JOURNAL_RESPONSE_CHANGED")
        if operation == "initialize":
            validate_root(response.get("rootProof"), self.run_id)
            require(response.get("bootstrapParent", {}).get("supported") is True and
                    response.get("bootstrapParent", {}).get("synced") is True, "JOURNAL_BOOTSTRAP_REQUIRED")
        else:
            require(response.get("rootProof") == specification["rootProof"] and response.get("name") == name,
                    "LINUX_JOURNAL_RESPONSE_CHANGED")
            require(response.get("sha256") == hashlib.sha256(encoded(response.get("value"))).hexdigest(), "LINUX_JOURNAL_REOPEN_HASH_CHANGED")
        if operation not in {"read", "initialize"}:
            from scoped_native_runtime import durable_barrier, save_state
            require(response["value"] == value and durable_barrier(response.get("barrier", {})), "LINUX_JOURNAL_BARRIER_UNCONFIRMED")
            # Explicitly nonauthoritative Windows mirror, never directory-fsync proof.
            save_state(self.private / name.replace(".json", ".mirror.json"),
                       {"authority": "LINUX_PRIVATE_JOURNAL", "root": specification["rootProof"]["root"],
                        "authoritativeSha256": response["sha256"], "windowsDurabilityClaimed": False, "value": value})
        require(file.is_file() and not file.is_symlink() and sha(file) == hashlib.sha256(raw).hexdigest(), "JOURNAL_REQUEST_CUSTODY_CHANGED")
        file.unlink()
        self.pending = False
        return response

    def exclusive(self, name, value):
        return self.invoke("exclusive", name, value)["barrier"]

    def state(self, value):
        return self.invoke("state", "build-state.json", value)["barrier"]

    def read(self, name):
        return self.invoke("read", name)["value"]


def prepare_linux_journal(private, run_id, worker_sha256, shared_sha256):
    """File-only bootstrap. Freeze this returned specification before build review."""
    specification = {"schema": 1, "backend": "UBUNTU_PRIVATE_JOURNAL_V1", "workerSha256": worker_sha256,
                     "sharedSha256": shared_sha256, "rootProof": None, "bootstrapParent": None}
    store = LinuxBuildJournal(private, run_id, specification, initializing=True)
    response = store.invoke("initialize", None)
    return {**specification, "rootProof": response["rootProof"], "bootstrapParent": response["bootstrapParent"]}


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 4 and sys.argv[1] == "--worker", "JOURNAL_ENTRYPOINT_REFUSED")
        print(json.dumps(worker(sys.argv[2], sys.argv[3])))
    except BaseException as error:
        print(json.dumps({"ok": False, "code": "LINUX_JOURNAL_REFUSED", "kind": type(error).__name__}))
        sys.exit(1)
