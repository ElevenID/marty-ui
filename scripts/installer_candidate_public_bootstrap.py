"""Acceptance-only guest bootstrap for an exact public GitHub release.

The controller transfers this fixed harness and signed grants, never release
payloads. Authenticate the public operator before its first execution. Failed
or uncertain attempts retain all private evidence and cannot be resumed here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

REPO = "ElevenID/marty-ui"
REPOSITORY_ID = "1140864197"
REF = "refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
ACCEPTANCE = ".github/workflows/installer-acceptance.yml"
PINS = {
    "gh": ("cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e", 41070752),
    "cosign": ("424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa", 145688404),
}
ASSETS = ("installer-inventory.json", "marty-deploy-linux-amd64")
SUFFIXES = ("", ".sigstore.json", ".provenance.jsonl")


def require(ok, reason="public candidate bootstrap refused"):
    if not ok:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def record(raw):
    require(0 < len(raw) <= 65536)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(type(value) is dict)
    return value


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def sha(value, length=64):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None)


def positive(value):
    require(type(value) is int and 0 < value < 2**53)


def private_directory(path):
    require(path.is_absolute() and path.resolve() == path)
    for item in (path, *path.parents):
        info = item.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
        require(info.st_uid in (0, os.geteuid()))
        require(not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
    info = path.lstat()
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    same_directory(fd, path)
    return fd


def same_directory(fd, path):
    held, named = os.fstat(fd), path.lstat()
    require(stat.S_ISDIR(named.st_mode) and not stat.S_ISLNK(named.st_mode))
    require((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino))


def private_file(path, maximum, mode=0o600):
    parent = private_directory(path.parent)
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode
                and 0 < info.st_size <= maximum)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            current = os.fstat(fd)
            require((info.st_dev, info.st_ino, info.st_size) ==
                    (current.st_dev, current.st_ino, current.st_size))
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(maximum + 1)
            require(len(raw) == info.st_size)
            same_directory(parent, path.parent)
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def private_digest(path, maximum, mode=0o600):
    parent = private_directory(path.parent)
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode
                and 0 < info.st_size <= maximum)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            current = os.fstat(fd)
            require((info.st_dev, info.st_ino, info.st_size) ==
                    (current.st_dev, current.st_ino, current.st_size))
            hashed, total = hashlib.sha256(), 0
            with os.fdopen(fd, "rb", closefd=False) as stream:
                for chunk in iter(lambda: stream.read(65536), b""):
                    total += len(chunk)
                    require(total <= maximum)
                    hashed.update(chunk)
            require(total == info.st_size)
            same_directory(parent, path.parent)
            return hashed.hexdigest(), total
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def exclusive(fd, parent, name, raw):
    same_directory(fd, parent)
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(handle)
        os.fsync(fd)
    finally:
        os.close(handle)
    same_directory(fd, parent)


def bounded_command(argv, *, executable_fd, env, cwd, timeout=120, limit=4 * 1024 * 1024):
    """Run a pinned open executable and bound both streams; kill its whole group."""
    process = None
    try:
        process = subprocess.Popen(argv, executable=f"/proc/self/fd/{executable_fd}",
            pass_fds=(executable_fd,), env=env, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() < deadline, "verifier timed out")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if chunk:
                        streams[key.fileobj].extend(chunk)
                        require(sum(map(len, streams.values())) <= limit,
                                "verifier output exceeded bound")
                    else:
                        selector.unregister(key.fileobj)
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                require(time.monotonic() < deadline, "verifier timed out")
                time.sleep(0.01)
            os.killpg(process.pid, signal.SIGKILL)
            require(process.wait() == 0, "verifier failed")
        return bytes(streams[process.stdout])
    except BaseException as error:
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        if not isinstance(error, Exception):
            raise
        raise ValueError("bounded verifier command failed") from None
    finally:
        if process is not None:
            process.stdout.close()
            process.stderr.close()


def open_pinned_tool(tools, directory_fd, name):
    same_directory(directory_fd, tools)
    expected = PINS[name]
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o700
                and info.st_size == expected[1])
        hashed = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                hashed.update(chunk)
        require((hashed.hexdigest(), info.st_size) == expected, "verifier pin differs")
        require(private_digest(tools / name, expected[1], 0o700) == expected)
        same_directory(directory_fd, tools)
        return fd
    except BaseException:
        os.close(fd)
        raise


def allowed(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or p.username or p.password or p.fragment or p.port not in (None, 443):
        return False
    if p.hostname == "github.com":
        return p.path.startswith("/ElevenID/marty-ui/releases/download/")
    return p.hostname in {"release-assets.githubusercontent.com", "objects.githubusercontent.com",
                          "github-releases.githubusercontent.com"}


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(allowed(newurl), "public release redirect refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, output, parent_fd, limit):
    require(allowed(url))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects())
    handle = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
    total, deadline = 0, time.monotonic() + 600
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "marty-candidate-public-bootstrap",
                                                      "Accept-Encoding": "identity"})
        with opener.open(request, timeout=30) as response:
            require(response.status == 200 and allowed(response.url))
            with os.fdopen(handle, "wb", closefd=False) as stream:
                while True:
                    require(time.monotonic() < deadline, "public release download timed out")
                    chunk = response.read(min(65536, limit + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    require(total <= limit, "public release asset exceeds bound")
                    stream.write(chunk)
                stream.flush()
        require(total > 0)
        os.fsync(handle)
        os.fsync(parent_fd)
    finally:
        os.close(handle)
    same_directory(parent_fd, output.parent)


def verified_certificate(output, workflow, source, run, attempt):
    require(len(output) <= 4 * 1024 * 1024)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    data = json.loads(output, object_pairs_hook=pairs)
    require(type(data) is list and len(data) == 1 and type(data[0]) is dict)
    require(type(data[0].get("attestation")) is dict)
    certificate = data[0]["verificationResult"]["signature"]["certificate"]
    expected = {
        "issuer": ISSUER,
        "runInvocationURI": f"https://github.com/{REPO}/actions/runs/{run}/attempts/{attempt}",
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": f"https://github.com/{REPO}",
        "sourceRepositoryDigest": source,
        "sourceRepositoryRef": REF,
        "sourceRepositoryIdentifier": REPOSITORY_ID,
        "buildSignerURI": f"https://github.com/{REPO}/{workflow}@{REF}",
    }
    require(type(certificate) is dict and all(certificate.get(k) == v for k, v in expected.items()))
    for key, value in {"githubWorkflowRepository": REPO, "githubWorkflowSHA": source,
                       "githubWorkflowRef": REF}.items():
        require(key not in certificate or certificate[key] == value)


def verify(path, tools, workflow, source, run, attempt, home):
    maximum = 536870912 if path.name == "marty-deploy-linux-amd64" else 65536
    subjects = [path, path.with_name(path.name + ".sigstore.json"),
                path.with_name(path.name + ".provenance.jsonl")]
    before = [private_digest(subject, maximum if index == 0 else 1048576)
              for index, subject in enumerate(subjects)]
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "XDG_CACHE_HOME": str(home),
           "GH_CONFIG_DIR": str(home), "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1"}
    tools_fd = private_directory(tools)
    def run_checked(name, args):
        fd = open_pinned_tool(tools, tools_fd, name)
        try:
            output = bounded_command(args, executable_fd=fd, env=env, cwd=home)
            require(private_digest(tools / name, PINS[name][1], 0o700) == PINS[name])
            same_directory(tools_fd, tools)
            return output
        finally:
            os.close(fd)
    cosign, gh = tools / "cosign", tools / "gh"
    try:
        run_checked("cosign", [str(cosign), "verify-blob", str(path), "--bundle", str(path) + ".sigstore.json",
                 "--certificate-identity", f"https://github.com/{REPO}/{workflow}@{REF}",
                 "--certificate-oidc-issuer", ISSUER])
        output = run_checked("gh", [str(gh), "attestation", "verify", str(path), "--bundle",
                          str(path) + ".provenance.jsonl", "--repo", REPO,
                          "--signer-workflow", f"{REPO}/{workflow}", "--source-ref", REF,
                          "--source-digest", source, "--deny-self-hosted-runners",
                          "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json"])
        verified_certificate(output, workflow, source, run, attempt)
    finally:
        os.close(tools_fd)
    require([private_digest(subject, maximum if index == 0 else 1048576)
             for index, subject in enumerate(subjects)] == before,
            "verified candidate bytes changed")
    return before[0][0]


def bootstrap(args):
    require(os.name == "posix" and os.uname().sysname == "Linux" and os.uname().machine == "x86_64"
            and os.geteuid() != 0)
    base = args.base
    base_fd = private_directory(base)
    try:
        require(args.grants == base / "grants" and args.tools == base / "tools"
                and args.inputs == base / "inputs" and args.install_dir.parent == base.parent)
        for directory in (args.grants, args.tools, args.inputs):
            os.close(private_directory(directory))
        tools_fd = private_directory(args.tools)
        try:
            for name in PINS:
                fd = open_pinned_tool(args.tools, tools_fd, name)
                os.close(fd)
        finally:
            os.close(tools_fd)
        auth_path = args.grants / "candidate-authorization.json"
        receipt_path = args.grants / "controller-consumption.json"
        auth_raw, receipt_raw = private_file(auth_path, 65536), private_file(receipt_path, 65536)
        with tempfile.TemporaryDirectory(prefix="verify-", dir=base) as temporary:
            home = Path(temporary)
            verify(auth_path, args.tools, ACCEPTANCE, args.harness_source_sha,
                   args.run_id, args.run_attempt, home)
            verify(receipt_path, args.tools, ACCEPTANCE, args.harness_source_sha,
                   args.run_id, args.run_attempt, home)
            require(private_file(auth_path, 65536) == auth_raw and private_file(receipt_path, 65536) == receipt_raw)
            auth, receipt = record(auth_raw), record(receipt_raw)
            context = dict(source_sha=args.source_sha, release_tag=args.release_tag,
                           operator_sha256=args.operator_sha256, phase="published", nonce=args.nonce,
                           harness_source_sha=args.harness_source_sha, run_id=args.run_id,
                           run_attempt=args.run_attempt)
            for key, value in context.items():
                require(auth.get(key) == value and receipt.get(key) == value)
            require(auth.get("schema") == "elevenid.installer-candidate-authorization/v1"
                    and auth.get("scope") == "acceptance-only" and auth.get("repository") == REPO
                    and auth.get("source_ref") == REF and auth.get("workflow") == ACCEPTANCE
                    and auth.get("platform") == "linux/amd64")
            require(receipt.get("schema") == "elevenid.installer-controller-consumption/v1"
                    and receipt.get("scope") == "controller-dispatch-consumed"
                    and receipt.get("repository") == REPO and receipt.get("source_ref") == REF
                    and receipt.get("workflow") == ACCEPTANCE)
            require(receipt.get("authorization_sha256") == digest(auth_raw)
                    and receipt.get("context_sha256") == digest(json.dumps(context, sort_keys=True,
                        separators=(",", ":")).encode("ascii")))
            for key, value in {"engine_id": args.engine_id, "guest_id": args.guest_id,
                               "disk_id": args.disk_id, "installation_id": args.installation_id}.items():
                require(receipt.get(key) == value)
            now = int(time.time())
            for key in ("issued_at", "expires_at", "build_run_id", "build_run_attempt"):
                positive(auth.get(key))
            require(auth["issued_at"] <= now < auth["expires_at"]
                    and 0 < auth["expires_at"] - auth["issued_at"] <= 3600
                    and receipt.get("consumed_at", 0) >= auth["issued_at"]
                    and receipt["consumed_at"] <= now < auth["expires_at"])
            require(auth["build_run_id"] == args.build_run_id
                    and auth["build_run_attempt"] == args.build_run_attempt)
            for key in ("inventory_sha256", "operator_sha256"):
                sha(auth.get(key))
            require(receipt.get("inventory_sha256") == auth["inventory_sha256"])
            build_workflow = (".github/workflows/nightly-release.yml" if "-nightly." in args.release_tag
                              else ".github/workflows/cd.yml")
            same_directory(base_fd, base)
            os.mkdir("bootstrap", mode=0o700, dir_fd=base_fd)
            os.fsync(base_fd)
            same_directory(base_fd, base)
            output = base / "bootstrap"
            output_fd = private_directory(output)
            try:
                exclusive(output_fd, output, "intent.json", json.dumps({
                    "schema": "elevenid.installer-public-bootstrap-intent/v1",
                    "context_sha256": receipt["context_sha256"],
                    "authorization_sha256": digest(auth_raw), "receipt_sha256": digest(receipt_raw),
                    "started_at": now, "installation_ready": False}, sort_keys=True).encode() + b"\n")
                def fetch_triplet(name):
                    for suffix in SUFFIXES:
                        asset = name + suffix
                        limit = (536870912 if name == "marty-deploy-linux-amd64" and not suffix
                                 else 65536 if not suffix else 1048576)
                        download(f"https://github.com/{REPO}/releases/download/{args.release_tag}/{asset}",
                                 output / asset, output_fd, limit)
                fetch_triplet(ASSETS[0])
                inventory_path = output / ASSETS[0]
                inventory_raw = private_file(inventory_path, 65536)
                require(digest(inventory_raw) == auth["inventory_sha256"])
                inventory = record(inventory_raw)
                require(inventory.get("schema") == "elevenid.installer-inventory/v1"
                        and inventory.get("repository") == REPO and inventory.get("platform") == "linux/amd64")
                for key in ("source_sha", "release_tag", "build_run_id", "build_run_attempt"):
                    require(inventory.get(key) == auth[key] == receipt.get(key))
                require(receipt.get("inventory_sha256") == digest(inventory_raw))
                verify(inventory_path, args.tools, build_workflow, args.source_sha,
                       args.build_run_id, args.build_run_attempt, home)
                entries = inventory.get("artifacts")
                require(type(entries) is list and len(entries) == 4)
                operator = [item for item in entries if type(item) is dict and item.get("name") == ASSETS[1]]
                require(len(operator) == 1 and operator[0].get("sha256") == auth["operator_sha256"]
                        and type(operator[0].get("size")) is int and 0 < operator[0]["size"] <= 536870912)
                fetch_triplet(ASSETS[1])
                operator_path = output / ASSETS[1]
                operator_digest, operator_size = private_digest(operator_path, 536870912)
                require(operator_size == operator[0]["size"]
                        and operator_digest == args.operator_sha256)
                verify(operator_path, args.tools, build_workflow, args.source_sha,
                       args.build_run_id, args.build_run_attempt, home)
                require(private_file(auth_path, 65536) == auth_raw
                        and private_file(receipt_path, 65536) == receipt_raw
                        and private_file(inventory_path, 65536) == inventory_raw
                        and private_digest(operator_path, 536870912)[0] == args.operator_sha256
                        and int(time.time()) < auth["expires_at"])
                exclusive(output_fd, output, "verified.json", json.dumps({
                    "schema": "elevenid.installer-public-bootstrap-verified/v1",
                    "context_sha256": receipt["context_sha256"],
                    "inventory_sha256": digest(inventory_raw),
                    "operator_sha256": args.operator_sha256,
                    "authorization_sha256": digest(auth_raw), "receipt_sha256": digest(receipt_raw),
                    "verified_at": int(time.time()), "installation_ready": False},
                    sort_keys=True).encode() + b"\n")
                same_directory(output_fd, output)
                os.chmod(operator_path, 0o700, follow_symlinks=False)
                same_directory(base_fd, base)
                return operator_path
            finally:
                os.close(output_fd)
    finally:
        os.close(base_fd)


def authenticated_operator_fd(args, base_fd, operator):
    """Rebind grants, lease, inventory and an open operator inode before exec."""
    same_directory(base_fd, args.base)
    output = args.base / "bootstrap"
    output_fd = private_directory(output)
    try:
        require(operator == output / "marty-deploy-linux-amd64")
        verified = record(private_file(output / "verified.json", 65536))
        exact(verified, {"schema", "context_sha256", "inventory_sha256", "operator_sha256",
                         "authorization_sha256", "receipt_sha256", "verified_at", "installation_ready"})
        require(verified["schema"] == "elevenid.installer-public-bootstrap-verified/v1"
                and verified["installation_ready"] is False
                and verified["operator_sha256"] == args.operator_sha256)
        auth_raw = private_file(args.grants / "candidate-authorization.json", 65536)
        receipt_raw = private_file(args.grants / "controller-consumption.json", 65536)
        inventory_raw = private_file(output / "installer-inventory.json", 65536)
        auth, receipt = record(auth_raw), record(receipt_raw)
        require(digest(auth_raw) == verified["authorization_sha256"]
                and digest(receipt_raw) == verified["receipt_sha256"]
                and digest(inventory_raw) == verified["inventory_sha256"]
                and receipt.get("context_sha256") == verified["context_sha256"]
                and receipt.get("authorization_sha256") == digest(auth_raw)
                and receipt.get("inventory_sha256") == digest(inventory_raw)
                and receipt.get("engine_id") == args.engine_id
                and receipt.get("installation_id") == args.installation_id
                and auth.get("phase") == "published"
                and auth.get("nonce") == args.nonce
                and auth.get("operator_sha256") == args.operator_sha256
                and auth.get("source_sha") == args.source_sha
                and auth.get("release_tag") == args.release_tag
                and auth.get("harness_source_sha") == args.harness_source_sha
                and auth.get("run_id") == args.run_id
                and auth.get("run_attempt") == args.run_attempt
                and auth.get("issued_at", 0) <= int(time.time()) < auth.get("expires_at", 0))
        fd = os.open(operator.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=output_fd)
        try:
            info = os.fstat(fd)
            named = operator.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o700
                    and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino))
            expected_size = next((item.get("size") for item in record(inventory_raw).get("artifacts", [])
                                  if type(item) is dict and item.get("name") == operator.name), None)
            require(type(expected_size) is int and expected_size == info.st_size
                    and 0 < expected_size <= 536870912)
            hashed, total = hashlib.sha256(), 0
            with os.fdopen(fd, "rb", closefd=False) as stream:
                for chunk in iter(lambda: stream.read(65536), b""):
                    total += len(chunk)
                    require(total <= expected_size)
                    hashed.update(chunk)
            require(total == expected_size and hashed.hexdigest() == args.operator_sha256)
            same_directory(output_fd, output)
            same_directory(base_fd, args.base)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(output_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("base", "grants", "tools", "inputs", "install-dir"):
        parser.add_argument("--" + key, type=Path, required=True)
    for key in ("source-sha", "release-tag", "operator-sha256", "nonce", "harness-source-sha",
                "engine-id", "guest-id", "disk-id", "installation-id"):
        parser.add_argument("--" + key, required=True)
    for key in ("run-id", "run-attempt", "build-run-id", "build-run-attempt"):
        parser.add_argument("--" + key, type=int, required=True)
    args = parser.parse_args(argv)
    try:
        for key in ("source_sha", "harness_source_sha"):
            sha(getattr(args, key), 40)
        for key in ("operator_sha256", "nonce", "disk_id"):
            sha(getattr(args, key))
        for key in ("run_id", "run_attempt", "build_run_id", "build_run_attempt"):
            positive(getattr(args, key))
        require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-nightly\.20[0-9]{6}\.[1-9][0-9]*)?",
                             args.release_tag) is not None)
        base_fd = private_directory(args.base)
        try:
            operator = bootstrap(args)
            operator_fd = authenticated_operator_fd(args, base_fd, operator)
            try:
                native = ["--authorization", str(args.grants / "candidate-authorization.json"),
                          "--controller-consumption", str(args.grants / "controller-consumption.json"),
                          "--inputs-dir", str(args.inputs), "--verification-tools", str(args.tools),
                          "--gh-bin", str(args.tools / "gh"), "--docker-bin", "/usr/bin/docker",
                          "--install-dir", str(args.install_dir), "--docker-engine-id", args.engine_id,
                          "--harness-source-sha", args.harness_source_sha, "--phase", "published",
                          "--run-id", str(args.run_id), "--run-attempt", str(args.run_attempt),
                          "--nonce", args.nonce]
                env = {"HOME": str(args.base.parent), "PATH": "/usr/bin:/bin"}
                bounded_command([str(operator), "fetch-published-candidate", *native],
                                executable_fd=operator_fd, env=env, cwd=args.base.parent,
                                timeout=1800)
            finally:
                os.close(operator_fd)
            operator_fd = authenticated_operator_fd(args, base_fd, operator)
            same_directory(base_fd, args.base)
            try:
                os.execve(operator_fd, [str(operator), "install-candidate", *native], env)
            finally:
                os.close(operator_fd)
        finally:
            os.close(base_fd)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, IndexError,
            subprocess.SubprocessError):
        parser.exit(1, "Public candidate bootstrap refused or incomplete; retain guest and evidence. Do not retry.\n")


if __name__ == "__main__":
    main()
