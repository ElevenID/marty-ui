#!/usr/bin/python3
"""One-shot engineering qualification of the reviewed b490 reader test.

Stage this exact script as /root/installer-reader-foreign-owner-root-qualification-v2.py
with root ownership, mode 0500, and a separately reviewed SHA-256. Do not run
from a workspace path. This is not publisher or release artifact admission.
"""

import hashlib
import json
import os
import re
import resource
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time

STAGED_SCRIPT = "/root/installer-reader-foreign-owner-root-qualification-v2.py"
SOURCE = ("/home/canvasrunner/.cache/marty-reader-qual-b490-target/"
          "x86_64-unknown-linux-musl/debug/deps/"
          "marty_deployment_catalog-5c85161b71e3f75b")
SOURCE_SHA256 = "5d71767dd8b523efc01161ecf9938a8dcf7f4b5180cc80a142162a1835bf2510"
SOURCE_SIZE = 41_116_688
MAX_ELF_SIZE = 64 * 1024 * 1024
SOURCE_UID = 1000
FIXTURE_ROOT = "/var/tmp"
FIXTURE_PARENT_MODE = 0o755
TEST = ("installer_creation_receipt_validation::tests::"
        "foreign_owned_private_openbao_metadata_qualification")
ARGV = (TEST, "--exact", "--ignored", "--test-threads=1")
MAX_OUTPUT = 64 * 1024
TIMEOUT = 90


def refuse(message):
    raise RuntimeError(message)


def require(ok, message):
    if not ok:
        refuse(message)


def stamp(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode),
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def directory_identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid,
            stat.S_IMODE(st.st_mode), st.st_nlink)


def require_named_directory(parent_fd, name, held_stat):
    named_fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=parent_fd)
    try:
        named = os.fstat(named_fd)
        require(stat.S_ISDIR(named.st_mode) and
                directory_identity(named) == directory_identity(held_stat),
                "named directory no longer matches held identity")
    finally:
        os.close(named_fd)


def require_empty_directory(fd):
    # Check at most one name; a malicious fixture UID cannot force an
    # unbounded list allocation in the root controller.
    with os.scandir(fd) as entries:
        require(next(entries, None) is None, "fixture directory is not empty")


def require_root_copy(private_fd, copied_fd, copied_stat):
    named_fd = os.open("qualified-test-elf", os.O_PATH | os.O_NOFOLLOW |
                       os.O_CLOEXEC, dir_fd=private_fd)
    try:
        require(stamp(os.fstat(named_fd)) == stamp(copied_stat) ==
                stamp(os.fstat(copied_fd)), "root-private ELF identity drift")
        digest = hashlib.sha256()
        offset = 0
        while offset < SOURCE_SIZE:
            chunk = os.pread(copied_fd, min(1024 * 1024, SOURCE_SIZE - offset), offset)
            require(chunk, "root-private ELF shortened")
            digest.update(chunk)
            offset += len(chunk)
        require(os.pread(copied_fd, 1, SOURCE_SIZE) == b"" and
                digest.hexdigest() == SOURCE_SHA256 and
                stamp(os.fstat(named_fd)) == stamp(copied_stat),
                "root-private ELF content drift")
    finally:
        os.close(named_fd)


def held_source():
    path_fd = os.open(SOURCE, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    original = os.fstat(path_fd)
    require(stat.S_ISREG(original.st_mode) and original.st_nlink == 1,
            "source is not a single-link regular file")
    require(original.st_uid == SOURCE_UID and 0 < SOURCE_SIZE <= MAX_ELF_SIZE and
            original.st_size == SOURCE_SIZE,
            "source owner or size changed")
    # Procfd reopening binds the already classified inode. No arbitrary path
    # receives an O_RDONLY open before its type has been checked.
    read_fd = os.open(f"/proc/self/fd/{path_fd}", os.O_RDONLY | os.O_CLOEXEC)
    require(stamp(os.fstat(read_fd)) == stamp(original), "source reopen changed")
    return path_fd, read_fd, original


def copy_admitted(read_fd, path_fd, original, private_fd):
    out_fd = os.open("qualified-test-elf", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=private_fd)
    digest = hashlib.sha256()
    remaining = SOURCE_SIZE
    try:
        while remaining:
            chunk = os.read(read_fd, min(1024 * 1024, remaining))
            require(chunk, "source shortened during copy")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                n = os.write(out_fd, view)
                require(n > 0, "destination write stalled")
                view = view[n:]
            remaining -= len(chunk)
        require(os.read(read_fd, 1) == b"", "source grew during copy")
        require(digest.hexdigest() == SOURCE_SHA256, "source SHA-256 mismatch")
        require(stamp(os.fstat(read_fd)) == stamp(original), "source changed during copy")
        require(stamp(os.fstat(path_fd)) == stamp(original), "held source changed")
        out = os.fstat(out_fd)
        require(stat.S_ISREG(out.st_mode) and out.st_nlink == 1 and
                out.st_uid == 0 and out.st_size == SOURCE_SIZE,
                "root-private copy identity changed")
        os.fsync(out_fd)
        os.fchmod(out_fd, 0o555)
        os.fsync(out_fd)
    finally:
        os.close(out_fd)
    os.fsync(private_fd)
    copied_fd = os.open("qualified-test-elf", os.O_RDONLY | os.O_NOFOLLOW |
                        os.O_CLOEXEC, dir_fd=private_fd)
    copied = os.fstat(copied_fd)
    require(stat.S_ISREG(copied.st_mode) and copied.st_uid == 0 and
            stat.S_IMODE(copied.st_mode) == 0o555 and copied.st_nlink == 1 and
            copied.st_size == SOURCE_SIZE, "copy not root-owned immutable mode")
    check = hashlib.sha256()
    remaining = SOURCE_SIZE
    while remaining:
        chunk = os.read(copied_fd, min(1024 * 1024, remaining))
        require(chunk, "root copy shortened during initial recheck")
        check.update(chunk)
        remaining -= len(chunk)
    require(os.read(copied_fd, 1) == b"" and
            check.hexdigest() == SOURCE_SHA256 and
            stamp(os.fstat(copied_fd)) == stamp(copied),
            "root copy digest or identity changed")
    return copied_fd, copied


def require_static_elf(fd, expected_size):
    header = os.pread(fd, 64, 0)
    require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01",
            "not 64-bit little-endian ELF")
    elf_type, machine = struct.unpack_from("<HH", header, 16)
    require(elf_type in (2, 3) and machine == 62, "unexpected ELF type or machine")
    phoff = struct.unpack_from("<Q", header, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", header, 54)
    require(phentsize == 56 and 0 < phnum <= 128 and
            phoff + phentsize * phnum <= expected_size, "invalid program header table")
    dynamic = []
    for index in range(phnum):
        ph = os.pread(fd, 56, phoff + index * 56)
        require(len(ph) == 56, "short program header")
        p_type, _, p_offset, _, _, p_filesz, _, _ = struct.unpack("<IIQQQQQQ", ph)
        require(p_offset + p_filesz <= expected_size, "program segment out of bounds")
        require(p_type != 3, "ELF interpreter is forbidden")
        if p_type == 2:
            require(p_filesz <= 1024 * 1024 and p_filesz % 16 == 0,
                    "invalid dynamic table")
            dynamic.append((p_offset, p_filesz))
    require(len(dynamic) <= 1, "ambiguous dynamic tables")
    if dynamic:
        offset, size = dynamic[0]
        terminated = False
        for pos in range(offset, offset + size, 16):
            entry = os.pread(fd, 16, pos)
            require(len(entry) == 16, "short dynamic entry")
            tag, _ = struct.unpack("<qQ", entry)
            if tag == 0:
                terminated = True
                break
            require(tag not in (1, 15, 29), "ELF needs library or RPATH/RUNPATH")
        require(terminated, "unterminated dynamic table")


def write_private(parent_fd, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            require(n > 0, "private record write stalled")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent_fd)


def fixture_tmpdir():
    tmp_fd = os.open(FIXTURE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                     os.O_CLOEXEC)
    tmp = os.fstat(tmp_fd)
    require(stat.S_ISDIR(tmp.st_mode) and tmp.st_uid == 0 and
            stat.S_IMODE(tmp.st_mode) == 0o1777, "unexpected fixture root custody")
    name = "marty-reader-qual-v2-" + secrets.token_hex(16)
    os.mkdir(name, 0o700, dir_fd=tmp_fd)
    parent_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                        os.O_CLOEXEC, dir_fd=tmp_fd)
    require(os.fstat(parent_fd).st_uid == 0, "fixture parent not root owned")
    os.mkdir("fixture", 0o700, dir_fd=parent_fd)
    child_fd = os.open("fixture", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                       os.O_CLOEXEC, dir_fd=parent_fd)
    os.fchown(child_fd, 65534, 65534)
    # InstallerState opens every ancestor O_RDONLY|O_DIRECTORY under the
    # fixture EUID; traverse-only mode 0711 caused the preserved v1 failure.
    os.fchmod(parent_fd, FIXTURE_PARENT_MODE)
    os.fsync(child_fd)
    os.fsync(parent_fd)
    os.fsync(tmp_fd)
    child = os.fstat(child_fd)
    require(child.st_uid == 65534 and child.st_gid == 65534 and
            stat.S_IMODE(child.st_mode) == 0o700, "fixture child custody changed")
    parent = os.fstat(parent_fd)
    require(parent.st_uid == 0 and parent.st_gid == 0 and
            stat.S_IMODE(parent.st_mode) == FIXTURE_PARENT_MODE,
            "fixture parent access contract changed")
    return tmp_fd, parent_fd, child_fd, name, parent, child


def run_one(binary_fd, tmpdir, private_fd):
    require(tuple(sys.argv) == (STAGED_SCRIPT,), "launcher takes no arguments")
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": tmpdir}

    def limits():
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    # waitid(WNOWAIT) below relies on the leader remaining waitable until our
    # explicit final reap. Never inherit SIGCHLD=SIG_IGN or SA_NOCLDWAIT.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    # Execute the held, already hashed root-owned inode through procfd. The
    # private pathname is never reopened by the execution decision.
    binary_path = f"/proc/self/fd/{binary_fd}"
    proc = subprocess.Popen((binary_path,) + ARGV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd="/", env=env, close_fds=True,
                            pass_fds=(binary_fd,), start_new_session=True,
                            preexec_fn=limits)
    output = collect_owned_process(proc, private_fd, TIMEOUT, MAX_OUTPUT)
    text = output.decode("utf-8", "strict")
    marker = f"test {TEST} ... ok"
    require(text.splitlines().count(marker) == 1, "expected exactly one passed test")
    require(len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; "
                           r"0 measured; [0-9]+ filtered out; finished in [0-9.]+s$",
                           text, flags=re.MULTILINE)) == 1,
            "unexpected test summary")
    return output


def collect_owned_process(proc, private_fd, timeout, max_output):
    """Bound output; kill the owned group while its leader PID is reserved."""
    selector = selectors.DefaultSelector()
    for pipe in (proc.stdout, proc.stderr):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    chunks = []
    used = 0
    deadline = time.monotonic() + timeout
    failure = None
    try:
        while selector.get_map():
            require(time.monotonic() < deadline, "test timed out")
            for key, _ in selector.select(timeout=0.5):
                chunk = os.read(key.fd, min(8192, max_output - used + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                used += len(chunk)
                require(used <= max_output, "test output exceeded bound")
                chunks.append(chunk)
        while True:
            require(time.monotonic() < deadline, "test leader timed out")
            status = os.waitid(os.P_PID, proc.pid,
                               os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                break
            time.sleep(0.05)
        require(status.si_code == os.CLD_EXITED and status.si_status == 0,
                "test process failed")
    except BaseException as exc:
        failure = exc
    finally:
        # The direct child has not been reaped; its PID/PGID cannot be reused.
        # Kill on success too, as a descendant may retain no output pipe.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
        selector.close()
        proc.stdout.close()
        proc.stderr.close()
    if failure is not None:
        if private_fd is not None:
            write_private(private_fd, "test-output.partial.txt", b"".join(chunks))
        raise failure
    return b"".join(chunks)


def main():
    require(os.getuid() == os.geteuid() == 0 and os.getegid() == 0,
            "root execution identity required")
    script = os.lstat(STAGED_SCRIPT)
    require(stat.S_ISREG(script.st_mode) and script.st_uid == 0 and
            stat.S_IMODE(script.st_mode) == 0o500 and script.st_nlink == 1,
            "launcher must be a root-private staged regular file")
    require(os.path.realpath(__file__) == STAGED_SCRIPT, "launcher path changed")
    os.setgroups([])
    os.umask(0o077)
    source_path_fd, source_read_fd, source_stat = held_source()
    private_name = "marty-reader-qualification-v2-" + secrets.token_hex(16)
    root_fd = os.open("/root", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                      os.O_CLOEXEC)
    require(os.fstat(root_fd).st_uid == 0 and
            stat.S_IMODE(os.fstat(root_fd).st_mode) == 0o700,
            "unexpected /root custody")
    os.mkdir(private_name, 0o700, dir_fd=root_fd)
    private_fd = os.open(private_name, os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
    private_stat = os.fstat(private_fd)
    copied_fd, copied_stat = copy_admitted(source_read_fd, source_path_fd,
                                          source_stat, private_fd)
    require_static_elf(copied_fd, SOURCE_SIZE)
    require(stamp(os.fstat(copied_fd)) == stamp(copied_stat), "ELF changed during check")
    admission = {
        "scope": "engineering synthetic test; no publisher/release admission",
        "source_commit": "b4901764aa77107e8b6c47c7ac085480d9b72cbf",
        "test_source_sha256": "6b8ac94f5013ce563b4b84aede7af45bf391cba0b35b8981dc2ab61b7c6e4eb2",
        "cargo_lock_sha256": "0dae57710d6482e3b1887995c671ddb629f46ffd2321d293a4c6af73b0a4d1fd",
        "elf_sha256": SOURCE_SHA256,
        "elf_size": SOURCE_SIZE,
        "elf_source_dev_inode": [source_stat.st_dev, source_stat.st_ino],
        "elf_private_dev_inode": [copied_stat.st_dev, copied_stat.st_ino],
        "static_no_interpreter_needed_rpath": True,
        "argv": list(ARGV),
    }
    write_private(private_fd, "admission.json",
                  (json.dumps(admission, sort_keys=True) + "\n").encode())
    tmp_fd, parent_fd, child_fd, tmp_name, parent_stat, child_stat = fixture_tmpdir()
    require_named_directory(root_fd, private_name, private_stat)
    require_root_copy(private_fd, copied_fd, copied_stat)
    print(json.dumps({"root_private_dir": f"/root/{private_name}",
                      "fixture_parent": f"{FIXTURE_ROOT}/{tmp_name}"}), flush=True)
    output = run_one(copied_fd, f"{FIXTURE_ROOT}/{tmp_name}/fixture", private_fd)
    require_named_directory(root_fd, private_name, private_stat)
    require_root_copy(private_fd, copied_fd, copied_stat)
    write_private(private_fd, "test-output.txt", output)
    require(directory_identity(os.fstat(child_fd)) == directory_identity(child_stat),
            "fixture identity drift")
    require_named_directory(parent_fd, "fixture", child_stat)
    require_empty_directory(child_fd)
    require_named_directory(tmp_fd, tmp_name, parent_stat)
    os.rmdir("fixture", dir_fd=parent_fd)
    post_parent = os.fstat(parent_fd)
    require(directory_identity(post_parent)[:-1] == directory_identity(parent_stat)[:-1]
            and post_parent.st_nlink + 1 == parent_stat.st_nlink,
            "fixture parent identity changed after child removal")
    require_named_directory(tmp_fd, tmp_name, post_parent)
    require_empty_directory(parent_fd)
    current_fixture_root = os.open(FIXTURE_ROOT, os.O_PATH | os.O_NOFOLLOW |
                                   os.O_CLOEXEC)
    try:
        require(directory_identity(os.fstat(current_fixture_root))[:-1] ==
                directory_identity(os.fstat(tmp_fd))[:-1],
                "fixture root binding changed")
    finally:
        os.close(current_fixture_root)
    os.rmdir(tmp_name, dir_fd=tmp_fd)
    os.fsync(tmp_fd)
    record = {
        "scope": "engineering synthetic test only; no publisher/release admission",
        "source_commit": "b4901764aa77107e8b6c47c7ac085480d9b72cbf",
        "test_source_sha256": "6b8ac94f5013ce563b4b84aede7af45bf391cba0b35b8981dc2ab61b7c6e4eb2",
        "cargo_lock_sha256": "0dae57710d6482e3b1887995c671ddb629f46ffd2321d293a4c6af73b0a4d1fd",
        "elf_sha256": SOURCE_SHA256,
        "elf_size": SOURCE_SIZE,
        "elf_static_no_interpreter_needed_rpath": True,
        "argv": list(ARGV),
        "passed": 1,
        "fixture_tmpdir_empty_removed": True,
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }
    write_private(private_fd, "qualification-result.json",
                  (json.dumps(record, sort_keys=True) + "\n").encode())
    print(json.dumps({"result": "one synthetic test passed", "root_record":
                      f"/root/{private_name}/qualification-result.json"}))


if __name__ == "__main__":
    main()
