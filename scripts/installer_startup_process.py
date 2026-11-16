"""Linux ownership of the fixed startup browser's complete descendant tree.

The caller starts a fresh, isolated Python interpreter, not a Python fork child
that could inherit another thread's locks. That interpreter is the nearest
subreaper for the launcher and its detached children. Only an empty kernel
child set permits a completed result. The caller never kills the supervisor to
implement a timeout: cancellation and caller death ask it to kill and reap its
own children, including newly adopted grandchildren.

This is process ownership, not a sandbox for hostile executables. The caller
separately admits the fixed browser runtime and harness. A kernel task stuck in
uninterruptible sleep cannot be reaped within a finite deadline. In that case
the caller receives CleanupPending, and the isolated reaper remains alive to
finish cleanup. Neither that result nor unexpected supervisor death claims a
clean tree. SIGKILL/OOM directed at the supervisor itself is outside this
guarantee; no ordinary cancellation path sends that signal to it.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import struct
import subprocess
import sys
import threading
import time

_CONFIG_LIMIT = 256 * 1024
_OUTPUT_LIMIT = 1024 * 1024
_CLEANUP_SECONDS = 8.0
_ACK_SECONDS = 2.0
_TICK = 0.025
_MAGIC = b"MSP1"
_HEADER = struct.Struct("!4sBQ")
_SUCCESS, _FAILED, _PENDING = 0, 1, 2
_WAIT_ALL = 0x40000000  # Linux __WALL also includes non-SIGCHLD clone children.
# Linux UAPI values (linux/fcntl.h); some Python builds omit these names even
# when their kernel and memfd_create support the operation.
_ADD_SEALS, _GET_SEALS, _SEALS = 1033, 1034, 0x000F


class ProcessError(ValueError):
    """Static diagnostics: never include argv, environment, or child output."""


class CleanupPending(ProcessError):
    """The isolated owner remains responsible; cleanup is not yet proven."""


def _require(condition):
    if not condition:
        raise ProcessError("startup process ownership check failed")


def _arguments(argv, env, timeout, limit):
    _require(sys.platform == "linux" and os.getuid() == os.geteuid()
             and os.getgid() == os.getegid())
    _require(isinstance(argv, (list, tuple)) and 1 <= len(argv) <= 64)
    _require(all(type(value) is str and "\0" not in value and len(value) <= 32768
                 for value in argv) and os.path.isabs(argv[0]))
    _require(type(env) is dict and 1 <= len(env) <= 128
             and all(type(key) is str and 0 < len(key) <= 256 and "=" not in key
                     and "\0" not in key and type(value) is str and "\0" not in value
                     and len(value) <= 32768 for key, value in env.items()))
    _require(type(env.get("HOME")) is str and os.path.isabs(env["HOME"]))
    _require(type(timeout) in (int, float))
    try:
        _require(math.isfinite(timeout) and 0 < timeout <= 300)
    except OverflowError:
        raise ProcessError("startup process wait budget is invalid") from None
    _require(type(limit) is int and 0 < limit <= _OUTPUT_LIMIT)


def _kernel_view():
    # A /proc mounted from an outer PID namespace cannot establish ownership
    # using this process's PIDs. Refuse it before any workload is started.
    try:
        _require(os.readlink("/proc/self") == str(os.getpid()))
        _require(_identity(os.getpid())[0] == os.getppid())
        _direct_pids()  # Establish discovery before launching work.
    except OSError:
        raise ProcessError("startup process census is unavailable") from None


def _close(fd):
    if fd is not None:
        try:
            os.close(fd)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def _config_fd(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    _require(len(raw) <= _CONFIG_LIMIT)
    descriptor = os.memfd_create("installer-startup-process", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0)
            view = view[written:]
        fcntl.fcntl(descriptor, _ADD_SEALS, _SEALS)
        return descriptor
    except BaseException:
        _close(descriptor)
        raise


def _read_config(descriptor):
    info = os.fstat(descriptor)
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
             and 0 < info.st_size <= _CONFIG_LIMIT
             and fcntl.fcntl(descriptor, _GET_SEALS) & _SEALS == _SEALS)
    raw = os.pread(descriptor, _CONFIG_LIMIT + 1, 0)
    _require(len(raw) == info.st_size)
    value = json.loads(raw)
    _require(type(value) is dict and set(value) == {"argv", "env", "timeout", "limit", "parent", "deadline"})
    _arguments(value["argv"], value["env"], value["timeout"], value["limit"])
    _require(type(value["parent"]) is int and value["parent"] > 0
             and type(value["deadline"]) in (int, float) and math.isfinite(value["deadline"]))
    return value


class _Reply:
    def __init__(self, descriptor, limit):
        self.descriptor = descriptor
        self.limit = limit
        self.raw = bytearray()
        self.ended = False
        os.set_blocking(descriptor, False)

    def read(self):
        while True:
            try:
                chunk = os.read(self.descriptor, min(65536, _HEADER.size + self.limit + 1 - len(self.raw)))
            except BlockingIOError:
                break
            if not chunk:
                self.ended = True
                break
            self.raw.extend(chunk)
            _require(len(self.raw) <= _HEADER.size + self.limit)
        if len(self.raw) < _HEADER.size:
            return None
        magic, status, length = _HEADER.unpack(self.raw[:_HEADER.size])
        _require(magic == _MAGIC and status in (_SUCCESS, _FAILED, _PENDING)
                 and length <= self.limit and (status == _SUCCESS or length == 0)
                 and len(self.raw) <= _HEADER.size + length)
        if len(self.raw) == _HEADER.size + length:
            return status, bytes(self.raw[_HEADER.size:])
        return None


def _read_reply(reply, process, deadline):
    with selectors.DefaultSelector() as selector:
        selector.register(reply.descriptor, selectors.EVENT_READ)
        while True:
            result = reply.read()
            if result is not None:
                return result
            if reply.ended or process.poll() is not None:
                # poll may observe exit before the final pipe read.
                result = reply.read()
                if result is not None:
                    return result
                raise ProcessError("startup process owner ended without cleanup proof")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            selector.select(min(_TICK, remaining))


def _reap_later(process):
    # Used only after an explicit cleanup-pending result. The isolated owner
    # continues killing/reaping; this thread merely reaps that one child when
    # it eventually finishes. It never performs signals or process discovery.
    try:
        process.wait()
    except (OSError, ChildProcessError):
        pass


def _retain_owner(process):
    threading.Thread(target=_reap_later, args=(process,), name="startup-owner-reap", daemon=True).start()


def command(argv, *, env, timeout=180, limit=65536):
    """Run the fixed browser and return bounded stdout after complete cleanup.

    stderr contributes to the same output budget and is never returned in an
    error. The caller's cancellation is propagated after cleanup; caller death
    is independently handled inside the isolated owner. No shell is involved.
    """
    _arguments(argv, env, timeout, limit)
    _kernel_view()
    process = None
    descriptors = set()
    control_write = None
    reply = None
    retained = False
    finished = False
    interrupted = None
    try:
        deadline = time.monotonic() + timeout
        config = _config_fd(dict(argv=list(argv), env=dict(env), timeout=timeout,
                                 limit=limit, parent=os.getpid(), deadline=deadline))
        descriptors.add(config)
        control_read, control_write = os.pipe2(os.O_CLOEXEC)
        result_read, result_write = os.pipe2(os.O_CLOEXEC)
        descriptors.update((control_read, control_write, result_read, result_write))
        # Executing this fixed source in a fresh interpreter also avoids .pyc,
        # ambient PYTHONPATH/site hooks, and inherited Python thread locks.
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--supervisor",
             str(config), str(control_read), str(result_write)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            close_fds=True, pass_fds=(config, control_read, result_write), start_new_session=True,
        )
        for descriptor in (config, control_read, result_write):
            _close(descriptor)
            descriptors.remove(descriptor)
        reply = _Reply(result_read, limit)
        result = _read_reply(reply, process, deadline)
        timed_out = result is None
        if timed_out:
            _close(control_write)
            descriptors.remove(control_write)
            control_write = None
            result = _read_reply(reply, process, time.monotonic() + _CLEANUP_SECONDS + _ACK_SECONDS)
        if result is None or result[0] == _PENDING:
            _retain_owner(process)
            retained = True
            raise CleanupPending("startup browser cleanup remains pending in its isolated owner")
        process.wait(timeout=_ACK_SECONDS)
        finished = True
        _require(process.returncode == 0)
        if result[0] != _SUCCESS or timed_out:
            raise ProcessError("startup browser command failed after descendant cleanup")
        return result[1]
    except BaseException as error:
        interrupted = error
        if process is not None and not finished and not retained:
            # EOF cannot be inherited by the workload: its control/result FDs
            # are closed before exec. Closing this end also works from a caller
            # thread without installing process-wide Python signal handlers.
            if control_write is not None:
                _close(control_write)
                descriptors.discard(control_write)
                control_write = None
            end = time.monotonic() + _CLEANUP_SECONDS + _ACK_SECONDS
            while time.monotonic() < end:
                try:
                    result = _read_reply(reply, process, end) if reply is not None else None
                    if result is not None and result[0] != _PENDING:
                        process.wait(timeout=max(0.001, end - time.monotonic()))
                        finished = True
                    break
                except (KeyboardInterrupt, SystemExit):
                    continue
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    break
            if not finished and process.poll() is None:
                _retain_owner(process)
                retained = True
                raise CleanupPending("startup browser cleanup remains pending in its isolated owner") from None
        if not isinstance(interrupted, Exception):
            raise
        if isinstance(interrupted, ProcessError):
            raise
        raise ProcessError("startup browser process observation failed") from None
    finally:
        for descriptor in descriptors:
            _close(descriptor)


def _prctl(option, value):
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.prctl
    function.restype = ctypes.c_int
    function.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    if function(option, value, 0, 0, 0) != 0:
        raise ProcessError("startup process ownership is unavailable")


def _close_other_fds(keep):
    # Only the fresh single-threaded supervisor and its pre-exec fork call this.
    names = os.listdir("/proc/self/fd")
    _require(len(names) <= 8192)
    for name in names:
        if name.isdecimal() and int(name) > 2 and int(name) not in keep:
            _close(int(name))


def _identity(pid):
    with open(f"/proc/{pid}/stat", "rb", buffering=0) as stream:
        raw = stream.read(8193)
    _require(len(raw) <= 8192 and raw.startswith(str(pid).encode() + b" ("))
    marker = raw.rfind(b") ")
    _require(marker > 0)
    values = raw[marker + 2:].split()
    _require(len(values) >= 20)
    return int(values[1]), int(values[19])  # parent PID and starttime, never comm.


def _direct_pids():
    me = os.getpid()
    try:
        # This optional interface depends on CONFIG_CHECKPOINT_RESTORE. Some
        # otherwise supported Linux kernels do not provide it.
        with open(f"/proc/{me}/task/{me}/children", "rb", buffering=0) as stream:
            raw = stream.read(1024 * 1024 + 1)
        _require(len(raw) <= 1024 * 1024)
        values = raw.split()
        _require(all(value.isdigit() for value in values))
        return {int(value) for value in values}
    except FileNotFoundError:
        pass
    result = set()
    with os.scandir("/proc") as entries:
        for index, entry in enumerate(entries):
            _require(index < 131072)
            if not entry.name.isdecimal():
                continue
            pid = int(entry.name)
            if pid <= 1 or pid == me:
                continue
            try:
                parent, _start = _identity(pid)
            except (OSError, ValueError):
                # A disappearing or unreadable unrelated process grants no
                # authority. A missed owned child prevents ECHILD and remains
                # for another discovery wave; it cannot create false success.
                continue
            if parent == me:
                result.add(pid)
    return result


class _Child:
    def __init__(self, pid):
        self.pid = pid
        self.start = _identity(pid)
        _require(self.start[0] == os.getpid())
        self.fd = None
        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
            try:
                self.fd = os.pidfd_open(pid, 0)
            except OSError as error:
                if error.errno not in (errno.ENOSYS, errno.EINVAL):
                    raise
        try:
            _require(_identity(pid) == self.start)
        except BaseException:
            _close(self.fd)
            raise

    def kill(self):
        # No other thread reaps children. The still-waitable direct child's PID
        # is reserved even on old Linux without pidfds; recheck parent/starttime
        # immediately before that fallback signal.
        _require(_identity(self.pid) == self.start)
        try:
            if self.fd is not None:
                signal.pidfd_send_signal(self.fd, signal.SIGKILL)
            else:
                os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # Already dead; only waitpid/ECHILD can prove it was reaped.

    def close(self):
        _close(self.fd)


class _Tree:
    def __init__(self):
        self.children = {}
        self.leader = None
        self.leader_status = None

    def remember(self, pid):
        if pid not in self.children:
            self.children[pid] = _Child(pid)

    def kill_direct(self):
        me = os.getpid()
        failure = None
        # Previously admitted direct children remain signalable if a later
        # census is unavailable. Never postpone their cleanup behind discovery.
        for child in self.children.values():
            try:
                child.kill()
            except (OSError, ValueError) as error:
                failure = error
        try:
            candidates = _direct_pids()
        except (OSError, ValueError) as error:
            failure, candidates = error, set()
        for pid in candidates:
            try:
                _require(pid > 1 and pid != me)
                self.remember(pid)
                self.children[pid].kill()
            except (OSError, ValueError) as error:
                failure = error
        if failure is not None:
            raise failure

    def reap(self):
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG | _WAIT_ALL)
            except ChildProcessError:
                _require(not self.children)
                return True
            if pid == 0:
                return False
            child = self.children.pop(pid, None)
            if child is not None:
                child.close()
            if pid == self.leader:
                self.leader_status = os.waitstatus_to_exitcode(status)

    def leader_exited(self):
        if self.leader_status is not None:
            return True
        result = os.waitid(os.P_PID, self.leader, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        return result is not None


class _Streams:
    def __init__(self, stdout, stderr, limit):
        self.descriptors = {stdout: True, stderr: False}
        self.limit = limit
        self.stdout = bytearray()
        self.count = 0
        self.failed = False
        for descriptor in self.descriptors:
            os.set_blocking(descriptor, False)

    def drain(self):
        for descriptor, is_stdout in list(self.descriptors.items()):
            for _ in range(8):
                try:
                    chunk = os.read(descriptor, 8192)
                except BlockingIOError:
                    break
                if not chunk:
                    _close(descriptor)
                    del self.descriptors[descriptor]
                    break
                room = max(0, self.limit - self.count)
                if is_stdout:
                    self.stdout.extend(chunk[:room])
                self.count = min(self.limit + 1, self.count + len(chunk))
                if self.count > self.limit:
                    break

    def close(self):
        for descriptor in self.descriptors:
            _close(descriptor)
        self.descriptors.clear()


def _launch(value, tree):
    stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
    stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
    parent = os.getpid()
    pid = os.fork()  # Fresh isolated interpreter: no other Python thread exists.
    if pid == 0:
        try:
            for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGCHLD, signal.SIGPIPE):
                signal.signal(signum, signal.SIG_DFL)
            _prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG, before exec and parent check.
            if os.getppid() != parent:
                os._exit(127)
            os.dup2(stdout_write, 1)
            os.dup2(stderr_write, 2)
            _close_other_fds(set())
            os.chdir(value["env"]["HOME"])
            os.execve(value["argv"][0], value["argv"], value["env"])
        except BaseException:
            os._exit(127)
    _close(stdout_write)
    _close(stderr_write)
    tree.leader = pid
    tree.remember(pid)
    return _Streams(stdout_read, stderr_read, value["limit"])


def _cancelled(control, flag):
    if flag[0]:
        return True
    try:
        # The parent writes no data. EOF (including abrupt death) or unexpected
        # input both cancel; this FD never reaches the launched executable.
        os.read(control, 1)
        return True
    except BlockingIOError:
        return False


def _send(descriptor, status, raw=b""):
    frame = memoryview(_HEADER.pack(_MAGIC, status, len(raw)) + raw)
    end = time.monotonic() + _ACK_SECONDS
    while frame:
        try:
            written = os.write(descriptor, frame)
            if written <= 0:
                return
            frame = frame[written:]
        except BlockingIOError:
            if time.monotonic() >= end:
                return
            time.sleep(_TICK)
        except BrokenPipeError:
            return  # Caller died; cleanup is independent of acknowledgement.


def _cleanup(tree, streams, result):
    deadline = time.monotonic() + _CLEANUP_SECONDS
    pending_sent = False
    while True:
        empty = False
        try:
            tree.kill_direct()
        except (OSError, ValueError):
            # An uncertain observation never authorizes signaling an unrelated
            # process. Reaping is independent: a missing census must not keep
            # known dead children reserved forever.
            pass
        try:
            empty = tree.reap()
        except (OSError, ValueError):
            pass
        if streams is not None:
            try:
                streams.drain()
            except (OSError, ValueError):
                streams.failed = True
        if empty:
            return not pending_sent
        if not pending_sent and time.monotonic() >= deadline:
            _send(result, _PENDING)
            pending_sent = True
        time.sleep(0.1 if pending_sent else _TICK)


def _supervisor(config, control, result):
    tree = _Tree()
    streams = None
    cancelled = [False]
    good = False
    try:
        value = _read_config(config)
        _close(config)
        _kernel_view()
        _require(control != result and stat.S_ISFIFO(os.fstat(control).st_mode)
                 and stat.S_ISFIFO(os.fstat(result).st_mode))
        os.set_blocking(control, False)
        os.set_blocking(result, False)
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, lambda *_: cancelled.__setitem__(0, True))
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        _prctl(36, 1)  # PR_SET_CHILD_SUBREAPER, before any workload exists.
        _prctl(1, signal.SIGTERM)
        _prctl(38, 1)  # PR_SET_NO_NEW_PRIVS; retain the Chromium sandbox.
        # Covers parent death before prctl and the getppid/prctl race. Death
        # after this check is observed through the signal and private pipe EOF.
        if os.getppid() != value["parent"] or _cancelled(control, cancelled):
            raise ProcessError("startup process caller is no longer present")
        _close_other_fds({control, result})
        streams = _launch(value, tree)
        while True:
            streams.drain()
            if (_cancelled(control, cancelled) or time.monotonic() >= value["deadline"]
                    or streams.count > value["limit"]):
                break
            if tree.leader_exited():
                good = True
                break
            time.sleep(_TICK)
    except BaseException:
        good = False
    finally:
        complete = _cleanup(tree, streams, result)
        if complete:
            good = (good and tree.leader_status == 0 and streams is not None
                    and not streams.failed and not streams.descriptors
                    and streams.count <= streams.limit)
            _send(result, _SUCCESS if good else _FAILED, bytes(streams.stdout) if good else b"")
        if streams is not None:
            streams.close()
        _close(control)
        _close(result)


def _main():
    if (len(sys.argv) != 5 or sys.argv[1] != "--supervisor"
            or not all(value.isdecimal() for value in sys.argv[2:])
            or len(set(sys.argv[2:])) != 3 or any(int(value) < 3 for value in sys.argv[2:])):
        return 2
    _supervisor(*(int(value) for value in sys.argv[2:]))
    return 0


if __name__ == "__main__":
    os._exit(_main())
