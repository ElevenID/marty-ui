"""Linux-only containment for an exact child and its inherited process group.

The surviving caller owns cleanup. This is not protection against SIGKILL of
that caller or its outer runner. Observe exit without reaping: the group leader
must retain its PID until group cleanup, including after an unexpected exit.
"""

import math
import os
import signal
import subprocess
import sys
import time


class OwnedProcessError(RuntimeError):
    """Static ownership/cleanup diagnostics; never child arguments or output."""


def validate_timeout(timeout):
    if type(timeout) not in (int, float) or timeout < 0:
        raise OwnedProcessError("Owned process wait budget is invalid")
    try:
        finite = math.isfinite(timeout)
    except OverflowError:
        finite = False
    if not finite:
        raise OwnedProcessError("Owned process wait budget is invalid")


class OwnedProcess:
    def __init__(self, command, **kwargs):
        if sys.platform != "linux":
            raise OwnedProcessError("Owned process containment requires Linux")
        if not isinstance(command, (list, tuple)) or not command:
            raise OwnedProcessError("Owned process requires an explicit argument array")
        if not all(isinstance(argument, (str, os.PathLike)) for argument in command):
            raise OwnedProcessError("Owned process arguments have an invalid type")
        if set(kwargs) - {"stdin", "stdout", "stderr", "env", "cwd"}:
            raise OwnedProcessError("Owned process launch options are not permitted")
        try:
            self._child = subprocess.Popen(command, start_new_session=True, **kwargs)
        except (OSError, TypeError, ValueError):
            raise OwnedProcessError("Owned process could not start") from None
        self._pid = self._child.pid
        self.returncode = None
        self._reaped = False
        self._group_cleaned = False

    @property
    def pid(self):
        return self._pid

    def poll(self):
        if self._reaped:
            return self.returncode
        try:
            observed = os.waitid(
                os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
            )
        except (OSError, ChildProcessError):
            raise OwnedProcessError("Owned process exit observation failed") from None
        if observed is None:
            return None
        if observed.si_pid != self.pid:
            raise OwnedProcessError("Owned process exit identity differs")
        if observed.si_code == os.CLD_EXITED:
            self.returncode = observed.si_status
        elif observed.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
            self.returncode = -observed.si_status
        else:
            raise OwnedProcessError("Owned process exit observation is not terminal")
        return self.returncode

    def _kill_group(self):
        if self._reaped or self._group_cleaned:
            return
        if type(self.pid) is not int or self.pid <= 1 or self._child.pid != self.pid:
            raise OwnedProcessError("Owned process group identity is invalid")
        # PID/session equality alone does not prove parenthood. Establish that
        # this leader remains our waitable child before any group signal.
        self.poll()
        try:
            if (
                self.pid in (os.getpid(), os.getpgrp())
                or os.getpgid(self.pid) != self.pid
                or os.getsid(self.pid) != self.pid
            ):
                raise OwnedProcessError("Owned process group identity differs")
            os.killpg(self.pid, signal.SIGKILL)
        except OSError:
            raise OwnedProcessError("Owned process group cleanup failed") from None
        self._group_cleaned = True

    def kill(self):
        self._kill_group()

    def wait(self, timeout=10):
        validate_timeout(timeout)
        if self._reaped:
            return self.returncode
        deadline = time.monotonic() + timeout
        while self.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("owned process", timeout)
            time.sleep(min(0.025, max(0, deadline - time.monotonic())))
        # Even a successful or crashed coordinator can leave descendants alive.
        # Its unreaped leader PID still reserves this exact session/group ID.
        self._kill_group()
        try:
            status = self._child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired("owned process", timeout) from None
        except OSError:
            raise OwnedProcessError("Owned process reap failed") from None
        self._reaped = True
        if status != self.returncode:
            raise OwnedProcessError("Owned process terminal status differs")
        return status

    def cleanup(self, timeout=10):
        validate_timeout(timeout)
        if not self._reaped:
            self._kill_group()
        return self.wait(timeout)
