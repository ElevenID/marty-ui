"""Owned synthetic coordinator cleanup; Linux process tests are explicit there."""

import importlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def process_owner(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("canvas_worker_owned_process")


@pytest.fixture
def kernel(process_owner, monkeypatch):
    state = SimpleNamespace(
        pid=4321,
        pgid=4321,
        sid=4321,
        status=None,
        reaped=False,
        now=0.0,
        events=[],
        error=None,
    )

    def checked(phase, value):
        if state.error == phase:
            raise OSError("private-kernel-error-sentinel")
        return value

    def waitid(kind, pid, flags):
        state.events.append(("waitid", kind, pid, flags))
        checked("waitid", None)
        if state.reaped:
            raise ChildProcessError("private-reaped-child-sentinel")
        if state.status is None:
            return None
        return SimpleNamespace(
            si_pid=state.pid,
            si_code=1 if state.status >= 0 else 2,
            si_status=abs(state.status),
        )

    def killpg(pgid, signal):
        state.events.append(("killpg", pgid, signal))
        checked("killpg", None)
        if state.status is None:
            state.status = -signal

    class Child:
        def __init__(self, command, **options):
            state.events.append(("start", command, options))
            self.pid = state.pid
            self.returncode = None

        def poll(self):
            pytest.fail("Popen.poll would prematurely reap the pinned leader")

        def wait(self, timeout):
            state.events.append(("reap", timeout))
            checked("reap", None)
            if state.status is None:
                raise subprocess.TimeoutExpired("private-child-command", timeout)
            state.reaped = True
            self.returncode = state.status
            return self.returncode

        def kill(self):
            state.events.append(("direct-kill", self.pid))
            state.status = -9

    monkeypatch.setattr(process_owner, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(process_owner, "signal", SimpleNamespace(SIGKILL=9))
    monkeypatch.setattr(
        process_owner,
        "os",
        SimpleNamespace(
            name="posix",
            PathLike=os.PathLike,
            getpid=lambda: 99,
            getpgrp=lambda: 99,
            getpgid=lambda pid: checked("getpgid", state.pgid if pid != 99 else 99),
            getsid=lambda pid: checked("getsid", state.sid if pid != 99 else 99),
            waitid=waitid,
            killpg=killpg,
            P_PID=1,
            WEXITED=4,
            WNOHANG=1,
            WNOWAIT=0x1000000,
            CLD_EXITED=1,
            CLD_KILLED=2,
            CLD_DUMPED=3,
        ),
    )
    monkeypatch.setattr(
        process_owner,
        "subprocess",
        SimpleNamespace(Popen=Child, TimeoutExpired=subprocess.TimeoutExpired),
    )
    monkeypatch.setattr(
        process_owner,
        "time",
        SimpleNamespace(
            monotonic=lambda: state.now,
            sleep=lambda seconds: setattr(state, "now", state.now + seconds),
        ),
    )
    return state


def test_owned_launch_creates_one_dedicated_session(process_owner, kernel):
    child = process_owner.OwnedProcess(["synthetic", "private-command-sentinel"])
    assert child.pid == kernel.pid
    [started] = [event for event in kernel.events if event[0] == "start"]
    assert started[2]["start_new_session"] is True
    assert child.poll() is None
    assert not kernel.reaped
    child.cleanup()


@pytest.mark.parametrize(
    "option,value",
    [
        ("shell", True),
        ("preexec_fn", lambda: None),
        ("process_group", 0),
        ("start_new_session", False),
    ],
)
def test_callers_cannot_override_process_containment(
    process_owner, kernel, option, value
):
    with pytest.raises((ValueError, process_owner.OwnedProcessError)):
        process_owner.OwnedProcess(["synthetic"], **{option: value})
    assert kernel.events == []


@pytest.mark.parametrize("status", [0, 1, -9])
def test_terminal_poll_pins_leader_until_group_cleanup_then_reap(
    process_owner, kernel, status
):
    child = process_owner.OwnedProcess(["synthetic"])
    kernel.status = status
    assert child.poll() == child.poll() == status
    assert child.returncode == status and not kernel.reaped
    wait_events = [event for event in kernel.events if event[0] == "waitid"]
    assert wait_events and all(event[3] & 0x1000000 for event in wait_events)
    assert child.wait(timeout=1) == status
    assert kernel.reaped
    phases = [event[0] for event in kernel.events]
    assert phases.index("killpg") < phases.index("reap")
    assert [event[1] for event in kernel.events if event[0] == "killpg"] == [4321]
    before = list(kernel.events)
    child.cleanup()
    assert kernel.events == before


@pytest.mark.parametrize("field,value", [("pgid", 99), ("sid", 99), ("pgid", 7777)])
def test_wrong_owner_is_rejected_without_any_group_signal(
    process_owner, kernel, field, value
):
    child = process_owner.OwnedProcess(["synthetic"])
    setattr(kernel, field, value)
    with pytest.raises(process_owner.OwnedProcessError) as caught:
        child.kill()
    assert not any(event[0] == "killpg" for event in kernel.events)
    assert "private" not in str(caught.value)


def test_externally_reaped_leader_cannot_authorize_group_signal(process_owner, kernel):
    child = process_owner.OwnedProcess(["synthetic"])
    kernel.reaped = True
    with pytest.raises(process_owner.OwnedProcessError):
        child.kill()
    assert not any(event[0] == "killpg" for event in kernel.events)


def test_observed_wrong_child_cannot_authorize_group_signal(process_owner, kernel):
    child = process_owner.OwnedProcess(["synthetic"])
    kernel.status = 0
    kernel.pid = 7777
    with pytest.raises(process_owner.OwnedProcessError):
        child.kill()
    assert not any(event[0] == "killpg" for event in kernel.events)


@pytest.mark.parametrize("method", ["wait", "cleanup"])
@pytest.mark.parametrize(
    "timeout", [-1, True, float("nan"), float("inf"), "1", 10**500]
)
def test_invalid_wait_budget_has_no_process_effect(
    process_owner, kernel, method, timeout
):
    child = process_owner.OwnedProcess(["synthetic"])
    before = list(kernel.events)
    with pytest.raises(process_owner.OwnedProcessError):
        getattr(child, method)(timeout=timeout)
    assert kernel.events == before


def test_pid_cannot_be_reassigned_to_an_unowned_group(process_owner, kernel):
    child = process_owner.OwnedProcess(["synthetic"])
    with pytest.raises(AttributeError):
        child.pid = 7777
    assert child.pid == 4321


def test_non_linux_rejected_before_launch(process_owner, kernel, monkeypatch):
    monkeypatch.setattr(process_owner, "sys", SimpleNamespace(platform="win32"))
    with pytest.raises(process_owner.OwnedProcessError):
        process_owner.OwnedProcess(["synthetic"])
    assert kernel.events == []


@pytest.mark.parametrize("phase", ["waitid", "getpgid", "getsid", "killpg", "reap"])
def test_cleanup_errors_are_static_and_never_claim_reaping(
    process_owner, kernel, phase
):
    child = process_owner.OwnedProcess(["synthetic", "private-command-sentinel"])
    kernel.error = phase
    with pytest.raises(process_owner.OwnedProcessError) as caught:
        child.cleanup()
    assert "private" not in str(caught.value)
    assert not kernel.reaped


def test_wait_timeout_keeps_owned_group_for_explicit_cleanup(process_owner, kernel):
    child = process_owner.OwnedProcess(["synthetic", "private-command-sentinel"])
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        child.wait(timeout=0.1)
    assert "private" not in str(caught.value)
    assert not kernel.reaped
    assert not any(event[0] == "killpg" for event in kernel.events)
    child.cleanup(timeout=1)
    assert kernel.reaped


@pytest.mark.skipif(
    sys.platform != "linux", reason="Requires Linux waitid and subreaper"
)
@pytest.mark.parametrize("leader_exits", [False, True])
def test_real_coordinator_and_grandchild_are_both_reaped(tmp_path, leader_exits):
    # The dedicated supervisor (not pytest or the machine) adopts its own
    # orphaned grandchild, allowing exact waitpid proof rather than accepting
    # a zombie as evidence that the process has disappeared.
    code = r"""
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
sys.path.insert(0, sys.argv[1])
from canvas_worker_owned_process import OwnedProcess
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(36, 1, 0, 0, 0) == 0
pid_file = Path(sys.argv[2])
leader_exits = sys.argv[3] == "True"
grandchild_code = "import time; time.sleep(60)"
leader_code = (
    "import pathlib,subprocess,sys,time; "
    "child=subprocess.Popen([sys.executable,'-c',sys.argv[2]]); "
    "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
    + ("sys.exit(0)" if leader_exits else "time.sleep(60)")
)
owner = OwnedProcess(
    [sys.executable, "-c", leader_code, str(pid_file), grandchild_code],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
grandchild = None
grandchild_fd = None
unrelated = subprocess.Popen(
    [sys.executable, "-c", grandchild_code],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
def supervisor_timeout(_signal, _frame):
    raise TimeoutError("Owned process test supervisor exceeded its observation budget")
signal.signal(signal.SIGALRM, supervisor_timeout)
signal.alarm(10)
try:
    deadline = time.monotonic() + 5
    while True:
        if pid_file.exists():
            captured = pid_file.read_text()
            if captured.isascii() and captured.isdigit():
                grandchild = int(captured)
                break
        assert time.monotonic() < deadline
        time.sleep(.01)
    assert grandchild > 1 and grandchild not in (owner.pid, os.getpid())
    assert os.getpgid(grandchild) == os.getsid(grandchild) == owner.pid
    grandchild_fd = os.pidfd_open(grandchild)
    if leader_exits:
        while owner.poll() is None:
            assert time.monotonic() < deadline
            time.sleep(.01)
        for _ in range(2):
            retained = os.waitid(os.P_PID, owner.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            assert retained.si_pid == owner.pid
        assert owner.wait(timeout=2) == 0
    else:
        owner.cleanup(timeout=2)
    deadline = time.monotonic() + 3
    while True:
        waited, status = os.waitpid(grandchild, os.WNOHANG)
        if waited == grandchild:
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9
            break
        assert time.monotonic() < deadline
        time.sleep(.01)
    for pid in (owner.pid, grandchild):
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise AssertionError("owned child was not reaped")
        assert not Path(f"/proc/{pid}").exists()
    owner.cleanup()
    assert unrelated.poll() is None
    print("exact owned coordinator and grandchild reaped")
finally:
    signal.alarm(0)
    try:
        owner.cleanup(timeout=2)
    finally:
        if grandchild_fd is not None:
            try:
                signal.pidfd_send_signal(grandchild_fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(grandchild_fd)
        unrelated.kill()
        unrelated.wait(timeout=2)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            str(ROOT / "scripts"),
            str(tmp_path / "child.pid"),
            str(leader_exits),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        # Ordinary observation timeout raises inside the supervisor and unwinds
        # its finally. This outer limit is only a catastrophic fallback, not a
        # guarantee against uncatchable death of the surviving owner itself.
        timeout=25,
        env=dict(os.environ),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "exact owned coordinator and grandchild reaped"
    assert result.stderr == ""
