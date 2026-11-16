"""Real isolated-owner tests; no Chromium, network, Docker, or host setup."""
import io
import builtins
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import installer_startup_process as owner

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux subreaper ownership")


@pytest.fixture
def kernel_owner():
    try:
        owner._kernel_view()
    except (OSError, ValueError):
        pytest.skip("requires /proc and process IDs from the same Linux PID namespace")
    return owner


def environment(path):
    return dict(HOME=str(path), PATH="/usr/bin:/bin", LANG="C", LC_ALL="C")


def invocation(code, *arguments):
    return [sys.executable, "-I", "-S", "-c", code, *map(str, arguments)]


def no_processes(record):
    value = json.loads(record.read_text())
    for key in ("leader", "child", "grandchild", "supervisor"):
        if key in value:
            assert not Path(f"/proc/{value[key]}").exists(), (key, value[key])


# The launcher and child intentionally use different sessions. The child forks
# a grandchild in another session, then remains alive so that cleanup must kill
# and reap multiple adoption waves. Every PID is recorded before the launcher
# can exit. Closing pipes proves EOF alone cannot be used as cleanup evidence.
TREE = r"""
import json,os,pathlib,signal,sys,time
record=pathlib.Path(sys.argv[1]); mode=sys.argv[2]; close_pipes=sys.argv[3]=='True'
leader=os.getpid(); supervisor=os.getppid()
ready_read,ready_write=os.pipe()
child=os.fork()
if child==0:
    os.close(ready_read);os.setsid()
    child=os.getpid()
    inner_read,inner_write=os.pipe()
    grandchild=os.fork()
    if grandchild==0:
        os.close(inner_read);os.setsid()
        if close_pipes:
            os.close(1);os.close(2)
        os.write(inner_write,b'r');os.close(inner_write)
        while True: time.sleep(1)
    os.close(inner_write);assert os.read(inner_read,1)==b'r';os.close(inner_read)
    record.write_text(json.dumps(dict(leader=leader,supervisor=supervisor,child=child,grandchild=grandchild)))
    os.write(ready_write,b'r');os.close(ready_write)
    if close_pipes:
        os.close(1);os.close(2)
    while True: time.sleep(1)
os.close(ready_write);assert os.read(ready_read,1)==b'r';os.close(ready_read)
if mode=='success':
    print('complete',flush=True);os._exit(0)
if mode=='failure':
    print('private-stderr-sentinel',file=sys.stderr,flush=True);os._exit(7)
if mode=='killed': os.kill(os.getpid(),signal.SIGKILL)
if mode=='stdout-overflow': os.write(1,b'x'*32768)
if mode=='stderr-overflow': os.write(2,b'private-stderr-sentinel'*2048)
while True: time.sleep(1)
"""


def test_success_returns_only_stdout_and_reaps_the_owner(kernel_owner, tmp_path):
    before = set(os.listdir("/proc/self/fd"))
    children = owner._direct_pids()
    result = kernel_owner.command(invocation(
        "import os,sys; print(os.getcwd()); print('private-stderr-sentinel',file=sys.stderr)"),
        env=environment(tmp_path), timeout=5)
    assert result == (str(tmp_path) + "\n").encode()
    assert set(os.listdir("/proc/self/fd")) == before
    assert owner._direct_pids() == children


@pytest.mark.parametrize("close_pipes", [False, True])
@pytest.mark.parametrize("mode", ["success", "failure", "killed", "timeout"])
def test_detached_tree_is_killed_and_reaped_after_launcher_exit_or_timeout(
    kernel_owner, tmp_path, mode, close_pipes
):
    record = tmp_path / "pids.json"
    started = time.monotonic()
    if mode == "success":
        assert kernel_owner.command(invocation(TREE, record, mode, close_pipes),
            env=environment(tmp_path), timeout=3) == b"complete\n"
    else:
        with pytest.raises(owner.ProcessError) as caught:
            kernel_owner.command(invocation(TREE, record, mode, close_pipes),
                env=environment(tmp_path), timeout=0.6 if mode == "timeout" else 3)
        assert not isinstance(caught.value, owner.CleanupPending)
        assert "private" not in str(caught.value)
    assert time.monotonic() - started < 5
    no_processes(record)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_both_output_streams_share_a_bound_and_overflow_cleans_detached_tree(
    kernel_owner, tmp_path, stream
):
    record = tmp_path / "pids.json"
    with pytest.raises(owner.ProcessError) as caught:
        kernel_owner.command(invocation(TREE, record, stream + "-overflow", True),
            env=environment(tmp_path), timeout=3, limit=1024)
    assert not isinstance(caught.value, owner.CleanupPending)
    assert "private" not in str(caught.value)
    no_processes(record)


def test_orphaned_double_fork_is_adopted_before_launcher_finishes(kernel_owner, tmp_path):
    record = tmp_path / "pids.json"
    code = r"""
import json,os,pathlib,sys,time
record=pathlib.Path(sys.argv[1]);leader=os.getpid();supervisor=os.getppid()
r,w=os.pipe();child=os.fork()
if child==0:
    os.close(r);os.setsid();grandchild=os.fork()
    if grandchild:
        os._exit(0)
    os.setsid();os.close(1);os.close(2)
    record.write_text(json.dumps(dict(leader=leader,supervisor=supervisor,grandchild=os.getpid())))
    os.write(w,b'r');os.close(w)
    while True:time.sleep(1)
os.close(w);assert os.read(r,1)==b'r';os.close(r);os.waitpid(child,0)
print('orphan-created',flush=True)
"""
    assert kernel_owner.command(invocation(code, record), env=environment(tmp_path), timeout=3) == b"orphan-created\n"
    no_processes(record)


def test_threaded_caller_does_not_inherit_python_locks(kernel_owner, tmp_path):
    # A held application lock and simultaneous live Python threads are normal
    # controller conditions. No preexec_fn or Python supervisor executes in a
    # fork of that interpreter; the owner is a fresh -I -S process.
    lock = threading.Lock()
    lock.acquire()
    barrier = threading.Barrier(3)
    results, errors = [], []

    def run():
        try:
            barrier.wait(timeout=3)
            results.append(kernel_owner.command(invocation("print('thread-safe')"),
                env=environment(tmp_path), timeout=3))
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=3)
    for thread in threads:
        thread.join(timeout=5)
    lock.release()
    assert not any(thread.is_alive() for thread in threads)
    assert not errors and results == [b"thread-safe\n", b"thread-safe\n"]


def test_keyboard_interrupt_waits_for_owned_tree_cleanup(kernel_owner, tmp_path):
    record = tmp_path / "pids.json"
    code = r"""
import os,pathlib,signal,sys,threading,time
sys.path.insert(0,sys.argv[1]);import installer_startup_process as owner
record=pathlib.Path(sys.argv[2])
def cancel():
    deadline=time.monotonic()+5
    while not record.exists():
        assert time.monotonic()<deadline;time.sleep(.01)
    os.kill(os.getpid(),signal.SIGINT)
thread=threading.Thread(target=cancel);thread.start()
try:
    owner.command([sys.executable,'-I','-S','-c',sys.argv[3],str(record),'timeout','True'],
        env=dict(HOME=str(record.parent),PATH='/usr/bin:/bin'),timeout=10)
except KeyboardInterrupt:
    print('cancelled-after-cleanup',flush=True)
else: raise AssertionError('cancellation was lost')
thread.join(timeout=1)
"""
    result = subprocess.run(invocation(code, SCRIPTS, record, TREE),
        env=environment(tmp_path), capture_output=True, timeout=12, check=True)
    assert result.stdout == b"cancelled-after-cleanup\n" and result.stderr == b""
    no_processes(record)


@pytest.mark.parametrize("death_signal", [signal.SIGTERM, signal.SIGKILL])
def test_caller_death_leaves_supervisor_to_reap_detached_descendants(
    kernel_owner, tmp_path, death_signal
):
    record = tmp_path / "pids.json"
    # An independent fixture reaper adopts only the supervisor after killing
    # its controller. This makes the test independent of the machine's PID1
    # zombie-reaping policy and lets it prove the supervisor itself was reaped.
    driver = r"""
import os,pathlib,signal,subprocess,sys,time
sys.path.insert(0,sys.argv[1]);import installer_startup_process as owner
owner._prctl(36,1)
record=pathlib.Path(sys.argv[2]);tree=owner._Tree()
controller=r'''
import pathlib,sys
sys.path.insert(0,sys.argv[1]);import installer_startup_process as owner
record=pathlib.Path(sys.argv[2])
owner.command([sys.executable,'-I','-S','-c',sys.argv[3],str(record),'timeout','True'],
    env=dict(HOME=str(record.parent),PATH='/usr/bin:/bin'),timeout=15)
'''
child=subprocess.Popen([sys.executable,'-I','-S','-c',controller,sys.argv[1],str(record),sys.argv[3]],
    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    deadline=time.monotonic()+5
    while not record.exists():
        assert time.monotonic()<deadline;time.sleep(.01)
    os.kill(child.pid,int(sys.argv[4]));child.wait(timeout=2)
    deadline=time.monotonic()+5
    while True:
        try: pid,status=os.waitpid(-1,os.WNOHANG)
        except ChildProcessError: break
        assert time.monotonic()<deadline
        if not pid:time.sleep(.01)
    print('caller-death-cleaned',flush=True)
finally:
    deadline=time.monotonic()+5
    while True:
        tree.kill_direct()
        if tree.reap():break
        assert time.monotonic()<deadline;time.sleep(.01)
"""
    result = subprocess.run(invocation(driver, SCRIPTS, record, TREE, int(death_signal)),
        env=environment(tmp_path), capture_output=True, timeout=15, check=True)
    assert result.stdout == b"caller-death-cleaned\n" and result.stderr == b""
    no_processes(record)


@pytest.mark.parametrize("timeout", [-1, 0, True, float("inf"), float("nan"), 10**500, "1", 301])
def test_invalid_budget_never_launches_a_supervisor(monkeypatch, tmp_path, timeout):
    monkeypatch.setattr(owner.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("unexpected launch"))
    with pytest.raises(owner.ProcessError):
        owner.command(invocation("pass"), env=environment(tmp_path), timeout=timeout)


@pytest.mark.parametrize("fault", ["argv-string", "relative-executable", "nul", "home", "env", "limit", "bool-limit"])
def test_invalid_command_shape_never_launches(monkeypatch, tmp_path, fault):
    argv, env, limit = invocation("pass"), environment(tmp_path), 65536
    if fault == "argv-string": argv = "python -c pass"
    elif fault == "relative-executable": argv[0] = "python"
    elif fault == "nul": argv[1] = "private\0sentinel"
    elif fault == "home": env["HOME"] = "relative"
    elif fault == "env": env["BAD=KEY"] = "private-sentinel"
    elif fault == "limit": limit = 2 * 1024 * 1024
    elif fault == "bool-limit": limit = True
    monkeypatch.setattr(owner.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("unexpected launch"))
    with pytest.raises(owner.ProcessError):
        owner.command(argv, env=env, limit=limit)


def test_outer_namespace_proc_mount_is_refused_before_launch(monkeypatch, tmp_path):
    monkeypatch.setattr(owner.os, "readlink", lambda path: str(os.getpid() + 1))
    monkeypatch.setattr(owner.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("unexpected launch"))
    with pytest.raises(owner.ProcessError):
        owner.command(invocation("pass"), env=environment(tmp_path))


def test_changed_starttime_cannot_authorize_a_signal(monkeypatch):
    identities = iter([(os.getpid(), 1), (os.getpid(), 1), (os.getpid(), 2)])
    monkeypatch.setattr(owner, "_identity", lambda _: next(identities))
    monkeypatch.setattr(owner.os, "pidfd_open", lambda *args: os.open("/dev/null", os.O_RDONLY))
    monkeypatch.setattr(owner.signal, "pidfd_send_signal", lambda *args: pytest.fail("unowned signal"))
    child = owner._Child(12345)
    try:
        with pytest.raises(owner.ProcessError): child.kill()
    finally:
        child.close()


def test_process_comm_cannot_shift_the_retained_starttime(monkeypatch):
    values = [b"S", b"456"] + [b"0"] * 17 + [b"789"] + [b"0"] * 4
    raw = b"123 (name with ) spaces) " + b" ".join(values)
    monkeypatch.setattr(owner, "open", lambda *args, **kwargs: io.BytesIO(raw), raising=False)
    assert owner._identity(123) == (456, 789)


def test_configuration_is_sealed_before_the_fresh_supervisor_receives_it(tmp_path):
    value = dict(argv=invocation("pass"), env=environment(tmp_path), timeout=1,
                 limit=1024, parent=os.getpid(), deadline=time.monotonic() + 1)
    descriptor = owner._config_fd(value)
    try:
        assert owner._read_config(descriptor) == value
        with pytest.raises(OSError): os.pwrite(descriptor, b"changed", 0)
        with pytest.raises(OSError): os.ftruncate(descriptor, 1)
    finally:
        os.close(descriptor)


def test_missing_optional_children_file_uses_exact_live_parent_identity(
    kernel_owner, tmp_path, monkeypatch
):
    child = subprocess.Popen(invocation("import time;time.sleep(30)"),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=environment(tmp_path))
    fd = os.pidfd_open(child.pid, 0)
    calls = []

    def without_optional_file(path, *args, **kwargs):
        if str(path).endswith("/children"):
            calls.append(str(path))
            raise FileNotFoundError(2, "optional kernel interface unavailable")
        return builtins.open(path, *args, **kwargs)

    monkeypatch.setattr(owner, "open", without_optional_file, raising=False)
    try:
        children = owner._direct_pids()
        assert calls and child.pid in children
        assert os.getpid() not in children and os.getppid() not in children
        assert all(owner._identity(pid)[0] == os.getpid() for pid in children)
    finally:
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        child.wait(timeout=3)
        os.close(fd)


def test_cleaning_browser_tree_preserves_unrelated_caller_child(kernel_owner, tmp_path):
    neighbor = subprocess.Popen(invocation("import time;time.sleep(30)"),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=environment(tmp_path))
    fd = os.pidfd_open(neighbor.pid, 0)
    record = tmp_path / "pids.json"
    try:
        assert kernel_owner.command(invocation(TREE, record, "success", True),
            env=environment(tmp_path), timeout=3) == b"complete\n"
        assert neighbor.poll() is None
        assert owner._identity(neighbor.pid)[0] == os.getpid()
        no_processes(record)
    finally:
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        neighbor.wait(timeout=3)
        os.close(fd)


def test_census_failure_is_preflighted_before_any_launch(monkeypatch, tmp_path):
    monkeypatch.setattr(owner.os, "readlink", lambda _: str(os.getpid()))
    monkeypatch.setattr(owner, "_identity", lambda _: (os.getppid(), 123))

    def unavailable():
        raise PermissionError(13, "private-kernel-error")

    monkeypatch.setattr(owner, "_direct_pids", unavailable)
    monkeypatch.setattr(owner.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("unexpected launch"))
    with pytest.raises(owner.ProcessError) as caught:
        owner.command(invocation("pass"), env=environment(tmp_path))
    assert "private" not in str(caught.value)


def test_persistent_census_failure_keeps_reaping_and_reports_pending(monkeypatch):
    now, sent, reaped = [0.0], [], []

    class Tree:
        def kill_direct(self):
            raise FileNotFoundError(2, "optional census lost")

        def reap(self):
            reaped.append(True)
            # Model later kernel-confirmed emptiness. Until then, the failed
            # scan itself must neither terminate cleanup nor prove success.
            return bool(sent)

    monkeypatch.setattr(owner.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(owner.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))
    monkeypatch.setattr(owner, "_send", lambda descriptor, status, raw=b"": sent.append((status, raw)))
    assert owner._cleanup(Tree(), None, 123) is False
    assert len(reaped) > 1 and now[0] >= owner._CLEANUP_SECONDS
    assert sent == [(owner._PENDING, b"")]
