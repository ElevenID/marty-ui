"""Deterministic engine startup waits: read-only, bounded and identity-bound."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import selfhost_windows_recovery as recovery

HOST='npipe:////./pipe/dockerDesktopLinuxEngine'
ENGINE='SYNTHETIC-ENGINE-ID'


@pytest.fixture
def clock(monkeypatch):
    now=[0.0];calls=[]
    monkeypatch.setattr(recovery.time,'monotonic',lambda:now[0])
    monkeypatch.setattr(recovery.time,'sleep',lambda seconds:now.__setitem__(0,now[0]+seconds))
    def install(responses):
        def run(args,**kwargs):
            assert args[:5]==['docker','--host',HOST,'info','--format']
            assert '{{json .ID}}' in args[-1] and 0<kwargs['timeout']<=10
            calls.append((now[0],kwargs['timeout']))
            value=responses.pop(0) if len(responses)>1 else responses[0]
            if value=='timeout':
                now[0]+=kwargs['timeout'];raise recovery.renewal.UncertainComposeMutation('synthetic timeout')
            if value=='unavailable':return subprocess.CompletedProcess(args,1,b'',b'PRIVATE_SENTINEL')
            if value=='missing':raise FileNotFoundError('PRIVATE_SENTINEL')
            return subprocess.CompletedProcess(args,0,value,b'')
        monkeypatch.setattr(recovery.renewal,'run_owned_mutation',run)
    return now,calls,install


def ready(**changes):
    return json.dumps({'OSType':'linux','ID':ENGINE,'DockerRootDir':'/var/lib/docker',**changes}).encode()


def test_wait_retries_only_unavailable_reads_then_admits_exact_engine(clock):
    now,calls,install=clock;install(['unavailable',ready()])
    recovery.wait_for_engine(HOST,ENGINE,timeout=12)
    assert now[0]==5 and len(calls)==2


@pytest.mark.parametrize('response',[ready(ID='FOREIGN'),ready(OSType='windows'),
    ready(DockerRootDir='/other'),b'{}',b'[]',b'not-json',b'{"ID":1,"ID":2}',b'x'*(1024*1024+1)],
    ids=['foreign','windows','root','missing','array','malformed','duplicate','oversized'])
def test_responding_wrong_or_malformed_engine_refuses_without_retry(clock,response):
    now,calls,install=clock;install([response])
    with pytest.raises(ValueError):recovery.wait_for_engine(HOST,ENGINE,timeout=12)
    assert now[0]==0 and len(calls)==1


def test_deadline_covers_returned_unavailability_without_any_workload_command(clock):
    now,calls,install=clock;install(['unavailable'])
    with pytest.raises(ValueError):recovery.wait_for_engine(HOST,ENGINE,timeout=12)
    assert now[0]==12 and len(calls)==3


def test_uncertain_read_cleanup_is_never_retried(clock):
    now,calls,install=clock;install(['timeout'])
    with pytest.raises(recovery.renewal.UncertainComposeMutation):
        recovery.wait_for_engine(HOST,ENGINE,timeout=12)
    assert now[0]==10 and len(calls)==1


def test_missing_cli_is_not_an_engine_startup_retry(clock):
    now,calls,install=clock;install(['missing'])
    with pytest.raises(FileNotFoundError):recovery.wait_for_engine(HOST,ENGINE,timeout=12)
    assert now[0]==0 and len(calls)==1


@pytest.mark.parametrize('host,engine,timeout',[('tcp://remote',ENGINE,12),(HOST,'bad',12),
    (HOST,ENGINE,0),(HOST,ENGINE,301),(HOST,ENGINE,True)])
def test_invalid_wait_binding_never_calls_docker(clock,host,engine,timeout):
    _now,calls,install=clock;install([ready()])
    with pytest.raises(ValueError):recovery.wait_for_engine(host,engine,timeout=timeout)
    assert not calls


@pytest.mark.skipif(os.name!='nt',reason='Actual owned Win32 job and inherited pipe')
def test_real_descendant_retaining_info_pipe_refuses_and_is_contained(monkeypatch):
    actual=recovery.renewal.run_owned_mutation;calls=[]
    def synthetic(args,**kwargs):
        assert args[:5]==['docker','--host',HOST,'info','--format']
        calls.append(args)
        code="import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);print('{}')"
        return actual([sys.executable,'-c',code],**kwargs)
    monkeypatch.setattr(recovery.renewal,'run_owned_mutation',synthetic)
    start=time.monotonic()
    with pytest.raises(recovery.renewal.UncertainComposeMutation) as error:
        recovery.wait_for_engine(HOST,ENGINE)
    assert error.value.owned_processes_zero and len(calls)==1
    assert time.monotonic()-start<15
