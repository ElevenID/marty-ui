"""Production orchestration boundaries with isolated native/browser test doubles."""
import copy
from pathlib import Path
import shlex
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_installer_startup_observation import startup_case, staged, put
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import installer_acceptance_startup as startup
import installer_startup_browser as browser
import installer_browser_runtime as runtime
import installer_release as r


@pytest.mark.parametrize('failure',[None,'browser','source-change','active-ended','native-challenge','selection-change'])
def test_collector_runs_challenged_native_browser_native_and_host_owners_before_writing(startup_case,monkeypatch,failure):
    c=startup_case;calls=[];source_checks=[]
    output=c.root/'collect';output.mkdir(mode=0o700)
    class Sources:
        root=Path(__file__).resolve().parents[1]
        def __init__(self,sha):assert sha==c.context['harness_source_sha']
        def check(self):
            source_checks.append(True)
            if failure=='source-change' and len(calls)>1:raise ValueError('simulated signed harness change')
        def __enter__(self):return self
        def __exit__(self,*_):pass
    monkeypatch.setattr(startup,'HarnessSources',Sources)
    class Client:
        count=0
        def request(self,method,path):
            assert method=='GET' and path.endswith('/actions/runs/99')
            self.count+=1
            return c.completed if failure=='active-ended' and self.count>2 else c.active
    native_count=0
    def execute(argv,**kwargs):
        nonlocal native_count
        calls.append((argv,kwargs))
        remote=argv[-1]
        if 'startup-observe' not in remote:
            assert remote=='fixed reviewed host observer'
            return r.encode(c.host_after)
        native_count+=1
        args=shlex.split(remote)
        value=copy.deepcopy(c.before if native_count==1 else c.after)
        value['request']=dict(observation_id=args[args.index('--observation-id')+1],challenge=args[args.index('--challenge')+1])
        if failure=='native-challenge':value['request']['challenge']='0'*64
        if failure=='selection-change' and native_count==2:value['selection']['configuration_sha256']='0'*64
        assert 'install-candidate' not in remote and 'acme continue' not in remote
        assert '--install-dir /home/installer/marty-install-'+c.target['installation_id'] in remote
        assert '/usr/bin/setpriv --no-new-privs --' in remote and c.context['operator_sha256'] in remote
        assert kwargs['timeout']==150 and kwargs['limit']==65536
        return r.encode(value)
    def actual_browser(**kwargs):
        calls.append(('browser',kwargs))
        assert kwargs['runtime_root']==c.root/'runtime'
        assert kwargs['harness']==Sources.root/'scripts/installer_startup_browser.cjs'
        assert native_count==1
        if failure=='browser':raise ValueError('simulated browser cleanup or rendering failure')
        value=copy.deepcopy(c.browser)
        value['request']=kwargs['native']['request']
        value['native_sha256']=r.digest(kwargs['native_raw'])
        return r.encode(value)
    monkeypatch.setattr(startup.browser,'run',actual_browser)
    options=dict(output=output,runtime_root=c.root/'runtime',artifact=c.artifact,host_raw=r.encode(c.host),
        context=c.context,target=c.target,authorization=c.authorization,receipt=c.receipt,inventory=c.inventory,pins=c.pins,
        **{k:c.options[k] for k in ('ssh','key','known_hosts','port','host','user','home')},
        bootstrap_source=None,probe_remote='fixed reviewed host observer',unchanged=lambda:None,
        guarded_execute=execute,client=Client(),clock=lambda:100020)
    if failure is None:
        report=startup.collect(**options)
        assert native_count==2 and len(calls)==4 and len(source_checks)>5
        assert (output/startup.NAME).read_bytes()==r.encode(report)
        assert report['selection']==c.before['selection']
        assert all(report[k] is False for k in ('installation_ready','functional_recovery_qualified','load_characterized'))
    else:
        with pytest.raises(ValueError):startup.collect(**options)
        assert not (output/startup.NAME).exists()


def test_browser_wrapper_uses_fixed_supervised_command_and_rechecks_runtime(startup_case,monkeypatch):
    c=startup_case;calls=[];checked=[]
    root=c.root/'runtime'
    class Runtime:
        identity=c.browser['runtime']
        node=root/'node/bin/node';chromium=root/'chrome-linux64/chrome';playwright=root/'playwright-core'
        def check(self):checked.append(True)
        def __enter__(self):return self
        def __exit__(self,*_):self.check()
    monkeypatch.setattr(runtime,'admit',lambda requested:Runtime() if requested==root else pytest.fail('runtime override'))
    output=c.root/'browser-run'
    harness=Path(__file__).resolve().parents[1]/'scripts/installer_startup_browser.cjs'
    def execute(argv,**kwargs):
        calls.append((argv,kwargs))
        assert argv==[str(root/'node/bin/node'),str(harness),'--input',str(output/'input.json'),
                      '--runtime-root',str(root),'--output',str(output/'browser.json')]
        assert kwargs['timeout']==180 and kwargs['limit']==65536
        assert set(kwargs['env'])=={'HOME','PATH','LANG','LC_ALL','XDG_CONFIG_HOME','XDG_CACHE_HOME'}
        data=r.decode((output/'input.json').read_bytes())
        assert data==browser.request(c.records['native_before'],c.before,c.browser['runtime'])
        assert 'ignoreHTTPSErrors' not in data and 'args' not in data
        put(output/'browser.json',r.encode(c.browser))
        return b''
    result=browser.run(runtime_root=root,native_raw=c.records['native_before'],native=c.before,harness=harness,
        output=output,unchanged=lambda:None,clock=lambda:100020,execute=execute)
    assert result==r.encode(c.browser) and len(calls)==1 and len(checked)>=4
    # The production default is the dedicated detached-descendant owner.
    assert browser.run.__kwdefaults__['execute'].__module__=='installer_startup_process'


@pytest.mark.parametrize('mutation',['file','same-bytes-inode','directory-away-back','unbound-bytes'])
def test_signed_harness_closure_holds_source_and_parent_identity(tmp_path,monkeypatch,mutation):
    root=tmp_path/'repo';(root/'scripts').mkdir(parents=True,mode=0o700)
    (root/'tests/browser').mkdir(parents=True,mode=0o700)
    paths=('scripts/fixed.cjs','tests/browser/package-lock.json')
    for name in paths:put(root/name,b'fixed committed source',0o644)
    monkeypatch.setattr(startup,'__file__',str(root/'scripts/installer_acceptance_startup.py'))
    monkeypatch.setattr(startup,'HARNESS_FILES',paths)
    def git(argv,**kwargs):
        assert argv[:3]==['/usr/bin/git','--no-replace-objects','-C']
        assert argv[-1].startswith('a'*40+':') and kwargs['env']['GIT_CONFIG_NOSYSTEM']=='1'
        return b'unbound checkout' if mutation=='unbound-bytes' else b'fixed committed source'
    if mutation=='unbound-bytes':
        with pytest.raises(ValueError):startup.HarnessSources('a'*40,execute=git)
        return
    with startup.HarnessSources('a'*40,execute=git) as held:
        held.check();target=root/paths[0]
        if mutation=='file':target.write_bytes(b'changed')
        elif mutation=='same-bytes-inode':target.rename(target.with_name('old.cjs'));put(target,b'fixed committed source',0o644)
        else:parent=target.parent;parent.rename(root/'moved');(root/'moved').rename(parent)
        with pytest.raises(ValueError):held.check()


def test_signed_source_closure_includes_browser_supervisor_and_code_bound_runtime_policy():
    assert {'scripts/installer_startup_browser.cjs','scripts/installer_startup_browser.py',
        'scripts/installer_startup_process.py','scripts/installer_browser_runtime.py',
        'scripts/installer_browser_runtime_policy.py','scripts/installer_browser_runtime_manifest.json',
        'scripts/installer_startup_continuation.py','scripts/installer_startup_transport.py'} <= set(startup.HARNESS_FILES)
