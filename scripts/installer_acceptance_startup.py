"""Five real startup observations, distinct from functional acceptance or Ready.

The production collector invokes the exact signed native observer and fixed real
browser. The report reader validates their complete public byte records; generic
case booleans, detached fixtures and incomplete checkpoints are not adapters.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import shlex
import stat
import tempfile
import time
import uuid

import installer_release as r
import installer_acceptance_v2 as v2
import installer_startup_observation as observation
import installer_startup_browser as browser
from installer_candidate_authorize import write_exclusive
from installer_candidate_hosting import HeldInput
from installer_host_admission import host_admission, resource_snapshot, _host_state
from installer_host_probe import command

NAME = 'installer-startup-observation.json'
MAX_BYTES = 256 * 1024
OWNER_NAMES = {'artifacts','native_before','native_after','browser','host_after'}
HARNESS_FILES = (
    'scripts/installer_acceptance_startup.py','scripts/installer_startup_observation.py',
    'scripts/installer_startup_browser.py','scripts/installer_startup_browser.cjs',
    'scripts/installer_startup_process.py',
    'scripts/installer_startup_continuation.py',
    'scripts/installer_acceptance_runner.py','scripts/installer_candidate_dispatch.py',
    'scripts/installer_acceptance_v2.py','scripts/installer_acceptance.py','scripts/installer_release.py',
    'scripts/installer_acceptance_return.py',
    'scripts/installer_startup_transport.py','scripts/installer_candidate_receipt_upload.py',
    'scripts/installer_candidate_hosting.py','scripts/installer_candidate_authorize.py',
    'scripts/installer_candidate_controller.py','scripts/installer_candidate_rendezvous.py',
    'scripts/installer_host_admission.py','scripts/installer_host_probe.py','scripts/installer_live_tls_probe.py',
    'scripts/verify_installer_provenance.py','scripts/stack_tag_gate.py',
    'scripts/installer_browser_runtime.py','scripts/installer_browser_runtime_policy.py',
    'scripts/installer_browser_runtime_manifest.json',
    'tests/installer-startup-browser/package.json','tests/installer-startup-browser/package-lock.json',
)


def decode(raw):
    r.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES,'startup report exceeds bound')
    def pairs(items):
        value={}
        for key,item in items:
            r.require(key not in value,'duplicate startup report field');value[key]=item
        return value
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid startup number')))
    r.require(type(value) is dict,'startup report must be an object')
    return value


def _run_identity(run, report):
    r.require(type(run) is dict and type(run.get('repository')) is dict
        and run['repository'].get('full_name')==r.REPOSITORY and run.get('path')==r.acceptance.WORKFLOW
        and run.get('event')=='workflow_dispatch' and run.get('head_branch')=='main'
        and run.get('head_sha')==report['harness_source_sha'] and type(run.get('id')) is int
        and run['id']==report['run_id'] and type(run.get('run_attempt')) is int
        and run['run_attempt']==report['run_attempt'], 'startup invocation differs')


def validate_active_run(run, report):
    _run_identity(run,report)
    r.require(run.get('status')=='in_progress' and run.get('conclusion') is None,
              'startup production requires the exact active invocation')


def validate_completed_run(run, report):
    _run_identity(run,report)
    r.require(run.get('status')=='completed' and run.get('conclusion')=='success',
              'startup return requires the exact completed successful invocation')


def _scope(context,target,authorization,receipt,host_raw,host):
    return dict(installation_id=target['installation_id'],engine_id=target['engine_id'],
        operator_sha256=context['operator_sha256'],authorized_at=r.decode(receipt)['consumed_at'],
        context_sha256=r.candidate_context_sha256(context),authorization_sha256=r.digest(authorization),
        controller_consumption_sha256=r.digest(receipt),host_observation_sha256=r.digest(host_raw),
        hosting=context['hosting'],runtime=host['runtime'])


def _neighbor_preservation(before,after,native):
    left,right=resource_snapshot(before),resource_snapshot(after)
    r.require(before['engine_id']==after['engine_id'] and before['runtime']==after['runtime']
        and before['rootless_resource_controls']==after['rootless_resource_controls']
        and before['docker_data_filesystem']['device']==after['docker_data_filesystem']['device']
        and all(before[k]==after[k] for k in ('docker_version','compose_version')),
        'host runtime changed across startup')
    for key in ('guest_memory_bytes','docker_memory_bytes'):
        observation.integer(after[key],minimum=v2.MIN_MEMORY_BYTES)
    owned=native['resources']
    containers={item['id'] for item in owned['containers'].values()}
    networks=set(owned['networks'].values());volumes=set(owned['volumes'])
    r.require(not containers.intersection(left['containers']) and not volumes.intersection(left['volumes'])
        and not networks.intersection(item['id'] for item in left['networks']), 'preexisting resource adoption observed')
    r.require(set(right['containers'])==set(left['containers'])|containers
        and set(right['volumes'])==set(left['volumes'])|volumes
        and {item['id'] for item in right['networks']}=={item['id'] for item in left['networks']}|networks
        and [item for item in right['networks'] if item['id'] not in networks]==left['networks']
        and set(left['images']) <= set(right['images']), 'prior resource census was not preserved')
    # Image pulls may enlarge the cache. This proves prior identities remain;
    # it does not claim neighboring workload contents or business data tests.
    return dict(before_sha256=r.digest(r.encode(left)),after_sha256=r.digest(r.encode(right)),
                preserved=True,scope='resource_identity_census',neighbor_data_qualified=False)


def _owners(report, *, context,target,authorization,receipt,inventory,pins,host):
    r.exact(report['owner_records'],OWNER_NAMES,'startup owner closure')
    raw={}
    for name,item in report['owner_records'].items():
        r.exact(item,{'sha256','record'},'actual startup owner bytes')
        r.require(type(item['record']) is str,'startup owner bytes missing')
        raw[name]=item['record'].encode()
        r.require(0<len(raw[name])<=65536 and r.digest(raw[name])==item['sha256'],'startup owner bytes changed')
    args=dict(context=context,target=target,authorization=authorization,receipt=receipt,inventory=inventory,pins=pins)
    artifact=r.decode(raw['artifacts'])
    observation.validate_artifacts(artifact,**args,now=report['observed_at'])
    before=observation.native(raw['native_before'],**args,observed_at=report['observed_at'],host_runtime=host['runtime'])
    after=observation.native(raw['native_after'],**args,observed_at=report['observed_at'],host_runtime=host['runtime'])
    r.require(before['request']!=after['request'] and artifact['completed_at']<=before['started_at'],
              'startup owner ordering differs')
    observation.stable_native(before,after)
    actual_browser=browser.validate(raw['browser'],native_raw=raw['native_before'],native=before,now=report['observed_at'])
    r.require(actual_browser['completed_at']<=after['started_at'] and after['completed_at']<=report['observed_at']
        and after['completed_at']-before['started_at']<=420, 'startup browser window differs')
    host_after=_host_state(raw['host_after'],target['engine_id'],owned_isolation=True)
    neighbors=_neighbor_preservation(host,host_after,after)
    return raw,artifact,before,after,actual_browser,neighbors


def _proofs(scope,selection,records,started_at,completed_at):
    role_record={
        'signed-artifact-verifier':'artifacts','rootless-storage-canary':'native_after',
        'native-compose':'native_after','deployment-validation':'native_after',
        'page-observation':'native_after','installed-browser':'browser',
    }
    schemas={'artifacts':observation.ARTIFACT_SCHEMA,'native_after':observation.NATIVE_SCHEMA,'browser':browser.SCHEMA}
    result={}
    for case in v2.STARTUP_CASES:
        proof=dict(schema=f'elevenid.installer-installed-{case}/v1',case=case,scope=scope,selection=selection,
            started_at=started_at,completed_at=completed_at,status='passed',checks=dict.fromkeys(v2.CASE_CHECKS[case],True),
            native_evidence={owner:dict(record=role_record[owner],sha256=r.digest(records[role_record[owner]]),
                owner_schema=schemas[role_record[owner]]) for owner in v2.CASE_OWNERS[case]})
        raw=r.encode(proof)
        result[case]=dict(name=f'installed-{case}.json',sha256=r.digest(raw),record=raw.decode())
    return result


def _validate_payload(report, *, inventory_bytes,source_sha,release_tag,phase):
    r.exact(report, {'schema','repository','source_sha','source_ref','harness_source_sha','release_tag','phase','platform',
        'inventory_sha256','workflow','run_id','run_attempt','profile','authority','host_observation','scope','selection',
        'cases','proofs','owner_records','neighbor_preservation','cleanup','observed_at','load_characterized',
        'installation_ready','functional_recovery_qualified'}, 'signed startup report')
    r.require(report['schema']==v2.SCHEMA and report['repository']==r.REPOSITORY
        and report['source_sha']==source_sha and report['release_tag']==release_tag and report['source_ref']=='refs/heads/main'
        and report['phase']==phase and phase in ('staged','published') and report['platform']=='linux/amd64'
        and report['inventory_sha256']=='sha256:'+r.digest(inventory_bytes) and report['workflow']==r.acceptance.WORKFLOW
        and report['profile']==v2.STARTUP_PROFILE
        and all(report[k] is False for k in ('load_characterized','installation_ready','functional_recovery_qualified')),
        'startup report identity or authority differs')
    r.identity(source_sha,release_tag,report['run_id'],report['run_attempt']);r.sha(report['harness_source_sha'])
    observation.integer(report['observed_at'],minimum=1)
    authority=r.exact(report['authority'],{'authorization','controller_consumption','authenticated_evidence_sha256'},'startup authority')
    r.require(type(authority['authorization']) is str and type(authority['controller_consumption']) is str,'startup grant bytes missing')
    authorization,receipt=authority['authorization'].encode(),authority['controller_consumption'].encode()
    auth,consumed=r.decode(authorization),r.decode(receipt)
    context=r.candidate_context(auth)
    r.require(all(context[key]==report[key] for key in ('source_sha','release_tag','harness_source_sha','run_id','run_attempt','phase')),
              'startup signed invocation differs')
    target={key:consumed[key] for key in ('guest_id','disk_id','engine_id','installation_id')}
    pins=authority['authenticated_evidence_sha256']
    observation.authority(context=context,target=target,authorization=authorization,receipt=receipt,inventory=inventory_bytes,
                          pins=pins,now=report['observed_at'])
    r.require(type(report['host_observation']) is str,'startup pre-pull observation missing')
    host_raw=report['host_observation'].encode()
    host=host_admission(host_raw,target['engine_id'],profile=v2.STARTUP_PROFILE)
    scope=_scope(context,target,authorization,receipt,host_raw,host)
    r.require(report['scope']==scope,'startup report scope differs')
    observation.current_selection(report['selection'])
    records,artifact,before,after,actual_browser,neighbors=_owners(report,context=context,target=target,
        authorization=authorization,receipt=receipt,inventory=inventory_bytes,pins=pins,host=host)
    r.require(report['selection']==after['selection'] and report['cases']==dict.fromkeys(v2.STARTUP_CASES,'passed')
        and report['proofs']==_proofs(scope,after['selection'],records,artifact['started_at'],after['completed_at'])
        and report['neighbor_preservation']==neighbors,'startup derived assertions differ from actual owners')
    r.require(report['cleanup']==dict(performed=False,recovery_retention_verified=False,
        owned_containers_remaining=None,owned_networks_remaining=None,owned_volumes_remaining=None),
        'startup cannot claim cleanup qualification')
    r.require(len(r.encode(report))<=MAX_BYTES,'startup report exceeds bound')
    return report


def validate_active_payload(report, *, run, **expected):
    validate_active_run(run,report)
    return _validate_payload(report,**expected)


def validate_completed_return(report, *, run, **expected):
    validate_completed_run(run,report)
    return _validate_payload(report,**expected)


def _assemble(*, records,context,target,authorization,receipt,inventory,pins,host_raw,observed_at):
    host=host_admission(host_raw,target['engine_id'],profile=v2.STARTUP_PROFILE)
    scope=_scope(context,target,authorization,receipt,host_raw,host)
    artifact=r.decode(records['artifacts']);after=r.decode(records['native_after'])
    report=dict(schema=v2.SCHEMA,repository=r.REPOSITORY,source_sha=context['source_sha'],source_ref='refs/heads/main',
        harness_source_sha=context['harness_source_sha'],release_tag=context['release_tag'],phase=context['phase'],
        platform='linux/amd64',inventory_sha256='sha256:'+r.digest(inventory),workflow=r.acceptance.WORKFLOW,
        run_id=context['run_id'],run_attempt=context['run_attempt'],profile=v2.STARTUP_PROFILE,
        authority=dict(authorization=authorization.decode(),controller_consumption=receipt.decode(),authenticated_evidence_sha256=pins),
        host_observation=host_raw.decode(),scope=scope,selection=after['selection'],cases=dict.fromkeys(v2.STARTUP_CASES,'passed'),
        proofs=_proofs(scope,after['selection'],records,artifact['started_at'],after['completed_at']),
        owner_records={name:dict(sha256=r.digest(raw),record=raw.decode()) for name,raw in records.items()},
        neighbor_preservation=_neighbor_preservation(host,_host_state(records['host_after'],target['engine_id'],owned_isolation=True),after),
        cleanup=dict(performed=False,recovery_retention_verified=False,owned_containers_remaining=None,
                     owned_networks_remaining=None,owned_volumes_remaining=None),
        observed_at=observed_at,load_characterized=False,installation_ready=False,functional_recovery_qualified=False)
    return report


class HarnessSources:
    """Exact fixed source closure from the authenticated harness commit, held across execution."""
    def __init__(self,source_sha,*,execute=command):
        r.sha(source_sha)
        self.root=Path(__file__).resolve().parent.parent
        self.handles=[]
        self.parents={}
        try:
            with tempfile.TemporaryDirectory(prefix='marty-startup-source-') as home:
                for name in HARNESS_FILES:
                    path=self.root/name
                    r.require(not any(p.is_symlink() for p in (path,*path.parents)),'startup harness source is linked')
                    for parent in (self.root,*reversed([p for p in path.parents if p!=self.root and self.root in p.parents])):
                        if parent not in self.parents:
                            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                            info=os.fstat(fd)
                            self.parents[parent]=(fd,self._stamp(info))
                            r.require(info.st_uid in (0,os.geteuid()) and not info.st_mode&0o022,
                                      'startup source directory ownership differs')
                    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                    self.handles.append((path,fd,None,None))
                    info=os.fstat(fd)
                    r.require(stat.S_ISREG(info.st_mode) and info.st_uid in (0,os.geteuid())
                        and not info.st_mode&0o022 and info.st_nlink==1 and 0<info.st_size<=1024*1024,
                        'startup harness source permissions differ')
                    raw=os.pread(fd,1024*1024+1,0)
                    expected=execute(['/usr/bin/git','--no-replace-objects','-C',str(self.root),'show',source_sha+':'+name],
                        env=dict(HOME=home,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',GIT_NO_REPLACE_OBJECTS='1',
                                 GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null'),timeout=15,limit=1024*1024)
                    r.require(raw==expected,'startup harness differs from the signed source')
                    self.handles[-1]=(path,fd,self._stamp(info),raw)
            self.check()
        except BaseException:
            self.close();raise
    @staticmethod
    def _stamp(info):
        return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    def check(self):
        for path,(fd,stamp) in self.parents.items():
            r.require(self._stamp(os.fstat(fd))==stamp==self._stamp(path.lstat()),
                      'held startup source directory changed')
        for path,fd,stamp,raw in self.handles:
            r.require(self._stamp(os.fstat(fd))==stamp==self._stamp(path.lstat())
                and not any(p.is_symlink() for p in path.parents)
                and os.pread(fd,len(raw)+1,0)==raw,'held startup harness changed')
    def close(self):
        for _,fd,_,_ in self.handles:os.close(fd)
        self.handles=[]
        for fd,_ in self.parents.values():os.close(fd)
        self.parents={}
    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def collect(*,output,runtime_root,artifact,host_raw,context,target,authorization,receipt,inventory,pins,
            ssh,key,known_hosts,port,host,user,home,bootstrap_source,probe_remote,unchanged,guarded_execute,
            client,clock=time.time):
    import installer_candidate_dispatch as dispatch
    import installer_candidate_rendezvous as transport
    host_before=host_admission(host_raw,target['engine_id'],profile=v2.STARTUP_PROFILE)
    args=dict(context=context,target=target,authorization=authorization,receipt=receipt,inventory=inventory,pins=pins)
    observation.authority(**args,now=int(clock()))
    records={'artifacts':r.encode(artifact)}
    expected_run={key:context[key] for key in ('harness_source_sha','run_id','run_attempt')}
    def active():
        result=client.request('GET',transport.REPO+'/actions/runs/'+str(context['run_id']))
        validate_active_run(result,expected_run)
        return result
    base,_,_=dispatch.remote_plan(home,user,context,target,authorization=authorization,bootstrap_source=bootstrap_source)
    operator=base+('/bootstrap/marty-deploy-linux-amd64' if context['phase']=='published' else '/marty-deploy')
    installation=home+'/marty-install-'+target['installation_id']
    remote_prefix=('set -eu; PATH=/usr/bin:/bin; export PATH; test "$(id -un)" = '+shlex.quote(user)+'; '
        'printf "%s  %s\\n" '+shlex.quote(context['operator_sha256'])+' '+shlex.quote(operator)
        +' | /usr/bin/sha256sum --check --status --strict; exec env -i HOME='+shlex.quote(home)
        +' PATH=/usr/bin:/bin /usr/bin/setpriv --no-new-privs -- '+shlex.quote(operator))
    with HarnessSources(context['harness_source_sha']) as sources, ExitStack() as held:
        retained=[]
        def check():unchanged();sources.check()
        def retain(name,raw):
            r.require(type(raw) is bytes and 0<len(raw)<=65536,'startup owner result exceeds bound')
            path=output/('startup-'+name.replace('_','-')+'.json')
            write_exclusive(path,raw)
            item=held.enter_context(HeldInput(path,65536));r.require(item.check()==raw,'startup owner changed')
            retained.append((item,raw))
            records[name]=raw
        def reobserve(name):
            observation_request=dict(observation_id=str(uuid.uuid4()),challenge=secrets.token_hex(32))
            invocation=remote_prefix+' startup-observe --install-dir '+shlex.quote(installation)
            invocation+=' --docker-bin /usr/bin/docker --observation-id '+observation_request['observation_id']+' --challenge '+observation_request['challenge']
            check();active()
            with tempfile.TemporaryDirectory(prefix='marty-startup-native-') as private:
                raw=guarded_execute([str(ssh),*dispatch.ssh_options(key,known_hosts,port),'-T',user+'@'+host,invocation],
                    env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=150,limit=65536)
            check()
            value=observation.native(raw,**args,observed_at=int(clock()),expected_request=observation_request,host_runtime=host_before['runtime'])
            retain(name,raw);return value
        active();check();retain('artifacts',records['artifacts'])
        before=reobserve('native_before')
        raw=browser.run(runtime_root=runtime_root,native_raw=records['native_before'],native=before,
            harness=sources.root/'scripts/installer_startup_browser.cjs',output=output/'startup-browser-runtime',
            unchanged=check,clock=clock)
        retain('browser',raw)
        after=reobserve('native_after');observation.stable_native(before,after)
        check()
        with tempfile.TemporaryDirectory(prefix='marty-startup-host-') as private:
            host_after=guarded_execute([str(ssh),*dispatch.ssh_options(key,known_hosts,port),'-T',user+'@'+host,probe_remote],
                env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120,limit=65536)
        retain('host_after',host_after);check()
        report=_assemble(records=records,**args,host_raw=host_raw,observed_at=int(clock()))
        validate_active_payload(report,inventory_bytes=inventory,source_sha=context['source_sha'],release_tag=context['release_tag'],
                                phase=context['phase'],run=active())
        # Each exact public owner record remains under a held private descriptor.
        for item,raw in retained:
            r.require(item.check()==raw,'retained startup owner bytes changed')
        check();write_exclusive(output/NAME,r.encode(report));check()
        return report
