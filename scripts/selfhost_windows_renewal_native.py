"""Signed Linux operator transport for held Windows renewal inputs.

The caller selects an already release-verified operator; digest and embedded
source/tag identity are rechecked while the NTFS asset remains held. This does
not replace signature/provenance verification or admit a release for production.
Preflights are read-only; scoped reauthentication writes only a fresh session.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path, PurePosixPath

from selfhost_windows_inputs import hold_private_input, hold_public_input

EXPORT_CHUNK_BYTES = 12000
EXPORT_LIMIT_BYTES = 8 * 1024 * 1024

PRODUCER_PREPARE = r'''
import base64,json,os,pathlib,sys
d=json.load(sys.stdin);os.umask(0o077);root=pathlib.Path(d['root'])
root.mkdir(mode=0o700)
for name in ['source','tls','keycloak','generation']:(root/name).mkdir(mode=0o700)
for name,value in d['current'].items():
 raw=base64.b64decode(value,validate=True)
 assert len(raw)<=65536 and b'\0' not in raw and b'PRIVATE KEY' not in raw
 raw.decode('utf-8')
 fd=os.open(root/'source'/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
for folder in [root/'source',root,root.parent]:
 fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
print(json.dumps({'prepared':True}))
'''

PRODUCER_ASSEMBLE = r'''
import hashlib,json,os,pathlib,secrets,subprocess,sys
d=json.load(sys.stdin);os.umask(0o077);root=pathlib.Path(d['root']);binary='/operator/tool'
assert hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()==d['binary_sha256']
p=subprocess.run([binary,'--build-identity'],capture_output=True,timeout=20)
assert p.returncode==0 and p.stdout.decode().strip()==d['source_sha']+':'+d['release_tag']
token=pathlib.Path(d['authority']).read_text().strip()
fd=os.open(root/'keycloak-response.private.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
timed_out=False
try:
 p=subprocess.run([binary,'operator','keycloak-provision',d['bao_addr'],'/input/ca.crt'],
  input=json.dumps({'token':token,'renew':True,'pki_mount':'keycloak-pki','nonce':secrets.token_hex(6)}).encode(),
  capture_output=True,timeout=90)
 captured=p.stdout
except subprocess.TimeoutExpired as error:
 captured=error.stdout or b'';timed_out=True
with os.fdopen(fd,'wb') as f:f.write(captured);f.flush();os.fsync(f.fileno())
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:os.fsync(fd)
finally:os.close(fd)
assert not timed_out and len(captured)<=128*1024 and p.returncode==0
outputs=json.loads(captured)
expected={'keycloak_signing_kms_token','keycloak_master_rs256_cert','keycloak_11id_rs256_cert',
 *(f'keycloak_{realm}_{purpose}_token' for realm in ['master','11id'] for purpose in ['cookie','ciba'])}
assert set(outputs)==expected and len({v for k,v in outputs.items() if k.endswith('_token')})==5
for name,value in outputs.items():
 assert isinstance(value,str) and value and len(value.encode())<=65536 and '\0' not in value and 'PRIVATE KEY' not in value
 fd=os.open(root/'keycloak'/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:f.write(value);f.flush();os.fsync(f.fileno())
def call(op,body,network=False):
 args=[binary,'operator',op]
 if network:args += [d['bao_addr'],'/input/ca.crt']
 p=subprocess.run(args,input=json.dumps(body).encode(),capture_output=True,timeout=90)
 assert p.returncode==0
 return json.loads(p.stdout)
assert call('generation',{'operation':'stage','current':str(root/'source'),'tls':str(root/'tls'),
 'keycloak':str(root/'keycloak'),'output':str(root/'generation'),'ca_overlap':False})=={'value':d['files']}
assert call('generation',{'operation':'verify','current':str(root/'source'),'candidate':str(root/'generation'),
 'ca_overlap':False,'ca_retire':False})=={'value':[d['files'],39]}
body={'token':token,'old':str(root/'source'),'new':str(root/'generation'),'minimum_ttl':d['minimum_ttl'],
 'require_orphan_new':True,'require_orphan_old':False,'replacement':None,'retiring':False}
for op in ['activation-tokens','activation-certificates']:assert call(op,body,True)=={'value':None}
print(json.dumps({'files':d['files'],'changed_files':39,'native_verified':True}))
'''


def produce_generation(config,current,logical_project,cycle_id,services_image,checkpoint):
    """Produce under the selected owner's durable guard; never activate here.

    The caller holds the selected lease, fresh authority and current native proof.
    checkpoint(phase,event,metadata) must durably record each started/completed
    boundary and named helper identity. Unknown outcomes retain their helpers.
    """
    from selfhost_windows_renewal import UncertainComposeMutation
    uncertain=False;zero=False
    try:
        return _produce_generation(config,current,logical_project,cycle_id,services_image,checkpoint)
    except UncertainComposeMutation as error:
        uncertain=True;zero=getattr(error,'owned_processes_zero',False) is True
    except Exception:
        pass
    current=None
    if uncertain:
        clean=UncertainComposeMutation('Windows renewal producer requires operator reconciliation')
        clean.stdout=clean.stderr=b'';clean.owned_processes_zero=zero
        raise clean
    raise ValueError('Windows renewal producer refused; preserve its guard and outputs')


def _produce_generation(config,current,logical_project,cycle_id,services_image,checkpoint):
    from selfhost_windows_renewal import Docker, require, run_owned_mutation
    from selfhost_windows_selection import decode
    config=json.loads(json.dumps(config));project=config['project'];native=config['native']
    require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}',project))
    require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}',native['helper_image']))
    require(re.fullmatch(r'[0-9a-f]{32}',cycle_id))
    require(re.fullmatch(r'marty-selfhost-[a-z0-9][a-z0-9-]{0,59}',logical_project))
    root='/control/windows-renewal-'+cycle_id
    require(native['renewed']==root+'/generation' and native['token_file']=='/control/recovery-session-'+cycle_id+'/token')
    require(native['control_volume']==project+'-renewal-control' and native['network']==project+'_default'
            and native['bao_addr']=='https://openbao:8200')
    require(re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}',services_image))
    require(40<=len(current)<=512 and all(re.fullmatch(r'[a-z][a-z0-9_]{0,127}',n) for n in current))
    docker=Docker(config['docker_host'],config['engine_id']);deadline=time.monotonic()+900
    def command(args,body=None):
        remaining=deadline-time.monotonic();require(remaining>0)
        p=run_owned_mutation([*docker.prefix,*args],stdin_bytes=body,timeout=min(240,remaining))
        require(p.returncode==0 and time.monotonic()<deadline)
        return p.stdout
    def completed_helper(phase,name,image,expected_id=None):
        items=docker.json(['inspect',name]);require(len(items)==1)
        item=items[0];cid=item['Id']
        require(re.fullmatch(r'[0-9a-f]{64}',cid) and item['Name']=='/'+name
                and (expected_id is None or cid==expected_id)
                and item['State']['Status']=='exited' and item['State']['ExitCode']==0
                and item['RestartCount']==0 and item['Config']['Image']==image
                and item['Config']['Labels']['marty.windows.renewal']==cycle_id
                and item['HostConfig']['LogConfig']['Type']=='none')
        checkpoint(phase,'helper',{'id':cid,'name':name,'image':image})
        command(['rm',cid]) # confirmed completed helper only, no volumes/force
    common=['run','--pull','never','-i','--log-driver','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--memory','512m','--cpus','1']
    with hold_private_input(Path(native['binary']),max_bytes=256*1024*1024) as binary:
        require(hashlib.sha256(binary).hexdigest()==native['binary_sha256'])
        with hold_private_input(Path(native['ca_file'])):
            checkpoint('prepare','started',{})
            name=project+'-renew-prepare-'+cycle_id
            request={'root':root,'current':{n:base64.b64encode(v).decode() for n,v in current.items()}}
            args=[*common,'--name',name,'--label','marty.windows.renewal='+cycle_id,'--network','none',
                '--mount',f'type=volume,src={native["control_volume"]},dst=/control,volume-nocopy',
                '--entrypoint','python',native['helper_image'],'-c',PRODUCER_PREPARE]
            require(decode(command(args,json.dumps(request).encode()))=={'prepared':True})
            completed_helper('prepare',name,native['helper_image']);checkpoint('prepare','completed',{})
            checkpoint('tls','started',{})
            name=project+'-renew-tls-'+cycle_id
            args=['create','--pull','never','--name',name,'--label','marty.windows.renewal='+cycle_id,
                '--log-driver','none','--network',native['network'],'--user','0:0','--read-only','--cap-drop','ALL',
                '--security-opt','no-new-privileges','--memory','512m','--cpus','1','--tmpfs','/tmp:rw,mode=1777',
                '--mount',f'type=bind,src={native["ca_file"]},dst=/input/ca.crt,readonly',
                '--mount',f'type=volume,src={native["control_volume"]},dst=/input/renewal,volume-subpath=recovery-session-{cycle_id},readonly,volume-nocopy',
                '--mount',f'type=volume,src={native["control_volume"]},dst=/output,volume-subpath=windows-renewal-{cycle_id}/tls,volume-nocopy',
                '-e','BAO_ADDR='+native['bao_addr'],'-e','BAO_CACERT=/input/ca.crt','-e','BAO_RENEWAL_TOKEN_FILE=/input/renewal/token',
                '-e','MARTY_TLS_BOOTSTRAP_PROFILE=selfhost-renew','-e','MARTY_SELFHOST_PROJECT='+logical_project,
                '-e','SELFHOST_TLS_OUTPUT_DIR=/output','--entrypoint','/usr/local/bin/marty-passport-tls-bootstrap',services_image]
            cid=command(args).decode().strip();require(re.fullmatch(r'[0-9a-f]{64}',cid))
            checkpoint('tls','created',{'id':cid,'name':name,'image':services_image})
            command(['start',cid]);require(command(['wait',cid]).decode().strip()=='0')
            completed_helper('tls',name,services_image,cid);checkpoint('tls','completed',{})
            checkpoint('keycloak','started',{})
            name=project+'-renew-keycloak-'+cycle_id
            request={k:native[k] for k in ['binary_sha256','source_sha','release_tag','bao_addr','minimum_ttl']}
            request.update(root=root,authority=native['token_file'],files=len(current))
            args=[*common,'--name',name,'--label','marty.windows.renewal='+cycle_id,'--network',native['network'],
                '--mount',f'type=volume,src={native["control_volume"]},dst=/control,volume-nocopy',
                '--mount',f'type=bind,src={native["binary"]},dst=/operator/tool,readonly',
                '--mount',f'type=bind,src={native["ca_file"]},dst=/input/ca.crt,readonly',
                '--entrypoint','python',native['helper_image'],'-c',PRODUCER_ASSEMBLE]
            require(decode(command(args,json.dumps(request).encode()))=={'files':len(current),'changed_files':39,'native_verified':True})
            completed_helper('keycloak',name,native['helper_image']);checkpoint('keycloak','completed',{})
            checkpoint('export','started',{})
            values=export_generation(config,native['renewed'])
            require(set(values)==set(current) and sum(values[n]!=current[n] for n in current)==39)
            checkpoint('export','completed',{})
    require(time.monotonic()<deadline)
    return values
EXPORT_WORKER = r'''
import base64,contextlib,hashlib,json,os,pathlib,stat,sys
d=json.load(sys.stdin);root=pathlib.Path(d['mirror'])
def identity(m):
 return (m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
with contextlib.ExitStack() as held:
 directory_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
 fd=os.open('/control',directory_flags);held.callback(os.close,fd)
 origin=os.fstat(fd);assert stat.S_ISDIR(origin.st_mode) and origin.st_uid==origin.st_gid==0
 directories=[]
 for name in root.parts[2:]:
  parent=fd;fd=os.open(name,directory_flags,dir_fd=parent);held.callback(os.close,fd)
  original=os.fstat(fd);assert stat.S_ISDIR(original.st_mode) and original.st_uid==original.st_gid==0
  directories.append((parent,name,fd,original))
 assert stat.S_IMODE(original.st_mode)==0o700
 assert sorted(os.listdir(fd))==d['names']
 files=[];values={}
 for name in d['names']:
  original=os.stat(name,dir_fd=fd,follow_symlinks=False)
  assert stat.S_ISREG(original.st_mode) and stat.S_IMODE(original.st_mode)==0o600
  assert original.st_uid==original.st_gid==0 and original.st_nlink==1 and original.st_size<=65536
  handle=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
  f=held.enter_context(os.fdopen(handle,'rb'))
  assert identity(os.fstat(f.fileno()))==identity(original)
  files.append((name,f,original))
 for name,f,original in files:
  raw=f.read(65537)
  assert len(raw)<=65536 and b'\0' not in raw and b'PRIVATE KEY' not in raw
  raw.decode('utf-8');values[name]=base64.b64encode(raw).decode('ascii')
 for name,f,original in files:
  assert identity(os.fstat(f.fileno()))==identity(original)
  assert identity(os.stat(name,dir_fd=fd,follow_symlinks=False))==identity(original)
 assert sorted(os.listdir(fd))==d['names']
 for parent,name,handle,original in reversed(directories):
  assert identity(os.fstat(handle))==identity(original)
  assert identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==identity(original)
 assert identity(os.stat('/control',follow_symlinks=False))==identity(origin)
payload=json.dumps(values,sort_keys=True,separators=(',',':')).encode()
assert 0<len(payload)<=8388608
digest=hashlib.sha256(payload).hexdigest();parts=(len(payload)+11999)//12000
if d['part'] is None:result={'length':len(payload),'sha256':digest,'parts':parts}
else:
 assert digest==d['sha256'] and type(d['part']) is int and 0<=d['part']<parts
 result={'sha256':digest,'part':d['part'],'chunk':payload[d['part']*12000:(d['part']+1)*12000].decode('ascii')}
encoded=json.dumps(result);assert len(encoded.encode())<=29000
print(encoded)
'''


def export_generation(config, mirror, *, purpose="selfhost-renewal"):
    """Return private leaf bytes through bounded read-only chunks, never stdout.

    The generation owner must hold its project lease and run native admission
    over the resulting held Windows files. Export alone admits no credentials,
    writes no host files and cannot select, mint or activate a generation.
    """
    from selfhost_windows_renewal import UncertainComposeMutation
    uncertain=False;owned_processes_zero=False
    try:
        return _export_generation(config,mirror,purpose=purpose)
    except UncertainComposeMutation as error:
        uncertain=True
        owned_processes_zero=getattr(error,'owned_processes_zero',False) is True
    except Exception:
        pass
    # Raise outside the except suite: parser/UTF8 exceptions retain private
    # data, and uncertain exceptions retain private chunks in their traceback
    # or prior exception chain even after their direct tails are cleared.
    if uncertain:
        clean=UncertainComposeMutation('Windows generation export requires transport inspection')
        clean.stdout=clean.stderr=b'';clean.owned_processes_zero=owned_processes_zero
        raise clean
    raise ValueError('Windows generation export refused')


def _repair_admission_execution(config,model,docker,native):
    """Reopen actual execution evidence; a readiness field alone admits nothing."""
    from contextlib import ExitStack, contextmanager
    with ExitStack() as inputs:
        @contextmanager
        def held_input(path, *, max_bytes):
            # Keep the verified handle open through the bind/source inspection.
            yield inputs.enter_context(hold_private_input(path,max_bytes=max_bytes))
        @contextmanager
        def held_public_input(path, *, max_bytes):
            yield inputs.enter_context(hold_public_input(path,max_bytes=max_bytes))
        from selfhost_windows_selection import decode
        from selfhost_windows_renewal import windows_mount_path_equal
        def require(value):
            if not value:raise ValueError('Windows generation export refused')
        def held_record(reference):
            require(isinstance(reference,dict) and set(reference)=={'path','sha256','bytes'})
            with held_input(Path(reference['path']),max_bytes=2*1024*1024) as raw:
                require(len(raw)==reference['bytes'] and hashlib.sha256(raw).hexdigest()==reference['sha256'])
                return decode(raw)
        proof=held_record(config['repair_admission_execution'])
        require(proof.get('schema')=='marty.passport-role-repair-execution/v1'
                and proof.get('project')==config['project'] and proof.get('resultSha256')==config['repair_admission_sha256']
                and proof.get('custodySources')==config['custody_sources']
                and proof.get('nativeOperator')==model['nativeOperator']
                and proof.get('volumeIdentity')==native['control_volume_identity'])
        worker=config['admission_worker']
        with held_input(Path(worker['path']),max_bytes=2*1024*1024) as raw:
            require(len(raw)==worker['bytes'] and hashlib.sha256(raw).hexdigest()==worker['sha256']
                    and proof.get('workerSha256')==worker['sha256'])
        armed=held_record(config['admission_armed_proposal'])
        require(proof['armedProposalSha256']==config['admission_armed_proposal']['sha256']
                and armed.get('executeAuthorized') is True
                and armed.get('custodyOwner',{}).get('acceptedRevision')==config['custody_sources']['revision']
                and armed.get('utilities',{}).get('deploy',{}).get('sha256')==native['binary_sha256']
                and armed.get('utilities',{}).get('bootstrap',{}).get('sha256')==native['bootstrap_sha256'])
        request=held_record(proof['jobRequest']);job=held_record(proof['jobResult'])
        actor=config['admission_actor'];actor_plan_ref=config['admission_actor_plan']
        with held_input(Path(actor['path']),max_bytes=2*1024*1024) as raw:
            require(len(raw)==actor['bytes'] and hashlib.sha256(raw).hexdigest()==actor['sha256'])
        actor_plan=held_record(actor_plan_ref)
        require(actor_plan.get('schema')=='marty.beta-trust-admission/v1' and actor_plan.get('executeAuthorized') is True
                and actor_plan.get('actor')==actor and actor_plan.get('worker')==worker
                and actor_plan.get('armedProposal')==config['admission_armed_proposal']
                and actor_plan.get('actorResultFile')==proof['actorResult']['path']
                and actor_plan.get('jobMembershipFile')==proof['jobMembership']['path'])
        require(isinstance(request.get('command'),list) and len(request['command'])==6
                and request['command']==[actor_plan['interpreter']['path'],'-B',actor['path'],actor_plan_ref['path'],actor_plan_ref['sha256'],'--run']
                and request.get('executableSha256')==actor_plan['interpreter']['sha256']
                and request.get('cwd')==str(Path(actor['path']).parent)
                and request.get('receiptFile')==proof['jobResult']['path']
                and request.get('environment',{}).get('PYTHONDONTWRITEBYTECODE')=='1')
        controller=held_record(proof['actorResult']);membership=held_record(proof['jobMembership'])
        require(controller.get('schema')=='marty.passport-role-repair-controller/v1'
                and controller.get('state')=='ADMISSION_AND_RESULT_CAPTURE_PASS'
                and controller.get('actorSha256')==actor['sha256'] and controller.get('actorPlanSha256')==actor_plan_ref['sha256']
                and controller.get('jobRequestSha256')==proof['jobRequest']['sha256']
                and controller.get('membershipSha256')==proof['jobMembership']['sha256']
                and controller.get('workerCid')==proof['workerCid'] and controller.get('resultSha256')==config['repair_admission_sha256']
                and type(controller.get('controllerPid')) is int and controller['controllerPid']>0
                and controller['controllerPid']==job.get('controllerPid')==membership.get('controllerPid')
                and membership.get('schema')=='marty.windows-job-observation/v1'
                and membership.get('controllerMemberVerified') is True and membership.get('inspectorMemberVerified') is True
                and membership.get('queryHandleClosed') is True and membership.get('controllerQueryHandleClosed') is True
                and membership.get('jobMemoryBytes')==request.get('memoryBytes')
                and membership.get('activeProcessLimit')==request.get('processLimit') and membership.get('limitFlags')==0x2208)
        require(request.get('schema')=='marty.windows-job-request/v1' and job.get('schema')=='marty.windows-job-result/v1'
                and isinstance(request.get('executableSha256'),str) and re.fullmatch('[a-f0-9]{64}',request['executableSha256'])
                and type(request.get('memoryBytes')) is int and request['memoryBytes']>0
                and job.get('state')=='COMPLETE' and job.get('exitCode')==0 and job.get('jobClosed') is True
                and job.get('terminalActiveProcesses')==0 and job.get('assignedBeforeResume') is True and job.get('processCreatedSuspended') is True
                and job.get('executableSha256')==request.get('executableSha256')
                and job.get('jobMemoryBytes')==request.get('memoryBytes')
                and all(job.get(k) is False for k in ['forcedTermination','timedOut','cancelled','hostMarginBreached']))
        cid=proof.get('workerCid');require(isinstance(cid,str) and re.fullmatch('[a-f0-9]{64}',cid))
        rows=docker.json(['inspect',cid]);require(isinstance(rows,list) and len(rows)==1)
        item=rows[0];state=item['State'];settings=item['Config'];host=item['HostConfig']
        require(item['Id']==cid and item['Created']==proof['workerCreated'] and item['Image']==proof['workerImageId']==config['admission_image_id']
                and item['Name']=='/'+config['project']+'-admission'
                and state['Status']=='exited' and state['ExitCode']==0 and state['Pid']==0 and state['Running'] is False
                and state['OOMKilled'] is False and not state['StartedAt'].startswith('0001-')
                and state['StartedAt']==proof['workerStartedAt'] and state['FinishedAt']==proof['workerFinishedAt']
                and item['RestartCount']==0 and settings['User']=='0:0'
                and settings['Entrypoint']==['python3'] and settings['Cmd']==['-B','/work/admit-linux.py','/work/proposal.armed.private.json',proof['armedProposalSha256']]
                and settings['Labels'].get('elevenid.trust-role.project')==config['project']
                and settings['Labels'].get('elevenid.trust-role.phase')=='admission'
                and host['NetworkMode']=='none' and host['Privileged'] is False
                and 'ALL' in host['CapDrop'] and 'no-new-privileges' in host['SecurityOpt'])
        mounts=sorted(item['Mounts'],key=lambda m:m['Destination'])
        require(mounts==proof['workerMounts']==config['admission_mounts'] and len({m['Destination'] for m in mounts})==len(mounts))
        control=[m for m in mounts if m['Destination']=='/control']
        require(len(control)==1 and control[0]['Type']=='volume' and control[0]['Name']==native['control_volume'] and control[0]['RW'] is True
                and all(m['Type']=='bind' and m['RW'] is False for m in mounts if m['Destination']!='/control'))
        # These are exact file binds, not a host-authored agreement about a broad /work directory.
        expected={'/work/admit-linux.py':worker,'/work/proposal.armed.private.json':config['admission_armed_proposal'],
                  '/tools/marty-deploy':armed['utilities']['deploy'],
                  '/tools/marty-passport-tls-bootstrap':armed['utilities']['bootstrap'],
                  '/input/workload-ca.pem':armed['publicInputs']['workload_identity_ca_cert']}
        custody=armed['custodyOwner']['candidateSourceRefs']
        require(custody['passport_remote_tls.py']['sha256']==config['custody_sources']['admissionOwnerSha256']
                and custody['selfhost_windows_renewal_native.py']['sha256']==config['custody_sources']['exportOwnerSha256'])
        for name in ['passport_remote_tls.py','selfhost_windows_renewal_native.py']:
            expected['/work/candidate/scripts/'+name]=custody[name]
        sources=config['admission_native_sources']
        require(set(sources)=={'selfhost_native_operator.py','source_matched_native.py'} and actor_plan.get('nativeSources')==sources)
        for name,reference in sources.items():expected['/work/owner/'+name]=reference
        require(set(m['Destination'] for m in mounts)==set(expected)|{'/control','/input/root.token'})
        for destination,reference in expected.items():
            matches=[m for m in mounts if m['Destination']==destination]
            require(len(matches)==1 and matches[0]['Type']=='bind' and matches[0]['RW'] is False
                    and windows_mount_path_equal(matches[0]['Source'],reference['path']))
            public_ca=destination=='/input/workload-ca.pem'
            if public_ca:
                require(reference['sha256']==model['pinnedIssuerInputSha256']
                        ==armed['publicInputs']['workload_identity_ca_cert']['sha256']
                        ==config['workload_ca_sha256'])
            reader=held_public_input if public_ca else held_input
            with reader(Path(reference['path']),max_bytes=65536 if public_ca else 128*1024*1024) as raw:
                require(len(raw)==reference['bytes'] and hashlib.sha256(raw).hexdigest()==reference['sha256'])
        # Bind the authority path without reopening or exporting its bytes here.
        authority=[m for m in mounts if m['Destination']=='/input/root.token'][0]
        require(windows_mount_path_equal(authority['Source'],armed['authorityReference']['path']))
        return proof


def _repair_exporter_source(config,model):
    """Bind a reviewed successor separately; never rewrite admitted source history."""
    import inspect
    from selfhost_windows_selection import decode
    def require(value):
        if not value:raise ValueError('Windows generation export refused')
    own=Path(__file__)
    if 'public_ca_read_recovery' not in config:
        require(config['custody_sources']['exportOwnerSha256']==hashlib.sha256(own.read_bytes()).hexdigest())
        return
    recovery=config['public_ca_read_recovery']
    require(recovery.get('schema')=='marty.passport-role-repair-public-ca-export-successor/v1'
            and isinstance(recovery.get('implementationRevision'),str)
            and re.fullmatch('[a-f0-9]{40}',recovery['implementationRevision'])
            and recovery.get('admittedCustodySources')==model['custodySources']==config['custody_sources'])
    admitted=recovery['admittedExporter'];successor=recovery['successorExporter'];public_owner=recovery['publicInputOwner']
    require(admitted['sha256']==model['custodySources']['exportOwnerSha256']
            and Path(successor['path'])==own
            and Path(public_owner['path'])==Path(inspect.unwrap(hold_public_input).__code__.co_filename))
    for reference in [admitted,successor,public_owner]:
        with hold_private_input(Path(reference['path']),max_bytes=2*1024*1024) as raw:
            require(len(raw)==reference['bytes'] and hashlib.sha256(raw).hexdigest()==reference['sha256'])


def _export_generation(config, mirror, *, purpose="selfhost-renewal"):
    from selfhost_windows_renewal import Docker, run_owned_mutation
    from selfhost_windows_selection import decode

    def require(value):
        if not value:raise ValueError('Windows generation export refused')
    config=json.loads(json.dumps(config));project=config['project'];native=config['native']
    require(purpose in {'selfhost-renewal','passport-role-repair'})
    repair=purpose=='passport-role-repair'
    require(repair or 'public_ca_read_recovery' not in config)
    if repair:
        match=re.fullmatch(r'marty-passport-acceptance-trust-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})',project)
        require(match is not None and native['control_volume']==project+'-tls-custody')
        require(mirror=='/control/trust-role-'+match.group(1)+'/generation')
    else:
        require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}',project))
        require(native['control_volume']==project+'-renewal-control')
    require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}',native['helper_image']))
    require(isinstance(mirror,str))
    path=PurePosixPath(mirror)
    require(str(path)==mirror and path.is_relative_to('/control') and len(path.parts)>=4
            and '..' not in path.parts and path.name in {'generation','application-generation','application-mail-generation'})
    require(all(re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,127}',name) for name in path.parts[2:]))
    deadline=time.monotonic()+600
    input_file=config['repair_admission_file'] if repair else config['compose_file']
    input_digest=config['repair_admission_sha256'] if repair else config['compose_sha256']
    with hold_private_input(Path(input_file),max_bytes=2*1024*1024) as raw:
        require(hashlib.sha256(raw).hexdigest()==input_digest)
        model=decode(raw)
        if repair:
            _repair_exporter_source(config,model)
            names=sorted(['workload_identity_ca_cert','trust_profile_workload_server_cert','trust_profile_workload_server_kms_token'])
            require(isinstance(model,dict) and model.get('schema')=='marty.passport-role-repair-admission/v1'
                    and model.get('project')==project and model.get('role')=='trust-profile-server'
                    and model.get('profile')=='passport-role-repair' and model.get('nativeAdmissionComplete') is True
                    and isinstance(model.get('files'),dict) and sorted(model['files'])==names)
        else:
            require(isinstance(model,dict) and isinstance(model.get('secrets'),dict))
            names=sorted(model['secrets'])
        require(0<len(names)<=512 and all(re.fullmatch(r'[a-z][a-z0-9_]{0,127}',name) for name in names))
        docker=Docker(config['docker_host'],config['engine_id'])
        volumes=docker.json(['volume','inspect',native['control_volume']])
        require(isinstance(volumes,list) and len(volumes)==1 and volumes[0]['Name']==native['control_volume']
                and volumes[0]['Driver']=='local' and volumes[0].get('Options') in (None,{}))
        if repair:
            require(volumes[0]==native['control_volume_identity'])
            require(model.get('nativeOperator')=={'sha256':native['binary_sha256'],'sourceSha':native['source_sha'],'releaseTag':native['release_tag']}
                    and model.get('custodySources')==config['custody_sources']
                    and set(config['custody_sources'])=={'revision','exportOwnerSha256','admissionOwnerSha256'}
                    and re.fullmatch(r'[0-9a-f]{64}',config['custody_sources']['admissionOwnerSha256'])
                    and re.fullmatch(r'[0-9a-f]{40}',config['custody_sources']['revision'])
                    and model.get('nativeProducerSha256')==native['bootstrap_sha256']
                    and model.get('pinnedIssuerInputSha256')==config['workload_ca_sha256'])
            execution=_repair_admission_execution(config,model,docker,native)
        def fetch(part=None,digest=None):
            remaining=deadline-time.monotonic();require(remaining>0)
            request={'mirror':mirror,'names':names,'part':part,'sha256':digest}
            args=[*docker.prefix,'run','--rm','--pull','never','-i','--log-driver','none','--network','none','--read-only',
                '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--cpus','1',
                '--mount',f'type=volume,src={native["control_volume"]},dst=/control,readonly,volume-nocopy',
                '--entrypoint','python',native['helper_image'],'-c',EXPORT_WORKER]
            p=run_owned_mutation(args,stdin_bytes=json.dumps(request).encode(),timeout=min(60,remaining))
            require(p.returncode==0 and 0<len(p.stdout)<=29000)
            require(time.monotonic()<deadline)
            return decode(p.stdout)
        manifest=fetch()
        require(isinstance(manifest,dict) and set(manifest)=={'length','sha256','parts'})
        length=manifest['length'];digest=manifest['sha256'];parts=manifest['parts']
        require(type(length) is int and 0<length<=EXPORT_LIMIT_BYTES
                and isinstance(digest,str) and re.fullmatch(r'[0-9a-f]{64}',digest)
                and type(parts) is int and parts==(length+EXPORT_CHUNK_BYTES-1)//EXPORT_CHUNK_BYTES)
        chunks=[]
        for index in range(parts):
            part=fetch(index,digest)
            require(isinstance(part,dict) and set(part)=={'sha256','part','chunk'}
                    and part['sha256']==digest and type(part['part']) is int and part['part']==index
                    and isinstance(part['chunk'],str) and part['chunk'].isascii())
            chunk=part['chunk'].encode('ascii')
            require(len(chunk)==min(EXPORT_CHUNK_BYTES,length-index*EXPORT_CHUNK_BYTES))
            chunks.append(chunk)
        payload=b''.join(chunks)
        require(len(payload)==length and hashlib.sha256(payload).hexdigest()==digest)
        encoded=decode(payload)
        require(isinstance(encoded,dict) and sorted(encoded)==names
                and json.dumps(encoded,sort_keys=True,separators=(',',':')).encode()==payload)
        values={}
        for name in names:
            require(isinstance(encoded[name],str) and len(encoded[name])<=87384)
            value=base64.b64decode(encoded[name],validate=True)
            require(len(value)<=65536 and base64.b64encode(value).decode('ascii')==encoded[name]
                    and b'\0' not in value and b'PRIVATE KEY' not in value)
            value.decode('utf-8');values[name]=value
            if repair:
                expected=model['files'][name]
                require(isinstance(expected,dict) and set(expected)=={'bytes','sha256'}
                        and type(expected['bytes']) is int and 0<expected['bytes']<=65536
                        and isinstance(expected['sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',expected['sha256'])
                        and len(value)==expected['bytes'] and hashlib.sha256(value).hexdigest()==expected['sha256'])
        if repair:
            require(_repair_admission_execution(config,model,docker,native)==execution)
    require(time.monotonic()<deadline)
    return values

AUTHORITY_WORKER = r'''
import hashlib,json,os,pathlib,subprocess,sys
d=json.load(sys.stdin)
binary='/operator/tool'
assert hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()==d['binary_sha256']
p=subprocess.run([binary,'--build-identity'],capture_output=True,timeout=20)
assert p.returncode==0 and p.stdout.decode().strip()==d['source_sha']+':'+d['release_tag']
os.umask(0o077)
folder=pathlib.Path(d['session_dir']);folder.mkdir(mode=0o700)
fd=os.open(folder/'token',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
p=subprocess.run([binary,'operator','approle-login','renewal',d['bao_addr'],'/input/ca.crt','/control/identity'],
                 input=b'{}',capture_output=True,timeout=90)
assert p.returncode==0
login=json.loads(p.stdout)
assert isinstance(login,dict) and isinstance(login.get('token'),str) and 20<=len(login['token'])<=8192
with os.fdopen(fd,'w') as f:
 f.write(login['token']);f.flush();os.fsync(f.fileno())
for directory in [folder,folder.parent]:
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
assert set(login)=={'role_id','secret_id','names','token'}
assert isinstance(login['names'],list) and len(login['names'])==len(set(login['names']))==21
assert all(isinstance(name,str) for name in login['names'])
p=subprocess.run([binary,'operator','authority-check',d['bao_addr'],'/input/ca.crt'],
                 input=json.dumps({'token':login['token'],'rotation':False}).encode(),capture_output=True,timeout=90)
assert p.returncode==0 and json.loads(p.stdout)=={'value':None}
print(json.dumps({'authority':True,'policy_count':21,'token_file':str(folder/'token')}))
'''


def reauthenticate(config, project, docker_prefix, session_dir):
    """Refresh existing scoped enrollment; print/store no credentials on host."""
    def require(value):
        if not value:raise ValueError('Windows scoped authority refresh refused')
    require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}',project))
    require(config['control_volume']==project+'-renewal-control' and config['network']==project+'_default')
    require(config['bao_addr']=='https://openbao:8200')
    require(re.fullmatch(r'/control/recovery-session-[0-9a-f]{32}',session_dir))
    require(re.fullmatch(r'[0-9a-f]{64}',config['binary_sha256']))
    require(re.fullmatch(r'[0-9a-f]{40}',config['source_sha']))
    require(re.fullmatch(r'v\d+\.\d+\.\d+(?:-nightly\.20\d{6}\.[1-9]\d*)?',config['release_tag']))
    require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}',config['helper_image']))
    # Docker must not silently create an empty control volume during recovery.
    p=subprocess.run([*docker_prefix,'volume','inspect',config['control_volume']],capture_output=True,timeout=30)
    require(p.returncode==0 and len(p.stdout)<=65536)
    volumes=json.loads(p.stdout)
    require(isinstance(volumes,list) and len(volumes)==1 and volumes[0]['Name']==config['control_volume']
            and volumes[0]['Driver']=='local' and volumes[0].get('Options') in (None,{}))
    with hold_private_input(Path(config['binary']),max_bytes=256*1024*1024) as binary:
        require(hashlib.sha256(binary).hexdigest()==config['binary_sha256'])
        with hold_private_input(Path(config['ca_file'])):
            request={k:config[k] for k in ['binary_sha256','source_sha','release_tag','bao_addr']}
            request['session_dir']=session_dir
            args=[*docker_prefix,'run','--rm','--pull','never','-i','--read-only','--cap-drop','ALL',
                '--security-opt','no-new-privileges','--network',config['network'],'--memory','256m','--cpus','1',
                '--mount',f'type=volume,src={config["control_volume"]},dst=/control',
                '--mount',f'type=bind,src={config["binary"]},dst=/operator/tool,readonly',
                '--mount',f'type=bind,src={config["ca_file"]},dst=/input/ca.crt,readonly',
                '--entrypoint','python',config['helper_image'],'-c',AUTHORITY_WORKER]
            from selfhost_windows_renewal import run_owned_mutation
            p=run_owned_mutation(args,stdin_bytes=json.dumps(request).encode(),timeout=240)
            require(p.returncode==0)
            expected={'authority':True,'policy_count':21,'token_file':session_dir+'/token'}
            require(json.loads(p.stdout)==expected)
    return expected['token_file']

WORKER = r'''
import base64,hashlib,json,os,pathlib,subprocess,sys
d=json.load(sys.stdin)
binary='/operator/tool'
assert hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()==d['binary_sha256']
p=subprocess.run([binary,'--build-identity'],capture_output=True,timeout=20)
assert p.returncode==0 and p.stdout.decode().strip()==d['source_sha']+':'+d['release_tag']
mirrors={'old':d['current'],'new':d['renewed']}
roots={}
os.umask(0o077)
for role,root in mirrors.items():
 assert sorted(p.name for p in pathlib.Path(root).iterdir())==sorted(d['bytes'][role])
 snapshot=pathlib.Path('/proof',role);snapshot.mkdir(mode=0o700)
 roots[role]=str(snapshot)
 for name,value in d['bytes'][role].items():
  expected=base64.b64decode(value,validate=True)
  assert len(expected)<=65536
  assert pathlib.Path(root,name).read_bytes()==expected
  fd=os.open(snapshot/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f:
   assert f.write(expected)==len(expected);f.flush();os.fsync(f.fileno())
token=pathlib.Path(d['token_file']).read_text().strip()
def native(op,body,network=False):
 args=[binary,'operator',op]
 if network:args += [d['bao_addr'],'/input/ca.crt']
 p=subprocess.run(args,input=json.dumps(body).encode(),capture_output=True,timeout=90)
 assert p.returncode==0
 r=json.loads(p.stdout);assert isinstance(r,dict) and set(r)=={'value'}
 return r['value']
assert native('authority-check',{'token':token,'rotation':False},True) is None
if d['transition']:
 assert native('generation',{'operation':'verify','current':roots['old'],'candidate':roots['new'],
                            'ca_overlap':False,'ca_retire':False})==[d['count'],d['changed']]
else:
 assert d['changed']==0 and mirrors['old']==mirrors['new'] and d['bytes']['old']==d['bytes']['new']
body={'token':token,'old':roots['old'],'new':roots['new'],'minimum_ttl':d['minimum_ttl'],
      'require_orphan_new':not d.get('initial_current',False),'require_orphan_old':False,
      'replacement':None,'retiring':False}
for op in ['activation-tokens','activation-certificates']:assert native(op,body,True) is None
print(json.dumps({'authority':True,'generation':d['transition'],'tokens':True,'certificates':True}))
'''


def preflight(config, project, old, new, docker_prefix):
    """Verify a changing generation; all transition checks remain mandatory."""
    return _preflight(config, project, old, new, docker_prefix, transition=True)


def preflight_current(config, project, current, docker_prefix):
    """Read-only current custody/lifetime proof, never a transition admission."""
    config = dict(config)
    config['renewed'] = config['current']
    return _preflight(config, project, current, current, docker_prefix, transition=False)


def preflight_initial_current(config, project, current, docker_prefix):
    """Read-only first-generation proof while initial root-descendant leaves exist.

    This never admits a replacement or production lifecycle. Subsequent selected
    generations use the ordinary orphan-required current proof.
    """
    config = dict(config)
    config['renewed'] = config['current']
    return _preflight(config, project, current, current, docker_prefix,
                      transition=False, initial_current=True)


def _preflight(config, project, old, new, docker_prefix, *, transition,
               initial_current=False):
    def require(value):
        if not value:
            raise ValueError('Windows native renewal preflight refused')
    require(set(old) == set(new) and 0 < len(old) <= 512)
    require(all(re.fullmatch(r'[a-z][a-z0-9_]{0,127}', name) for name in old))
    changed = sum(old[name] != new[name] for name in old)
    require(type(initial_current) is bool and not (transition and initial_current))
    require(changed > 0 if transition else changed == 0)
    require(re.fullmatch(r'[0-9a-f]{64}', config['binary_sha256']))
    require(re.fullmatch(r'[0-9a-f]{40}', config['source_sha']))
    require(re.fullmatch(r'v\d+\.\d+\.\d+(?:-nightly\.20\d{6}\.[1-9]\d*)?', config['release_tag']))
    require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', config['helper_image']))
    require(config['control_volume'] == project + '-renewal-control')
    require(config['network'] == project + '_default')
    require(config['bao_addr'] == 'https://openbao:8200')
    require(type(config['minimum_ttl']) is int and 60 <= config['minimum_ttl'] <= 28800)
    require(transition or config['minimum_ttl'] >= 3600)
    for key in ['current', 'renewed', 'token_file']:
        p = PurePosixPath(config[key])
        require(p.is_relative_to('/control') and len(p.parts) >= 3
                and '..' not in p.parts and str(p) == config[key])
    require(config['current'] != config['renewed'] if transition else config['current'] == config['renewed'])
    with hold_private_input(Path(config['binary']), max_bytes=256 * 1024 * 1024) as binary:
        require(hashlib.sha256(binary).hexdigest() == config['binary_sha256'])
        with hold_private_input(Path(config['ca_file'])):
            request = {key: config[key] for key in ['binary_sha256', 'source_sha', 'release_tag',
                                                  'bao_addr', 'current', 'renewed', 'token_file', 'minimum_ttl']}
            request.update(count=len(old), changed=changed, transition=transition,
                           initial_current=initial_current, bytes={
                role: {name: base64.b64encode(raw).decode('ascii') for name, raw in values.items()}
                for role, values in [('old', old), ('new', new)]})
            args = [*docker_prefix, 'run', '--rm', '--pull', 'never', '-i', '--read-only',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                    '--network', config['network'], '--tmpfs',
                    '/proof:rw,noexec,nosuid,nodev,size=128m,mode=0700', '--mount',
                    f'type=volume,src={config["control_volume"]},dst=/control,readonly', '--mount',
                    f'type=bind,src={config["binary"]},dst=/operator/tool,readonly', '--mount',
                    f'type=bind,src={config["ca_file"]},dst=/input/ca.crt,readonly',
                    '--entrypoint', 'python', config['helper_image'], '-c', WORKER]
            # Lazy import keeps the shared transport in its existing owner and
            # avoids a module-import cycle. Payload travels over the gated pipe,
            # never through command-line arguments or diagnostic output.
            from selfhost_windows_renewal import run_owned_mutation
            p = run_owned_mutation(args, stdin_bytes=json.dumps(request).encode(), timeout=240)
            require(p.returncode == 0)
            require(json.loads(p.stdout) == {'authority': True, 'generation': transition,
                                            'tokens': True, 'certificates': True})
