"""Synthetic portable-export boundary controls; no credentials, Docker or native calls."""
from pathlib import Path
import base64,contextlib,copy,hashlib,importlib.util,json,sys,types,unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
p=ROOT/'scripts/selfhost_windows_renewal_native.py'
spec=importlib.util.spec_from_file_location('candidate_portable_owner',p)
owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)

class PortableControls(unittest.TestCase):
 def exercise(self,defect=None):
  project='marty-passport-acceptance-trust-af68f23d-17cf-47fc-a19e-9ae4ad3ebbb0'
  mirror='/control/trust-role-af68f23d-17cf-47fc-a19e-9ae4ad3ebbb0/generation'
  values={n:('synthetic-public-or-scoped-'+n).encode() for n in ['workload_identity_ca_cert','trust_profile_workload_server_cert','trust_profile_workload_server_kms_token']}
  volume={'Name':project+'-tls-custody','Driver':'local','Options':{},'CreatedAt':'fixed-creation'}
  fixture={'deploy':b'synthetic-deploy','bootstrap':b'synthetic-bootstrap','ca':b'synthetic-public-ca','tls-owner':b'synthetic-admission-owner'}
  native={'control_volume':volume['Name'],'helper_image':'python@sha256:'+'a'*64,'control_volume_identity':copy.deepcopy(volume),'binary_sha256':hashlib.sha256(fixture['deploy']).hexdigest(),'source_sha':'82862f78876f2885a32353ba99a34ccba284faac','release_tag':'v0.0.0','bootstrap_sha256':hashlib.sha256(fixture['bootstrap']).hexdigest()}
  custody={'revision':'d'*40,'exportOwnerSha256':hashlib.sha256(p.read_bytes()).hexdigest(),'admissionOwnerSha256':hashlib.sha256(fixture['tls-owner']).hexdigest()}
  if defect=='same-revision':custody['revision']=native['source_sha']
  receipt={'schema':'marty.passport-role-repair-admission/v1','project':project,'profile':'passport-role-repair','role':'trust-profile-server','nativeAdmissionComplete':True,
   'files':{n:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for n,v in values.items()},
   'nativeOperator':{'sha256':native['binary_sha256'],'sourceSha':native['source_sha'],'releaseTag':native['release_tag']},'custodySources':custody,'nativeProducerSha256':native['bootstrap_sha256'],'pinnedIssuerInputSha256':hashlib.sha256(fixture['ca']).hexdigest()}
  if defect=='extra-file':receipt['files']['foreign_token']={'bytes':1,'sha256':'f'*64}
  if defect=='wrong-operator':receipt['nativeOperator']['sourceSha']='f'*40
  if defect=='changed-volume':volume['CreatedAt']='different-creation'
  if defect=='changed-bytes':values['trust_profile_workload_server_kms_token']+=b'changed'
  raw=json.dumps(receipt).encode()
  config={'project':project,'native':native,'repair_admission_file':'synthetic-receipt','repair_admission_sha256':hashlib.sha256(raw).hexdigest(),'custody_sources':custody,'workload_ca_sha256':hashlib.sha256(fixture['ca']).hexdigest(),'docker_host':'synthetic','engine_id':'synthetic'}
  records={}
  def reference(name,raw):
   path='C:/synthetic/'+name;records[str(Path(path))]=raw
   return {'path':path,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
  worker_source=b'synthetic-reviewed-admission-worker'
  request={'schema':'marty.windows-job-request/v1','executableSha256':'e'*64,'memoryBytes':1024**3}
  job={'schema':'marty.windows-job-result/v1','state':'COMPLETE','exitCode':0,'jobClosed':True,'terminalActiveProcesses':0,'assignedBeforeResume':True,
   'executableSha256':'e'*64,'jobMemoryBytes':1024**3,'controllerPid':1234,'processCreatedSuspended':True,'forcedTermination':False,'timedOut':False,'cancelled':False,'hostMarginBreached':False}
  custody_refs={'passport_remote_tls.py':reference('tls-owner.py',fixture['tls-owner']),'selfhost_windows_renewal_native.py':reference('export-owner.py',p.read_bytes())}
  armed={'executeAuthorized':True,'custodyOwner':{'acceptedRevision':custody['revision'],'candidateSourceRefs':custody_refs},
   'utilities':{'deploy':reference('deploy',fixture['deploy']),'bootstrap':reference('bootstrap',fixture['bootstrap'])},
   'publicInputs':{'workload_identity_ca_cert':reference('ca.pem',fixture['ca'])},'authorityReference':{'path':'C:/synthetic/root.token'}}
  armed_raw=json.dumps(armed).encode();armed_digest=hashlib.sha256(armed_raw).hexdigest()
  worker={'Id':'f'*64,'Created':'fixed-creation','Image':'sha256:'+'a'*64,'Name':'/'+project+'-admission','RestartCount':0,
   'State':{'Status':'exited','ExitCode':0,'Pid':0,'Running':False,'OOMKilled':False,'StartedAt':'2026-11-12T00:00:00Z','FinishedAt':'2026-11-12T00:00:01Z'},
   'Config':{'User':'0:0','Entrypoint':['python3'],'Cmd':['-B','/work/admit-linux.py','/work/proposal.armed.private.json',armed_digest],
    'Labels':{'elevenid.trust-role.project':project,'elevenid.trust-role.phase':'admission'}},
   'HostConfig':{'NetworkMode':'none','Privileged':False,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges']},
   'Mounts':[{'Destination':'/control','Type':'volume','Name':native['control_volume'],'RW':True}]}
  worker_ref=reference('worker.py',worker_source);armed_ref=reference('armed.json',armed_raw)
  sources={name:reference(name,('synthetic-'+name).encode()) for name in ['selfhost_native_operator.py','source_matched_native.py']}
  expected={'/work/admit-linux.py':worker_ref,'/work/proposal.armed.private.json':armed_ref,'/tools/marty-deploy':armed['utilities']['deploy'],
   '/tools/marty-passport-tls-bootstrap':armed['utilities']['bootstrap'],'/input/workload-ca.pem':armed['publicInputs']['workload_identity_ca_cert'],
   **{'/work/candidate/scripts/'+name:ref for name,ref in custody_refs.items()},**{'/work/owner/'+name:ref for name,ref in sources.items()},'/input/root.token':armed['authorityReference']}
  worker['Mounts'] += [{'Destination':name,'Type':'bind','Source':ref['path'],'RW':False} for name,ref in expected.items()]
  # Keep proof/config equality intact for wrong-source controls: only the trusted file reference differs.
  if defect and defect.startswith('wrong-source:'):
   target=defect.split(':',1)[1]
   for mount in worker['Mounts']:
    if mount['Destination']==target:mount['Source']='C:/synthetic/unrelated-source'
  actor_ref=reference('actor.py',b'synthetic-reviewed-actor')
  membership={'schema':'marty.windows-job-observation/v1','controllerPid':1234,'controllerMemberVerified':True,'inspectorMemberVerified':True,
   'queryHandleClosed':True,'controllerQueryHandleClosed':True,'jobMemoryBytes':1024**3,'activeProcessLimit':32,'limitFlags':0x2208}
  membership_ref=reference('membership.json',json.dumps(membership).encode())
  actor_result_path='C:/synthetic/actor-result.json'
  plan={'schema':'marty.beta-trust-admission/v1','executeAuthorized':True,'actor':actor_ref,'worker':worker_ref,'armedProposal':armed_ref,
   'actorResultFile':actor_result_path,'jobMembershipFile':membership_ref['path'],'nativeSources':sources,'interpreter':{'path':'C:/synthetic/python.exe','sha256':'e'*64}}
  plan_ref=reference('actor-plan.json',json.dumps(plan).encode())
  request.update(command=['C:/synthetic/python.exe','-B',actor_ref['path'],plan_ref['path'],plan_ref['sha256'],'--run'],cwd=str(Path(actor_ref['path']).parent),receiptFile='C:/synthetic/job.json',environment={'PYTHONDONTWRITEBYTECODE':'1'},processLimit=32)
  if defect=='unrelated-command':request['command'][2]='C:/synthetic/unrelated-actor.py'
  if defect=='unrelated-job':job['controllerPid']=5678
  request_raw=json.dumps(request).encode();job_raw=json.dumps(job).encode()
  request_ref=reference('request.json',request_raw);job_ref=reference('job.json',job_raw)
  controller={'schema':'marty.passport-role-repair-controller/v1','state':'ADMISSION_AND_RESULT_CAPTURE_PASS','actorSha256':actor_ref['sha256'],
   'actorPlanSha256':plan_ref['sha256'],'jobRequestSha256':request_ref['sha256'],'membershipSha256':membership_ref['sha256'],'workerCid':worker['Id'],
   'resultSha256':config['repair_admission_sha256'],'controllerPid':1234}
  controller_ref=reference('actor-result.json',json.dumps(controller).encode())
  proof={'schema':'marty.passport-role-repair-execution/v1','project':project,'resultSha256':config['repair_admission_sha256'],'custodySources':custody,
   'nativeOperator':receipt['nativeOperator'],'volumeIdentity':native['control_volume_identity'],'workerSha256':hashlib.sha256(worker_source).hexdigest(),
   'jobRequest':request_ref,'jobResult':job_ref,'actorResult':controller_ref,'jobMembership':membership_ref,'workerCid':worker['Id'],'workerCreated':worker['Created'],
   'workerImageId':worker['Image'],'workerStartedAt':worker['State']['StartedAt'],'workerFinishedAt':worker['State']['FinishedAt'],'armedProposalSha256':armed_digest,
   'workerMounts':sorted(copy.deepcopy(worker['Mounts']),key=lambda m:m['Destination'])}
  proof_raw=json.dumps(proof).encode();config['repair_admission_execution']=reference('synthetic-execution',proof_raw)
  config['admission_worker']=worker_ref;config['admission_actor']=actor_ref;config['admission_actor_plan']=plan_ref;config['admission_native_sources']=sources
  config['admission_armed_proposal']=armed_ref;config['admission_image_id']=worker['Image'];config['admission_mounts']=sorted(copy.deepcopy(worker['Mounts']),key=lambda m:m['Destination'])
  if defect=='readiness-only':config['repair_admission_execution']=None
  records['synthetic-receipt']=raw
  @contextlib.contextmanager
  def held(path,*a,**kw):yield records[str(path)]
  class Docker:
   prefix=['docker']
   def __init__(self,*a):pass
   def json(self,argv):return [worker] if argv[0]=='inspect' else [volume]
  payload=json.dumps({n:base64.b64encode(v).decode() for n,v in values.items()},sort_keys=True,separators=(',',':')).encode()
  digest=hashlib.sha256(payload).hexdigest()
  def run(argv,stdin_bytes,timeout):
   request=json.loads(stdin_bytes)
   result={'length':len(payload),'sha256':digest,'parts':1} if request['part'] is None else {'sha256':digest,'part':0,'chunk':payload.decode()}
   return types.SimpleNamespace(returncode=0,stdout=json.dumps(result).encode())
  fake=types.ModuleType('selfhost_windows_renewal');fake.Docker=Docker;fake.run_owned_mutation=run;fake.windows_mount_path_equal=lambda actual,expected:actual==expected
  selection=types.ModuleType('selfhost_windows_selection');selection.decode=json.loads
  prior={name:sys.modules.get(name) for name in ['selfhost_windows_renewal','selfhost_windows_selection']}
  sys.modules['selfhost_windows_renewal']=fake;sys.modules['selfhost_windows_selection']=selection
  original_private=owner.hold_private_input;original_public=owner.hold_public_input
  # Both public CA/source records and private records are synthetic held inputs.
  # The production reader still enforces its Windows boundary outside this unit.
  owner.hold_private_input=held;owner.hold_public_input=held
  try:return owner._export_generation(config,mirror,purpose='selfhost-renewal' if defect=='legacy-purpose' else 'passport-role-repair')
  finally:
   owner.hold_private_input=original_private;owner.hold_public_input=original_public
   for name,value in prior.items():
    if value is None:sys.modules.pop(name,None)
    else:sys.modules[name]=value

 def test_exact_three_files_return_private_bytes(self):self.assertEqual(len(self.exercise()),3)
 def test_same_native_and_custody_revision_is_admitted(self):self.assertEqual(len(self.exercise('same-revision')),3)
 def test_host_readiness_without_execution_is_refused(self):
  with self.assertRaises(ValueError):self.exercise('readiness-only')
 def test_old_purpose_cannot_admit_beta_repair(self):
  with self.assertRaises(ValueError):self.exercise('legacy-purpose')
 def test_extra_secret_refused(self):
  with self.assertRaises(ValueError):self.exercise('extra-file')
 def test_changed_volume_generation_refused(self):
  with self.assertRaises(ValueError):self.exercise('changed-volume')
 def test_changed_file_bytes_refused(self):
  with self.assertRaises(ValueError):self.exercise('changed-bytes')
 def test_wrong_native_identity_refused(self):
  with self.assertRaises(ValueError):self.exercise('wrong-operator')
 def test_matching_host_proof_cannot_substitute_source_mounts(self):
  for target in ['/work/admit-linux.py','/work/proposal.armed.private.json','/tools/marty-deploy','/tools/marty-passport-tls-bootstrap','/input/workload-ca.pem']:
   with self.subTest(target=target):
    with self.assertRaises(ValueError):self.exercise('wrong-source:'+target)
 def test_unrelated_command_or_closed_job_is_refused(self):
  for defect in ['unrelated-command','unrelated-job']:
   with self.subTest(defect=defect):
    with self.assertRaises(ValueError):self.exercise(defect)

if __name__=='__main__':unittest.main()
