import importlib.util,sys,json,copy,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[2]/'scripts'
UI=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(UI/'scripts'))
import scoped_mdoc_config as reps

def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module('northstar',HERE/'scoped_northstar_fixture.py')
def original():
 return dict(Id='b'*64,Name='/elevenid-beta-northstar-admissions-1',Image=m.IMAGE,
  Path='docker-entrypoint.sh',Args=['node','src/server.mjs'],
  Config=dict(Hostname='b'*12,Env=['PORT=4175'],Labels={
   'com.docker.compose.project':'elevenid-beta','com.docker.compose.service':m.ROLE,
   'org.opencontainers.image.revision':m.SOURCE,'com.docker.compose.config-hash':'old-hash',
   'com.docker.compose.project.config_files':'/owned/original.json',
   'com.docker.compose.project.working_dir':'/owned','com.docker.compose.version':'2.40.0'}),
  HostConfig=dict(Binds=None,Mounts=[dict(Type='bind',Source='/owned/fixture.json',
   Target=m.TARGET,ReadOnly=True,BindOptions={'CreateMountpoint':False})],ReadonlyRootfs=True,
   CapDrop=['ALL'],SecurityOpt=['no-new-privileges:true']),
  Mounts=[dict(Type='bind',Source='/owned/fixture.json',Destination=m.TARGET,RW=False,Mode='ro',Propagation='rprivate')],
  NetworkSettings={'Networks':{'elevenid-beta-network':dict(NetworkID='1'*64,EndpointID='2'*64,
   Aliases=[m.ROLE],IPAMConfig=None,Links=None,IPAddress='172.20.0.2',DNSNames=[m.ROLE,'b'*12])}},
  State=dict(Running=True,Status='running',Pid=1000,OOMKilled=False,Restarting=False,ExitCode=0,
   StartedAt='2026-11-01T14:00:00Z',FinishedAt='0001-01-01T00:00:00Z',Health={'Status':'healthy'}))
def original_model():
 return dict(name='elevenid-beta',services={m.ROLE:dict(image=m.IMAGE,read_only=True,pull_policy='never',
  secrets=[dict(source='northstar_run',target='northstar_run')])},
  secrets={'northstar_run':{'file':'/owned/fixture.json'}},
  networks={'beta':{'external':True,'name':'elevenid-beta-network'}})

class Controls(unittest.TestCase):
 def setUp(self):
  self.before=original()
  self.model=original_model()
  self.fixture='/owned/new-fixture.json'
  self.new=copy.deepcopy(self.before);self.new['Id']='f'*64
  if self.before['Config']['Hostname']==self.before['Id'][:12]:self.new['Config']['Hostname']=self.new['Id'][:12]
  self.provenance={k:self.before['Config']['Labels'].get(k,'') for k in ['com.docker.compose.config-hash','com.docker.compose.project.config_files','com.docker.compose.project.working_dir','com.docker.compose.version']}
  self.provenance['com.docker.compose.config-hash']='SOURCE_ONLY_NEW_HASH'
  self.new['Config']['Labels'].update(self.provenance)
  old=self.before['Mounts'][0]['Source'];self.new['Mounts'][0]['Source']=self.fixture
  self.new['HostConfig']['Binds']=[v.replace(old,self.fixture) for v in (self.new['HostConfig'].get('Binds') or [])]
  for mount in self.new['HostConfig'].get('Mounts',[]):
   if mount.get('Target')==m.TARGET:mount['Source']=self.fixture
  self.new['State'].update(Running=False,Status='created',Pid=0,OOMKilled=False,StartedAt='0001-01-01T00:00:00Z',FinishedAt='0001-01-01T00:00:00Z')
 def guard(self,row):m.candidate_guard(self.before,row,fixture=self.fixture,provenance=self.provenance,running=False,host_mounts=reps.host_mounts,daemon_source=reps.daemon_source)
 def test_one_fixture_created_control(self):self.guard(self.new)
 def test_wrong_source(self):
  row=copy.deepcopy(self.new);row['Mounts'][0]['Source']+='-wrong'
  with self.assertRaises(ValueError):self.guard(row)
 def test_writable_or_duplicate_or_unknown_mount_option(self):
  for mutate in [lambda r:r['Mounts'][0].update(RW=True),lambda r:r['Mounts'].append(copy.deepcopy(r['Mounts'][0])),lambda r:r['HostConfig']['Mounts'][0].update(BindOptions={'Unreviewed':True})]:
   row=copy.deepcopy(self.new);mutate(row)
   with self.assertRaises(ValueError):self.guard(row)
 def test_foreign_config_network_or_image(self):
  for mutate in [lambda r:r['Config']['Env'].append('SOURCE_ONLY_UNRELATED=changed'),lambda r:r.update(Image='sha256:'+'0'*64),lambda r:next(iter(r['NetworkSettings']['Networks'].values())).update(NetworkID='wrong')]:
   row=copy.deepcopy(self.new);mutate(row)
   with self.assertRaises(ValueError):self.guard(row)
 def test_only_fixture_model_source_may_change(self):
  changed=copy.deepcopy(self.model);changed['secrets']['northstar_run']['file']=self.fixture;m.model_delta(self.model,changed,self.fixture)
  changed['services'][m.ROLE]['read_only']=False
  with self.assertRaises(ValueError):m.model_delta(self.model,changed,self.fixture)
 def test_same_original_restart_requires_explicit_completed_restore_intent(self):
  row=copy.deepcopy(self.before);row['State'].update(StartedAt='2026-11-02T00:00:00Z',Running=True)
  kwargs=dict(fixture=self.before['Mounts'][0]['Source'],provenance=self.provenance,running=True,host_mounts=reps.host_mounts,daemon_source=reps.daemon_source)
  with self.assertRaises(ValueError):m.candidate_guard(self.before,row,**kwargs)
  m.candidate_guard(self.before,row,allow_original_restart=True,**kwargs)
 def test_shared_hooks_defaults_and_no_state_machine_copy(self):
  core=module('reviewed_meta',HERE/'repair_beta_release_metadata.py')
  self.assertEqual(core.Operation.stop_exit_codes(None,'gateway'),(0,))
  self.assertEqual(core.Operation.stop_arguments(None,'gateway','known','SIGTERM'),['kill','--signal','SIGTERM','known'])
  self.assertTrue(core.Operation.cached_image_matches(None,'ref',{'RepoDigests':['ref']}))
  cls=m.execution_type(core)
  self.assertEqual(cls.stop_exit_codes(None,m.ROLE),(143,))
  self.assertEqual(cls.stop_arguments(None,m.ROLE,'known','SIGTERM'),['stop','--signal','SIGTERM','--timeout','-1','known'])
  self.assertIs(cls.create_start,core.Operation.create_start)
  self.assertIs(cls.stop_generation,core.Operation.stop_generation)



class SharedRecovery(Controls):
 def run_recovery(self, *, failed_start, pending_start=False, missing_start=False):
  import tempfile,types,hashlib
  core=module('recover_core',HERE/'repair_beta_release_metadata.py')
  cls=m.execution_type(core)
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)
   def save(name,value):
    p=root/name;p.write_text(json.dumps(value));return core.ref(p)
   old_fixture=root/'old-fixture.json';old_fixture.write_text('{}')
   new_fixture=root/'new-fixture.json';new_fixture.write_text('{}')
   changed=copy.deepcopy(self.model);changed['secrets']['northstar_run']['file']=str(new_fixture)
   original=copy.deepcopy(self.before)
   new=copy.deepcopy(self.new)
   new['Mounts'][0]['Source']=str(new_fixture)
   for mount in new['HostConfig'].get('Mounts',[]):
    if mount.get('Target')==m.TARGET:mount['Source']=str(new_fixture)
   new['State'].update(Status='exited',Running=False,Pid=0,Restarting=False,ExitCode=1,
                      StartedAt='2026-11-01T20:00:00Z',FinishedAt='2026-11-01T20:00:01Z')
   rows={new['Id']:new} if failed_start else {original['Id']:copy.deepcopy(original)}
   if not failed_start:rows[original['Id']]['State'].update(Status='exited',Running=False,Pid=0,ExitCode=143)
   retained='a'*64
   config=dict(scope='FUNCTIONAL_ONLY',sourceRevision=m.SOURCE,runId='run-source-control',sourceSha256='reviewed-source',
     oldCids={m.ROLE:original['Id']},originalContainer=save('original.json',original),
     oldModels={m.ROLE:save('old-model.json',self.model)},newModels={m.ROLE:save('new-model.json',changed)},
     oldFixture=core.ref(old_fixture),newFixture=core.ref(new_fixture),
     oldPublicManifest=core.ref(old_fixture),publicManifest=core.ref(new_fixture),
     provenance={'apply':self.provenance,'rollback':self.provenance},rollbackAuthorized=True,
     preflightResult=save('preflight.json',{'allIds':[original['Id'],retained]}))
   operations=['apply-create-'+m.ROLE] if failed_start else ['apply-stop-'+m.ROLE]
   if failed_start and not (pending_start or missing_start):operations.append('apply-start-'+m.ROLE)
   failed=dict(sourceSha256=config['sourceSha256'],runId=config['runId'],oldCids=config['oldCids'],
     newCids={m.ROLE:new['Id']} if failed_start else {},operations=operations,
     pending='apply-start-'+m.ROLE if pending_start else None,
     before=save('before.json',{m.ROLE:original}))
   config['recoveryState']=save('failure.json',failed)
   calls=[]
   def inspect(cid):return copy.deepcopy(rows[cid])
   def observe(args,stem):
    if args[:2]==['image','inspect']:return [{'Id':m.IMAGE,'Config':{'Labels':{'org.opencontainers.image.revision':m.SOURCE}}}]
    if args[:2]==['network','inspect']:
     network=next(iter(original['NetworkSettings']['Networks'].values()))
     return [{'Id':network['NetworkID']}]
    raise AssertionError(args)
   def lines(args,stem):return list(rows) if '--filter' in args else [retained,*rows]
   def command(args,stem,**kwargs):
    calls.append(args)
    assert args[0]=='start',args
    row=rows[args[1]];row['State'].update(Status='running',Running=True,Pid=99999,StartedAt='2026-11-01T21:00:00Z',Health={'Status':'healthy'})
   def compose(args,stem,**kwargs):
    calls.append(['compose',*args]);assert args[:2]==['up','--no-start']
    row=copy.deepcopy(self.new);row['Id']='e'*64
    row['Config']['Hostname']=row['Id'][:12] if original['Config']['Hostname']==original['Id'][:12] else original['Config']['Hostname']
    row['Mounts']=copy.deepcopy(original['Mounts']);row['HostConfig']=copy.deepcopy(original['HostConfig'])
    rows.clear();rows[row['Id']]=row
   g=types.SimpleNamespace(inspect=inspect,observe=observe,observe_lines=lines,engine=lambda:None,
     command=command,compose=compose,IMAGE_IDS={},IMAGE_CONFIG={},NETWORK_IDS={})
   out=root/'out';out.mkdir()
   operation=cls(config,out,transport=g,identities={str(i):{} for i in range(22)},representations=reps,
     observe_external=lambda fixture:{'fixtureMatches':True})
   result=operation.recover(failed)
   self.assertEqual(result['state'],'D11_NORTHSTAR_ORIGINAL_CONFIGURATION_RESTORED')
   self.assertNotIn('oldMarker',config)
   self.assertTrue(any(call[0]=='start' for call in calls))
   return calls
 def test_failed_started_exited_successor_reaches_shared_rollback(self):
  calls=self.run_recovery(failed_start=True)
  self.assertTrue(any(call[0]=='compose' for call in calls))
 def test_pending_start_known_cid_can_recover(self):self.run_recovery(failed_start=True,pending_start=True)
 def test_exited_successor_without_start_authority_refuses_before_effect(self):
  with self.assertRaises(ValueError):self.run_recovery(failed_start=True,missing_start=True)
 def test_original_only_shared_rollback_starts_exact_old_cid(self):
  calls=self.run_recovery(failed_start=False)
  self.assertFalse(any(call[0]=='compose' for call in calls))

if __name__=='__main__':unittest.main()
