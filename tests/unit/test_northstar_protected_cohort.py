"""Hermetic scoped-cohort risks; no Docker, API, Node or browser process."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

UI=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(UI/'scripts'))
import northstar_protected_cohort as m


def cid(i): return f'{i:064x}'
def row(i,project='elevenid-beta',network='beta-network'):
    return {'Id':cid(i),'Name':'/row-'+str(i),'Labels':{'com.docker.compose.project':project,
        'com.docker.compose.service':'role-'+str(i)},'Networks':{network:{'NetworkID':cid(999)}},'Generation':{'Running':True,'Paused':False,'Restarting':False,'OOMKilled':False,'Pid':i,'StartedAt':'stable'}}


class Controls(unittest.TestCase):
    def test_native_failure_dto_preserves_only_safe_bounded_summary(self):
        config={'protectedCohort':{'schema':m.SCHEMA,'profile':{'sha256':'a'*64}},
                'runtimeAuthority':{'profile':{'sha256':'a'*64}},'sourceRepository':str(UI),
                'currentSourceAuthority':{'ui':'a'*40},'nodeExecutable':{}}
        core=types.SimpleNamespace(git_blob=lambda repo,revision,relative:(UI/relative).read_bytes(),read_executable_ref=lambda ref:Path('synthetic-node'))
        summary={'status':4294967295,'timedOut':False,'signalled':True,'stdoutBytes':0,'stderrBytes':43}
        failure={'schema':'marty.northstar-runtime-scope-failure/v1','errorClass':'Error','code':'NATIVE_DOCKER_SYNC_FAILED','operationSummary':{**summary,'stderr':'secret-provider-token'}}
        terminal=types.SimpleNamespace(stdout=json.dumps(failure).encode(),returncode=1)
        with patch.object(m,'native_projection',return_value={}),patch.object(m.subprocess,'run',return_value=terminal):
            with self.assertRaisesRegex(ValueError,'NATIVE_DOCKER_SYNC_FAILED') as caught:m.runtime_authority(config,core,live=True)
        self.assertEqual(caught.exception.scopeFailure['operationSummary'],summary)
        self.assertNotIn('secret',json.dumps(caught.exception.scopeFailure))
        self.assertEqual(m.safe_operation_summary({'status':True,'stdoutBytes':2**40,'stderrBytes':-1,'timedOut':'secret','signalled':1}),
                         {'status':None,'stdoutBytes':None,'stderrBytes':None,'timedOut':False,'signalled':False})
        self.assertIsNone(m.safe_operation_summary([]))

    def test_native_projection_binds_actual_fixture_without_inheriting_execution_authority(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            def save(name,value):
                file=root/name;file.write_text(json.dumps(value),encoding='utf-8')
                return {'path':str(file),'sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
            def bound(ref):
                p=Path(ref['path']);assert hashlib.sha256(p.read_bytes()).hexdigest()==ref['sha256'];return p
            repo=root/'recorder';(repo/'src').mkdir(parents=True)
            for name in ('externalQualification.js','canvasDockerTransport.js'):(repo/'src'/name).write_bytes(b'pinned owner')
            profile=save('profile.json',{});observation=save('observation.json',{})
            descriptor=save('descriptor.json',{'engineId':'reviewed-engine'});canary=save('canary.json',{})
            receipt=save('fixture-result.json',{'runId':'owned-run','driverSource':'6'*40,'recorderSource':'a'*40})
            fixture={'runId':'owned-run','driverRevision':'6'*40,'recorderRevision':'a'*40,'executeAuthorized':True,
                     'profile':profile,'observation':observation,'dockerTransport':descriptor,'dockerCanary':canary}
            selected={'fixtureInput':save('input.armed.json',fixture),'recorderRepository':str(repo)}
            config={'runId':'owned-run','fixtureAuthority':receipt,'currentSourceAuthority':{'recorder':'a'*40,'ui':'9'*40},
                    'engineId':'reviewed-engine','runtimeAuthority':{'profile':profile,'observation':observation},
                    'protectedCohort':{'nativeTransport':selected},'executeAuthorized':False}
            core=types.SimpleNamespace(load=lambda r:json.loads(bound(r).read_bytes()),read_ref=bound,git_blob=lambda *args:b'pinned owner')
            result=m.native_projection(config,core)
            self.assertEqual(result['dockerTransport'],descriptor);self.assertEqual(result['dockerCanary'],canary)
            self.assertNotIn('executeAuthorized',result);self.assertFalse(config['executeAuthorized'])
            for key,value in [('runId','foreign'),('driverRevision','f'*40),('recorderRevision','e'*40)]:
                bad={**fixture,key:value};selected['fixtureInput']=save('bad-'+key+'.json',bad)
                with self.subTest(key=key),self.assertRaisesRegex(AssertionError,'SCOPE_NATIVE_FIXTURE_SOURCE_CHANGED'):
                    m.native_projection(config,core)
            selected['fixtureInput']=save('good-again.json',fixture)
            config['engineId']='foreign'
            with self.assertRaisesRegex(AssertionError,'SCOPE_NATIVE_ENGINE_CHANGED'):m.native_projection(config,core)
            config['engineId']='reviewed-engine';(repo/'src/canvasDockerTransport.js').write_bytes(b'changed owner')
            with self.assertRaisesRegex(AssertionError,'SCOPE_NATIVE_SOURCE_CHANGED'):m.native_projection(config,core)

    def test_producer_prepare_failure_retains_fixed_metadata_without_success_report(self):
        spec=importlib.util.spec_from_file_location('scope_producer_boundary',UI/'scripts/reconcile_northstar_off.py')
        producer=importlib.util.module_from_spec(spec);spec.loader.exec_module(producer)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);private=root/'.codex/private';private.mkdir(parents=True)
            def save(name,value):
                file=private/name;file.write_text(value if isinstance(value,str) else json.dumps(value),encoding='utf-8')
                return {'path':str(file),'sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
            dispatcher=save('dispatcher.py',"def prepare(config, output):\n raise ValueError('SCOPE_NATIVE_TEST_REFUSED')\n")
            operation=save('operation.json',{'sourceSha256':dispatcher['sha256']})
            input=save('input.json',{'readOnlyVerificationAuthorized':True,'dispatcher':dispatcher,'operation':operation,'outputDir':str(private/'output')})
            with patch.object(sys,'argv',['producer','--input',input['path']]),patch.object(producer.Path,'home',return_value=root),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(producer.main(),1)
            failure=json.loads((private/'output/failure.json').read_bytes())
            self.assertEqual(failure['code'],'SCOPE_NATIVE_TEST_REFUSED');self.assertEqual(failure['stage'],'prepare')
            self.assertFalse((private/'output/result.json').exists())
            secret=ValueError('secret-cookie-value /private/provider/path')
            safe=producer.failure_record(secret,'observe-recovered-off')
            self.assertEqual(safe['code'],'READONLY_RECONCILIATION_FAILED');self.assertNotIn('secret',json.dumps(safe))
            secret.scopeFailure={'errorClass':'AssertionError','code':'RESOURCE_PRESERVED_MOUNT_CHANGED','exitCode':1,'stdoutBytes':200}
            self.assertEqual(producer.failure_record(secret,'observe-recovered-off')['scopeFailure'],secret.scopeFailure)

    def test_pause_authority_requires_exact_source_command_and_terminal_job(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            def ref(name,sha='a'*64):return {'path':str(root/name),'sha256':sha}
            scope={'stockBefore':ref('before.json'),'stockPaused':ref('paused.json'),'stockPause':{
                'operator':ref('operate.py',m.PAUSE_SOURCE_SHA256),'controller':ref('run-contained.cjs',m.PAUSE_CONTROLLER_SHA256),
                'request':ref('request.json'),'job':ref('job.json')}}
            request={'schema':'marty.windows-job-request/v1','command':['python','-B',str(root/'operate.py'),'pause'],
                'cwd':str(root),'receiptFile':str(root/'job.json'),'executableSha256':'b'*64,
                'memoryBytes':256*1024**2,'hostMarginBytes':1024**3,'processLimit':32}
            job={'schema':'marty.windows-job-result/v1','executableSha256':'b'*64,'jobClosed':True,
                'terminalActiveProcesses':0,'processCreatedSuspended':True,'assignedBeforeResume':True,
                'forcedTermination':False,'hostMarginBreached':False,'jobMemoryBytes':256*1024**2,'state':'COMPLETE','exitCode':0}
            values={'request.json':request,'job.json':job}
            core=types.SimpleNamespace(load=lambda r:values[Path(r['path']).name],read_ref=lambda r:Path(r['path']))
            m.pause_authority(scope,core)
            for key,value in [('jobClosed',False),('terminalActiveProcesses',1),('forcedTermination',True),('hostMarginBreached',True)]:
                with self.subTest(key=key):
                    previous=job[key];job[key]=value
                    with self.assertRaises((ValueError,AssertionError)):m.pause_authority(scope,core)
                    job[key]=previous
            request['command'][-1]='restore'
            with self.assertRaisesRegex(AssertionError,'SCOPE_PAUSE_JOB_CHANGED'):m.pause_authority(scope,core)
            request['command'][-1]='pause';scope['stockPause']['controller']['sha256']='f'*64
            with self.assertRaisesRegex(AssertionError,'SCOPE_PAUSE_SOURCE_CHANGED'):m.pause_authority(scope,core)

    def fixture(self,root):
        roles={'role-'+str(i):cid(i) for i in range(1,29)}
        model=(UI/'docker-compose.canvas-oss-acceptance.yml').read_bytes()
        names=sorted(m.STOCK_NAMES|{'/marty-canvas-oss-postgres','/marty-canvas-oss-redis','/marty-canvas-oss-mail'})
        stock={}
        full={}
        rows={cid(i):row(i) for i in range(1,29)}
        for i,name in enumerate(names,1000):
            live={'Running':name not in m.STOCK_NAMES,'Pid':0 if name in m.STOCK_NAMES else i,
                  'StartedAt':'stable','Paused':False,'Restarting':False}
            actual={'Id':cid(i),'Name':name,'Image':'image','Config':{'Env':[],'Labels':{'com.docker.compose.project':'stock','com.docker.compose.service':name.replace('/marty-canvas-oss-','canvas-')}},'HostConfig':{},'Mounts':[],'State':{**live,'OOMKilled':False}}
            full[cid(i)]=actual
            stock[cid(i)]={'name':name,'image':'image','spec':m.spec(actual),'live':copy.deepcopy(live)}
            rows[cid(i)]=row(i,'stock','stock-network');rows[cid(i)]['Name']=name;rows[cid(i)]['Labels']=copy.deepcopy(actual['Config']['Labels']);rows[cid(i)]['Generation']={key:actual['State'][key] for key in ('Running','Paused','Restarting','OOMKilled','Pid','StartedAt')}
            rows[cid(i)]['Networks']['stock-network']['NetworkID']=cid(998)
        rows[cid(200)]=row(200)
        monitor=copy.deepcopy(full[cid(1000)]);monitor.update(Id=cid(1100),Name='/stock-canvas-continuity-monitor-1')
        monitor['Config']['Labels']['com.docker.compose.service']='canvas-continuity-monitor'
        monitor['State'].update(Running=False,Pid=0)
        full[cid(1100)]=monitor
        stock[cid(1100)]={'name':monitor['Name'],'image':monitor['Image'],'spec':m.spec(monitor),'live':copy.deepcopy(monitor['State'])}
        rows[cid(1100)]=row(1100,'stock','stock-network');rows[cid(1100)]['Name']=monitor['Name']
        rows[cid(1100)]['Labels']=copy.deepcopy(monitor['Config']['Labels'])
        rows[cid(1100)]['Networks']['stock-network']['NetworkID']=cid(998)
        rows[cid(1100)]['Generation']={key:monitor['State'][key] for key in ('Running','Paused','Restarting','OOMKilled','Pid','StartedAt')}
        stopped={}
        for i in range(14):
            id=cid(50+i);role='off-'+str(i)
            rows[id]=row(50+i);rows[id]['Labels']['com.docker.compose.service']=role
            rows[id]['Generation'].update(Running=False,Pid=0)
            actual={'Id':id,'Name':rows[id]['Name'],'Image':'off-image','Config':{'Labels':copy.deepcopy(rows[id]['Labels']),'Env':[]},
                    'HostConfig':{'ReadonlyRootfs':True},'Mounts':[],
                    'State':{**rows[id]['Generation'],'FinishedAt':'stopped'},'NetworkSettings':{'Networks':copy.deepcopy(rows[id]['Networks'])}}
            stopped[id]=copy.deepcopy(actual);full[id]=actual;roles[role]=id
        roles=m.RuntimeRoles(roles,stopped=stopped)
        config={'protectedCohort':{'schema':m.SCHEMA,'profile':{'sha256':'a'*64},
                'stockBefore':{'rows':stock,'targets':{k:v['name'] for k,v in stock.items() if v['name'] in m.STOCK_NAMES}},
                'stockPause':{},'nativeTransport':{},'stockModelAnchor':[copy.deepcopy(next(r for r in full.values() if r['Name']=='/marty-canvas-oss-web'))],'stockPaused':{'state':'ONLY_STOCK_CANVAS_WEB_JOBS_EDGE_STOPPED','allOtherRowsUnchanged':True,'specsUnchanged':True}},
                'sourceRepository':str(UI),'currentSourceAuthority':{'ui':'revision'}}
        core=types.SimpleNamespace(load=lambda x:x,git_blob=lambda *args:model)
        with patch.object(m,'runtime_authority',return_value=roles),patch.object(m,'pause_authority'):
            scope=m.ProtectedCohort(config,core,{k:{'containerId':v} for k,v in list(roles.items())[:22]})
        class Transport:
            def observe_lines(self,args,stem): return sorted(rows)
            def command(self,args,stem,**kwargs):
                self.last=(args,kwargs)
                p=root/(stem+'.jsonl');p.write_bytes(b'\n'.join(json.dumps(rows[k]).encode() for k in sorted(rows)));return p
            def inspect(self,id): return full[id]
            def old_guard(self,expected,*,running):
                actual=full[expected['Id']]
                assert all(actual[k]==expected[k] for k in ('Id','Name','Image','Config','HostConfig','Mounts')),'OLD_CONFIG_CHANGED'
                assert actual['State']['Running'] is running
                return actual
        transport=Transport()
        return scope,roles,rows,full,transport

    def test_independent_add_remove_keeps_raw_ids_and_census(self):
        with tempfile.TemporaryDirectory() as d:
            scope,roles,rows,_,g=self.fixture(Path(d))
            rows[cid(300)]=row(300,'foreign','foreign-network');rows[cid(300)]['Networks']['foreign-network']['NetworkID']=cid(997)
            with patch.object(m,'runtime_authority',return_value=roles):
                first=scope.snapshot(g,'before',{cid(200)})
                del rows[cid(300)];rows[cid(301)]=row(301,'foreign2','other');rows[cid(301)]['Networks']['other']['NetworkID']=cid(996)
                after=scope.snapshot(g,'after',{cid(200)})
            scope.assert_cohort(after,first,'CHANGED',phase='execute-before',known_ids={cid(200)})
            self.assertIn(cid(300),first);self.assertIn(cid(301),after)
            proof=scope.proof();scope.validate_proof(proof,cid(200))
            self.assertFalse(proof['globalUnchangedClaimed'])
            self.assertEqual(g.last[1],{'limit':m.CENSUS_LIMIT})
            self.assertNotIn('Env',g.last[0][2])

    def test_managed_project_and_network_collisions_refused(self):
        for project,network,network_id in [('elevenid-beta','foreign',997),('foreign','beta-network',997),('foreign','foreign',999)]:
            with self.subTest(project=project,network=network,network_id=network_id), tempfile.TemporaryDirectory() as d:
                scope,roles,rows,_,g=self.fixture(Path(d))
                rows[cid(300)]=row(300,project,network);rows[cid(300)]['Networks'][network]['NetworkID']=cid(network_id)
                with patch.object(m,'runtime_authority',return_value=roles),self.assertRaisesRegex(AssertionError,'SCOPE_MANAGED_COLLISION'):
                    scope.snapshot(g,'collision',{cid(200)})

    def test_declared_existing_monitor_is_protected_but_absent_profiles_remain_absent(self):
        with tempfile.TemporaryDirectory() as d:
            scope,roles,rows,_,g=self.fixture(Path(d))
            self.assertEqual(len(scope.stock),7);self.assertEqual(len(scope.fixed),49)
            self.assertIn('canvas-continuity-monitor',scope.stock_roles.values())
            self.assertNotIn('canvas-contract',scope.stock_roles.values());self.assertNotIn('canvas-lifecycle',scope.stock_roles.values())
            with patch.object(m,'runtime_authority',return_value=roles):observed=scope.snapshot(g,'seven-peers',{cid(200)})
            self.assertEqual(len(observed),50)
            for service in ('canvas-contract','undeclared-peer'):
                added=row(1600,'stock','stock-network');added['Name']='/stock-'+service+'-1'
                added['Labels']['com.docker.compose.service']=service;added['Networks']['stock-network']['NetworkID']=cid(998)
                rows[cid(1600)]=added
                with patch.object(m,'runtime_authority',return_value=roles),self.assertRaisesRegex(AssertionError,'SCOPE_MANAGED_COLLISION'):
                    scope.snapshot(g,'unexpected-'+service,{cid(200)})
                del rows[cid(1600)]

    def test_same_optional_service_in_foreign_project_is_not_adopted_from_before(self):
        with tempfile.TemporaryDirectory() as d:
            scope,roles,rows,_,g=self.fixture(Path(d))
            foreign=row(1600,'foreign-project','foreign-network');foreign['Name']='/foreign-project-canvas-continuity-monitor-1'
            foreign['Labels']['com.docker.compose.service']='canvas-continuity-monitor';foreign['Networks']['foreign-network']['NetworkID']=cid(997)
            rows[cid(1600)]=foreign
            scope.config['protectedCohort']['stockBefore']['rows'][cid(1600)]={'name':foreign['Name'],'live':{'Running':False,'Pid':0}}
            with patch.object(m,'runtime_authority',return_value=roles),patch.object(m,'pause_authority'):
                rebuilt=m.ProtectedCohort(scope.config,scope.core,{k:{'containerId':v} for k,v in list(roles.items())[:22]})
                rebuilt.snapshot(g,'foreign-optional',{cid(200)})
            self.assertNotIn(cid(1600),rebuilt.fixed);self.assertEqual(len(rebuilt.stock),7)

    def test_optional_peer_type_spec_generation_and_anchor_drift_refuse(self):
        for change in ('type','spec','generation','service'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as d:
                scope,roles,rows,full,g=self.fixture(Path(d));actual=full[cid(1100)]
                if change=='type':actual['Mounts']=[{'Type':'volume','Source':'foreign','Destination':'/data','RW':True}]
                if change=='spec':actual['HostConfig']['ReadonlyRootfs']=False
                if change=='generation':actual['State']['StartedAt']='foreign-generation'
                if change=='service':rows[cid(1100)]['Labels']['com.docker.compose.service']='canvas-contract'
                with patch.object(m,'runtime_authority',return_value=roles),self.assertRaisesRegex(AssertionError,'SCOPE_STOCK_(CHANGED|SERVICE_CHANGED)'):
                    scope.snapshot(g,'optional-drift',{cid(200)})
        with tempfile.TemporaryDirectory() as d:
            scope,roles,_,_,_=self.fixture(Path(d))
            scope.config['protectedCohort']['stockModelAnchor'][0]['Config']['Env']=['ANCHOR_CHANGED=1']
            with patch.object(m,'runtime_authority',return_value=roles),patch.object(m,'pause_authority'),self.assertRaisesRegex(AssertionError,'SCOPE_STOCK_ANCHOR_CHANGED'):
                m.ProtectedCohort(scope.config,scope.core,{k:{'containerId':v} for k,v in list(roles.items())[:22]})

    def test_shared_docker_builtin_network_is_not_claimed_as_project_owned(self):
        with tempfile.TemporaryDirectory() as d:
            scope,roles,rows,_,g=self.fixture(Path(d))
            rows[cid(1)]['Networks']['none']={'NetworkID':cid(995)}
            rows[cid(300)]=row(300,'foreign','none');rows[cid(300)]['Networks']['none']['NetworkID']=cid(995)
            with patch.object(m,'runtime_authority',return_value=roles):
                actual=scope.snapshot(g,'shared-none',{cid(200)})
            self.assertIn(cid(300),actual)

    def test_every_protected_class_missing_refuses(self):
        for missing in (1,28,50,1000,1100,200):
            with self.subTest(missing=missing),tempfile.TemporaryDirectory() as d:
                scope,roles,rows,_,g=self.fixture(Path(d));del rows[cid(missing)]
                with patch.object(m,'runtime_authority',return_value=roles),self.assertRaisesRegex(AssertionError,'SCOPE_PROTECTED_ID_MISSING'):
                    scope.snapshot(g,'missing',{cid(200)})

    def test_stock_spec_or_generation_drift_refuses(self):
        for field in ('Config','State'):
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                scope,roles,rows,full,g=self.fixture(Path(d))
                if field=='Config':full[cid(1000)]['Config']['Env']=['CHANGED=1']
                else:full[cid(1000)]['State']['StartedAt']='new'
                with patch.object(m,'runtime_authority',return_value=roles),self.assertRaisesRegex(AssertionError,'SCOPE_STOCK_CHANGED'):
                    scope.snapshot(g,'changed',{cid(200)})

    def test_authority_drift_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            scope,roles,rows,_,g=self.fixture(Path(d));roles=m.RuntimeRoles({**roles,'role-28':cid(500)},stopped=roles.stopped)
            with patch.object(m,'runtime_authority',return_value=roles),self.assertRaisesRegex(AssertionError,'SCOPE_RUNTIME_CHANGED'):
                scope.snapshot(g,'changed',{cid(200)})

    def test_same_cid_ancillary_generation_drift_refuses(self):
        for field,value in [('Pid',555),('StartedAt','new-generation')]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                scope,roles,rows,_,g=self.fixture(Path(d))
                with patch.object(m,'runtime_authority',return_value=roles):
                    scope.snapshot(g,'first',{cid(200)})
                    rows[cid(28)]['Generation'][field]=value
                    with self.assertRaisesRegex(AssertionError,'SCOPE_PROTECTED_METADATA_CHANGED'):
                        scope.snapshot(g,'restarted',{cid(200)})

    def test_fourteen_off_roles_preserve_bound_configuration_and_terminal_generation(self):
        for change in ('config','pid','startedAt','running','network'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as d:
                scope,roles,rows,full,g=self.fixture(Path(d))
                self.assertEqual(len(scope.roles),42);self.assertEqual(len(scope.stopped),14)
                self.assertTrue(all(r['State']['Running'] is False and r['State']['Pid']==0 for r in scope.stopped.values()))
                with patch.object(m,'runtime_authority',return_value=roles):
                    scope.snapshot(g,'before',{cid(200)})
                    actual=full[cid(50)]
                    if change=='config':actual['Config']['Env']=['CHANGED=1']
                    if change=='pid':actual['State']['Pid']=99
                    if change=='startedAt':actual['State']['StartedAt']='new-generation'
                    if change=='running':actual['State']['Running']=True
                    if change=='network':actual['NetworkSettings']['Networks']={'foreign':{'NetworkID':cid(997)}}
                    with self.assertRaises(AssertionError):scope.snapshot(g,'off-drift',{cid(200)})

    def test_outside_scope_generation_drift_is_recorded_without_unchanged_claim(self):
        with tempfile.TemporaryDirectory() as d:
            scope,roles,rows,_,g=self.fixture(Path(d))
            rows[cid(300)]=row(300,'foreign','foreign-network');rows[cid(300)]['Networks']['foreign-network']['NetworkID']=cid(997)
            with patch.object(m,'runtime_authority',return_value=roles):
                before=scope.snapshot(g,'first',{cid(200)})
                rows[cid(300)]['Generation'].update(Pid=500,StartedAt='new-generation')
                after=scope.snapshot(g,'restarted-foreign',{cid(200)})
            scope.assert_cohort(after,before,'CHANGED',phase='execute-before',known_ids={cid(200)})
            proof=scope.proof()
            self.assertNotEqual(proof['observations'][0]['classification'][cid(300)]['Generation'],
                                proof['observations'][1]['classification'][cid(300)]['Generation'])
            self.assertFalse(proof['globalUnchangedClaimed'])

    def test_target_replacement_requires_journal_expected_identity(self):
        with tempfile.TemporaryDirectory() as d:
            scope,roles,rows,_,g=self.fixture(Path(d))
            with patch.object(m,'runtime_authority',return_value=roles):actual=scope.snapshot(g,'before',{cid(200)})
            with self.assertRaisesRegex(AssertionError,'WRONG_TARGET'):
                scope.assert_cohort(actual,(actual-{cid(200)})|{cid(201)},'WRONG_TARGET',phase='recovery-before',known_ids={cid(200),cid(201)})

    def test_complete_typed_census_required(self):
        good=row(1);raw=json.dumps(good).encode()
        self.assertEqual(set(m.parse_census(raw,{cid(1)})),{cid(1)})
        cases=[(b'',{cid(1)}),(raw+b'\n'+raw,{cid(1)}),(raw,{cid(2)}),
               (json.dumps({**good,'Env':['secret']}).encode(),{cid(1)}),
               (json.dumps({**good,'Networks':{'bad':{'NetworkID':'invalid'}}}).encode(),{cid(1)}),
               (b' '*(m.CENSUS_LIMIT+1),{cid(1)})]
        for data,ids in cases:
            with self.subTest(size=len(data)),self.assertRaises((AssertionError,json.JSONDecodeError)):
                m.parse_census(data,ids)

    def test_current_scope_does_not_admit_missing_protected_from_historical_ids(self):
        with tempfile.TemporaryDirectory() as d:
            scope,roles,rows,_,g=self.fixture(Path(d))
            with patch.object(m,'runtime_authority',return_value=roles):
                scope.snapshot(g,'first',{cid(200)});scope.snapshot(g,'final',{cid(200)})
            proof=scope.proof();scope.validate_proof(proof,cid(200))
            # A historical foreign ID need not exist, but protected membership
            # cannot be relabelled outside scope in a terminal proof.
            bad=copy.deepcopy(proof);bad['observations'][-1]['protectedIds'].remove(cid(28))
            with self.assertRaisesRegex(AssertionError,'SCOPE_PROOF_MEMBERSHIP'):
                scope.validate_proof(bad,cid(200))

    def test_real_operation_hooks_apply_and_rollback_with_foreign_churn(self):
        spec=importlib.util.spec_from_file_location('scope_existing_scenario',UI/'tests/unit/test_scoped_northstar_fixture.py')
        legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);scenario=legacy.Scenario(root,startup=True)
            fixture_scope,fixture_roles,_,full,_=self.fixture(root)
            roles={role:identity['containerId'] for role,identity in scenario.identities.items()}
            for i in range(6):
                role='ancillary-'+str(i);new=copy.deepcopy(scenario.old);new['Id']=cid(500+i)
                new['Config']['Labels']['com.docker.compose.service']=role
                scenario.rows[new['Id']]=new;roles[role]=new['Id']
            stock={}
            for id,actual in full.items():
                if id not in fixture_scope.stock:continue
                actual=copy.deepcopy(actual)
                actual['Config']['Labels']={'com.docker.compose.project':'stock','com.docker.compose.service':fixture_scope.stock_roles[id]}
                actual['NetworkSettings']={'Networks':{'stock-network':{'NetworkID':cid(998)}}}
                scenario.rows[id]=actual
                stock[id]={'id':id,'name':actual['Name'],'image':actual['Image'],'spec':m.spec(actual),'live':copy.deepcopy(actual['State'])}
            stopped={}
            for i in range(14):
                role='off-'+str(i);actual=copy.deepcopy(scenario.old);actual['Id']=cid(700+i)
                actual['Config']['Labels']['com.docker.compose.service']=role;actual['State']['Paused']=False
                scenario.rows[actual['Id']]=actual;roles[role]=actual['Id'];stopped[actual['Id']]=copy.deepcopy(actual)
            roles=m.RuntimeRoles(roles,stopped=stopped)
            scope={'schema':m.SCHEMA,'profile':{'sha256':'a'*64},'stockPause':{},'nativeTransport':{},'stockModelAnchor':scenario.save('stock-anchor.json',[next(r for r in scenario.rows.values() if r['Name']=='/marty-canvas-oss-web')]),
                'stockBefore':scenario.save('stock-before.json',{'rows':stock,'targets':{id:r['name'] for id,r in stock.items() if r['name'] in m.STOCK_NAMES}}),
                'stockPaused':scenario.save('stock-paused.json',{'state':'ONLY_STOCK_CANVAS_WEB_JOBS_EDGE_STOPPED','allOtherRowsUnchanged':True,'specsUnchanged':True})}
            scenario.config.update(protectedCohort=scope,sourceRepository=str(UI),currentSourceAuthority={'ui':'test'})
            scenario.core.git_blob=lambda *args:(UI/'docker-compose.canvas-oss-acceptance.yml').read_bytes()
            original_command=scenario.g.command
            counter=[0]
            def command(args,stem,**kwargs):
                if args[:2]==['inspect','--format']:
                    counter[0]+=1;p=root/('census-'+str(counter[0])+'.jsonl')
                    rows=[{'Id':r['Id'],'Name':r['Name'],'Labels':r['Config'].get('Labels'),
                           'Networks':r['NetworkSettings']['Networks'],'Generation':{key:r['State'].get(key,False) for key in ('Running','Paused','Restarting','OOMKilled','Pid','StartedAt')}} for id,r in scenario.rows.items() if id in args[3:]]
                    p.write_bytes(b'\n'.join(json.dumps(r).encode() for r in rows));return p
                return original_command(args,stem,**kwargs)
            scenario.g.command=command
            with patch.object(m,'runtime_authority',return_value=roles),patch.object(m,'pause_authority'):
                scenario.operation=scenario.new_operation('scoped-apply')
                pre=scenario.operation.preflight();scenario.config['preflightResult']=scenario.save('scoped-preflight.json',pre)
                scenario.config['globalCohortPreimage']=scenario.save('scoped-baseline.json',pre['allIds'])
                foreign=copy.deepcopy(scenario.old);foreign['Id']=cid(900);foreign['Config']['Labels']={'com.docker.compose.service':'foreign'}
                foreign['NetworkSettings']={'Networks':{'foreign':{'NetworkID':cid(997)}}}
                scenario.rows[foreign['Id']]=foreign
                result=scenario.operation.execute(pre)
                self.assertIn(cid(900),result['allIds']);self.assertFalse(result['protectedCohort']['globalUnchangedClaimed'])
                legacy.m.validate_scoped_registration_result(scenario.config,result,scenario.core)
                tampered=copy.deepcopy(result);tampered['newCids'][legacy.m.ROLE]=cid(901)
                with self.assertRaisesRegex(AssertionError,'SCOPE_PROOF_TARGET_CHANGED'):
                    legacy.m.validate_scoped_registration_result(scenario.config,tampered,scenario.core)
                failed=copy.deepcopy(scenario.operation.state);scenario.config['recoveryState']=scenario.save('scoped-failed.json',failed)
                del scenario.rows[cid(900)]
                recovered=scenario.new_operation('scoped-recovery').recover(failed)
                self.assertEqual(recovered['state'],'D11_NORTHSTAR_ORIGINAL_CONFIGURATION_RESTORED_OFF')
                self.assertNotIn(cid(900),recovered['allIds'])
                target=scenario.core.load(recovered['recovered'])[legacy.m.ROLE]['Id']
                scenario.operation.protected_cohort.validate_proof(recovered['protectedCohort'],target)

    def test_scoped_terminal_reconciliation_consumes_current_closure_not_past_foreign_ids(self):
        spec=importlib.util.spec_from_file_location('scope_receipt_fixture',UI/'tests/unit/test_northstar_reconciled_authority.py')
        receipts=importlib.util.module_from_spec(spec);spec.loader.exec_module(receipts)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            save,c,owner,blobs,result,historical,evidence=receipts.Controls().fixture(root)
            source_scope,source_roles,_,_,_=self.fixture(root)
            scope_config=copy.deepcopy(source_scope.config['protectedCohort'])
            scope_config['stockBefore']=save('scoped-stock-before.json',scope_config['stockBefore'])
            scope_config['stockPaused']=save('scoped-stock-paused.json',scope_config['stockPaused'])
            scope_config['stockModelAnchor']=save('scoped-stock-anchor.json',scope_config['stockModelAnchor'])
            roles={role:owner.load(ref)['Id'] for role,ref in c['retainedContainers'].items()}
            roles.update({'ancillary-'+str(i):cid(500+i) for i in range(6)})
            roles.update({role:id for role,id in source_roles.items() if role.startswith('off-')})
            roles=m.RuntimeRoles(roles,stopped=source_roles.stopped)
            fixed=set(roles.values())|set(source_scope.stock)
            current=fixed|{'c'*64}
            classification={id:{'Id':id,'Name':'/protected-'+str(i),'Labels':{},'Networks':{},'Generation':copy.deepcopy(row(1)['Generation'])}
                            for i,id in enumerate(sorted(current))}
            for role,id in roles.items():
                classification[id]['Labels']={'com.docker.compose.project':'elevenid-beta','com.docker.compose.service':role}
            for id,stock in source_scope.stock.items():
                classification[id]['Name']=stock['name']
                classification[id]['Labels']={'com.docker.compose.project':source_scope.stock_project,'com.docker.compose.service':source_scope.stock_roles[id]}
            observation={'schema':m.SCHEMA,'profileSha256':'a'*64,'allIds':sorted(current),
                'protectedIds':sorted(current),'outsideScopeIds':[],'classification':classification,'globalUnchangedClaimed':False}
            typed={'schema':m.SCHEMA,'profileSha256':'a'*64,'observations':[copy.deepcopy(observation),observation],'globalUnchangedClaimed':False}
            proof=c['reconciledOffAuthority'];supplied=owner.load(proof['input']);producer=owner.load(supplied['operation'])
            c['protectedCohort']=producer['protectedCohort']=scope_config
            blobs['docker-compose.canvas-oss-acceptance.yml']=(UI/'docker-compose.canvas-oss-acceptance.yml').read_bytes()
            supplied['operation']=save('producer.json',producer);proof['input']=save('input.json',supplied)
            result.update(state='D11_SCOPED_JOURNAL_RECOVERY_OFF_OBSERVED',producerInput=proof['input'],operation=supplied['operation'],
                historicalOwnedIds=result.pop('ownedIds'),allIds=sorted(current),protectedCohort=typed)
            proof['result']=save('output/result.json',result)
            c['globalCohortPreimage']=save('scoped-current.json',sorted(current))
            # The old expected set included a now-removed foreign row e*64.
            self.assertIn('e'*64,historical);self.assertNotIn('e'*64,current)
            with patch.object(m,'runtime_authority',return_value=roles),patch.object(m,'pause_authority'):
                self.assertEqual(receipts.m.stopped_authority(c,owner,receipts.reps)['Id'],'c'*64)
                self.assertEqual(owner.load(evidence['failure'])['state'],'FAILED')
                c['globalCohortPreimage']=save('scoped-missing.json',sorted(current-{next(iter(fixed))}))
                with self.assertRaisesRegex(ValueError,'SCOPE_CURRENT_REQUIRED_ID_MISSING'):
                    receipts.m.stopped_authority(c,owner,receipts.reps)


if __name__=='__main__':unittest.main()
