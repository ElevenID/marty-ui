"""Hermetic receipt controls. No Docker, browser, or supervised processes."""
import copy, importlib.util, json, sys, tempfile, types, unittest
from pathlib import Path
UI=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(UI/'scripts'))
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
m=module('reconciliation_adapter',UI/'scripts/scoped_northstar_fixture.py')
core=module('reconciliation_core',UI/'scripts/repair_beta_release_metadata.py')
reps=module('reconciliation_reps',UI/'scripts/scoped_mdoc_config.py')
legacy=module('reconciliation_existing_controls',UI/'tests/unit/test_scoped_northstar_fixture.py')

class Controls(unittest.TestCase):
    def fixture(self,root):
        def save(name,value):
            file=root/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(json.dumps(value),encoding='utf-8');return core.ref(file)
        def text(name,value=''):
            file=root/name;file.write_text(value,encoding='utf-8');return core.ref(file)
        def job(name,source,supplied,success):
            request=dict(schema='marty.windows-job-request/v1',command=[sys.executable,'-B',source['path']]+([] if success else ['--rollback'])+['--input',supplied['path']],
                receiptFile=str(root/(name+'-job.json')),executableSha256='a'*64,memoryBytes=1024**3,hostMarginBytes=1024**3,processLimit=32)
            receipt=dict(schema='marty.windows-job-result/v1',executableSha256='a'*64,jobMemoryBytes=1024**3,jobClosed=True,
                terminalActiveProcesses=0,processCreatedSuspended=True,assignedBeforeResume=True,forcedTermination=False,
                hostMarginBreached=False,state='COMPLETE' if success else 'FAILED',exitCode=0 if success else 1)
            return save(name+'-request.json',request),save(name+'-job.json',receipt)
        def terminal(name,stdout=''):
            return save(name+'-terminal.json',dict(exit=0,stdout=text(name+'.stdout',stdout),stderr=text(name+'.stderr')))
        old=legacy.original();old['Created']='old-created'
        fixture=text('legacy-fixture.json','{}');model=legacy.original_model();model['secrets']['northstar_run']['file']=fixture['path']
        model_ref=save('old-model.json',model)
        for row in [old]:
            row['Mounts'][0]['Source']=reps.daemon_source(fixture['path']);row['HostConfig']['Mounts'][0]['Source']=reps.daemon_source(fixture['path'])
            row['Config']['Labels']['com.docker.compose.project.config_files']=model_ref['path'];row['Config']['Labels']['com.docker.compose.project.working_dir']=str(root)
        created=copy.deepcopy(old);created.update(Id='c'*64,Created='created-once')
        created['Config']['Hostname']='c'*12;created['Config']['Labels']['com.docker.compose.replace']='d'*64
        created['State'].update(Status='created',Running=False,Pid=0,ExitCode=0,StartedAt='0001-01-01T00:00:00Z',FinishedAt='0001-01-01T00:00:00Z')
        dispatcher=text('dispatcher.py','# fixed reviewed preparation source\n');source=dispatcher['sha256']
        retained={}
        for i in range(22):
            row=copy.deepcopy(old);row['Id']=f'{i+100:064x}';retained['role-'+str(i)]=save('retained-'+str(i)+'.json',row)
        baseline=[old['Id']]+[core.load(ref)['Id'] for ref in retained.values()]+['e'*64]
        expected=sorted((set(baseline)-{old['Id']})|{created['Id']})
        forward=save('forward.json',dict(runId='generic-run',sourceSha256=source,oldCids={m.ROLE:old['Id']},newCids={m.ROLE:'d'*64},pending=None,operations=['apply-create-'+m.ROLE,'apply-start-'+m.ROLE]))
        previous=dict(runId='generic-run',sourceSha256=source,rollbackAuthorized=True,executeAuthorized=False,
            oldCids={m.ROLE:old['Id']},originalContainer=save('original.json',old),oldModels={m.ROLE:model_ref},oldFixture=fixture,
            retainedContainers=retained,recoveryState=forward,preflightResult=save('preflight.json',dict(state='D11_REBIND_PREFLIGHT_PASSED',sourceSha256=source,allIds=baseline)),
            sourceFiles={name:core.ref(UI/'scripts'/name) for name in ['scoped_northstar_fixture.py','repair_beta_release_metadata.py','scoped_mdoc_config.py']},
            shutdown=dict(result=save('shutdown.json',dict(state='BETA_AND_SELFHOST_PRODUCTION_STOPPED',restartAutomatically=False,forcedStatelessNodeContainer=old['Id'])),
                after=save('shutdown-after.json',{old['Id']:old})),
            transportInput=save('transport.json',{'executables':{'docker':{'path':'reviewed-docker'}}}),
            provenance={'rollback':{k:v for k,v in old['Config']['Labels'].items() if k in ['com.docker.compose.config-hash','com.docker.compose.project.config_files','com.docker.compose.project.working_dir','com.docker.compose.version']}})
        previous_ref=save('rollback.json',previous)
        prefix=['reviewed-docker','--context','desktop-linux']
        create_terminal=terminal('create');stop_terminal=terminal('stop')
        evidence=dict(readOnlyVerificationAuthorized=True,rollbackInput=previous_ref,dispatcher=dispatcher,
            invocation=save('invocation.json',dict(mode='rollback',input=previous_ref,sourceSha256=source)),
            failure=save('failure.json',dict(state='FAILED',code='RECOVERY_UNRELATED_ID_CHANGED',sourceSha256=source)),
            failureState=save('recovery-state.json',dict(runId='generic-run',sourceSha256=source,oldCids={m.ROLE:old['Id']},newCids={m.ROLE:created['Id']},
                pending=None,operations=['rollback-stop-'+m.ROLE,'rollback-create-'+m.ROLE],recoveryOriginal=forward,
                terminals={'rollback-stop-'+m.ROLE:stop_terminal,'rollback-create-'+m.ROLE:create_terminal})),
            created=save('created.json',created),createTerminal=create_terminal,
            createIntent=save('create-intent.json',{'argv':prefix+['compose','-f',model_ref['path'],'up','--no-start','--no-deps','--no-build','--pull','never','--force-recreate',m.ROLE]}),
            stopIntent=save('stop-intent.json',{'argv':prefix+['stop','--signal','SIGTERM','--timeout','-1','d'*64]}),
            discoveryIntent=save('discovery-intent.json',{'argv':prefix+['ps','-aq','--no-trunc','--filter','label=com.docker.compose.project=elevenid-beta','--filter','label=com.docker.compose.service='+m.ROLE]}),
            discoveryTerminal=terminal('discovery',created['Id']+'\n'),beforeTerminal=terminal('before','\n'.join((set(baseline)-{old['Id']})|{'d'*64})),
            afterTerminal=terminal('after','\n'.join(expected+['f'*64])))
        evidence['jobRequest'],evidence['job']=job('history',dispatcher,previous_ref,False)
        evidence_ref=save('history-input.json',evidence)
        producer=copy.deepcopy(previous);producer.update(sourceRepository=str(UI),currentSourceAuthority={'ui':'1'*40})
        producer['sourceFiles']['runtime-successor.cjs']=text('runtime-successor.cjs','reviewed generic bridge')
        producer_ref=save('producer.json',producer)
        supplied=dict(readOnlyVerificationAuthorized=True,operation=producer_ref,history=evidence_ref,outputDir=str(root/'output'))
        supplied_ref=save('input.json',supplied);source_ref=core.ref(UI/'scripts/reconcile_northstar_off.py')
        result=dict(state='D11_JOURNAL_RECOVERY_OFF_OBSERVED',producerInput=supplied_ref,producerSource=source_ref,operation=producer_ref,history=evidence_ref,
            historicalRecoveryState='FAILED',retained22Verified=True,runtimeWrites=False,releaseQualified=False,recordingQualified=False,
            ownedIds=expected,currentContainer=save('output/reconciled-container.private.json',created))
        result_ref=save('output/result.json',result);request_ref,job_ref=job('verification',source_ref,supplied_ref,True)
        config=copy.deepcopy(producer);config.update(originalContainer=result['currentContainer'],oldCids={m.ROLE:created['Id']},globalCohortPreimage=save('cohort.json',expected+['a'*64]),
            reconciledOffAuthority=dict(input=supplied_ref,source=source_ref,request=request_ref,job=job_ref,result=result_ref))
        blobs={path:(UI/path).read_bytes() for path in ['scripts/scoped_northstar_fixture.py','scripts/reconcile_northstar_off.py','scripts/repair_beta_release_metadata.py','scripts/scoped_mdoc_config.py']}
        owner=types.SimpleNamespace(load=core.load,read_ref=core.read_ref,git_blob=lambda repo,rev,path:blobs[path])
        return save,config,owner,blobs,result,expected,evidence

    def test_git_source_lf_crlf_and_code_drift(self):
        for ending in (b"\n", b"\r\n"):
            with self.subTest(ending=ending), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                _,c,owner,blobs,_,_,_=self.fixture(root)
                for name,value in blobs.items():
                    blobs[name]=value.replace(b"\r\n", b"\n")
                for name in ("repair_beta_release_metadata.py", "scoped_mdoc_config.py", "reconcile_northstar_off.py"):
                    file=root/name
                    file.write_bytes(blobs["scripts/"+name].replace(b"\n", ending))
                    if name=="reconcile_northstar_off.py":
                        source=core.ref(file)
                    else:
                        c["sourceFiles"][name]=core.ref(file)
                m.reconciliation_source(c,source,owner)
                # A fresh, valid raw hash cannot authorize different executable source.
                file=Path(source["path"])
                file.write_bytes(file.read_bytes()+b"\nraise RuntimeError('changed')\n")
                with self.assertRaisesRegex(ValueError,"RECONCILIATION_PRODUCER_NOT_MAINTAINED"):
                    m.reconciliation_source(c,core.ref(file),owner)
                # Canonical text matching never replaces verification of raw custody bytes.
                with self.assertRaises(ValueError):
                    m.reconciliation_source(c,source,owner)

    def test_terminal_maintained_bundle_and_dynamic_additions(self):
        with tempfile.TemporaryDirectory() as tmp:
            save,c,owner,_,_,expected,evidence=self.fixture(Path(tmp))
            self.assertEqual(m.stopped_authority(c,owner,reps)['Id'],'c'*64)
            self.assertEqual(core.load(evidence['failure'])['state'],'FAILED')
            c['globalCohortPreimage']=save('more.json',expected+['a'*64,'9'*64])
            self.assertEqual(m.stopped_authority(c,owner,reps)['Id'],'c'*64)
    def test_source_job_observation_and_owned_drift_refused(self):
        for kind in ['job-live','job-active','job-forced','source','result-path','input','history-pass','owned-missing','candidate']:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                save,c,owner,blobs,result,expected,_=self.fixture(Path(tmp));proof=c['reconciledOffAuthority']
                job=copy.deepcopy(core.load(proof['job']))
                if kind=='job-live':job['state']='RUNNING'
                if kind=='job-active':job['terminalActiveProcesses']=1
                if kind=='job-forced':job['forcedTermination']=True
                if kind in ['job-live','job-active','job-forced']:proof['job']=save('verification-job.json',job)
                if kind=='source':blobs['scripts/reconcile_northstar_off.py']=b'foreign'
                if kind=='result-path':proof['result']=save('foreign-result.json',result)
                if kind=='input':result['producerInput']={'path':'foreign','sha256':'f'*64};proof['result']=save('output/result.json',result)
                if kind=='history-pass':result['historicalRecoveryState']='PASS';proof['result']=save('output/result.json',result)
                if kind=='owned-missing':c['globalCohortPreimage']=save('missing.json',expected[1:])
                if kind=='candidate':row=core.load(c['originalContainer']);row['Mounts'][0]['RW']=True;c['originalContainer']=save('bad-row.json',row)
                with self.assertRaises(ValueError):m.stopped_authority(c,owner,reps)

if __name__=='__main__':unittest.main()
