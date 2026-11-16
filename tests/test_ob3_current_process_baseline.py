"""Controlled generation reconciliation only; no observed runtime qualification."""
from copy import deepcopy
import hashlib,json,pathlib,sys
import pytest
from test_scoped_d12_ob3_quiesce import fixture
import scoped_d12_native_execution as execution

@pytest.mark.parametrize('fault',[None,'extra-role','newer-generation','unreviewed-drift','cid','host-config','job','raw-state','review','ancillary'])
def test_current_process_baseline_preserves_acks_and_refuses_drift(tmp_path,monkeypatch,fault):
 i,s,intent,r,save,backend,rows,prefix,observed=fixture(tmp_path,monkeypatch)
 old={role:{'Id':row['containerId'],'Image':row['imageId'],'HostConfig':{'Memory':64},'Mounts':[],
  'RestartCount':0,'State':{'Status':'running' if role in prefix else 'exited','Running':role in prefix,'Pid':s['startAcks'][role]['hostPid'] if role in prefix else 0,
  'StartedAt':s['startAcks'][role]['startedAt'] if role in prefix else row['startedAt'],'Paused':False,'OOMKilled':False,'ExitCode':0}} for role,row in rows.items()}
 r['currentOwned22']=save('capture/owned-baseline.json',old);anc={'postgres':{'Id':'f'*64,'State':{'Pid':900}}};r['currentAncillary6']=save('capture/ancillary-baseline.json',anc)
 current=deepcopy(old);restarted=['canvas-sync-worker','compliance-profile','deployment-profile','device-registration'];reviewed=[]
 for role in restarted:
  ack=s['startAcks'][role];current[role]['State'].update(StartedAt='2026-01-03T00:00:00Z',Pid=ack['hostPid']+100);current[role]['RestartCount']=3
  reviewed.append(dict(role=role,ackStartedAt=ack['startedAt'],ackHostPid=ack['hostPid'],observedStartedAt=current[role]['State']['StartedAt'],observedHostPid=current[role]['State']['Pid'],restartCount=3,status='running'))
 job=save('fresh-job.json',dict(schema='marty.windows-job-result/v1',state='COMPLETE',exitCode=0,jobClosed=True,terminalActiveProcesses=0,timedOut=False,forcedTermination=False,cancelled=False,hostMarginBreached=False))
 baseline=dict(schema='marty.d12-ob3-current-process-baseline/v1',originalOperationState=r['originalOperationState'],journalRead=save('fresh-capture/worker.json',observed),job=job,rootReview=None,owned22=None,ancillary6=None,restartedRoles=restarted)
 review=dict(state='ROOT_QUIESCENCE_FAILURE_RECONCILED_READONLY',journalStateSha256=r['originalOperationState']['sha256'],journalUnchanged=True,created22CidsUnchanged=True,closedJobSha256=job['sha256'],workerResultSha256=baseline['journalRead']['sha256'],quiescenceQualified=False,fullStackQualified=False,restartDrift=reviewed)
 if fault=='extra-role':baseline['restartedRoles']=restarted+['organization']
 elif fault=='newer-generation':current[restarted[0]]['State']['Pid']+=1
 elif fault=='unreviewed-drift':current['organization']['State']['Pid']+=1
 elif fault=='cid':current[restarted[0]]['Id']='e'*64
 elif fault=='host-config':current[restarted[0]]['HostConfig']['Memory']=128
 elif fault=='job':baseline['job']=save('bad-job.json',{'state':'FAILED'})
 elif fault=='raw-state':
  changed=deepcopy(observed);changed[0]['files']['build-state.json']['storedBytesBase64']='e30=';baseline['journalRead']=save('fresh-capture/worker-bad.json',changed);review['workerResultSha256']=baseline['journalRead']['sha256']
 elif fault=='review':review['journalUnchanged']=False
 elif fault=='ancillary':anc['postgres']['State']['Pid']+=1
 baseline.update(rootReview=save('fresh-review.json',review),owned22=save('fresh-capture/owned.json',current),ancillary6=save('fresh-capture/ancillary.json',anc))
 r['currentProcessBaseline']=save('baseline.json',baseline);acks=deepcopy(s['startAcks'])
 if fault:
  with pytest.raises((ValueError,AssertionError,KeyError)):execution.partial_start_ob3_checkpoint(i,s,intent,r,operation_backend=backend)
 else:execution.partial_start_ob3_checkpoint(i,s,intent,r,operation_backend=backend)
 assert s['startAcks']==acks
