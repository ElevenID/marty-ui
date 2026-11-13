'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {maintenanceCreatedContext,createdTargetOb3Authority,verifyCreatedTargetModel}=require('./functional-debug-runtime');
const selectedRoles=['auth','compliance-profile','credential-template','flow','gateway','issuance-native','organization','presentation-policy','signing-keys','trust-profile'];
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'created-source-control-'));t.after(()=>{const target=path.resolve(root),temporary=path.resolve(os.tmpdir());assert.equal(path.dirname(target),temporary);assert(path.basename(target).startsWith('created-source-control-'));assert(!fs.lstatSync(target).isSymbolicLink());assert.equal(fs.realpathSync(target),target);fs.rmSync(target,{recursive:true});});
 const file=(name,value,raw=false)=>{const target=path.join(root,name),bytes=raw?Buffer.from(value):Buffer.from(JSON.stringify(value));fs.writeFileSync(target,bytes);return {path:target,bytes:bytes.length,sha256:hash(bytes)};};
 const caps={Memory:268435456,MemorySwap:536870912,NanoCpus:1000000000,PidsLimit:128,RestartPolicy:{Name:'no',MaximumRetryCount:0}};
 const before={roles:[]},resourceBefore=[],saved={},selection={binaries:{}},model={services:{},secrets:{},volumes:{}},configs=[],all={},generations=new Map();
 const imageId='sha256:'+'b'.repeat(64),imageConfig={Env:['BASE=1'],Cmd:['/entrypoint'],Entrypoint:null,User:'10001:10001',WorkingDir:'/app'};
 const names=[...selectedRoles,...Array.from({length:12},(_,i)=>'retained-'+i)];
 for(const [i,role] of names.entries()){
  const cid=(i+1).toString(16).padStart(64,'0'),next=(i+101).toString(16).padStart(64,'0');
  before.roles.push({role,project:'elevenid-beta',containerId:cid,imageId,startedAt:'2026-01-01T00:00:00Z',binaryMounts:[]});
  resourceBefore.push({Id:cid,Image:imageId,StartedAt:'2026-01-01T00:00:00Z',HostConfig:structuredClone(caps),Mounts:[],Labels:{}});
  configs.push({cid});all[role]={id:cid,image:imageId};generations.set(role,{cid,startedAt:'2026-01-01T00:00:00Z',pid:1});
  saved[role]={Id:cid,Image:imageId,State:{Status:'exited',Pid:0,Running:false,Paused:false,ExitCode:0,OOMKilled:false,StartedAt:'2026-01-01T00:00:00Z'},HostConfig:structuredClone(caps),Labels:{},Mounts:[]};
  if(selectedRoles.includes(role)){
   const binary=file('marty-'+role,'SYNTHETIC_SOURCE_BYTES',true),target='/usr/local/bin/marty-'+role;
   selection.binaries[role]=binary;model.services[role]={environment:{ROLE:role},secrets:[]};
   Object.assign(saved[role],{Id:next,Labels:{'com.docker.compose.service':role,'com.docker.compose.project':'elevenid-beta'},Cmd:['/entrypoint'],Entrypoint:null,User:'10001:10001',WorkingDir:'/app',Mounts:[{Type:'bind',Source:binary.path,Destination:target,RW:false}]});
   saved[role].State={...saved[role].State,Status:'created',StartedAt:'0001-01-01T00:00:00Z'};
  }
 }
 const post={selection:file('selection.json',selection),selected22:file('selected.json',saved),selected22Job:file('job.json',{state:'COMPLETE',exitCode:0,jobClosed:true,terminalActiveProcesses:0,forcedTermination:false,timedOut:false,cancelled:false,hostMarginBreached:false}),plannedModels:{'elevenid-beta':file('model.json',model)}};
 const restart={a:{configs:{rows:configs},cap:{allRunningRoles:all}},generations};
 const invoke=()=>maintenanceCreatedContext(restart,before,resourceBefore,post,argv=>{assert.deepEqual(argv,['image','inspect',imageId]);return JSON.stringify([{Id:imageId,Config:imageConfig}]);});
 return {file,post,restart,before,resourceBefore,saved,selection,model,imageConfig,invoke};
}
test('postCREATE closed10 rebinds source-owned created generations and retains other12',t=>{
 const f=fixture(t),out=f.invoke();assert.equal(out.created.size,10);assert.equal(out.before.roles.length,22);
 for(const row of out.before.roles)assert.equal(row.containerId,f.saved[row.role].Id);
 assert.deepEqual(f.before.roles.map(row=>row.containerId),f.resourceBefore.map(row=>row.Id)); // caller inputs never mutated
});
function actualPreimageFixture(t){
 const f=fixture(t),actual=structuredClone(f.before),newTime='2026-01-02T00:00:00Z';
 const retained=actual.roles.find(row=>row.role==='retained-0');retained.startedAt=newTime;f.saved['retained-0'].State.StartedAt=newTime;
 for(const [i,role] of selectedRoles.entries())actual.roles.find(row=>row.role===role).containerId=(i+301).toString(16).padStart(64,'0');
 f.post.selected22=f.file('selected-after-restart.json',f.saved);
 const current=Object.values(f.saved).map(row=>({Id:row.Id,Image:row.Image,Pid:row.State.Pid,StartedAt:row.State.StartedAt,Labels:row.Labels,
  HostConfig:structuredClone(row.HostConfig),Mounts:structuredClone(row.Mounts)}));
 for(let i=0;i<6;i++)current.push({Id:(i+201).toString(16).padStart(64,'0'),Image:f.before.roles[0].imageId,Pid:100+i,StartedAt:newTime,Labels:{},HostConfig:structuredClone(f.resourceBefore[0].HostConfig),Mounts:[]});
 f.post.actualRuntimeBefore=f.file('actual-before.json',actual);
 f.post.actualResourceBefore=f.file('actual-resource28.json',current);
 const prior=Object.fromEntries(actual.roles.map(row=>[row.role,{Id:row.containerId,Image:row.imageId,State:{StartedAt:row.startedAt},HostConfig:structuredClone(f.resourceBefore.find(item=>item.Id===f.before.roles.find(old=>old.role===row.role).containerId).HostConfig)}]));
 f.post.acknowledgedState=f.file('acknowledged.json',{phase:'EFFECT_ACKNOWLEDGED',acknowledgedStep:'REPLACE_CREATED_CREDENTIAL_GENERATION',replacementPreimage:f.post.actualRuntimeBefore,priorCreatedSnapshot:f.file('prior-created.json',prior)});
 return {...f,actual,current,newTime,invoke:()=>maintenanceCreatedContext(f.restart,f.before,f.resourceBefore,f.post,argv=>{assert.deepEqual(argv,['image','inspect',f.before.roles[0].imageId]);return JSON.stringify([{Id:argv[2],Config:f.imageConfig}]);})};
}
test('postCREATE actual acknowledged preimage rebinds retained process time',t=>{
 const f=actualPreimageFixture(t),out=f.invoke();assert.equal(out.generations.get('retained-0').startedAt,f.newTime);
 assert.equal(out.generations.get('retained-0').pid,0);
 assert.equal(out.resourceBefore.length,28);assert.equal(out.before.roles.find(row=>row.role==='retained-0').startedAt,f.newTime);
});
test('postCREATE actual preimage refuses an unacknowledged ref',t=>{
 const f=actualPreimageFixture(t),ack={phase:'EFFECT_ACKNOWLEDGED',acknowledgedStep:'REPLACE_CREATED_CREDENTIAL_GENERATION',replacementPreimage:f.file('foreign.json',{})};
 f.post.acknowledgedState=f.file('wrong-ack.json',ack);assert.throws(f.invoke,/MAINTENANCE_CREATED_ACTUAL_PREIMAGE_ACK_CHANGED/);
});
test('postCREATE actual preimage refuses retained timestamp drift',t=>{
 const f=actualPreimageFixture(t);f.saved['retained-0'].State.StartedAt='2026-01-03T00:00:00Z';f.post.selected22=f.file('selected-tampered.json',f.saved);assert.throws(f.invoke,/MAINTENANCE_CREATED_RETAINED_STARTED_AT/);
});
function deferredBureauFixture(t){
 const f=actualPreimageFixture(t),old='retained-0',role='passport-beta-bureau';
 f.before.roles.find(row=>row.role===old).role=role;f.actual.roles.find(row=>row.role===old).role=role;
 f.saved[role]=f.saved[old];delete f.saved[old];f.saved[role].State.ExitCode=1;
 f.restart.a.cap.allRunningRoles[role]=f.restart.a.cap.allRunningRoles[old];delete f.restart.a.cap.allRunningRoles[old];
 f.restart.generations.set(role,f.restart.generations.get(old));f.restart.generations.delete(old);
 f.post.selected22=f.file('bureau-selected.json',f.saved);f.post.actualRuntimeBefore=f.file('bureau-actual.json',f.actual);
 const prior=JSON.parse(fs.readFileSync(JSON.parse(fs.readFileSync(f.post.acknowledgedState.path)).priorCreatedSnapshot.path));
 prior[role]=prior[old];delete prior[old];prior[role].State={StartedAt:f.newTime,Status:'exited',ExitCode:1};
 const failure=f.file('bureau-deferred-failure.json',{containerId:prior[role].Id,sqlstate42501Observed:true,permissionDeniedForSchemaObserved:true});
 f.post.ob3Authority=f.file('bureau-authority.json',{schema:'marty.d12-ob3-quiescent-recovery/v1',operation:'REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME',deferredRoles:[role],deferredFailure:failure});
 f.post.acknowledgedState=f.file('bureau-ack.json',{phase:'EFFECT_ACKNOWLEDGED',acknowledgedStep:'REPLACE_CREATED_CREDENTIAL_GENERATION',replacementPreimage:f.post.actualRuntimeBefore,priorCreatedSnapshot:f.file('bureau-prior.json',prior),replacementAuthority:f.post.ob3Authority});
 return f;
}
test('postCREATE OB3 retains the specifically acknowledged deferred bureau failure',t=>{
 const f=deferredBureauFixture(t),out=f.invoke();assert.equal(out.deferredExitCodes.get('passport-beta-bureau'),1);
});
test('postCREATE OB3 refuses a foreign deferred bureau failure',t=>{
 const f=deferredBureauFixture(t),authority=JSON.parse(fs.readFileSync(f.post.ob3Authority.path));
 authority.deferredFailure=f.file('foreign-bureau-failure.json',{containerId:'f'.repeat(64),sqlstate42501Observed:true,permissionDeniedForSchemaObserved:true});
 f.post.ob3Authority=f.file('foreign-bureau-authority.json',authority);
 const ack=JSON.parse(fs.readFileSync(f.post.acknowledgedState.path));ack.replacementAuthority=f.post.ob3Authority;
 f.post.acknowledgedState=f.file('foreign-bureau-ack.json',ack);
 assert.throws(f.invoke);
});
for(const fault of ['role','reusedCid','image','command','mount','writable','cap','job'])test('postCREATE refuses '+fault,t=>{
 const f=fixture(t),role=selectedRoles[0];
 if(fault==='role'){delete f.selection.binaries[role];f.post.selection=f.file('bad-selection.json',f.selection);}
 if(fault==='reusedCid')f.saved[role].Id=f.before.roles[0].containerId;
 if(fault==='image')f.saved[role].Image='sha256:'+'c'.repeat(64);
 if(fault==='command')f.saved[role].Cmd=['/foreign'];
 if(fault==='mount')f.saved[role].Mounts[0].Source='C:/foreign/marty-auth';
 if(fault==='writable')f.saved[role].Mounts[0].RW=true;
 if(fault==='cap')f.saved[role].HostConfig.Memory++;
 if(fault==='job')f.post.selected22Job=f.file('bad-job.json',{state:'FAILED'});
 f.post.selected22=f.file('changed-selected.json',f.saved);assert.throws(f.invoke);
});
test('postCREATE missing public image defaults normalize only absent user and working dir',t=>{
 const f=fixture(t);delete f.imageConfig.User;delete f.imageConfig.WorkingDir;
 for(const role of selectedRoles){f.saved[role].User='';f.saved[role].WorkingDir='';}
 f.post.selected22=f.file('nullable-selected.json',f.saved);assert.equal(f.invoke().created.size,10);
});

function acknowledgedFixture(t,replacement=false){
 const f=fixture(t),runId='SYNTHETIC_CREATE_CONTROL',engineId='SYNTHETIC_ENGINE';
 const selectedContainerIds=Object.fromEntries(selectedRoles.map(role=>[role,f.saved[role].Id]));
 const ack={schema:'marty.d12-current-native-operation/v1',runId,phase:'EFFECT_ACKNOWLEDGED',acknowledgedStep:replacement?'REPLACE_CREATED_CREDENTIAL_GENERATION':'CREATE_SELECTED',pendingStep:null,pendingArgv:null};
 if(replacement){const previous=structuredClone(f.saved);for(const [i,role]of selectedRoles.entries())previous[role].Id=(i+501).toString(16).padStart(64,'0');ack.priorCreatedSnapshot=f.file('previous-created.json',previous);}
 const created=f.file('actual-unit-ack-proof.json',{schema:'marty.d12-owned-created-cids/v1',runId,selection:f.post.selection,durableCreateAck:{phase:ack.phase,acknowledgedStep:ack.acknowledgedStep},selectedContainerIds});
 const composeArguments=['docker','compose','-p','elevenid-beta','--project-directory','C:/reviewed','-f','C:/reviewed/target.json','--env-file','C:/reviewed/current10.env'];
 const input={composeArguments,runId,engineId,selection:f.post.selection,plannedModels:f.post.plannedModels,runtimeBefore:f.file('original-running.json',f.before),resourceBefore:f.file('baseline-resource.json',f.resourceBefore),createdCids:created,acknowledgedState:f.file('ack.json',ack)};
 const live=Object.fromEntries(Object.entries(f.saved).map(([role,row])=>[row.Id,{Id:row.Id,Image:row.Image,State:structuredClone(row.State),HostConfig:structuredClone(row.HostConfig),Mounts:structuredClone(row.Mounts),Config:{Env:selectedRoles.includes(role)?['BASE=1','ROLE='+role]:['UNCHANGED=1'],Labels:structuredClone(row.Labels),Cmd:row.Cmd,Entrypoint:row.Entrypoint,User:row.User,WorkingDir:row.WorkingDir}}]));
 if(replacement){
  const previous=JSON.parse(fs.readFileSync(ack.priorCreatedSnapshot.path));
  for(const role of selectedRoles){
   const labels=live[selectedContainerIds[role]].Config.Labels;
   Object.assign(labels,{'com.docker.compose.project.config_files':'C:/reviewed/target.json','com.docker.compose.project.working_dir':'C:/reviewed','com.docker.compose.project.environment_file':'C:/reviewed/current10.env','com.docker.compose.depends_on':'flow:service_healthy:false,issuance-native:service_healthy:false'});
   Object.assign(previous[role].Labels,labels,{'com.docker.compose.project.environment_file':'C:/old/current10.env','com.docker.compose.depends_on':'issuance-native:service_healthy:false,flow:service_healthy:false'});
  }
  ack.priorCreatedSnapshot=f.file('prior-labels.json',previous);input.acknowledgedState=f.file('ack-labels.json',ack);
 }
 let inspected=0;
 const read=argv=>{
  if(JSON.stringify(argv)===JSON.stringify(['info','--format','{{json .}}']))return JSON.stringify({ID:engineId});
  if(argv[0]==='image'){assert.deepEqual(argv,['image','inspect','sha256:'+'b'.repeat(64)]);return JSON.stringify([{Id:argv[2],Config:f.imageConfig}]);}
  assert.equal(argv.length,2);assert.equal(argv[0],'inspect');assert(live[argv[1]]);inspected++;
  const row=structuredClone(live[argv[1]]);if(f.drift&&inspected>22)row.HostConfig.UnrecordedDefault='changed';if(f.mountChange&&inspected>22)f.mountChange(row.Mounts);return JSON.stringify([row]);
 };
 return {...f,live,input,ack,invoke:()=>verifyCreatedTargetModel(input,{readDocker:read}),drift:()=>{f.drift=true;},changeMounts:change=>{f.mountChange=change;}};
}
for(const replacement of [false,true])test('current owner verifies '+(replacement?'replacement':'create')+' target before start without claiming closed Job',t=>{
 const f=acknowledgedFixture(t,replacement),result=f.invoke();assert.equal(result.roles.length,22);assert.equal(result.currentJobNormalClosureNotYetQualified,true);assert.equal(result.functionalQualification,false);assert.equal(result.runningProcessQualification,false);assert.equal(result.environmentValuesReported,false);
});
for(const fault of ['environment','generation','full-cap-drift','reused-replacement-cid'])test('current acknowledged target refuses '+fault,t=>{
 const replacement=fault==='reused-replacement-cid',f=acknowledgedFixture(t,replacement),first=Object.values(f.live)[0];
 if(fault==='environment')first.Config.Env.push('UNREVIEWED=1');
 if(fault==='generation')first.State.Running=true;
 if(fault==='full-cap-drift')f.drift();
 if(replacement){const previous=JSON.parse(fs.readFileSync(f.ack.priorCreatedSnapshot.path));previous.auth.Id=first.Id;f.ack.priorCreatedSnapshot=f.file('reused-cid-previous.json',previous);f.input.acknowledgedState=f.file('reused-cid-ack.json',f.ack);}
 assert.throws(f.invoke);
});

function credentialReplacementFixture(t){
 const f=acknowledgedFixture(t,true),previous=JSON.parse(fs.readFileSync(f.ack.priorCreatedSnapshot.path)),model=JSON.parse(fs.readFileSync(f.input.plannedModels['elevenid-beta'].path));
 const live=f.live[JSON.parse(fs.readFileSync(f.input.createdCids.path)).selectedContainerIds['trust-profile']];
 const credentials=[['trust_profile_workload_server_cert','/run/secrets/trust_profile_workload_server_cert'],['trust_profile_tls_kms_token','/run/secrets/trust_profile_tls_kms_token']];
 for(const [source,destination]of credentials){
  model.secrets[source]={file:'C:/private/new-generation/'+source};model.services['trust-profile'].secrets.push({source,target:destination});
  const mount={Type:'bind',Source:model.secrets[source].file,Destination:destination,RW:false,Propagation:'rprivate',Mode:'ro'};
  live.Mounts.push(mount);previous['trust-profile'].Mounts.push({...mount,Source:'C:/private/prior-generation/'+source});
 }
 f.input.plannedModels={'elevenid-beta':f.file('new-credential-model.json',model)};
 f.ack.priorCreatedSnapshot=f.file('old-credential-mounts.json',previous);f.input.acknowledgedState=f.file('new-credential-ack.json',f.ack);
 return {...f,credentialMount:live.Mounts.find(mount=>mount.Destination===credentials[0][1])};
}
test('replacement allows only the two source-model-verified credential mount sources to change',t=>{
 const f=credentialReplacementFixture(t),before=fs.readFileSync(f.ack.priorCreatedSnapshot.path);assert.equal(f.invoke().roles.length,22);assert(fs.readFileSync(f.ack.priorCreatedSnapshot.path).equals(before));
});
test('replacement accepts Docker normalization of unset OOM kill disable to false',t=>{
 const f=credentialReplacementFixture(t),previous=JSON.parse(fs.readFileSync(f.ack.priorCreatedSnapshot.path));
 previous['compliance-profile'].HostConfig.OomKillDisable=null;
 const ids=JSON.parse(fs.readFileSync(f.input.createdCids.path)).selectedContainerIds;
 f.live[ids['compliance-profile']].HostConfig.OomKillDisable=false;
 f.ack.priorCreatedSnapshot=f.file('nullable-oom-prior.json',previous);
 f.input.acknowledgedState=f.file('nullable-oom-ack.json',f.ack);
 assert.equal(f.invoke().state,'ACTUAL_CREATED_TARGET_MODEL_BOUND_BY_CURRENT_OWNER');
});
test('replacement refuses enabling OOM kill disable',t=>{
 const f=credentialReplacementFixture(t),ids=JSON.parse(fs.readFileSync(f.input.createdCids.path)).selectedContainerIds;
 f.live[ids['compliance-profile']].HostConfig.OomKillDisable=true;
 assert.throws(f.invoke,/MAINTENANCE_CREATED_UNRELATED_CAP_CHANGED:compliance-profile/);
});
for(const field of ['Propagation','UnexpectedField'])test('replacement refuses credential mount '+field+' drift',t=>{
 const f=credentialReplacementFixture(t);f.credentialMount[field]='changed';assert.throws(f.invoke,/MAINTENANCE_CREATED_FULL_MOUNTS_CHANGED:trust-profile/);
});
test('replacement retains exact raw sources for every noncredential mount',t=>{
 const f=credentialReplacementFixture(t),auth=JSON.parse(fs.readFileSync(f.input.createdCids.path)).selectedContainerIds.auth;
 f.live[auth].Mounts[0].Source=f.live[auth].Mounts[0].Source.replaceAll('\\','/');assert.throws(f.invoke,/MAINTENANCE_CREATED_FULL_MOUNTS_CHANGED:auth/);
});

for(const [field,value]of [
 ['com.docker.compose.project.environment_file','C:/foreign/current10.env'],
 ['com.docker.compose.depends_on','flow:service_started:false,issuance-native:service_healthy:false'],
 ['com.docker.compose.depends_on','flow:service_healthy:false,flow:service_healthy:false'],
 ['com.docker.compose.depends_on','flow:service_healthy:false,issuance-native:service_healthy:false,extra:service_started:false'],
 ['com.docker.compose.depends_on','flow:service_healthy:maybe'],
 ['unrelated.label','changed']
])test('replacement refuses unapproved Compose label '+field+' '+value,t=>{
 const f=acknowledgedFixture(t,true),ids=JSON.parse(fs.readFileSync(f.input.createdCids.path)).selectedContainerIds;
 f.live[ids.auth].Config.Labels[field]=value;assert.throws(f.invoke);
});
test('retained service labels cannot change even to approved generated values',t=>{
 const f=acknowledgedFixture(t,true),retained=Object.entries(f.live).find(([,v])=>v.State.Status==='exited')[1];
 retained.Config.Labels['com.docker.compose.project.environment_file']='C:/reviewed/current10.env';assert.throws(f.invoke,/MAINTENANCE_CREATED_UNRELATED_LABEL_CHANGED/);
});


test('created target mount digest accepts only destination reordering',t=>{
 const f=credentialReplacementFixture(t);f.changeMounts(mounts=>mounts.reverse());
 const result=f.invoke();assert.equal(result.state,'ACTUAL_CREATED_TARGET_MODEL_BOUND_BY_CURRENT_OWNER');
 assert.equal(result.functionalQualification,false);assert.equal(result.currentJobNormalClosureNotYetQualified,true);
});
test('created target mount digest retains every field and refuses propagation drift',t=>{
 const f=credentialReplacementFixture(t);f.changeMounts(mounts=>{if(mounts.length>1)mounts[0].Propagation='changed-propagation';});
 assert.throws(f.invoke,/MAINTENANCE_CREATED_FULL_MOUNTS_CHANGED|MAINTENANCE_CREATED_TARGET_CHANGED_DURING_READ/);
});

test('second OB3 target binds current ack authority and historical T5 lineage',()=>{
 const oldRef={sha256:'old'},newRef={sha256:'new'},selected={sha256:'selected'};
 const old={schema:'marty.d12-ob3-quiescent-recovery/v1',operation:'REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME',
  dispatchAuthorized:true,draftOnly:false,replaceCredentialGeneration:true,runId:'run',deferredRoles:['passport-beta-bureau']};
 const current={schema:'marty.d12-ob3-acknowledged-replacement-recovery/v1',
  operation:'REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME',
  previousRecoveryAuthority:oldRef,dispatchAuthorized:true,draftOnly:false,
  replaceCredentialGeneration:true,runId:'run',deferredRoles:['passport-beta-bureau'],selected22:selected};
 const load=ref=>ref===newRef?current:ref===oldRef?old:assert.fail('foreign authority');
 const input={runId:'run',ob3Authority:newRef},ack={acknowledgedStep:'REPLACE_CREATED_CREDENTIAL_GENERATION',replacementAuthority:newRef,priorCreatedSnapshot:selected};
 assert.deepEqual(createdTargetOb3Authority(input,ack,load),{legacy:old,current,second:true});
 assert.throws(()=>createdTargetOb3Authority(input,{...ack,replacementAuthority:oldRef},load));
 assert.throws(()=>createdTargetOb3Authority(input,{...ack,priorCreatedSnapshot:oldRef},load));
 assert.throws(()=>createdTargetOb3Authority(input,ack,ref=>ref===newRef?{...current,previousRecoveryAuthority:newRef}:old));
 assert.deepEqual(createdTargetOb3Authority({...input,ob3Authority:oldRef},{...ack,replacementAuthority:oldRef},load),
  {legacy:old,current:old,second:false});
});
