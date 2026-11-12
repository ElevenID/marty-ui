'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const {resourceSuccessor,authority,verifyAncillary,restartAuthority,produceResourceRestart,canonicalSourceDigest,mountDigest,CONFIG_DIGEST_SCHEMA}=require('./beta-resource-runtime');
const {verifyFunctionalRuntime}=require('./functional-debug-runtime');
const sha=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const hex=n=>n.toString(16).padStart(64,'0');
const START='2026-11-01T00:00:00Z',AFTER='2026-11-04T00:00:00Z';
const roles=[...Array.from({length:21},(_,i)=>'functional-'+i),'docs','nginx-proxy','openbao','postgres','redis','keycloak'];
function fixture(){
 const base={},before={},all={},targets={},models={},live={},modelPath='C:/private/reviewed-model.json',image='sha256:'+hex(999);
 const model={services:{}};
 for(const [i,role] of roles.entries()){
  const id=hex(i+1),next=role==='keycloak'?id:hex(i+101);
  before[role]={id,imageId:image,startedAt:START,pid:i+1,health:'healthy',memory:0,memorySwap:0,modelPath};
  all[role]={id:next,image,startedAt:AFTER,pid:i+101,health:'healthy',memoryBytes:268435456,combinedSwapBytes:536870912};
  if(role!=='keycloak')targets[role]=268435456;
  model.services[role]={environment:{ROLE:role}};
  live[next]={Id:next,Image:image,State:{Running:true,Pid:i+101,StartedAt:AFTER,Health:{Status:'healthy'}},HostConfig:{Memory:268435456,MemorySwap:536870912},Config:{Env:['BASE=1','ROLE='+role],Labels:{'com.docker.compose.project.config_files':modelPath}},Mounts:[]};
 }
 before.keycloak.memory=1073741824;before.keycloak.memorySwap=2147483648;
 const kcOld=all.keycloak.id,kcNew=hex(500);live[kcNew]={...live[kcOld],Id:kcNew,HostConfig:{Memory:1073741824,MemorySwap:2147483648},Config:{Env:['BASE=1','JAVA_OPTS_KC_HEAP=-XX:InitialRAMPercentage=20 -XX:MaxRAMPercentage=65'],Labels:{}}};
 delete live[kcOld];
 const uiOld=hex(600),uiNew=hex(601),uiLive={Id:uiNew,Image:image,State:{Running:true,Pid:601,StartedAt:AFTER,Health:{Status:'healthy'}},HostConfig:{Memory:268435456,MemorySwap:536870912},Config:{Env:['BASE=1'],Labels:{'com.docker.compose.project.config_files':'C:/private/ui-model.json'}},Mounts:[]};live[uiNew]=uiLive;
 const old=roles.filter(x=>x!=='docs'&&x!=='nginx-proxy'&&!['openbao','postgres','redis','keycloak'].includes(x)).map((role,i)=>({role,imageId:image,requiredContainerId:before[role].id,requiredStartedAt:START,requiredHostPid:i+1,requiredObservation:{containerId:before[role].id,startedAt:START,hostPid:i+1,health:'healthy'}}));
 old.push({role:'ui-prod',imageId:image,requiredContainerId:uiOld,requiredStartedAt:START,requiredHostPid:600,requiredObservation:{containerId:uiOld,startedAt:START,hostPid:600,health:'healthy'}});
 const refs={base:{path:'base',sha256:hex(701)},capResult:{path:'cap',sha256:hex(702)},uiResult:{path:'ui',sha256:hex(703)},uiStarted:{path:'start',sha256:hex(704)},uiObservation:{path:'uiLive',sha256:hex(705)},keycloakResult:{path:'kc',sha256:hex(706)},keycloakHeap:{path:'heap',sha256:hex(707)},configDigests:{path:'configs',sha256:hex(708)},engineAuthority:{path:'engine',sha256:hex(709)}};
 const profile={schema:'marty.functional-mixed-runtime/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,baseProfile:refs.base,resourceRecreation:refs};
 const input={before,targets,models:{[modelPath]:{afterPath:modelPath,afterSha256:hex(710)}}};
 const cap={state:'BETA_CAPS_RECREATED',kernelCapsVerified:roles.length,productionTouched:false,imagesBuilt:false,roles:Object.keys(targets),allRunningRoles:all,baseRef:{path:'input',sha256:hex(711)}};
 const ui={state:'BETA_UI_256M_RECREATED',productionTouched:false,imagesBuilt:false,memoryBytes:268435456,globalIds:[...Object.values(all).map(x=>x.id),uiNew],oldCid:uiOld,newCid:uiNew,modelPath:'C:/private/ui-model.json',modelSha256:hex(712)};
 const configs={schema:CONFIG_DIGEST_SCHEMA,capResultSha256:refs.capResult.sha256,uiResultSha256:refs.uiResult.sha256,keycloakResultSha256:refs.keycloakResult.sha256,rows:Object.values(live).map(row=>({cid:row.Id,image:row.Image,envSha256:sha(Object.entries(Object.fromEntries(row.Config.Env.map(v=>v.split(/=(.*)/s).slice(0,2)))).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0)),mountsSha256:mountDigest(row),modelPath:row.Config.Labels['com.docker.compose.project.config_files']||null}))};
 const values={base:{},cap,input,ui,start:{cid:uiNew,image,running:true,startedAt:AFTER},uiLive:{cid:uiNew,image,running:true,health:'healthy',startedAt:AFTER,pid:601,memoryBytes:268435456,combinedSwapBytes:536870912},kc:{state:'KEYCLOAK_HEAP_UPDATED',productionTouched:false,oldCid:kcOld,newCid:kcNew},heap:{state:'KEYCLOAK_EFFECTIVE_HEAP_VERIFIED',cid:kcNew,memoryBytes:1073741824,healthy:true,jvmMemoryFlags:['-XX:InitialRAMPercentage=20','-XX:MaxRAMPercentage=65','-XX:MaxMetaspaceSize=256m']},configs,engine:{engineId:'3dbbbe66-1c98-4e0c-b0a6-f927c05e7341'},[modelPath]:model,'C:/private/ui-model.json':{services:{'ui-prod':{}}}};
 const approvedEngineSha=refs.engineAuthority.sha256;
 const boundJson=ref=>values[ref.path];
 const context={boundJson,expectedRuntime:()=>old,receiptDigests:()=>({approved:approvedEngineSha})};
 const read=args=>{
  if(args[0]==='ps')return kcNew+'\n';
  if(args[0]==='image')return JSON.stringify([{Config:{Env:['BASE=1']}}]);
  if(args[0]==='inspect')return JSON.stringify([live[args[1]]]);
  throw Error('unexpected Docker operation');
 };
 return {profile,context,read,live,values,refs,uiNew};
}
test('functional resource successor accepts only bound generation and live configuration',()=>{
 const f=fixture();assert.equal(authority(f.profile,f.context).rows.length,22);
 assert.equal(verifyAncillary(f.profile,f.read,f.context).rows.length,22);
});
test('tampered receipt and supplied observation transport are refused',()=>{
 const f=fixture();f.profile.resourceRecreation.engineAuthority.sha256=hex(999);
 assert.throws(()=>authority(f.profile,f.context),/RESOURCE_ENGINE_AUTHORITY_NOT_IN_BASE/);
 assert.throws(()=>verifyFunctionalRuntime(f.profile,{observe:()=>({})}),/actual Docker transport/);
});
for(const kind of ['image','env','mount'])test('unauthorized '+kind+' drift is refused',()=>{
 const f=fixture(),target=f.live[hex(101)],read=args=>{
  if(args[0]!=='inspect'||args[1]!==target.Id)return f.read(args);
  const row=structuredClone(target);
  if(kind==='image')row.Image='sha256:'+hex(998);
  if(kind==='env')row.Config.Env.push('EXTRA=1');
  if(kind==='mount')row.Mounts.push({Type:'bind',Source:'/tmp',Destination:'/tmp/x',RW:false});
  return JSON.stringify([row]);
 };
 assert.throws(()=>verifyAncillary(f.profile,read,f.context));
});

test('v2 mount digest uses only shared reviewed Windows/Desktop equivalence',()=>{
 const windows={Mounts:[{Type:'bind',Source:'C:\\Users\\maree\\config.json',Destination:'/config.json',RW:false},
  {Type:'volume',Source:'/var/lib/docker/volumes/owned/_data',Destination:'/data',Name:'owned',RW:true}]};
 const desktop=structuredClone(windows);desktop.Mounts[0].Source='/run/desktop/mnt/host/c/Users/maree/config.json';
 desktop.Mounts.reverse();
 assert.equal(mountDigest(windows),mountDigest(desktop));
 const rows=require('./functional-debug-runtime').comparableBinaryMounts(windows.Mounts.map(m=>
  ({type:m.Type,source:m.Source,destination:m.Destination,name:m.Name||null,rw:m.RW})))
  .sort((a,b)=>a.destination.localeCompare(b.destination));
 assert.equal(mountDigest(windows),sha({schema:'marty.beta-resource-mounts/v2',mounts:rows}));
 assert.notEqual(mountDigest(windows),sha(rows),'old raw digest is not v2 proof');
 for(const [field,value]of [['Source','C:/Users/maree/foreign.json'],['Type','volume'],['RW',true],
  ['Destination','/foreign.json'],['Name','foreign']]){
  const changed=structuredClone(windows);changed.Mounts[0][field]=value;
  assert.notEqual(mountDigest(windows),mountDigest(changed),field+' drift must remain visible');
 }
 for(const source of ['/host_mnt/c/Users/maree/config.json','C:/Users/../config.json']){
  const changed=structuredClone(windows);changed.Mounts[0].Source=source;
  assert.throws(()=>mountDigest(changed),/alias|traversal|Noncanonical/);
 }
 assert.throws(()=>mountDigest({Mounts:[...windows.Mounts,windows.Mounts[0]]}),/DUPLICATE/);
});

test('v2 live Keycloak config accepts reviewed aliases and refuses path/type/rw drift',()=>{
 for(const changed of [null,'Source','Type','RW']){
  const f=fixture(),kc=f.values.kc.newCid;
  const row=f.live[kc];
  row.Mounts=[{Type:'bind',Source:'C:/Users/maree/keycloak/config.json',Destination:'/config.json',RW:false}];
  f.values.configs.rows.find(x=>x.cid===kc).mountsSha256=mountDigest(row);
  row.Mounts[0].Source='/run/desktop/mnt/host/c/Users/maree/keycloak/config.json';
  if(changed==='Source')row.Mounts[0].Source+='.foreign';
  if(changed==='Type')row.Mounts[0].Type='volume';
  if(changed==='RW')row.Mounts[0].RW=true;
  if(changed)assert.throws(()=>verifyAncillary(f.profile,f.read,f.context),/KEYCLOAK_MOUNT_CHANGED/);
  else assert.equal(verifyAncillary(f.profile,f.read,f.context).rows.length,22);
 }
});

test('resource v2 refuses an old unversioned-normalization config proof',()=>{
 const f=fixture();f.values.configs.schema='marty.beta-resource-config-digests/v1';
 assert.throws(()=>authority(f.profile,f.context));
});

function restartedFixture(){
 const f=fixture(),role='functional-0',cid=f.values.cap.allRunningRoles[role].id;
 for(const row of Object.values(f.live)){row.State.Paused=false;row.State.OOMKilled=false;}
 f.live[f.values.kc.newCid].State.StartedAt='2026-11-05T00:00:00Z';
 const prior=f.context.expectedRuntime;
 f.context.expectedRuntime=profile=>profile===f.profile?authority(f.profile,{...f.context,expectedRuntime:prior}).rows:prior(profile);
 f.live[cid].State.StartedAt='2026-11-08T00:00:00Z';f.live[cid].State.Pid=801;
 const baseRef={path:'resource-profile',sha256:hex(801)};
 f.values['resource-profile']=f.profile;
 const read=args=>args[0]==='info'?JSON.stringify({ID:f.values.engine.engineId}):f.read(args);
 const produced=produceResourceRestart(baseRef,{...f.context,readDocker:read,
  observeDocker:row=>({role:row.role,startedAt:f.live[row.requiredContainerId].State.StartedAt,
   hostPid:f.live[row.requiredContainerId].State.Pid}),validateRuntimeObservation:()=>{}});
 const successor={schema:f.profile.schema,scope:f.profile.scope,releaseQualified:false,recordingQualified:false,
  baseProfile:baseRef,resourceRestart:{path:'restart',sha256:hex(802)}};
 f.values.restart=produced;
 return {f,read,produced,successor,context:f.context,cid};
}
test('resource restart binds a real changed generation while old profile refuses it',()=>{
 const x=restartedFixture();
 assert.deepEqual(x.produced.historicalGenerationUnknown,['keycloak']);
 assert.throws(()=>verifyAncillary(x.f.profile,x.read,x.context),/RESOURCE_GENERATION_CHANGED:functional-0/);
 const bound=restartAuthority(x.successor,x.context);
 assert.equal(bound.rows.length,22);assert.equal(bound.generations.size,28);
 assert.equal(verifyAncillary(x.f.profile,x.read,x.context,bound.generations).rows.length,22);
});
test('Keycloak first pin alone cannot qualify a restart',()=>{
 const x=restartedFixture(),row=x.f.values.restart.roles.find(r=>r.role==='functional-0');
 row.startedAt=AFTER;row.pid=101;
 assert.throws(()=>restartAuthority(x.successor,x.context),/RESOURCE_RESTART_NO_CHANGE/);
});
test('restart source hash is canonical across LF and CRLF but detects changed code',()=>{
 const actual=fs.readFileSync(require.resolve('./beta-resource-runtime'));
 const lf=Buffer.from(actual.toString('utf8').replaceAll('\r\n','\n'));
 const crlf=Buffer.from(lf.toString('utf8').replaceAll('\n','\r\n'));
 assert.equal(canonicalSourceDigest(lf),canonicalSourceDigest(crlf));
 assert.notEqual(canonicalSourceDigest(lf),canonicalSourceDigest(Buffer.concat([lf,Buffer.from('x')])));
});
test('resource restart rejects tampered source, ID, generation and unchanged PID',()=>{
 for(const kind of ['source','cid','oldTime','sameTimeWrongPid']){
  const x=restartedFixture(),receipt=x.f.values.restart;
  if(kind==='source')receipt.sourceSha256=hex(1);
  if(kind==='cid')receipt.roles.find(r=>r.role==='functional-0').cid=hex(1);
  if(kind==='oldTime')receipt.roles.find(r=>r.role==='functional-0').startedAt=START;
  if(kind==='sameTimeWrongPid')receipt.roles.find(r=>r.role==='functional-0').startedAt=AFTER;
  assert.throws(()=>restartAuthority(x.successor,x.context),/RESOURCE_RESTART_/);
 }
});
test('resource restart producer refuses unchanged and foreign live configuration',()=>{
 const x=restartedFixture();
 x.f.live[x.cid].State.StartedAt=AFTER;x.f.live[x.cid].State.Pid=101;
 assert.throws(()=>produceResourceRestart(x.successor.baseProfile,{...x.context,readDocker:x.read,
  observeDocker:()=>({}),validateRuntimeObservation:()=>{}}),/RESOURCE_RESTART_NO_CHANGE/);
 for(const field of ['Image','Mounts','HostConfig']){
  const y=restartedFixture(),row=y.f.live[y.cid];
  if(field==='Image')row.Image='sha256:'+hex(998);
  if(field==='Mounts')row.Mounts.push({Type:'bind',Source:'/foreign',Destination:'/foreign',RW:false});
  if(field==='HostConfig')row.HostConfig.Memory=1;
  assert.throws(()=>verifyAncillary(y.f.profile,y.read,y.context,restartAuthority(y.successor,y.context).generations));
 }
});
test('resource restart refuses paused or OOM ancillary while preserving generation proof',()=>{
 for(const state of ['Paused','OOMKilled']){
  const x=restartedFixture();x.f.live[x.cid].State[state]=true;
  const bound=restartAuthority(x.successor,x.context);
  assert.throws(()=>verifyAncillary(x.f.profile,x.read,x.context,bound.generations),/RESOURCE_RESTART_STATE_CHANGED:functional-0/);
 }
});


test('named volume identities remain exact while relative bind sources are refused',()=>{
 const volume={Type:'volume',Source:'a'.repeat(64),Destination:'/openbao/file',Name:'owned',RW:true};
 const row={Mounts:[volume]};
 assert.equal(mountDigest(row),mountDigest(structuredClone(row)));
 for(const [field,value]of [['Source','b'.repeat(64)],['Name','foreign'],['RW',false],['Destination','/foreign'],['Type','tmpfs']]){
  const changed=structuredClone(row);changed.Mounts[0][field]=value;
  assert.notEqual(mountDigest(row),mountDigest(changed),field+' must remain bound');
 }
 const changed=structuredClone(row);changed.Mounts[0].Type='bind';
 assert.throws(()=>mountDigest(changed),/Unsupported host mount alias/);
 for(const source of ['',null,'bad\0source']){
  const changed=structuredClone(row);changed.Mounts[0].Source=source;
  assert.throws(()=>mountDigest(changed),/RESOURCE_MOUNT_SOURCE/);
 }
});

function successorFixture(){
 const f=fixture();
 for(const role of ['openbao','postgres','redis']){
  const cap=f.values.cap.allRunningRoles[role],old=f.values.input.before[role];
  f.values.ui.globalIds=f.values.ui.globalIds.map(id=>id===cap.id?old.id:id);
  cap.id=old.id;delete f.values.input.targets[role];
 }
 f.values.cap.roles=Object.keys(f.values.input.targets);
 return f;
}

test('resource successor derives only exact cap/UI/Keycloak replacements from validated receipts',()=>{
 const f=successorFixture(),result=resourceSuccessor(f.profile.baseProfile,f.profile,f.context);
 assert.equal(result.kind,'resource-recreation');assert.equal(result.replacements.length,28);
 assert.equal(result.replacements.filter(row=>row.oldCid!==row.newCid).length,25);
 assert.deepEqual(result.replacements.filter(row=>row.oldCid===row.newCid).map(row=>row.role).sort(),
  ['openbao','postgres','redis']);
 assert.equal(result.replacements.find(row=>row.role==='keycloak').newCid,f.values.kc.newCid);
 assert.equal(result.replacements.find(row=>row.role==='ui-prod').newCid,f.values.ui.newCid);
});

test('resource successor refuses base/composition/role/target/reused-ID ambiguity',()=>{
 for(const kind of ['base','composition','role','target','fixed','duplicate','reuse','keycloak']){
  const f=successorFixture(),previous={...f.profile.baseProfile};
  if(kind==='base')previous.sha256=hex(1999);
  if(kind==='composition')f.profile.issuanceFenceNativeOverlay={};
  if(kind==='role')f.values.input.before.foreign=f.values.input.before.docs;
  if(kind==='target')f.values.input.targets.openbao=268435456;
  if(kind==='fixed')f.values.cap.allRunningRoles.redis.id=hex(1999);
  if(kind==='duplicate')f.values.cap.allRunningRoles.docs.id=f.values.cap.allRunningRoles['nginx-proxy'].id;
  if(kind==='reuse')f.values.cap.allRunningRoles.docs.id=f.values.input.before['nginx-proxy'].id;
  if(kind==='keycloak')f.values.kc.oldCid=hex(1999);
  assert.throws(()=>resourceSuccessor(previous,f.profile,f.context),undefined,kind);
 }
});

function maintenanceFixture(){
 const f=fixture(),a=authority(f.profile,f.context),generations=new Map(),before={roles:[]};
 for(const [cid,row]of Object.entries(f.live)){
  const role=cid===a.ui.newCid?'ui-prod':cid===a.kc.newCid?'keycloak':Object.entries(a.cap.allRunningRoles).find(([,v])=>v.id===cid)[0];
  Object.assign(row.HostConfig,{NanoCpus:1000000000,PidsLimit:128,RestartPolicy:{Name:'no',MaximumRetryCount:0}});
  Object.assign(row.State,{Status:'running',Running:true,Paused:false,OOMKilled:false,ExitCode:0});generations.set(role,{role,cid,startedAt:row.State.StartedAt,pid:row.State.Pid});
  if(a.rows.some(v=>v.role===role)){
   before.roles.push({role,containerId:cid,imageId:row.Image,startedAt:row.State.StartedAt,hostPid:row.State.Pid,running:true,state:'running'});
   Object.assign(row.State,{Status:'exited',Running:false,Pid:0,ExitCode:0});
  }
 }
 const resourceBefore=Object.values(f.live).map(row=>({Id:row.Id,Image:row.Image,StartedAt:row.State.StartedAt,Labels:structuredClone(row.Config.Labels),Mounts:structuredClone(row.Mounts),HostConfig:structuredClone(row.HostConfig)}));
 return {...f,a,generations,before,resourceBefore,inspect:()=>Object.values(f.live)};
}
test('maintenance recovery exact22stopped and6running retains structural/source checks',()=>{
 const f=maintenanceFixture(),check=require('./functional-debug-runtime').validateMaintenanceResourceRows;
 const result=check(f.a,f.generations,f.before,f.inspect(),f.resourceBefore);assert.equal(result.roles.length,22);assert.equal(result.resources.length,28);assert(result.roles.every(row=>row.state==='exited'&&row.hostPid===0&&!row.running));
});
for(const kind of ['runningManaged','stoppedAncillary','changedGeneration','changedEnv','changedMount','changedCap','changedOtherCap','changedFullMountField','duplicateCID'])test('maintenance recovery refuses '+kind,()=>{
 const f=maintenanceFixture(),rows=f.inspect(),managed=rows.find(row=>row.State.Status==='exited'),ancillary=rows.find(row=>row.State.Status==='running');
 if(kind==='runningManaged')Object.assign(managed.State,{Status:'running',Running:true,Pid:1});
 if(kind==='stoppedAncillary')Object.assign(ancillary.State,{Status:'exited',Running:false,Pid:0});
 if(kind==='changedGeneration')managed.State.StartedAt='2026-11-11T00:00:00Z';
 if(kind==='changedEnv')managed.Config.Env.push('DRIFT=1');
 if(kind==='changedMount')managed.Mounts.push({Type:'bind',Source:'/unexpected',Destination:'/unexpected',RW:false});
 if(kind==='changedCap')managed.HostConfig.Memory++;
 if(kind==='changedOtherCap')managed.HostConfig.PidsLimit=999;
 if(kind==='changedFullMountField'){const mount={Type:'volume',Source:'/owned',Destination:'/owned',RW:true,Name:'owned',Propagation:''};managed.Mounts.push(mount);const base=f.resourceBefore.find(row=>row.Id===managed.Id);base.Mounts.push({...mount,Propagation:'different'});}
 if(kind==='duplicateCID')rows[1]=rows[0];
 assert.throws(()=>require('./functional-debug-runtime').validateMaintenanceResourceRows(f.a,f.generations,f.before,rows,f.resourceBefore));
});
test('maintenance recovery does not weaken normal running ancillary verifier',()=>{
 const f=maintenanceFixture();assert.throws(()=>verifyAncillary(f.profile,f.read,f.context));
});

test('maintenance recovery actual recorded nginx five-field projection permits unknown historical defaults',()=>{
 const f=maintenanceFixture(),row=f.live[f.a.cap.allRunningRoles['nginx-proxy'].id],old=f.resourceBefore.find(v=>v.Id===row.Id);
 // Actual selected resource28 baseline shape and nonsecret nginx values.
 old.HostConfig={Memory:268435456,MemorySwap:536870912,NanoCpus:0,PidsLimit:null,RestartPolicy:{MaximumRetryCount:0,Name:'unless-stopped'}};
 row.HostConfig={...structuredClone(old.HostConfig),Privileged:false,ReadonlyRootfs:false,AutoRemove:false,ShmSize:67108864,NetworkMode:'elevenid-beta-network'};
 const result=require('./functional-debug-runtime').validateMaintenanceResourceRows(f.a,f.generations,f.before,f.inspect(),f.resourceBefore);
 assert.equal(result.resources.length,28);assert(result.resources.find(v=>v.role==='nginx-proxy').hostConfigSha256);
});
test('maintenance recovery baseline cap projection is closed rather than arbitrary keys',()=>{
 const f=maintenanceFixture();delete f.resourceBefore[0].HostConfig.PidsLimit;
 assert.throws(()=>require('./functional-debug-runtime').validateMaintenanceResourceRows(f.a,f.generations,f.before,f.inspect(),f.resourceBefore),/MAINTENANCE_CAPS_PROJECTION_SCHEMA/);
});
test('maintenance recovery unrecorded full live caps remain visible to the two-read stability guard',()=>{
 const f=maintenanceFixture(),check=require('./functional-debug-runtime').validateMaintenanceResourceRows;
 const first=check(f.a,f.generations,f.before,f.inspect(),f.resourceBefore);
 Object.values(f.live)[0].HostConfig.ShmSize=12345;
 const second=check(f.a,f.generations,f.before,f.inspect(),f.resourceBefore);
 assert.notDeepEqual(second,first);
});

function dependencyHealthFixture(){
 const f=maintenanceFixture(),runtime=require('./functional-debug-runtime'),path=require('node:path'),os=require('node:os');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'marty-maintenance-health-')),created=[];
 const file=(name,value,json=true)=>{const target=path.join(root,name),raw=Buffer.from(json?JSON.stringify(value):value);fs.writeFileSync(target,raw,{flag:'wx'});created.push(target);return {path:target,sha256:crypto.createHash('sha256').update(raw).digest('hex'),bytes:raw.length};};
 const template=file('route.txt','location = /ready {\n set $backend_api ${GATEWAY_UPSTREAM};\n proxy_pass http://$backend_api/ready;\n}',false);
 const entrypoint=file('entrypoint.txt',"GATEWAY_UPSTREAM=${GATEWAY_UPSTREAM:-gateway:8000}\nenvsubst '${PUBLIC_DOMAIN} ${UI_DEV_PORT} ${DOCS_DOMAIN} ${GATEWAY_UPSTREAM}' < /etc/nginx/conf.d/default.conf.template",false);
 const proxy=f.live[f.a.cap.allRunningRoles['nginx-proxy'].id],gateway=f.live[f.before.roles.find(row=>row.role==='functional-0').containerId];
 // The fixture's managed role names are synthetic; select one as the real closed gateway dependency.
 const managed=f.before.roles.find(row=>row.role==='functional-0');managed.role='gateway';f.a.rows.find(row=>row.role==='functional-0').role='gateway';
 const old=f.generations.get('functional-0');f.generations.delete('functional-0');f.generations.set('gateway',{...old,role:'gateway'});f.a.cap.allRunningRoles.gateway=f.a.cap.allRunningRoles['functional-0'];delete f.a.cap.allRunningRoles['functional-0'];f.a.input.before.gateway=f.a.input.before['functional-0'];f.a.input.targets.gateway=f.a.input.targets['functional-0'];
 proxy.Config.Env.push('GATEWAY_UPSTREAM=gateway:8000');proxy.Config.Healthcheck={Test:['CMD-SHELL','wget --quiet --tries=1 --spider http://127.0.0.1/ready || exit 1'],Interval:10000000000,Timeout:5000000000,Retries:12,StartPeriod:15000000000};
 proxy.Mounts=[{Type:'bind',Source:template.path,Destination:'/etc/nginx/conf.d/default.conf.template',RW:false},{Type:'bind',Source:entrypoint.path,Destination:'/docker-entrypoint.d/40-substitute-env.sh',RW:false}];
 proxy.State.Health={Status:'unhealthy',Log:Array.from({length:5},()=>({ExitCode:1,Output:'wget: server returned error: HTTP/1.1 502 Bad Gateway\n',End:new Date(Date.now()-1000).toISOString()}))};
 f.resourceBefore.find(row=>row.Id===proxy.Id).Mounts=structuredClone(proxy.Mounts);
 const proof=f.a.configs.rows.find(row=>row.cid===proxy.Id);proof.mountsSha256=mountDigest(proxy);proof.envSha256=sha(Object.entries(Object.fromEntries(proxy.Config.Env.map(v=>v.split(/=(.*)/s).slice(0,2)))).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0));
 const observation=file('observation.json',{Id:proxy.Id,Image:proxy.Image,Healthcheck:proxy.Config.Healthcheck,Health:proxy.State.Health,Mounts:proxy.Mounts});
 const selected=file('upstream.json',{containerId:proxy.Id,selectedVariable:'GATEWAY_UPSTREAM',present:true,value:'gateway:8000',otherEnvironmentValuesReported:false});
 const evidence=file('evidence.json',{schema:'marty.maintenance-proxy-dependency/v1',proxyObservation:observation,selectedUpstream:selected,routeTemplate:template,entrypoint});
 return {...f,proxy,gateway,binding:()=>runtime.maintenanceProxyEvidence(evidence),cleanup:()=>{for(const item of created)fs.unlinkSync(item);fs.rmdirSync(root);}};
}
test('maintenance recovery exact proxy502 with bound source and stopped gateway is classified unready',()=>{
 const f=dependencyHealthFixture();try{
  const result=require('./functional-debug-runtime').validateMaintenanceResourceRows(f.a,f.generations,f.before,f.inspect(),f.resourceBefore,f.binding());
  const row=result.resources.find(row=>row.role==='nginx-proxy');assert.equal(row.health,'unhealthy');assert.equal(row.maintenanceHealthClassification.state,'EXPECTED_MAINTENANCE_UPSTREAM_STOPPED');assert.equal(row.maintenanceHealthClassification.functionalReadiness,false);assert.equal(result.dependencyObservations.length,1);
 }finally{f.cleanup();}
});
for(const kind of ['differentUpstream','runningGateway','differentProbe','differentFailure','staleFailure','writableSource'])test('maintenance recovery proxy cause refuses '+kind,()=>{
 const f=dependencyHealthFixture();try{
  const binding=f.binding();
  if(kind==='differentUpstream')f.proxy.Config.Env[f.proxy.Config.Env.length-1]='GATEWAY_UPSTREAM=other:8000';
  if(kind==='runningGateway')Object.assign(f.gateway.State,{Status:'running',Running:true,Pid:123});
  if(kind==='differentProbe')f.proxy.Config.Healthcheck.Test=['CMD','false'];
  if(kind==='differentFailure')f.proxy.State.Health.Log[4].Output='connection refused';
  if(kind==='staleFailure')f.proxy.State.Health.Log[4].End='2020-01-01T00:00:00Z';
  if(kind==='writableSource')f.proxy.Mounts[0].RW=true;
  assert.throws(()=>require('./functional-debug-runtime').validateMaintenanceResourceRows(f.a,f.generations,f.before,f.inspect(),f.resourceBefore,binding));
 }finally{f.cleanup();}
});
