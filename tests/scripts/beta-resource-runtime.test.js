'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {authority,verifyAncillary,mountDigest,CONFIG_DIGEST_SCHEMA}=require('./beta-resource-runtime');
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
