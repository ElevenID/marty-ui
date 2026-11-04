'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {authority,verifyAncillary}=require('./beta-resource-runtime');
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
 const configs={schema:'marty.beta-resource-config-digests/v1',capResultSha256:refs.capResult.sha256,uiResultSha256:refs.uiResult.sha256,keycloakResultSha256:refs.keycloakResult.sha256,rows:Object.values(live).map(row=>({cid:row.Id,image:row.Image,envSha256:sha(Object.entries(Object.fromEntries(row.Config.Env.map(v=>v.split(/=(.*)/s).slice(0,2)))).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0)),mountsSha256:sha([]),modelPath:row.Config.Labels['com.docker.compose.project.config_files']||null}))};
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
