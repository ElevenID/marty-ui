'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto'),{spawnSync}=require('node:child_process');
const HASH=/^[a-f0-9]{64}$/;
function bytes(ref,limit=1024*1024){
 assert(ref&&path.isAbsolute(ref.path)&&HASH.test(ref.sha256),'BOUND_REFERENCE_REQUIRED');
 const stat=fs.lstatSync(ref.path);assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<=limit,'REGULAR_INPUT_REQUIRED');
 const raw=fs.readFileSync(ref.path);assert(createHash('sha256').update(raw).digest('hex')===ref.sha256,'BOUND_INPUT_CHANGED');return raw;
}
const json=ref=>JSON.parse(bytes(ref));
function projectInventory(rows,organizationId,bindingId){
 assert(Array.isArray(rows)&&rows.length<500,'SCOPED_INVENTORY_INCOMPLETE');
 assert(new Set(rows.map(row=>row.id)).size===rows.length,'DUPLICATE_JOB_ID');
 assert(rows.every(row=>typeof row.id==='string'&&row.id&&row.organization_id===organizationId&&row.binding_id===bindingId),'SCOPED_INVENTORY_ESCAPED');
 return rows.map(row=>({id:row.id,organization_id:row.organization_id,binding_id:row.binding_id}));
}
async function execute(input,mode,payload={}){
 bytes(input.runtimeHelper);const verifier=require(path.resolve(input.runtimeHelper.path));
 const docker=input.executables.docker;bytes(docker,256*1024*1024);
 const read=args=>{
  const result=spawnSync(docker.path,['--config',input.dockerConfig,'--context','desktop-linux',...args],
   {encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:8*1024*1024});
  assert(!result.error&&result.status===0,'SOURCE_BOUND_DOCKER_READ_FAILED');return result.stdout;
 };
 const engine=()=>assert(read(['info','--format','{{.ID}}']).trim()===input.engineId,'ENGINE_CHANGED');
 engine();
 const expected=()=>verifier.expectedCanvasIssuerPreimage(input.baseProfile,input.evidence);
 const observations=rows=>rows.map(row=>{const actual=verifier.observeDocker(row,read);return {actual,row:verifier.validateRuntimeObservation(row,actual)};});
 const after=(rollback=false)=>{
  const build=verifier.boundJson(input.evidence.buildReceipt),hash=rollback?'81749432b2d86dd2e8ea83176a824bf8075254860858b6552e76b0e5cdd3ee0c':build.binaries['marty-issuance-service'].sha256;
  const next=verifier.applyNativeOverlayRows(expected(),payload.before.binding,{roles:{'issuance-native':payload.role}},
   {roles:['issuance-native'],source:rollback?'85a6e31265f465a6a46c0cd97ecc6be4770fe7b4':build.uiRevision,
    coreSource:build.coreRevision,kind:rollback?'ISSUANCE_CORE_FUNCTIONAL_OVERLAY':'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',hashes:{'marty-issuance-service':hash}});
  const actual=observations(next);return {state:'ACTUAL22_READBACK_VERIFIED',roles:actual.map(x=>x.row),actualRows:actual.map(x=>x.actual),runtimeProfileQualified:false};
 };
 let result;
 if(mode==='before')result={binding:verifier.verifyCanvasIssuerPreimage(input.baseProfile,input.evidence,{readDocker:read})};
 else if(mode==='untouched'){
  let transition=false;
  if(payload.nativeTransition){
   const proof=payload.nativeTransition,reference=proof.createdConfig||proof.originalConfig;
   const saved=json(reference),actual=JSON.parse(read(['inspect',proof.containerId]))[0];
   assert(actual.Id===proof.containerId&&actual.Id===saved.Id&&actual.Image===saved.Image,'TRANSITION_OWNER_CHANGED');
   assert(actual.Config.Labels['com.docker.compose.project']==='elevenid-beta'
    &&actual.Config.Labels['com.docker.compose.service']==='issuance-native','TRANSITION_ROLE_CHANGED');
   assert(['created','exited','running'].includes(actual.State.Status),'TRANSITION_STATE_UNKNOWN');
   if(!actual.State.Running)assert(actual.State.Pid===0&&!actual.State.OOMKilled,'TRANSITION_PROCESS_UNKNOWN');
   for(const key of ['Name','Config','HostConfig','Mounts'])assert(JSON.stringify(actual[key])===JSON.stringify(saved[key]),'TRANSITION_CONFIG_CHANGED');
   if(proof.originalConfig)assert(!actual.State.Running&&actual.State.Status==='exited','ORIGINAL_TRANSITION_NOT_STOPPED');
   transition=true;
  }
  const rows=expected().filter(row=>row.role!=='issuance-native').map(row=>{
   const actual=verifier.observeDocker(row,read);
   const observed=transition&&row.role==='gateway'?verifier.validateRuntimeIdentity(row,actual):verifier.validateRuntimeObservation(row,actual);
   return {actual,row:observed};
  });
  result={state:'UNCHANGED21_IDENTITY_VERIFIED',roles:rows.map(x=>x.row),actualRows:rows.map(x=>x.actual),
   readinessVerified:rows.every(x=>x.actual.health==='healthy'||x.actual.role==='canvas-sync-worker'&&x.actual.health===null)};
 }else if(mode==='after'||mode==='after-rollback')result=after(mode==='after-rollback');
 else if(mode==='after-original-restore'){
  const actual=expected().map(row=>{
   const observed=verifier.observeDocker(row,read);
   if(row.role!=='issuance-native')return {actual:observed,row:verifier.validateRuntimeObservation(row,observed)};
   const validated=verifier.validateRuntimeObservation(row,observed,true);
   assert(observed.containerId===row.requiredContainerId&&Date.parse(observed.startedAt)>Date.parse(row.requiredStartedAt),'ORIGINAL_RESTORE_GENERATION_INVALID');
   return {actual:observed,row:validated};
  });
  result={state:'ORIGINAL_RESTORED_ACTUAL22_VERIFIED',roles:actual.map(x=>x.row),actualRows:actual.map(x=>x.actual),runtimeProfileQualified:false};
 }
 else if(mode==='verify-profile')result={binding:verifier.verifyFunctionalRuntime(verifier.boundJson(payload.profile),{readDocker:read})};
 else if(mode==='inventory'){
  after(false); // Prove the actual scoped backend before interpreting a short list.
  assert(input.organizationId==='00000000-0000-0000-0000-000000000001');
  assert(/^[a-f0-9-]{36}$/.test(input.inventoryBindingId),'EXACT_BINDING_REQUIRED');
  const key=bytes(input.apiKey,16384).toString('utf8').trim();
  const {MartyClient}=require(path.join(input.driverRepository,'tests/scripts/run-canvas-oss-standard-contract.js'));
  const client=new MartyClient('https://beta.elevenidllc.com',key);
  try{
   const route='/v1/integrations/canvas/canvas-sync-jobs?organization_id='+encodeURIComponent(input.organizationId)
    +'&binding_id='+encodeURIComponent(input.inventoryBindingId)+'&limit=500';
   const response=await client.request('GET',route,{includeStatus:true});
   const rows=projectInventory(response.payload,input.organizationId,input.inventoryBindingId);
   result={state:'SCOPED_INVENTORY_READ_VERIFIED',httpStatus:response.status,scopeVerified:true,rowCount:rows.length,rows,
    authMode:'EXISTING_SCOPED_API_KEY',sessionCreated:false,credentialsMinted:false,privateCredentialCopyCreated:false,authCleanupComplete:true};
  }finally{client.apiKey=null;}
 }else throw Error('MODE_REFUSED');
 engine();return result;
}
async function main(){
 const {values}=require('node:util').parseArgs({options:{inputs:{type:'string'},'inputs-sha256':{type:'string'},mode:{type:'string'},payload:{type:'string'},'payload-sha256':{type:'string'}},strict:true});
 const input=json({path:values.inputs,sha256:values['inputs-sha256']});
 assert(input.schema==='marty.canvas-issuer-native-successor-input/v1');
 bytes(input.nodeReader);assert(path.resolve(input.nodeReader.path)===path.resolve(__filename),'SOURCE_READER_CHANGED');
 const payload=values.payload?json({path:values.payload,sha256:values['payload-sha256']}):{};
 process.stdout.write(JSON.stringify(await execute(input,values.mode,payload))+'\n');
}
if(require.main===module)main().catch(error=>{process.stderr.write(JSON.stringify({state:'READBACK_FAILED',errorType:error.name,
 code:/^[A-Z][A-Z0-9_]{2,79}$/.test(error.message)?error.message:'SOURCE_BOUND_READBACK_FAILED'})+'\n');process.exitCode=1;});
module.exports={projectInventory};
