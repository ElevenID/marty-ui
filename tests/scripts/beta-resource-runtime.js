'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const HASH=/^[a-f0-9]{64}$/;
const sha=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
function envMap(rows){assert(Array.isArray(rows),'RESOURCE_ENV_SCHEMA');const pairs=rows.map(text=>{assert(typeof text==='string');const i=text.indexOf('=');assert(i>0,'RESOURCE_ENV_SCHEMA');return [text.slice(0,i),text.slice(i+1)]});assert.equal(new Set(pairs.map(pair=>pair[0])).size,pairs.length,'RESOURCE_ENV_DUPLICATE');return Object.fromEntries(pairs);}
function envDigest(value){return sha(Object.entries(value).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0));}
const CONFIG_DIGEST_SCHEMA='marty.beta-resource-config-digests/v2';
function sameGeneration(live,expected,role){
 assert(live.State?.StartedAt===expected.startedAt&&live.State?.Pid===expected.pid,'RESOURCE_GENERATION_CHANGED:'+role);
}
function mountDigest(row){
 assert(Array.isArray(row.Mounts),'RESOURCE_MOUNT_SCHEMA');
 const mounts=row.Mounts.map(m=>{
  assert(typeof m.Type==='string'&&m.Type.length>0&&typeof m.Destination==='string'
   &&m.Destination.startsWith('/')&&typeof m.RW==='boolean','RESOURCE_MOUNT_SCHEMA');
  assert(m.Name===undefined||m.Name===null||typeof m.Name==='string','RESOURCE_MOUNT_SCHEMA');
  return {type:m.Type,source:m.Source,destination:m.Destination,name:m.Name||null,rw:m.RW};
 });
 // Lazy lookup keeps the shared runtime's resource-adapter import acyclic.
 const {comparableBinaryMounts}=require('./functional-debug-runtime');
 const rows=mounts.map(mount=>{
  assert(typeof mount.source==='string'&&mount.source.length>0&&!/[\x00-\x1f\x7f]/.test(mount.source),'RESOURCE_MOUNT_SOURCE');
  // Docker volume sources are opaque engine identities, not host-path aliases.
  return mount.type==='bind'?comparableBinaryMounts([mount])[0]:mount;
 });
 assert.equal(new Set(rows.map(x=>x.destination)).size,rows.length,'RESOURCE_MOUNT_DUPLICATE');
 rows.sort((a,b)=>a.destination<b.destination?-1:a.destination>b.destination?1:0);
 return sha({schema:'marty.beta-resource-mounts/v2',mounts:rows});
}
function authority(profile,{boundJson,expectedRuntime,receiptDigests}){
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');
 assert.equal(profile.scope,'FUNCTIONAL_ONLY');
 assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 const r=profile.resourceRecreation;assert(r&&profile.baseProfile,'RESOURCE_PROFILE_REQUIRED');
 const base=boundJson(profile.baseProfile),old=expectedRuntime(base);
 assert.equal(old.length,22,'RESOURCE_BASE_ROLE_COUNT_CHANGED');assert.equal(new Set(old.map(x=>x.role)).size,old.length);assert.equal(old.filter(x=>x.role==='ui-prod').length,1);
 const cap=boundJson(r.capResult),input=boundJson(cap.baseRef),ui=boundJson(r.uiResult),uiStarted=boundJson(r.uiStarted),uiLive=boundJson(r.uiObservation),kc=boundJson(r.keycloakResult),heap=boundJson(r.keycloakHeap),configs=boundJson(r.configDigests);
 assert(Object.values(receiptDigests(base)).includes(r.engineAuthority.sha256),'RESOURCE_ENGINE_AUTHORITY_NOT_IN_BASE');
 const engine=boundJson(r.engineAuthority);assert.match(engine.engineId,/^[a-f0-9-]{36}$/);
 assert.equal(cap.state,'BETA_CAPS_RECREATED');assert.equal(cap.kernelCapsVerified,Object.keys(input.before).length);
 assert.equal(cap.productionTouched,false);assert.equal(cap.imagesBuilt,false);
 assert.deepEqual(cap.roles.slice().sort(),Object.keys(input.targets).sort());
 assert.equal(new Set(cap.roles).size,Object.keys(input.targets).length);assert.deepEqual(Object.keys(cap.allRunningRoles).sort(),Object.keys(input.before).sort());
 assert.equal(ui.state,'BETA_UI_256M_RECREATED');assert.equal(ui.productionTouched,false);assert.equal(ui.imagesBuilt,false);
 assert.equal(ui.memoryBytes,268435456);assert(Array.isArray(ui.globalIds)&&ui.globalIds.every(id=>HASH.test(id)));
 assert.equal(new Set(ui.globalIds).size,ui.globalIds.length,'RESOURCE_GLOBAL_IDS_DUPLICATE');
 for(const role of Object.keys(cap.allRunningRoles))assert(ui.globalIds.includes(cap.allRunningRoles[role].id),'RESOURCE_REQUIRED_ID_MISSING:'+role);
 assert(ui.globalIds.includes(ui.newCid)&&!ui.globalIds.includes(ui.oldCid),'RESOURCE_UI_ID_SET_CHANGED');
 assert.equal(configs.schema,CONFIG_DIGEST_SCHEMA);
 assert.equal(configs.capResultSha256,r.capResult.sha256);assert.equal(configs.uiResultSha256,r.uiResult.sha256);assert.equal(configs.keycloakResultSha256,r.keycloakResult.sha256);
 assert.equal(configs.rows.length,Object.keys(input.before).length+1);assert.equal(new Set(configs.rows.map(x=>x.cid)).size,configs.rows.length);
 assert.equal(kc.state,'KEYCLOAK_HEAP_UPDATED');assert.equal(kc.productionTouched,false);
 assert.equal(kc.oldCid,cap.allRunningRoles.keycloak.id);
 assert(HASH.test(kc.newCid)&&kc.newCid!==kc.oldCid);
 assert.equal(heap.state,'KEYCLOAK_EFFECTIVE_HEAP_VERIFIED');assert.equal(heap.cid,kc.newCid);
 assert.equal(heap.memoryBytes,1073741824);assert.equal(heap.healthy,true);
 assert.deepEqual([...heap.jvmMemoryFlags].sort(),['-XX:MaxMetaspaceSize=256m','-XX:InitialRAMPercentage=20','-XX:MaxRAMPercentage=65'].sort());
 assert.equal(uiStarted.cid||uiStarted.id||uiStarted.containerId,ui.newCid);
 assert.equal(uiLive.cid,ui.newCid);assert.equal(uiLive.image,uiStarted.image);
 assert.equal(uiLive.startedAt,uiStarted.startedAt);assert.equal(uiLive.running,true);assert.equal(uiLive.health,'healthy');
 assert.equal(uiLive.memoryBytes,268435456);assert.equal(uiLive.combinedSwapBytes,536870912);
 assert(Number.isInteger(uiLive.pid)&&uiLive.pid>0);
 const rows=old.map(row=>{
  if(row.role==='ui-prod'){
   assert.equal(row.requiredContainerId,ui.oldCid);
   assert.equal(uiStarted.image||uiStarted.imageId,row.imageId);
   assert.equal(uiStarted.running,true);
   assert(Number.isFinite(Date.parse(uiStarted.startedAt))&&Date.parse(uiStarted.startedAt)>Date.parse(row.requiredStartedAt));
   const observation={...row.requiredObservation,containerId:ui.newCid,startedAt:uiStarted.startedAt,hostPid:uiLive.pid};
   return {...row,requiredContainerId:ui.newCid,requiredStartedAt:uiStarted.startedAt,requiredHostPid:uiLive.pid,requiredObservation:observation};
  }
  const before=input.before[row.role],after=cap.allRunningRoles[row.role];
  assert(before&&after,'RESOURCE_ROLE_MISSING:'+row.role);
  assert.equal(before.id,row.requiredContainerId,'RESOURCE_PREIMAGE_CHANGED:'+row.role);
  assert.equal(before.imageId,row.imageId);assert.equal(after.image,row.imageId);
  assert.equal(before.startedAt,row.requiredStartedAt);
  assert(HASH.test(after.id)&&after.id!==before.id);
  assert(Number.isFinite(Date.parse(after.startedAt))&&Date.parse(after.startedAt)>Date.parse(before.startedAt));
  assert(Number.isInteger(after.pid)&&after.pid>0);
  assert(after.health==='healthy'||row.role==='canvas-sync-worker'&&after.health===null,'RESOURCE_ROLE_HEALTH:'+row.role);
  const observation=row.requiredObservation?{...row.requiredObservation,containerId:after.id,startedAt:after.startedAt,hostPid:after.pid}:undefined;
  return {...row,requiredContainerId:after.id,requiredStartedAt:after.startedAt,requiredHostPid:after.pid,...(observation?{requiredObservation:observation}:{})};
 });
 return {rows,cap,input,ui,uiStarted,uiLive,kc,configs,engineId:engine.engineId};
}
function verifyAncillary(profile,readDocker,{boundJson,expectedRuntime,receiptDigests},generations=null){
 const a=authority(profile,{boundJson,expectedRuntime,receiptDigests});
 if(generations){
  assert(generations instanceof Map&&generations.size===Object.keys(a.cap.allRunningRoles).length+1,'RESOURCE_RESTART_COHORT_CHANGED');
  for(const [role,prior] of Object.entries(a.cap.allRunningRoles)){
   const row=generations.get(role);assert(row&&row.cid===(role==='keycloak'?a.kc.newCid:prior.id),'RESOURCE_RESTART_ID_CHANGED:'+role);
   assert(Number.isFinite(Date.parse(row.startedAt))&&Number.isSafeInteger(row.pid)&&row.pid>0,'RESOURCE_RESTART_GENERATION_INVALID:'+role);
  }
  const ui=generations.get('ui-prod');assert(ui&&ui.cid===a.ui.newCid,'RESOURCE_RESTART_ID_CHANGED:ui-prod');
 }
 const ids=readDocker(['ps','-q','--no-trunc','--filter','label=com.docker.compose.project=elevenid-beta','--filter','label=com.docker.compose.service=keycloak']).trim().split(/\s+/).filter(Boolean);
 assert.deepEqual(ids,[a.kc.newCid],'KEYCLOAK_GENERATION_CHANGED');
 const configRows=new Map(a.configs.rows.map(x=>[x.cid,x]));
 const modelRows=new Map(Object.values(a.input.models).map(x=>[x.afterPath,x]));
 const imageEnv=new Map();
 function checkConfiguration(row,role,modelPath,modelSha){
  const proof=configRows.get(row.Id);assert(proof,'RESOURCE_CONFIG_PROOF_MISSING:'+role);
  assert.equal(proof.image,row.Image);assert.equal(proof.modelPath,modelPath);
  const image=row.Image;if(!imageEnv.has(image))imageEnv.set(image,envMap(JSON.parse(readDocker(['image','inspect',image]))[0].Config?.Env||[]));
  const model=boundJson({path:modelPath,sha256:modelSha});const service=model.services?.[role];assert(service,'RESOURCE_MODEL_ROLE_MISSING:'+role);
  const configured=service.environment||{};assert(configured&&typeof configured==='object'&&!Array.isArray(configured),'RESOURCE_MODEL_ENV_SCHEMA');
  const expected={...imageEnv.get(image),...configured};
  assert.equal(envDigest(envMap(row.Config?.Env||[])),envDigest(expected),'RESOURCE_ENV_CHANGED:'+role);
  assert.equal(proof.envSha256,envDigest(expected),'RESOURCE_ENV_PROOF_CHANGED:'+role);
  assert.equal(mountDigest(row),proof.mountsSha256,'RESOURCE_MOUNT_CHANGED:'+role);
 }
 const row=JSON.parse(readDocker(['inspect',ids[0]]))[0];
 assert.equal(row.Id,a.kc.newCid);assert.equal(row.State?.Running,true);assert.equal(row.State?.Health?.Status,'healthy');
 if(generations)assert(row.State?.Paused===false&&row.State?.OOMKilled===false,'RESOURCE_RESTART_STATE_CHANGED:keycloak');
 if(generations)sameGeneration(row,generations.get('keycloak'),'keycloak');
 assert.equal(row.HostConfig?.Memory,1073741824);assert.equal(row.HostConfig?.MemorySwap,2147483648);
 assert.equal(row.Image,a.cap.allRunningRoles.keycloak.image);
 const env=row.Config?.Env||[];assert(env.includes('JAVA_OPTS_KC_HEAP=-XX:InitialRAMPercentage=20 -XX:MaxRAMPercentage=65'),'KEYCLOAK_HEAP_ENV_CHANGED');
 const kcProof=configRows.get(row.Id);assert(kcProof&&kcProof.image===row.Image);assert.equal(envDigest(envMap(env)),kcProof.envSha256,'KEYCLOAK_ENV_CHANGED');assert.equal(mountDigest(row),kcProof.mountsSha256,'KEYCLOAK_MOUNT_CHANGED');
 for(const [role,expected] of Object.entries(a.cap.allRunningRoles)){if(role==='keycloak')continue;const old=a.input.before[role];
  const live=JSON.parse(readDocker(['inspect',expected.id]))[0];
  assert.equal(live.Id,expected.id);assert.equal(live.Image,expected.image);
  if(generations)assert(live.State?.Paused===false&&live.State?.OOMKilled===false,'RESOURCE_RESTART_STATE_CHANGED:'+role);
  assert.equal(live.State?.Running,true);sameGeneration(live,generations?.get(role)||expected,role);
  assert.equal(live.HostConfig?.Memory,a.input.targets[role]||old.memory);
  assert.equal(live.HostConfig?.MemorySwap,a.input.targets[role]?a.input.targets[role]*2:old.memorySwap);
  assert.equal(live.State?.Health?.Status||null,expected.health,'RESOURCE_ROLE_HEALTH_CHANGED:'+role);
  const modelPath=live.Config?.Labels?.['com.docker.compose.project.config_files'];if(a.input.targets[role]){const model=modelRows.get(modelPath);assert(model,'RESOURCE_MODEL_PATH_CHANGED:'+role);checkConfiguration(live,role,modelPath,model.afterSha256);}
  else{assert.equal(modelPath,old.modelPath,'RESOURCE_PRESERVED_MODEL_CHANGED:'+role);const proof=configRows.get(live.Id);assert(proof&&proof.image===live.Image);assert.equal(envDigest(envMap(live.Config?.Env||[])),proof.envSha256,'RESOURCE_PRESERVED_ENV_CHANGED:'+role);assert.equal(mountDigest(live),proof.mountsSha256,'RESOURCE_PRESERVED_MOUNT_CHANGED:'+role);}
 }
 const liveUi=JSON.parse(readDocker(['inspect',a.ui.newCid]))[0];
 assert.equal(liveUi.Id,a.ui.newCid);assert.equal(liveUi.HostConfig?.Memory,268435456);assert.equal(liveUi.HostConfig?.MemorySwap,536870912);
 if(generations)assert(liveUi.State?.Paused===false&&liveUi.State?.OOMKilled===false,'RESOURCE_RESTART_STATE_CHANGED:ui-prod');
 if(generations){assert.equal(liveUi.State?.Running,true);sameGeneration(liveUi,generations.get('ui-prod'),'ui-prod');assert.equal(liveUi.State?.Health?.Status,'healthy');}
 assert.equal(liveUi.Config?.Labels?.['com.docker.compose.project.config_files'],a.ui.modelPath);
 checkConfiguration(liveUi,'ui-prod',a.ui.modelPath,a.ui.modelSha256);
 return a;
}
function resourceSuccessor(previousRef,profile,context){
 assert.deepEqual(Object.keys(profile).sort(),['schema','scope','releaseQualified','recordingQualified','baseProfile','resourceRecreation'].sort(),
  'RESOURCE_SUCCESSOR_COMPOSITION_CHANGED');
 assert.equal(profile.baseProfile.sha256,previousRef.sha256,'RESOURCE_SUCCESSOR_BASE_CHANGED');
 const previous=context.boundJson(previousRef);
 assert.deepEqual(context.boundJson(profile.baseProfile),previous,'RESOURCE_SUCCESSOR_BASE_CHANGED');
 const a=authority(profile,context),before=context.expectedRuntime(previous),after=a.rows;
 const cid=row=>row.requiredContainerId||row.requiredObservation?.containerId;
 const ancillary=['docs','nginx-proxy','openbao','postgres','redis','keycloak'];
 const roles=[...before.map(row=>row.role).filter(role=>role!=='ui-prod'),...ancillary].sort();
 assert.equal(roles.length,27);assert.equal(new Set(roles).size,27,'RESOURCE_SUCCESSOR_ROLES_CHANGED');
 assert.deepEqual(Object.keys(a.input.before).sort(),roles,'RESOURCE_SUCCESSOR_ROLES_CHANGED');
 assert.deepEqual(Object.keys(a.cap.allRunningRoles).sort(),roles,'RESOURCE_SUCCESSOR_ROLES_CHANGED');
 const fixed=new Set(['openbao','postgres','redis','keycloak']);
 assert.deepEqual(Object.keys(a.input.targets).sort(),roles.filter(role=>!fixed.has(role)),
  'RESOURCE_SUCCESSOR_TARGETS_CHANGED');
 const replacements=roles.map(role=>{
  const oldCid=a.input.before[role].id,capCid=a.cap.allRunningRoles[role].id;
  assert(HASH.test(oldCid)&&HASH.test(capCid),'RESOURCE_SUCCESSOR_ID_CHANGED');
  assert.equal(capCid===oldCid,fixed.has(role),'RESOURCE_SUCCESSOR_UNAUTHORIZED_RECREATION');
  if(role==='keycloak')assert.equal(a.kc.oldCid,oldCid,'RESOURCE_SUCCESSOR_KEYCLOAK_PREIMAGE_CHANGED');
  return {role,oldCid,newCid:role==='keycloak'?a.kc.newCid:capCid};
 });
 replacements.push({role:'ui-prod',oldCid:a.ui.oldCid,newCid:a.ui.newCid});
 const oldIds=replacements.map(row=>row.oldCid),newIds=replacements.map(row=>row.newCid);
 assert(oldIds.every(id=>HASH.test(id))&&newIds.every(id=>HASH.test(id)));
 assert.equal(new Set(oldIds).size,28,'RESOURCE_SUCCESSOR_DUPLICATE_ID');
 assert.equal(new Set(newIds).size,28,'RESOURCE_SUCCESSOR_DUPLICATE_ID');
 for(const row of replacements)assert(row.newCid===row.oldCid||!oldIds.includes(row.newCid),
  'RESOURCE_SUCCESSOR_REUSED_ID');
 for(const [rows,key]of [[before,'oldCid'],[after,'newCid']]){
  assert.equal(rows.length,22);assert.equal(new Set(rows.map(row=>row.role)).size,22);
  for(const row of rows)assert.equal(replacements.find(next=>next.role===row.role)?.[key],cid(row),
   'RESOURCE_SUCCESSOR_RETAINED_ROLE_CHANGED');
 }
 return {kind:'resource-recreation',replacements,uiGlobalIds:a.ui.globalIds};
}

// Match the committed UTF-8 Git blob across Windows CRLF and LF checkouts.
// Receipt/configuration files remain byte-hashed by the existing bound readers.
const canonicalSourceDigest=bytes=>crypto.createHash('sha256')
 .update(Buffer.from(bytes.toString('utf8').replaceAll('\r\n','\n'))).digest('hex');
const restartSource=()=>canonicalSourceDigest(fs.readFileSync(__filename));
function restartBaseline(a){
 const rows=Object.entries(a.cap.allRunningRoles).map(([role,row])=>role==='keycloak'
  // The cap row belongs to the retired KC CID. It is only a time floor, never a same-CID generation.
  ?{role,cid:a.kc.newCid,earliestStartedAt:row.startedAt}
  :{role,cid:row.id,startedAt:row.startedAt,pid:row.pid});
 assert(Number.isFinite(Date.parse(a.uiLive.startedAt))&&Number.isSafeInteger(a.uiLive.pid)&&a.uiLive.pid>0,
  'RESOURCE_RESTART_UI_BASELINE_MISSING');
 rows.push({role:'ui-prod',cid:a.ui.newCid,startedAt:a.uiLive.startedAt,pid:a.uiLive.pid});
 return rows.sort((x,y)=>x.role.localeCompare(y.role));
}
function restartAuthority(profile,context){
 assert.deepEqual(Object.keys(profile).sort(),['schema','scope','releaseQualified','recordingQualified','baseProfile','resourceRestart'].sort(),'RESOURCE_RESTART_PROFILE_SCHEMA');
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');assert.equal(profile.scope,'FUNCTIONAL_ONLY');
 assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 const base=context.boundJson(profile.baseProfile),receipt=context.boundJson(profile.resourceRestart);
 return validateRestart(profile.baseProfile,base,receipt,context);
}
function validateRestart(baseRef,base,receipt,context){
 assert(base.resourceRecreation&&!base.resourceRestart,'RESOURCE_RESTART_BASE_REQUIRED');
 assert.deepEqual(Object.keys(receipt).sort(),['schema','scope','releaseQualified','recordingQualified','baseProfile','engineId','sourceSha256','historicalGenerationUnknown','roles'].sort(),'RESOURCE_RESTART_RECEIPT_SCHEMA');
 assert.equal(receipt.schema,'marty.beta-resource-restart/v1');assert.equal(receipt.scope,'FUNCTIONAL_ONLY');
 assert.equal(receipt.releaseQualified,false);assert.equal(receipt.recordingQualified,false);
 assert.deepEqual(receipt.baseProfile,baseRef,'RESOURCE_RESTART_BASE_CHANGED');
 assert.equal(receipt.sourceSha256,restartSource(),'RESOURCE_RESTART_SOURCE_CHANGED');
 assert.deepEqual(receipt.historicalGenerationUnknown,['keycloak'],'RESOURCE_RESTART_UNKNOWN_GENERATION_CHANGED');
 const a=authority(base,context);assert.equal(receipt.engineId,a.engineId,'RESOURCE_RESTART_ENGINE_CHANGED');
 const baseline=restartBaseline(a),roles=receipt.roles;
 assert(Array.isArray(roles)&&roles.length===baseline.length,'RESOURCE_RESTART_COHORT_CHANGED');
 assert.deepEqual(roles.map(row=>row.role),baseline.map(row=>row.role),'RESOURCE_RESTART_COHORT_CHANGED');
 let changed=0;
 const generations=new Map(roles.map((row,index)=>{
  assert.deepEqual(Object.keys(row).sort(),['role','cid','startedAt','pid'].sort(),'RESOURCE_RESTART_ROW_SCHEMA');
  const old=baseline[index];assert.equal(row.cid,old.cid,'RESOURCE_RESTART_ID_CHANGED:'+row.role);
  assert(Number.isSafeInteger(row.pid)&&row.pid>0&&Number.isFinite(Date.parse(row.startedAt)),'RESOURCE_RESTART_GENERATION_INVALID:'+row.role);
  if(row.role==='keycloak')assert(Date.parse(row.startedAt)>Date.parse(old.earliestStartedAt),
   'RESOURCE_RESTART_KEYCLOAK_BEFORE_RECREATION');
  else if(row.startedAt===old.startedAt)assert.equal(row.pid,old.pid,'RESOURCE_RESTART_UNCHANGED_PID:'+row.role);
  else {assert(Date.parse(row.startedAt)>Date.parse(old.startedAt),'RESOURCE_RESTART_NOT_NEWER:'+row.role);changed++;}
  return [row.role,row];
 }));
 assert(changed>0,'RESOURCE_RESTART_NO_CHANGE');
 const expected=context.expectedRuntime(base);
 const rows=expected.map(row=>{const g=generations.get(row.role);assert(g,'RESOURCE_RESTART_ROLE_MISSING');
  return {...row,requiredStartedAt:g.startedAt,requiredHostPid:g.pid,
   ...(row.requiredObservation?{requiredObservation:{...row.requiredObservation,startedAt:g.startedAt,hostPid:g.pid}}:{})};});
 return {base,a,receipt,generations,rows};
}
function produceResourceRestart(baseRef,{boundJson,expectedRuntime,receiptDigests,observeDocker,validateRuntimeObservation,readDocker}){
 assert.equal(typeof readDocker,'function','RESOURCE_RESTART_ACTUAL_DOCKER_REQUIRED');
 const base=boundJson(baseRef),context={boundJson,expectedRuntime,receiptDigests};
 assert(base.resourceRecreation&&!base.resourceRestart,'RESOURCE_RESTART_BASE_REQUIRED');
 const a=authority(base,context),before=JSON.parse(readDocker(['info','--format','{{json .}}']));
 assert.equal(before.ID,a.engineId,'RESOURCE_RESTART_ENGINE_CHANGED');
 const baseline=restartBaseline(a),roles=baseline.map(old=>{
  const live=JSON.parse(readDocker(['inspect',old.cid]))[0];
  assert(live&&live.Id===old.cid,'RESOURCE_RESTART_ID_CHANGED:'+old.role);
  return {role:old.role,cid:old.cid,startedAt:live.State?.StartedAt,pid:live.State?.Pid};
 });
 const receipt={schema:'marty.beta-resource-restart/v1',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,
  baseProfile:baseRef,engineId:a.engineId,sourceSha256:restartSource(),historicalGenerationUnknown:['keycloak'],roles};
 const result=validateRestart(baseRef,base,receipt,context);
 verifyAncillary(base,readDocker,context,result.generations);
 for(const row of expectedRuntime(base)){const actual=observeDocker(row,readDocker);validateRuntimeObservation(row,actual,true);
  const generation=result.generations.get(row.role);assert.equal(actual.startedAt,generation.startedAt);assert.equal(actual.hostPid,generation.pid);}
 verifyAncillary(base,readDocker,context,result.generations);
 const after=JSON.parse(readDocker(['info','--format','{{json .}}']));assert.equal(after.ID,a.engineId,'RESOURCE_RESTART_ENGINE_CHANGED');
 boundJson(baseRef);return receipt;
}

module.exports={resourceSuccessor,authority,verifyAncillary,restartAuthority,produceResourceRestart,canonicalSourceDigest,mountDigest,CONFIG_DIGEST_SCHEMA};
