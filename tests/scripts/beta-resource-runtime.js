'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const HASH=/^[a-f0-9]{64}$/;
const sha=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
function envMap(rows){assert(Array.isArray(rows),'RESOURCE_ENV_SCHEMA');const pairs=rows.map(text=>{assert(typeof text==='string');const i=text.indexOf('=');assert(i>0,'RESOURCE_ENV_SCHEMA');return [text.slice(0,i),text.slice(i+1)]});assert.equal(new Set(pairs.map(pair=>pair[0])).size,pairs.length,'RESOURCE_ENV_DUPLICATE');return Object.fromEntries(pairs);}
function envDigest(value){return sha(Object.entries(value).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0));}
const CONFIG_DIGEST_SCHEMA='marty.beta-resource-config-digests/v2';
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
 return {rows,cap,input,ui,kc,configs,engineId:engine.engineId};
}
function verifyAncillary(profile,readDocker,{boundJson,expectedRuntime,receiptDigests}){
 const a=authority(profile,{boundJson,expectedRuntime,receiptDigests});
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
 assert.equal(row.HostConfig?.Memory,1073741824);assert.equal(row.HostConfig?.MemorySwap,2147483648);
 assert.equal(row.Image,a.cap.allRunningRoles.keycloak.image);
 const env=row.Config?.Env||[];assert(env.includes('JAVA_OPTS_KC_HEAP=-XX:InitialRAMPercentage=20 -XX:MaxRAMPercentage=65'),'KEYCLOAK_HEAP_ENV_CHANGED');
 const kcProof=configRows.get(row.Id);assert(kcProof&&kcProof.image===row.Image);assert.equal(envDigest(envMap(env)),kcProof.envSha256,'KEYCLOAK_ENV_CHANGED');assert.equal(mountDigest(row),kcProof.mountsSha256,'KEYCLOAK_MOUNT_CHANGED');
 for(const [role,expected] of Object.entries(a.cap.allRunningRoles)){if(role==='keycloak')continue;const old=a.input.before[role];
  const live=JSON.parse(readDocker(['inspect',expected.id]))[0];
  assert.equal(live.Id,expected.id);assert.equal(live.Image,expected.image);
  assert.equal(live.State?.Running,true);assert.equal(live.State?.StartedAt,expected.startedAt);assert.equal(live.State?.Pid,expected.pid);
  assert.equal(live.HostConfig?.Memory,a.input.targets[role]||old.memory);
  assert.equal(live.HostConfig?.MemorySwap,a.input.targets[role]?a.input.targets[role]*2:old.memorySwap);
  assert.equal(live.State?.Health?.Status||null,expected.health,'RESOURCE_ROLE_HEALTH_CHANGED:'+role);
  const modelPath=live.Config?.Labels?.['com.docker.compose.project.config_files'];if(a.input.targets[role]){const model=modelRows.get(modelPath);assert(model,'RESOURCE_MODEL_PATH_CHANGED:'+role);checkConfiguration(live,role,modelPath,model.afterSha256);}
  else{assert.equal(modelPath,old.modelPath,'RESOURCE_PRESERVED_MODEL_CHANGED:'+role);const proof=configRows.get(live.Id);assert(proof&&proof.image===live.Image);assert.equal(envDigest(envMap(live.Config?.Env||[])),proof.envSha256,'RESOURCE_PRESERVED_ENV_CHANGED:'+role);assert.equal(mountDigest(live),proof.mountsSha256,'RESOURCE_PRESERVED_MOUNT_CHANGED:'+role);}
 }
 const liveUi=JSON.parse(readDocker(['inspect',a.ui.newCid]))[0];
 assert.equal(liveUi.Id,a.ui.newCid);assert.equal(liveUi.HostConfig?.Memory,268435456);assert.equal(liveUi.HostConfig?.MemorySwap,536870912);
 assert.equal(liveUi.Config?.Labels?.['com.docker.compose.project.config_files'],a.ui.modelPath);
 checkConfiguration(liveUi,'ui-prod',a.ui.modelPath,a.ui.modelSha256);
 return a;
}
module.exports={authority,verifyAncillary,mountDigest,CONFIG_DIGEST_SCHEMA};
