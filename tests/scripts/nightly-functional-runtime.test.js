"use strict";
const test=require('node:test'),assert=require('node:assert/strict');
const nightly=require('./nightly-functional-runtime');
const shared=require('./functional-debug-runtime');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{createHash}=require('node:crypto');
const copy=value=>JSON.parse(JSON.stringify(value));
function fixture(){
 const documents={},refs={};
 for(const name of ['releaseLock','deployment','writerRestore','phase1Input','observation']){refs[name]={path:name,sha256:name==='releaseLock'?nightly.LOCK_SHA:'a'.repeat(64)};}
 const profile={schema:'marty.functional-mixed-runtime/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,signedImageDeployment:refs};
 const services={ui:nightly.UI};for(const role of nightly.ROLES.filter(r=>r!=='ui-prod'&&!r.startsWith('passport-')))services[role]=nightly.SERVICES;
 documents.releaseLock={release:'marty-ui@'+nightly.RELEASE.slice(1),services};documents.phase1Input={release:nightly.RELEASE,betaOnly:true,engineId:'engine'};
 const ids={},raw={},images=[nightly.SERVICES,nightly.UI].map((reference,index)=>({reference,Id:'sha256:'+String(index+1).repeat(64),RepoDigests:[reference],Config:{Labels:{'org.opencontainers.image.revision':nightly.SOURCE,'io.elevenid.selfhost.public-profile':'tester'}}}));
 const rowFor=role=>nightly.authority(profile,{boundJson:r=>documents[path.basename(r.path).replace(/\.json$/,'')]}).rows.find(row=>row.role===role);
 for(const [index,role]of [...nightly.ROLES,'keycloak','nginx-proxy'].entries()){
  const cid=(index+1).toString(16).padStart(64,'0');ids[role]=cid;
  raw[cid]={Id:cid,Image:images[role==='ui-prod'?1:0].Id,Config:{Image:role==='ui-prod'?nightly.UI:nightly.SERVICES,User:role==='ui-prod'?'101':'10001:10001',Labels:{'com.docker.compose.project':role==='ui-prod'?'elevenid-beta-ui':'elevenid-beta','com.docker.compose.service':role}},State:{Running:true,OOMKilled:false,Status:'running',Pid:100+index,StartedAt:'2026-11-01T00:00:00.000000000Z',...(role==='canvas-sync-worker'?{}:{Health:{Status:'healthy'}})},Mounts:[]};
 }
 documents.deployment={state:'PHASE2_MIXED_INFRA_STARTED',release:nightly.RELEASE,fullNightlyQualified:false,newCids:ids};
 documents.writerRestore={state:'OPENBAO_NIGHTLY_IMAGE_AND_PLUGIN_RUNNING',fullNightlyQualified:false,keysGenerated:false,writersRemainQuiesced:false,restoredWriters:copy(Object.values(raw))};
 function readDocker(args){
  if(args[0]==='info')return JSON.stringify({ID:'engine'});
  if(args[0]==='image')return JSON.stringify([images.find(image=>image.reference===args[2])]);
  if(args[0]==='ps'){const role=args.at(-1).split('=').at(-1);return ids[role];}
  const row=raw[args[1]];assert(row);
  if(args[0]==='inspect')return JSON.stringify([row]);
  const role=row.Config.Labels['com.docker.compose.service'],expected=rowFor(role);
  if(args[2]==='readlink')return '/usr/local/bin/'+expected.binary;
  if(args[2]==='sha256sum')return 'c'.repeat(64)+'  '+args[3];
  if(args[2]==='cat')return 'Uid:\t10001\t'+(role==='ui-prod'?'101':'10001')+'\t10001\t10001\nGid:\t10001\t10001\t10001\t10001\n';
  throw Error('Unreviewed Docker operation');
 }
 return {profile,documents,raw,ids,readDocker,boundJson:ref=>documents[path.basename(ref.path).replace(/\.json$/,'')]};
}
function produce(f){return nightly.produce(f.profile,{...shared,readDocker:f.readDocker,boundJson:f.boundJson});}
test('actual observation boundary binds all22 images and PID executables without native overlays',()=>{
 const f=fixture();f.documents.observation=produce(f);const rows=nightly.expected(f.profile,{boundJson:f.boundJson,validateRuntimeObservation:shared.validateRuntimeObservation});assert.equal(rows.length,22);assert(rows.every(row=>row.kind==='SIGNED_NIGHTLY_IMAGE'));assert.equal(f.documents.observation.releaseQualified,false);
});
test('wrong signed image source and wrong role generation fail closed',()=>{
 const f=fixture();f.documents.observation=produce(f);f.documents.observation.images[0].sourceRevision='0'.repeat(40);assert.throws(()=>nightly.expected(f.profile,{boundJson:f.boundJson,validateRuntimeObservation:shared.validateRuntimeObservation}));
 const g=fixture();g.raw[g.ids.flow].State.StartedAt='2026-11-02T00:00:00Z';assert.throws(()=>produce(g));
});
test('executable overlay and wrong nonroot UID cannot become image evidence',()=>{
 const f=fixture();f.raw[f.ids.flow].Mounts=[{Destination:'/usr/local/bin/marty-flow',Type:'bind',Source:'/tmp/old-binary',RW:false}];assert.throws(()=>produce(f));
 const g=fixture();g.raw[g.ids.flow].Config.User='0';assert.throws(()=>produce(g));
});
test('missing role and native authority substitution are rejected',()=>{
 const f=fixture();f.documents.writerRestore.restoredWriters.pop();assert.throws(()=>produce(f));
 const g=fixture();g.profile.nativeOverlay={};assert.throws(()=>produce(g));
});

test('shared verifier returns existing v2 IPC binding with truthful signed-image classification',()=>{
 const f=fixture(),root=fs.mkdtempSync(path.join(os.tmpdir(),'nightly-verifier-'));
 try{
  for(const name of ['releaseLock','deployment','writerRestore','phase1Input']){
   const file=path.join(root,name+'.json'),bytes=name==='releaseLock'?fs.readFileSync(path.join(__dirname,'../fixtures/nightly263-images.json')):Buffer.from(JSON.stringify(f.documents[name]));
   fs.writeFileSync(file,bytes);f.profile.signedImageDeployment[name]={path:file,sha256:createHash('sha256').update(bytes).digest('hex')};
  }
  f.documents.observation=produce(f);const file=path.join(root,'observation.json'),bytes=Buffer.from(JSON.stringify(f.documents.observation));
  fs.writeFileSync(file,bytes);f.profile.signedImageDeployment.observation={path:file,sha256:createHash('sha256').update(bytes).digest('hex')};
  const binding=shared.verifyFunctionalRuntime(f.profile,{readDocker:f.readDocker});
  assert.equal(binding.schema,'marty.functional-mixed-runtime-binding/v2');assert.equal(binding.runtimeKind,'SIGNED_NIGHTLY_IMAGES');
  assert.equal(binding.mixedSourceStack,false);assert.equal(binding.releaseQualified,false);assert.equal(binding.roles.length,22);
 }finally{assert.equal(path.dirname(root),os.tmpdir());fs.rmSync(root,{recursive:true});}
});
