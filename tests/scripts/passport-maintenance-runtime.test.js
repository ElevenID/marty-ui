'use strict';
// Generated generation/lineage controls, not an actual22 or migration receipt.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {validateGenerations,ROLES,SOURCE,CORE}=require('./passport-maintenance-runtime');
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
function fixture(){
 const names='auth organization credential-template trust-profile applicant notification compliance-profile presentation-policy deployment-profile flow verification revocation-profile device-registration issuance issuance-native canvas-sync-worker passport-beta-bureau gateway signing-keys passport-callback-signer canvas-sandbox ui-prod'.split(' ');
 const selection={profile:'d12-passport-canonical-subset',state:'SELECTED_NOT_DEPLOYED',sourceRevision:SOURCE,coreRevision:CORE,roleBinaries:ROLES,
  binaries:Object.fromEntries(Object.keys(ROLES).map(role=>[role,{path:'/new/'+ROLES[role],sha256:hash('new'+role)}])),scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false};
 const before=names.map(role=>{
  const binary=role==='ui-prod'?null:ROLES[role]||'marty-'+role,sha256=binary?hash(role):null;
  return {role,binary,source:hash('prior').slice(0,40),...(role==='issuance-native'?{coreSource:hash('older-core').slice(0,40)}:{}),sha256,kind:'SYNTHETIC_CONTROL',imageId:'sha256:'+hash('image'),project:role==='ui-prod'?'elevenid-beta-ui':'elevenid-beta',containerId:hash('old'+role),hostPid:1,startedAt:'2026-10-28T00:00:00Z',health:role==='canvas-sync-worker'?null:'healthy',effectiveUid:10001,configuredRuntimeUid:10001,executablePath:binary?'/usr/local/bin/'+binary:null,processExecutableSha256:sha256,binaryMounts:binary?[{type:'bind',source:'/old/'+binary,destination:'/usr/local/bin/'+binary,writable:false}]:[]};
 });
 const expected=before.map(row=>({...row,requiredObservation:Object.fromEntries(['containerId','imageId','health','executablePath','processExecutableSha256','binaryMounts','startedAt','hostPid','effectiveUid','configuredRuntimeUid'].map(key=>[key,row[key]]))}));
 const observed=before.map(row=>({...structuredClone(row),service:row.role,running:true,status:'running',binarySha256:row.sha256,startedAt:'2026-10-28T01:00:00Z',hostPid:2,
  ...(ROLES[row.role]?{containerId:hash('new'+row.role),binarySha256:selection.binaries[row.role].sha256,processExecutableSha256:selection.binaries[row.role].sha256,binaryMounts:[{...row.binaryMounts[0],source:selection.binaries[row.role].path}]}:{})}));
 return {expected,before,selection,observed};
}
test('all22 maintenance generations preserve19 lineages and select exact3 ELF/Core lineages',()=>{
 const f=fixture(),result=validateGenerations(f.expected,f.before,f.selection,f.observed);
 assert.equal(result.length,22);
 for(const row of result){assert.equal(row.startedAt,'2026-10-28T01:00:00Z');if(ROLES[row.role]){assert.equal(row.source,SOURCE);assert.equal(row.coreSource,CORE);}else assert.equal(row.source,f.before.find(x=>x.role===row.role).source);}
});
for(const [name,change]of Object.entries({
 'stale selected generation':f=>f.observed.find(x=>x.role==='flow').startedAt=f.before[0].startedAt,
 'stale unselected generation':f=>f.observed.find(x=>x.role==='auth').startedAt=f.before[0].startedAt,
 'unselected recreation':f=>f.observed.find(x=>x.role==='auth').containerId=hash('unexpected'),
 'foreign selected source':f=>f.observed.find(x=>x.role==='flow').binaryMounts[0].source='/foreign/flow',
 'writable selected bind':f=>f.observed.find(x=>x.role==='flow').binaryMounts[0].writable=true,
 'changed unselected UID':f=>f.observed.find(x=>x.role==='auth').effectiveUid=0,
 'changed selected image':f=>f.observed.find(x=>x.role==='flow').imageId='sha256:'+hash('foreign'),
 'wrong running inode':f=>f.observed.find(x=>x.role==='flow').processExecutableSha256=hash('foreign'),
 'lost role':f=>f.observed.pop(),
 'duplicate container':f=>f.observed[0].containerId=f.observed[1].containerId,
 'forged predecessor Core':f=>f.before.find(x=>x.role==='issuance-native').coreSource='a'.repeat(40),
 'false promoted subset':f=>f.selection.releaseQualified=true,
}))test('refuses '+name,()=>{const f=fixture();change(f);assert.throws(()=>validateGenerations(f.expected,f.before,f.selection,f.observed));});
