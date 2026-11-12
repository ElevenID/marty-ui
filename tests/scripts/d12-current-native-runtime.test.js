'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const runtime=require('./functional-debug-runtime'),reader=require('./d12-current-native-runtime');
const roles=['flow','gateway','issuance-native',...Array.from({length:19},(_,i)=>'retained-'+i)];
const selected=reader.ROLES,hash='a'.repeat(64),next='b'.repeat(64);
function fixture(current10=false){
 const selected=current10?reader.CURRENT10.roles:reader.ROLES;
 const roles=current10?[...Object.keys(selected),...Array.from({length:12},(_,i)=>"retained-"+i)]:["flow","gateway","issuance-native",...Array.from({length:19},(_,i)=>"retained-"+i)];
 const before={roles:roles.map((role,i)=>({role,binary:selected[role]||'marty-'+role,project:'elevenid-beta',
  containerId:(i+1).toString(16).padStart(64,'0'),imageId:'sha256:'+hash,
  startedAt:'2026-10-01T00:00:00Z',hostPid:i+1,health:'healthy',
  effectiveUid:10001,configuredRuntimeUid:10001,source:'old',coreSource:'old',kind:'native',
  sha256:hash,processExecutableSha256:hash,binaryMounts:[{type:'bind',source:'/old/'+(selected[role]||'marty-'+role),
   destination:'/usr/local/bin/'+(selected[role]||'marty-'+role),writable:false}]}))};
 const selection={profile:current10?reader.CURRENT10.profile:'d12-passport-current-functional',state:'SELECTED_NOT_DEPLOYED',
  sourceRevision:current10?reader.CURRENT10.source:reader.SOURCE,coreRevision:current10?reader.CURRENT10.core:reader.CORE,roleBinaries:selected,
  binaries:Object.fromEntries(Object.entries(selected).map(([role,binary])=>[role,{sha256:next,path:'/owned/'+binary}])),
  scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false};
 return {before,selection};
}
function invoke(edit,current10=false){
 const selected=current10?reader.CURRENT10.roles:reader.ROLES;
 const {before,selection}=fixture(current10),oldJson=runtime.boundJson,oldObserve=runtime.observeDocker;
 const runId='00000000-0000-4000-8000-000000000001';
 const created={runId,roles:before.roles.map(prior=>({role:prior.role,imageId:prior.imageId,
  containerId:selected[prior.role]?'c'.repeat(63)+(Object.keys(selected).indexOf(prior.role)+1).toString(16):prior.containerId,
  state:selected[prior.role]?'created':'exited',hostPid:0}))};
 const startAcks={runId,acks:Object.fromEntries(created.roles.map(row=>[row.role,{containerId:row.containerId,
  imageId:row.imageId,startedAt:'2026-10-02T00:00:00Z',hostPid:42}]))};
 try{
  runtime.boundJson=ref=>ref.value;
  runtime.observeDocker=prior=>{
   const isSelected=!!selected[prior.role],binary=selected[prior.role];
   const row={role:prior.role,service:prior.role,project:prior.project,imageId:prior.imageId,running:true,status:'running',health:'healthy',
    containerId:isSelected?'c'.repeat(63)+(Object.keys(selected).indexOf(prior.role)+1).toString(16):prior.containerId,
    startedAt:'2026-10-02T00:00:00Z',hostPid:42,
    effectiveUid:10001,configuredRuntimeUid:10001,
    binarySha256:isSelected?next:hash,processExecutableSha256:isSelected?next:hash,
    executablePath:'/usr/local/bin/'+prior.binary,
    binaryMounts:isSelected?[{type:'bind',source:'/owned/'+binary,destination:'/usr/local/bin/'+binary,writable:false}]:prior.binaryMounts};
   return edit?edit(prior,row):row;
  };
  return reader.observe({before:{value:before},selection:{value:selection},created:{value:created},
    startAcks:{value:startAcks},runId,engineId:'engine'},
    {readDocker:()=>JSON.stringify({ID:'engine'})});
 }finally{runtime.boundJson=oldJson;runtime.observeDocker=oldObserve;}
}
test('current D12 actual reader retains 19 roles and requires three fresh exact binaries',()=>{
 const result=invoke();assert.equal(result.roles.length,22);assert.equal(result.functionalReady,false);
 assert.equal(result.roles.filter(x=>x.source===reader.SOURCE).length,3);
});
test('same selected container or wrong mounted binary never becomes fresh runtime proof',()=>{
 assert.throws(()=>invoke((prior,row)=>prior.role==='flow'?{...row,containerId:prior.containerId}:row));
 assert.throws(()=>invoke((prior,row)=>prior.role==='flow'?{...row,containerId:'d'.repeat(64)}:row));
 assert.throws(()=>invoke((prior,row)=>prior.role==='flow'?{...row,binarySha256:hash}:row));
});
test('unexpected same-container restart generation or process refuses',()=>{
 assert.throws(()=>invoke((prior,row)=>prior.role==='flow'?{...row,startedAt:'2026-10-03T00:00:00Z'}:row));
 assert.throws(()=>invoke((prior,row)=>prior.role==='flow'?{...row,hostPid:43}:row));
});

test('closed current10 observes native Auth generation and retains twelve unselected roles',()=>{
 const result=invoke(undefined,true);
 assert.equal(result.roles.filter(x=>x.source===reader.CURRENT10.source).length,10);
 assert.equal(result.roles.filter(x=>x.source==='old').length,12);
 for(const edit of [(p,r)=>p.role==='auth'?{...r,hostPid:43}:r,
                    (p,r)=>p.role==='auth'?{...r,binarySha256:hash}:r,
                    (p,r)=>p.role==='auth'?{...r,containerId:p.containerId}:r]){
  assert.throws(()=>invoke(edit,true));
 }
});
