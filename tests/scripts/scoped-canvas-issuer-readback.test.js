const test=require('node:test'),assert=require('node:assert/strict');
const {projectInventory,validateTransitionConfig}=require('./scoped-canvas-issuer-readback');
test('scoped inventory retains only bounded ownership metadata',()=>{
 assert.deepEqual(projectInventory([{id:'job',organization_id:'org',binding_id:'binding',payload:{secret:'never-retain'}}],'org','binding'),
  [{id:'job',organization_id:'org',binding_id:'binding'}]);
});
test('foreign, duplicated and saturated scoped inventories fail closed',()=>{
 const row={id:'job',organization_id:'org',binding_id:'binding'};
 for(const rows of [[{...row,organization_id:'foreign'}],[{...row,binding_id:'foreign'}],[row,row],Array.from({length:500},(_,i)=>({...row,id:String(i)}))])
  assert.throws(()=>projectInventory(rows,'org','binding'));
});

test('transition config compares objects semantically and mounts by unique destination',()=>{
 const saved={Name:'native',Config:{Env:['A=1'],User:'10001'},HostConfig:{ReadonlyRootfs:false},Mounts:[
  {Destination:'/a',Source:'a',RW:false},{Destination:'/b',Source:'b',RW:false}]};
 const actual={...saved,Config:{User:'10001',Env:['A=1']},Mounts:[...saved.Mounts].reverse()};
 assert.doesNotThrow(()=>validateTransitionConfig(actual,saved));
 assert.throws(()=>validateTransitionConfig({...actual,Mounts:[saved.Mounts[0],saved.Mounts[0]]},saved),/DESTINATION_DUPLICATE/);
 for(const changed of [{...saved.Mounts[0],RW:true},{...saved.Mounts[0],Source:'foreign'}])
  assert.throws(()=>validateTransitionConfig({...actual,Mounts:[changed,saved.Mounts[1]]},saved),/TRANSITION_CONFIG_CHANGED/);
 assert.throws(()=>validateTransitionConfig({...actual,Config:{...saved.Config,User:'0'}},saved),/TRANSITION_CONFIG_CHANGED/);
});
