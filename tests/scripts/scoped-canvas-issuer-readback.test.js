const test=require('node:test'),assert=require('node:assert/strict');
const {projectInventory}=require('./scoped-canvas-issuer-readback');
test('scoped inventory retains only bounded ownership metadata',()=>{
 assert.deepEqual(projectInventory([{id:'job',organization_id:'org',binding_id:'binding',payload:{secret:'never-retain'}}],'org','binding'),
  [{id:'job',organization_id:'org',binding_id:'binding'}]);
});
test('foreign, duplicated and saturated scoped inventories fail closed',()=>{
 const row={id:'job',organization_id:'org',binding_id:'binding'};
 for(const rows of [[{...row,organization_id:'foreign'}],[{...row,binding_id:'foreign'}],[row,row],Array.from({length:500},(_,i)=>({...row,id:String(i)}))])
  assert.throws(()=>projectInventory(rows,'org','binding'));
});
