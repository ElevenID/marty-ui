'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {freshExactAncillaryRead}=require('./functional-debug-runtime');
const hex=n=>n.toString(16).padStart(64,'0');
function fixture(){
 const allRunningRoles={};for(let i=1;i<=26;i++)allRunningRoles['role-'+i]={id:hex(i)};
 allRunningRoles.keycloak={id:hex(27)};
 const authority={cap:{allRunningRoles},kc:{newCid:hex(28)},ui:{newCid:hex(29)}};
 const ids=[...Array.from({length:26},(_,i)=>hex(i+1)),hex(28),hex(29)];
 let generation=1,batches=0,other=0;
 const read=args=>{
  if(args[0]==='inspect'){
   assert.equal(args.length,29,'exact 28-row Docker batch');batches++;
   return JSON.stringify(ids.map(Id=>({Id,State:{Pid:generation}})));
  }
  other++;return 'actual-other-command';
 };
 return {authority,ids,read,get batches(){return batches;},get other(){return other;},next(){generation++;}};
}
test('exact full-CID 28-row snapshot is served only within one guard',()=>{
 const f=fixture(),read=freshExactAncillaryRead(f.read,f.authority);
 assert.equal(read(['ps','-q']),'actual-other-command');
 assert.equal(JSON.parse(read(['inspect',f.ids[0]]))[0].Id,f.ids[0]);
 assert.equal(JSON.parse(read(['inspect',f.ids.at(-1)]))[0].Id,f.ids.at(-1));
 assert.equal(f.batches,1);assert.equal(f.other,1);
 assert.throws(()=>read(['inspect',hex(27)]),/RESOURCE_BATCH_UNEXPECTED_INSPECT/);
 assert.throws(()=>read(['inspect',f.ids[0],f.ids[1]]),/RESOURCE_BATCH_UNEXPECTED_INSPECT/);
});
for(const kind of ['missing','duplicate','foreign','recreatedKeycloak'])test(kind+' exact Docker batch is refused',()=>{
 const f=fixture();
 const read=args=>{
  if(args[0]!=='inspect')return 'other';
  const rows=f.ids.map(Id=>({Id}));
  if(kind==='missing')rows.pop();
  if(kind==='duplicate')rows[1]={Id:rows[0].Id};
  if(kind==='foreign')rows[1]={Id:hex(900)};
  if(kind==='recreatedKeycloak')rows[26]={Id:hex(27)};
  return JSON.stringify(rows);
 };
 assert.throws(()=>freshExactAncillaryRead(read,f.authority)(['inspect',f.ids[0]]),/RESOURCE_BATCH_/);
});
test('second ancillary guard gets a genuinely fresh snapshot',()=>{
 const f=fixture();
 const first=freshExactAncillaryRead(f.read,f.authority);
 assert.equal(JSON.parse(first(['inspect',f.ids[0]]))[0].State.Pid,1);
 f.next();
 assert.equal(JSON.parse(first(['inspect',f.ids[0]]))[0].State.Pid,1);
 const second=freshExactAncillaryRead(f.read,f.authority);
 assert.equal(JSON.parse(second(['inspect',f.ids[0]]))[0].State.Pid,2);
 assert.equal(f.batches,2);
});
test('native transport four-megabyte response bound remains fail closed',()=>{
 const f=fixture(),read=freshExactAncillaryRead(()=> ' '.repeat(4*1024*1024+1),f.authority);
 assert.throws(()=>read(['inspect',f.ids[0]]),/RESOURCE_BATCH_OUTPUT_BOUNDS/);
});
