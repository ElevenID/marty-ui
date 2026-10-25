const test=require('node:test'),assert=require('node:assert/strict');
const {listResources,requireActiveComplianceProfile}=require('./beta-demo-resource-helpers');

test('resource discovery reads beyond the first page before selecting owned names',async()=>{
 const items=Array.from({length:101},(_,i)=>({id:'resource-'+i,name:i===100?'target':'other'}));
 const offsets=[];const page={evaluate:async(_fn,{requestPath})=>{
  const q=new URL(requestPath,'https://fixture.invalid').searchParams;const offset=Number(q.get('offset'));offsets.push(offset);
  assert.equal(q.get('organization_id'),'org-one');assert.equal(q.get('limit'),'100');
  return {ok:true,status:200,body:items.slice(offset,offset+100)};
 }};
 const result=await listResources(page,'/v1/credential-templates','org-one');
 assert.equal(result.find(x=>x.name==='target').id,'resource-100');assert.deepEqual(offsets,[0,100]);
});
test('ignored offsets or malformed identities cannot masquerade as complete discovery',async()=>{
 const items=Array.from({length:100},(_,i)=>({id:'resource-'+i}));
 const page={evaluate:async()=>({ok:true,status:200,body:items})};
 await assert.rejects(listResources(page,'/v1/credential-templates','org-one'),/duplicate/);
});
test('inactive, hidden and foreign compliance profiles fail before setup mutations',async()=>{
 const good={id:'profile-one',organization_id:'org-one',status:'ACTIVE',discoverable:true};
 for(const change of [{status:'DRAFT'},{discoverable:false},{organization_id:'foreign'}]){
  const page={evaluate:async(_fn,{requestPath,requestOptions})=>{
   assert.equal(requestPath,'/v1/compliance-profiles/profile-one');assert.equal(requestOptions.method,undefined);
   return {ok:true,status:200,body:{...good,...change}};
  }};
  await assert.rejects(requireActiveComplianceProfile(page,{profileId:'profile-one',organizationId:'org-one'}));
 }
 const page={evaluate:async()=>({ok:true,status:200,body:good})};
 assert.deepEqual(await requireActiveComplianceProfile(page,{profileId:'profile-one',organizationId:'org-one'}),good);
});
