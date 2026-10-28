'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {ownedVerificationFlow}=require('./owned-verification-flow');
const org='11111111-1111-4111-8111-111111111111';
const runId='22222222-2222-4222-8222-222222222222';
const id='33333333-3333-4333-8333-333333333333';
function fixture(t,{foreign=false,missing=false,initialStatus='PENDING'}={}){
  const privateDirectory=fs.mkdtempSync(path.join(os.tmpdir(),'canvas-owned-flow-'));
  t.after(()=>fs.rmSync(privateDirectory,{recursive:true,force:true}));
  let flow,postCount=0,status=initialStatus;
  const api=async(method,route)=>{
    if(method==='GET'&&route.startsWith('/v1/flows/instances?'))return {ok:true,status:200,
      body:missing?[]:[{id,organization_id:org,metadata:{external_reference:flow.reference}}]};
    if(method==='GET'&&route===`/v1/flows/instances/${id}`)return {ok:true,status:200,
      body:{id,organization_id:org,status,metadata:{external_reference:foreign?'foreign':flow.reference}}};
    if(method==='POST'&&route===`/v1/flows/instances/${id}/cancel`){postCount++;status='CANCELLED';
      return {ok:true,status:200,body:{id,status}};}
    throw Error('Unexpected source-only operation');
  };
  flow=ownedVerificationFlow({organizationId:org,runId,privateDirectory,api});
  return {flow,get postCount(){return postCount;},journal:()=>JSON.parse(fs.readFileSync(flow.journal))};
}
test('wallet failure cancels only the exact run-owned pending Flow and verifies terminal readback',async t=>{
  const f=fixture(t);
  await assert.rejects(f.flow.run(async flow=>{
    flow.beforeCreate({organization_id:org,external_reference:flow.reference});
    assert.equal(f.journal().createIntent,true);
    await flow.acknowledge({ok:true,instanceId:id});
    throw Error('CONTROLLED_WALLET_400');
  }),/CONTROLLED_WALLET_400/);
  assert.equal(f.postCount,1);assert.equal(f.flow.terminalStatus,'CANCELLED');
  assert.equal(f.journal().retirementConfirmed,true);
});
test('canonical lifecycle verify hook retires its created Flow when wallet transport fails',async t=>{
  const f=fixture(t);
  const {verify}=require('./audit-beta-credential-lifecycle');
  const page={evaluate:async()=>({ok:true,status:200,instanceId:id,
    requestUri:'openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test%2Frequest'})};
  const result=await f.flow.run(()=>verify(page,{},f.flow.reference,{
    organizationId:org,presentationPolicyId:'44444444-4444-4444-8444-444444444444',
    issuerDid:'did:web:example.test',flowCustody:f.flow,returnOnWalletFailure:true}));
  assert.equal(result.diagnostic.outcome,'TRANSPORT_FAILED');
  assert.equal(f.postCount,1);assert.equal(f.flow.terminalStatus,'CANCELLED');
});
test('lost create response with no matching row remains ambiguous and cannot claim cleanup',async t=>{
  const f=fixture(t,{missing:true});
  await assert.rejects(f.flow.run(async flow=>{
    flow.beforeCreate({organization_id:org,external_reference:flow.reference});
    flow.noteLostResponse();throw Error('CONTROLLED_TRANSPORT_LOSS');
  }),error=>error.code==='OWNED_FLOW_CLEANUP_UNCONFIRMED'
    &&error.cause?.code==='OWNED_FLOW_CREATE_AMBIGUOUS');
  assert.equal(f.postCount,0);assert.equal(f.journal().retirementConfirmed,false);
});
test('acknowledged instance absent from complete list remains unresolved',async t=>{
  const f=fixture(t,{missing:true});
  await assert.rejects(f.flow.run(async flow=>{
    flow.beforeCreate({organization_id:org,external_reference:flow.reference});
    await flow.acknowledge({ok:true,instanceId:id});
  }),error=>error.code==='OWNED_FLOW_CLEANUP_UNCONFIRMED'
    &&error.cause?.code==='OWNED_FLOW_CREATE_AMBIGUOUS');
  assert.equal(f.journal().retirementConfirmed,false);
});
test('foreign instance tuple refuses cancellation and retains the custody journal',async t=>{
  const f=fixture(t,{foreign:true});
  await assert.rejects(f.flow.run(async flow=>{
    flow.beforeCreate({organization_id:org,external_reference:flow.reference});
    await flow.acknowledge({ok:true,instanceId:id});
  }),error=>error.code==='OWNED_FLOW_CLEANUP_UNCONFIRMED');
  assert.equal(f.postCount,0);assert.equal(f.journal().state,'CUSTODY_UNRESOLVED');
});
test('unknown public Flow status cannot trigger cancellation or cleanup success',async t=>{
  const f=fixture(t,{initialStatus:'VERIFIED'});
  await assert.rejects(f.flow.run(async flow=>{
    flow.beforeCreate({organization_id:org,external_reference:flow.reference});
    await flow.acknowledge({ok:true,instanceId:id});
  }),error=>error.code==='OWNED_FLOW_CLEANUP_UNCONFIRMED');
  assert.equal(f.postCount,0);assert.equal(f.journal().retirementConfirmed,false);
});
