'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {sessionIsolation,cancelOwnedLogin,expiredOffer,freshLoginRecovery,assertions,SUPPORTED,retireLoginFlow}=require('./dev-test-wallet-contract');
function holders({leak=false,resetOther=false,allowWrong=false,allowEmpty=false}={}){
 const data={a:['credential-a'],b:['credential-b']};
 function holder(id){const row={session:{origin:'http://127.0.0.1:8790',evidence:{runId:id,sessionId:id,instanceId:'same-owned-instance'},assertOwned:async()=>{}}};
  const request=async(method,url,o)=>{const wrong=o.headers['x-marty-wallet-run-id']!==id;
   let status=wrong&&!allowWrong?403:200;
   if(url.endsWith('/api/reset')&&!wrong){data[resetOther?'a':id]=[];status=204;}
   if(url.endsWith('/api/present')&&!wrong)status=data[id].length||allowEmpty?200:422;
   return {status:()=>status,json:async()=>[...(leak?data.a:data[id])].map(id=>({id}))};};
  row.context={request:{get:(u,o)=>request('GET',u,o),post:(u,o)=>request('POST',u,o)}};
  row.session.reset=()=>request('POST','/api/reset',{headers:{'x-marty-wallet-run-id':id}});return row;
 }return {a:holder('a'),b:holder('b')};
}
test('actual transport ownership sequence requires own positives and own-only reset; unsupported APIs stay N/A',async()=>{
 const f=holders(),r=await sessionIsolation({...f,requestUri:'PRIVATE_REQUEST',readAuth:async()=>({authenticated:false})});
 assert.equal(r.wrong_run_denied,true);assert.equal(r.own_reset_preserves_other,true);
 assert.equal(SUPPORTED.individualCredentialDelete,'N/A');assert.equal(SUPPORTED.holderClickCancel,'N/A');
 assert.equal(SUPPORTED.distinctHolderKeys,'N/A_SHARED_FIXTURE_KEY');
});
test('leaked inventory, wrong-run acceptance, cross-reset, empty-holder presentation and login cannot pass',async()=>{
 for(const edit of [{leak:true},{allowWrong:true},{resetOther:true},{allowEmpty:true}])
  await assert.rejects(sessionIsolation({...holders(edit),requestUri:'PRIVATE_REQUEST',readAuth:async()=>({authenticated:false})}));
 await assert.rejects(sessionIsolation({...holders(),requestUri:'PRIVATE_REQUEST',readAuth:async()=>({authenticated:true})}));
});
function cancelFixture(edit={}){
 const calls=[],binding={instanceId:'flow-owned',organizationId:'org',presentationPolicyId:'policy',trustProfileId:'trust',nonceSha256:'a'.repeat(64)};
 let cancelled=false;
 return {calls,binding,readInstance:async()=>({id:edit.foreign?'foreign':binding.instanceId,organization_id:'org',
  context_data:{presentation_policy_id:'policy',trust_profile_id:'trust'},status:cancelled?'CANCELLED':'AWAITING_WALLET'}),
  beforeCancel:async()=>calls.push('intent'),cancel:async()=>{calls.push('cancel');cancelled=true;return {ok:!edit.noAck};},
  finalize:async()=>({status:edit.redirect?302:400,setCookie:!!edit.cookie}),readAuth:async()=>({authenticated:!!edit.login})};
}
test('harness cancellation is exact-owned/intent-first and never claims a holder UI button',async()=>{
 const f=cancelFixture(),r=await cancelOwnedLogin(f);assert.deepEqual(f.calls,['intent','cancel']);
 assert.equal(r.kind,'HARNESS_CANCELS_OWNED_FLOW');assert.equal(r.holderClickCancel,'N/A');
 assert.equal(freshLoginRecovery(r,{binding:{instanceId:'new-flow',nonceSha256:'b'.repeat(64)},authenticated:true,browserFinalizeVerified:true}),true);
 for(const binding of [{instanceId:r.flowInstanceId,nonceSha256:'b'.repeat(64)},
  {instanceId:'new-flow',nonceSha256:r.nonceSha256}])assert.throws(()=>freshLoginRecovery(r,{binding,authenticated:true,browserFinalizeVerified:true}));
});
test('foreign ownership, unknown cancel ACK, cookie, redirect or unexpected login fail closed',async()=>{
 for(const edit of [{foreign:true},{noAck:true},{cookie:true},{redirect:true},{login:true}]){
  const f=cancelFixture(edit);await assert.rejects(cancelOwnedLogin(f));if(edit.foreign||edit.login)assert.deepEqual(f.calls,[]);
 }
});
test('cleanup reconciles only the bound login Flow and records intent before cancellation',async()=>{
 const f=cancelFixture();assert.deepEqual(await retireLoginFlow(f),{status:'CANCELLED'});
 assert.deepEqual(f.calls,['intent','cancel']);
 for(const edit of [{foreign:true},{noAck:true}])await assert.rejects(retireLoginFlow(cancelFixture(edit)));
 const done=cancelFixture();done.readInstance=async()=>({id:'flow-owned',organization_id:'org',
  context_data:{presentation_policy_id:'policy',trust_profile_id:'trust'},status:'COMPLETED'});
 assert.deepEqual(await retireLoginFlow(done),{status:'COMPLETED'});assert.deepEqual(done.calls,[]);
});
function expiryFixture(edit={}){
 let now=Date.parse('2026-10-28T00:00:30Z');const start=now,calls=[];
 const offer={'urn:ietf:params:oauth:grant-type:pre-authorized_code':{'pre-authorized_code':'PRIVATE_CODE'}};
 return {calls,issuance:{transaction:{created_at:'2026-10-28T00:00:00Z',expires_at:'2026-10-28T00:01:00Z'},
  application:{offer_expires_at:'2026-10-28T00:01:00Z'},offer:{grants:offer}},
  prerequisite:{isolatedDeployment:true,expectedServerOfferTtlSeconds:edit.wrongTtl?120:60,maximumWaitSeconds:90},
  now:()=>now,delay:async ms=>{now+=ms;},readOffer:async()=>({status:now===start?200:now>start+30000&&!edit.neverExpires?410:200}),
  exchangeCachedCode:async()=>{calls.push('token');return {status:400,error:edit.wrongError?'other':'invalid_grant'};},
  receiveExpired:async()=>({ok:false,visibleMessage:true,responseHasError:true}),
  inventoryAfter:async()=>edit.created?['unexpected']:[],noIssuedCredential:async()=>!edit.issued};
}
test('expiry reuses natural server 200-to-410 and invalid-grant observations, never close-session substitute',async()=>{
 const f=expiryFixture(),r=await expiredOffer(f);assert.equal(r.actual_server_expiry,true);assert.equal(r.expired_code_denied,true);
 assert.deepEqual(f.calls,['token']);
});
test('TTL mismatch, timeout, wrong denial or issued credential never qualify expiry',async()=>{
 for(const edit of [{wrongTtl:true},{neverExpires:true},{wrongError:true},{created:true},{issued:true}]){
  const f=expiryFixture(edit);await assert.rejects(expiredOffer(f));
  if(edit.wrongTtl||edit.neverExpires)assert.deepEqual(f.calls,[]);
 }
});
test('missing or truthy invented outcomes never become contract passes',()=>{
 assert(Object.values(assertions({checks:{actual_server_expiry:'passed',harness_cancel_no_login:1}})).every(v=>v===false));
});

test('four existing manifest assertions require both real receipts and both independent post-close410 observations',()=>{
 const {coreAssertions}=require('./dev-test-wallet-contract');
 const report={receipts:['a','b'].map(id=>({applicationId:id,transactionId:'tx-'+id,credentialId:'credential-'+id,httpStatus:201,ok:true})),
 checks:{two_session_inventory:true},initialLogin:{authenticated:true,browserFinalizeVerified:true},recoveryLogin:{authenticated:true,browserFinalizeVerified:true},
 walletSessions:['a','b'].map(id=>({instanceId:'owned',sessionId:id,runId:id,closed:true})),
 closedWalletSessions:['a','b'].map(id=>({instanceId:'owned',sessionId:id,runId:id,status:410}))};
 assert(Object.values(coreAssertions(report)).every(v=>v===true));
 for(const mutate of [r=>r.receipts[1].applicationId='a',r=>r.receipts[0].httpStatus=200,r=>r.closedWalletSessions.pop(),
 r=>r.closedWalletSessions[1].sessionId='a',r=>r.closedWalletSessions[1].status=200,r=>r.recoveryLogin.authenticated=false]){
  const changed=structuredClone(report);mutate(changed);assert(Object.values(coreAssertions(changed)).some(v=>v===false));
 }
});
