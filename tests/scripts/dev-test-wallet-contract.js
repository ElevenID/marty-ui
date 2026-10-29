'use strict';
// Transport assertions only. Rust owns sessions, storage, protocol and signing.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {expiryWindow,awaitNaturalExpiry,GRANT}=require('./beta-membership-support-contract');
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const REQUIRED=['two_session_inventory','wrong_run_denied','own_reset_preserves_other',
 'empty_holder_cannot_present_other','harness_cancel_no_login','fresh_nonce_login_recovery',
 'actual_server_expiry','expired_code_denied','fresh_offer_recovery'];
const SUPPORTED=Object.freeze({inventory:'SUPPORTED',presentation:'SUPPORTED',reset:'SUPPORTED',
 individualCredentialRead:'N/A',individualCredentialDelete:'N/A',holderClickCancel:'N/A',
 harnessFlowCancel:'SUPPORTED',distinctHolderKeys:'N/A_SHARED_FIXTURE_KEY'});
function inventoryIds(rows){
 assert(Array.isArray(rows)&&rows.length<=128,'WALLET_INVENTORY_INVALID');
 const ids=rows.map(row=>row?.id);assert(ids.every(x=>typeof x==='string'&&x.length>0)
  &&new Set(ids).size===ids.length,'WALLET_INVENTORY_INVALID');return ids.sort();
}
async function inventory(holder){
 await holder.session.assertOwned();
 const r=await holder.context.request.get(holder.session.origin+'/api/credentials',{
  headers:{'x-marty-wallet-run-id':holder.session.evidence.runId},timeout:15000,maxRedirects:0});
 assert.equal(r.status(),200,'WALLET_INVENTORY_READ_FAILED');return inventoryIds(await r.json());
}
async function sessionIsolation({a,b,requestUri,readAuth}){
 assert(a.context!==b.context&&a.session!==b.session,'DISTINCT_WALLET_HOLDERS_REQUIRED');
 assert.equal(a.session.origin,b.session.origin);assert.equal(a.session.evidence.instanceId,b.session.evidence.instanceId);
 assert.notEqual(a.session.evidence.sessionId,b.session.evidence.sessionId);
 assert.notEqual(a.session.evidence.runId,b.session.evidence.runId);
 const beforeA=await inventory(a),beforeB=await inventory(b);
 assert.equal(beforeA.length,1,'HOLDER_A_POSITIVE_REQUIRED');assert.equal(beforeB.length,1,'HOLDER_B_POSITIVE_REQUIRED');
 assert.notEqual(beforeA[0],beforeB[0],'DISTINCT_STORED_CREDENTIALS_REQUIRED');
 const headers={'x-marty-wallet-run-id':a.session.evidence.runId},wrongRunStatuses=[];
 for(const [method,route,data] of [['get','/api/credentials'],['post','/api/reset',{}],
  ['post','/api/present',{request_uri:requestUri}]]){
  const r=await b.context.request[method](a.session.origin+route,{headers,data,timeout:15000,maxRedirects:0});
  assert.equal(r.status(),403,'WRONG_RUN_MUST_BE_DENIED');
  wrongRunStatuses.push(r.status());
 }
 assert.deepEqual(await inventory(a),beforeA,'HOLDER_A_INVENTORY_CHANGED');
 assert.deepEqual(await inventory(b),beforeB,'HOLDER_B_INVENTORY_CHANGED');
 await b.session.reset();
 assert.deepEqual(await inventory(b),[],'HOLDER_B_RESET_FAILED');
 assert.deepEqual(await inventory(a),beforeA,'RESET_CHANGED_OTHER_HOLDER');
 const denied=await b.context.request.post(b.session.origin+'/api/present',{
  headers:{'x-marty-wallet-run-id':b.session.evidence.runId},data:{request_uri:requestUri},
  timeout:30000,maxRedirects:0});
 assert.equal(denied.status(),422,'EMPTY_HOLDER_PRESENTATION_NOT_PROVEN');
 assert.equal((await readAuth()).authenticated,false,'DENIAL_CREATED_LOGIN');
 return {two_session_inventory:true,wrong_run_denied:true,own_reset_preserves_other:true,
  empty_holder_cannot_present_other:true,inventoryASha256:digest(beforeA),inventoryBSha256:digest(beforeB),
  afterResetInventoryASha256:digest(await inventory(a)),afterResetInventoryBCount:0,wrongRunStatuses,
  emptyHolderPresentationStatus:denied.status(),denialAuthenticated:false,
  supportedOperations:SUPPORTED,keyBoundary:'SHARED_CONFIGURED_SIGNER_SESSION_ISOLATION_ONLY'};
}
async function cancelOwnedLogin({binding,readInstance,cancel,finalize,readAuth,beforeCancel}){
 const before=await readBoundLoginFlow(binding,readInstance);
 assert(['PENDING','IN_PROGRESS','AWAITING_WALLET'].includes(String(before.status).toUpperCase()),'CANCEL_FLOW_NOT_PENDING');
 assert.equal((await readAuth()).authenticated,false,'CANCEL_REQUIRES_SIGNED_OUT_CONTEXT');
 await beforeCancel();const acknowledgement=await cancel();assert.equal(acknowledgement.ok,true,'FLOW_CANCEL_NOT_ACKNOWLEDGED');
 const after=await readBoundLoginFlow(binding,readInstance);assert.equal(String(after.status).toUpperCase(),'CANCELLED');
 const result=await finalize();assert(!result.setCookie&&![301,302,303,307,308].includes(result.status),'CANCEL_FINALIZED_LOGIN');
 assert.equal((await readAuth()).authenticated,false,'CANCEL_CREATED_LOGIN');
 return {kind:'HARNESS_CANCELS_OWNED_FLOW',harness_cancel_no_login:true,flowInstanceId:binding.instanceId,
  nonceSha256:binding.nonceSha256,terminalStatus:'CANCELLED',holderClickCancel:'N/A'};
}
async function readBoundLoginFlow(binding,readInstance){
 const before=await readInstance();
 assert.equal(before.id,binding.instanceId);assert.equal(before.organization_id,binding.organizationId);
 assert.equal(before.context_data?.presentation_policy_id,binding.presentationPolicyId);
 assert.equal(before.context_data?.trust_profile_id,binding.trustProfileId);
 return before;
}
async function retireLoginFlow({binding,readInstance,cancel,beforeCancel}){
 const before=await readBoundLoginFlow(binding,readInstance),status=String(before.status).toUpperCase();
 if(['COMPLETED','FAILED','CANCELLED','EXPIRED'].includes(status))return {status};
 assert(['PENDING','IN_PROGRESS','AWAITING_WALLET'].includes(status),'FLOW_RETIREMENT_STATE_UNKNOWN');
 await beforeCancel();assert.equal((await cancel()).ok,true,'FLOW_RETIREMENT_NOT_ACKNOWLEDGED');
 const after=await readBoundLoginFlow(binding,readInstance);assert.equal(String(after.status).toUpperCase(),'CANCELLED');
 return {status:'CANCELLED'};
}
function freshLoginRecovery(cancelled,recovered){
 assert.notEqual(recovered.binding.instanceId,cancelled.flowInstanceId,'RECOVERY_REUSED_FLOW');
 assert.notEqual(recovered.binding.nonceSha256,cancelled.nonceSha256,'RECOVERY_REUSED_NONCE');
 assert(recovered.authenticated===true&&recovered.browserFinalizeVerified===true,'FRESH_LOGIN_NOT_VERIFIED');
 return true;
}
async function expiredOffer({issuance,prerequisite,readOffer,exchangeCachedCode,receiveExpired,
 inventoryAfter,noIssuedCredential,now=Date.now,delay}){
 const window=expiryWindow(issuance.transaction,issuance.application,prerequisite,now());
 assert.equal((await readOffer()).status,200,'FRESH_OFFER_POSITIVE_REQUIRED');
 const observed=await awaitNaturalExpiry({window,readOffer,now,...(delay?{delay}:{})});
 const token=await exchangeCachedCode(issuance.offer.grants[GRANT]['pre-authorized_code']);
 assert(token.status===400&&token.error==='invalid_grant','EXPIRED_CODE_NOT_DENIED');
 const receipt=await receiveExpired();assert(receipt.ok===false&&receipt.visibleMessage&&receipt.responseHasError,
  'EXPIRED_OFFER_WALLET_DENIAL_REQUIRED');
 assert.deepEqual(await inventoryAfter(),[],'EXPIRED_OFFER_CREATED_WALLET_CREDENTIAL');
 assert.equal(await noIssuedCredential(),true,'EXPIRED_OFFER_ISSUED_CREDENTIAL');
 return {actual_server_expiry:true,expired_code_denied:true,window,observed,
  tokenDenial:{status:token.status,error:token.error},walletDenial:{httpStatus:receipt.httpStatus,
   ok:false,visibleMessage:receipt.visibleMessage===true,responseHasError:receipt.responseHasError===true},
  inventoryEmpty:true,noIssuedCredential:true};
}
function coreAssertions(report){
 const receipts=report.receipts||[],sessions=report.walletSessions||[],denials=report.closedWalletSessions||[];
 const received=receipts.length===2&&new Set(receipts.map(r=>r.applicationId)).size===2
  &&receipts.every(r=>r.httpStatus===201&&r.ok===true&&r.applicationId&&r.transactionId&&r.credentialId);
 return {governed_claim:received,
  expected_credential_received_and_stored:received&&report.checks?.two_session_inventory===true,
  presentation_authenticated:report.initialLogin?.authenticated===true&&report.initialLogin?.browserFinalizeVerified===true
   &&report.recoveryLogin?.authenticated===true&&report.recoveryLogin?.browserFinalizeVerified===true,
  closed_wallet_session_rejected:sessions.length===2&&denials.length===2
   &&new Set(denials.map(d=>d.sessionId)).size===2
   &&sessions.every(s=>s.closed===true&&denials.some(d=>d.status===410&&d.instanceId===s.instanceId
    &&d.sessionId===s.sessionId&&d.runId===s.runId))};
}
function assertions(report){
 return Object.fromEntries(REQUIRED.map(key=>[key,report.checks?.[key]===true]));
}
module.exports={coreAssertions,REQUIRED,SUPPORTED,assertions,cancelOwnedLogin,expiredOffer,freshLoginRecovery,inventory,inventoryIds,sessionIsolation,retireLoginFlow};
