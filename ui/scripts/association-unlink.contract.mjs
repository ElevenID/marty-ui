// SPDX-License-Identifier: AGPL-3.0-only
// Native Node transport/storage unit contract; does not qualify a mounted browser.
import {test,afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {createAssociationConsentClient} from '../src/services/associationConsent.js';
const originalFetch=globalThis.fetch,originalWindow=globalThis.window;
const org='10000000-0000-4000-8000-000000000001',challenge='20000000-0000-4000-8000-000000000002';
const identity='30000000-0000-4000-8000-000000000003',otherChallenge='40000000-0000-4000-8000-000000000004';
const key=revision=>`elevenid.association-unlink.v1:${org}:${identity}:${revision}`;
const principal=user=>({authenticated:true,user:{user_id:user??'learner-one'}});
const current=(revision=2,active=false,selectedChallenge=challenge)=>({kind:'current',record:{
 challenge_id:selectedChallenge,source_id:'source-one',binding_id:'binding-one',revision:2,phase:'confirmed',current:active,
 expired:false,expires_at_ms:Date.now()+120000,application_id:'application-one',subject_id:'canonical-subject',
 identity:{identity_id:identity,revision,active},can_relink:false}});
const response=value=>new Response(JSON.stringify(value),{status:200,headers:{'content-type':'application/json','cache-control':'no-store'}});
function fixture() {
 const storage=new Map(),calls=[],steps=[];
 globalThis.window={sessionStorage:{getItem:key=>storage.get(key)??null,setItem:(key,value)=>storage.set(key,value)}};
 globalThis.fetch=async(path,options)=>{calls.push({path,options});assert.ok(steps.length,'unexpected transport');return steps.shift()(path,options);};
 return {storage,calls,queue:(...values)=>steps.push(...values.map(value=>typeof value==='function'?value:async()=>response(value))),
  client:createAssociationConsentClient({organizationId:org,challengeId:challenge})};
}
afterEach(()=>{globalThis.fetch=originalFetch;if(originalWindow===undefined)delete globalThis.window;else globalThis.window=originalWindow;});
function receipt(f,revision=1){const i=JSON.parse(f.storage.get(key(revision)));return {operation_id:i.operationId,identity_id:identity,action:'unlink',revision:revision+1,active:false};}
test('unlink persists exact original metadata before one session write and separately checks current identity',async()=>{
 const f=fixture();f.queue(principal(),async(path,options)=>{
  assert.equal(path,`/v1/organizations/${org}/external-associations/${identity}/unlink`);
  const i=JSON.parse(f.storage.get(key(1)));assert.equal(i.userId,'learner-one');assert.equal(i.challengeId,challenge);
  assert.deepEqual(JSON.parse(options.body),{operation_id:i.operationId,expected_revision:1});return response(receipt(f));
 },current(),principal());
 const result=await f.client.unlink(identity,1,'learner-one');assert.equal(result.record.identity.active,false);
 assert.equal(f.storage.size,1);assert.equal(f.calls.length,4);assert.equal(f.client.hasUnlinkRecovery(identity,1),true);
 for(const {options} of f.calls){assert.equal(options.credentials,'same-origin');assert.equal(options.redirect,'error');assert.equal(options.referrerPolicy,'no-referrer');}
 const count=f.calls.length;await assert.rejects(f.client.unlink(identity,1,'learner-one'),{code:'recovery_required'});assert.equal(f.calls.length,count);
});
test('lost unlink reply recovers the original operation from another challenge without another write',async()=>{
 const f=fixture();f.queue(principal(),async()=>{throw Error('synthetic lost reply');});
 await assert.rejects(f.client.unlink(identity,1,'learner-one'),{code:'commit_unknown'});
 const original=JSON.parse(f.storage.get(key(1))),client=createAssociationConsentClient({organizationId:org,challengeId:otherChallenge});
 f.queue(principal(),{kind:'receipt',receipt:receipt(f)},current(3,true,otherChallenge),principal());
 const result=await client.recoverUnlink(identity,1);
 assert.equal(result.receipt.active,false);assert.equal(result.record.identity.active,true);assert.equal(result.record.identity.revision,3);
 assert.equal(result.receipt.operation_id,original.operationId);
 assert.deepEqual(JSON.parse(f.calls[3].options.body),{operation_id:original.operationId});
 assert.equal(f.calls.filter(c=>c.path.endsWith('/unlink')).length,1);
});
test('a switched reviewed actor cannot persist or dispatch unlink; recovery also requires the original actor',async()=>{
 const f=fixture();f.queue(principal('other-user'));await assert.rejects(f.client.unlink(identity,1,'learner-one'),{code:'authentication_required'});
 assert.equal(f.storage.size,0);assert.equal(f.calls.length,1);
 f.queue(principal(),async()=>{throw Error('lost');});await assert.rejects(f.client.unlink(identity,1,'learner-one'),{code:'commit_unknown'});
 const before=f.calls.length;f.queue(principal('other-user'));await assert.rejects(f.client.recoverUnlink(identity,1),{code:'authentication_required'});
 assert.equal(f.calls.length,before+1);
});
test('later explicit unlink after a fresh relink uses a distinct revision journal while preserving old history',async()=>{
 const f=fixture();f.queue(principal(),async()=>response(receipt(f)),current(),principal());await f.client.unlink(identity,1,'learner-one');
 const old=f.storage.get(key(1));f.queue(principal(),async()=>response(receipt(f,3)),current(4),principal());
 await f.client.unlink(identity,3,'learner-one');assert.equal(f.storage.size,2);assert.equal(f.storage.get(key(1)),old);
 assert.notEqual(JSON.parse(f.storage.get(key(1))).operationId,JSON.parse(f.storage.get(key(3))).operationId);
 const count=f.calls.length;await assert.rejects(f.client.unlink(identity,Number.MAX_SAFE_INTEGER,'learner-one'),{code:'invalid_request'});assert.equal(f.calls.length,count);
});
test('wrong receipt or current identity yields uncertainty while the original journal remains intact',async()=>{
 for(const scenario of ['receipt','identity','actor']) {
  const f=fixture();f.queue(principal(),async()=>response({...receipt(f),...scenario==='receipt'?{identity_id:otherChallenge}:{}}));
  if(scenario!=='receipt') {
   const view=current();if(scenario==='identity')view.record.identity.identity_id=otherChallenge;
   f.queue(view,principal(scenario==='actor'?'other-user':'learner-one'));
  }
  await assert.rejects(f.client.unlink(identity,1,'learner-one'),{code:'commit_unknown'});assert.equal(f.storage.size,1);
 }
});
test('existing confirmation keeps its reviewed-actor and original receipt contract',async()=>{
 const f=fixture(),code='A'.repeat(43);f.queue(principal(),async(_path,options)=>{
  const body=JSON.parse(options.body);assert.equal(body.code,code);
  return response({operation_id:body.operation_id,challenge_id:challenge,action:'confirm',revision:2,phase:'confirmed'});
 },current(1,true),principal());
 const result=await f.client.act('confirm',code,1,null,'learner-one');assert.equal(result.record.current,true);
 assert.ok([...f.storage.values()].every(value=>!value.includes(code)));
});
