'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {requireProviderInvalidSecret,requireMartyInvalidSecret,planWrongSecretCase,runWrongSecretCase,retireCanvasSession,requireOwnedMartyResource,assertCanvasLoginIdentity}=require('./audit-beta-canvas-invalid-secret');
const valid={status:401,error:'invalid_client',description:'invalid client',issuedCode:true,clientEnabled:true,clientId:'100',issuedClientId:'100'};
test('only enabled same-client issued-code credential error counts',()=>{assert.equal(requireProviderInvalidSecret(valid).validEnabledClient,true)});
for(const patch of [{description:'unknown client'},{description:undefined},{error:'invalid_grant'},{error:'access_denied'},{error:'unknown_client'},{status:500},{status:200},{issuedCode:false},{clientEnabled:false},{issuedClientId:'101'}])test('reject confounded denial '+JSON.stringify(patch),()=>{assert.throws(()=>requireProviderInvalidSecret({...valid,...patch}));});
test('typed Marty failure is insufficient without independent provider credential denial',()=>{const url=new URL('https://beta.elevenidllc.com/console/org/integrations/canvas?platform_id=owned&outcome=error&error_code=oauth_token_exchange_failed');assert.throws(()=>requireMartyInvalidSecret(url,'owned',{codeIssuedForSameClient:true,providerInvalidSecret:false}));assert.equal(requireMartyInvalidSecret(url,'owned',{codeIssuedForSameClient:true,providerInvalidSecret:true}).errorCode,'oauth_token_exchange_failed');});
test('bad-state and different-platform failures never stand in for bad secret',()=>{for(const [error,id]of [['oauth_state_invalid','owned'],['oauth_token_exchange_failed','foreign']]){const u=new URL('https://beta.elevenidllc.com/?platform_id='+id+'&outcome=error&error_code='+error);assert.throws(()=>requireMartyInvalidSecret(u,'owned',{codeIssuedForSameClient:true,providerInvalidSecret:true}));}});
test('plan creates no resources and cannot label qualified',()=>{const p=planWrongSecretCase();assert.equal(p.executionStarted,false);assert.equal(p.releaseQualified,false);assert.equal(p.recordingQualified,false);});
test('untrusted input exception text is never surfaced',async()=>{const secret='NEVER-LOG-CANVAS-SECRET';const credentials={get email(){throw Error(secret)}};await assert.rejects(runWrongSecretCase({canvasCredentials:credentials}),error=>!error.message.includes(secret));});

test('Canvas cleanup uses supported DELETE and verifies the original cookie after reinjection',async()=>{
 const events=[],cookies=[{name:'_csrf_token',value:'encoded%2Bcsrf'},{name:'_canvas_session',value:'owned-secret'}];
 const context={cookies:async()=>cookies,addCookies:async actual=>{assert.deepEqual(actual,cookies);events.push('reinjected')},request:{
  delete:async(url,options)=>{assert.equal(url,'https://canvas-test.elevenidllc.com/logout');assert.equal(options.headers['X-CSRF-Token'],'encoded+csrf');events.push('delete');return {status:()=>302}},
  get:async(url,options)=>{assert.equal(options.maxRedirects,0);assert.equal(options.headers.Accept,'application/json');events.push('old-cookie-probe');return {status:()=>401}}}};
 assert.equal(await retireCanvasSession(context,()=>{}),true);assert.deepEqual(events,['delete','reinjected','old-cookie-probe']);
});
test('Canvas successful profile read never counts as logout',async()=>{const context={cookies:async()=>[{name:'_csrf_token',value:'csrf'}],addCookies:async()=>{},request:{delete:async()=>({status:()=>302}),get:async()=>({status:()=>200})}};await assert.rejects(retireCanvasSession(context,()=>{}),/remains authorized/);});

test('resource retirement refuses changed identity, foreign organization and ambiguous inventory before DELETE',async()=>{
 const row={collection:'/v1/integrations/canvas/integration-secrets',id:'owned',name:'owned-name',state:'CREATED'};
 const value={id:'owned',name:'owned-name',organization_id:'org',provider:'canvas',purpose:'oauth_client_secret'};
 for(const payload of [[{...value,name:'renamed'}],[{...value,organization_id:'foreign'}],[value,value],[]]){
  const calls=[];await assert.rejects(requireOwnedMartyResource(async(path,options)=>{calls.push(options.method||'GET');return {status:200,payload}}, {},row,'org'));
  assert.deepEqual(calls,['GET']);
 }
 assert.equal((await requireOwnedMartyResource(async()=>({status:200,payload:[value]}),{},row,'org')).id,'owned');
});

test('stock self-profile must confirm the actual configured admin identity',()=>{
 assert.equal(assertCanvasLoginIdentity({id:12,primary_email:'admin@governed.org'},'admin@governed.org'),true);
 assert.equal(assertCanvasLoginIdentity({id:12,login_id:'Admin@Governed.org'},'admin@governed.org'),true);
 for(const profile of [{id:12},{id:12,primary_email:'other@governed.org'},{primary_email:'admin@governed.org'}])assert.throws(()=>assertCanvasLoginIdentity(profile,'admin@governed.org'));
});
