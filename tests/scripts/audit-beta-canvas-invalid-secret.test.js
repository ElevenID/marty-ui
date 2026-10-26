'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {requireProviderInvalidSecret,requireMartyInvalidSecret,planWrongSecretCase,runWrongSecretCase,retireCanvasSession,requireOwnedMartyResource,assertCanvasLoginIdentity,canvasFailureDiagnostic,safeCanvasFailure,authorizationBoundaryChecks,providerDenialObservation,requestStatelessTokenDenial}=require('./audit-beta-canvas-invalid-secret');
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
test('Canvas successful profile read never counts as logout',async()=>{let clock=0;const context={cookies:async()=>[{name:'_csrf_token',value:'csrf'}],addCookies:async()=>{},request:{delete:async()=>({status:()=>302}),get:async()=>({status:()=>200})}};await assert.rejects(retireCanvasSession(context,()=>{},{now:()=>clock,wait:async ms=>{clock+=ms}}),/remains authorized/);});

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

test('failure diagnostic never returns query, origin, credentials or DOM text',async()=>{
 const locator={first(){return this},isVisible:async()=>true};
 const value=await canvasFailureDiagnostic({url:()=> 'https://untrusted.test/login?secret=NEVER-LOG',locator:()=>locator,getByText:()=>locator});
 assert.equal(value.path,'OTHER');assert.equal(value.csrfErrorVisible,true);
 const serialized=JSON.stringify(value);for(const secret of ['untrusted','NEVER-LOG','secret='])assert(!serialized.includes(secret));
});

test('failure labels match the pinned stock controller messages without classifying arbitrary HTTP400',async()=>{
 const patterns=[];const locator={first(){return this},isVisible:async()=>false};
 const result=await canvasFailureDiagnostic({url:()=> 'https://canvas-test.elevenidllc.com/login/canvas',locator:()=>locator,getByText:pattern=>{patterns.push(pattern);return locator}});
 for(const message of ['Please verify your username or password and try again.','Invalid Authenticity Token','No password was given','To protect your account, it has been locked.','Too many failed login attempts.','You have recently logged in multiple times too quickly.'])assert(patterns.some(pattern=>pattern.test(message)));
 assert(!patterns.some(pattern=>pattern.test('400 Bad Request')));assert.equal(result.credentialErrorVisible,false);assert.equal(result.csrfErrorVisible,false);
});

test('Canvas delayed revocation probes the same original cookies until observed denial',async()=>{
 let clock=0,reads=0,current='original';const evidence=[];const original=[{name:'_csrf_token',value:'csrf'},{name:'_normandy_session',value:'original'}];
 const context={cookies:async()=>original,addCookies:async cookies=>{assert.equal(cookies[1].value,'original');current=cookies[1].value},request:{delete:async(_url,options)=>{assert.equal(options.timeout,12000);return {status:()=>302}},get:async()=>{assert.equal(current,'original');current='refreshed-response-cookie';reads++;return {status:()=>reads<3?200:401}}}};
 assert.equal(await retireCanvasSession(context,()=>{},{now:()=>clock,wait:async ms=>{clock+=ms},observe:value=>evidence.push(value)}),true);
 assert.deepEqual(evidence.at(-1).probes,[{status:200,elapsedMs:0},{status:200,elapsedMs:1000},{status:401,elapsedMs:2000}]);assert.equal(original[1].value,'original');
});
test('unknown logout/transport/readback failures cannot qualify even when a cookie probe denies',async()=>{
 for(const kind of ['unknown-logout','logout-transport','unknown-probe']){let probes=0;const context={cookies:async()=>[{name:'_csrf_token',value:'csrf'}],addCookies:async()=>{},request:{delete:async()=>{if(kind==='logout-transport')throw Error('private');return {status:()=>kind==='unknown-logout'?200:302}},get:async()=>{probes++;return {status:()=>kind==='unknown-probe'?500:401}}}};await assert.rejects(retireCanvasSession(context,()=>{}));assert.equal(probes,1);}
});
test('primary stock contract failure survives a separate cleanup failure and session teardown',async()=>{
 const Module=require('node:module'),load=Module._load;class StockFailure extends Error{constructor(){super('untrusted provider detail');this.name='ContractFailure';this.code='canvas_oauth_scope_controls_missing'}}
 let closed=false;const locator={first(){return this},isVisible:async()=>false};const page={on(){},off(){},url:()=> 'https://canvas-test.elevenidllc.com/login/canvas',locator:()=>locator,getByText:()=>locator};
 const context={newPage:async()=>page,cookies:async()=>[{name:'_csrf_token',value:'csrf'}],addCookies:async()=>{},close:async()=>{closed=true},request:{delete:async()=>({status:()=>302}),get:async()=>({status:()=>401})}};
 const stock={ContractFailure:StockFailure,loginCanvas:async()=>{throw new StockFailure()},retireCanvasSetupFixtures:async()=>{throw Error('separate private cleanup detail')}};
 const result={};Module._load=function(request,parent,...rest){if(request==='./run-canvas-oss-standard-contract'&&parent.filename.endsWith('audit-beta-canvas-invalid-secret.js'))return stock;return load.call(this,request,parent,...rest)};
 try{await assert.rejects(runWrongSecretCase({result,save:()=>{},adminPage:{context:()=>({browser:()=>({newContext:async()=>context})})},runId:'owned-run-123',canvasCredentials:{email:'owned@local.test',password:'private'},retainPrivateAuthority:()=>{}}),/control failed/);}
 finally{Module._load=load;}
 assert.deepEqual(result.validClientSecretCase.operationFailure,{type:'ContractFailure',code:'canvas_oauth_scope_controls_missing'});assert.deepEqual(result.validClientSecretCase.resourceCleanupFailure,{type:'Error'});assert.equal(result.validClientSecretCase.failureType,'ContractFailure');assert.equal(result.validClientSecretCase.canvasSessionRetired,true);assert.equal(closed,true);
 assert.deepEqual(safeCanvasFailure(Object.assign(Error('secret'),{code:'secret'}),StockFailure),{type:'Error'});
});

test('OAuth boundary observations expose only booleans and known error classes, never secret values',()=>{
 const secret='NEVER-PUBLISH-STATE-CODE-OR-SECRET';
 const start=new URL('https://canvas-test.elevenidllc.com/login/oauth2/auth');start.searchParams.set('client_id',secret);start.searchParams.set('state',secret);start.searchParams.set('redirect_uri','https://beta.elevenidllc.com/v1/integrations/canvas/oauth/callback');
 assert.deepEqual(authorizationBoundaryChecks(start,secret),{originExpected:true,pathExpected:true,clientIdMatches:true,redirectUriExpected:true,statePresent:true});
 const observations=[authorizationBoundaryChecks(start,secret),providerDenialObservation(401,{error:secret,error_description:secret})];assert(!JSON.stringify(observations).includes(secret));
 assert.equal(providerDenialObservation(401,{error:'invalid_client',error_description:'invalid client'}).descriptionClass,'INVALID_CLIENT_SECRET');assert.equal(providerDenialObservation(401,{error:'invalid_client',error_description:'unknown client'}).descriptionClass,'UNKNOWN_CLIENT');assert.equal(providerDenialObservation(401,{errors:[{message:secret}]}).errorClass,'UNRECOGNIZED');
});

test('negative token transport is isolated from browser cookies and disposed on every outcome',async()=>{
 for(const mode of ['response','parse-failure','cookie-injection']){
  const events=[];const factory={newContext:async options=>{assert.deepEqual(options,{storageState:{cookies:[],origins:[]},ignoreHTTPSErrors:false,extraHTTPHeaders:{Accept:'application/json'}});return {storageState:async()=>({cookies:mode==='cookie-injection'?[{name:'browser',value:'NEVER-LOG'}]:[]}),post:async(url,options)=>{events.push('post');assert.equal(url,'https://canvas-test.elevenidllc.com/login/oauth2/token');assert.equal(options.maxRedirects,0);assert.equal(options.timeout,30000);assert.equal(options.headers,undefined);return {status:()=>401,json:async()=>{if(mode==='parse-failure')throw Error('private body');return {error:'invalid_client',error_description:'invalid client'}}}},dispose:async()=>events.push('dispose')};}};
  if(mode==='response'){const observations=[];const value=await requestStatelessTokenDenial(factory,{code:'private-code',client_secret:'private-secret'},{observe:row=>observations.push(row)});assert.equal(value.status,401);assert.equal(observations.at(-1).initialCookieCount,0);assert(!JSON.stringify(observations).includes('private'));assert.deepEqual(events,['post','dispose']);}
  else{await assert.rejects(requestStatelessTokenDenial(factory,{code:'private-code'}));assert.deepEqual(events,mode==='cookie-injection'?['dispose']:['post','dispose']);}
 }
});
