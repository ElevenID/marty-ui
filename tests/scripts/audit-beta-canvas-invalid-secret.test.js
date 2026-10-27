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


const {ownedOAuthReferences,retireOwnedOAuthConnection,requireFreshOAuthValue,oauthFallbackPresence,observeOAuthSelection}=require('./audit-beta-canvas-invalid-secret');
const oauthAccess={id:'11111111-1111-4111-8111-111111111111',organization_id:'owned-org',provider:'canvas',purpose:'oauth_access_token',
 metadata:{platform_id:'owned-platform'},enabled:true,last_used_at:null,secret_hint:'NEVER-EXPOSE',encrypted_secret_value:'NEVER-EXPOSE'};
test('recovery plan is explicit and leaves the existing negative-only default unchanged',()=>{
 assert.equal(planWrongSecretCase().scope,'VALID_ENABLED_CANVAS_CLIENT_WRONG_SECRET_FUNCTIONAL_ONLY');
 const recovery=planWrongSecretCase({recoverWithValidSecret:true});assert(recovery.stockLogoutScope.includes('global logout'));assert(recovery.scope.includes('RECOVERY'));assert.equal(recovery.executionStarted,false);
 assert.equal(recovery.releaseQualified,false);assert.equal(recovery.recordingQualified,false);assert.throws(()=>planWrongSecretCase({recoverWithValidSecret:'true'}));
});
test('recovery metadata binds owned tenant/platform and never returns value or hint fields',()=>{
 const refs=ownedOAuthReferences([oauthAccess,{...oauthAccess,id:'22222222-2222-4222-8222-222222222222',metadata:{platform_id:'another-platform'}}],'owned-org','owned-platform',{requireAccess:true});
 assert.equal(refs.length,1);assert.equal(refs[0].lastUsedAt,null);assert(!JSON.stringify(refs).includes('NEVER-EXPOSE'));
 for(const rows of [[],[oauthAccess,oauthAccess],[{...oauthAccess,organization_id:'foreign'}],[{...oauthAccess,provider:'other'}],[{...oauthAccess,enabled:false}],[{...oauthAccess,metadata:{platform_id:'foreign'}}]])
  assert.throws(()=>ownedOAuthReferences(rows,'owned-org','owned-platform',{requireAccess:true}));
});
test('native OAuth disconnect requires typed ACK then empty owned-reference readback',async()=>{
 const calls=[],observations=[];let reads=0;
 const result=await retireOwnedOAuthConnection(async(route,options)=>{const method=options.method||'GET';calls.push(method);
  assert(!route.includes('expire_sessions'));if(method==='DELETE'){assert.equal(route,'/v1/integrations/canvas/platforms/owned-platform/oauth');return {status:200,payload:{platform_id:'owned-platform',status:'disconnected',scopes:[]}};}
  return {status:200,payload:reads++===0?[oauthAccess]:[]};
 },{},'owned-org','owned-platform',value=>observations.push(value),{requireAccess:true});
 assert.deepEqual(calls,['GET','DELETE','GET']);assert.equal(result.typedDisconnectedAck,true);assert.equal(result.atomicMetadataAbsence,true);
 assert.equal(result.providerRevokeAckSourceBound,true);assert.equal(result.providerStatusDirectlyObserved,false);assert.equal(result.serverHeldBearerProbed,false);assert.equal(observations[0].typedDisconnectedAck,false);
});
for(const mode of ['pending','wrong-platform','remaining-secret','transport'])test('recovery cleanup preserves unresolved authority on '+mode,async()=>{
 const events=[];let reads=0,last;
 await assert.rejects(retireOwnedOAuthConnection(async(_route,options)=>{
  const method=options.method||'GET';events.push(method);
  if(method==='DELETE'){
   if(mode==='transport')throw Error('private token detail');
   return {status:200,payload:{platform_id:mode==='wrong-platform'?'other':'owned-platform',status:mode==='pending'?'revocation_pending':'disconnected',scopes:[]}};
  }
  return {status:200,payload:reads++===0||mode==='remaining-secret'?[oauthAccess]:[]};
 },{},'owned-org','owned-platform',value=>{last=value}));
 assert.deepEqual(events,mode==='remaining-secret'?['GET','DELETE','GET']:['GET','DELETE']);
 assert(!last?.atomicMetadataAbsence);assert(!JSON.stringify(last||{}).includes('private token detail'));
});
test('fresh authorization values cannot replay a prior code or state and remain out of evidence',()=>{
 const seen=new Set();assert.equal(requireFreshOAuthValue(seen,'private-issued-code'),true);
 assert.throws(()=>requireFreshOAuthValue(seen,'private-issued-code'),error=>!error.message.includes('private-issued-code'));
 assert.equal(requireFreshOAuthValue(seen,'another-private-code'),true);assert.throws(()=>requireFreshOAuthValue(seen,''));
});
test('fallback presence returns booleans only and rejects ambiguous process configuration',()=>{
 const observed=oauthFallbackPresence('OTHER=private\0CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK=0\0CANVAS_ADMIN_API_TOKEN=NEVER-EXPOSE\0CANVAS_ADMIN_API_TOKEN_FILE=/private/NEVER-EXPOSE\0');
 assert.deepEqual(observed,{fallbackEnabled:false,adminTokenScalarPresent:true,adminTokenFileReferencePresent:true});assert(!JSON.stringify(observed).includes('NEVER-EXPOSE'));
 assert.equal(oauthFallbackPresence('CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK=TRUE\0').fallbackEnabled,true);
 assert.throws(()=>oauthFallbackPresence('CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK=0\0CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK=1\0'));
});
test('OAuth-only source observation requires the exact still-running bound PID and disabled fallback',()=>{
 const roles=['issuance','issuance-native'].map((role,index)=>({role,containerId:String(index+1).repeat(64),hostPid:index+10,startedAt:'2026-10-26T00:00:00Z'}));
 const binding={schema:'marty.functional-mixed-runtime-binding/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,roles:[...roles,...Array.from({length:20},(_,index)=>({role:'unvisited'+index}))]};
 for(const mode of ['valid','enabled','changed-pid']){
  const calls=[];let inspected=0;
  const read=args=>{calls.push(args[0]);const row=roles.find(item=>item.containerId===args[1]);
   if(args[0]==='exec')return 'CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK='+(mode==='enabled'?'1':'0')+'\0CANVAS_ADMIN_API_TOKEN=PRIVATE\0';
   inspected++;return JSON.stringify([{Id:row.containerId,State:{Running:true,Pid:mode==='changed-pid'&&inspected%2===0?999:row.hostPid,StartedAt:row.startedAt}}]);};
  if(mode==='valid'){const result=observeOAuthSelection(binding,{read});assert.equal(result.length,2);assert(result.every(row=>row.fallbackEnabled===false));assert(!JSON.stringify(result).includes('PRIVATE'));assert.deepEqual(calls,['inspect','exec','inspect','inspect','exec','inspect']);}
  else assert.throws(()=>observeOAuthSelection(binding,{read}));
 }
});

test('cleanup can reconcile disabled owned references without treating them as usable OAuth authority',async()=>{
 const disabled={...oauthAccess,enabled:false};assert.equal(ownedOAuthReferences([disabled],'owned-org','owned-platform')[0].enabled,false);
 assert.throws(()=>ownedOAuthReferences([disabled],'owned-org','owned-platform',{requireAccess:true}));
 const calls=[];await assert.rejects(retireOwnedOAuthConnection(async(_route,options)=>{const method=options.method||'GET';calls.push(method);
  return method==='DELETE'?{status:200,payload:{platform_id:'owned-platform',status:'revocation_pending',scopes:[]}}:{status:200,payload:[disabled]};
 },{},'owned-org','owned-platform'));assert.deepEqual(calls,['GET','DELETE']);
});

test('recovery uses the actual canonical client POST scope-discovery route and typed body',async()=>{
 const {readOwnedCanvasScope}=require('./audit-beta-canvas-invalid-secret'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
 const source=fs.readFileSync(path.join(__dirname,'../../ui/src/services/canvasIntegrationsApi.js'),'utf8');
 const start=source.indexOf('export async function discoverCanvasScope('),end=source.indexOf('\n}',start)+2;assert(start>=0&&end>start);
 let canonical;const sandbox={API_BASE:'/v1/integrations/canvas',encodeURIComponent,post:(route,body)=>{canonical={route,body:JSON.parse(JSON.stringify(body))};}};
 vm.runInNewContext(source.slice(start,end).replace(/^export /,''),sandbox);
 await sandbox.discoverCanvasScope('owned-platform',{includeCourses:true,includeAssignments:false,includeQuizzes:false,includeModules:false,limit:1});
 let observed;const result=await readOwnedCanvasScope(async(route,options)=>{observed={route,method:options.method,body:options.body};
  return {status:200,payload:{platform_id:'owned-platform',organization_id:'owned-org',canvas_base_url:'https://canvas-test.elevenidllc.com',courses:[{name:'DO-NOT-RECORD'}]}};
 },{},'owned-org','owned-platform');
 assert.equal(observed.method,'POST');assert.equal(observed.route,canonical.route);assert.deepEqual(observed.body,canonical.body);
 assert(!JSON.stringify(result).includes('DO-NOT-RECORD'));assert.equal(result.courseCount,1);
});
test('normal successful recovery cannot claim disconnected authority when its access ref was already absent',async()=>{
 const calls=[];await assert.rejects(retireOwnedOAuthConnection(async(_route,options)=>{calls.push(options.method||'GET');return {status:200,payload:[]};
 },{},'owned-org','owned-platform',()=>{},{requireAccess:true}));assert.deepEqual(calls,['GET']);
});
test('recovery fails closed before creating browser authority without the existing all22 runtime proof',async()=>{
 let browserTouched=false;await assert.rejects(runWrongSecretCase({result:{},save(){},recoverWithValidSecret:true,
  canvasCredentials:{email:'governed-user',password:'private'},retainPrivateAuthority(){},adminPage:{context(){browserTouched=true;throw Error('must not create browser authority');}}}));
 assert.equal(browserTouched,false);
});
