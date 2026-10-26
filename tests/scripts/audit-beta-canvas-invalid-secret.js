'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const CANVAS='https://canvas-test.elevenidllc.com',MARTY='https://beta.elevenidllc.com';
function requireProviderInvalidSecret({status,error,description,issuedCode,clientEnabled,clientId,issuedClientId}){
 assert.equal(clientEnabled,true,'Require an observed enabled owned client');
 assert.equal(clientId,issuedClientId,'Authorization code must be issued for the same valid client');
 assert.equal(issuedCode,true,'Require a real provider authorization-code redirect');
 assert([400,401].includes(status),'Require provider credential denial, not a transport failure');
 assert.equal(error,'invalid_client','Bad code/state or generic error is not secret-specific evidence');
 assert.equal(description,'invalid client','Stock Canvas unknown-client and invalid-secret descriptions differ');
 return {status,error,providerErrorClass:'invalid_client_secret',validEnabledClient:true,codeIssuedForSameClient:true};
}
function requireMartyInvalidSecret(url,platformId,{codeIssuedForSameClient,providerInvalidSecret}){
 assert.equal(codeIssuedForSameClient,true);assert.equal(providerInvalidSecret,true);
 assert.equal(url.origin,MARTY);assert.equal(url.searchParams.get('platform_id'),platformId);
 assert.equal(url.searchParams.get('outcome'),'error');
 assert.equal(url.searchParams.get('error_code'),'oauth_token_exchange_failed');
 return {outcome:'error',errorCode:'oauth_token_exchange_failed',providerInvalidSecret:true};
}
function planWrongSecretCase({recoverWithValidSecret=false}={}){assert.equal(typeof recoverWithValidSecret,'boolean');return {
 stockLogoutScope:'Audit-test-account global logout stamp under exclusive lease; owned old-cookie denial is verified, not a targeted-only session retirement.',
 scope:recoverWithValidSecret?'VALID_CLIENT_WRONG_SECRET_AND_FRESH_VALID_SECRET_RECOVERY_FUNCTIONAL_ONLY':'VALID_ENABLED_CANVAS_CLIENT_WRONG_SECRET_FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,
 owns:['fresh stock Canvas OAuth Developer Key','fresh Marty draft platform','fresh KMS-backed wrong-secret reference',...(recoverWithValidSecret?['fresh KMS-backed correct-secret reference','server-owned OAuth access/optional-refresh references']:[])],
 phases:['bind all actual executable roles and reviewed mixed runtime receipts','fresh governed beta and stock Canvas sessions',
 'stock production Developer Key wizard and enabled-client readback','fresh provider-issued code: explicit invalid_client on wrong-secret token exchange',
 'second fresh code: real Marty callback typed oauth_token_exchange_failed; draft remains disconnected',
 'archive owned Marty platform and delete secret; delete owned Canvas key via stock UI; retire both sessions'],
 optionalRecovery:recoverWithValidSecret?'Third fresh server-owned state/code; new owned correct KMS client-secret ref; shared native authorization, catalog read and native disconnect before owned retirement.':'Not enabled in this negative-only slice; future recovery must use a fresh real authorization, never reuse codes.',
 forbiddenEvidence:['unknown client ID','invented/expired/reused code','bad state','network/TLS error','generic provider error'],
 executionStarted:false};}
async function executeWrongSecretCase({result,save,gateway,admin,adminPage,organizationId,runId,canvasCredentials,retainPrivateAuthority,recoverWithValidSecret=false}){
 assert(canvasCredentials&&canvasCredentials.email&&canvasCredentials.password);
 assert.equal(typeof retainPrivateAuthority,'function','Owned stock authority needs protected recovery custody');
 assert.equal(typeof recoverWithValidSecret,'boolean','Recovery requires an explicit reviewed boolean');
 if(recoverWithValidSecret)assert(result?.functionalRuntimeBinding?.scope==='FUNCTIONAL_ONLY'&&result.functionalRuntimeBinding.releaseQualified===false
  &&result.functionalRuntimeBinding.recordingQualified===false&&result.functionalRuntimeBinding.roles?.length===22,'Recovery requires the reviewed all22 functional runtime binding before browser authority');
 const stock=require('./run-canvas-oss-standard-contract');
 const browser=adminPage.context().browser(),context=await browser.newContext(),page=await context.newPage();
 const owned={scope:'OWNED_CANVAS_SETUP_RESOURCES',runSuffix:runId,resources:{}};
 result.validClientSecretCase={state:'STARTED',stockLogoutScope:'AUDIT_TEST_ACCOUNT_GLOBAL_LOGOUT_UNDER_EXCLUSIVE_LEASE',stage:'CANVAS_LOGIN',loginHttp:[],ownedMarty:[],ownedCanvas:owned,qualification:false};save();
 const stage=value=>{result.validClientSecretCase.stage=value;save();};
 const observeResponse=response=>{
  const url=new URL(response.url());if(url.origin!==CANVAS||!['/login/canvas','/login','/logout','/api/v1/users/self/profile'].includes(url.pathname))return;
  const method=response.request().method();if(!['GET','POST','DELETE'].includes(method))return;
  if(result.validClientSecretCase.loginHttp.length<16)result.validClientSecretCase.loginHttp.push({method,path:url.pathname,status:response.status()});
  else result.validClientSecretCase.additionalLoginHttp=(result.validClientSecretCase.additionalLoginHttp||0)+1;save();
 };
 page.on('response',observeResponse);
 const state={owned,runSuffix:runId,canvasOrigin:CANVAS,adminPage:page,
  persistOwned:save};
 // Private credential bytes and authorization codes remain only in this closure.
 let primaryFailure=null,cleanupFailure=null;
 const describe=error=>safeCanvasFailure(error,stock.ContractFailure);
 let clientId,correctSecret,platform,wrongRef,oauthMayExist=false;const authorizationStates=new Set(),authorizationCodes=new Set();const wrong=crypto.randomBytes(32).toString('hex');
 async function create(collection,body){
  const row={collection,name:body.name||body.display_name,state:'CREATING'};
  result.validClientSecretCase.ownedMarty.push(row);save();
  const response=await gateway(collection,{...admin,method:'POST',body});
  row.httpStatus=response.status;row.returnedId=response.payload?.id;row.state='RESPONSE_UNVERIFIED';save();
  assert([200,201].includes(response.status));assert.equal(response.payload.organization_id,organizationId);
  assert.equal(response.payload.name||response.payload.display_name,row.name);
  assert.match(response.payload.id,/^[a-f0-9-]{36}$/i);
  row.id=response.payload.id;row.state='CREATED';save();return response.payload;
 }
 async function start(secretRef=wrongRef,phase='AUTHORIZATION_START'){
  stage(phase);
  const started=await gateway('/v1/integrations/canvas/platforms/'+platform.id+'/oauth/authorizations',
   {...admin,method:'POST',body:{client_id:clientId,client_secret_secret_id:secretRef.id,capabilities:['catalog']}});
  result.validClientSecretCase.authorizationStarts=result.validClientSecretCase.authorizationStarts||[];
  const observation={status:started.status};result.validClientSecretCase.authorizationStarts.push(observation);save();
  assert.equal(started.status,200);
  const url=new URL(started.payload.authorization_url);Object.assign(observation,authorizationBoundaryChecks(url,clientId));save();
  assert.equal(url.origin,CANVAS);assert.equal(url.pathname,'/login/oauth2/auth');assert.equal(url.searchParams.get('client_id'),clientId);
  assert(url.searchParams.get('state'));assert.equal(url.searchParams.get('redirect_uri'),MARTY+'/v1/integrations/canvas/oauth/callback');
  observation.freshState=!authorizationStates.has(url.searchParams.get('state'));save();requireFreshOAuthValue(authorizationStates,url.searchParams.get('state'));return url;
 }
 async function authorize(url,intercept){
  const captured=await stock.authorizeCanvasOAuth(page,url,{canvasOrigin:CANVAS,martyOrigin:MARTY,captureAtProvider:intercept,
   observe:value=>{result.validClientSecretCase.oauthAuthorizationObservations=result.validClientSecretCase.oauthAuthorizationObservations||[];result.validClientSecretCase.oauthAuthorizationObservations.push({independentControl:intercept,...value});save();}});
  const freshCode=!authorizationCodes.has(captured.code);result.validClientSecretCase.authorizationCodeFreshness=result.validClientSecretCase.authorizationCodeFreshness||[];result.validClientSecretCase.authorizationCodeFreshness.push({freshCode});save();requireFreshOAuthValue(authorizationCodes,captured.code);return captured;
 }
 try{
  await stock.loginCanvas(page,CANVAS,canvasCredentials.email,canvasCredentials.password,{observe:value=>stage('CANVAS_'+value)});
  retainPrivateAuthority('canvasSession',JSON.stringify(await context.cookies(CANVAS)));
  state.adminCanvas=new stock.CanvasSessionClient(CANVAS,context);
  stage('CANVAS_ACCOUNTS');
  const accounts=await state.adminCanvas.request('GET','/api/v1/accounts?per_page=100');assert(Array.isArray(accounts));
  const account=accounts.find(row=>!row.parent_account_id);assert(account?.id);state.accountId=String(account.id);
  stage('CANVAS_PROFILE');
  const profile=await state.adminCanvas.request('GET','/api/v1/users/self/profile');assertCanvasLoginIdentity(profile,canvasCredentials.email);state.adminId=String(profile.id);
  stage('CANVAS_KEY_CREATE');
  result.validClientSecretCase.canvasKeyIntent={name:'Marty OAuth '+runId,accountId:state.accountId,state:'CREATING'};save();
  const key=await stock.createOauthDeveloperKey(page,{canvasOrigin:CANVAS,accountId:state.accountId,ownerEmail:canvasCredentials.email,
   name:'Marty OAuth '+runId,redirectUri:MARTY+'/v1/integrations/canvas/oauth/callback',observe:value=>stage('CANVAS_KEY_'+value),
   onOwned:id=>{owned.resources.oauthDeveloperKey=String(id);result.validClientSecretCase.canvasKeyIntent.state='ID_RECEIVED';save();}});
  result.validClientSecretCase.canvasKeyIntent.state='CREATED';save();
  clientId=key.clientId;correctSecret=key.clientSecret;retainPrivateAuthority('canvasOwnedClientSecret',correctSecret);assert.notEqual(wrong,correctSecret);
  const enabled=await stock.findCanvasDeveloperKey(state,{id:clientId,name:'Marty OAuth '+runId});
  assert.equal(String(enabled?.id),clientId);assert.equal(enabled.workflow_state,'active');
  assert.equal(enabled.developer_key_account_binding?.workflow_state,'on');
  stage('PLATFORM_CREATE');
  platform=await create('/v1/integrations/canvas/platforms',{display_name:'Wrong-secret audit '+runId,canvas_base_url:CANVAS,enabled:false});
  assert.equal(platform.enabled,false);
  stage('SECRET_CREATE');
  wrongRef=await create('/v1/integrations/canvas/integration-secrets',{organization_id:organizationId,name:'Wrong-secret audit '+runId,
   provider:'canvas',purpose:'oauth_client_secret',secret_value:wrong,metadata:{audit_run_id:runId},enabled:true});
  const first=await start();stage('PROVIDER_AUTHORIZE');const issued=await authorize(first,true);
  stage('TOKEN_DENIAL');
  const denied=await requestStatelessTokenDenial(require('@playwright/test').request,{grant_type:'authorization_code',client_id:clientId,
   client_secret:wrong,code:issued.code,redirect_uri:MARTY+'/v1/integrations/canvas/oauth/callback'},
   {observe:value=>{result.validClientSecretCase.providerTokenObservation=value;save();}});
  const body=denied.body;
  result.validClientSecretCase.providerDenial=requireProviderInvalidSecret({status:denied.status,error:body.error,description:body.error_description,
   clientEnabled:true,issuedCode:true,clientId,issuedClientId:first.searchParams.get('client_id')});save();
  const second=await start();result.validClientSecretCase.distinctAuthorizationState=second.searchParams.get('state')!==first.searchParams.get('state');save();assert.notEqual(second.searchParams.get('state'),first.searchParams.get('state'));
  stage('MARTY_CALLBACK');await authorize(second,false);
  const martyUrl=new URL(page.url());result.validClientSecretCase.martyCallbackObservation={originExpected:martyUrl.origin===MARTY,platformMatches:martyUrl.searchParams.get('platform_id')===platform.id,outcomeExpected:martyUrl.searchParams.get('outcome')==='error',errorCodeExpected:martyUrl.searchParams.get('error_code')==='oauth_token_exchange_failed'};save();
  result.validClientSecretCase.martyDenial=requireMartyInvalidSecret(martyUrl,platform.id,
   {codeIssuedForSameClient:true,providerInvalidSecret:true});
  stage('DRAFT_DISCONNECTED_READBACK');
  const after=await gateway('/v1/integrations/canvas/platforms/'+platform.id,admin);
  assert.equal(after.status,200);assert.equal(after.payload.enabled,false);
  assert.notEqual(after.payload.connection_config?.oauth_status,'connected');
  result.validClientSecretCase.state='VALID_CLIENT_WRONG_SECRET_DENIED';save();
  if(recoverWithValidSecret){
   const recovery=result.validClientSecretCase.recovery={state:'STARTED',qualified:false};save();
   stage('RECOVERY_INITIAL_REFS');const initialRefs=await readOwnedOAuthReferences(gateway,admin,organizationId,platform.id);
   assert.equal(initialRefs.length,0,'Fresh disconnected draft must not adopt previous OAuth authority');
   stage('RECOVERY_OAUTH_SOURCE_BINDING');recovery.oauthSelectionBefore=observeOAuthSelection(result.functionalRuntimeBinding);save();
   stage('RECOVERY_CORRECT_SECRET');
   const correctRef=await create('/v1/integrations/canvas/integration-secrets',{organization_id:organizationId,name:'Correct-secret recovery '+runId,
    provider:'canvas',purpose:'oauth_client_secret',secret_value:correctSecret,metadata:{audit_run_id:runId,platform_id:platform.id},enabled:true});
   // Mark before authorization starts: an interrupted callback still needs the
   // native disconnect path, never an assumption that no token was published.
   oauthMayExist=true;const third=await start(correctRef,'RECOVERY_AUTHORIZATION_START');
   recovery.distinctFreshState=authorizationStates.size===3;save();assert.equal(recovery.distinctFreshState,true);
   stage('RECOVERY_PROVIDER_AUTHORIZE');await authorize(third,false);recovery.distinctFreshCode=authorizationCodes.size===3;save();assert.equal(recovery.distinctFreshCode,true);
   stock.assertCanvasOauthCompletion(new URL(page.url()),MARTY,platform.id);
   stage('RECOVERY_CONNECTED_READBACK');
   const connected=await gateway('/v1/integrations/canvas/platforms/'+platform.id,admin);
   assert.equal(connected.status,200);assert.equal(connected.payload.organization_id,organizationId);assert.equal(connected.payload.enabled,false);
   assert.equal(connected.payload.connection_config?.oauth_status,'connected');assert.equal(connected.payload.connection_config?.oauth_client_id,clientId);
   const beforeCatalog=await readOwnedOAuthReferences(gateway,admin,organizationId,platform.id,{requireAccess:true});
   recovery.beforeCatalog=beforeCatalog;save();stage('RECOVERY_OWNED_OAUTH_CATALOG');
   const catalog=await readOwnedCanvasScope(gateway,admin,organizationId,platform.id);
   const afterCatalog=await readOwnedOAuthReferences(gateway,admin,organizationId,platform.id,{requireAccess:true});
   const firstAccess=beforeCatalog.find(row=>row.purpose==='oauth_access_token'),lastAccess=afterCatalog.find(row=>row.purpose==='oauth_access_token');
   recovery.afterCatalog=afterCatalog;recovery.oauthSelectionAfter=observeOAuthSelection(result.functionalRuntimeBinding);assert.deepEqual(recovery.oauthSelectionAfter,recovery.oauthSelectionBefore);recovery.catalog=catalog;
   // Metadata reads are SELECT-only. Timestamp movement is corroboration, not
   // an invented activity gate: refresh may return newly saved token bytes.
   recovery.accessRefRotated=firstAccess.id!==lastAccess.id;
   recovery.lastUsedAdvanced=lastAccess.lastUsedAt!==null&&(firstAccess.lastUsedAt===null||Date.parse(lastAccess.lastUsedAt)>Date.parse(firstAccess.lastUsedAt));
   recovery.state='NATIVE_OAUTH_CONNECTED_AND_CATALOG_READ';save();
   result.validClientSecretCase.state='WRONG_SECRET_DENIED_AND_VALID_SECRET_RECOVERED';save();
  }

 }catch(error){
  primaryFailure=error;
  result.validClientSecretCase.failureStage=result.validClientSecretCase.stage;
  result.validClientSecretCase.operationFailure=describe(error);
  result.validClientSecretCase.failureDom=await canvasFailureDiagnostic(page).catch(()=>({diagnosticUnavailable:true}));save();
 }finally{
  let retired=false;
  try{
   if(oauthMayExist){stage('RECOVERY_NATIVE_DISCONNECT');
    result.validClientSecretCase.recovery.disconnect=await retireOwnedOAuthConnection(gateway,admin,organizationId,platform.id,
     value=>{result.validClientSecretCase.recovery.disconnect=value;save();},{requireAccess:!primaryFailure&&result.validClientSecretCase.recovery.state==='NATIVE_OAUTH_CONNECTED_AND_CATALOG_READ'});oauthMayExist=false;save();}
   for(const row of [...result.validClientSecretCase.ownedMarty].sort((a,b)=>Number(b.collection.endsWith('/platforms'))-Number(a.collection.endsWith('/platforms')))){
    assert.equal(row.state,'CREATED','Unknown creation requires reconciliation');
    await requireOwnedMartyResource(gateway,admin,row,organizationId);
    const response=await gateway(row.collection+'/'+row.id,{...admin,method:'DELETE'});assert.equal(response.status,204);row.state='RETIRED';save();
    if(row.collection.endsWith('/platforms')){const read=await gateway(row.collection+'/'+row.id,admin);assert.equal(read.status,404);}
    else{const read=await gateway(row.collection+'?organization_id='+organizationId+'&provider=canvas',admin);
     assert.equal(read.status,200);assert(Array.isArray(read.payload));assert(!read.payload.some(value=>value.id===row.id));}
   }
   retired=result.validClientSecretCase.ownedMarty.every(row=>row.state==='RETIRED');
   assert(!result.validClientSecretCase.canvasKeyIntent||owned.resources.oauthDeveloperKey,'Ambiguous Canvas creation needs reconciliation');
   const cleanup=await stock.retireCanvasSetupFixtures(state,retired,true);
   assert.equal(cleanup.complete,true);result.validClientSecretCase.canvasCleanup=cleanup;
   result.validClientSecretCase.allOwnedAuthorityRetired=retired;
   save();
  }catch(error){
   cleanupFailure=error;result.validClientSecretCase.resourceCleanupFailure=describe(error);save();
  }finally{
   // Session teardown must not replace the original operation or resource-cleanup failure.
   try{
    result.validClientSecretCase.canvasSessionRetired=await retireCanvasSession(context,retainPrivateAuthority,{observe:value=>{result.validClientSecretCase.canvasSessionRetirement=value;save();}});save();
   }catch(error){cleanupFailure=cleanupFailure||error;result.validClientSecretCase.sessionCleanupFailure=describe(error);save();}
   finally{page.off('response',observeResponse);try{await context.close();}catch(error){cleanupFailure=cleanupFailure||error;result.validClientSecretCase.contextCleanupFailure=describe(error);save();}correctSecret=undefined;}
  }
 }
 if(primaryFailure)throw primaryFailure;
 if(cleanupFailure)throw cleanupFailure;
 if(recoverWithValidSecret)result.validClientSecretCase.recovery.localOperationsAndOwnedCleanupPassed=true;
 // The caller still owns beta-session retirement and all22 after-binding; this function never promotes qualification.
 save();return result.validClientSecretCase;
}
function requireFreshOAuthValue(seen,value){
 assert.equal(typeof value,'string');assert(value.length>0);assert.equal(seen.has(value),false,'Fresh server-issued OAuth value required');seen.add(value);return true;
}
function oauthFallbackPresence(raw){
 const seen=new Set(),presence={fallbackEnabled:false,adminTokenScalarPresent:false,adminTokenFileReferencePresent:false};
 for(const entry of raw.split('\0').filter(value=>value.includes('='))){const at=entry.indexOf('='),name=entry.slice(0,at);
  if(!['CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK','CANVAS_ADMIN_API_TOKEN','CANVAS_ADMIN_API_TOKEN_FILE'].includes(name))continue;
  assert.equal(seen.has(name),false,'Ambiguous process fallback configuration');seen.add(name);const value=entry.slice(at+1).trim();
  if(name==='CANVAS_ALLOW_LOCAL_ADMIN_TOKEN_FALLBACK')presence.fallbackEnabled=['1','true','yes','on'].includes(value.toLowerCase());
  else presence[name==='CANVAS_ADMIN_API_TOKEN'?'adminTokenScalarPresent':'adminTokenFileReferencePresent']=Boolean(value);
 }
 return presence;
}
function observeOAuthSelection(binding,{read=args=>require('node:child_process').execFileSync('docker',args,{encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024,windowsHide:true})}={}){
 assert(binding&&['marty.functional-mixed-runtime-binding/v1','marty.functional-mixed-runtime-binding/v2'].includes(binding.schema));
 assert.equal(binding.scope,'FUNCTIONAL_ONLY');assert.equal(binding.releaseQualified,false);assert.equal(binding.recordingQualified,false);assert.equal(binding.roles.length,22);
 return ['issuance','issuance-native'].map(role=>{
  const selected=binding.roles.filter(row=>row.role===role);assert.equal(selected.length,1);const row=selected[0];assert.match(row.containerId,/^[a-f0-9]{64}$/);
  const before=JSON.parse(read(['inspect',row.containerId]))[0];assert.equal(before.Id,row.containerId);assert.equal(before.State.Running,true);
  assert.equal(before.State.Pid,row.hostPid);assert.equal(before.State.StartedAt,row.startedAt);
  const presence=oauthFallbackPresence(read(['exec',row.containerId,'cat','/proc/1/environ']));
  const after=JSON.parse(read(['inspect',row.containerId]))[0];assert.equal(after.Id,before.Id);assert.equal(after.State.Pid,before.State.Pid);assert.equal(after.State.StartedAt,before.State.StartedAt);
  assert.equal(presence.fallbackEnabled,false,'OAuth recovery must not be masked by local administrator fallback');
  return {role,containerId:row.containerId,hostPid:row.hostPid,startedAt:row.startedAt,...presence};
 });
}
function ownedOAuthReferences(payload,organizationId,platformId,{requireAccess=false}={}){
 assert.equal(typeof requireAccess,'boolean');
 assert(Array.isArray(payload));assert(payload.every(row=>row.organization_id===organizationId&&row.provider==='canvas'),'Secret inventory is not tenant/provider bound');
 const owned=payload.filter(row=>row.metadata?.platform_id===platformId&&['oauth_access_token','oauth_refresh_token'].includes(row.purpose));
 assert.equal(new Set(owned.map(row=>row.id)).size,owned.length,'Ambiguous owned OAuth references');
 for(const row of owned){assert.match(row.id,/^[a-f0-9-]{36}$/i);assert.equal(typeof row.enabled,'boolean');if(requireAccess)assert.equal(row.enabled,true);
  assert(row.last_used_at==null||Number.isFinite(Date.parse(row.last_used_at)),'Invalid last-used metadata');}
 if(requireAccess){assert.equal(owned.filter(row=>row.purpose==='oauth_access_token').length,1);assert(owned.filter(row=>row.purpose==='oauth_refresh_token').length<=1);}
 return owned.map(row=>({id:row.id,organizationId,platformId,purpose:row.purpose,enabled:row.enabled,lastUsedAt:row.last_used_at??null}));
}
async function readOwnedOAuthReferences(gateway,admin,organizationId,platformId,options={}){
 const response=await gateway('/v1/integrations/canvas/integration-secrets?organization_id='+encodeURIComponent(organizationId)+'&provider=canvas',admin);
 assert.equal(response.status,200);return ownedOAuthReferences(response.payload,organizationId,platformId,options);
}
async function readOwnedCanvasScope(gateway,admin,organizationId,platformId){
 const response=await gateway('/v1/integrations/canvas/platforms/'+encodeURIComponent(platformId)+'/scope-discovery',
  {...admin,method:'POST',body:{include_courses:true,include_assignments:false,include_quizzes:false,include_modules:false,limit:1}});
 assert.equal(response.status,200);assert.equal(response.payload.platform_id,platformId);assert.equal(response.payload.organization_id,organizationId);
 assert.equal(response.payload.canvas_base_url,CANVAS);assert(Array.isArray(response.payload.courses));
 return {status:200,platformMatches:true,organizationMatches:true,originMatches:true,courseCount:response.payload.courses.length};
}
async function retireOwnedOAuthConnection(gateway,admin,organizationId,platformId,observe=()=>{},{requireAccess=false}={}){
 assert.equal(typeof requireAccess,'boolean');
 const before=await readOwnedOAuthReferences(gateway,admin,organizationId,platformId,{requireAccess});
 const response=await gateway('/v1/integrations/canvas/platforms/'+encodeURIComponent(platformId)+'/oauth',{...admin,method:'DELETE'});
 const evidence={status:response.status,typedDisconnectedAck:false,ownedReferenceIds:before.map(row=>row.id),atomicMetadataAbsence:false,
  providerStatusDirectlyObserved:false,serverHeldBearerProbed:false,normalSuccessCleanup:requireAccess,providerRevokeAckSourceBound:false};observe({...evidence});
 assert.equal(response.status,200);assert.equal(response.payload.platform_id,platformId);assert.equal(response.payload.status,'disconnected');
 assert(Array.isArray(response.payload.scopes)&&response.payload.scopes.length===0);evidence.typedDisconnectedAck=true;observe({...evidence});
 const after=await readOwnedOAuthReferences(gateway,admin,organizationId,platformId);
 assert.equal(after.length,0,'Owned OAuth authority remains; preserve recovery custody');evidence.atomicMetadataAbsence=true;
 evidence.providerRevokeAckSourceBound=requireAccess;
 evidence.nativeAckSemantics=requireAccess?'source-bound provider DELETE accepted200/204/404 before atomic connection/secret removal':'partial-failure disconnect/readback completed; no independent provider revoke claim';observe({...evidence});return evidence;
}
async function canvasFailureDiagnostic(page){
 const url=new URL(page.url());
 const path=url.origin===CANVAS&&['/login/canvas','/login','/'].includes(url.pathname)?url.pathname:'OTHER';
 const visible=async locator=>locator.first().isVisible({timeout:1000}).catch(()=>false);
 return {path,identifierVisible:await visible(page.locator('#pseudonym_session_unique_id, input[name="pseudonym_session[unique_id]"]')),
  passwordVisible:await visible(page.locator('#pseudonym_session_password, input[name="pseudonym_session[password]"]')),
  credentialErrorVisible:await visible(page.getByText(/please verify your username or password|incorrect username or password entries/i)),
  csrfErrorVisible:await visible(page.getByText(/invalid authenticity token/i)),
  passwordMissingVisible:await visible(page.getByText(/no password was given/i)),
  accountLockedVisible:await visible(page.getByText(/it has been locked/i)),
  loginRateLimitedVisible:await visible(page.getByText(/too many failed login attempts|recently logged in multiple times too quickly/i))};
}
function assertCanvasLoginIdentity(profile,email){
 assert(profile?.id,'Stock Canvas self-profile must identify the authenticated user');
 const identities=[profile.primary_email,profile.login_id].filter(value=>typeof value==='string');
 assert(identities.some(value=>value.toLowerCase()===email.toLowerCase()),'Stock Canvas self-profile must match the configured governed login identity');
 return true;
}
async function requireOwnedMartyResource(gateway,admin,row,organizationId){
 assert.equal(row.state,'CREATED');
 const platform=row.collection==='/v1/integrations/canvas/platforms';
 assert(platform||row.collection==='/v1/integrations/canvas/integration-secrets');
 const response=await gateway(platform?row.collection+'/'+row.id:row.collection+'?organization_id='+organizationId+'&provider=canvas',admin);
 assert.equal(response.status,200);
 const values=platform?[response.payload]:response.payload;assert(Array.isArray(values));
 const matches=values.filter(value=>value.id===row.id);assert.equal(matches.length,1,'Owned resource must have one exact public readback');
 const value=matches[0];assert.equal(value.organization_id,organizationId);
 assert.equal(value.name||value.display_name,row.name,'Owned resource identity changed');
 if(!platform){assert.equal(value.provider,'canvas');assert.equal(value.purpose,'oauth_client_secret');}
 return value;
}
async function requestStatelessTokenDenial(requestFactory,form,{observe=()=>{}}={}){
 // Match the production Rust provider: independent HTTP client, no browser cookies or TLS bypass.
 const isolated=await requestFactory.newContext({storageState:{cookies:[],origins:[]},ignoreHTTPSErrors:false,extraHTTPHeaders:{Accept:'application/json'}});
 try{
  const initial=await isolated.storageState();assert(Array.isArray(initial.cookies)&&initial.cookies.length===0,'Token control must start without browser authority');
  const response=await isolated.post(CANVAS+'/login/oauth2/token',{form,maxRedirects:0,timeout:30000});
  const status=response.status();observe({status,transport:'STATELESS_API_CONTEXT',initialCookieCount:0,bodyJsonParsed:false});
  const body=await response.json();observe({...providerDenialObservation(status,body),transport:'STATELESS_API_CONTEXT',initialCookieCount:0,bodyJsonParsed:true});
  return {status,body};
 }finally{await isolated.dispose();}
}
function authorizationBoundaryChecks(url,clientId){
 return {originExpected:url.origin===CANVAS,pathExpected:url.pathname==='/login/oauth2/auth',clientIdMatches:url.searchParams.get('client_id')===clientId,redirectUriExpected:url.searchParams.get('redirect_uri')===MARTY+'/v1/integrations/canvas/oauth/callback',statePresent:Boolean(url.searchParams.get('state'))};
}
function providerDenialObservation(status,body){
 const errors=new Set(['invalid_client','invalid_grant','invalid_request','access_denied','unsupported_grant_type']);
 const description=body?.error_description;
 return {status,errorClass:errors.has(body?.error)?body.error:'UNRECOGNIZED',errorFieldPresent:Object.hasOwn(body||{},'error'),descriptionFieldPresent:Object.hasOwn(body||{},'error_description'),descriptionClass:description==='invalid client'?'INVALID_CLIENT_SECRET':description==='unknown client'?'UNKNOWN_CLIENT':description==='authorization_code not found'?'INVALID_AUTHORIZATION_CODE':typeof description==='string'?'OTHER':'ABSENT'};
}
function safeCanvasFailure(error,ContractFailure){
 if(ContractFailure&&error instanceof ContractFailure)return {type:'ContractFailure',code:/^[a-z0-9_]{1,100}$/.test(error.code)?error.code:'stock_contract_failure'};
 return {type:['AssertionError','TimeoutError'].includes(error?.name)?error.name:'Error'};
}
async function retireCanvasSession(context,retainPrivateAuthority,{observe=()=>{},now=Date.now,wait=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
 const cookies=(await context.cookies(CANVAS)).map(row=>({...row})),csrf=cookies.find(row=>row.name==='_csrf_token');
 const started=now(),evidence={logoutStatus:null,probes:[]};
 const emit=()=>observe(JSON.parse(JSON.stringify(evidence)));
 try{retainPrivateAuthority('canvasSession',JSON.stringify(cookies));}catch{/* Logout must still execute. */}
 assert(csrf?.value,'Stock Canvas session lacks required CSRF evidence');
 let logoutFailure=null;
 try{const response=await context.request.delete(CANVAS+'/logout',{headers:{'X-CSRF-Token':decodeURIComponent(csrf.value)},maxRedirects:0,timeout:Math.max(1,12000-(now()-started))});evidence.logoutStatus=response.status();emit();}
 catch(error){logoutFailure=error;evidence.logoutTransportFailed=true;emit();}
 const expectedRedirect=[302,303].includes(evidence.logoutStatus);
 // Stock caches the eager-loaded pseudonym user for default5s. Never probe a refreshed cookie.
 for(;;){
  await context.addCookies(cookies.map(row=>({...row})));
  let status;
  try{const old=await context.request.get(CANVAS+'/api/v1/users/self/profile',{headers:{Accept:'application/json'},maxRedirects:0,timeout:Math.max(1,12000-(now()-started))});status=old.status();}
  catch(error){evidence.probeTransportFailed=true;emit();throw error;}
  evidence.probes.push({status,elapsedMs:now()-started});emit();
  assert(!logoutFailure&&expectedRedirect,'Stock DELETE /logout must complete its supported redirect');
  assert([200,401,403].includes(status),'Unrecognized session readback cannot prove retirement');
  if([401,403].includes(status))return true;
  assert(now()-started<12000,'The original Canvas session remains authorized after bounded cache propagation');
  await wait(Math.min(1000,12000-(now()-started)));
 }
}
async function runWrongSecretCase(options){
 try{return await executeWrongSecretCase(options);}catch(error){
  if(options?.result?.validClientSecretCase){
   options.result.validClientSecretCase.failureType=options.result.validClientSecretCase.operationFailure?.type||safeCanvasFailure(error).type;
   try{options.save();}catch{/* Retain the original sanitized failure even if persistence failed. */}
  }
  // Never surface a Playwright URL, code, provider body, token or supplied secret.
  throw new Error('Canvas valid-client wrong-secret control failed; preserve its owned journal for review.');
 }
}
module.exports={readOwnedCanvasScope,requireFreshOAuthValue,oauthFallbackPresence,observeOAuthSelection,ownedOAuthReferences,readOwnedOAuthReferences,retireOwnedOAuthConnection,requestStatelessTokenDenial,authorizationBoundaryChecks,providerDenialObservation,safeCanvasFailure,canvasFailureDiagnostic,assertCanvasLoginIdentity,requireOwnedMartyResource,retireCanvasSession,planWrongSecretCase,requireProviderInvalidSecret,requireMartyInvalidSecret,runWrongSecretCase};
if(require.main===module){assert.deepEqual(process.argv.slice(2),['--plan'],'Offline plan only; execution requires reviewed existing capability runner');console.log(JSON.stringify(planWrongSecretCase(),null,2));}
