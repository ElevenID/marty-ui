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
function planWrongSecretCase(){return {
 scope:'VALID_ENABLED_CANVAS_CLIENT_WRONG_SECRET_FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,
 owns:['fresh stock Canvas OAuth Developer Key','fresh Marty draft platform','fresh KMS-backed wrong-secret reference'],
 phases:['bind all actual executable roles and reviewed mixed runtime receipts','fresh governed beta and stock Canvas sessions',
 'stock production Developer Key wizard and enabled-client readback','fresh provider-issued code: explicit invalid_client on wrong-secret token exchange',
 'second fresh code: real Marty callback typed oauth_token_exchange_failed; draft remains disconnected',
 'archive owned Marty platform and delete secret; delete owned Canvas key via stock UI; retire both sessions'],
 optionalRecovery:'Not enabled in this negative-only slice; future recovery must use a fresh real authorization, never reuse codes.',
 forbiddenEvidence:['unknown client ID','invented/expired/reused code','bad state','network/TLS error','generic provider error'],
 executionStarted:false};}
async function executeWrongSecretCase({result,save,gateway,admin,adminPage,organizationId,runId,canvasCredentials,retainPrivateAuthority,recoverWithValidSecret=false}){
 assert(canvasCredentials&&canvasCredentials.email&&canvasCredentials.password);
 assert.equal(typeof retainPrivateAuthority,'function','Owned stock authority needs protected recovery custody');
 assert.equal(recoverWithValidSecret,false,'Correct-secret recovery is not enabled by this reviewed negative-only plan');
 const stock=require('./run-canvas-oss-standard-contract');
 const browser=adminPage.context().browser(),context=await browser.newContext(),page=await context.newPage();
 const owned={scope:'OWNED_CANVAS_SETUP_RESOURCES',runSuffix:runId,resources:{}};
 result.validClientSecretCase={state:'STARTED',stage:'CANVAS_LOGIN',loginHttp:[],ownedMarty:[],ownedCanvas:owned,qualification:false};save();
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
 let clientId,correctSecret,platform,wrongRef;const wrong=crypto.randomBytes(32).toString('hex');
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
 async function start(){
  const started=await gateway('/v1/integrations/canvas/platforms/'+platform.id+'/oauth/authorizations',
   {...admin,method:'POST',body:{client_id:clientId,client_secret_secret_id:wrongRef.id,capabilities:['catalog']}});
  assert.equal(started.status,200);const url=new URL(started.payload.authorization_url);
  assert.equal(url.origin,CANVAS);assert.equal(url.pathname,'/login/oauth2/auth');assert.equal(url.searchParams.get('client_id'),clientId);
  assert(url.searchParams.get('state'));assert.equal(url.searchParams.get('redirect_uri'),MARTY+'/v1/integrations/canvas/oauth/callback');return url;
 }
 async function authorize(url,intercept){
  let captured;const callback=MARTY+'/v1/integrations/canvas/oauth/callback';
  const handler=async route=>{const target=new URL(route.request().url());
   assert.equal(target.origin,MARTY);assert.equal(target.pathname,'/v1/integrations/canvas/oauth/callback');
   assert.equal(target.searchParams.get('state'),url.searchParams.get('state'));assert(target.searchParams.get('code'));
   assert(!target.searchParams.has('error'));captured={code:target.searchParams.get('code'),state:target.searchParams.get('state')};
   if(intercept)await route.fulfill({status:200,contentType:'text/plain',body:'Owned OAuth code observed for explicit credential-denial control.'});else await route.continue();};
  await page.route(callback+'**',handler);
  try{await page.goto(url.href,{waitUntil:'domcontentloaded',timeout:60000});
   if(!captured)await page.locator('#oauth2_accept_form').getByRole('button',{name:/^authorize$/i}).click();
   await page.waitForURL(value=>value.origin===MARTY&&(intercept||value.searchParams.has('outcome')),{timeout:60000});
   assert(captured,'Stock provider did not issue a code');return captured;
  }finally{await page.unroute(callback+'**',handler);}
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
  platform=await create('/v1/integrations/canvas/platforms',{display_name:'Wrong-secret audit '+runId,canvas_base_url:CANVAS,enabled:false});
  assert.equal(platform.enabled,false);
  wrongRef=await create('/v1/integrations/canvas/integration-secrets',{organization_id:organizationId,name:'Wrong-secret audit '+runId,
   provider:'canvas',purpose:'oauth_client_secret',secret_value:wrong,metadata:{audit_run_id:runId},enabled:true});
  const first=await start(),issued=await authorize(first,true);
  const denied=await context.request.post(CANVAS+'/login/oauth2/token',{form:{grant_type:'authorization_code',client_id:clientId,
   client_secret:wrong,code:issued.code,redirect_uri:MARTY+'/v1/integrations/canvas/oauth/callback'},maxRedirects:0,timeout:30000});
  const body=await denied.json();
  result.validClientSecretCase.providerDenial=requireProviderInvalidSecret({status:denied.status(),error:body.error,description:body.error_description,
   clientEnabled:true,issuedCode:true,clientId,issuedClientId:first.searchParams.get('client_id')});save();
  const second=await start();assert.notEqual(second.searchParams.get('state'),first.searchParams.get('state'));
  await authorize(second,false);
  result.validClientSecretCase.martyDenial=requireMartyInvalidSecret(new URL(page.url()),platform.id,
   {codeIssuedForSameClient:true,providerInvalidSecret:true});
  const after=await gateway('/v1/integrations/canvas/platforms/'+platform.id,admin);
  assert.equal(after.status,200);assert.equal(after.payload.enabled,false);
  assert.notEqual(after.payload.connection_config?.oauth_status,'connected');
  result.validClientSecretCase.state='VALID_CLIENT_WRONG_SECRET_DENIED';save();
 }catch(error){
  primaryFailure=error;
  result.validClientSecretCase.failureStage=result.validClientSecretCase.stage;
  result.validClientSecretCase.operationFailure=describe(error);
  result.validClientSecretCase.failureDom=await canvasFailureDiagnostic(page).catch(()=>({diagnosticUnavailable:true}));save();
 }finally{
  let retired=false;
  try{
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
   result.validClientSecretCase.allOwnedAuthorityRetired=retired;save();
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
 return result.validClientSecretCase;
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
module.exports={safeCanvasFailure,canvasFailureDiagnostic,assertCanvasLoginIdentity,requireOwnedMartyResource,retireCanvasSession,planWrongSecretCase,requireProviderInvalidSecret,requireMartyInvalidSecret,runWrongSecretCase};
if(require.main===module){assert.deepEqual(process.argv.slice(2),['--plan'],'Offline plan only; execution requires reviewed existing capability runner');console.log(JSON.stringify(planWrongSecretCase(),null,2));}
