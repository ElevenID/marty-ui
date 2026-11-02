// Fresh dedicated passport custody only. Feature resources remain owned by the
// existing Python passport producer; this helper never adopts prior results.
'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {createHash,randomUUID}=require('node:crypto');
const {spawnSync}=require('node:child_process');
const ORIGIN='https://beta.elevenidllc.com',MEMORY=640*1024**2;
function check(value,code){if(!value)throw Object.assign(Error(code),{code});}
function bound(ref){
 check(ref&&Object.keys(ref).sort().join(',')==='path,sha256'&&path.isAbsolute(ref.path)
  &&/^[a-f0-9]{64}$/.test(ref.sha256),'PASSPORT_INPUT_REF_INVALID');
 check(fs.realpathSync(ref.path)===path.resolve(ref.path),'PASSPORT_INPUT_PATH_CHANGED');
 const stat=fs.lstatSync(ref.path);check(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>0&&stat.size<=2*1024**2,'PASSPORT_INPUT_FILE_INVALID');
 const bytes=fs.readFileSync(ref.path);check(createHash('sha256').update(bytes).digest('hex')===ref.sha256,'PASSPORT_INPUT_BYTES_CHANGED');return bytes;
}
function selectedAuthorities(row){
 const result=spawnSync('docker',['--context','desktop-linux','inspect',row.containerId],
  {encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:4*1024**2});
 check(result.status===0&&!result.error,'PASSPORT_SELECTED_SERVICE_INSPECTION_FAILED');
 let records;try{records=JSON.parse(result.stdout);}catch{check(false,'PASSPORT_SELECTED_SERVICE_JSON_INVALID');}check(Array.isArray(records)&&records.length===1,'PASSPORT_SELECTED_SERVICE_AMBIGUOUS');
 const item=records[0],labels=item.Config?.Labels||{};
 check(item.Id===row.containerId&&item.Image===row.imageId&&item.State?.Running===true
  &&item.State.Pid===row.hostPid&&item.State.StartedAt===row.startedAt
  &&labels['com.docker.compose.project']==='elevenid-beta'&&labels['com.docker.compose.service']==='issuance-native',
 'PASSPORT_SELECTED_SERVICE_CHANGED');
 const entries=item.Config?.Env;check(Array.isArray(entries)&&entries.every(value=>typeof value==='string'&&value.includes('=')),
  'PASSPORT_SELECTED_ENV_INVALID');
 const pairs=entries.map(value=>[value.slice(0,value.indexOf('=')),value.slice(value.indexOf('=')+1)]);
 check(new Set(pairs.map(([key])=>key)).size===pairs.length,'PASSPORT_SELECTED_ENV_DUPLICATE');
 const env=Object.fromEntries(pairs);
 return {service:env.GRPC_SERVICE_TOKEN,operator:env.PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN};
}
const FAILURE_CODES=new Set(["PASSPORT_BROWSER_CLEANUP_FAILED", "PASSPORT_DEDICATED_IDENTITY_CHANGED", "PASSPORT_DEDICATED_SESSION_MISSING", "PASSPORT_FRESH_RUN_ID_REQUIRED", "PASSPORT_GOVERNED_CREDENTIALS_REQUIRED", "PASSPORT_GOVERNED_PERMISSIONS_MISSING", "PASSPORT_INPUT_BYTES_CHANGED", "PASSPORT_INPUT_FILE_INVALID", "PASSPORT_INPUT_PATH_CHANGED", "PASSPORT_INPUT_REF_INVALID", "PASSPORT_NATIVE_AUTHORITIES_CHANGED", "PASSPORT_NATIVE_AUTHORITIES_DIFFER", "PASSPORT_NATIVE_AUTHORITIES_MISSING", "PASSPORT_OWNED_OUTPUT_EXISTS", "PASSPORT_PLAN_ORGANIZATION_CHANGED", "PASSPORT_PRIOR_CUSTODY_RETAINED", "PASSPORT_PROFILE_REF_CHANGED", "PASSPORT_RECORDING_LOCK_CHANGED", "PASSPORT_RUNTIME_CHANGED", "PASSPORT_SELECTED_ENV_DUPLICATE", "PASSPORT_SELECTED_ENV_INVALID", "PASSPORT_SELECTED_SERVICE_AMBIGUOUS", "PASSPORT_SELECTED_SERVICE_CHANGED", "PASSPORT_SELECTED_SERVICE_INSPECTION_FAILED", "PASSPORT_SELECTED_SERVICE_JSON_INVALID", "PASSPORT_SELECTED_SERVICE_MISSING", "PASSPORT_SESSIONS_NOT_DISTINCT", "PASSPORT_SESSION_CUSTODY_ROLE_CHANGED", "PASSPORT_SESSION_PREPARATION_ABORTED", "PASSPORT_SESSION_RETIREMENT_FAILED"]);
const FAILURE_STAGES=new Set(["INPUT", "SOURCE_BINDING", "JOB_MEMBERSHIP", "INITIAL_RUNTIME", "BOUND_INPUTS", "TOKEN_EQUALITY", "PRIVATE_CUSTODY", "LOGIN", "PERMISSIONS", "FINAL_RUNTIME", "BROWSER_CLEANUP", "PUBLISHING_FIXTURE"]);
function safeFailure(error,stage){
 const code=FAILURE_CODES.has(error?.code)?error.code:'PASSPORT_SESSION_PREPARATION_FAILED';
 const failureStage=FAILURE_STAGES.has(error?.stage)?error.stage:FAILURE_STAGES.has(stage)?stage:'INPUT';
 return Object.assign(Error(code),{code,stage:failureStage});
}
async function prepare(input,state){
 state.stage='INPUT';
 check(input?.schema==='marty.passport-dedicated-session-input/v1'
  &&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(input.runId),
  'PASSPORT_FRESH_RUN_ID_REQUIRED');
 state.stage='SOURCE_BINDING';
 const recorder=fs.realpathSync(input.recorderRepository),driver=path.resolve(__dirname,'../..');
 const {assertSourceBinding}=require(path.join(recorder,'src/externalQualification'));
 assertSourceBinding(recorder,input.recorderRevision);assertSourceBinding(driver,input.driverRevision);
 // Existing supervisor proof is mandatory before any browser or session effect.
 state.stage='JOB_MEMBERSHIP';
 const job=require(path.join(recorder,'src/windowsJob'));job.requireNativeJob({memoryBytes:MEMORY});
 const {verifyFunctionalLiveBinding}=require(path.join(recorder,'src/localNativeLiveBinding'));
 const verify=()=>verifyFunctionalLiveBinding({receipt:input.runtimeReceipt.path,sha256:input.runtimeReceipt.sha256,
  profile:input.runtimeProfile.path,functionalRerun:true,origin:ORIGIN,imageSourceId:input.imageSourceId});
 state.stage='INITIAL_RUNTIME';bound(input.runtimeProfile);const observed=verify();
 check(observed.profileSha256===input.runtimeProfile.sha256,'PASSPORT_PROFILE_REF_CHANGED');
 const selected=observed.binding.roles.filter(row=>row.role==='issuance-native');check(selected.length===1,'PASSPORT_SELECTED_SERVICE_MISSING');
 state.stage='BOUND_INPUTS';
 const email=bound(input.adminEmail).toString('utf8').trim(),password=bound(input.adminPassword).toString('utf8').trim();
 check(/^[^\s@]+@[^\s@]+$/.test(email)&&password.length>0,'PASSPORT_GOVERNED_CREDENTIALS_REQUIRED');
 bound(input.nativeEnvironment);const environment=Object.create(null);
 require('./verify-beta-waltid-acceptance').loadEnvFile(input.nativeEnvironment.path,environment);
 const service=environment.GRPC_SERVICE_TOKEN,operator=environment.PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN;
 check(typeof service==='string'&&service.length>=32&&typeof operator==='string'&&operator.length>=32&&service!==operator,
  'PASSPORT_NATIVE_AUTHORITIES_MISSING');
 state.stage='TOKEN_EQUALITY';const tokens=selectedAuthorities(selected[0]);
 check(tokens.service===service&&tokens.operator===operator,'PASSPORT_NATIVE_AUTHORITIES_DIFFER');
 check(input.organizationId===input.plan?.application?.organization_id
  &&input.organizationId===input.plan?.certificate_plan?.organization_id
  &&/^[a-f0-9-]{36}$/.test(input.organizationId)
  &&Object.keys(input.resourcePlan||{}).sort().join(',')==='compliance_profile_id,name_prefix',
 'PASSPORT_PLAN_ORGANIZATION_CHANGED');
 state.stage='PRIVATE_CUSTODY';
 const parent=fs.realpathSync(path.join(os.homedir(),'.codex/private/beta-v258-deployment-20261019'));
 const directory=path.join(parent,'d12-functional-'+input.runId),fixture=path.join(directory,'fixture.json');
 check(!fs.existsSync(directory),'PASSPORT_PRIOR_CUSTODY_RETAINED');
 const {retireCanvasBetaSession,createOriginalCookieSessionContext}=require('./run-canvas-oss-standard-contract');
 const requestFactory=require('@playwright/test').request;
 const lock=require(path.join(recorder,'src/recordingLock')).acquireRecordingLock(
  require(path.join(recorder,'src/canvasCaptureHost')).canonicalArtifacts(recorder),{action:'d12-dedicated-session-provision',runId:input.runId});
 let browser,complete=false,failure,dispose,interrupted=false,browserCloseAttempted=false;const contexts={};
 const active=()=>check(!interrupted,'PASSPORT_SESSION_PREPARATION_ABORTED');
 const journal={schema:'marty.passport-dedicated-sessions/v1',organizationId:input.organizationId,sessions:{},complete:false};
 const journalFile=path.join(directory,'dedicated-sessions.json');
 const write=(file,value,exclusive=false)=>{check(!exclusive||!fs.existsSync(file),'PASSPORT_OWNED_OUTPUT_EXISTS');
  const temporary=file+'.next-'+randomUUID();fs.writeFileSync(temporary,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});fs.renameSync(temporary,file);};
 const closeBrowser=async()=>{if(browser&&!browserCloseAttempted){browserCloseAttempted=true;
  try{await browser.close();journal.browserCleanupComplete=true;}catch{journal.browserCleanupComplete=false;
   throw Object.assign(Error('PASSPORT_BROWSER_CLEANUP_FAILED'),{code:'PASSPORT_BROWSER_CLEANUP_FAILED'});}}};
 const required={csca:['organization:view','signing-key:create','signing-key:delete','passport-certificate:issue-csca'],
  dsc:['organization:view','signing-key:create','signing-key:delete','passport-certificate:issue'],
  flow:['organization:view','credential-template:create','credential-template:view','application-template:create','application-template:view',
   'flow-definition:create','flow-definition:activate','flow-definition:edit','flow-definition:delete','flow-instance:start','flow-instance:view','api-key:create','api-key:revoke']};
 try{
  fs.mkdirSync(directory);require(path.join(recorder,'src/ownedNativeWallet')).protectOwnedDirectory(directory,parent);write(journalFile,journal,true);
  dispose=job.watchAbortInput(process.stdin,()=>{interrupted=true;});active();
  const {chromium}=require('@playwright/test'),{login}=require('./audit-beta-credential-lifecycle');
  browser=await chromium.launch({headless:true});
  for(const role of ['csca','dsc','flow']){
   active();
   const context=await browser.newContext();contexts[role]=context;const page=await context.newPage();
   state.stage='LOGIN';journal.sessions[role]={loginAttempted:true,permissionVerified:false};write(journalFile,journal);
   await login(page,email,password);
   const cookies=(await context.cookies(ORIGIN)).filter(cookie=>cookie.name==='sessionId');
   check(cookies.length===1&&cookies[0].value,'PASSPORT_DEDICATED_SESSION_MISSING');
   journal.sessions[role]={loginAttempted:true,cookie:'sessionId='+cookies[0].value,cookies,permissionVerified:false};write(journalFile,journal);active();
   state.stage='PERMISSIONS';
   const me=await context.request.get(ORIGIN+'/v1/auth/me',{maxRedirects:0}),identity=await me.json();
   check(me.status()===200&&identity.authenticated===true&&identity.user?.email?.toLowerCase()===email.toLowerCase(),
    'PASSPORT_DEDICATED_IDENTITY_CHANGED');
   const response=await context.request.get(ORIGIN+'/v1/organizations/'+encodeURIComponent(input.organizationId)+'/members/me/permissions',{maxRedirects:0});
   const permissions=await response.json();active();
   check(response.status()===200&&permissions.has_org_console_access===true&&Array.isArray(permissions.permissions)
    &&required[role].every(key=>permissions.permissions.includes(key)),'PASSPORT_GOVERNED_PERMISSIONS_MISSING');
   journal.sessions[role].permissionVerified=true;write(journalFile,journal);await page.close();
  }
  check(new Set(Object.values(journal.sessions).map(row=>row.cookie)).size===3,'PASSPORT_SESSIONS_NOT_DISTINCT');
  state.stage='FINAL_RUNTIME';active();const final=verify();check(JSON.stringify(final.binding)===JSON.stringify(observed.binding),'PASSPORT_RUNTIME_CHANGED');
  const after=selectedAuthorities(selected[0]);check(after.service===service&&after.operator===operator,'PASSPORT_NATIVE_AUTHORITIES_CHANGED');
  for(const ref of [input.adminEmail,input.adminPassword,input.nativeEnvironment,input.runtimeProfile])bound(ref);
  const value={schema:'marty.passport-fresh-private/v3',plan:input.plan,resourcePlan:input.resourcePlan,
   custody:{cscaSession:journal.sessions.csca.cookie,dscSession:journal.sessions.dsc.cookie,flowSession:journal.sessions.flow.cookie,
    serviceToken:service,operatorToken:operator},privateStatePath:path.join(directory,'native-wire-state.json'),privateHandoffPath:path.join(directory,'native-handoff.json')};
  state.stage='BROWSER_CLEANUP';await closeBrowser();active();
  state.stage='PUBLISHING_FIXTURE';journal.complete=true;write(journalFile,journal);write(fixture,value,true);complete=true;
 }catch(error){failure=safeFailure(error,state.stage);journal.failure={stage:failure.stage,code:failure.code};}
 finally{
  if(!complete)for(const [role,context]of Object.entries(contexts)){
   let isolated;
   try{
    let cookies=journal.sessions[role]?.cookies;
    if(!cookies){cookies=(await context.cookies(ORIGIN)).filter(row=>row.name==='sessionId');
     check(cookies.length===1&&cookies[0].value,'PASSPORT_DEDICATED_SESSION_MISSING');
     journal.sessions[role]={...journal.sessions[role],cookie:'sessionId='+cookies[0].value,cookies};
     try{write(journalFile,journal);}catch{journal.persistenceFailure=true;}}
    const selected=await createOriginalCookieSessionContext(requestFactory,cookies);isolated=selected.isolated;
    const retirement=await retireCanvasBetaSession(selected.session,{retain(label,value){
     check(label==='betaAdminSession','PASSPORT_SESSION_CUSTODY_ROLE_CHANGED');
     journal.sessions[role].cookies=JSON.parse(value);write(journalFile,journal);
    }});
    journal.sessions[role].retirement=retirement;journal.sessions[role].retiredAfterPreparationFailure=true;
   }catch{journal.sessions[role]={...journal.sessions[role],retiredAfterPreparationFailure:false,
     retirementFailureCode:'PASSPORT_SESSION_RETIREMENT_FAILED'};}
   finally{if(isolated)try{await isolated.dispose();}catch{journal.sessions[role].retirementTransportClosed=false;}}
  }
  if(!browserCloseAttempted)try{await closeBrowser();}catch(error){failure||=safeFailure(error,'BROWSER_CLEANUP');
   journal.failure={stage:failure.stage,code:failure.code};}
  if(!complete&&fs.existsSync(journalFile))try{journal.complete=false;write(journalFile,journal);}catch{}
  if(dispose)dispose();check(lock.release(),'PASSPORT_RECORDING_LOCK_CHANGED');
 }
 if(failure)throw failure;
 return {scope:'D12_DEDICATED_SESSION_PROVISION_ONLY',dedicatedSessions:3,permissionChecksPassed:true,featureResourcesCreated:false,
  browserCleanupComplete:journal.browserCleanupComplete===true,privateFixture:fixture,privateFixtureSha256:createHash('sha256').update(fs.readFileSync(fixture)).digest('hex'),functionalRunPerformed:false};
}
async function prepareDedicatedPassportFixture(input){
 const state={stage:'INPUT'};try{return await prepare(input,state);}catch(error){throw safeFailure(error,state.stage);}
}
module.exports={prepareDedicatedPassportFixture};
