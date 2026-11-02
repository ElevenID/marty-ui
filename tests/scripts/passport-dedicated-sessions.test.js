const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm');
const {createHash,randomUUID}=require('node:crypto');
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function fixture(t,mode){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'passport-session-source-control-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const parent=path.join(root,'.codex/private/beta-v258-deployment-20261019');fs.mkdirSync(parent,{recursive:true});
 const recorder=path.join(root,'recorder'),driver=path.join(root,'driver');fs.mkdirSync(recorder);fs.mkdirSync(path.join(driver,'tests/scripts'),{recursive:true});
 let onAbort;const counts={disposed:0,jobs:0,observations:0,browsers:0,logins:0,retired:0,closed:0,released:0,inspections:0};
 const service='s'.repeat(64),operator='o'.repeat(64),email='owned-admin@example.invalid';
 const ref=(name,text)=>{const file=path.join(root,name);fs.writeFileSync(file,text);return {path:file,sha256:digest(Buffer.from(text))};};
 const profile=ref('profile.json','{}'),input={schema:'marty.passport-dedicated-session-input/v1',runId:randomUUID(),
  recorderRepository:recorder,recorderRevision:'a'.repeat(40),driverRevision:'b'.repeat(40),imageSourceId:'c'.repeat(40),
  runtimeProfile:profile,runtimeReceipt:ref('runtime.json','{}'),adminEmail:ref('email.private',email),adminPassword:ref('password.private','private-password'),
  nativeEnvironment:ref('tokens.env','GRPC_SERVICE_TOKEN='+service+'\nPASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN='+operator+'\n'),
  organizationId:'00000000-0000-0000-0000-000000000001',
  plan:{application:{organization_id:'00000000-0000-0000-0000-000000000001'},certificate_plan:{organization_id:'00000000-0000-0000-0000-000000000001'}},
  resourcePlan:{name_prefix:'Source control',compliance_profile_id:'10000000-0000-0000-0000-000000000005'}};
 const row={role:'issuance-native',containerId:'d'.repeat(64),imageId:'sha256:'+'e'.repeat(64),hostPid:123,startedAt:'fixed'};
 const binding={roles:[row]};
 const required=['organization:view','signing-key:create','signing-key:delete','passport-certificate:issue-csca','passport-certificate:issue',
  'credential-template:create','credential-template:view','application-template:create','application-template:view',
  'flow-definition:create','flow-definition:activate','flow-definition:edit','flow-definition:delete','flow-instance:start','flow-instance:view','api-key:create','api-key:revoke'];
 const envSource=fs.readFileSync(path.join(__dirname,'verify-beta-waltid-acceptance.js'),'utf8');
 const envFunction=envSource.match(/function loadEnvFile\([^]*?\n}/)[0];
 const loadEnvFile=vm.runInNewContext('('+envFunction+')',{fs,process});
 const source=fs.readFileSync(path.join(__dirname,'passport-dedicated-sessions.js'),'utf8'),module={exports:{}};
 const sourceFailure=()=>{throw Error('SOURCE_CHANGED');};
 const contract=fs.readFileSync(path.join(__dirname,'run-canvas-oss-standard-contract.js'),'utf8');
 const commonContext={DEFAULT_MARTY_ORIGIN:'https://beta.elevenidllc.com',requireCondition(value,code){if(!value)throw Object.assign(Error(code),{code});}};
 const common={};for(const name of ['retireCanvasBetaSession','createOriginalCookieSessionContext']){
  const expression=contract.match(new RegExp('async function '+name+'\\([^]*?\\n}'))[0];
  common[name]=vm.runInNewContext('('+expression+')',commonContext);
 }
 const fakeRequire=name=>{
  if(name==='node:os')return {homedir:()=>root};
  if(name==='node:child_process')return {spawnSync(){counts.inspections++;
   const env=['GRPC_SERVICE_TOKEN='+((mode==='token-mismatch'||(mode==='token-drift'&&counts.inspections>1))?'foreign':service),
    'PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN='+operator];
   return {status:0,stdout:JSON.stringify([{Id:row.containerId,Image:row.imageId,State:{Running:true,Pid:mode==='generation'?999:row.hostPid,StartedAt:row.startedAt},Config:{Env:env,Labels:{'com.docker.compose.project':'elevenid-beta','com.docker.compose.service':'issuance-native'}}}])};
  }};
  if(name.endsWith('src'+path.sep+'externalQualification'))return {assertSourceBinding:mode==='source'?sourceFailure:()=>{}};
  if(name.endsWith('src'+path.sep+'windowsJob'))return {requireNativeJob({memoryBytes}){counts.jobs++;assert.equal(memoryBytes,640*1024**2);if(mode==='job')throw Error('ACTUAL_JOB_REQUIRED');},watchAbortInput(_stream,callback){onAbort=callback;return ()=>counts.disposed++;}};
  if(name.endsWith('src'+path.sep+'localNativeLiveBinding'))return {verifyFunctionalLiveBinding(args){counts.observations++;assert.equal(args.receipt,input.runtimeReceipt.path);assert.equal(args.profile,input.runtimeProfile.path);const value=structuredClone(binding);if(mode==='runtime-drift'&&counts.observations>1)value.roles[0].hostPid++;return {profileSha256:input.runtimeProfile.sha256,binding:value};}};
  if(name.endsWith('src'+path.sep+'recordingLock'))return {acquireRecordingLock:()=>({release(){counts.released++;return true;}})};
  if(name.endsWith('src'+path.sep+'canvasCaptureHost'))return {canonicalArtifacts:()=>path.join(root,'artifacts')};
  if(name.endsWith('src'+path.sep+'ownedNativeWallet'))return {protectOwnedDirectory:()=>{}};
  if(name==='./verify-beta-waltid-acceptance')return {loadEnvFile};
  if(name==='./run-canvas-oss-standard-contract')return common;
  if(name==='./audit-beta-credential-lifecycle')return {login:async()=>{counts.logins++;if(mode==='abort')onAbort();if(mode==='login')throw Error('PRIVATE_LOGIN_CONTENT');}};
  if(name==='@playwright/test')return {request:{newContext:async()=>{
   let retired=false;return {post:async(url,options)=>{assert(url.endsWith('/v1/auth/logout'));assert(options.headers.Cookie.startsWith('sessionId='));retired=true;counts.retired++;return {status:()=>mode==='logout-ack'?200:302};},
    get:async(url,options)=>{assert(url.endsWith('/v1/auth/me'));assert(options.headers.Cookie.startsWith('sessionId='));return {status:()=>200,json:async()=>({authenticated:mode==='logout-denial'||!retired})};},dispose:async()=>{}};
  }},chromium:{launch:async()=>{counts.browsers++;let ordinal=0;return {
   async newContext(){const role=['csca','dsc','flow'][ordinal++],cookie=mode==='duplicate'?'same-cookie':'owned-'+role;let retired=false;
    return {newPage:async()=>({close:async()=>{}}),cookies:async()=>[{name:'sessionId',value:cookie}],addCookies:async()=>{},request:{
     post:async()=>{throw Error('MANUAL_LOGOUT_MUST_NOT_BE_USED');},
     get:async url=>{if(url.endsWith('/permissions')){
      const journal=JSON.parse(fs.readFileSync(path.join(parent,'d12-functional-'+input.runId,'dedicated-sessions.json')));
      assert.equal(journal.sessions[role].cookie,'sessionId='+cookie,'Cookie must be durable before permission GET');
      return {status:()=>200,json:async()=>({has_org_console_access:true,permissions:(mode==='permissions'||mode==='logout-ack'||mode==='logout-denial')&&role==='dsc'?[]:required})};
     }return {status:()=>200,json:async()=>retired?{authenticated:false}:{authenticated:true,user:{email}}};}
    }};
   },close:async()=>{counts.closed++;assert.equal(fs.existsSync(path.join(parent,'d12-functional-'+input.runId,'fixture.json')),false);if(mode==='browser-close')throw Error('PRIVATE_BROWSER_CONTENT');}
  };}}};
  return require(name);
 };
 vm.runInNewContext(source,{require:fakeRequire,module,exports:module.exports,__dirname:path.join(driver,'tests/scripts'),Buffer,process,console},{filename:'passport-dedicated-sessions.js'});
 return {run:()=>module.exports.prepareDedicatedPassportFixture(input),counts,input,parent};
}

test('fresh producer accepts a bound non-example-domain Admin and requires three exact governed sessions',async t=>{
 const f=fixture(t,'success'),result=await f.run();assert.equal(result.dedicatedSessions,3);assert.equal(result.functionalRunPerformed,false);
 const value=JSON.parse(fs.readFileSync(result.privateFixture));assert.equal(value.schema,'marty.passport-fresh-private/v3');
 assert.equal(new Set([value.custody.cscaSession,value.custody.dscSession,value.custody.flowSession]).size,3);
 assert.equal(f.counts.jobs,1);assert.equal(f.counts.observations,2);assert.equal(f.counts.logins,3);assert.equal(f.counts.retired,0);assert.equal(f.counts.closed,1);assert.equal(f.counts.released,1);assert.equal(f.counts.disposed,1);
 assert.equal(fs.existsSync(value.privateStatePath),false);assert.equal(fs.existsSync(value.privateHandoffPath),false);
});
for(const mode of ['token-mismatch','generation','job','source'])test('pre-browser refusal: '+mode,async t=>{
 const f=fixture(t,mode);await assert.rejects(f.run());assert.equal(f.counts.browsers,0);assert.equal(f.counts.logins,0);
 assert.equal(fs.existsSync(path.join(f.parent,'d12-functional-'+f.input.runId)),false);
});
for(const mode of ['permissions','duplicate','login','abort','runtime-drift','token-drift','browser-close'])test('failed preparation retires owned sessions and cannot claim complete: '+mode,async t=>{
 const f=fixture(t,mode);await assert.rejects(f.run(),error=>typeof error.code==='string'&&error.code.startsWith('PASSPORT_')&&typeof error.stage==='string'&&!error.message.includes('PRIVATE_'));
 const directory=path.join(f.parent,'d12-functional-'+f.input.runId),journal=JSON.parse(fs.readFileSync(path.join(directory,'dedicated-sessions.json')));
 assert.equal(journal.complete,false);assert.equal(fs.existsSync(path.join(directory,'fixture.json')),false);
 if(mode==='browser-close'){assert.equal(journal.failure.stage,'BROWSER_CLEANUP');assert.equal(journal.failure.code,'PASSPORT_BROWSER_CLEANUP_FAILED');assert.equal(journal.browserCleanupComplete,false);}
 if(mode==='permissions'){assert.equal(journal.failure.stage,'PERMISSIONS');assert.equal(journal.failure.code,'PASSPORT_GOVERNED_PERMISSIONS_MISSING');}
 if(mode==='login'){assert.equal(journal.failure.stage,'LOGIN');assert.equal(journal.failure.code,'PASSPORT_SESSION_PREPARATION_FAILED');}
 assert(Object.values(journal.sessions).every(row=>row.retiredAfterPreparationFailure===true));
 assert(f.counts.retired>0);assert.equal(f.counts.closed,1);assert.equal(f.counts.released,1);assert.equal(f.counts.disposed,1);
});
test('dotenv explicit destination does not mutate process environment',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'passport-env-control-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const file=path.join(root,'env');fs.writeFileSync(file,'D12_CONTROL_VALUE=private-control\n');
 const source=fs.readFileSync(path.join(__dirname,'verify-beta-waltid-acceptance.js'),'utf8'),fn=vm.runInNewContext('('+source.match(/function loadEnvFile\([^]*?\n}/)[0]+')',{fs,process});
 const before=process.env.D12_CONTROL_VALUE,target={};fn(file,target);assert.equal(target.D12_CONTROL_VALUE,'private-control');assert.equal(process.env.D12_CONTROL_VALUE,before);
});


for(const mode of ['logout-ack','logout-denial'])test('maintained retirement helper preserves failed custody: '+mode,async t=>{
 const f=fixture(t,mode);await assert.rejects(f.run());
 const journal=JSON.parse(fs.readFileSync(path.join(f.parent,'d12-functional-'+f.input.runId,'dedicated-sessions.json')));
 assert.equal(journal.complete,false);assert(Object.values(journal.sessions).some(row=>row.retiredAfterPreparationFailure===false));
 assert(Object.values(journal.sessions).every(row=>row.retirementFailureCode==='PASSPORT_SESSION_RETIREMENT_FAILED'));
 assert.equal(journal.failure.code,'PASSPORT_GOVERNED_PERMISSIONS_MISSING');
});
