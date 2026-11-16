// Synthetic beta Admin key lifecycle only; no demo, media or release qualification.
'use strict';
const fs=require('node:fs'),path=require('node:path');
const {createHash}=require('node:crypto');
const ORIGIN='https://beta.elevenidllc.com',ORG='00000000-0000-0000-0000-000000000001';
const MEMORY=640*1024**2;
const SCOPES=Object.freeze(['integrations:write','applications:write','templates:read','credentials:read','credentials:revoke','trust:read','compliance:read']);
const CODES=new Set(['INPUT_INVALID','BOUND_REF_CHANGED','PLAN_CHANGED','IDENTITY_CHANGED','ORG_CHANGED','COOKIE_MISSING',
 'KEY_OWNERSHIP_CHANGED','KEY_STATE_CHANGED','KEY_INVENTORY_INVALID','CREATE_ALREADY_ATTEMPTED','CREATE_OUTCOME_UNKNOWN',
 'CREATE_SECRET_INVALID','REVOKE_OUTCOME_UNKNOWN','SESSION_RETIREMENT_FAILED','BROWSER_CLEANUP_FAILED','TRANSPORT_CLEANUP_FAILED',
 'KEY_HTTP_FAILED','PRIVATE_OUTPUT_FAILED','ABORTED']);
function check(ok,code){if(!ok)throw Object.assign(Error(code),{code});}
function safeFailure(error,stage){return {code:CODES.has(error?.code)?error.code:'KEY_LIFECYCLE_FAILED',stage};}
function bound(ref){
 check(ref&&Object.keys(ref).sort().join(',')==='path,sha256'&&path.isAbsolute(ref.path)
  &&/^[a-f0-9]{64}$/.test(ref.sha256),'BOUND_REF_CHANGED');
 const stat=fs.lstatSync(ref.path);check(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>0&&stat.size<=2*1024**2
  &&fs.realpathSync(ref.path)===path.resolve(ref.path),'BOUND_REF_CHANGED');
 const bytes=fs.readFileSync(ref.path);check(createHash('sha256').update(bytes).digest('hex')===ref.sha256,'BOUND_REF_CHANGED');return bytes;
}
function record(file,value){
 const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,typeof value==='string'?value:JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
function boundJson(ref){return JSON.parse(bound(ref).toString('utf8').replace(/^\uFEFF/,''));}
function planFrom(input){
 const p=boundJson(input.plan);
 check(p.schema==='marty.canvas-owned-api-key-plan/v1'&&p.organizationId===ORG&&p.ttlSeconds===7200
  &&JSON.stringify(p.scopes)===JSON.stringify(SCOPES)&&p.callbacks===false&&p.isTest===true&&p.createOnlyOnce===true
  &&p.cleanup==='revoke-exact-id-and-readback'&&p.outputSecret==='api-key.private'
  &&/^d07d08-\d{8}-[a-f0-9]{8}$/.test(p.runId)&&typeof p.name==='string'&&p.name.includes(p.runId)
  &&/^[a-f0-9-]{36}$/.test(p.idempotencyKey),'PLAN_CHANGED');
 check(input.adminEmail.sha256===p.adminEmailSha256&&input.adminPassword.sha256===p.adminPasswordSha256,'IDENTITY_CHANGED');return p;
}
function owned(row,p,id){
 check(row?.id===id&&/^[a-f0-9-]{36}$/.test(id)&&row.organization_id===ORG&&row.name===p.name
  &&Array.isArray(row.scopes)&&JSON.stringify([...row.scopes].sort())===JSON.stringify([...SCOPES].sort()),'KEY_OWNERSHIP_CHANGED');return row;
}
function sameExpiry(actual,wanted){return Number.isFinite(Date.parse(actual))&&Number.isFinite(Date.parse(wanted))&&Math.abs(Date.parse(actual)-Date.parse(wanted))<60000;}
async function keyOperation(input,p,api,write,active=()=>{}){
 const base='/v1/api-keys',query='?organization_id='+ORG;
 async function list(){active();const r=await api('GET',base+query+'&limit=500&offset=0');
  const rows=Array.isArray(r.body)?r.body:r.body?.keys;
  check(r.status===200&&Array.isArray(rows)&&rows.length<500&&rows.every(x=>typeof x?.id==='string')
   &&new Set(rows.map(x=>x.id)).size===rows.length,'KEY_INVENTORY_INVALID');return rows;}
 let id,expiry;
 if(input.mode==='create'){
  check(!fs.existsSync(input.createIntentPath)&&!fs.existsSync(input.secretOutput),'CREATE_ALREADY_ATTEMPTED');
  check(!(await list()).some(row=>row.name===p.name),'CREATE_ALREADY_ATTEMPTED');
  expiry=new Date(Date.now()+7200*1000).toISOString();active();
  record(input.createIntentPath,{schema:'marty.canvas-api-key-intent/v1',state:'CREATE_INTENT',plan:input.plan,
   runId:p.runId,organizationId:ORG,name:p.name,scopes:SCOPES,expiresAt:expiry,idempotencyKey:p.idempotencyKey});
  // Once the durable intent exists, this operator never repeats POST, including after an unknown result.
  let r;try{r=await api('POST',base+query,{name:p.name,scopes:SCOPES,expires_at:expiry,is_test:true},p.idempotencyKey);}
  catch{check(false,'CREATE_OUTCOME_UNKNOWN');}
  check([200,201].includes(r.status)&&typeof r.body?.id==='string','CREATE_OUTCOME_UNKNOWN');id=r.body.id;
  write('created.private.json',{schema:'marty.canvas-api-key-created/v1',state:'CREATE_RESPONSE_OBSERVED_UNVERIFIED',
   id,runId:p.runId,name:p.name,organizationId:ORG,scopes:r.body.scopes,expiresAt:r.body.expires_at,
   secretFile:input.secretOutput,secretRetired:false,httpStatus:r.status});
  // Save the one-time secret before further readbacks; retain it on all failures.
  check(typeof r.body.key==='string'&&/^mk_test_[A-Za-z0-9]{43}$/.test(r.body.key),'CREATE_SECRET_INVALID');
  record(input.secretOutput,r.body.key+'\n');owned(r.body,p,id);
  check(sameExpiry(r.body.expires_at,expiry),'KEY_STATE_CHANGED');
 }else{
  const c=boundJson(input.created);bound(input.secret);
  check(c.schema==='marty.canvas-api-key-created/v1'&&c.runId===p.runId&&c.organizationId===ORG&&c.name===p.name
   &&c.secretRetired===false&&path.resolve(c.secretFile)===path.resolve(input.secret.path)
   &&/^mk_test_[A-Za-z0-9]{43}$/.test(bound(input.secret).toString('utf8').trim()),'KEY_OWNERSHIP_CHANGED');
  id=c.id;expiry=c.expiresAt;
 }
 let row=owned((await list()).find(x=>x.id===id),p,id);
 check(sameExpiry(row.expires_at,expiry),'KEY_STATE_CHANGED');
 if(input.mode==='revoke'){
  if(row.enabled!==false){check(row.enabled===true,'KEY_STATE_CHANGED');active();
   write('revoke-intent.json',{id,organizationId:ORG,plan:input.plan,created:input.created});
   let r;try{r=await api('DELETE',base+'/'+encodeURIComponent(id)+query);}
   catch{check(false,'REVOKE_OUTCOME_UNKNOWN');}
   check([200,204].includes(r.status),'REVOKE_OUTCOME_UNKNOWN');}
  row=owned((await list()).find(x=>x.id===id),p,id);
  check(row.enabled===false&&sameExpiry(row.expires_at,expiry),'KEY_STATE_CHANGED');
  // Revalidate exact raw custody immediately before deleting only the selected secret.
  bound(input.secret);fs.unlinkSync(input.secret.path);
 }else check(row.enabled===true&&Date.parse(row.expires_at)>Date.now(),'KEY_STATE_CHANGED');
 return {state:input.mode==='revoke'?'REVOKED':'ACTIVE_SCOPED_KEY',id,organizationId:ORG,scopes:SCOPES,
  expiresAt:row.expires_at,secretRetired:input.mode==='revoke'};
}
async function withAdmin(input,p,deps,operation){
 let browser,context,custody,cookies,isolated,result,failure,stage='BROWSER',retired=false,closed=false;
 const write=(name,value)=>record(path.join(input.outputDir,name),value);
 const fail=error=>{failure||=safeFailure(error,stage);};
 try{
  custody=deps.createCustody(p.runId,input.outputDir);
  browser=await deps.launch();context=await browser.newContext({baseURL:ORIGIN});const page=await context.newPage();
  stage='LOGIN';await deps.login(page,bound(input.adminEmail).toString('utf8').trim(),bound(input.adminPassword).toString('utf8').trim());
  cookies=await context.cookies(ORIGIN);check(cookies.length>0,'COOKIE_MISSING');
  custody.retain('betaAdminSession',JSON.stringify(cookies)); // durable original cookies BEFORE any key API effect
  write('session-cookie-metadata.json',{cookies:cookies.map(({name,domain,secure,httpOnly,path})=>({name,domain,secure,httpOnly,path}))});
  stage='IDENTITY';const me=await context.request.get(ORIGIN+'/v1/auth/me',{maxRedirects:0,timeout:15000});const identity=await me.json();
  check(me.status()===200&&identity.authenticated===true&&identity.user?.user_id===input.expectedUserId
   &&identity.user?.email?.toLowerCase()===bound(input.adminEmail).toString('utf8').trim().toLowerCase(),'IDENTITY_CHANGED');
  stage='ORGANIZATION';await deps.selectOrg(page);
  check(await page.evaluate(()=>localStorage.getItem('activeOrgId'))===ORG,'ORG_CHANGED');
  const api=async(method,url,body,idem)=>{
   deps.active?.();const response=await context.request.fetch(ORIGIN+url,{method,maxRedirects:0,timeout:20000,
    headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{}),...(idem?{'Idempotency-Key':idem}:{})},
    ...(body?{data:body}:{})});let payload=null;try{payload=await response.json();}catch{}
   return {status:response.status(),body:payload};
  };
  stage='KEY_OPERATION';result=await operation(api,write);
 }catch(error){fail(error);}
 finally{
  stage='SESSION_RETIREMENT';
  if(context){try{
   if(!cookies){cookies=await context.cookies(ORIGIN);check(cookies.length>0,'COOKIE_MISSING');custody.retain('betaAdminSession',JSON.stringify(cookies));}
   const original=await deps.originalContext(cookies);isolated=original.isolated;
   const receipt=await deps.retireSession(original.session,custody);
   check(receipt.oldCookieAuthenticated===false,'SESSION_RETIREMENT_FAILED');write('session-retirement.json',receipt);retired=true;
  }catch(error){fail(Object.assign(Error(),{code:'SESSION_RETIREMENT_FAILED'}));}}
  stage='TRANSPORT_CLEANUP';if(isolated)try{await isolated.dispose();}catch{fail(Object.assign(Error(),{code:'TRANSPORT_CLEANUP_FAILED'}));}
  stage='BROWSER_CLEANUP';if(browser)try{await browser.close();closed=true;}catch{fail(Object.assign(Error(),{code:'BROWSER_CLEANUP_FAILED'}));}
  // Retain original cookies for recovery after ANY failed operation or cleanup.
  if(!failure)try{deps.active?.();}catch(error){fail(error);}
  if(!failure&&retired&&closed)try{custody.retire();}catch(error){fail(error);}
  write('result.json',{schema:'marty.canvas-key-lifecycle-result/v1',mode:input.mode,complete:!failure&&retired&&closed,
   sessionRetired:retired,browserClosed:closed,functionalOnly:true,releaseQualified:false,mediaQualified:false,
   producerSource:{path:__filename,sha256:createHash('sha256').update(fs.readFileSync(__filename)).digest('hex')},
   sourceUi:input.driverRevision,sourceRecorder:input.recorderRevision,plan:input.plan,
   ...(failure?{failure}:{key:result})});
 }
 if(failure)throw Object.assign(Error(failure.code),failure);return result;
}
async function run(input){
 check(input?.schema==='marty.canvas-key-lifecycle-input/v1'&&input.executeAuthorized===true
  &&['create','readback','revoke'].includes(input.mode)&&/^[a-f0-9-]{36}$/.test(input.expectedUserId)
  &&path.basename(input.adminEmail?.path||'')==='nightly-d05-synthetic-admin-email.private'
  &&path.basename(input.adminPassword?.path||'')==='nightly-d05-synthetic-admin-password.private','INPUT_INVALID');
 const recorder=fs.realpathSync(input.recorderRepository),driver=path.resolve(__dirname,'../..');
 const {assertSourceBinding}=require(path.join(recorder,'src/externalQualification'));
 assertSourceBinding(driver,input.driverRevision);assertSourceBinding(recorder,input.recorderRevision);
 const job=require(path.join(recorder,'src/windowsJob'));job.requireNativeJob({memoryBytes:MEMORY});
 const p=planFrom(input);bound(input.adminEmail);bound(input.adminPassword);
 check(path.isAbsolute(input.outputDir)&&!fs.existsSync(input.outputDir),'PRIVATE_OUTPUT_FAILED');
 // Create-once marker and secret share the caller-selected protected owned root; never follow links.
 const parent=fs.realpathSync(input.privateDirectory);
 check(path.dirname(path.resolve(input.outputDir))===parent,'PRIVATE_OUTPUT_FAILED');
 require(path.join(recorder,'src/ownedNativeWallet')).protectOwnedDirectory(parent,path.dirname(parent));
 if(input.mode==='create'){
  check(!fs.existsSync(path.join(parent,'01-create-intent.json'))&&!fs.existsSync(path.join(parent,'02-created.json')),'CREATE_ALREADY_ATTEMPTED');
  check(path.resolve(input.createIntentPath)===path.join(parent,'node-create-intent.json')
   &&path.resolve(input.secretOutput)===path.join(parent,'api-key.private'),'PRIVATE_OUTPUT_FAILED');
 }
 if(input.mode!=='create')check(path.dirname(path.resolve(input.secret.path))===parent
  &&path.basename(input.secret.path)==='api-key.private','PRIVATE_OUTPUT_FAILED');
 fs.mkdirSync(input.outputDir);require(path.join(recorder,'src/ownedNativeWallet')).protectOwnedDirectory(input.outputDir,parent);
 const common=require('./run-canvas-oss-standard-contract'),auth=require('./audit-beta-credential-lifecycle');
 const pw=require('@playwright/test');let aborted=false;
 const dispose=job.watchAbortInput(process.stdin,()=>{aborted=true;});
 try{return await withAdmin(input,p,{createCustody:common.createCanvasCaptureCustody,launch:()=>pw.chromium.launch({headless:true}),
  login:auth.login,selectOrg:auth.selectOrg,originalContext:c=>common.createOriginalCookieSessionContext(pw.request,c),
  retireSession:common.retireCanvasBetaSession,active:()=>check(!aborted,'ABORTED')},
  (api,write)=>keyOperation(input,p,api,write,()=>check(!aborted,'ABORTED')));
 }finally{dispose();}
}
module.exports={SCOPES,planFrom,bound,boundJson,owned,safeFailure,keyOperation,withAdmin,run};
if(require.main===module){(async()=>{try{
 check(process.argv.length===6&&process.argv[2]==='--input'&&process.argv[4]==='--input-sha256','INPUT_INVALID');
 const input=boundJson({path:path.resolve(process.argv[3]),sha256:process.argv[5]});await run(input);
 process.stdout.write(JSON.stringify({state:'KEY_LIFECYCLE_COMPLETE',functionalOnly:true,releaseQualified:false,mediaQualified:false})+'\n');
 }catch(error){process.stderr.write(JSON.stringify(safeFailure(error,'OPERATOR'))+'\n');process.exitCode=1;}})();}
