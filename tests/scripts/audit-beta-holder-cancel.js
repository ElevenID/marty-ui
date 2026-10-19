#!/usr/bin/env node
'use strict';
// Real desktop browser cancellation. Recovery uses the first-party test wallet;
// neither action qualifies an independent Android wallet.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {spawn, spawnSync, execFileSync} = require('node:child_process');
const ROOT=path.resolve(__dirname,'../..');
const WORKSPACE=path.resolve(ROOT,'..');
const BASE='https://beta.elevenidllc.com';
const WALLET='http://127.0.0.1:8787';
const ORG='00000000-0000-0000-0000-000000000001';
const TEMPLATE='50000000-0000-0000-0000-000000000040';
const TRUST='60000000-0000-0000-0000-000000000001';
const PRODUCT='33330c2a0bec50e30ca09cb9d61eb532e75361f2';
const RELEASE='beta-v258-33330c2a0bec';
function assertProductBinding(deployment) {
  assert.equal(deployment.marty_ui_sha,PRODUCT,'Unexpected beta UI source');
  assert.equal(deployment.deployment_release_marker,RELEASE,'Unexpected beta release marker');
  for(const component of ['marty-ui','marty-ui-auth','marty-ui-presentation-policy']) {
    assert.equal(deployment.component_revisions?.[component],PRODUCT,`Unexpected beta component ${component}`);
  }
}
const CHROME='C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function canonical(value) { return Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value; }
const hash=value=>crypto.createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const fileHash=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function nativeChooserBuild(root=ROOT) {
  const directory=path.join(root,'tests/artifacts/native-credential-chooser');
  const binary=path.join(directory,'native-credential-chooser.exe');
  const source=path.join(root,'tests/scripts/native-credential-chooser.cpp');
  const metadata=path.join(directory,'build.json');
  for(const file of [directory,binary,source,metadata])assert.equal(fs.lstatSync(file).isSymbolicLink(),false,'Native helper cannot use symlinks');
  const proof=JSON.parse(fs.readFileSync(metadata,'utf8').replace(/^\uFEFF/,''));
  assert.equal(proof.source_sha256,fileHash(source),'Native helper source binding changed');
  assert.equal(proof.binary_sha256,fileHash(binary),'Native helper binary binding changed');
  assert.deepEqual(proof.self_test,{state:'NATIVE_ABI_SELF_TEST_PASS',windows_enumerated:false,controls_invoked:false});
  return {binary,proof};
}
function guards(env) {
  assert.equal(env.BETA_ORIGIN,BASE);assert.equal(env.MARTY_TEST_WALLET_ORIGIN,WALLET);
  assert.equal(env.D05_SYNTHETIC_FIXTURE,'1');assert.equal(env.D05_NATIVE_CHOOSER_CANCEL,'1');
  assert.equal(env.RECORD_VIDEO,'0','This driver is unrecorded only');
  assert.notEqual(env.NODE_TLS_REJECT_UNAUTHORIZED,'0');assert.notEqual(env.BETA_LOCAL_PROXY,'1');
  assert.ok(env.TEST_ADMIN_EMAIL&&env.TEST_ADMIN_PASSWORD&&env.MARTY_TEST_WALLET_HOLDER_KID?.startsWith('did:'));
  assert.equal(env.CHROME_BINARY,CHROME,'Explicit installed Chrome binary required');
}
function chromeArguments(profile) {
  assert.ok(path.isAbsolute(profile));
  return [`--user-data-dir=${profile}`,'--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',
    '--no-first-run','--no-default-browser-check','--force-renderer-accessibility=complete',
    '--disable-background-networking','--disable-component-update','--new-window','about:blank'];
}
async function fetchPublicJson(url, fetcher=fetch) {
  const response=await fetcher(url);
  assert.equal(response.ok,true,'Public beta HTTP preflight failed');
  return response.json();
}
async function closeOwnedBrowser({browser,contexts=[],child,forceStop,wait=delay}) {
  for(const context of contexts.filter(Boolean))await context.close().catch(()=>{});
  // browser.close() on a CDP attachment only disconnects. Ask this owned
  // browser process to exit first, then disconnect the Playwright client.
  if(browser){
    try {const session=await browser.newBrowserCDPSession();await session.send('Browser.close');}catch{}
    await browser.close().catch(()=>{});
  }
  if(!child)return;
  for(let i=0;i<20&&child.exitCode===null&&child.signalCode===null;i++)await wait(250);
  if(child.exitCode===null&&child.signalCode===null){
    await forceStop();
    for(let i=0;i<20&&child.exitCode===null&&child.signalCode===null;i++)await wait(250);
  }
  assert.ok(child.exitCode!==null||child.signalCode!==null,'Owned Chrome process did not exit; preserve profile for recovery');
}
function heldMediaHashes() {
  const files=['2026.08.0-membership-badge-login-r1/guided/membership-guided.mp4','2026.08.0-credential-lifecycle-r2/guided/lifecycle-guided.mp4'];
  return Object.fromEntries(files.map(file=>[file,fileHash(path.join(WORKSPACE,'marty-demo-recorder/artifacts',file))]));
}
function observeNativeCredentialApi() {
  // Transparent observer: call the actual native implementation, return its
  // actual resolution, and rethrow its original rejection. Never synthesize it.
  const nativeGet=navigator.credentials?.get;
  const observation={nativeImplementation:typeof nativeGet==='function'&&Function.prototype.toString.call(nativeGet).includes('[native code]'),calls:[]};
  Object.defineProperty(window,'__d05NativeObservation',{value:observation});
  if (!observation.nativeImplementation) return;
  Object.defineProperty(navigator.credentials,'get',{configurable:true,value:function(options) {
    const call={startedAt:Date.now(),digital:Boolean(options?.digital),protocols:options?.digital?.requests?.map(r=>r.protocol)||[],settled:false};
    observation.calls.push(call);
    return Reflect.apply(nativeGet,this,[options]).then(value=>{call.settled=true;call.returnedCredential=Boolean(value);return value;},error=>{
      call.settled=true;call.errorName=error?.name;call.rejectedAt=Date.now();throw error;
    });
  }});
}
function classifyStatus(text) {
  if(text.includes('Preparing the wallet chooser'))return 'PREPARING_REQUEST';
  if(text.includes('Opening your wallet chooser'))return 'OPENING_CHOOSER';
  if(text.includes('Wallet request was canceled.'))return 'CANCELED';
  if(text.includes('Wallet response received.'))return 'FINALIZING';
  if(text.includes('Login session expired.'))return 'EXPIRED';
  if(text.includes('Verified!'))return 'VERIFIED';
  return text.trim()?'OTHER_NONEMPTY':'EMPTY';
}
function safeErrorName(name) {
  return ['Error','TypeError','ReferenceError','SyntaxError','RangeError','AssertionError','TimeoutError','NotAllowedError','AbortError','SecurityError','NotSupportedError','InvalidStateError','NetworkError'].includes(name)?name:'OTHER_ERROR';
}
const RECOVERY_ERROR_CODES=new Set(['invalid_request','invalid_request_uri','request_uri_fetch_failed','request_object_fetch_failed','invalid_request_object','invalid_signature','unsupported_format','unsupported_protocol','no_matching_credentials','credential_not_found','credential_revoked','credential_expired','presentation_rejected','verification_failed','invalid_nonce','invalid_state','access_denied']);
function safeRecoveryCode(value){return typeof value==='string'&&RECOVERY_ERROR_CODES.has(value)?value:value===undefined||value===null?null:'OTHER_ERROR';}
async function observeRecoveryResponse(response){
  const body=await response.json().catch(()=>null);
  return {httpStatus:response.status(),httpOk:response.ok(),jsonBody:body!==null,bodyOk:typeof body?.ok==='boolean'?body.ok:null,errorCode:safeRecoveryCode(body?.error_code??body?.code??body?.error),errorCodes:Array.isArray(body?.error_codes)?body.error_codes.slice(0,16).map(safeRecoveryCode):[]};
}
function validateRecoveryRequest(recovery,previousNonce){
  assert.ok(typeof recovery.nonce==='string'&&recovery.nonce&&recovery.nonce!==previousNonce,'Fresh recovery nonce required');
  const outer=new URL(recovery.href);assert.equal(outer.protocol,'openid4vp:','Canonical OpenID4VP recovery link required');
  assert.equal(outer.username,'');assert.equal(outer.password,'');assert.equal(outer.hash,'');
  const requests=outer.searchParams.getAll('request_uri');assert.equal(requests.length,1,'One signed request URI required');
  const request=new URL(requests[0]);assert.equal(request.origin,BASE);assert.equal(request.username,'');assert.equal(request.password,'');assert.equal(request.hash,'');
  assert.match(request.pathname,/^\/v1\/flows\/instances\/[a-f0-9-]{36}\/request$/);
  assert.equal(request.search,'','Recovery must use the canonical first-party request, not DC API or compatibility transport');
  return recovery.href; // Preserve the actual signed product link and all outer OID4VP parameters.
}
function cancellationAssertions(facts) {
  return {
    native_chooser_cancel: facts.nativeCancel?.state==='NATIVE_CANCEL_INVOKED' && facts.nativeCall?.errorName==='NotAllowedError' && facts.nativeCall?.returnedCredential!==true,
    no_presentation_submitted: facts.submissionRequests===0 && facts.flow?.nonce_consumptions===0 && facts.flow?.callback_count===0 && facts.flow?.completed===false && facts.flow?.result_present===false,
    no_session_on_cancel: facts.authenticated===false && facts.pendingStatus==='pending',
    trusted_recovery: facts.recovered===true,
  };
}
function flowSql(id) {
  assert.match(id,UUID);
  return `SELECT json_build_object('status',status,'completed',completed_at IS NOT NULL,'result_present',result IS NOT NULL,'nonce_consumptions',(SELECT count(*) FROM flow_service.flow_nonce_consumptions WHERE flow_instance_id='${id}'),'callback_count',(SELECT count(*) FROM flow_service.flow_callback_outbox WHERE flow_instance_id='${id}')) FROM flow_service.flow_instances WHERE id='${id}' AND organization_id='${ORG}';`;
}
function sql(statement) {
  const result=spawnSync('docker',['exec','-i','elevenid-beta-postgres-1','psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','marty'],{input:statement,encoding:'utf8',windowsHide:true});
  assert.equal(result.status,0,'Scoped beta metadata query failed');return result.stdout.trim();
}
async function until(fn,timeout=30000) {const deadline=Date.now()+timeout;while(Date.now()<deadline){const value=await fn();if(value)return value;await delay(300);}throw new Error('Bounded prerequisite wait failed');}
async function main(env=process.env) {
  guards(env);assert.equal(process.platform,'win32');assert.ok(fs.statSync(CHROME).isFile());
  assert.equal(execFileSync('git',['status','--porcelain'],{cwd:ROOT,encoding:'utf8'}).trim(),'','Driver checkout must be clean');
  const artifactRoot=path.join(WORKSPACE,'audits/beta-release-20261018/d05-holder-cancel-attempts');fs.mkdirSync(artifactRoot,{recursive:true});
  const dir=fs.mkdtempSync(path.join(artifactRoot,'attempt-'));
  const report={startedAt:new Date().toISOString(),scope:'Unrecorded real desktop browser cancellation with first-party recovery',independentWalletQualification:false,recorded:false,stage:'preflight',checks:{},facts:{}};
  report.driverSource=execFileSync('git',['rev-parse','HEAD'],{cwd:ROOT,encoding:'utf8'}).trim();report.chromeBinarySha256=fileHash(CHROME);
  const {chromium}=require('@playwright/test');
  const {login}=require('./audit-beta-credential-lifecycle');
  const {requireJson,browserJson}=require('./beta-demo-resource-helpers');
  const privateRoot=path.join(WORKSPACE,'_codex-private/beta-runtime-20261018/holder-cancel-browser');fs.mkdirSync(privateRoot,{recursive:true});
  const privateReal=fs.realpathSync(privateRoot), relativePrivate=path.relative(fs.realpathSync(WORKSPACE),privateReal);
  assert.ok(relativePrivate&&!relativePrivate.startsWith('..')&&!path.isAbsolute(relativePrivate),'Private runtime must remain inside workspace');
  report.heldMediaBefore=heldMediaHashes();
  const lock=path.join(WORKSPACE,'marty-demo-recorder/artifacts/.recording.lock');fs.writeFileSync(lock,JSON.stringify({pid:process.pid,action:'d05-real-browser-cancel'}),{flag:'wx'});
  let profile,realProfile,child,browser,operator,walletPage,authPage,adminContext,walletContext,authContext,transaction,initial;
  let submissionRequests=0,spawnedAt;
  const request=(route,method='GET',body)=>requireJson(operator,route,{method,...(body?{body:JSON.stringify(body)}:{})});
  const protectedState=async()=>{
    const config=await request(`/v1/signing-keys/config?organization_id=${ORG}`);
    const discovery=await fetchPublicJson(`${BASE}/.well-known/openid-credential-issuer/org/${ORG}`);
    return {trust:hash({profile:await request(`/v1/trust-profiles/${TRUST}`),issuers:await request(`/v1/trust-profiles/${TRUST}/issuers`)}),
      signingDefaults:hash(Object.fromEntries(['default_service_id','format_defaults','type_defaults'].map(k=>[k,config[k]]))),discovery:hash(discovery)};
  };
  try {
    report.nativeHelperBuild=nativeChooserBuild().proof;
    profile=fs.mkdtempSync(path.join(privateRoot,'profile-'));realProfile=fs.realpathSync(profile);
    report.deployment=await fetchPublicJson(`${BASE}/.well-known/marty-release`);
    assertProductBinding(report.deployment);
    report.stage='launch_owned_chrome';
    spawnedAt=Date.now();child=spawn(CHROME,chromeArguments(profile),{stdio:'ignore',windowsHide:false});
    assert.ok(child.pid);child.on('error',()=>{});
    const port=await until(()=>{
      const file=path.join(profile,'DevToolsActivePort');if(!fs.existsSync(file))return null;
      const value=Number(fs.readFileSync(file,'utf8').split(/\r?\n/)[0]);return value>0&&value<65536?value:null;
    });
    browser=await chromium.connectOverCDP(`http://127.0.0.1:${port}`);report.browserVersion=browser.version();
    authContext=browser.contexts()[0];await authContext.addInitScript(observeNativeCredentialApi);
    // Block external QR forwarding; this is not an auth response substitution.
    await authContext.route('https://api.qrserver.com/**',route=>route.abort());
    authPage=await authContext.newPage();report.pageErrorNames=[];
    authPage.on('pageerror',error=>report.pageErrorNames.push(safeErrorName(error.name)));
    authPage.on('request',r=>{if(r.method()==='POST'&&new URL(r.url()).origin===BASE&&/\/submit(?:\/|$)/.test(new URL(r.url()).pathname))submissionRequests++;});
    adminContext=await browser.newContext();operator=await adminContext.newPage();await login(operator,env.TEST_ADMIN_EMAIL,env.TEST_ADMIN_PASSWORD);
    initial=await protectedState();report.protectedBefore=initial;
    const me=async()=>{const response=await authContext.request.get(`${BASE}/v1/auth/me`);assert.ok(response.ok());return response.json();};
    assert.equal((await me()).authenticated,false);
    report.stage='request_actual_native_chooser';
    report.substage='navigate_auth_page';
    let prefetchResponse;
    authPage.on('response',response=>{
      const url=new URL(response.url());
      if(url.origin===BASE&&/^\/v1\/flows\/instances\/[a-f0-9-]+\/request$/.test(url.pathname)&&url.searchParams.get('transport')==='dc_api')prefetchResponse=response;
    });
    await authPage.goto(`${BASE}/v1/auth/credential-login`);
    const details=await authPage.evaluate(()=>({nonce:document.body.dataset.nonce,submit:document.body.dataset.dcApiSubmitUrl,
      protocol:document.body.dataset.dcApiProtocol,supported:typeof DigitalCredential!=='undefined'&&DigitalCredential.userAgentAllowsProtocol(document.body.dataset.dcApiProtocol)}));
    assert.equal(details.supported,true,'Real browser protocol capability is unavailable');
    const flowMatch=details.submit.match(/^\/v1\/flows\/instances\/([a-f0-9-]+)\/submit\/dc-api$/);assert.ok(flowMatch);assert.match(flowMatch[1],UUID);
    report.cancelFlowId=flowMatch[1];report.protocol=details.protocol;
    report.substage='await_actual_signed_request_response';
    await until(()=>prefetchResponse);
    report.prefetch={httpStatus:prefetchResponse.status()};
    assert.ok(prefetchResponse.ok(),'Actual signed request fetch failed');
    assert.equal(await prefetchResponse.finished(),null,'Actual signed request transfer failed');
    // Run a subsequent browser task after the real response has finished, so
    // the product's response.text() and promise continuations can settle.
    await authPage.evaluate(()=>new Promise(resolve=>setTimeout(resolve,0)));
    report.prefetch.transferFinished=true;
    report.substage='click_actual_open_wallet';
    await authPage.locator('[data-action="show-mobile"]').click();
    await authPage.locator('#wallet-link').click();
    report.substage='await_native_credential_invocation';
    await until(async()=>authPage.evaluate(()=>window.__d05NativeObservation?.calls.length===1));
    const nativeBefore=await authPage.evaluate(()=>window.__d05NativeObservation);report.nativeBeforeCancel=nativeBefore;
    assert.equal(nativeBefore.nativeImplementation,true);assert.equal(nativeBefore.calls[0].settled,false,'Browser rejected before a real holder cancellation');
    report.stage='cancel_browser_owned_dialog';
    report.facts.nativeCancel=await until(()=>{
      const native=nativeChooserBuild();report.nativeHelperBuild=native.proof;
      const result=spawnSync(native.binary,[String(child.pid),CHROME,String(spawnedAt)],{encoding:'utf8',windowsHide:true,timeout:15000});
      if(result.status===2){(report.nativeDialogObservations||=[]).push(JSON.parse(result.stdout));return null;}
      if(result.status!==0)fs.writeFileSync(path.join(privateRoot,path.basename(dir)+'-native-helper-error.log'),String(result.stderr||result.error?.name||'Unknown native helper failure'));
      assert.equal(result.status,0,'Native browser chooser observation/cancellation failed');return JSON.parse(result.stdout);
    },30000);
    await authPage.locator('#status').getByText('Wallet request was canceled.',{exact:true}).waitFor({timeout:15000});
    report.facts.nativeCall=(await authPage.evaluate(()=>window.__d05NativeObservation.calls))[0];
    assert.equal(report.facts.nativeCall.errorName,'NotAllowedError');
    await delay(2800);
    const statusResponse=await authContext.request.get(`${BASE}/v1/auth/credential-login/status?nonce=${encodeURIComponent(details.nonce)}`);assert.ok(statusResponse.ok());
    const status=await statusResponse.json();assert.ok(!status.session_id);
    report.facts.pendingStatus=status.status;report.facts.authenticated=(await me()).authenticated;
    report.facts.submissionRequests=submissionRequests;report.facts.flow=JSON.parse(sql(flowSql(report.cancelFlowId)));
    assert.ok(Object.entries(cancellationAssertions(report.facts)).filter(([key])=>key!=='trusted_recovery').every(([,value])=>value));
    report.stage='trusted_first_party_recovery';report.recovery={};
    report.substage='create_wallet_context';
    walletContext=await browser.newContext();walletPage=await walletContext.newPage();
    report.substage='reset_first_party_wallet';
    const reset=await walletContext.request.post(`${WALLET}/api/reset`);report.recovery.reset=await observeRecoveryResponse(reset);assert.ok(reset.ok());
    report.substage='issue_recovery_credential';
    const issuance=await browserJson(operator,'/v1/issuance',{method:'POST',body:JSON.stringify({organization_id:ORG,credential_template_id:TEMPLATE,subject_did:env.MARTY_TEST_WALLET_HOLDER_KID,
      claims:{email:'demo.member@example.test',organization_id:ORG,role:'applicant',achievement_name:'Verified Member',achievement_description:'Synthetic holder cancellation recovery',issued_at:new Date().toISOString()}})});
    report.recovery.issuance={httpStatus:issuance.status,httpOk:issuance.ok,errorCode:safeRecoveryCode(issuance.body?.error_code??issuance.body?.code??issuance.body?.error)};
    transaction=issuance.body;assert.ok(issuance.ok,'Recovery issuance rejected');assert.match(transaction?.id,UUID);report.recoveryTransactionId=transaction.id;
    report.substage='navigate_first_party_wallet';
    const walletNavigation=await walletPage.goto(WALLET);report.recovery.walletNavigationStatus=walletNavigation?.status()??null;assert.ok(walletNavigation?.ok());
    report.substage='receive_recovery_credential';
    await walletPage.getByLabel('Credential offer URI').fill(transaction.credential_offer_uri);
    const received=walletPage.waitForResponse(r=>r.url()===`${WALLET}/api/receive`&&r.request().method()==='POST');await walletPage.getByRole('button',{name:/^receive$/i}).click();
    report.recovery.receive=await observeRecoveryResponse(await received);assert.ok(report.recovery.receive.httpOk,'Recovery credential receipt rejected');
    report.substage='navigate_fresh_recovery_auth';
    const authNavigation=await authPage.goto(`${BASE}/v1/auth/credential-login`);report.recovery.authNavigationStatus=authNavigation?.status()??null;assert.ok(authNavigation?.ok());
    report.substage='validate_fresh_recovery_request';
    const recovery=await authPage.evaluate(()=>({nonce:document.body.dataset.nonce,href:document.querySelector('#wallet-link').href}));
    const recoveryUri=validateRecoveryRequest(recovery,details.nonce);report.recovery.freshCanonicalRequest=true;
    report.substage='present_recovery_credential';
    await walletPage.getByLabel('Presentation request URI').fill(recoveryUri);
    const presented=walletPage.waitForResponse(r=>r.url()===`${WALLET}/api/present`&&r.request().method()==='POST');await walletPage.getByRole('button',{name:/^present$/i}).click();
    report.recovery.present=await observeRecoveryResponse(await presented);assert.ok(report.recovery.present.httpOk&&report.recovery.present.bodyOk===true,'Recovery presentation rejected');
    report.substage='await_recovered_authentication';
    await until(async()=>{const state=await me();report.recovery.authenticated=state.authenticated===true;return report.recovery.authenticated;},60000);report.facts.recovered=true;
    report.state='FUNCTIONAL_PASS';
  } catch(error) {
    report.state='FAILED';report.failure={type:safeErrorName(error.name),stage:report.stage,substage:report.substage};
    if(authPage)try{
      report.failureObservation=await authPage.evaluate(()=>{
        const observation=window.__d05NativeObservation;
        return {nativeImplementation:observation?.nativeImplementation===true,callCount:observation?.calls?.length??null,
          calls:(observation?.calls||[]).map(call=>({settled:call.settled,errorName:call.errorName,returnedCredential:call.returnedCredential}))};
      });
      report.failureObservation.calls=report.failureObservation.calls.map(call=>({...call,errorName:call.errorName?safeErrorName(call.errorName):undefined}));
      report.failureObservation.statusClass=classifyStatus(await authPage.locator('#status').innerText({timeout:2000}));
    }catch{report.failureObservationUnavailable=true;}
  }
  finally {
    try {
      if(transaction&&operator) {
        const ids=sql(`SELECT id FROM issuance_service.issued_credentials WHERE transaction_id='${transaction.id}';`).split(/\r?\n/).filter(Boolean);
        for(const id of ids){assert.match(id.replace(/^urn:uuid:/,''),UUID);await request(`/v1/issued-credentials/${encodeURIComponent(id)}/revoke`,'POST',{reason:'D05 holder cancellation recovery cleanup'});}
        report.checks.recovery_credentials_revoked=ids.length===1;
      }
      if(walletContext)assert.ok((await walletContext.request.post(`${WALLET}/api/reset`)).ok());
      if(operator&&initial){report.protectedAfter=await protectedState();report.checks.protected_state_unchanged=hash(initial)===hash(report.protectedAfter);}
    } catch(error){report.cleanupFailure={type:error.name};report.state='FAILED';}
    try {
      await closeOwnedBrowser({browser,contexts:[walletContext,adminContext],child,forceStop:async()=>{
        const result=spawnSync('powershell',['-NoProfile','-NonInteractive','-File',path.join(__dirname,'stop-owned-credential-browser.ps1'),
          '-BrowserProcessId',String(child.pid),'-BrowserExecutable',CHROME,'-SpawnedAtMilliseconds',String(spawnedAt)],{encoding:'utf8',windowsHide:true,timeout:15000});
        assert.equal(result.status,0,'Owned browser tree termination failed');
      }});
      report.checks.owned_browser_exited=true;
      if(profile){assert.equal(fs.realpathSync(profile),realProfile);assert.equal(path.dirname(realProfile),privateReal);assert.equal(path.dirname(profile),privateRoot);fs.rmSync(profile,{recursive:true,force:true});}report.checks.owned_browser_profile_removed=true;}
    catch(error){report.cleanupFailure={type:error.name};report.state='FAILED';}
    report.heldMediaAfter=heldMediaHashes();report.checks.held_media_unchanged=hash(report.heldMediaBefore)===hash(report.heldMediaAfter);
    report.behaviorAssertions=cancellationAssertions(report.facts);
    report.holderCancelNoSession=report.state==='FUNCTIONAL_PASS'&&Object.values(report.behaviorAssertions).every(Boolean)&&report.checks.protected_state_unchanged===true&&report.checks.recovery_credentials_revoked===true&&report.checks.held_media_unchanged&&!report.cleanupFailure;
    report.completedAt=new Date().toISOString();fs.writeFileSync(path.join(dir,'report.json'),JSON.stringify(report,null,2)+'\n');
    fs.appendFileSync(path.join(artifactRoot,'attempts.jsonl'),JSON.stringify({directory:path.basename(dir),state:report.state,holderCancelNoSession:report.holderCancelNoSession})+'\n');
    fs.unlinkSync(lock);
  }
  console.log(JSON.stringify({state:report.state,holderCancelNoSession:report.holderCancelNoSession,report:path.join(dir,'report.json')}));
  assert.equal(report.holderCancelNoSession,true,'Actual browser cancellation/recovery evidence incomplete');
}
if(require.main===module)main().catch(error=>{console.error(`D05 cancellation failed: ${error.name}`);process.exitCode=1;});
module.exports={safeRecoveryCode,observeRecoveryResponse,validateRecoveryRequest,nativeChooserBuild,assertProductBinding,classifyStatus,safeErrorName,fetchPublicJson,closeOwnedBrowser,guards,chromeArguments,observeNativeCredentialApi,cancellationAssertions,flowSql,main};
