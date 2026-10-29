#!/usr/bin/env node
'use strict';
// Dev/test transport composition. No holder/issuer cryptography is implemented here.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const support=require('./audit-beta-membership-support');
const contract=require('./dev-test-wallet-contract');
const {GRANT}=require('./beta-membership-support-contract');
const {closeControlSession}=require('./verify-beta-credential-login');
const {acquireWalletSession}=require('./demo-wallet-session');
const {createDemoLiveEvidence,applyLocalNativeReadiness}=require('./demo-live-evidence');
const {createCanvasCaptureCustody,retireCanvasBetaSession}=require('./run-canvas-oss-standard-contract');
const {requireJson}=require('./beta-demo-resource-helpers');
const digest=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
async function main(env=process.env){
 assert.equal(env.RECORD_VIDEO,'0','Dev/test coverage is functional-only');
 assert.equal(env.BETA_ORIGIN,'https://beta.elevenidllc.com');
 const settings=support.guards(env,'expired-offer');
 const directory=path.resolve(env.DEMO_ARTIFACT_DIR);assert(!fs.existsSync(path.join(directory,'report.json')));
 const receipt=path.resolve(env.DEMO_LOCAL_FUNCTIONAL_WALLET_RECEIPT||'');
 const privateDirectory=path.dirname(receipt),relative=path.relative(path.join(os.homedir(),'.codex','private'),privateDirectory);
 assert(relative&&!relative.startsWith('..')&&!path.isAbsolute(relative),'Owned private wallet custody required');
 assert(fs.lstatSync(privateDirectory).isDirectory()&&!fs.lstatSync(privateDirectory).isSymbolicLink());
 const report={scenario:'first-party-browser-wallet',schemaVersion:3,state:'PREPARING',
  controlScope:{classification:'FIRST_PARTY_CONTROL',publicWalletProduct:false},runId:env.DEMO_EXECUTION_EVIDENCE_RUN_ID,
  devTestWalletContract:{kind:'SUPPORTED_SDK_DEV_TEST_V1',supportedOperations:contract.SUPPORTED,
   keyBoundary:'SHARED_CONFIGURED_SIGNER_SESSION_ISOLATION_ONLY',independentHolderKeysClaimed:false},
  checks:{},flows:[],walletSessions:[],receipts:[],closedWalletSessions:[],cleanup:{complete:false},releaseReady:false,demo_qualified:false,
  recordingQualified:false,mediaGenerated:false,fullLegacyContractQualified:false,errors:[]};
 const save=()=>{const p=path.join(directory,'report.json'),fd=fs.openSync(p+'.next','wx',0o600);
  try{fs.writeFileSync(fd,JSON.stringify(report,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(p+'.next',p);};
 let evidence,browser,controller,fixture,operator,stage='PREPARATION';
 const contexts=[],holders=[],flows=[];
 async function context(kind){const c=await browser.newContext();const row={context:c,kind,retired:false};
  contexts.push(row);if(kind==='beta'){
   row.custody=createCanvasCaptureCustody(`${report.runId}-beta-${contexts.length}`,privateDirectory);
   await c.addInitScript(()=>Object.defineProperty(globalThis,'DigitalCredential',{value:undefined,configurable:false}));
  }return row;}
 async function page(row){const p=await row.context.newPage();evidence.bindPage(p);return p;}
 async function retire(row){if(row.retired)return;
  const current=await support.authMe(row.context,settings.origin);
  if((await row.context.cookies(settings.origin)).length){
   row.retirement=await retireCanvasBetaSession(row.context,row.custody);
  }else {assert.equal(current.authenticated,false,'Authenticated session lost custody');row.retirement={neverAuthenticated:true};}
  row.custody.retire();row.retired=true;
 }
 function hooks(){let entry;return {async beforeStart(){entry={createAttempted:true,owned:null,terminal:false};
   flows.push(entry);report.flows.push({createAttempted:true,instanceId:null,retirementConfirmed:false});save();},
  async acknowledge({binding,instance}){assert(entry&&!entry.owned,'Duplicate Flow acknowledgement');
   entry.owned={id:binding.instanceId,organizationId:binding.organizationId};
   entry.binding=binding;const row=report.flows[flows.indexOf(entry)];row.instanceId=binding.instanceId;row.nonceSha256=binding.nonceSha256;save();
  }};}
 async function start(){const c=await context('beta'),p=await page(c),h=hooks();
  const login=await support.startLogin({authPage:p,operator,fixture,origin:settings.origin,flowHooks:h});
  return {...login,context:c,page:p};
 }
 async function positive(a){const c=await context('beta'),p=await page(c);
  const result=await support.present({authPage:p,walletPage:a.page,authContext:c.context,operator,fixture,
   ...settings,record:false,waitFor:require('./verify-beta-waltid-acceptance').waitFor,
   issuerDid:fixture.trusted.issuerDid,allowed:true,step:async()=>{},flowHooks:hooks()});
  await retire(c);return result;
 }
 save();
 try{
  evidence=await createDemoLiveEvidence();assert(evidence.ownedWalletBinding&&evidence.functionalRuntimeBinding);
  assert(/^[a-f0-9]{64}$/.test(env.DEMO_D05_FIXTURE_SHA256||''),'Exact dev/test fixture hash required');
  assert.equal(createHash('sha256').update(fs.readFileSync(env.DEMO_D05_FIXTURE_FILE)).digest('hex'),env.DEMO_D05_FIXTURE_SHA256,
   'Dev/test fixture changed after controller preflight');
  fixture=(await support.prepareFixture(directory,env,'expired-offer',evidence)).fixture;
  assert.equal(fixture.expiry.mode,'PER_OWNED_OFFER','Dedicated per-owned-offer lifetime required');
  browser=await require('@playwright/test').chromium.launch({headless:true});
  const admin=await context('beta'),applicant=await context('beta');operator=await page(admin);const applicantPage=await page(applicant);
  const {login,waitFor}=require('./audit-beta-credential-lifecycle');
  await login(operator,env.TEST_ADMIN_EMAIL,env.TEST_ADMIN_PASSWORD);await login(applicantPage,env.TEST_APPLICANT_EMAIL,env.TEST_APPLICANT_PASSWORD);
  controller=support.createSupportController({operator,applicantPage,fixture,lane:'expired-offer',origin:settings.origin,
   runId:report.runId,waitFor,onOwned:owned=>{report.ownedApplications=JSON.parse(JSON.stringify(owned));save();}});
  stage='SOURCE_AUTHORITY';report.fixtureBindingsSha256=digest(await controller.preflight());
  report.cryptographicScope={credentialFormat:fixture.trusted.credentialFormat,
   evidence:'OBSERVED_CONFIGURED_NATIVE_POLICY_SIGNATURE_AND_TRUST_RESULT',
   freshPresentationHolderProofClaimed:false,independentHolderKeysClaimed:false};
  for(const suffix of ['a','b']){const c=await context('wallet');const holder={context:c.context,page:await page(c)};
   holders.push(holder);holder.session=await acquireWalletSession(c.context,{origin:settings.wallet,runId:report.runId+'-'+suffix});
   report.walletSessions.push(holder.session.evidence);save();}
  const [a,b]=holders;report.walletSession=a.session.evidence;
  assert.equal(a.session.evidence.instanceId,evidence.ownedWalletBinding.instanceId);
  stage='ACTUAL_OFFER_EXPIRY';const expiring=await controller.issue(fixture.trusted,'dev-test-expiry',
   {offerTtlSeconds:fixture.expiry.expectedServerOfferTtlSeconds});
  const offerUrl=settings.origin+'/v1/issuance/offers/'+encodeURIComponent(expiring.owned.transactionId);
  const metadata=await requireJson(operator,'/.well-known/oauth-authorization-server/org/'+fixture.trusted.organizationId);
  const tokenUrl=new URL(metadata.token_endpoint);assert.equal(tokenUrl.origin,settings.origin);assert(!tokenUrl.username&&!tokenUrl.password&&!tokenUrl.search&&!tokenUrl.hash);
  report.expiry=await contract.expiredOffer({issuance:expiring,prerequisite:fixture.expiry,
   readOffer:()=>operator.request.get(offerUrl,{timeout:15000}).then(r=>({status:r.status()})),
   exchangeCachedCode:code=>operator.request.post(tokenUrl.href,{timeout:15000,form:{grant_type:GRANT,'pre-authorized_code':code}}).then(async r=>({status:r.status(),error:(await r.json()).error})),
   receiveExpired:()=>support.receive(a.page,settings.wallet,expiring.offerUri,false),
   inventoryAfter:()=>contract.inventory(a),noIssuedCredential:()=>controller.noIssuedCredential(expiring.owned)});
  report.checks.actual_server_expiry=true;report.checks.expired_code_denied=true;
  assert((await controller.cleanupOne(expiring.owned)).ok);const fresh=await controller.reissue(expiring,fixture.trusted);
  assert.notEqual(fresh.owned.transactionId,expiring.owned.transactionId);
  stage='RECEIPT';
  for(const [index,holder] of holders.entries()){
   const issued=index===0?fresh:await controller.issue(fixture.trusted,'dev-test-holder-'+index);
   const receipt=await support.receive(holder.page,settings.wallet,issued.offerUri,false);assert(receipt.ok);
   const credential=await controller.issuedCredential(issued,fixture.trusted);
   report.receipts.push({httpStatus:receipt.httpStatus,ok:receipt.ok,
    applicationId:issued.owned.applicationId,transactionId:issued.owned.transactionId,credentialId:credential.id});
   await holder.page.locator('#credentials li:not(.empty)').first().waitFor();
   assert.equal(await holder.page.locator('#credentials li:not(.empty)').count(),1);
  }
  stage='POSITIVE_LOGIN';report.initialLogin=await positive(a);report.checks.fresh_offer_recovery=report.initialLogin.authenticated===true;
  stage='SESSION_ISOLATION';const denial=await start();
  Object.assign(report.checks,await contract.sessionIsolation({a,b,requestUri:denial.details.href,
   readAuth:()=>support.authMe(denial.context.context,settings.origin)}));
  await b.page.reload();await b.page.locator('#credentials .empty').waitFor();
  await a.page.reload();assert.equal(await a.page.locator('#credentials li:not(.empty)').count(),1);
  stage='HARNESS_CANCELLATION';
  report.cancellation=await contract.cancelOwnedLogin({binding:denial.binding,
   readInstance:()=>requireJson(operator,denial.instancePath),
   beforeCancel:async()=>{report.cancelIntent={kind:'HARNESS_CANCELS_OWNED_FLOW',instanceId:denial.binding.instanceId};save();},
   cancel:()=>requireJson(operator,denial.instancePath+'/cancel',{method:'POST'}).then(()=>({ok:true})),
   finalize:async()=>{const r=await denial.context.context.request.get(settings.origin+'/v1/auth/credential-login/finalize?nonce='+encodeURIComponent(denial.details.nonce),{timeout:15000,maxRedirects:0});return {status:r.status(),setCookie:Boolean(r.headers()['set-cookie'])};},
   readAuth:()=>support.authMe(denial.context.context,settings.origin)});
  report.checks.harness_cancel_no_login=true;
  stage='FRESH_LOGIN_RECOVERY';report.recoveryLogin=await positive(a);
  report.checks.fresh_nonce_login_recovery=contract.freshLoginRecovery(report.cancellation,report.recoveryLogin);
 }catch(error){report.errors.push({stage,code:/^[A-Z][A-Z0-9_]{2,79}$/.test(error.message)?error.message:'DEV_TEST_CONTRACT_FAILED',type:error.name});}
 finally{
  for(const entry of flows){try{assert(entry.owned,'Unresolved Flow creation');const route='/v1/flows/instances/'+entry.owned.id;
   const result=await contract.retireLoginFlow({binding:entry.binding,readInstance:()=>requireJson(operator,route),
    beforeCancel:async()=>{report.flows[flows.indexOf(entry)].cancelIntent=true;save();},
    cancel:()=>requireJson(operator,route+'/cancel',{method:'POST'}).then(()=>({ok:true}))});
   const row=report.flows[flows.indexOf(entry)];row.retirementConfirmed=true;row.terminalStatus=result.status;
  }catch{report.errors.push({stage:'FLOW_CLEANUP',code:'OWNED_FLOW_RETIREMENT_UNCONFIRMED'});}}
  if(controller){try{report.resourceCleanup=await controller.cleanup();report.configurationReadback=await controller.invariantReadback();}
   catch{report.errors.push({stage:'RESOURCE_CLEANUP',code:'OWNED_RESOURCE_CLEANUP_UNCONFIRMED'});}}
  for(const holder of holders){try{assert(holder.session,'Session creation outcome unknown');
   report.closedWalletSessions.push(await closeControlSession(holder.session,holder.context));}
   catch{report.errors.push({stage:'WALLET_CLEANUP',code:'OWNED_WALLET_CLEANUP_UNCONFIRMED'});}}
  for(const c of contexts.filter(c=>c.kind==='beta')){try{await retire(c);}catch{report.errors.push({stage:'AUTH_CLEANUP',code:'OWNED_AUTH_CLEANUP_UNCONFIRMED'});}}
  for(const c of contexts){try{await c.context.close();}catch{report.errors.push({stage:'CONTEXT_CLEANUP',code:'CONTEXT_CLOSE_UNCONFIRMED'});}}
  if(browser){try{await browser.close();}catch{report.errors.push({stage:'BROWSER_CLEANUP',code:'BROWSER_CLOSE_UNCONFIRMED'});}}
  report.devTestWalletAssertions=contract.assertions(report);
  report.devTestWalletCoreAssertions=contract.coreAssertions(report);
  report.authRetirements=contexts.filter(c=>c.kind==='beta').map(c=>({retired:c.retired,...c.retirement}));
  report.cleanup.complete=report.resourceCleanup?.ok===true&&report.configurationReadback?.ok===true
   &&report.walletSessions.length===2&&report.walletSessions.every(s=>s.closed===true)
   &&contexts.filter(c=>c.kind==='beta').every(c=>c.retired)&&report.flows.length===3
   &&report.flows.every(f=>f.retirementConfirmed)&&report.errors.length===0;
  report.engineeringReady=Object.values(report.devTestWalletAssertions).every(v=>v===true)
   &&Object.values(report.devTestWalletCoreAssertions).every(v=>v===true)&&report.cleanup.complete;
  report.state=report.engineeringReady?'FINISHED':'FAILED';
  if(evidence){try{
   applyLocalNativeReadiness(report,evidence,{ready:report.engineeringReady,cleanupComplete:report.cleanup.complete});
   if(report.engineeringReady)await evidence.complete();
  }catch{report.functionalReady=false;report.operations_verified=false;report.state='FAILED';
   report.errors.push({stage:'EVIDENCE_FINALIZATION',code:'SOURCE_BOUND_EVIDENCE_UNCONFIRMED'});
  }finally{evidence.close();}}
  save();if(report.state!=='FINISHED')process.exitCode=1;
 }
 return report;
}
module.exports={main};
if(require.main===module)main().catch(()=>{process.stderr.write('Dev/test wallet preparation failed.\n');process.exitCode=1;});
