'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'verify-beta-credential-login.js'),'utf8');
function launch(run){
 const body=source.slice(source.indexOf('async function main('),source.indexOf('\nif (require.main === module)'));
 let created=0,closed=0;const evidence={close(){closed++;}};
 const main=vm.runInNewContext(body+'\nmain',{assert,createDemoLiveEvidence:async()=>{created++;return evidence;},runCredentialLogin:run});
 return {main,evidence,counts:()=>({created,closed})};
}
test('primary membership uses exact shared live owner and closes IPC after success',async()=>{
 let actual;const x=launch(async options=>{actual=options;return 'complete';});
 assert.equal(await x.main({retainedMembership:true}),'complete');assert.equal(actual.retainedMembership,true);assert.equal(actual.retainedFirstParty,false);assert.equal(actual.evidence,x.evidence);assert.deepEqual(x.counts(),{created:1,closed:1});
});
test('primary membership closes IPC on actual shared-driver failure',async()=>{
 const x=launch(async()=>{throw Error('owned cleanup refused');});await assert.rejects(x.main({retainedMembership:true}),/owned cleanup refused/);assert.deepEqual(x.counts(),{created:1,closed:1});
});
test('SDK control and legacy callers retain separate modes',async()=>{
 let options;const x=launch(async o=>{options=o;});await x.main({retainedFirstParty:true});assert.equal(options.retainedMembership,false);assert.equal(options.retainedFirstParty,true);
 const y=launch(async o=>{assert.equal(o,undefined);});await y.main();assert.deepEqual(y.counts(),{created:0,closed:0});
});
test('ambiguous or nonboolean modes refuse before IPC or product calls',async()=>{
 const x=launch(async()=>assert.fail('driver must not run'));await assert.rejects(x.main({retainedMembership:true,retainedFirstParty:true}),/Select one/);await assert.rejects(x.main({retainedMembership:'true'}));assert.deepEqual(x.counts(),{created:0,closed:0});
});
test('primary shares owned receipt, exact account, retirement and readiness gates while SDK assertions stay scoped',()=>{
 for(const required of ['const ownedMembership = retainedFirstParty || retainedMembership','retainSummary: ownedMembership','report.cleanup = await control.cleanup()','report.authoringSessionsRetired === true','walletSession?.evidence.closed === true','applyLocalNativeReadiness(report, evidence','report.completion.authenticatedEmail?.toLowerCase() !== inputs.email.toLowerCase()'])assert(source.includes(required),required);
 assert(source.includes('if (retainedFirstParty) {\n        report.firstPartyControlAssertions'));
 assert(source.includes('do not qualify holder cancellation, untrusted-issuer or expired-offer behavior, or an independent wallet'));
});

function retirementFixture({denied=true}={}) {
 let stored=null,retired=0,disposed=0,sent=null;
 const custody={retain(role,v){assert.equal(role,'betaAdminSession');stored=JSON.parse(v);},retire(){retired++;return true;}};
 const body=source.slice(source.indexOf('function membershipSessionRetirement('),source.indexOf('\nasync function runCredentialLogin('));
 const factory=vm.runInNewContext(body+'\nmembershipSessionRetirement',{assert,BETA_ORIGIN:'https://beta.elevenidllc.com',request:{},createCanvasCaptureCustody:()=>custody,
  createOriginalCookieSessionContext:async(_,cookies)=>{sent=cookies;return {isolated:{dispose:async()=>{disposed++;}},session:{original:cookies}};},
  retireCanvasBetaSession:async(session,c)=>{assert.equal(session.original[0].value,'ORIGINAL');assert.equal(c,custody);if(!denied)throw Error('Original cookie still authorized');return {logoutStatus:302,oldCookieAuthenticated:false};}});
 return {factory,state:()=>({stored,retired,disposed,sent})};
}
test('logout and denial use captured original cookie after browser jar clears; benign preference retained',async()=>{
 const x=retirementFixture(),owner=x.factory('00000000-0000-4000-8000-000000000001');let cookies=[{name:'sessionId',value:'ORIGINAL'},{name:'activeOrg',value:'org',secure:false}];
 await owner.capture('admin',{cookies:async()=>cookies});cookies=[];const proof=await owner.retire();assert.equal(proof.complete,true);assert.equal(proof.sessions[0].originalCookieVerified,true);assert.equal(x.state().retired,1);assert.equal(x.state().disposed,1);assert.equal(x.state().sent[1].name,'activeOrg');assert(!JSON.stringify(proof).includes('ORIGINAL'));
});
test('unconfirmed original-cookie denial preserves custody and refuses retirement proof',async()=>{
 const x=retirementFixture({denied:false}),owner=x.factory('00000000-0000-4000-8000-000000000001');await owner.capture('admin',{cookies:async()=>[{name:'sessionId',value:'ORIGINAL'}]});const proof=await owner.retire();assert.equal(proof.complete,false);assert.equal(x.state().retired,0);assert.equal(x.state().disposed,1);
});
