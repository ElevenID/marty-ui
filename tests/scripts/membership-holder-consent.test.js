'use strict';
// Source/transport controls only; no browser, wallet, provider or database effects.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const contract=require('./beta-membership-support-contract');
const origin='https://beta.elevenidllc.com';
const uuid=n=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
function fixture(n=1){
 const instance={id:uuid(n),organization_id:uuid(20),status:'AWAITING_WALLET',created_at:new Date().toISOString(),
  context_data:{callback_url:`http://auth/internal/v1/auth/credential-verified?nonce=auth-${n}`,
   nonce:`flow-${n}`,oid4vp_expected_state:uuid(n),presentation_policy_id:uuid(21),trust_profile_id:null}};
 const details={nonce:`auth-${n}`,href:'openid4vp://authorize?request_uri='+encodeURIComponent(`${origin}/v1/flows/instances/${instance.id}/request?transport=redirect`)};
 const payload={response_mode:'direct_post',response_uri:`${origin}/v1/flows/instances/${instance.id}/submit`,nonce:`flow-${n}`,state:uuid(n)};
 const encode=value=>'header.'+Buffer.from(JSON.stringify(value)).toString('base64url')+'.signature';
 const bind=(value=payload)=>contract.directPostLoginBinding(details,instance,uuid(20),origin,{afterMs:Date.now()-15000,beforeMs:Date.now()+15000},encode(value));
 return {instance,details,payload,bind};
}
const ack={status:200,acknowledged:true,verifierHttpStatus:200,holderDecision:'Cancel',consentProtocol:'EXPLICIT_TEST_WALLET_DIALOG_V1'};
const noSession={authHttpStatus:200,authenticated:false,sessionCookiePresent:false,finalizeStatus:400,finalizeSetCookie:false};
function cancelled(f){return {...f.instance,status:'CANCELLED',error_code:'access_denied',state_history:[{new_state:'CANCELLED',event:'wallet_access_denied',actor:'wallet_submission'}]};}

test('actual direct-post request binds distinct Auth and Flow nonces without claiming signature verification',()=>{
 const f=fixture(),binding=f.bind();assert.equal(binding.requestMetadataSignatureVerified,false);
 assert.notEqual(binding.nonceSha256,binding.flowNonceSha256);
 assert.equal(contract.holderDeclineEvidence(binding,cancelled(f),ack,noSession).holderClickCancel,true);
 for(const change of [{state:'foreign'},{nonce:'foreign'},{response_mode:'dc_api'},{response_uri:'https://foreign.example/submit'}])assert.throws(()=>f.bind({...f.payload,...change}));
 f.details.nonce='unrelated-auth';assert.throws(()=>f.bind());
});

test('delivery ACK cannot replace committed Flow cancellation, its actual cause, or no-session observations',()=>{
 const f=fixture(),binding=f.bind(),after=cancelled(f);
 for(const row of [{...after,status:'AWAITING_WALLET'},{...after,error_code:'admin_cancel'},{...after,state_history:[]},{...after,id:uuid(99)}])assert.throws(()=>contract.holderDeclineEvidence(binding,row,ack,noSession));
 for(const changed of [{...noSession,authenticated:true},{...noSession,sessionCookiePresent:true},{...noSession,finalizeSetCookie:true}])assert.throws(()=>contract.holderDeclineEvidence(binding,after,ack,changed));
});

test('retry must replace RP nonce, Flow, presentation nonce, state and request while retaining governed scope',()=>{
 const first=fixture().bind(),fresh=fixture(2).bind();assert.equal(contract.freshDirectPostLogin(first,fresh),true);
 for(const key of ['instanceId','nonceSha256','flowNonceSha256','stateSha256','requestSha256'])assert.throws(()=>contract.freshDirectPostLogin(first,{...fresh,[key]:first[key]}));
});

function driver(overrides={}){
 const source=fs.readFileSync(path.join(__dirname,'verify-beta-credential-login.js'),'utf8'),module={exports:{}};
 const scopedRequire=name=>Object.hasOwn(overrides,name)?overrides[name]:['fs','path','node:assert/strict'].includes(name)?require(name):name==='./beta-membership-support-contract'?contract:name==='./demo-recording'?{maskProtocolField:async()=>{}}:{};
 vm.runInNewContext(source,{require:scopedRequire,module,__dirname,process:{env:{},argv:[]},URL,Buffer,console,setTimeout,clearTimeout});
 return module.exports;
}
function page(decision,{dialogCount=decision===null?0:1,tag="DIALOG",visible=true}={}){
 const calls=[],route=decision==='Cancel'?'/api/presentation-decline':'/api/present';
 const response={url:()=>`http://127.0.0.1:8787${route}`,request:()=>({method:()=> 'POST',postDataJSON:()=>({request_uri:'request'})}),status:()=>200,ok:()=>true,
  json:async()=>decision==='Cancel'?{acknowledged:true,submission:{verifier_http_status:200}}:{ok:true}};
 const wallet={url:()=> 'http://127.0.0.1:8787/?wallet_run=owned',getByLabel:()=>({fill:async()=>calls.push('fill'),inputValue:async()=> 'request'}),
  waitForResponse:predicate=>{assert.equal(predicate(response),true);return Promise.resolve(response);},
  getByRole:()=>({click:async()=>calls.push('Present')}),
  locator:id=>{assert.equal(id,'#presentation-consent');return {count:async()=>dialogCount,evaluate:async()=>tag,waitFor:async options=>{calls.push(options.state==='hidden'?'closed':'dialog');assert.equal(visible,true);},getByRole:(_role,options)=>({count:async()=>1,click:async()=>calls.push(options.name)})};}};
 return {wallet,calls};
}
test('primary Cancel clicks the real dialog and waits for decline transport without presenting',async()=>{
 const f=page('Cancel'),result=await driver().presentBadge(f.wallet,'request',{holderDecision:'Cancel'});
 assert.deepEqual(f.calls,['fill','Present','dialog','Cancel','closed']);assert.equal(result.acknowledged,true);assert.equal(result.accepted,undefined);
});
test('primary Approve is an explicit dialog action while the old SDK path remains unchanged',async()=>{
 const next=page('Approve');assert.equal((await driver().presentBadge(next.wallet,'request',{holderDecision:'Approve'})).accepted,true);
 assert.deepEqual(next.calls,['fill','Present','dialog','Approve','closed']);
 const shared=page('Approve');const result=await driver().presentBadge(shared.wallet,'request');
 assert.deepEqual(shared.calls,['fill','Present','dialog','Approve','closed']);assert.equal(result.holderDecision,'Approve');assert.equal(result.consentProtocol,'EXPLICIT_TEST_WALLET_DIALOG_V1');
 const old=page(null);await driver().presentBadge(old.wallet,'request');assert.deepEqual(old.calls,['fill','Present']);
});
test('Auth no-session observer checks the real finalize response and rereads the cookie jar',async()=>{
 let reads=0;const context={cookies:async()=>[],request:{get:async url=>url.includes('/finalize?')?
  {status:()=>400,headers:()=>({})}:{status:()=>200,json:async()=>{reads++;return {authenticated:false};}}}};
 const result=await driver().observeDeclinedLogin(context,'auth');assert.equal(result.authenticated,false);assert.equal(reads,2);
 context.cookies=async()=>[{name:'sessionId'}];await assert.rejects(()=>driver().observeDeclinedLogin(context,'auth'));
});


test('unsupported or failed consent UI never falls back to legacy presentation',async()=>{
 for(const options of [{dialogCount:2},{tag:'DIV'},{visible:false}]){
  const f=page('Approve',options);await assert.rejects(()=>driver().presentBadge(f.wallet,'request'));
  assert(!f.calls.includes('Approve'));
 }
 const old=page(null);await assert.rejects(()=>driver().presentBadge(old.wallet,'request',{holderDecision:'Cancel'}));
 assert.deepEqual(old.calls,['fill']);
});

test('known owned Flow is retained before request emission can fail',async()=>{
 const f=fixture(),calls=[];let held;
 const current=driver({'./beta-demo-resource-helpers':{requireJson:async()=>{calls.push('owner-read');return f.instance;}}});
 const page={context:()=>({request:{get:async()=>{calls.push('request');return {status:()=>400};}}})};
 await assert.rejects(()=>current.bindMembershipLogin(page,{},f.details,uuid(20),Date.now(),async binding=>{
  held=binding;calls.push('owned-retained');
 }));
 assert.deepEqual(calls,['owner-read','owned-retained','request']);assert.equal(held.instanceId,f.instance.id);
 assert.equal(held.instancePath,'/v1/flows/instances/'+f.instance.id);
 const {retireLoginFlow}=require('./dev-test-wallet-contract');let state=f.instance;
 const cleanup=await retireLoginFlow({binding:held,readInstance:async()=>state,
  beforeCancel:async()=>calls.push('cleanup-intent'),cancel:async()=>{calls.push(held.instancePath+'/cancel');state={...state,status:'CANCELLED'};return {ok:true};}});
 assert.equal(cleanup.status,'CANCELLED');assert.deepEqual(calls.slice(-2),['cleanup-intent',held.instancePath+'/cancel']);
 let foreignCalls=0;await assert.rejects(()=>retireLoginFlow({binding:held,
  readInstance:async()=>({...f.instance,organization_id:uuid(99)}),beforeCancel:async()=>{},cancel:async()=>{foreignCalls++;}}));
 assert.equal(foreignCalls,0);
});
