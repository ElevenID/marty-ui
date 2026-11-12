'use strict';
// Execute the real consumer function bodies with synthetic browser transport only.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {presentWalletRequest}=require('./demo-wallet-session');
const origin='http://127.0.0.1:8787',requestUri='owned-request';
const consumers=[['lifecycle','audit-beta-credential-lifecycle.js','present'],['primary','verify-beta-credential-login.js','presentBadge'],['organization','audit-beta-org-credential-paths.js','presentWithTestWallet'],['support','audit-beta-membership-support.js','present']];
function page({dialogCount=1,tag='DIALOG',buttonFails=false,dialogFails=false,inputDrift=false,buttonCount=1,responseFails=false,presentFails=false,status=200}={}){
 const calls=[],body=status===200?{ok:true}:{error:'wallet-error',submission:{submitted:true,verifier_http_status:400,verifier_error:'invalid_presentation',private_field:'not-projected'}};
 const response={url:()=>origin+'/api/present',request:()=>({method:()=> 'POST',postDataJSON:()=>({request_uri:requestUri})}),status:()=>status,ok:()=>status===200,json:async()=>body};
 const wallet={url:()=>origin+'/?wallet_run=owned',isClosed:()=>false,
  getByLabel:()=>({fill:async value=>{assert.equal(value,requestUri);calls.push('fill');},inputValue:async()=>inputDrift?'private-other-request':requestUri}),
  waitForResponse:predicate=>{
   const foreignResponses=[
    {...response,url:()=>origin+'/api/presentation-decline'},
    {...response,url:()=> 'https://foreign.example/api/present'},
    {...response,request:()=>({method:()=> 'GET'})},
    {...response,request:()=>({method:()=> 'POST',postDataJSON:()=>({request_uri:'other'})})},
   ];
   for(const foreign of foreignResponses)assert.equal(predicate(foreign),false);
   assert.equal(predicate(response),true);return responseFails?Promise.reject(Error('response-timeout')):Promise.resolve(response);
  },
  getByRole:role=>role==='button'?{click:async()=>{calls.push('Present');if(presentFails)throw Error('present-click-failed');}}:{filter:()=>({waitFor:async()=>{}})},
  locator:()=>({count:async()=>dialogCount,evaluate:async()=>tag,
   waitFor:async ({state})=>{calls.push(state);if(dialogFails)throw Error('dialog-timeout');},
   getByRole:(_role,{name})=>({count:async()=>buttonCount,click:async()=>{calls.push(name);if(buttonFails)throw Error('consent-click-failed');}})})};
 return {wallet,calls,response};
}
function consumer([kind,file,name],f,{allowed=true}={}){
 const source=fs.readFileSync(path.join(__dirname,file),'utf8'),start=source.indexOf('async function '+name+'('),end=source.indexOf('\nasync function ',start+1);
 assert(start>=0&&end>start);assert.match(source,/\{[^}]*presentWalletRequest[^}]*\}\s*=\s*require\('\.\/demo-wallet-session'\)/);
 assert(!/getByRole\('button', \{ name: \/\^present/.test(source),'Direct Present bypass remains in '+file);
 const authPage={waitForURL:async()=>{},locator:()=>({waitFor:async()=>{},innerText:async()=> 'does not trust for sign-in',getByRole:()=>({isVisible:async()=>true})})};
 const globals={URL,assert,presentWalletRequest,TEST_WALLET_ORIGIN:origin,RECORD_VIDEO:true,
  maskProtocolField:async(_page,_label,record)=>{f.calls.push('mask');if(kind==='lifecycle')assert.equal(record,true);},
  showStep:async()=>{},redact:value=>'redacted:'+value,
  startLogin:async()=>({details:{href:requestUri,nonce:'owned-auth'},instancePath:'/v1/flows/instances/owned',binding:{},loginAuthority:{}}),
  observeCredentialLoginBrowser:()=>({completion:async()=>({nonceEvidence:{status:'completed'},browserFinalize:{verified:true},statusObservation:{}})}),
  rebindLoginInstance:async()=>{},requireJson:async()=>({}),nativeLoginResult:()=>({}),
  requireCompletedLoginNonce:value=>assert.equal(value,'completed'),authMe:async()=>({authenticated:allowed,user:{email:'owned@example.test'}}),
  isCredentialLoginDestinationUrl:()=>true};
 const fn=vm.runInNewContext('('+source.slice(start,end).trim()+')',globals);
 if(kind==='support')return fn({authPage,walletPage:f.wallet,authContext:{request:{get:async url=>url.includes('/status?')?{status:()=>200,json:async()=>({status:'failed',reason_code:'issuer_not_trusted'})}:{headers:()=>({})}}},operator:{},fixture:{applicant:{email:'owned@example.test'}},origin:'https://beta.elevenidllc.com',wallet:origin,record:true,waitFor:async operation=>operation(),issuerDid:'did:web:issuer',allowed,step:async()=>{}});
 return fn(f.wallet,requestUri);
}
for(const item of consumers){
 const [kind]=item;
 test(kind+' actual consumer explicitly approves new UI and retains legacy zero-dialog transport',async()=>{
  for(const dialogCount of [0,1]){
   const f=page({dialogCount}),result=await consumer(item,f);
   assert.equal(kind==='primary'?result.accepted:kind==='support'?result.authenticated:result.ok,true);
   assert.deepEqual(f.calls,dialogCount?['mask','fill','Present','visible','Approve','hidden']:['mask','fill','Present']);
  }
 });
 test(kind+' actual consumer never falls back after malformed or failing consent',async()=>{
  for(const options of [{dialogCount:2},{tag:'DIV'},{buttonCount:0},{buttonCount:2},{buttonFails:true},{dialogFails:true},{inputDrift:true},{responseFails:true},{presentFails:true}]){
   const f=page(options);await assert.rejects(()=>consumer(item,f),error=>!String(error).includes('private-other-request'));
   assert(f.calls.filter(x=>x==='Present').length<=1);assert(!f.calls.includes('Cancel'));
   if(options.dialogCount===2||options.tag||options.inputDrift||options.buttonCount!==undefined)assert(!f.calls.includes('Present'));
  }
 });
 test(kind+' actual consumer preserves the real HTTP error contract',async()=>{
  const f=page({status:400});const result=await consumer(item,f,{allowed:false});
  if(kind==='support'){assert.equal(result.authenticated,false);assert.equal(result.walletHttpStatus,400);assert.equal(result.finalizeSetCookie,false);}
  else {assert.equal(kind==='primary'?result.accepted:result.ok,false);assert.equal(result.status,400);assert.equal(result.error,kind==='lifecycle'?'wallet-error':'redacted:wallet-error');
   if(kind==='lifecycle')assert.deepEqual(JSON.parse(JSON.stringify(result.submission)),{submitted:true,verifier_http_status:400,verifier_error:'invalid_presentation'});}
 });
}
