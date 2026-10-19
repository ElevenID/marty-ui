const assert=require('node:assert/strict');
const test=require('node:test');
const vm=require('node:vm');
const path=require('node:path');
const {guards,chromeArguments,observeNativeCredentialApi,cancellationAssertions,flowSql}=require('./audit-beta-holder-cancel');
const validEnv=()=>({BETA_ORIGIN:'https://beta.elevenidllc.com',MARTY_TEST_WALLET_ORIGIN:'http://127.0.0.1:8787',D05_SYNTHETIC_FIXTURE:'1',D05_NATIVE_CHOOSER_CANCEL:'1',RECORD_VIDEO:'0',TEST_ADMIN_EMAIL:'unit@example.test',TEST_ADMIN_PASSWORD:'unit-only',MARTY_TEST_WALLET_HOLDER_KID:'did:example:unit',CHROME_BINARY:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'});

test('actual release preflight accepts v258 and rejects stale or mixed product bindings',()=>{
  const {assertProductBinding}=require('./audit-beta-holder-cancel');
  const revision='33330c2a0bec50e30ca09cb9d61eb532e75361f2';
  const release={marty_ui_sha:revision,deployment_release_marker:'beta-v258-33330c2a0bec',component_revisions:Object.fromEntries(['marty-ui','marty-ui-auth','marty-ui-presentation-policy'].map(name=>[name,revision]))};
  assertProductBinding(release);
  assert.throws(()=>assertProductBinding({...release,marty_ui_sha:'4381c9cdec45263010f1386366b2a82647688507'}));
  assert.throws(()=>assertProductBinding({...release,deployment_release_marker:'beta-v257-4381c9cdec45'}));
  for(const name of Object.keys(release.component_revisions))assert.throws(()=>assertProductBinding({...release,component_revisions:{...release.component_revisions,[name]:'4381c9cdec45263010f1386366b2a82647688507'}}));
});
test('cancellation driver fails closed outside exact beta/synthetic/unrecorded scope',()=>{
  guards(validEnv());
  for(const [key,value] of Object.entries({BETA_ORIGIN:'https://production.example',MARTY_TEST_WALLET_ORIGIN:'https://wallet.example',D05_SYNTHETIC_FIXTURE:'0',D05_NATIVE_CHOOSER_CANCEL:'0',RECORD_VIDEO:'1',NODE_TLS_REJECT_UNAUTHORIZED:'0',BETA_LOCAL_PROXY:'1',CHROME_BINARY:'other.exe'}))assert.throws(()=>guards({...validEnv(),[key]:value}));
});
test('Chrome launch contains no fake credential UI, auth substitution, or disabled TLS flag',()=>{
  const args=chromeArguments(path.resolve('owned-profile'));
  assert.ok(args.includes('--remote-debugging-address=127.0.0.1'));
  assert.ok(args.some(value=>value.startsWith('--user-data-dir=')));
  assert.ok(args.every(value=>!/fake|ignore-certificate|disable-web-security|enable-features/.test(value)));
});
function facts(){return {nativeCancel:{state:'NATIVE_CANCEL_INVOKED'},nativeCall:{errorName:'NotAllowedError'},submissionRequests:0,flow:{nonce_consumptions:0,callback_count:0,completed:false,result_present:false},authenticated:false,pendingStatus:'pending',recovered:true};}
test('NotAllowedError alone never proves holder cancellation',()=>{
  assert.ok(Object.values(cancellationAssertions(facts())).every(Boolean));
  assert.equal(cancellationAssertions({...facts(),nativeCancel:undefined}).native_chooser_cancel,false);
  assert.equal(cancellationAssertions({...facts(),nativeCall:{errorName:'AbortError'}}).native_chooser_cancel,false);
  assert.equal(cancellationAssertions({...facts(),nativeCall:{errorName:'NotAllowedError',returnedCredential:true}}).native_chooser_cancel,false);
});
test('presentation/session side effects and missing recovery fail their proof gates',()=>{
  assert.equal(cancellationAssertions({...facts(),submissionRequests:1}).no_presentation_submitted,false);
  assert.equal(cancellationAssertions({...facts(),flow:{...facts().flow,nonce_consumptions:1}}).no_presentation_submitted,false);
  assert.equal(cancellationAssertions({...facts(),authenticated:true}).no_session_on_cancel,false);
  assert.equal(cancellationAssertions({...facts(),pendingStatus:'completed'}).no_session_on_cancel,false);
  assert.equal(cancellationAssertions({...facts(),recovered:false}).trusted_recovery,false);
});
test('flow metadata query rejects malformed or injected identities',()=>{
  assert.match(flowSql('00000000-0000-4000-8000-000000000001'),/flow_nonce_consumptions/);
  assert.throws(()=>flowSql("x'; DELETE FROM flow_service.flow_instances;--"));
});
test('native observer refuses a JavaScript replacement instead of fabricating a native call',()=>{
  const replacement=()=>Promise.reject(new Error('test only'));
  const sandbox={navigator:{credentials:{get:replacement}},window:{}};
  vm.runInNewContext(`(${observeNativeCredentialApi.toString()})()`,sandbox);
  assert.equal(sandbox.window.__d05NativeObservation.nativeImplementation,false);
  assert.equal(sandbox.navigator.credentials.get,replacement);
});
test('observer forwards native Promise resolution and original rejection unchanged (unit mechanics only)',async()=>{
  for(const reject of [false,true]){
    const sandbox={navigator:{credentials:{get:(reject?Promise.reject:Promise.resolve).bind(Promise)}},window:{}};
    vm.runInNewContext(`(${observeNativeCredentialApi.toString()})()`,sandbox);
    const original={name:'NotAllowedError',digital:{requests:[{protocol:'unit-test-only'}]}};
    if(reject)await assert.rejects(sandbox.navigator.credentials.get(original),error=>error===original);
    else assert.equal(await sandbox.navigator.credentials.get(original),original);
    const observed=sandbox.window.__d05NativeObservation.calls[0];
    assert.equal(observed.settled,true);assert.equal(observed.errorName,reject?'NotAllowedError':undefined);
  }
});

test('standard Fetch Response preflight accepts JSON and rejects HTTP failure before parsing',async()=>{
  const {fetchPublicJson}=require('./audit-beta-holder-cancel');
  const http=require('node:http');
  const server=http.createServer((req,res)=>{res.writeHead(req.url==='/release'?200:503,{'Content-Type':'application/json'});res.end(JSON.stringify({source:'unit'}));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const base=`http://127.0.0.1:${server.address().port}`;
    assert.deepEqual(await fetchPublicJson(base+'/release'),{source:'unit'});
    await assert.rejects(fetchPublicJson(base+'/unavailable'),/Public beta HTTP preflight failed/);
  }finally{await new Promise(resolve=>server.close(resolve));}
});
test('owned CDP teardown closes contexts then browser process before disconnect',async()=>{
  const {closeOwnedBrowser}=require('./audit-beta-holder-cancel');const calls=[];
  const child={exitCode:null,signalCode:null};
  await closeOwnedBrowser({child,contexts:[{close:async()=>calls.push('context')}],browser:{
    newBrowserCDPSession:async()=>({send:async method=>{calls.push(method);child.exitCode=0;}}),close:async()=>calls.push('disconnect')},
    forceStop:async()=>assert.fail('graceful exit must not force terminate')});
  assert.deepEqual(calls,['context','Browser.close','disconnect']);
});
test('owned teardown invokes guarded fallback and fails closed if process survives',async()=>{
  const {closeOwnedBrowser}=require('./audit-beta-holder-cancel');let stops=0;
  await assert.rejects(closeOwnedBrowser({child:{exitCode:null,signalCode:null},forceStop:async()=>stops++,wait:async()=>{}}),/preserve profile/);
  assert.equal(stops,1);
  const child={exitCode:null,signalCode:null};
  await closeOwnedBrowser({child,forceStop:async()=>{child.exitCode=1;},wait:async()=>{}});
});

test('actual auth controller waits for signed request then real click invokes credentials and displays native cancellation',async()=>{
  const fs=require('node:fs');
  const asset=fs.readFileSync(path.resolve(__dirname,'../../services/auth/assets/credential-login.js'),'utf8');
  let resolveFetch,rejectCredential;const calls=[];const handlers={};
  const attributes={};
  const walletLink={style:{},setAttribute:(k,v)=>attributes[k]=v,removeAttribute:k=>delete attributes[k],getAttribute:k=>attributes[k],addEventListener:(event,fn)=>handlers[event]=fn};
  const status={innerHTML:''};
  const bodyAttrs={'data-nonce':'unit-only','data-dc-api-request-url':'/unit-request','data-dc-api-submit-url':'/unit-submit','data-dc-api-protocol':'openid4vp-v1-signed'};
  const sandbox={document:{body:{getAttribute:k=>bodyAttrs[k]},getElementById:id=>({'wallet-link':walletLink,status}[id]||null),querySelector:()=>null},
    window:{isSecureContext:true,location:{origin:'https://unit.invalid'}},navigator:{userAgent:'Desktop',credentials:{get:options=>{calls.push(options);return new Promise((_,reject)=>rejectCredential=reject);}}},
    DigitalCredential:{userAgentAllowsProtocol:()=>true},fetch:()=>new Promise(resolve=>resolveFetch=resolve),setInterval:()=>1,clearInterval:()=>{},console};
  vm.runInNewContext(asset,sandbox);
  const click=()=>handlers.click({preventDefault(){}});
  click();click();assert.equal(calls.length,0);assert.match(status.innerHTML,/Preparing the wallet chooser/);
  // Complete the real controller's prefetch promise; no fake readiness variable.
  resolveFetch(new Response('synthetic-unit-request',{status:200}));
  await new Promise(resolve=>setImmediate(resolve));
  click();assert.equal(calls.length,1);assert.equal(calls[0].digital.requests[0].data.request,'synthetic-unit-request');
  assert.equal(attributes['data-busy'],'true');
  rejectCredential(Object.assign(new Error('unit native boundary simulation'),{name:'NotAllowedError'}));
  await new Promise(resolve=>setImmediate(resolve));
  assert.match(status.innerHTML,/Wallet request was canceled/);assert.equal(attributes['data-busy'],undefined);
});
test('failure observations never preserve unknown status or arbitrary error strings',()=>{
  const {classifyStatus,safeErrorName}=require('./audit-beta-holder-cancel');
  assert.equal(classifyStatus('secret arbitrary URL and nonce'),'OTHER_NONEMPTY');
  assert.equal(safeErrorName('secret arbitrary string'),'OTHER_ERROR');
  assert.equal(classifyStatus('Preparing the wallet chooser. Tap Open wallet again in a moment.'),'PREPARING_REQUEST');
});
