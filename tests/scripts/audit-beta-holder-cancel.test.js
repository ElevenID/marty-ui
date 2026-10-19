const assert=require('node:assert/strict');
const test=require('node:test');
const vm=require('node:vm');
const path=require('node:path');
const {guards,chromeArguments,observeNativeCredentialApi,cancellationAssertions,flowSql}=require('./audit-beta-holder-cancel');
const validEnv=()=>({BETA_ORIGIN:'https://beta.elevenidllc.com',MARTY_TEST_WALLET_ORIGIN:'http://127.0.0.1:8787',D05_SYNTHETIC_FIXTURE:'1',D05_NATIVE_CHOOSER_CANCEL:'1',RECORD_VIDEO:'0',TEST_ADMIN_EMAIL:'unit@example.test',TEST_ADMIN_PASSWORD:'unit-only',MARTY_TEST_WALLET_HOLDER_KID:'did:example:unit',CHROME_BINARY:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'});
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
