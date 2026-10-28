'use strict';
// SOURCE-ONLY process/secret-transport control; this does not exercise Canvas or a wallet.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {fork}=require('node:child_process'),test=require('node:test');
const name='CANVAS_OSS_OWNED_BOUNDARY_TEST_SECRET';
if(process.env.CANVAS_OWNED_BOUNDARY_CHILD==='1'){
 const stock=require('./run-canvas-oss-standard-contract');
 try{
  const evidence={functionalRuntimeBinding:{scope:'FUNCTIONAL_ONLY'},ownedWalletBinding:{
   kind:'OWNED_NATIVE_WALLET_V1',scope:'FUNCTIONAL_ONLY',releaseQualified:false,
   recordingQualified:false,origin:process.env.MARTY_TEST_WALLET_ORIGIN}};
  const boundary=stock.requireOwnedNativeExecutionBoundary(evidence);
  assert.equal(boundary.release_qualified,false);assert.equal(boundary.recording_qualified,false);
  assert.equal(stock.requireSecretFile(name),'SOURCE_ONLY_VALUE');
  process.env[name]='SOURCE_ONLY_RAW';assert.throws(()=>stock.requireSecretFile(name));delete process.env[name];
  process.env[name+'_FILE']=path.join(os.tmpdir(),'outside-owned-root');
  assert.throws(()=>stock.requireSecretFile(name));
  process.send({ok:true});
 }catch(error){process.send({ok:false,message:error.message});process.exitCode=1;}
}else{
 test('Windows native Canvas boundary needs recorder IPC and host-private file transport',async t=>{
  if(process.platform!=='win32')return t.skip('Reviewed native wallet path requires Windows');
  const privateRoot=path.join(os.homedir(),'.codex','private');
  const root=fs.mkdtempSync(path.join(privateRoot,'canvas-owned-boundary-source-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const secretFile=path.join(root,'bounded.txt');fs.writeFileSync(secretFile,'SOURCE_ONLY_VALUE\n');
  const env={...process.env,CANVAS_OWNED_BOUNDARY_CHILD:'1',CANVAS_OSS_EXECUTION_BOUNDARY:'local_owned_windows_functional',
   CANVAS_OSS_SECRET_TRANSPORT:'owned_host_private_files',CANVAS_OSS_OWNED_SECRET_ROOT:root,
   CANVAS_OSS_DRIVER_SOURCE_SHA:'a'.repeat(40),MARTY_TEST_WALLET_ORIGIN:'http://127.0.0.1:8791',
   RECORD_VIDEO:'0',[name+'_FILE']:secretFile};
  const child=fork(__filename,[],{env,stdio:['ignore','ignore','pipe','ipc'],windowsHide:true});
  let stderr='';child.stderr.on('data',chunk=>{stderr+=chunk.toString().slice(0,1000)});
  const message=await new Promise((resolve,reject)=>{child.once('message',resolve);child.once('error',reject);});
  const exit=await new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
  assert.deepEqual(message,{ok:true},stderr);assert.deepEqual(exit,{code:0,signal:null});
 });
}
