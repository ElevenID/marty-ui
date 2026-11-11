'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {createHash}=require('node:crypto');
const m=require('../../scripts/northstar_runtime_scope.cjs');
const {mountDigest}=require('./beta-resource-runtime');
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'northstar-native-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const file=path.join(root,'transport.json');fs.writeFileSync(file,JSON.stringify({engineId:'reviewed-engine'}));
 const input={recorder:{repository:'/reviewed/recorder',revision:'a'.repeat(40)},engineId:'reviewed-engine',
  dockerTransport:{path:file,sha256:createHash('sha256').update(fs.readFileSync(file)).digest('hex')},
  dockerCanary:{path:'/bound/canary.json',sha256:'b'.repeat(64)}};
 const calls=[],row={Mounts:[{Type:'volume',Name:'c'.repeat(64),Source:'/var/lib/docker/volumes/'+ 'c'.repeat(64)+'/_data',Destination:'/openbao/data',RW:true}]};
 const module={ENV:'NATIVE_DESCRIPTOR',CANARY_ENV:'NATIVE_CANARY',createDockerTransport(options){calls.push(options);return {
  native:true,requireStdinCanary(){calls.push('canary');},read(args){calls.push(args);return JSON.stringify([row]);}};}};
 const bindSource=(repo,revision)=>calls.push({repo,revision});
 return {input,module,bindSource,calls,row};
}
test('uses bound native factory, source, canary and descriptor rather than Windows CLI projection',t=>{
 const f=fixture(t),read=m.nativeRead(f.input,{bindSource:f.bindSource,transportModule:f.module});
 assert.deepEqual(f.calls[0],{repo:f.input.recorder.repository,revision:f.input.recorder.revision});
 assert.equal(f.calls[1].functionalRerun,true);
 assert.equal(f.calls[1].environment.NATIVE_DESCRIPTOR,f.input.dockerTransport.path);
 assert.equal(f.calls[1].environment.NATIVE_DESCRIPTOR_SHA256,f.input.dockerTransport.sha256);
 assert.equal(f.calls[1].environment.NATIVE_CANARY,f.input.dockerCanary.path);
 assert.equal(f.calls[1].environment.NATIVE_CANARY_SHA256,f.input.dockerCanary.sha256);
 assert.equal(f.calls[2],'canary');
 const observed=JSON.parse(read(['inspect','known-cid']))[0];
 const desktop=structuredClone(f.row);desktop.Mounts[0].Source=desktop.Mounts[0].Name;
 assert.notEqual(mountDigest(desktop),mountDigest(f.row)); // Opaque volume sources stay strict.
 assert.equal(mountDigest(observed),mountDigest(f.row));
 const drift=structuredClone(observed);drift.Mounts[0].Source+='/foreign';
 assert.notEqual(mountDigest(drift),mountDigest(observed));
});
test('engine mismatch refuses before native factory',t=>{
 const f=fixture(t);f.input.engineId='foreign';
 assert.throws(()=>m.nativeRead(f.input,{bindSource:f.bindSource,transportModule:f.module}),/SCOPE_NATIVE_ENGINE_CHANGED/);
 assert.equal(f.calls.length,1);
});
test('source mismatch refuses before native factory',t=>{
 const f=fixture(t);
 assert.throws(()=>m.nativeRead(f.input,{bindSource(){throw Error('source refused');},transportModule:f.module}),/source refused/);
 assert.equal(f.calls.length,0);
});
test('cannot fall back to CLI or continue without canary proof',t=>{
 const f=fixture(t);
 for(const native of [false,true]){
  const module={...f.module,createDockerTransport(){return {native,requireStdinCanary(){throw Error('SCOPE_CANARY_CHANGED');}};}};
  assert.throws(()=>m.nativeRead(f.input,{bindSource:f.bindSource,transportModule:module}),native?/SCOPE_CANARY_CHANGED/:/SCOPE_NATIVE_TRANSPORT_REQUIRED/);
 }
});
test('diagnostics retain fixed class and code without provider text, values or digests',()=>{
 const error=new assert.AssertionError({message:'RESOURCE_PRESERVED_MOUNT_CHANGED:openbao\nactual-secret-value',actual:'private',expected:'other'});
 assert.deepEqual(m.safeFailure(error),{schema:'marty.northstar-runtime-scope-failure/v1',errorClass:'AssertionError',code:'RESOURCE_PRESERVED_MOUNT_CHANGED'});
 for(const message of ['token=private-value','/private/credential/path','RESOURCE_CHANGED token=secret']){
  const safe=m.safeFailure(new Error(message));assert.equal(safe.code,'SCOPE_NATIVE_VERIFICATION_FAILED');assert(!JSON.stringify(safe).includes('private'));
 }
});


test('native failures preserve fixed code and bounded summary without any provider payload',()=>{
 const error=Object.assign(Error('secret-provider-token /private/path'),{code:'NATIVE_DOCKER_SYNC_FAILED',operationSummary:{status:4294967295,timedOut:false,signalled:true,stdoutBytes:0,stderrBytes:43,stderr:'secret-provider-token'}});
 const value=m.safeFailure(error);assert.equal(value.code,'NATIVE_DOCKER_SYNC_FAILED');assert.deepEqual(value.operationSummary,{status:4294967295,timedOut:false,signalled:true,stdoutBytes:0,stderrBytes:43});assert(!JSON.stringify(value).includes('secret'));
 const invalid=m.safeFailure({...error,operationSummary:{status:true,timedOut:'secret',signalled:1,stdoutBytes:64*1024**2+1,stderrBytes:-1}});
 assert.deepEqual(invalid.operationSummary,{status:null,timedOut:false,signalled:false,stdoutBytes:null,stderrBytes:null});
 const foreign=m.safeFailure({code:'secret-code',message:'private token',operationSummary:error.operationSummary});assert.equal(foreign.code,'SCOPE_NATIVE_VERIFICATION_FAILED');assert(!Object.hasOwn(foreign,'operationSummary'));
});
