"use strict";
// Unit metadata controls stop before resource qualification or any Docker read.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const runtime=require('./functional-debug-runtime'),owner=require('./beta-resource-runtime');
function fixture(t,ack){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'maintenance-ack-control-'));t.after(()=>{
  const target=path.resolve(root),temporary=path.resolve(os.tmpdir());
  assert.equal(path.dirname(target),temporary);assert(path.basename(target).startsWith('maintenance-ack-control-'));
  assert(!fs.lstatSync(target).isSymbolicLink());assert.equal(fs.realpathSync(target),target);
  fs.rmSync(target,{recursive:true});
 });
 const file=(name,value)=>{const p=path.join(root,name),raw=Buffer.from(JSON.stringify(value));fs.writeFileSync(p,raw);return {path:p,bytes:raw.length,sha256:crypto.createHash('sha256').update(raw).digest('hex')};};
 const runId='8b5f5d22-eb3a-4a7f-b9e7-2cdcb651c8e0',runtimeBefore=file('running-before.json',{}),rootProof={device:1,inode:2,uid:1000,mode:448,root:'/private/d02-build-journal-'+runId};
 const job={state:'COMPLETE',exitCode:0,jobClosed:true,terminalActiveProcesses:0,timedOut:false,forcedTermination:false,cancelled:false,hostMarginBreached:false};
 const state={schema:'marty.d12-current-native-operation/v1',runId,phase:'EFFECT_ACKNOWLEDGED',acknowledgedStep:ack,pendingStep:null,pendingArgv:null};
 const row=document=>({present:true,sha256:'a'.repeat(64),identity:{uid:1000,nlink:1,mode:420},document});
 const read=[{state:'EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE',mountReadOnly:true,root:{...rootProof,gid:1000},files:{
  'build-apply-intent.json':row({schema:'marty.d12-current-apply-intent/v1',runId,runtimeBefore}),
  'build-state.json':row(state),'build-receipt.json':{present:false},'configuration-receipt.json':{present:false}}}];
 const recovery={schema:'marty.d12-maintenance-resource-recovery/v1',runId,runtimeBefore,
  operationJournal:file('backend.json',{rootProof}),journalRead:null,reconciliationJob:file('read-job.json',job),
  failedCutoverJob:file('failed-job.json',{...job,state:'FAILED',exitCode:1}),resourceBefore:file('resources.json',{}),resourceBeforeJob:file('resource-job.json',job),postCreate:{}};
 let dockerReads=0;const barrier=new Error('CONTROL_AFTER_CHECKPOINT_BEFORE_RESOURCE_QUALIFICATION');
 const invoke=()=>{recovery.journalRead=file('journal-read.json',read);const ref=file('recovery.json',recovery);const saved=owner.restartAuthority;
  owner.restartAuthority=()=>{throw barrier;};try{return runtime.verifyMaintenanceRuntime({resourceRestart:{}},{recoveryRef:ref,readDocker:()=>{dockerReads++;throw new Error('DOCKER_READ_FORBIDDEN');}});}finally{owner.restartAuthority=saved;}};
 return {state,read,invoke,barrier,dockerReads:()=>dockerReads};
}
for(const ack of ['CREATE_SELECTED','REPLACE_CREATED_CREDENTIAL_GENERATION'])test('maintenance checkpoint accepts only acknowledged '+ack+' before qualification',t=>{
 const f=fixture(t,ack);assert.throws(f.invoke,error=>error===f.barrier);assert.equal(f.dockerReads(),0);
});
for(const fault of ['wrong-ack','pending','receipt','root'])test('maintenance replacement checkpoint refuses '+fault,t=>{
 const f=fixture(t,'REPLACE_CREATED_CREDENTIAL_GENERATION');
 if(fault==='wrong-ack')f.state.acknowledgedStep='START_auth';
 if(fault==='pending')f.state.pendingStep='INSPECT_CREATED';
 if(fault==='receipt')f.read[0].files['configuration-receipt.json'].present=true;
 if(fault==='root')f.read[0].root.inode++;
 assert.throws(f.invoke,error=>error!==f.barrier);assert.equal(f.dockerReads(),0);
});
