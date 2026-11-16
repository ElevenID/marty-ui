'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm'),{createRequire}=require('node:module'),{createHash}=require('node:crypto');

// Exercise the production bridge; only its existing Recorder/source-read boundaries
// are substituted. This is forwarding/error-contract coverage, not a runtime proof.
function bridge({ob3=true,invalid=false,mismatch=false}={}){
 const filename=path.join(__dirname,'demo-live-evidence.js'),real=createRequire(filename),helper=path.join(os.homedir(),'.codex','private','bridge-source','externalLiveEvidenceHelper.js'),receipt=path.join(os.homedir(),'.codex','private','bridge-source','functional-runtime.json');
 const bytes=Buffer.from('source boundary'),calls=[];
 const configuration={path:path.join(os.homedir(),'.codex','private','bridge-source','membership-badge-login-expired-offer.json'),sha256:'c'.repeat(64),bytes:100};
 const readiness={readinessScope:'OB3_FUNCTIONAL_ONLY',fullStackQualified:false,ob3RuntimeReady:true,nativeRuntimeReady:false,deferredRoles:['passport-beta-bureau'],deferredFailure:{path:receipt,sha256:'d'.repeat(64),bytes:100},allowedScenarios:['D05_MEMBERSHIP_EXPIRED_NEGATIVE']};
 const acknowledged={kind:'FUNCTIONAL_RUNTIME_V2',profileSha256:'a'.repeat(64),receiptSha256:'b'.repeat(64),scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,...(ob3?{ob3Readiness:readiness,ob3Configuration:configuration}:{})};
 const environment={RECORD_VIDEO:'0',DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT:receipt,DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256:acknowledged.receiptSha256,DEMO_EXECUTION_EVIDENCE_HELPER:helper,DEMO_EXECUTION_EVIDENCE_HELPER_SHA256:createHash('sha256').update(bytes).digest('hex')};
 const protocol={validateFunctionalRuntimeContext(value){calls.push({phase:'validate',value});if(invalid)throw Error('RECORDER_REFUSED_CONTEXT');return acknowledged;},functionalRuntimeContext(value){calls.push({phase:'project',value});return mismatch?{...acknowledged,receiptSha256:'e'.repeat(64)}:acknowledged;}};
 const loader={loadFunctionalRuntimeObservation(file,hash,options){calls.push({phase:'load',file,hash,options});return {kind:'TEST_RECORDED_BOUNDARY'};}};
 const sourceFs={lstatSync(){return {isSymbolicLink:()=>false};},statSync(){return {isFile:()=>true};},readFileSync(){return bytes;}};
 const m={exports:{}};
 const requireBoundary=name=>name==='node:fs'?sourceFs:path.basename(name)==='externalLiveEvidence.js'?protocol:path.basename(name)==='canvasNativeRuntime.js'?loader:real(name);
 vm.runInThisContext('(function(require,module,exports,__filename,__dirname){'+fs.readFileSync(filename,'utf8')+'\n})',{filename})(requireBoundary,m,m.exports,filename,__dirname);
 return {api:m.exports,calls,configuration,readiness,acknowledged,environment,client:{functionalRuntimeBinding:acknowledged}};
}
test('OB3 bridge forwards exact Recorder-validated config and preserves partial readiness metadata',()=>{
 const b=bridge(),report={releaseReady:true};
 assert.equal(b.api.applyLocalNativeReadiness(report,b.client,{ready:true,cleanupComplete:true},b.environment),true);
 assert.deepEqual(b.calls.map(row=>row.phase),['validate','load','project']);
 const load=b.calls[1];assert.equal(load.options.ob3Configuration,b.configuration);assert.equal(load.options.functionalRerun,true);
 assert.equal(load.hash,b.acknowledged.receiptSha256);
 assert.equal(report.localFunctionalRuntime.ob3Configuration,b.configuration);assert.equal(report.localFunctionalRuntime.ob3Readiness,b.readiness);
 assert.equal(report.localFunctionalRuntime.ob3Readiness.fullStackQualified,false);assert.equal(report.releaseReady,false);assert.equal(report.demo_qualified,false);assert.equal(report.localFunctionalRuntime.recordingQualified,false);
});
test('Recorder context refusal, mounted acknowledgement mismatch and recording request remain hard failures',()=>{
 const invalid=bridge({invalid:true});assert.throws(()=>invalid.api.applyLocalNativeReadiness({},invalid.client,{ready:true,cleanupComplete:true},invalid.environment),/RECORDER_REFUSED_CONTEXT/);assert.equal(invalid.calls.some(row=>row.phase==='load'),false);
 const mismatch=bridge({mismatch:true});assert.throws(()=>mismatch.api.applyLocalNativeReadiness({},mismatch.client,{ready:true,cleanupComplete:true},mismatch.environment),/differs from mounted receipt/);
 const recording=bridge();recording.environment.RECORD_VIDEO='1';assert.throws(()=>recording.api.applyLocalNativeReadiness({},recording.client,{ready:true,cleanupComplete:true},recording.environment),/cannot record/);assert.equal(recording.calls.length,0);
});
test('legacy full-runtime options/report shape and no-local-binding behavior remain unchanged',()=>{
 const b=bridge({ob3:false}),report={};assert.equal(b.api.applyLocalNativeReadiness(report,b.client,{ready:true,cleanupComplete:true},b.environment),true);
 assert.deepEqual(b.calls[1].options,{functionalRerun:true});assert.deepEqual(report.localFunctionalRuntime,{profileSha256:b.acknowledged.profileSha256,receiptSha256:b.acknowledged.receiptSha256,scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false});
 const untouched={releaseReady:true};assert.equal(b.api.applyLocalNativeReadiness(untouched,{}, {ready:true,cleanupComplete:true},{}),true);assert.deepEqual(untouched,{releaseReady:true});
});
