
'use strict';
// Wrapper/transport controls only: no KMS, browser, native process or feature proof.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm');
function fixture(t,mode='functional'){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'org-wrapper-control-'));t.after(()=>{const resolved=path.resolve(root);assert.equal(path.dirname(resolved),path.resolve(os.tmpdir()));assert(path.basename(resolved).startsWith('org-wrapper-control-'));assert(!fs.lstatSync(resolved).isSymbolicLink());assert.equal(fs.realpathSync(resolved),resolved);fs.rmSync(resolved,{recursive:true});});
 const python=path.join(root,'python.exe'),validator=path.join(root,'validator.exe');fs.writeFileSync(python,'source-control');fs.writeFileSync(validator,'source-control');
 const file=path.resolve(__dirname,'audit-beta-organization-primitives.js'),report={releaseReady:true,release_checks:{status:'pass'},behaviorAssertions:{configure_organization:true,configure_issuer_profiles:true,configure_trust_and_mip_primitives:true,unauthorized_administration_denied:true}},calls=[];
 const env={DEMO_PYTHON_EXECUTABLE:python,DEMO_SIGNING_CAPABILITY_BIN:validator,DEMO_D10_KMS_URL:'https://kms.example.invalid',DEMO_ARTIFACT_DIR:root,RECORD_VIDEO:'0'};
 const source={repository:path.join(root,'objects'),revision:'b'.repeat(40),...(mode==='functional'?{gitExport:{path:path.join(root,'export-manifest.json'),sha256:'c'.repeat(64),bytes:42}}:{})};
 const client={pythonDriverSource:directory=>{calls.push({kind:'source',directory});return source;},...(mode==='functional'?{functionalRuntimeBinding:{scope:'FUNCTIONAL_ONLY'}}:mode==='native'?{nativeRuntimeBinding:{releaseQualified:false}}:{}),runPythonCapture:async args=>{calls.push({kind:'python',args});fs.writeFileSync(path.join(root,'report.json'),JSON.stringify(report));return {transportOnly:true};},close:()=>calls.push({kind:'close'})};
 const boundary=name=>name==='node:child_process'?(()=>{throw Error('Wrapper must not derive source through a Git HEAD subprocess');})():name==='./demo-live-evidence'?{createDemoLiveEvidence:async()=>client,applyLocalNativeReadiness:(value,received,options)=>{assert.equal(received,client);calls.push({kind:'readiness',options});value.releaseReady=false;value.functionalReady=options.ready&&options.cleanupComplete;value.operations_verified=value.functionalReady;value.recordingQualified=false;return value.functionalReady;}}:require(name);
 const m={exports:{}};vm.runInThisContext('(function(require,module,exports,__dirname,process){'+fs.readFileSync(file,'utf8').replace(/^#![^\n]*\n/,'')+'\n})',{filename:file})(boundary,m,m.exports,path.dirname(file),{env});
 return {main:m.exports.main,report,calls,source,client,root,read:()=>JSON.parse(fs.readFileSync(path.join(root,'report.json')))};
}
test('organization wrapper requires all Python assertion result fields before adapting functional IPC reports',async t=>{
 const f=fixture(t);await f.main();assert.equal(f.calls.filter(c=>c.kind==='readiness').length,1);assert.equal(f.read().releaseReady,false);assert.equal(f.read().functionalReady,true);assert.equal(f.calls.filter(c=>c.kind==='close').length,1);assert.equal(f.calls.find(c=>c.kind==='python').args.entrypoint,'scripts/beta_org_console_audit.py');assert.deepEqual(f.calls.find(c=>c.kind==='python').args.args,['--record-video']);assert.equal(f.calls.find(c=>c.kind==='python').args.inputs.recordVideo,false);
});
test('partial loader cannot qualify a missing KMS capability assertion or blocked Python release checks',async t=>{
 for(const change of [r=>r.behaviorAssertions.configure_issuer_profiles=false,r=>delete r.behaviorAssertions.configure_issuer_profiles,r=>r.release_checks.status='blocked',r=>r.releaseReady=false,r=>r.behaviorAssertions.unauthorized_administration_denied=false]){const f=fixture(t);change(f.report);await assert.rejects(f.main(),/actual operations or scoped cleanup incomplete/);assert.equal(f.read().functionalReady,false);assert.equal(f.read().releaseReady,false);assert.equal(f.calls.filter(c=>c.kind==='close').length,1);}
});
test('legacy native mode retains readiness adaptation and unbound default is not relabeled functional',async t=>{
 const old=fixture(t,'native');await old.main();assert.equal(old.calls.filter(c=>c.kind==='readiness').length,1);const normal=fixture(t,'default');await normal.main();assert.equal(normal.calls.filter(c=>c.kind==='readiness').length,0);assert.equal(normal.read().functionalReady,undefined);assert.equal(normal.read().releaseReady,true);
});

test('organization Python caller forwards only the shared owner exact export source and fixed entrypoint',async t=>{
 const f=fixture(t);await f.main();const selected=f.calls.find(c=>c.kind==='source'),python=f.calls.find(c=>c.kind==='python');assert.equal(f.calls.filter(c=>c.kind==='source').length,1);assert.equal(selected.directory,path.resolve(__dirname,'../..'));assert.equal(python.args.repository,f.source.repository);assert.equal(python.args.revision,f.source.revision);assert.equal(python.args.gitExport,f.source.gitExport);assert.equal(python.args.entrypoint,'scripts/beta_org_console_audit.py');assert(f.calls.indexOf(selected)<f.calls.indexOf(python));
});
test('missing source capability or shared-owner changed export refusal cannot fall back to Git HEAD or start Python',async t=>{
 for(const changed of [false,true]){const f=fixture(t);if(changed)f.client.pythonDriverSource=()=>{throw Error('Export byte differs from committed blob');};else delete f.client.pythonDriverSource;await assert.rejects(f.main(),changed?/committed blob/:/Recorder-owned Python source binding/);assert(!f.calls.some(c=>c.kind==='python'));assert(!f.calls.some(c=>c.kind==='readiness'));assert(!fs.existsSync(path.join(f.root,'report.json')));assert.equal(f.calls.filter(c=>c.kind==='close').length,1);}
});
test('shared checkedSource rejection remains terminal without ready/report promotion',async t=>{
 const f=fixture(t);f.client.runPythonCapture=async()=>{throw Error('Python capture source changed');};await assert.rejects(f.main(),/source changed/);assert(!f.calls.some(c=>c.kind==='readiness'));assert(!fs.existsSync(path.join(f.root,'report.json')));assert.equal(f.calls.filter(c=>c.kind==='close').length,1);
});
