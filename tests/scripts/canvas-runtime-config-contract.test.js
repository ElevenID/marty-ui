const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {pathToFileURL}=require('node:url');
const test=require('node:test');
const generator=path.resolve(__dirname,'../../scripts/canvas-oss/generate-runtime-config.mjs');
const validator=path.resolve(__dirname,'../../scripts/canvas-oss/validate-runtime-config.mjs');
const contract=import(pathToFileURL(path.resolve(__dirname,'../../scripts/canvas-oss/runtime-config-contract.mjs')).href);
function fixture(t) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'canvas-config-contract-'));
  t.after(()=>{
    assert.equal(path.dirname(fs.realpathSync(root)),fs.realpathSync(os.tmpdir()));
    fs.rmSync(root,{recursive:true,force:true});
  });
  const result=spawnSync(process.execPath,[generator,root],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  return root;
}
test('real generator output validates directly and metadata contains only fingerprints',async t=>{
  const root=fixture(t),{CONFIGURATION_NAMES,validateRuntimeConfiguration}=await contract;
  const files=Object.fromEntries(CONFIGURATION_NAMES.map(name=>[name,fs.readFileSync(path.join(root,name),'utf8')]));
  assert.equal(validateRuntimeConfiguration(files).state,'REVIEWED_CANVAS_CONFIGURATION_VALID');
  const run=spawnSync(process.execPath,[validator,root],{encoding:'utf8'});assert.equal(run.status,0,run.stderr);
  const report=JSON.parse(run.stdout);assert.equal(report.productionDemoReady,false);
  const generation=JSON.parse(fs.readFileSync(path.join(root,'generation.json')));
  assert.deepEqual(report.configurationSha256,generation.configuration_sha256);
  assert(!run.stdout.includes('encryption_key:') && !run.stdout.includes('"kty"'));
});
test('read-only destination cannot make injected Ruby or modified security/session config acceptable',async t=>{
  const root=fixture(t),{CONFIGURATION_NAMES,validateRuntimeConfiguration}=await contract;
  const original=Object.fromEntries(CONFIGURATION_NAMES.map(name=>[name,fs.readFileSync(path.join(root,name),'utf8')]));
  for(const [name,text] of [['security.yml',original['security.yml']+'<%= CONTROLLED_INJECTED_RUBY %>\n'],
    ['database.yml',original['database.yml'].replace('canvas-postgres','unreviewed-database')],
    ['session_store.yml',original['session_store.yml'].replace('secure: true','secure: false')]]) {
    assert.throws(()=>validateRuntimeConfiguration({...original,[name]:text}));
  }
});
test('injected LTI key fields and payload cannot be hidden inside the allowed configuration mount',async t=>{
  const root=fixture(t),{CONFIGURATION_NAMES,validateRuntimeConfiguration}=await contract;
  const original=Object.fromEntries(CONFIGURATION_NAMES.map(name=>[name,fs.readFileSync(path.join(root,name),'utf8')]));
  const changed=original['dynamic_settings.yml'].replace('"alg":"RS256"','"alg":"RS256","unreviewed":"CONTROLLED_SENSITIVE_VALUE"');
  assert.notEqual(changed,original['dynamic_settings.yml']);
  assert.throws(()=>validateRuntimeConfiguration({...original,'dynamic_settings.yml':changed}),error=>{
    assert(!error.message.includes('CONTROLLED_SENSITIVE_VALUE'));return true;
  });
});
test('actual file validator rejects changed mounted contents without echoing them',t=>{
  const root=fixture(t);
  fs.appendFileSync(path.join(root,'security.yml'),'CONTROLLED_SENSITIVE_VALUE\n');
  const run=spawnSync(process.execPath,[validator,root],{encoding:'utf8'});
  assert.notEqual(run.status,0);assert.equal(run.stdout,'');assert(!run.stderr.includes('CONTROLLED_SENSITIVE_VALUE'));
});
test('generator refuses overwrite and noncanonical origin before creating configuration',t=>{
  const root=fixture(t), before=fs.readFileSync(path.join(root,'security.yml'),'utf8');
  const again=spawnSync(process.execPath,[generator,root],{encoding:'utf8'});assert.notEqual(again.status,0);
  assert.equal(fs.readFileSync(path.join(root,'security.yml'),'utf8'),before);
  const next=path.join(root,'must-not-exist');
  const changed=spawnSync(process.execPath,[generator,next],{encoding:'utf8',env:{...process.env,CANVAS_OSS_ORIGIN:'https://other.example.test'}});
  assert.notEqual(changed.status,0);assert(!fs.existsSync(next));
});
