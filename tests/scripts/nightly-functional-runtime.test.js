'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const nightly=require('./nightly-functional-runtime'),runtime=require('./functional-debug-runtime');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
for(const name of ['authority','expected','produce'])test('retired signed-image '+name+' refuses before supplied inputs and readers',()=>{
 const never=new Proxy({}, {get(){assert.fail('Retired generation accessed input or reader');}});
 assert.throws(()=>nightly[name](never,never),/^Error: RETIRED_SIGNED_IMAGE_GENERATION$/);
});
test('shared signed-image producer refuses before options getters',()=>{
 const never=new Proxy({}, {get(){assert.fail('Retired producer accessed options');}});
 assert.throws(()=>runtime.produceSignedImageObservation(never,never),/RETIRED_SIGNED_IMAGE_GENERATION/);
});
for(const value of [false,null,{},undefined])for(const inherited of [false,true])test('old signed selector is denied before mixed dispatch '+String(value)+' inherited='+inherited,()=>{
 const fields={signedImageDeployment:value};
 const profile=Object.assign(inherited?Object.create(fields):fields,{schema:'marty.functional-mixed-runtime/v2',resourceRecreation:{}});
 Object.defineProperty(profile,'baseProfile',{get(){assert.fail('Retired selector read a predecessor');}});
 assert.throws(()=>runtime.expectedRuntime(profile),/RETIRED_PROVIDER_RUNTIME_PROFILE/);
 assert.throws(()=>runtime.verifyFunctionalRuntime(profile,{readDocker(){assert.fail('Retired selector reached Docker');}}),/RETIRED_PROVIDER_RUNTIME_PROFILE/);
});
for(const args of [[],['--check'],['--not-an-option']])test('observer CLI refuses before receipt/output access '+JSON.stringify(args),t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'retired-image-observer-'));t.after(()=>fs.rmSync(dir,{recursive:true}));
 const output=path.join(dir,'observation.json'),sentinel=path.join(dir,'existing');fs.writeFileSync(sentinel,'preserve');
 const result=spawnSync(process.execPath,[path.join(__dirname,'observe-nightly-functional-runtime.js'),'--profile',path.join(dir,'absent-profile'),'--output',output,...args],{cwd:dir,encoding:'utf8'});
 assert.equal(result.status,1);assert.equal(result.stdout,'');assert.equal(result.stderr.trim(),'RETIRED_SIGNED_IMAGE_GENERATION');
 assert.deepEqual(fs.readdirSync(dir),['existing']);assert.equal(fs.readFileSync(sentinel,'utf8'),'preserve');
});
