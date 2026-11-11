'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'audit-beta-membership-badge-login.js'),'utf8');
async function run(reject=false){const calls=[],errors=[],process={};vm.runInNewContext(source,{require:name=>{
 if(name==='./verify-beta-credential-login')return {main:async options=>{calls.push(options);if(reject)throw Error('SECRET');}};
 assert.equal(name,'./verify-beta-waltid-acceptance');return {redact:value=>{calls.push('redact');return value.replaceAll('SECRET','[redacted]');}};
},console:{error:value=>errors.push(JSON.parse(value))},process});await new Promise(setImmediate);return {calls,errors,process};}
test('actual audit wrapper selects only primary owned membership mode',async()=>{const r=await run();assert.equal(r.calls.length,1);assert.equal(r.calls[0].retainedMembership,true);assert.deepEqual(Object.keys(r.calls[0]),['retainedMembership']);assert.deepEqual(r.errors,[]);assert.equal(r.process.exitCode,undefined);});
test('actual audit wrapper redacts shared-driver failure and exits nonzero',async()=>{const r=await run(true);assert.equal(r.process.exitCode,1);assert.equal(r.calls.at(-1),'redact');assert.equal(r.errors.length,1);assert(!JSON.stringify(r.errors).includes('SECRET'));assert(JSON.stringify(r.errors).includes('[redacted]'));});
