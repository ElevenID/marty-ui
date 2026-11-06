'use strict';
const fs=require('node:fs');
const assert=require('node:assert/strict');
const runtime=require('../tests/scripts/functional-debug-runtime');
function authority(ref){
 const profile=runtime.boundJson(ref);
 const transition=runtime.resourceRecreationSuccessor(profile.baseProfile,profile);
 const rows=transition.replacements.map(row=>({role:row.role,cid:row.newCid}));
 assert.equal(rows.length,28);assert.equal(new Set(rows.map(row=>row.cid)).size,28);
 assert.equal(runtime.expectedRuntime(profile).length,22);
 return {schema:'marty.northstar-resource-scope/v1',profileSha256:ref.sha256,rows,off:runtime.retainedBetaOffAuthority(profile)};
}
function nativeRead(input,{bindSource,transportModule}={}){
 const recorder=input.recorder;
 bindSource=bindSource||require(recorder.repository+'/src/externalQualification').assertSourceBinding;
 bindSource(recorder.repository,recorder.revision);
 const module=transportModule||require(recorder.repository+'/src/canvasDockerTransport');
 const descriptor=runtime.boundJson(input.dockerTransport);
 assert.equal(descriptor.engineId,input.engineId,'SCOPE_NATIVE_ENGINE_CHANGED');
 const environment={...process.env,[module.ENV]:input.dockerTransport.path,
  [module.ENV+'_SHA256']:input.dockerTransport.sha256,[module.CANARY_ENV]:input.dockerCanary.path,
  [module.CANARY_ENV+'_SHA256']:input.dockerCanary.sha256};
 const transport=module.createDockerTransport({functionalRerun:true,environment});
 assert.equal(transport.native,true,'SCOPE_NATIVE_TRANSPORT_REQUIRED');
 transport.requireStdinCanary(); // Existing owner verifies source, engine and retirement.
 return args=>transport.read(args);
}
function safeFailure(error){
 const first=String(error?.message||'').split('\n',1)[0];
 const match=/^((?:RESOURCE_|KEYCLOAK_|SCOPE_)[A-Z0-9_]{1,70})(?::[a-z0-9-]{1,80})?$/.exec(first);
 const classes=new Set(['Error','AssertionError','TypeError','RangeError','SyntaxError']);
 return {schema:'marty.northstar-runtime-scope-failure/v1',
  errorClass:classes.has(error?.name)?error.name:'Error',code:match?match[1]:'SCOPE_NATIVE_VERIFICATION_FAILED'};
}
function main(){
 const raw=fs.readFileSync(0);assert(raw.length<=32768);
 const input=JSON.parse(raw),result=authority(input.profile);
 assert.equal(typeof input.verifyLive,'boolean');
 if(input.verifyLive){
  runtime.verifyResourceAncillary(runtime.boundJson(input.profile),nativeRead(input));
 }
 process.stdout.write(JSON.stringify(result));
}
if(require.main===module){try{main();}catch(error){process.stdout.write(JSON.stringify(safeFailure(error)));process.exitCode=1;}}
module.exports={authority,nativeRead,safeFailure};
