'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {requireCurrentEngineeringRuntime}=require('./audit-beta-canvas-capture');
test('Canvas functional run refuses a stock engineering receipt from a different runtime observation',()=>{
 const runtime={profileSha256:'a'.repeat(64),receiptSha256:'b'.repeat(64)};
 const summary={kind:'canvas_local_engineering',functional_runtime_profile_sha256:runtime.profileSha256,
  functional_runtime_observation_sha256:runtime.receiptSha256};
 assert.doesNotThrow(()=>requireCurrentEngineeringRuntime(summary,runtime));
 assert.throws(()=>requireCurrentEngineeringRuntime({...summary,functional_runtime_observation_sha256:'c'.repeat(64)},runtime));
 assert.throws(()=>requireCurrentEngineeringRuntime({...summary,functional_runtime_profile_sha256:'c'.repeat(64)},runtime));
 assert.throws(()=>requireCurrentEngineeringRuntime({...summary,kind:'canvas_portability'},runtime));
});
