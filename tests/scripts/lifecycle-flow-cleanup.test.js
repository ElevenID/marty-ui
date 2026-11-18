'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {cleanupLifecycleFlows,retireOwnedFlow}=require('./lifecycle-flow-cleanup');
const id='12345678-1234-4234-8234-123456789abc',owned={id,organizationId:'org',externalReference:'fresh-run:active'};
test('only exact current pending Flow is cancelled and terminal projection confirmed',async()=>{const calls=[];let cancelled=false;const result=await cleanupLifecycleFlows(async(route,options)=>{calls.push({route,options});if(options){cancelled=true;return {ok:true};}return {ok:true,body:{id,organization_id:'org',metadata:{external_reference:owned.externalReference},status:cancelled?'CANCELLED':'AWAITING_WALLET'}};},[owned]);assert(result.ok);assert.equal(calls.filter(call=>call.options).length,1);assert.equal(result.instances[0].status,'CANCELLED');});
test('terminal owned Flow is observed without another cancellation',async()=>{const result=await cleanupLifecycleFlows(async(route,options)=>{assert(!options);return {ok:true,body:{id,organization_id:'org',metadata:{external_reference:owned.externalReference},status:'COMPLETED'}};},[owned]);assert(result.ok);assert(result.instances[0].alreadyTerminal);});
test('foreign org, stale reference, unknown status or lost create never cancels',async()=>{for(const change of [{organization_id:'foreign'},{metadata:{external_reference:'old-run'}},{status:'UNKNOWN'}]){let mutations=0;const result=await cleanupLifecycleFlows(async(route,options)=>{if(options)mutations++;return {ok:true,body:{id,organization_id:'org',metadata:{external_reference:owned.externalReference},status:'PENDING',...change}};},[owned]);assert(!result.ok);assert.equal(mutations,0);}const result=await cleanupLifecycleFlows(()=>assert.fail('Unresolved ID must not be read'),[{...owned,id:null}]);assert(!result.ok);});
test('cancel ACK without exact terminal confirmation remains cleanup failure',async()=>{const result=await cleanupLifecycleFlows(async(route,options)=>options?{ok:true}:{ok:true,body:{id,organization_id:'org',metadata:{external_reference:owned.externalReference},status:'PENDING'}},[owned]);assert(!result.ok);});
test('shared exact retirement records intent before cancellation',async()=>{
  let intent=false,cancelled=false;
  const result=await retireOwnedFlow(async(route,options)=>{
    if(options){assert(intent);cancelled=true;return {ok:true};}
    return {ok:true,body:{id,organization_id:'org',metadata:{external_reference:owned.externalReference},
      status:cancelled?'CANCELLED':'PENDING'}};
  },owned,{beforeCancel:()=>{intent=true;}});
  assert.equal(result.status,'CANCELLED');assert(intent);
});
