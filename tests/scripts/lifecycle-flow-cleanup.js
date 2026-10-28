'use strict';
const assert=require('node:assert/strict');
const TERMINAL=new Set(['COMPLETED','FAILED','CANCELLED','EXPIRED']);
const PENDING=new Set(['PENDING','IN_PROGRESS','AWAITING_WALLET','AWAITING_APPROVAL','AWAITING_EVIDENCE']);
async function cleanupLifecycleFlows(read,flows){
  const evidence={ok:true,instances:[],failures:[]};
  for(const owned of flows){try{
    assert(/^[a-f0-9-]{36}$/i.test(owned.id||'')&&typeof owned.externalReference==='string'&&owned.externalReference,'Owned Flow create outcome is unresolved');
    const route='/v1/flows/instances/'+encodeURIComponent(owned.id);
    const inspect=async()=>{const r=await read(route);assert(r.ok&&r.body?.id===owned.id&&r.body.organization_id===owned.organizationId
      &&r.body.metadata?.external_reference===owned.externalReference,'Flow ownership is not proven');return r.body;};
    const before=await inspect(),status=String(before.status).toUpperCase();
    assert(TERMINAL.has(status)||PENDING.has(status),'Unknown Flow state');
    if(TERMINAL.has(status)){evidence.instances.push({id:owned.id,status,alreadyTerminal:true});continue;}
    const cancelled=await read(route+'/cancel',{method:'POST'});assert(cancelled.ok,'Owned Flow cancel failed');
    const after=await inspect();assert.equal(String(after.status).toUpperCase(),'CANCELLED');
    evidence.instances.push({id:owned.id,status:'CANCELLED',cancelled:true});
  }catch{evidence.ok=false;evidence.failures.push({id:owned.id||null,code:'OWNED_FLOW_RETIREMENT_UNCONFIRMED'});}}
  return evidence;
}
module.exports={cleanupLifecycleFlows};
