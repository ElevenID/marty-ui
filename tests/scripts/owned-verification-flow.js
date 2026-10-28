'use strict';
// Exact run-owned verification Flow custody. Shared by browser demos that call
// the canonical lifecycle verify() helper; no credential or signing logic here.
const fs=require('node:fs'),path=require('node:path');
const {randomUUID}=require('node:crypto');
const {inspectOwnedFlow,retireOwnedFlow}=require('./lifecycle-flow-cleanup');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
function check(ok,code){if(!ok){const error=Error(code);error.code=code;throw error;}}

function browserFlowApi(page){
  return async(method,route)=>page.evaluate(async({method,route})=>{
    const response=await fetch(route,{method,credentials:'include',signal:AbortSignal.timeout(15000)});
    return {status:response.status,ok:response.ok,body:await response.json().catch(()=>null)};
  },{method,route});
}
function ownedVerificationFlow({organizationId,runId,privateDirectory,api}){
  check(UUID.test(organizationId||'')&&UUID.test(runId||''),'OWNED_FLOW_ID_INVALID');
  check(path.isAbsolute(privateDirectory||'')&&fs.realpathSync(privateDirectory)===privateDirectory
    &&fs.lstatSync(privateDirectory).isDirectory()&&!fs.lstatSync(privateDirectory).isSymbolicLink(),
  'OWNED_FLOW_PRIVATE_DIRECTORY_INVALID');
  check(typeof api==='function','OWNED_FLOW_API_REQUIRED');
  const reference=`canvas-engineering-${runId}-${randomUUID()}`;
  const journal=path.join(privateDirectory,`canvas-verification-${runId}.json`);
  const read=(route,options)=>api(options?.method||'GET',route);
  const owned=id=>({id,organizationId,externalReference:reference});
  let state={scope:'OWNED_CANVAS_VERIFICATION_FLOW',organizationId,reference,runId,
    createIntent:false,instanceId:null,postResponseLost:false,retirementConfirmed:false,
    state:'PREPARED'};
  function save(exclusive=false){const file=exclusive?journal:journal+'.next';
    fs.writeFileSync(file,JSON.stringify(state,null,2)+'\n',{flag:'wx',mode:0o600});
    if(!exclusive)fs.renameSync(file,journal);
  }
  save(true);
  async function listMatching(){
    const matches=[];let offset=0;
    for(let page=0;page<100;page++){
      const route=`/v1/flows/instances?organization_id=${encodeURIComponent(organizationId)}&limit=100&offset=${offset}`;
      const response=await api('GET',route);
      check(response.ok&&response.status===200&&Array.isArray(response.body)
        &&response.body.length<=100,'OWNED_FLOW_LIST_UNCONFIRMED');
      for(const row of response.body)if(row?.metadata?.external_reference===reference)matches.push(row);
      if(response.body.length<100)return matches;
      offset+=100;
    }
    check(false,'OWNED_FLOW_LIST_INCOMPLETE');
  }
  return {
    reference,journal,
    get terminalStatus(){return state.terminalStatus||null;},
    get retirementConfirmed(){return state.retirementConfirmed===true;},
    beforeCreate(request){
      check(!state.createIntent&&request?.organization_id===organizationId
        &&request?.external_reference===reference,'OWNED_FLOW_CREATE_CHANGED');
      state.createIntent=true;state.state='CREATE_INTENT';save();
    },
    noteLostResponse(){state.postResponseLost=true;state.state='POST_RESPONSE_UNKNOWN';save();},
    async acknowledge(session){
      if(!session?.ok)return;
      check(UUID.test(session.instanceId||''),'OWNED_FLOW_ACK_INVALID');
      state.instanceId=session.instanceId;state.state='ACKNOWLEDGED';save();
      await inspectOwnedFlow(read,owned(session.instanceId));
    },
    async finalize(){
      if(!state.createIntent){state.retirementConfirmed=true;state.state='NO_CREATE';save();return;}
      const matches=await listMatching();
      if(matches.length===0){
        // A lost POST response cannot prove that no row was committed.
        check(!state.postResponseLost&&!state.instanceId,'OWNED_FLOW_CREATE_AMBIGUOUS');
        state.retirementConfirmed=true;state.state='ABSENT';save();return;
      }
      check(matches.length===1,'OWNED_FLOW_DUPLICATE_REFERENCE');
      const id=matches[0].id;
      check(!state.instanceId||state.instanceId===id,'OWNED_FLOW_ACK_MISMATCH');
      state.instanceId=id;state.state='RETIRE_INTENT';save();
      const retired=await retireOwnedFlow(read,owned(id),{beforeCancel:()=>{
        state.cancelIntent=true;save();}});
      state.terminalStatus=retired.status;state.retirementConfirmed=true;state.state='TERMINAL';save();
    },
    async run(task){
      let value,primary,cleanup;
      try{value=await task(this);}catch(error){primary=error;}
      try{await this.finalize();}catch(error){cleanup=error;state.state='CUSTODY_UNRESOLVED';
        state.cleanupCode=error.code||'OWNED_FLOW_CLEANUP_FAILED';save();}
      if(cleanup){const error=Error('OWNED_FLOW_CLEANUP_UNCONFIRMED');error.code='OWNED_FLOW_CLEANUP_UNCONFIRMED';
        error.cause=cleanup;error.primary=primary;throw error;}
      if(primary)throw primary;
      return value;
    },
  };
}
module.exports={ownedVerificationFlow,browserFlowApi};
