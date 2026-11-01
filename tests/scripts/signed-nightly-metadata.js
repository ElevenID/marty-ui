"use strict";
const assert=require('node:assert/strict'),{isDeepStrictEqual}=require('node:util');
const OPERATOR_SHA='828446643762b2abc3bc675a8265623e7c36ee68dad60dbb285b16919bbe73cb';
const TARGET='/opt/marty-ui-static/demos/manifests/2026.08.0.json';
const ROLES=['ui-prod','gateway'];
const same=(a,b,reason)=>assert(isDeepStrictEqual(a,b),reason);
const canonical=source=>require('./functional-debug-runtime').comparableBinaryMounts([{source}])[0].source;
const json=value=>JSON.stringify(Object.fromEntries(Object.entries(value).sort()));
function labels(row){
 const output={...row.Config.Labels},groups=new Map();
 for(const key of Object.keys(output)){
  if(key.startsWith('desktop.docker.io/')){
   const match=/^desktop\.docker\.io\/mounts\/(\d+)\/(Source|SourceKind|Target)$/.exec(key);
   if(match){const group=groups.get(match[1])||{};group[match[2]]=output[key];groups.set(match[1],group);}
   else if(key==='desktop.docker.io/ports.scheme')assert.equal(output[key],'v2');
   else {const match=/^desktop\.docker\.io\/ports\/(\d+\/(?:tcp|udp))$/.exec(key);assert(match,'Unknown Desktop metadata label');
    const ports=row.NetworkSettings.Ports[match[1]];assert(Array.isArray(ports)&&ports.length===1);
    assert.equal(output[key],(ports[0].HostIp==='0.0.0.0'?'':ports[0].HostIp)+':'+ports[0].HostPort);}
   delete output[key];
  }
 }
 for(const group of groups.values()){
  same(Object.keys(group).sort(),['Source','SourceKind','Target']);assert.equal(group.SourceKind,'hostFile');
  const mount=row.Mounts.filter(value=>value.Destination===group.Target);assert.equal(mount.length,1);assert.equal(mount[0].Type,'bind');
  assert.equal(canonical(group.Source),canonical(mount[0].Source));
 }
 for(const field of ['com.docker.compose.config-hash','com.docker.compose.project.config_files','com.docker.compose.project.working_dir'])delete output[field];
 return output;
}
function mounts(values,key){const output=Object.fromEntries(values.map(value=>[value[key],value.Type==='bind'?{...value,Source:canonical(value.Source)}:value]));assert.equal(Object.keys(output).length,values.length);return output;}
function host(row){const output=structuredClone(row.HostConfig);if(output.Mounts)output.Mounts=mounts(output.Mounts,'Target');for(const field of ['Dns','DnsOptions','DnsSearch'])if(output[field]===null||(Array.isArray(output[field])&&!output[field].length))output[field]=[];return output;}
function environment(row){const result={};for(const value of row.Config.Env){const at=value.indexOf('=');assert(at>0);const key=value.slice(0,at);assert(!Object.hasOwn(result,key));result[key]=value.slice(at+1);}return result;}
function generatedHostname(before,after){
 if(before.Config.Hostname!==after.Config.Hostname){
  assert.equal(before.Config.Hostname,before.Id.slice(0,12),'Unexpected original hostname');
  assert.equal(after.Config.Hostname,after.Id.slice(0,12),'Unexpected successor hostname');
  after.Config.Hostname=before.Config.Hostname;
 }
}
function transition(original, actual, role, input, marker){
 assert(ROLES.includes(role));assert.notEqual(actual.Id,original.Id);assert(/^[a-f0-9]{64}$/.test(actual.Id));
 for(const field of ['Name','Image','Path','Args'])same(actual[field],original[field],'Metadata changed '+field);
 const before=structuredClone(original),after=structuredClone(actual);
 if(role==='ui-prod'){
  const pub=input.publicManifest.path;
  const remove=(items,key)=>{
   const found=items.filter(value=>value[key]===TARGET);assert.equal(found.length,1);const item=found[0];assert.equal(item.Type,'bind');assert.equal(canonical(item.Source),canonical(pub));
   assert.equal(key==='Target'?item.ReadOnly:!item.RW,true);
   if(key==='Target')same({...item,Source:canonical(item.Source)},{Type:'bind',Source:canonical(pub),Target:TARGET,ReadOnly:true,BindOptions:{}},'Unexpected public bind options');
   else same({...item,Source:canonical(item.Source)},{Type:'bind',Source:canonical(pub),Destination:TARGET,Mode:'ro',RW:false,Propagation:'rprivate'},'Unexpected public mount fields');
   return items.filter(value=>value!==item);};
  assert(!before.Mounts.some(value=>value.Destination===TARGET));
  assert(!(before.HostConfig.Mounts||[]).some(value=>value.Target===TARGET));
  after.Mounts=remove(after.Mounts,'Destination');after.HostConfig.Mounts=remove(after.HostConfig.Mounts,'Target');
 }
 same(host(after),host(before),'Metadata HostConfig changed');same(mounts(after.Mounts,'Destination'),mounts(before.Mounts,'Destination'),'Metadata mounts changed');
 generatedHostname(before,after);
 const config=row=>{const output={...row.Config};delete output.Env;delete output.Labels;return output;};same(config(after),config(before),'Metadata Config changed');
 const changes=role==='gateway'?{ELEVENID_COMPONENT_REVISIONS_JSON:json(marker.component_revisions),ELEVENID_IMAGE_DIGESTS_JSON:json(marker.image_digests)}:{};
 same(environment(actual),{...environment(original),...changes},'Metadata environment changed');same(labels(actual),labels(original),'Metadata provenance labels changed');
 const networks=row=>Object.fromEntries(Object.entries(row.NetworkSettings.Networks).map(([name,endpoint])=>[name,endpoint.NetworkID]));
 same(networks(actual),networks(original),'Metadata networks changed');same(actual.NetworkSettings.Ports,original.NetworkSettings.Ports,'Metadata ports changed');
 assert.equal(actual.State.Running,true);assert.equal(actual.State.OOMKilled,false);assert.equal(actual.State.Health?.Status,'healthy');
 assert(Number.isSafeInteger(actual.State.Pid)&&actual.State.Pid>0);assert(Date.parse(actual.State.StartedAt)>Date.parse(original.State.StartedAt));return actual;
}
function metadataSuccessor(ref, byRole, tools){
 const value=tools.boundJson(ref);assert.equal(value.schema,'marty.functional-signed-metadata-successor/v1');
 assert.equal(value.operator.sha256,OPERATOR_SHA);tools.verifyBoundFile(value.operator,1024*1024);
 const input=tools.boundJson(value.input),preflight=tools.boundJson(input.preflightResult),result=tools.boundJson(value.result);
 assert.equal(input.schema,'marty.beta-release-metadata-repair-input/v1');assert.equal(input.sourceSha256,OPERATOR_SHA);
 assert.equal(input.betaOnly,true);same(input.roles,ROLES);assert.equal(input.executeAuthorized,true);assert.equal(input.rollbackAuthorized,false);
 assert.equal(result.state,'BETA_RELEASE_METADATA_REPAIRED');assert.equal(result.sourceSha256,OPERATOR_SHA);assert.equal(result.runId,input.runId);
 assert.equal(preflight.state,'BETA_METADATA_PREFLIGHT_PASSED');assert.equal(preflight.sourceSha256,OPERATOR_SHA);assert.equal(preflight.runId,input.runId);
 same(preflight.models,input.newModels,'Preflight models changed');assert.equal(preflight.publicManifestSha256,input.publicManifest.sha256);
 assert.equal(preflight.readability.helperRemoved,true);assert.equal(preflight.readability.knownExit,0);assert.equal(preflight.readability.mountReadOnly,true);
 assert.equal(preflight.readability.sourceSha256,input.publicManifest.sha256);assert.equal(preflight.readability.uid,101);assert.equal(preflight.readability.gid,101);
 for(const field of ['file','parent'])assert(/^[a-f0-9]{64}$/.test(preflight.readability.aclBeforeAndAfter[field]));
 for(const flag of ['releaseQualified','recordingQualified']){assert.equal(input[flag],false);assert.equal(result[flag],false);}
 const operation=tools.boundJson(result.operation);assert.equal(operation.sourceSha256,OPERATOR_SHA);assert.equal(operation.runId,input.runId);assert.equal(operation.pending,null);
 const steps=ROLES.flatMap(role=>['stop','create','start'].map(action=>'apply-'+action+'-'+role));same(operation.operations,steps,'Metadata operation order changed');
 same(Object.keys(operation.terminals).sort(),[...steps].sort());
 for(const step of steps){const terminal=tools.boundJson(operation.terminals[step]);assert.equal(terminal.exit,0);tools.verifyBoundFile(terminal.stdout,16*1024*1024,0);tools.verifyBoundFile(terminal.stderr,16*1024*1024,0);}
 const before=tools.boundJson(result.before),after=tools.boundJson(result.after),marker=tools.boundJson(input.expectedMarker);
 same(Object.keys(before).sort(),[...ROLES].sort());same(Object.keys(after).sort(),[...ROLES].sort());
 same(result.oldCids,input.oldCids);same(operation.oldCids,input.oldCids);same(result.newCids,operation.newCids);same(Object.keys(result.newCids).sort(),[...ROLES].sort());
 assert.equal(result.served.manifest.sha256,input.publicManifest.sha256);same(tools.boundJson(result.served.marker),marker,'Served metadata marker changed');
 const expectedIds=preflight.allIds.filter(id=>!ROLES.some(role=>input.oldCids[role]===id)).concat(Object.values(result.newCids));
 assert.equal(new Set(result.allIds).size,result.allIds.length);same([...result.allIds].sort(),expectedIds.sort(),'Unrelated registration changed');
 const output=new Map(byRole);
 for(const role of ROLES){assert.equal(input.oldCids[role],byRole.get(role).Id);assert.equal(before[role].Id,input.oldCids[role]);assert.equal(after[role].Id,result.newCids[role]);
  require('./signed-nightly-restart').configuration(byRole.get(role),before[role]);
  output.set(role,transition(before[role],after[role],role,input,marker));}
 return output;
}

// One actual failed metadata apply followed by reviewed original-config UI recovery.
const RECOVERY_PINS=Object.freeze({
 operator:'1a93fb898eea6ce49206f8da8894f9d55629b3728e83005241ac6a6851886ec7',
 input:'a7318dbaa269f263aa7601c8e03c67a70a56268b63ec3feb9f2b94c1cdc32f07',
 result:'dc05b36efa42de7ef3ce4a0eb150ecee1895e45323e388d2d78a8655bce4e22d',
 failedState:'73bf62dd8b03c5752c436989d5ba4c7090ef7895734ae4b379bee9c3686b425f',
 stopOperator:'1a102fd36f6e3804751bbefd8e2f721924e9b21b70600999a3e4c12f50b9c73f',
 stopResult:'07ac180ee016004675e1c35456d8de7e3a331646cdd60537a0389f65998f824a'
});
function metadataRecovery(ref,byRole,tools){
 const value=tools.boundJson(ref);assert.equal(value.schema,'marty.functional-signed-metadata-recovery/v1');
 same(Object.keys(value).sort(),['schema','operation',...Object.keys(RECOVERY_PINS)].sort());
 const get=key=>{assert.equal(value[key].sha256,RECOVERY_PINS[key]);return tools.boundJson(value[key]);};
 for(const key of ['operator','stopOperator']){assert.equal(value[key].sha256,RECOVERY_PINS[key]);tools.verifyBoundFile(value[key],1024*1024);}
 const input=get('input'),result=get('result'),failed=get('failedState'),stop=get('stopResult'),operation=tools.boundJson(value.operation);
 assert.equal(input.sourceSha256,RECOVERY_PINS.operator);assert.equal(input.rollbackAuthorized,true);assert.equal(input.executeAuthorized,false);
 same(input.recoveryState,value.failedState);same(result.originalFailure,value.failedState);
 assert.equal(result.state,'BETA_METADATA_ORIGINAL_CONFIG_RESTORED');assert.equal(failed.pending,null);
 same(Object.keys(failed.newCids),['ui-prod']);same(failed.operations,['apply-stop-ui-prod','apply-create-ui-prod','apply-start-ui-prod']);
 assert.equal(stop.state,'EXACT_FAILED_UI_STOPPED_NO_REMOVE');assert.equal(stop.cid,failed.newCids['ui-prod']);assert.equal(stop.exit,1);tools.verifyBoundFile(stop.terminal,1024*1024);
 assert.equal(operation.sourceSha256,RECOVERY_PINS.operator);assert.equal(operation.runId,input.runId);assert.equal(operation.pending,null);
 same(operation.recoveryOriginal,value.failedState);same(operation.operations,['rollback-create-ui-prod','rollback-start-ui-prod']);
 same(Object.keys(operation.terminals).sort(),[...operation.operations].sort());
 for(const step of operation.operations){const terminal=tools.boundJson(operation.terminals[step]);assert.equal(terminal.exit,0);tools.verifyBoundFile(terminal.stdout,16*1024*1024,0);tools.verifyBoundFile(terminal.stderr,16*1024*1024,0);}
 const before=tools.boundJson(failed.before),recovered=tools.boundJson(result.recovered),preflight=tools.boundJson(input.preflightResult);same(Object.keys(recovered),['ui-prod']);
 for(const role of ROLES){assert.equal(before[role].Id,byRole.get(role).Id);require('./signed-nightly-restart').configuration(byRole.get(role),before[role]);}
 const row=recovered['ui-prod'];assert.equal(row.Id,operation.newCids['ui-prod']);assert.notEqual(row.Id,before['ui-prod'].Id);assert.notEqual(row.Id,failed.newCids['ui-prod']);
 const original=structuredClone(before['ui-prod']),actual=structuredClone(row);generatedHostname(original,actual);original.Id=actual.Id;original.Config.Labels=labels(original);actual.Config.Labels=labels(actual);
 require('./signed-nightly-restart').configuration(original,actual);
 assert.equal(row.State.Running,true);assert.equal(row.State.OOMKilled,false);assert.equal(row.State.Health.Status,'healthy');assert(row.State.Pid>0);assert.notEqual(row.State.StartedAt,before['ui-prod'].State.StartedAt);
 const expected=preflight.allIds.filter(id=>id!==before['ui-prod'].Id);same([...result.allIds].sort(),[...expected,row.Id].sort());same([...stop.allIds].sort(),[...expected,failed.newCids['ui-prod']].sort());
 same(tools.boundJson(result.served.marker),tools.boundJson(input.oldMarker));assert.equal(result.served.manifest.sha256,input.oldPublicManifest.sha256);
 for(const flag of ['releaseQualified','recordingQualified']){assert.equal(input[flag],false);assert.equal(result[flag],false);}
 const output=new Map(byRole);output.set('ui-prod',row);return output;
}

module.exports={metadataSuccessor,metadataRecovery,transition,labels,generatedHostname,OPERATOR_SHA,RECOVERY_PINS};
