"use strict";
const {test}=require('node:test'),assert=require('node:assert/strict');
const {transition,labels}=require('./signed-nightly-metadata');
const TARGET='/opt/marty-ui-static/demos/manifests/2026.08.0.json';
const marker={component_revisions:{'marty-ui':'a'.repeat(40)},image_digests:{gateway:'sha256:'+'b'.repeat(64)}};
const input={publicManifest:{path:'C:/Users/test/public.json'}};
function row(role){return {Id:'a'.repeat(64),Name:'/role',Image:'sha256:'+'b'.repeat(64),Path:'/binary',Args:[],Config:{Env:['KEEP=value','ELEVENID_COMPONENT_REVISIONS_JSON=old','ELEVENID_IMAGE_DIGESTS_JSON=old'],Labels:{'com.docker.compose.service':role},Hostname:'a'.repeat(12),User:'101'},HostConfig:{Mounts:[],Dns:null,DnsOptions:null,DnsSearch:null,Memory:42},Mounts:[],NetworkSettings:{Networks:{owned:{NetworkID:'c'.repeat(64)}},Ports:{}},State:{StartedAt:'2026-01-01T00:00:00Z',Running:true,Pid:1,OOMKilled:false,Health:{Status:'healthy'}}};}
function successor(role){const before=row(role),after=structuredClone(before);after.Id='d'.repeat(64);after.State.StartedAt='2026-01-02T00:00:00Z';after.State.Pid=2;after.Config.Hostname=after.Id.slice(0,12);
 if(role==='gateway')after.Config.Env=['KEEP=value','ELEVENID_COMPONENT_REVISIONS_JSON='+JSON.stringify(marker.component_revisions),'ELEVENID_IMAGE_DIGESTS_JSON='+JSON.stringify(marker.image_digests)];
 else{after.Mounts=[{Type:'bind',Source:input.publicManifest.path,Destination:TARGET,Mode:'ro',RW:false,Propagation:'rprivate'}];after.HostConfig.Mounts=[{Type:'bind',Source:input.publicManifest.path,Target:TARGET,ReadOnly:true,BindOptions:{}}];}
 return {before,after};}
test('Gateway changes only its two maps; UI adds only its exact readonly public file',()=>{for(const role of ['gateway','ui-prod']){const {before,after}=successor(role);assert.equal(transition(before,after,role,input,marker),after);assert.equal(before.Id,'a'.repeat(64));}});
test('changed private env, writable/alternate public mount, memory, network and generation refuse',()=>{for(const mutate of [v=>v.Config.Hostname='unreviewed-host',v=>v.Config.Env.push('PRIVATE=changed'),v=>v.Mounts[0].RW=true,v=>v.HostConfig.Mounts[0].BindOptions.NonRecursive=true,v=>v.Mounts[0].Source='C:/other.json',v=>v.HostConfig.Memory=43,v=>v.NetworkSettings.Networks.owned.NetworkID='f'.repeat(64),v=>v.State.Pid=0,v=>v.State.StartedAt='2026-01-01T00:00:00Z']){const {before,after}=successor('ui-prod');mutate(after);assert.throws(()=>transition(before,after,'ui-prod',input,marker));}});
test('Desktop labels must describe the actual file mount and port; unknown fields refuse',()=>{const {after}=successor('ui-prod');Object.assign(after.Config.Labels,{'desktop.docker.io/mounts/0/Source':input.publicManifest.path,'desktop.docker.io/mounts/0/SourceKind':'hostFile','desktop.docker.io/mounts/0/Target':TARGET,'desktop.docker.io/ports.scheme':'v2','desktop.docker.io/ports/80/tcp':':3002'});after.NetworkSettings.Ports={'80/tcp':[{HostIp:'0.0.0.0',HostPort:'3002'}]};labels(after);for(const [key,value] of [['desktop.docker.io/mounts/0/Source','C:/other.json'],['desktop.docker.io/mounts/0/SourceKind','hostDirectory'],['desktop.docker.io/ports/80/tcp',':9999'],['desktop.docker.io/unknown','value']]){const changed=structuredClone(after);changed.Config.Labels[key]=value;assert.throws(()=>labels(changed));}});

function authorityFixture(){const {OPERATOR_SHA}=require('./signed-nightly-metadata'),docs={};let n=0;const put=value=>{const path='doc'+(++n),ref={path,sha256:'f'.repeat(64)};docs[path]=value;return ref;};
 const pairs=Object.fromEntries(['ui-prod','gateway'].map(role=>[role,successor(role)]));pairs.gateway.before.Id='b'.repeat(64);pairs.gateway.after.Id='e'.repeat(64);pairs.gateway.before.Config.Hostname=pairs.gateway.before.Id.slice(0,12);pairs.gateway.after.Config.Hostname=pairs.gateway.after.Id.slice(0,12);
 const oldCids=Object.fromEntries(Object.entries(pairs).map(([role,p])=>[role,p.before.Id])),newCids=Object.fromEntries(Object.entries(pairs).map(([role,p])=>[role,p.after.Id]));
 const publicManifest={path:input.publicManifest.path,sha256:'c'.repeat(64)},newModels={gateway:put({model:'gateway'}),'ui-prod':put({model:'ui'})};
 const preflight=put({state:'BETA_METADATA_PREFLIGHT_PASSED',sourceSha256:OPERATOR_SHA,runId:'owned',models:newModels,publicManifestSha256:publicManifest.sha256,allIds:Object.values(oldCids),readability:{helperRemoved:true,knownExit:0,mountReadOnly:true,sourceSha256:publicManifest.sha256,uid:101,gid:101,aclBeforeAndAfter:{file:'a'.repeat(64),parent:'b'.repeat(64)}}});
 const inputRef=put({schema:'marty.beta-release-metadata-repair-input/v1',sourceSha256:OPERATOR_SHA,runId:'owned',betaOnly:true,roles:['ui-prod','gateway'],executeAuthorized:true,rollbackAuthorized:false,releaseQualified:false,recordingQualified:false,preflightResult:preflight,newModels,publicManifest,oldCids,expectedMarker:put(marker)});
 const steps=['ui-prod','gateway'].flatMap(role=>['stop','create','start'].map(action=>'apply-'+action+'-'+role));const terminal=put({exit:0,stdout:put({}),stderr:put({})});
 const operation=put({sourceSha256:OPERATOR_SHA,runId:'owned',pending:null,operations:steps,terminals:Object.fromEntries(steps.map(step=>[step,terminal])),oldCids,newCids});
 const after=put(Object.fromEntries(Object.entries(pairs).map(([role,p])=>[role,p.after])));
 const result=put({state:'BETA_RELEASE_METADATA_REPAIRED',sourceSha256:OPERATOR_SHA,runId:'owned',releaseQualified:false,recordingQualified:false,operation,before:put(Object.fromEntries(Object.entries(pairs).map(([role,p])=>[role,p.before]))),after,oldCids,newCids,served:{manifest:publicManifest,marker:put(marker)},allIds:Object.values(newCids)});
 const value=put({schema:'marty.functional-signed-metadata-successor/v1',operator:{path:'operator',sha256:OPERATOR_SHA},input:inputRef,result});
 return {value,docs,after,operation,result,tools:{boundJson:ref=>structuredClone(docs[ref.path]),verifyBoundFile:()=>{}},before:new Map(Object.entries(pairs).map(([role,p])=>[role,p.before]))};}
test('complete dual-role authority requires terminal order, exact global IDs and served bytes',()=>{const {metadataSuccessor}=require('./signed-nightly-metadata');const f=authorityFixture();const actual=metadataSuccessor(f.value,f.before,f.tools);assert.equal(actual.get('gateway').Id,'e'.repeat(64));
 for(const mutate of [f=>f.docs[f.operation.path].pending='unknown',f=>f.docs[f.operation.path].operations.reverse(),f=>f.docs[f.result.path].allIds.push('9'.repeat(64)),f=>f.docs[f.result.path].served.manifest.sha256='0'.repeat(64),f=>f.docs[f.after.path].gateway.Config.Env.push('OTHER=changed')]){const negative=authorityFixture();mutate(negative);assert.throws(()=>metadataSuccessor(negative.value,negative.before,negative.tools));}
});

function recoveryFixture(){
 const {RECOVERY_PINS}=require('./signed-nightly-metadata'),docs={};let n=0;
 const put=(value,sha='f'.repeat(64))=>{const path='recovery-doc'+(++n),ref={path,sha256:sha};docs[path]=value;return ref;};
 const before=Object.fromEntries(['ui-prod','gateway'].map(role=>[role,row(role)]));before.gateway.Id='b'.repeat(64);before.gateway.Config.Hostname=before.gateway.Id.slice(0,12);
 const actual=structuredClone(before['ui-prod']);actual.Id='d'.repeat(64);actual.Config.Hostname=actual.Id.slice(0,12);actual.State.StartedAt='2026-01-02T00:00:00Z';actual.State.Pid=2;
 const oldIds=Object.values(before).map(row=>row.Id),failedCid='e'.repeat(64);
 const preflight=put({allIds:oldIds}),beforeRef=put(before),oldMarker=put({old:true}),oldPublic={path:'old-public',sha256:'c'.repeat(64)};
 const failed=put({sourceSha256:RECOVERY_PINS.operator,runId:'owned',oldCids:Object.fromEntries(Object.entries(before).map(([key,row])=>[key,row.Id])),pending:null,before:beforeRef,newCids:{'ui-prod':failedCid},operations:['apply-stop-ui-prod','apply-create-ui-prod','apply-start-ui-prod']},RECOVERY_PINS.failedState);
 const input=put({sourceSha256:RECOVERY_PINS.operator,runId:'owned',rollbackAuthorized:true,executeAuthorized:false,recoveryState:failed,preflightResult:preflight,oldMarker,oldPublicManifest:oldPublic,releaseQualified:false,recordingQualified:false},RECOVERY_PINS.input);
 const terminal=put({exit:0,stdout:put({}),stderr:put({})});
 const operation=put({sourceSha256:RECOVERY_PINS.operator,runId:'owned',pending:null,recoveryOriginal:failed,operations:['rollback-create-ui-prod','rollback-start-ui-prod'],terminals:{'rollback-create-ui-prod':terminal,'rollback-start-ui-prod':terminal},newCids:{'ui-prod':actual.Id}});
 const recovered=put({'ui-prod':actual}),result=put({state:'BETA_METADATA_ORIGINAL_CONFIG_RESTORED',originalFailure:failed,recovered,allIds:[before.gateway.Id,actual.Id],served:{marker:oldMarker,manifest:oldPublic},releaseQualified:false,recordingQualified:false},RECOVERY_PINS.result);
 const stopResult=put({state:'EXACT_FAILED_UI_STOPPED_NO_REMOVE',cid:failedCid,exit:1,terminal:put({}),allIds:[before.gateway.Id,failedCid]},RECOVERY_PINS.stopResult);
 const value=put({schema:'marty.functional-signed-metadata-recovery/v1',operator:{path:'reviewed-operator',sha256:RECOVERY_PINS.operator},stopOperator:{path:'reviewed-stop',sha256:RECOVERY_PINS.stopOperator},input,result,failedState:failed,stopResult,operation});
 return {value,docs,before:new Map(Object.entries(before)),recovered,result,failed,operation,tools:{boundJson:ref=>structuredClone(docs[ref.path]),verifyBoundFile:()=>{}}};
}
test('actual reviewed recovery algorithm preserves original configuration and rejects unrelated changes',()=>{
 const {metadataRecovery}=require('./signed-nightly-metadata');const f=recoveryFixture();assert.equal(metadataRecovery(f.value,f.before,f.tools).get('ui-prod').Id,'d'.repeat(64));
 for(const mutate of [f=>f.docs[f.value.path].result.sha256='0'.repeat(64),f=>f.docs[f.operation.path].pending='unknown',f=>f.docs[f.recovered.path]['ui-prod'].Config.Env.push('PRIVATE=changed'),f=>f.docs[f.recovered.path]['ui-prod'].Config.Hostname='unrelated',f=>f.docs[f.recovered.path]['ui-prod'].HostConfig.Memory++,f=>f.docs[f.result.path].allIds.push('extra')]){const n=recoveryFixture();mutate(n);assert.throws(()=>metadataRecovery(n.value,n.before,n.tools));}
});

test('same-generation preimages validate Desktop-derived labels while retaining Compose provenance',()=>{
 const {sameGenerationConfiguration}=require('./signed-nightly-metadata');
 const before=row('ui-prod');before.Config.Labels['com.docker.compose.config-hash']='same';before.NetworkSettings.Ports={'80/tcp':[{HostIp:'0.0.0.0',HostPort:'3000'}]};
 before.Config.Labels['desktop.docker.io/ports.scheme']='v2';before.Config.Labels['desktop.docker.io/ports/80/tcp']=':3000';
 const after=structuredClone(before);delete after.Config.Labels['desktop.docker.io/ports.scheme'];delete after.Config.Labels['desktop.docker.io/ports/80/tcp'];sameGenerationConfiguration(before,after);
 for(const mutate of [value=>value.Config.Labels['com.docker.compose.config-hash']='changed',value=>value.Config.Labels['desktop.docker.io/unknown']='extra',value=>value.Config.Env.push('PRIVATE=changed')]){const changed=structuredClone(after);mutate(changed);assert.throws(()=>sameGenerationConfiguration(before,changed));}
 const wrong=structuredClone(before);wrong.Config.Labels['desktop.docker.io/ports/80/tcp']=':9999';assert.throws(()=>sameGenerationConfiguration(wrong,after));
});
