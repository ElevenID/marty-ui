'use strict';
// Functional-only binding for the reviewed restart of retained beta containers.
const assert=require('node:assert/strict');
const PHASES=['infrastructure','keycloak','clients','edge'];
const PLAN='b296aee1812106df5215f0e18da43478b31f02a46b8828bc82fbbb946ff09b19';
const SOURCE='a97eecd33d9fe99fa27445b4d2f95448013457bbf1dbd6566531ed813bba2b42';
const INFRA_SOURCE='188e9c3d93b18d9d6c266ff6c1459234a8c8019f4a8f775df5339228320dcbe9';
const INFRA_RECEIPT='22d2487cbecdaf6d3cda8057484fb0e9da5a487e7fb5400dce61beba55debf0f';

function authority(profile,{boundJson,verifyBoundFile,expectedRuntime}){
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');
 assert.equal(profile.scope,'FUNCTIONAL_ONLY');
 assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 const resume=profile.runtimeResume;
 assert(resume&&Object.keys(resume).sort().join(',')==='phaseResults,plan,source','Closed beta resume references required');
 assert.equal(resume.plan.sha256,PLAN);assert.equal(resume.source.sha256,SOURCE);
 verifyBoundFile(resume.source,128*1024); // The exact reviewed start operator, not a caller-supplied substitute.
 const plan=boundJson(resume.plan),base=boundJson(profile.baseProfile);
 assert.equal(plan.schema,'marty.beta-only-resume-plan/v1');
 assert.equal(plan.engineId,'3dbbbe66-1c98-4e0c-b0a6-f927c05e7341');
 assert.equal(plan.sources.sharedShutdownGuards.sha256,'0c814e20f8cb955864d70407526e327710cecb9f96e064c861eee3cdacd43afb');
 assert.equal(plan.sources.retainedAfter.sha256,'a84e079e4aac883e9f6afbe19c8d742d444deef70fd52c8c508d6ec1361dcb03');
 assert.equal(base.schema,profile.schema);assert(!base.runtimeResume,'Nested beta resume is unsupported');
 const original={...profile};delete original.runtimeResume;delete original.baseProfile;
 const prior={...base};delete prior.baseProfile;
 assert.deepEqual(original,prior,'Resume must preserve the exact previous functional profile');
 const before=boundJson(plan.sources.retainedAfter),allIds=Object.keys(before).sort();
 const started=plan.proposal.startOrder;
 assert(Array.isArray(started)&&started.length===28);
 const targets=new Map(started.map(row=>[row.role,row.cid]));
 assert.equal(targets.size,28);assert.equal(new Set(targets.values()).size,28);
 const groups=[['postgres','redis','openbao'],['keycloak'],
  started.map(row=>row.role).filter(role=>!['postgres','redis','openbao','keycloak','ui-prod','docs','nginx-proxy'].includes(role)),
  ['ui-prod','docs','nginx-proxy']];
 const protectedIds=[...plan.scope.productionAllDoNotStart,...plan.scope.alreadyOffBetaDoNotStart,
  plan.scope.targets.find(row=>row.role==='northstar-admissions')].map(row=>row.cid);
 assert.equal(protectedIds.length,47);assert.equal(new Set(protectedIds).size,47);
 assert(protectedIds.every(id=>Object.hasOwn(before,id)&&![...targets.values()].includes(id)));
 assert(Array.isArray(resume.phaseResults)&&resume.phaseResults.length===PHASES.length);
 assert.equal(resume.phaseResults[0].sha256,INFRA_RECEIPT,'Only the reviewed infrastructure predecessor is accepted');
 const generations=new Map();
 for(let i=0;i<PHASES.length;i++){
  const receipt=boundJson(resume.phaseResults[i]);
  assert.equal(receipt.state,'BETA_RETAINED_PHASE_COMPLETE');assert.equal(receipt.phase,PHASES[i]);
  assert.equal(receipt.planSha256,PLAN);
  assert.equal(receipt.sourceSha256,i===0?INFRA_SOURCE:SOURCE);
  assert.equal(receipt.production32Off,true);assert.equal(receipt.alreadyOffBeta14Off,true);
  assert.equal(receipt.northstarOff,true);assert.equal(receipt.demoQualified,false);
  assert(Array.isArray(receipt.started));
  assert.deepEqual(receipt.started.map(row=>row.role),groups[i],'Beta startup phase order changed');
  if(i>0)assert.deepEqual(receipt.priorPhaseRefs,resume.phaseResults.slice(0,i));
  for(const row of receipt.started){
   assert.equal(targets.get(row.role),row.cid);assert(!generations.has(row.cid),'Duplicate restarted container');
   assert(Number.isInteger(row.pid)&&row.pid>0&&Number.isFinite(Date.parse(row.startedAt)));
   assert(row.health==='healthy'||row.health===null||(row.role==='openbao'&&row.health==='starting'
    &&row.openbaoUnsealStillRequiresSeparateGate===true),'Unexpected startup health');
   generations.set(row.cid,row);
  }
 }
 assert.equal(generations.size,28,'Every reviewed beta target must complete');
 const expected=expectedRuntime(base);
 assert.equal(expected.length,22);assert.equal(new Set(expected.map(row=>row.role)).size,22);
 const rows=expected.map(row=>{
  const cid=row.requiredContainerId||row.requiredObservation?.containerId,actual=generations.get(cid);
  assert(actual&&actual.role===row.role,'Functional role was not restarted as reviewed');
  const previous=row.requiredStartedAt??row.requiredObservation?.startedAt;
  assert(Number.isFinite(Date.parse(previous))&&Date.parse(actual.startedAt)>Date.parse(previous),
   'Beta resume generation must be newer');
  return {...row,requiredStartedAt:actual.startedAt,requiredHostPid:actual.pid,
   ...(row.requiredObservation?{requiredObservation:{...row.requiredObservation,startedAt:actual.startedAt,hostPid:actual.pid}}:{})};
 });
 return {engineId:plan.engineId,allIds,protectedIds,rows};
}

function verifyLive(authority,readDocker){
 assert.equal(JSON.parse(readDocker(['info','--format','{{json .}}'])).ID,authority.engineId);
 const ids=readDocker(['ps','-a','-q','--no-trunc']).trim().split(/\s+/).filter(Boolean).sort();
 assert.deepEqual(ids,authority.allIds,'Docker registration set changed');
 const protectedRows=JSON.parse(readDocker(['inspect',...authority.protectedIds]));
 assert.equal(protectedRows.length,authority.protectedIds.length);
 const byId=new Map(protectedRows.map(row=>[row.Id,row]));
 for(const cid of authority.protectedIds){const state=byId.get(cid)?.State;
  assert(state&&state.Running===false&&state.Pid===0&&!state.Restarting&&!state.OOMKilled,'Protected service started');}
}
module.exports={authority,verifyLive};
