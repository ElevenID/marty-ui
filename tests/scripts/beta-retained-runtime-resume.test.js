'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {authority,verifyLive}=require('./beta-retained-runtime-resume');
const PLAN='b296aee1812106df5215f0e18da43478b31f02a46b8828bc82fbbb946ff09b19';
const SOURCE='a97eecd33d9fe99fa27445b4d2f95448013457bbf1dbd6566531ed813bba2b42';
const INFRA='188e9c3d93b18d9d6c266ff6c1459234a8c8019f4a8f775df5339228320dcbe9';
const hex=n=>n.toString(16).padStart(64,'0');
const ref=(path,sha256)=>({path,sha256});
function fixture(){
 const names=['postgres','redis','openbao','keycloak',...Array.from({length:21},(_,i)=>'service-'+i),'ui-prod','docs','nginx-proxy'];
 const start=names.map((role,i)=>({role,cid:hex(i+1)}));
 const baseRef=ref('base',hex(901)),planRef=ref('plan',PLAN),sourceRef=ref('source',SOURCE),afterRef=ref('after','a84e079e4aac883e9f6afbe19c8d742d444deef70fd52c8c508d6ec1361dcb03');
 const protectedRows=Array.from({length:47},(_,i)=>({cid:hex(i+100),role:i===46?'northstar-admissions':'protected-'+i}));
 const base={schema:'marty.functional-mixed-runtime/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,baseProfile:baseRef};
 const phases=['infrastructure','keycloak','clients','edge'];
 const groups=[names.slice(0,3),names.slice(3,4),names.slice(4,25),names.slice(25)];
 const phaseResults=phases.map((_,i)=>ref('phase'+i,i===0?'22d2487cbecdaf6d3cda8057484fb0e9da5a487e7fb5400dce61beba55debf0f':hex(i+700)));
 const receipts=phases.map((phase,i)=>({state:'BETA_RETAINED_PHASE_COMPLETE',phase,planSha256:PLAN,
  sourceSha256:i===0?INFRA:SOURCE,production32Off:true,alreadyOffBeta14Off:true,northstarOff:true,demoQualified:false,
  priorPhaseRefs:phaseResults.slice(0,i),started:groups[i].map(role=>({role,cid:start.find(x=>x.role===role).cid,
   pid:300+names.indexOf(role),startedAt:'2026-11-01T23:00:00Z',health:role==='openbao'?null:'healthy'}))}));
 const plan={schema:'marty.beta-only-resume-plan/v1',engineId:'3dbbbe66-1c98-4e0c-b0a6-f927c05e7341',
  sources:{sharedShutdownGuards:ref('stop','0c814e20f8cb955864d70407526e327710cecb9f96e064c861eee3cdacd43afb'),retainedAfter:afterRef},
  proposal:{startOrder:start},scope:{productionAllDoNotStart:protectedRows.slice(0,32),alreadyOffBetaDoNotStart:protectedRows.slice(32,46),
   targets:[...start,protectedRows[46]]}};
 const before=Object.fromEntries([...start,...protectedRows].map(row=>[row.cid,{}]));
 const profile={...base,baseProfile:baseRef,runtimeResume:{plan:planRef,source:sourceRef,phaseResults}};
 const values={base,plan,after:before,...Object.fromEntries(receipts.map((r,i)=>['phase'+i,r]))};
 const context={boundJson:r=>values[r.path],verifyBoundFile:()=>{},expectedRuntime:()=>start.slice(0,22).map(row=>({
  role:row.role,requiredContainerId:row.cid,requiredStartedAt:'2026-11-01T20:00:00Z',requiredHostPid:100,
  requiredObservation:{startedAt:'2026-11-01T20:00:00Z',hostPid:100}}))};
 return {profile,context,receipts,plan,before,start,protectedRows};
}
test('reviewed retained beta phases advance only the selected 22 generations',()=>{
 const f=fixture(),result=authority(f.profile,f.context);
 assert.equal(result.rows.length,22);assert.equal(result.rows[0].requiredHostPid,300);
 assert.equal(result.rows[0].requiredContainerId,f.start[0].cid);
 assert.equal(result.rows[0].requiredObservation.startedAt,'2026-11-01T23:00:00Z');
 const read=args=>{
  if(args[0]==='info')return JSON.stringify({ID:result.engineId});
  if(args[0]==='ps')return result.allIds.join('\n');
  if(args[0]==='inspect')return JSON.stringify(args.slice(1).map(Id=>({Id,State:{Running:false,Pid:0,Restarting:false,OOMKilled:false}})));
  throw Error('Unexpected Docker read');
 };
 verifyLive(result,read);
 assert.throws(()=>verifyLive(result,args=>args[0]==='ps'?result.allIds.slice(1).join('\n'):read(args)),/registration set/);
 assert.throws(()=>verifyLive(result,args=>args[0]==='inspect'?JSON.stringify(args.slice(1).map(Id=>({Id,State:{Running:true,Pid:1}}))):read(args)),/Protected service started/);
});
test('missing phase, changed source, phase order and stale generation are refused',()=>{
 const f=fixture();f.receipts[2].started.reverse();
 assert.throws(()=>authority(f.profile,f.context),/phase order/);
 f.receipts[2].started.reverse();f.profile.runtimeResume.phaseResults.pop();
 assert.throws(()=>authority(f.profile,f.context));
 f.profile.runtimeResume.phaseResults=fixture().profile.runtimeResume.phaseResults;
 f.profile.runtimeResume.phaseResults[0].sha256=hex(99);
 assert.throws(()=>authority(f.profile,f.context),/reviewed infrastructure predecessor/);
 f.profile.runtimeResume.phaseResults[0].sha256='22d2487cbecdaf6d3cda8057484fb0e9da5a487e7fb5400dce61beba55debf0f';
 f.profile.runtimeResume.source.sha256=hex(99);
 assert.throws(()=>authority(f.profile,f.context));
 f.profile.runtimeResume.source.sha256=SOURCE;f.receipts[1].started[0].startedAt='2026-11-01T19:00:00Z';
 assert.throws(()=>authority(f.profile,f.context),/generation must be newer/);
});
