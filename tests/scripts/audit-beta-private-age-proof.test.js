const assert = require('node:assert/strict');
const test = require('node:test');
const { createAgeProofController } = require('./audit-beta-private-age-proof');

const expected = { run_id: 'run-1', organization_id: 'org-1', trusted_template_id: 'template-1',
  rejected_template_id: 'template-2', policy_id: 'policy-1', trust_profile_id: 'trust-1',
  service_origin: 'https://demo.example.test' };
const lane = 'eudi-age-proof-interoperability';
const okay = body => ({ status: 200, body });
const plan = {
  trusted_issuance: { method: 'POST', path: '/v1/issuance', body: { credential_template_id: 'template-1' } },
  rejected_issuance: { method: 'POST', path: '/v1/issuance', body: { credential_template_id: 'template-2' } },
  verification: { method: 'POST', path: '/v1/flows/verify', body: { organization_id: 'org-1' } },
  setup_sha256: 'a'.repeat(64),
};

function fixture({ onApi, onCheck, readRequest, page = {} } = {}) {
  const calls = [];
  const states = [];
  const controller = createAgeProofController({
    page, expected, syntheticClaims: { age_over_21: true },
    api: async (_page, route, options = {}) => {
      const call = { route, method: options.method || 'GET', body: options.body && JSON.parse(options.body) };
      calls.push(call);
      const reply = await onApi?.(call);
      if (reply !== undefined) return reply;
      return okay({ name: 'Fixture resource' });
    },
    check: (operation, bound, observed) => {
      assert.equal(bound, expected);
      const result = onCheck?.(operation, observed);
      if (result !== undefined) return result;
      if (operation === 'prepare') return plan;
      if (operation === 'cleanup') return { actions: [], pending_offers: observed.owned_issuance.map(item => item.id) };
      return {};
    },
    readRequest: readRequest || (async () => 'measured-request'),
    onState: state => states.push(state),
  });
  return { controller, calls, states };
}

test('D03 dependency reads fail before mutation and do not report an uncertain creation', async () => {
  const { controller, calls } = fixture({ onApi: call => {
    if (call.route.includes('credential-templates')) throw Error('Template unavailable');
  } });
  await assert.rejects(controller.preflight(), /Template unavailable/);
  assert.equal((await controller.cleanup()).ok, true);
  assert.deepEqual(controller.owned, { issuance: [], instances: [], uncertainMutations: [] });
  assert.equal(calls.filter(call => call.method !== 'GET').length, 0);
});

test('D03 retains an issuance ID before a lost verification creation response', async () => {
  const { controller, states } = fixture({ onApi: call => {
    if (call.route === '/v1/issuance') return okay({ id: 'transaction-1', organization_id: 'org-1', credential_template_id: 'template-1' });
    if (call.route === '/v1/flows/verify') throw Error('Lost creation response');
    if (call.route.startsWith('/v1/issued-credentials?')) return okay([]);
  } });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /Lost creation response/);
  assert.equal(controller.owned.issuance[0].id, 'transaction-1');
  assert.equal(controller.owned.uncertainMutations.length, 1);
  assert.equal(states.at(-1).ownedResources.issuance[0].id, 'transaction-1');
  const cleanup = await controller.cleanup();
  assert.equal(cleanup.ok, false);
  assert.deepEqual(cleanup.pendingOffers, ['transaction-1']);
  assert.equal(cleanup.uncertainMutations[0].operation, `${lane}-trusted-verification`);
});

test('D03 never reports clean after a successful issuance response without its public ID', async () => {
  const { controller, calls } = fixture({ onApi: call => {
    if (call.route === '/v1/issuance') return okay({ transaction_id: 'legacy-or-unknown' });
  } });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /no exact resource ID/);
  const cleanup = await controller.cleanup();
  assert.equal(cleanup.ok, false);
  assert.equal(cleanup.uncertainMutations.length, 1);
  assert.equal(calls.filter(call => call.method !== 'GET').length, 1);
});

test('D03 pending cleanup uses exact shared cancellation and retains unconfirmed outcomes', async () => {
  for (const confirmed of [true, false]) {
    const requests = [];
    let revoked = false;
    const page = { evaluate: async (_fn, request) => {
      requests.push(request);
      const { requestPath, requestOptions } = request;
      if (requestPath === '/v1/issued-credentials?organization_id=org-1') {
        return { ok: true, ...okay([{ id: 'unrelated-credential', organization_id: 'org-1', flow_execution_id: 'previous-run' }]) };
      }
      if (requestPath === '/v1/issuance/transaction-1/revoke') {
        assert.equal(requestOptions.method, 'POST');
        assert.deepEqual(JSON.parse(requestOptions.body), { reason: 'D03 current-run cleanup' });
        revoked = confirmed;
        // A successful mutation response alone cannot prove cleanup.
        return { ok: true, ...okay({ id: 'transaction-1', status: 'revoked' }) };
      }
      assert.equal(requestPath, '/v1/issuance/transaction-1?organization_id=org-1');
      return { ok: true, ...okay({ id: 'transaction-1', organization_id: 'org-1',
        credential_template_id: 'template-1', application_id: null, status: revoked ? 'revoked' : 'expired' }) };
    } };
    const { controller, states } = fixture({ page, onApi: call => {
      if (call.route === '/v1/issuance') return okay({ id: 'transaction-1', organization_id: 'org-1', credential_template_id: 'template-1' });
      if (call.route === '/v1/flows/verify') return { status: 409, body: { error: 'conflict' } };
      if (call.route.startsWith('/v1/issued-credentials?')) return okay([]);
    } });
    await controller.preflight();
    await assert.rejects(controller.prepareLane(lane), /HTTP 409/);
    const cleanup = await controller.cleanup();
    const uncertainty = confirmed ? [] : [{ operation: 'transaction_cancellation', transactionId: 'transaction-1' }];
    assert.equal(cleanup.ok, confirmed);
    assert.deepEqual(cleanup.pendingOffers, confirmed ? [] : ['transaction-1']);
    assert.deepEqual(cleanup.uncertainMutations, uncertainty);
    assert.deepEqual(states.at(-1).ownedResources.uncertainMutations, uncertainty);
    assert.equal(cleanup.actions[0].id, 'transaction-1');
    assert.equal(cleanup.actions[0].ok, confirmed);
    assert.equal(cleanup.actions[0].cancellation.scope, 'TRANSACTION_CANCELLATION_ONLY');
    assert.deepEqual(requests.map(({ requestPath, requestOptions }) => [requestOptions.method || 'GET', requestPath]), [
      ['GET', '/v1/issuance/transaction-1?organization_id=org-1'],
      ['GET', '/v1/issued-credentials?organization_id=org-1'],
      ['POST', '/v1/issuance/transaction-1/revoke'],
      ['GET', '/v1/issuance/transaction-1?organization_id=org-1'],
    ]);
  }
});

test('D03 retains both exact IDs before request inspection fails and cleans only those resources', async () => {
  const { controller, calls } = fixture({
    readRequest: async () => { throw Error('Signed request missing'); },
    onApi: call => {
      if (call.route === '/v1/issuance') return okay({ id: 'transaction-1', organization_id: 'org-1', credential_template_id: 'template-1' });
      if (call.route === '/v1/flows/verify') return okay({ instance_id: 'instance-1' });
      if (call.route.startsWith('/v1/issued-credentials?')) return okay([
        { id: 'owned-credential', flow_execution_id: 'transaction-1' },
        { id: 'unrelated-credential', flow_execution_id: 'old-transaction' },
      ]);
      if (call.route === '/v1/issued-credentials/owned-credential') return okay({ id: 'owned-credential', organization_id: 'org-1', status: 'REVOKED' });
      if (call.route === '/v1/flows/instances/instance-1') return okay({ id: 'instance-1', organization_id: 'org-1', status: 'CANCELLED' });
    },
    onCheck: (operation, observed) => {
      if (operation !== 'cleanup') return;
      assert.deepEqual(observed.owned_issuance.map(item => item.id), ['transaction-1']);
      assert.deepEqual(observed.owned_instances.map(item => item.id), ['instance-1']);
      return { pending_offers: [], actions: [
        { resource: 'credential', id: 'owned-credential', method: 'POST', path: '/v1/issued-credentials/owned-credential/revoke', body: {}, expected_status: 'REVOKED' },
        { resource: 'instance', id: 'instance-1', method: 'POST', path: '/v1/flows/instances/instance-1/cancel', body: {}, expected_status: 'CANCELLED' },
      ] };
    },
  });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /Signed request missing/);
  assert.deepEqual(controller.owned.instances.map(item => item.id), ['instance-1']);
  assert.equal(controller.owned.uncertainMutations.length, 0);
  const cleanup = await controller.cleanup();
  assert.equal(cleanup.ok, true);
  assert.deepEqual(calls.filter(call => call.method === 'POST').map(call => call.route), [
    '/v1/issuance', '/v1/flows/verify',
    '/v1/issued-credentials/owned-credential/revoke', '/v1/flows/instances/instance-1/cancel',
  ]);
  await assert.rejects(controller.prepareLane(lane), /duplicated/);
});

test('D03 hands the native wallet the OpenID4VP request URI', async () => {
  let issued = 0;
  let started = 0;
  const { controller, calls } = fixture({ onApi: call => {
    if (call.route === '/v1/issuance') return okay({ id: `transaction-${++issued}`,
      organization_id: 'org-1', credential_template_id: call.body.credential_template_id,
      credential_offer_uri: 'openid-credential-offer://example' });
    if (call.route === '/v1/flows/verify') {
      const instance = `instance-${++started}`;
      const walletUri = `openid4vp://authorize?request_uri=https%3A%2F%2Fdemo.example.test%2Fv1%2Fflows%2Finstances%2F${instance}%2Frequest`;
      return okay({ instance_id: instance, request_uri: walletUri, qr_code_data: walletUri });
    }
  } });
  await controller.preflight();
  const binding = await controller.prepareLane(lane);
  assert.equal(started, 2);
  assert.match(binding.trusted.requestUri, /^openid4vp:\/\/authorize\?/);
  assert.match(binding.rejected.requestUri, /^openid4vp:\/\/authorize\?/);
  assert.deepEqual(calls.filter(call => call.method === 'POST').map(call => call.route), [
    '/v1/issuance', '/v1/flows/verify', '/v1/issuance', '/v1/flows/verify',
  ]);
});

test('D03 proven request rejection leaves no uncertain mutation', async () => {
  const { controller } = fixture({ onApi: call => {
    if (call.route === '/v1/issuance') return { status: 409, body: { error: 'conflict' } };
  } });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /HTTP 409/);
  assert.equal((await controller.cleanup()).ok, true);
  assert.deepEqual(controller.owned.issuance, []);
});

test('D03 Rust ownership rejection prevents every cleanup mutation', async () => {
  const { controller, calls } = fixture({
    onApi: call => {
      if (call.route === '/v1/issuance') return okay({ id: 'transaction-1', organization_id: 'other-org', credential_template_id: 'template-1' });
      if (call.route.startsWith('/v1/issued-credentials?')) return okay([{ id: 'foreign-record' }]);
    },
    onCheck: operation => { if (operation === 'cleanup') throw Error('Inventory crossed organization boundary'); },
  });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /organization or template boundary/);
  const cleanup = await controller.cleanup();
  assert.equal(cleanup.ok, false);
  assert.match(cleanup.errors[0], /organization boundary/);
  assert.equal(calls.filter(call => call.method !== 'GET').length, 1);
});

test('D03 generic rejection diagnostics cannot become the issuer-trust assertion', async () => {
  const { controller } = fixture({ onCheck: operation => {
    if (operation === 'denied') return { observation: 'UNTRUSTED_FIXTURE_REJECTED', issuer_trust_denial_observed: false };
  } });
  const item = templateId => ({ templateId, instanceId: 'instance-1', issuanceReply: okay({}), requestBinding: {} });
  await assert.rejects(controller.completeLane(lane, { trusted: item('template-1'), rejected: item('template-2') }, {
    report: {}, rejectionText: 'Presentation failed', scenarioSha256: 'f'.repeat(64), denialActionIndex: 1,
  }), /BLOCKED: generic wallet rejection/);
  assert.deepEqual(controller.laneResults, []);
});

const {ageProofExecutionMode,ageProofOperationsComplete}=require('./audit-beta-private-age-proof');
test('D03 explicitly selects functional/no-media or full recording without treating missing mode as opt-out',()=>{
 assert.deepEqual(ageProofExecutionMode({RECORD_VIDEO:'0'}),{functionalRerun:true,recordVideo:false});
 assert.deepEqual(ageProofExecutionMode({RECORD_VIDEO:'1'}),{functionalRerun:false,recordVideo:true});
 for(const value of [undefined,'false','true',''])assert.throws(()=>ageProofExecutionMode({RECORD_VIDEO:value}),/explicit RECORD_VIDEO/);
});
test('D03 functional readiness requires original assertions, two distinct stock lanes, and exact cleanup',()=>{
 const valid=()=>({errors:[],cleanup:{ok:true},androidGate:{result:'PASS'},lanes:[{laneId:'eudi-age-proof-interoperability'},{laneId:'spruceid-age-proof-interoperability'}],
 behaviorAssertions:Object.fromEntries(['trusted_mdl_issuance','request_only_age_over_21','verify_issuer_trust_and_minimum_response','untrusted_issuer_denied','independent_wallets_pass'].map(k=>[k,true]))});
 assert.equal(ageProofOperationsComplete(valid()),true);
 for(const change of [r=>r.cleanup.ok=false,r=>r.lanes.pop(),r=>r.lanes[1].laneId=r.lanes[0].laneId,
  r=>r.androidGate.result='FAIL',r=>r.errors.push('failure'),...Object.keys(valid().behaviorAssertions).map(k=>r=>r.behaviorAssertions[k]=false)]){
  const r=valid();change(r);assert.equal(ageProofOperationsComplete(r),false);
 }
});

const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {prepareAgeProofLiveInputs,finalizeAgeProofRun,ageProofUsesLiveClient}=require('./audit-beta-private-age-proof');
const finalizeAgeProofFunctional=(report,client,annotate)=>finalizeAgeProofRun(report,client,{functionalRerun:true,recordVideo:false},annotate);
function completedFunctionalReport(){return {errors:[],cleanup:{ok:true},androidGate:{result:'PASS'},
 lanes:[{laneId:'eudi-age-proof-interoperability'},{laneId:'spruceid-age-proof-interoperability'}],
 behaviorAssertions:Object.fromEntries(['trusted_mdl_issuance','request_only_age_over_21','verify_issuer_trust_and_minimum_response','untrusted_issuer_denied','independent_wallets_pass'].map(k=>[k,true]))};}
const annotate=(_report,_client,{ready,cleanupComplete})=>ready&&cleanupComplete;
test('D03 binds its actual page then uses the shared exact-byte input acknowledgement and seal',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'d03-inputs-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const page={},events=[],inputs={schemaVersion:1,scenario:'private-online-age-proof',expected:{run_id:'actual-current-test-run'},syntheticClaims:{age_over_21:true}};
 let releaseRead;const ack=new Promise(resolve=>releaseRead=resolve);let returned=false;
 const client={bindPage(actual){assert.equal(actual,page);events.push('bind');},async readFixture(file){
  events.push('read');assert.equal(file,'d03-fixture-input.json');await ack;return fs.readFileSync(path.join(dir,file));
 },async seal(){events.push('seal');}};
 const pending=prepareAgeProofLiveInputs(dir,client,page,inputs).then(actual=>{returned=true;assert.deepEqual(actual,inputs);});
 await new Promise(resolve=>setImmediate(resolve));assert.equal(returned,false);assert.deepEqual(events,['bind','read']);
 releaseRead();await pending;assert.deepEqual(events,['bind','read','seal']);
 // The shared writer is exclusive; a second invocation cannot replace consumed inputs.
 await assert.rejects(prepareAgeProofLiveInputs(dir,client,page,inputs),/EEXIST/);
});
test('D03 refuses altered acknowledged input bytes and a rejected seal before any feature',async t=>{
 for(const fault of ['bytes','seal']){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'d03-input-refuse-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  let sealed=false;
  const client={bindPage(){},async readFixture(file){return fault==='bytes'?Buffer.from('{}'):fs.readFileSync(path.join(dir,file));},
   async seal(){sealed=true;throw Error('parent rejected SEAL');}};
  await assert.rejects(prepareAgeProofLiveInputs(dir,client,{}, {run_id:'fresh-test'}),fault==='bytes'?/fixture differs/:/parent rejected SEAL/);
  assert.equal(sealed,fault==='seal');
 }
});
test('D03 never publishes functional readiness until the same client COMPLETE is acknowledged',async()=>{
 const report=completedFunctionalReport(),events=[];let releaseComplete;
 const ack=new Promise(resolve=>releaseComplete=resolve);
 const client={async complete(){events.push('complete');assert.equal(report.cleanup.ok,true);await ack;},close(){events.push('close');}};
 const pending=finalizeAgeProofFunctional(report,client,annotate);
 await new Promise(resolve=>setImmediate(resolve));
 assert.deepEqual(events,['complete']);assert.equal(report.functionalReady,false);assert.equal(report.operations_verified,false);
 assert.equal(report.liveEvidenceCompletion.acknowledged,false);releaseComplete();assert.equal(await pending,true);
 assert.deepEqual(events,['complete','close']);assert.equal(report.liveEvidenceCompletion.acknowledged,true);
 assert.equal(report.functionalReady,true);assert.equal(report.operations_verified,true);assert.equal(report.releaseReady,false);
});
test('D03 refuses COMPLETE for failed cleanup, missing stock lane, original assertion failure or earlier error',async()=>{
 for(const fail of [r=>r.cleanup.ok=false,r=>r.lanes.pop(),r=>r.behaviorAssertions.untrusted_issuer_denied=false,r=>r.errors.push('original feature error')]){
  const report=completedFunctionalReport();fail(report);let completed=0,closed=0;
  assert.equal(await finalizeAgeProofFunctional(report,{complete(){completed++;},close(){closed++;}},annotate),false);
  assert.equal(completed,0);assert.equal(closed,1);assert.equal(report.functionalReady,false);assert.equal(report.operations_verified,false);
 }
});
test('D03 completion, annotation and close failures keep original errors and cannot report functional success',async()=>{
 for(const fault of ['complete','annotation','close']){
  const report=completedFunctionalReport();let closed=0;
  const client={async complete(){if(fault==='complete')throw Error('parent COMPLETE rejected');},close(){closed++;if(fault==='close')throw Error('evidence close rejected');}};
  const apply=(...args)=>{if(fault==='annotation')throw Error('runtime acknowledgement rejected');return annotate(...args);};
  assert.equal(await finalizeAgeProofFunctional(report,client,apply),false);assert.equal(closed,1);
  assert.equal(report.functionalReady,false);assert.equal(report.operations_verified,false);assert.equal(report.releaseReady,false);assert.equal(report.errors.length,1);
 }
 const original=completedFunctionalReport();original.errors.push('original feature error');
 await finalizeAgeProofFunctional(original,{complete(){throw Error('must not complete');},close(){throw Error('close also failed');}},annotate);
 assert.deepEqual(original.errors,['original feature error','close also failed']);
});

test('D03 selected parent lifecycle applies to both modes; only standalone recording can omit it',()=>{
 const functional=ageProofExecutionMode({RECORD_VIDEO:'0'}),recording=ageProofExecutionMode({RECORD_VIDEO:'1'});
 assert.equal(ageProofUsesLiveClient(functional,{}),true);
 assert.equal(ageProofUsesLiveClient(recording,{}),false);
 for(const mode of [functional,recording])for(const value of ['selected-helper.js',''])
  assert.equal(ageProofUsesLiveClient(mode,{DEMO_EXECUTION_EVIDENCE_HELPER:value}),true);
});
test('D03 normal recording with a selected parent retains media gates and awaits COMPLETE before release readiness',async()=>{
 const mode=ageProofExecutionMode({RECORD_VIDEO:'1'}),report=completedFunctionalReport();
 report.applicationVideo={path:'actual-test-recording.webm',sha256:'a'.repeat(64)};
 let acknowledge;const wait=new Promise(resolve=>acknowledge=resolve),events=[];
 const pending=finalizeAgeProofRun(report,{async complete(){events.push('complete');await wait;},close(){events.push('close');}},mode);
 await new Promise(resolve=>setImmediate(resolve));assert.equal(report.releaseReady,false);assert.deepEqual(events,['complete']);
 acknowledge();assert.equal(await pending,true);assert.equal(report.releaseReady,true);assert.equal(report.functionalReady,false);
 assert.equal(report.liveEvidenceCompletion.acknowledged,true);assert.deepEqual(events,['complete','close']);
 for(const fault of ['media','assertion','cleanup','complete','close']){
  const r=completedFunctionalReport();r.applicationVideo=report.applicationVideo;let completed=0,closed=0;
  if(fault==='media')delete r.applicationVideo;if(fault==='assertion')r.behaviorAssertions.untrusted_issuer_denied=false;if(fault==='cleanup')r.cleanup.ok=false;
  const passed=await finalizeAgeProofRun(r,{complete(){completed++;if(fault==='complete')throw Error('recording COMPLETE refused');},close(){closed++;if(fault==='close')throw Error('recording evidence close refused');}},mode);
  assert.equal(passed,false);assert.equal(r.releaseReady,false);assert.equal(closed,1);assert.equal(completed,['complete','close'].includes(fault)?1:0);
 }
});
test('D03 standalone recording keeps its strict media success while functional mode cannot fall back to standalone',async()=>{
 const report=completedFunctionalReport();report.applicationVideo={path:'actual-test-recording.webm'};
 assert.equal(await finalizeAgeProofRun(report,null,ageProofExecutionMode({RECORD_VIDEO:'1'})),true);
 assert.equal(report.liveEvidenceCompletion.selected,false);assert.equal(report.liveEvidenceCompletion.acknowledged,false);
 const functional=completedFunctionalReport();assert.equal(await finalizeAgeProofRun(functional,null,ageProofExecutionMode({RECORD_VIDEO:'0'})),false);
 assert.equal(functional.functionalReady,false);assert.match(functional.errors[0],/requires its live evidence client/);
});
