'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const stock = require('./run-canvas-oss-standard-contract');
const { retireCaptureIssuance } = require('./audit-beta-canvas-capture');

const ORG = '00000000-0000-0000-0000-000000000001';
const PLATFORM = '11111111-1111-4111-8111-111111111111';
const BINDING = '22222222-2222-4222-8222-222222222222';
const APPLICATION = '33333333-3333-4333-8333-333333333333';
const TEMPLATE = '44444444-4444-4444-8444-444444444444';

function fixture({ foreign = false, remainsActive = false } = {}) {
  const calls = [];
  const owned = { id: BINDING, organization_id: foreign ? 'foreign' : ORG,
    platform_id: PLATFORM, display_name: 'Portable Canvas badge run-owned',
    enabled: true, activated_at: '2026-11-05T00:00:00Z' };
  const state = { organizationId: ORG, platformId: PLATFORM, binding: { id: BINDING },
    runSuffix: 'run-owned', bindingActivationPossible: true, applicationId: APPLICATION,
    templates: { credential: { id: TEMPLATE } },
    owned: { martyBindingId: BINDING, martyPlatformId: PLATFORM },
    marty: {
      async get() { calls.push('binding-get');
        return calls.filter(value => value === 'binding-get').length === 1 || remainsActive
          ? owned : { ...owned, enabled: false, activated_at: null };
      },
      async post() { calls.push('binding-deactivate'); return {}; },
    } };
  const receipt = { complete: true, exactApplication: APPLICATION };
  const operations = { ...stock, async retireCanvasApplication(input) {
    calls.push('application-retire');
    assert.equal(input.applicationId, APPLICATION);
    assert.equal(input.bindingId, BINDING);
    input.reconcile();
    return receipt;
  } };
  return { calls, state, receipt, operations };
}

test('full capture fences and confirms the exact binding before application retirement', async () => {
  const { calls, state, receipt, operations } = fixture();
  const report = { pendingOperations: [], transactionId: 'owned-transaction' };
  assert.equal(await retireCaptureIssuance(state, report, APPLICATION, operations), receipt);
  assert.equal(report.issuanceRetirement, receipt);
  assert.deepEqual(calls, ['binding-get', 'binding-deactivate', 'binding-get', 'application-retire']);
});

test('foreign binding or failed fence preserves existing receipt and prevents retirement', async () => {
  for (const mode of ['foreign', 'remainsActive']) {
    const { calls, state, operations } = fixture({ [mode]: true });
    const prior = { historical: true };
    const report = { pendingOperations: [], issuanceRetirement: prior };
    await assert.rejects(retireCaptureIssuance(state, report, APPLICATION, operations));
    assert.equal(report.issuanceRetirement, prior);
    assert.ok(!calls.includes('application-retire'));
  }
});

test('unknown application after activation remains fail closed before any binding mutation', async () => {
  const { calls, state, operations } = fixture();
  state.applicationId = undefined;
  state.owned.martyLearnerLaunchIntent = true;
  const report = { pendingOperations: [] };
  await assert.rejects(retireCaptureIssuance(state, report, undefined, operations));
  assert.deepEqual(calls, []);
  assert.equal(report.issuanceRetirement, undefined);
});

test('activated prelaunch binding uses the maintained fenced application absence proof', async () => {
  const { state, operations } = fixture();
  state.applicationId = undefined;
  state.owned.martyBindingActivationAttempted = true;
  const steps = [];
  let disabled = false;
  state.marty.get = async route => {
    if (route.endsWith('/canvas-sync-jobs?organization_id=' + ORG + '&limit=500')) {
      steps.push('jobs'); return [{ id: 'job-owned', organization_id: ORG,
        binding_id: BINDING, platform_id: PLATFORM, target_type: 'background_roster',
        application_id: null, status: 'succeeded' }];
    }
    if (route.includes('/canvas-award-candidates?')) { steps.push('candidates');
      return [{ organization_id: ORG, binding_id: BINDING,
        application_id: null, status: 'pending_claim' }];
    }
    if (route.endsWith(`/program-bindings/${BINDING}/applications`)) {
      steps.push('applications');
      return { organization_id: ORG, binding_id: BINDING, platform_id: PLATFORM,
        binding_disabled: disabled, complete: true, applications: [] };
    }
    assert.equal(route, `/v1/integrations/canvas/program-bindings/${BINDING}`);
    steps.push('binding-get');
    return { id: BINDING, organization_id: ORG, platform_id: PLATFORM,
      display_name: 'Portable Canvas badge run-owned', enabled: !disabled,
      activated_at: disabled ? null : '2026-11-05T00:00:00Z' };
  };
  state.marty.post = async route => {
    assert.equal(route, `/v1/integrations/canvas/program-bindings/${BINDING}/deactivate`);
    steps.push('binding-deactivate'); disabled = true; return {};
  };
  const receipt = { complete: true, noApplication: true };
  operations.retireCanvasApplication = async input => {
    steps.push('application-retire');
    assert.equal(input.applicationId, undefined);
    assert.equal(disabled, true);
    input.reconcile();
    return receipt;
  };
  const report = { pendingOperations: [] };
  assert.equal(await retireCaptureIssuance(state, report, undefined, operations), receipt);
  assert.equal(state.prelaunchAbsenceConfirmed, true);
  assert.equal(report.issuanceRetirement, receipt);
  assert.deepEqual(steps, ['binding-get', 'binding-deactivate', 'binding-get',
    'jobs', 'candidates', 'applications', 'binding-get', 'binding-get', 'application-retire']);
});
