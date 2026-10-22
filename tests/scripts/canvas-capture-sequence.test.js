'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { runCanvasCapture, requireJobBinding, requireIssuedBinding, requireCaptureMutationReconciliation } = require('./canvas-capture-sequence');
const stock = require('./run-canvas-oss-standard-contract');
const APP = '10000000-0000-4000-8000-000000000001';
const scope = { application_id: APP, organization_id: 'org', binding_id: 'binding',
  platform_id: 'platform', credential_template_id: 'template' };

test('foreign, stale, replayed and unsuccessful terminal jobs cannot bind a capture', () => {
  const job = { ...scope, id: 'job', status: 'succeeded', created_at: new Date(10000).toISOString() };
  const run = (change, seen = new Set()) => requireJobBinding(
    { body: { sync: { job_id: 'job' } }, job: { ...job, ...change } }, scope, seen, 10000);
  for (const field of ['application_id', 'organization_id', 'binding_id', 'platform_id', 'id']) {
    assert.throws(() => run({ [field]: 'foreign' }));
  }
  assert.throws(() => run({ created_at: new Date(0).toISOString() }));
  assert.throws(() => run({ status: 'failed' }));
  assert.throws(() => run({}, new Set(['job'])));
  assert.equal(run({}).id, 'job');
});

test('receipt readback rejects wrong transaction, template, organization, duplicates or nonactive credential', () => {
  const record = { ...scope, id: 'credential', flow_execution_id: 'tx', status: 'ACTIVE' };
  for (const field of ['organization_id', 'credential_template_id', 'flow_execution_id', 'status']) {
    assert.throws(() => requireIssuedBinding([{ ...record, [field]: 'foreign' }], scope, 'tx'));
  }
  assert.throws(() => requireIssuedBinding([record, record], scope, 'tx'));
  assert.equal(requireIssuedBinding([record], scope, 'tx'), record);
  assert.equal(requireIssuedBinding([{ ...record, application_id: 'other' }], scope, 'tx'), null);
});

function harness({ scenario = 'external-evidence-to-credential', fail = '' } = {}) {
  const state = { grade: 95, issued: false, approved: false, reserved: false, revision: 0, jobs: 0, mutations: [], checkpoints: [],
    claimObserved: false, claimClicked: false, walletReceipts: 0 };
  const report = { behaviorAssertions: {} };
  const record = { ...scope, id: 'credential', flow_execution_id: 'tx', status: 'ACTIVE', issuer_did: 'did:web:issuer.test' };
  const review = { id: 'review', application_id: APP, credential_id: 'credential', status: 'open' };
  const marty = {
    async get(url) {
      if (url.startsWith('/v1/issuance?')) return state.reserved || (fail === 'denied-transaction-reserved' && state.grade === 40)
        ? [{ ...scope, id: 'tx', status: 'pending' }] : [];
      if (url.startsWith('/v1/issued-credentials?')) return state.issued || (fail === 'denied-credential-issued' && state.grade === 40)
        ? [record] : [];
      if (url === '/v1/issued-credentials/credential') return record;
      if (url.startsWith('/v1/issuance/tx?')) return { ...scope, id: 'tx' };
      if (url.endsWith('/evidence-facts?current_only=true') || url.endsWith('/evidence-facts')) {
        if ((fail === 'post-denial-stale-evidence' && state.jobs === 4)
          || (fail === 'post-recovery-stale-evidence' && state.jobs === 5)) return state.lastFacts;
        const facts = [{ id: `fact-${state.revision}`, provider: 'canvas',
        requirement_id: 'score', fact_type: 'canvas.assignment_score', source: { source: 'canvas_rest' },
        verification: { status: 'VERIFIED' }, logical_key: 'a'.repeat(64),
        source_revision: String(state.revision).padStart(64, '0'), payload_hash: String(state.grade).padStart(64, '0'),
        observed_at: new Date(10000).toISOString(), effective_at: new Date(10000).toISOString() }];
        state.lastFacts = facts; return facts;
      }
      if (url.includes('/evidence-policy-reviews?')) return state.review ? [{ ...review,
        status: state.grade === 40 ? 'open' : 'resolved', resolution_action: 'evidence_recovered' }] : [];
      throw Error('Unexpected GET '+url);
    },
    async post(url, body, statuses) {
      if (url.endsWith('/approve')) {
        assert.equal(state.grade, 95); assert.equal(state.issued, false); state.approved = true;
        state.reserved = true;
        return { application_id: fail === 'foreign-approval' ? 'foreign' : APP, issuance_transaction_id: 'tx' };
      }
      assert.equal(url, '/v1/integrations/canvas/evidence-events');
      assert.equal(body.application_id, APP);
      assert.equal(body.canvas_account_id, 'untrusted-capture-account');
      assert.equal(body.completed, true);
      assert.equal(body.score_percent, 100);
      assert.deepEqual(statuses, [410]); state.legacy = true;
      if (fail === 'ingest-side-effect') state.revision++;
      return { detail: 'gone' };
    },
  };
  const page = {
    async evaluate() { return { claim: { unsigned: !state.issued,
      status: state.approved ? 'ready_to_claim' : 'pending_claim',
      available: state.approved || (fail === 'denied-claimable' && state.grade === 40) } }; },
    getByTestId(id) { return { waitFor: async () => {}, count: async () =>
      id === 'canvas-claim-action' && (state.approved || (fail === 'denied-claimable' && state.grade === 40)) ? 1 : 0,
    click: async () => {
      if (id === 'canvas-claim-action') {
        assert.equal(state.claimObserved, true, 'Claim observer must precede the product click');
        state.claimClicked = true;
      }
    },
      getByRole() { return { first() { return { click: async () => {} }; } }; } }; },
    async addStyleTag() {},
    async waitForResponse(predicate) {
      const origin = 'https://beta.elevenidllc.com';
      const endpoint = '/v1/integrations/canvas/lti/experience-sessions/current/claim';
      const response = (url, method = 'POST') => ({ url: () => url,
        request: () => ({ method: () => method }),
        status: () => fail === 'claim-http-failed' ? 404 : 200,
        json: async () => ({ id: fail === 'foreign-claim-application' ? 'foreign' : APP,
          organization_id: fail === 'foreign-claim-organization' ? 'foreign' : 'org',
          transaction_id: fail === 'foreign-claim-transaction' ? 'foreign' : 'tx',
          offer_url: 'offer-in-memory-only' }) });
      assert.equal(predicate(response('https://foreign.test' + endpoint)), false);
      assert.equal(predicate(response(origin + `/v1/me/applications/${APP}/claim`)), false);
      assert.equal(predicate(response(origin + endpoint + '/foreign')), false);
      assert.equal(predicate(response(origin + endpoint, 'GET')), false);
      const owned = response(origin + endpoint);
      assert.equal(predicate(owned), true);
      state.claimObserved = true;
      return owned;
    },
  };
  const setup = { organizationId: 'org', binding: { id: 'binding' }, platformId: 'platform',
    martyOrigin: 'https://beta.elevenidllc.com', fixtures: { course: { id: 1 }, assignment: { id: 2 }, learner: { id: 3 } },
    templates: { application: { id: 'application-template' }, credential: { id: 'template', vct: 'https://issuer.test/badge' }, policy: { id: 'policy' } },
    pinnedBinding: { evidence_requirements: [{ requirement_id: 'score', fact_type: 'canvas.assignment_score', source: 'canvas_rest' }] },
    marty, adminCanvas: { async putForm(url, body) {
      state.grade = body['submission[posted_grade]']; state.revision++;
      state.mutations.push(state.grade);
      if (state.issued && state.grade === 40) state.review = true;
      return { assignment_id: 2, user_id: 3, score: state.grade };
    } },
  };
  const operations = { ...stock,
    async waitForCanvasCourseCompletion() { return { requirement_count: 1, requirement_completed_count: 1 }; },
    async validateAndActivateBinding() { return { activation: { ready: true } }; },
    async waitForLatestRosterJob() { return { result: { pending_claim: 1 } }; },
    async waitForCandidate() { return { status: 'pending_claim' }; },
    async launchLearnerResource() { return { page, bootstrap: { application_id: APP,
      organization_id: fail === 'foreign-bootstrap' ? 'foreign' : 'org', application_template_id: 'application-template',
      credential_template_id: 'template', canvas_platform_id: 'platform', canvas_program_binding_id: 'binding' } }; },
    async reloadLearnerExperience() {},
    async triggerLearnerSync() {
      state.jobs++;
      const job = { ...scope, id: `job-${state.jobs}`, status: 'succeeded', created_at: new Date(10000).toISOString(),
        result: { policy_allowed: state.grade === 95 && !(fail === 'recovery-transient-course' && state.jobs === 3),
          requirements_checked: 1 } };
      if (fail === 'denial-sync' && state.grade === 40) throw Error('Worker failed');
      if (fail === 'stale-job' && state.jobs === 2) job.created_at = new Date(0).toISOString();
      return { body: { sync: { job_id: job.id } }, job };
    },
    async waitFor(fn) { const value = await fn(); assert.ok(value, 'Expected terminal result'); return value; },
  };
  const wallet = {
    async receiveCredential(_page, offer, vct) {
      assert.equal(state.claimClicked, true);
      assert.equal(offer, 'offer-in-memory-only');
      assert.equal(vct, setup.templates.credential.vct);
      state.walletReceipts++;
      state.issued = true;
      return { ok: true, receipt: { id: 'wallet-record', vct: setup.templates.credential.vct } };
    },
    async verify() { if (fail === 'wallet-presentation-rejected') return {
      session: { ok: true, status: 200, requestUri: '[present]' },
      wallet: { ok: false, status: 400 }, result: null };
    return { session: { ok: true }, wallet: { ok: true }, result: {
      httpStatus: 200, status: fail === 'verification-missing-status' ? undefined
        : fail === 'verification-pending' ? 'PENDING' : 'COMPLETED',
      evaluation: fail === 'verification-missing-evaluation' ? undefined : fail === 'verification-denied' ? 'failed' : 'passed',
      decision: fail === 'verification-denied' ? 'deny' : 'allow' } }; },
  };
  return { state, report, run: () => runCanvasCapture({ setup, page, adminPage: page, walletPage: page, scenario,
    operations, wallet, now: () => 10000, report,
    checkpoint: async (page, phase) => state.checkpoints.push(phase) }) };
}

test('D08 current operations bind one launch, approval, receipt, verifier and resolved review', async () => {
  const h = harness(); await h.run();
  assert.deepEqual(h.state.mutations, [40, 95, 40, 95]);
  assert.equal(h.report.unsignedPendingObserved, true);
  assert.equal(h.report.correctionReview.resolved, true);
  assert.equal(h.report.credentialId, 'credential');
  assert.equal(h.state.legacy, true);
  assert.equal(h.report.deniedEvidence.claimAvailable, false);
  assert.equal(h.report.untrustedIngest.authoritativeStateUnchanged, true);
  assert.deepEqual(h.report.untrustedIngest.before, h.report.untrustedIngest.after);
  assert.doesNotThrow(() => requireCaptureMutationReconciliation(h.report));
  assert.equal(h.state.checkpoints.includes('correction-review-open'), true);
  assert.equal(h.state.checkpoints.includes('correction-review-resolved'), true);
  assert.deepEqual(Object.values(h.report.behaviorAssertions), [true, true, true, true]);
});

test('D07 runs fresh pre-issuance denial/recovery and retired-ingest operation without inheriting D08', async () => {
  const h = harness({ scenario: 'canvas-learning-achievement' }); await h.run();
  assert.deepEqual(h.state.mutations, [40, 95]);
  assert.equal(h.report.correctionReview, undefined);
  assert.equal(h.report.behaviorAssertions.invalid_evidence_provenance_denied, true);
});

test('recovery requires a new permitting job after transient course recalculation', async () => {
  const h = harness({ scenario: 'canvas-learning-achievement', fail: 'recovery-transient-course' });
  await h.run();
  assert.equal(h.report.recoveryRetries.length, 1);
  assert.equal(h.report.recoveryRetries[0].policyAllowed, false);
  assert.equal(h.report.preIssuanceCorrection.recovered.policyAllowed, true);
  assert.equal(h.report.preIssuanceCorrection.recovered.jobId, 'job-4');
});

test('rejected wallet presentation cannot qualify verification', async () => {
  const h = harness({ scenario: 'canvas-learning-achievement', fail: 'wallet-presentation-rejected' });
  await assert.rejects(h.run(), /completed wallet presentation/);
  assert.equal(h.report.verificationAttempt.walletStatus, 400);
  assert.equal(h.report.verification, undefined);
  assert.deepEqual(h.report.behaviorAssertions, {});
});

for (const fail of ['foreign-claim-application', 'foreign-claim-organization', 'foreign-claim-transaction', 'claim-http-failed']) {
  test(`${fail} cannot deliver a foreign or failed offer to the wallet`, async () => {
    const h = harness({ fail });
    await assert.rejects(h.run(), /Claim.*application|Claim.*organization|Claim.*transaction|Canvas claim HTTP 404/);
    assert.equal(h.state.walletReceipts, 0);
    assert.equal(h.state.issued, false);
    assert.deepEqual(h.report.behaviorAssertions, {});
    assert.equal(h.report.pendingOperations.includes('wallet-claim'), true);
  });
}

for (const fail of ['denied-transaction-reserved', 'denied-credential-issued', 'denied-claimable']) {
  test(`${fail} cannot qualify the denied evidence path`, async () => {
    const h = harness({ fail }); await assert.rejects(h.run());
    assert.equal(h.state.grade, 95);
    assert.deepEqual(h.report.behaviorAssertions, {});
  });
}

test('retired-ingest side effect cannot qualify and leaves mutation ownership uncertain', async () => {
  const h = harness({ fail: 'ingest-side-effect' }); await assert.rejects(h.run());
  assert.equal(h.state.grade, 95);
  assert.deepEqual(h.report.behaviorAssertions, {});
  assert.throws(() => requireCaptureMutationReconciliation(h.report), /uncertain/);
  assert.equal(h.report.pendingOperations.includes('legacy-evidence-ingest'), true);
  assert.equal(h.report.untrustedIngest.authoritativeStateUnchanged, false);
});

for (const fail of ['post-denial-stale-evidence', 'post-recovery-stale-evidence']) {
  test(`${fail} cannot turn a fresh job or review into fresh authoritative evidence`, async () => {
    const h = harness({ fail }); await assert.rejects(h.run(), /reused.*evidence/);
    assert.equal(h.state.grade, 95);
    assert.deepEqual(h.report.behaviorAssertions, {});
  });
}

for (const fail of ['foreign-bootstrap', 'denial-sync', 'stale-job', 'foreign-approval', 'verification-denied',
  'verification-pending', 'verification-missing-status', 'verification-missing-evaluation']) {
  test(`${fail} leaves assertions incomplete and restores the exact synthetic grade`, async () => {
    const h = harness({ fail }); await assert.rejects(h.run());
    assert.equal(h.state.grade, 95);
    assert.deepEqual(h.report.behaviorAssertions, {});
    if (!fail.startsWith('verification-')) assert.equal(h.state.issued, false);
  });
}

test('stock assignment launch retains the real popup and binds only its own continue/bootstrap response', async () => {
  const calls = [];
  const origin = 'https://beta.elevenidllc.com';
  const response = host => ({ url: () => `${host}/v1/integrations/canvas/lti/experience-sessions/current/bootstrap`,
    request: () => ({ method: () => 'POST' }), status: () => 200, json: async () => ({ application_id: APP }) });
  const popup = {
    url: () => origin+'/lti', waitForURL: async predicate => assert.equal(predicate(new URL(origin+'/lti')), true),
    waitForLoadState: async () => {},
    waitForResponse: async predicate => {
      calls.push('observe-bootstrap');
      assert.equal(predicate(response('https://foreign.test')), false);
      assert.equal(predicate(response(origin)), true);
      return response(origin);
    },
    getByTestId: id => ({ waitFor: async () => calls.push(id), click: async () => calls.push(id),
      getByText: () => ({ isVisible: async () => { calls.push('verified-resource-ui'); return true; } }),
      getByRole: () => ({ first: () => ({ isVisible: async () => false }) }) }),
  };
  const locator = { first() { return this; }, or() { return this; },
    isVisible: async () => true,
    waitFor: async () => {}, click: async () => calls.push('assignment-or-launch-click') };
  const canvas = { goto: async url => calls.push(url), getByRole: () => locator,
    on: (event, listener) => { assert.equal(event, 'response'); assert.equal(typeof listener, 'function'); calls.push('observe-documents'); },
    off: (event, listener) => { assert.equal(event, 'response'); assert.equal(typeof listener, 'function'); calls.push('release-documents'); },
    frames: () => [], mainFrame: () => null,
    waitForURL: async predicate => assert.equal(predicate(new URL('https://canvas-test.elevenidllc.com/courses/1/assignments/2')), true),
    context: () => ({ waitForEvent: async event => { assert.equal(event, 'page'); calls.push('observe-popup'); return popup; } }) };
  const result = await stock.launchLearnerResource(canvas, { origin: 'https://canvas-test.elevenidllc.com' },
    { course: { id: 1 } }, { id: 2, name: 'Run-owned assignment' }, origin);
  assert.equal(result.page, popup);
  assert.equal(result.bootstrap.application_id, APP);
  assert.ok(calls.indexOf('observe-bootstrap') < calls.indexOf('canvas-lti-continue'));
  assert.equal(calls[0], 'observe-documents');
  assert.equal(calls[1], 'https://canvas-test.elevenidllc.com/courses/1/assignments');
  assert.equal(calls.includes('verified-resource-ui'), true);
  assert.equal(calls.includes('release-documents'), true);
  assert.equal(calls.includes('canvas-evidence-sync-panel'), true);
});

test('stock evidence sync observes its exact enqueue response before clicking and follows that job', async () => {
  const calls = [];
  const origin = 'https://beta.elevenidllc.com';
  const response = host => ({ url: () => `${host}/v1/integrations/canvas/lti/experience-sessions/current/evidence-sync`,
    request: () => ({ method: () => 'POST' }), status: () => 202, json: async () => ({ sync: { job_id: 'current-job' } }) });
  const page = { url: () => origin+'/console/applicant/apply/template',
    waitForResponse: async predicate => { calls.push('observe-enqueue');
      assert.equal(predicate(response('https://foreign.test')), false);
      assert.equal(predicate(response(origin)), true); return response(origin); },
    getByTestId: id => ({ click: async () => calls.push(id) }), waitForTimeout: async () => {} };
  const result = await stock.triggerLearnerSync(page, { get: async url => {
    assert.equal(url, '/v1/integrations/canvas/canvas-sync-jobs/current-job');
    return { id: 'current-job', status: 'succeeded' };
  } });
  assert.equal(result.job.id, 'current-job');
  assert.deepEqual(calls, ['observe-enqueue', 'canvas-evidence-sync-action']);
});
