'use strict';

// Browser/API transport and correlation only. Rust owns policy, authorization,
// approval, signing, status and review resolution. No imported case is an outcome.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const stock = require('./run-canvas-oss-standard-contract');
const { receiveCredential, verify } = require('./audit-beta-credential-lifecycle');
const { requireVerificationDecision } = require('./beta-demo-review-ui');
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const headFingerprint = event => hash(event.headRevisions.map(({ requirementId, sourceRevision, payloadHash }) =>
  ({ requirementId, sourceRevision, payloadHash })).sort((a, b) => a.requirementId.localeCompare(b.requirementId)));
const same = (actual, expected, label) => assert.equal(String(actual || ''), String(expected), label);
const enc = encodeURIComponent;

function requireJobBinding(sync, scope, seen, after) {
  const job = sync?.job;
  same(job?.id, sync?.body?.sync?.job_id, 'Enqueued and completed jobs must match');
  for (const field of ['application_id', 'organization_id', 'binding_id', 'platform_id']) {
    same(job?.[field], scope[field], `Foreign Canvas job ${field}`);
  }
  assert.equal(job.status, 'succeeded');
  assert.ok(!seen.has(job.id), 'A prior sync job cannot prove a fresh correction');
  assert.ok(Date.parse(job.created_at) >= after - 1000, 'Sync job predates this operation');
  seen.add(job.id);
  return job;
}

function requireIssuedBinding(records, scope, transactionId) {
  assert.ok(Array.isArray(records));
  const matches = records.filter(record => String(record.application_id) === scope.application_id);
  assert.ok(matches.length <= 1, 'Application has duplicate issued credentials');
  if (!matches.length) return null;
  const record = matches[0];
  same(record.organization_id, scope.organization_id, 'Credential organization');
  same(record.credential_template_id, scope.credential_template_id, 'Credential template');
  same(record.flow_execution_id, transactionId, 'Credential transaction');
  assert.equal(String(record.status).toUpperCase(), 'ACTIVE');
  assert.ok(record.credential_id || record.id, 'Credential ID missing');
  return record;
}

function requireCaptureMutationReconciliation(report) {
  const pending = report.pendingOperations || [];
  assert.ok(report.transactionId || !pending.includes('scoped-approval'),
    'Approval outcome is uncertain; preserve the platform and exact application for reconciliation');
  assert.ok(!pending.includes('legacy-evidence-ingest'),
    'Rejected-ingest outcome is uncertain; preserve the platform and exact application for reconciliation');
}

async function readLearnerStatus(page) {
  return page.evaluate(async () => {
    const session = JSON.parse(sessionStorage.getItem('elevenid.canvas-lti.session.v1') || 'null');
    const response = await fetch('/v1/integrations/canvas/lti/experience-sessions/current/evidence-status', {
      headers: { Authorization: `Bearer ${session?.token || ''}` }, cache: 'no-store',
    });
    if (!response.ok) throw Error('Canvas evidence read failed');
    return response.json();
  });
}

async function runCanvasCapture({ setup, page, adminPage, walletPage, scenario,
  checkpoint = async () => {}, operations = stock, wallet = { receiveCredential, verify },
  now = Date.now, onApplication = () => {}, report }) {
  assert.ok(['canvas-learning-achievement', 'external-evidence-to-credential'].includes(scenario));
  const { marty, adminCanvas, learnerCanvas, fixtures, externalAssignment,
    organizationId, binding, platformId, pinnedBinding, templates, martyOrigin } = setup;
  report.currentOperation = 'learner-resource-launch';
  const launch = await operations.launchLearnerResource(page, learnerCanvas, fixtures, externalAssignment, martyOrigin);
  page = launch.page;
  const applicationId = String(launch.bootstrap?.application_id || '');
  assert.match(applicationId, /^[a-f0-9-]{36}$/i);
  for (const [field, expected] of Object.entries({ organization_id: organizationId,
    application_template_id: templates.application.id, credential_template_id: templates.credential.id,
    canvas_platform_id: platformId, canvas_program_binding_id: binding.id })) {
    same(launch.bootstrap[field], expected, `Foreign bootstrap ${field}`);
  }
  onApplication(applicationId);
  report.currentOperation = 'background-roster-activation';
  const activationAt = new Date().toISOString();
  await operations.validateAndActivateBinding(marty, binding.id);
  report.currentOperation = 'background-roster-job';
  const rosterJob = await operations.waitForLatestRosterJob(marty, organizationId, binding.id, activationAt);
  report.currentOperation = 'unsigned-pending-candidate';
  const candidate = await operations.waitForCandidate(marty, organizationId, binding.id, 'pending_claim');
  assert.ok(Number(rosterJob?.result?.pending_claim || 0) >= 1 || candidate,
    'Background roster did not produce an unsigned pending claim');
  report.currentOperation = 'learner-repeat-launch';
  const repeat = await operations.launchLearnerResource(page, learnerCanvas, fixtures, externalAssignment, martyOrigin);
  assert.equal(String(repeat.bootstrap?.application_id), applicationId,
    'Repeat learner launch created a different application');
  page = repeat.page;
  const scope = { application_id: applicationId, organization_id: organizationId,
    binding_id: binding.id, platform_id: platformId, credential_template_id: templates.credential.id };
  report.scope = scope;
  report.operations = [];
  report.pendingOperations = [];
  const seen = new Set();
  const inventory = () => marty.get(`/v1/issued-credentials?organization_id=${enc(organizationId)}`);
  const transactions = async () => {
    const records = await marty.get(`/v1/issuance?organization_id=${enc(organizationId)}`);
    assert.ok(Array.isArray(records), 'Issuance inventory is not a collection');
    return records.filter(record => String(record.application_id) === applicationId);
  };
  const approvalPath = `/v1/integrations/canvas/applications/${enc(applicationId)}/approve`;
  const unsigned = async () => {
    const state = await readLearnerStatus(page);
    assert.equal(state.claim?.unsigned, true);
    assert.equal((await inventory()).filter(r => String(r.application_id) === applicationId).length, 0,
      'Credential signed before wallet claim');
    return state;
  };
  report.currentOperation = 'pending-claim-ui';
  await page.getByTestId('canvas-pending-claim').waitFor({ state: 'visible' });
  report.currentOperation = 'pending-claim-unsigned';
  const pending = await unsigned();
  assert.equal(pending.claim.status, 'pending_claim');
  assert.equal(pending.claim.available, false);
  report.unsignedPendingObserved = true;

  async function sync(phase, permitted) {
    const started = now();
    report.currentOperation = `${phase}-sync-request`;
    const observed = await operations.triggerLearnerSync(page, marty);
    report.currentOperation = `${phase}-job-binding`;
    const job = requireJobBinding(observed, scope, seen, started);
    assert.equal(job.result?.policy_allowed, permitted);
    assert.equal(Number(job.result?.requirements_checked), pinnedBinding.evidence_requirements.length);
    const facts = await marty.get(`/v1/organizations/${enc(organizationId)}/applicants/${enc(applicationId)}/evidence-facts?current_only=true`);
    const heads = operations.validateAuthoritativeEvidenceHeads(facts, pinnedBinding.evidence_requirements);
    report.currentOperation = `${phase}-policy-ui`;
    await page.getByTestId(permitted ? 'canvas-evidence-policy-permitted' : 'canvas-evidence-policy-not-permitted')
      .waitFor({ state: 'visible' });
    const event = { phase, applicationId, jobId: job.id, policyAllowed: permitted,
      headRevisions: heads.map(f => ({ id: f.id, requirementId: f.requirement_id,
        sourceRevision: f.source_revision, payloadHash: f.payload_hash })) };
    report.operations.push(event);
    await checkpoint(page, phase, event);
    return event;
  }
  const initial = await sync('authoritative-evidence', true);
  await page.getByTestId('canvas-authoritative-evidence-verified').waitFor({ state: 'visible' });

  const gradePath = `/api/v1/courses/${fixtures.course.id}/assignments/${fixtures.assignment.id}/submissions/${fixtures.learner.id}`;
  async function grade(value) {
    const changed = await adminCanvas.putForm(gradePath, { 'submission[posted_grade]': value }, [200]);
    same(changed.user_id, fixtures.learner.id, 'Grade changed a different learner');
    same(changed.assignment_id, fixtures.assignment.id, 'Grade changed a different assignment');
    assert.equal(Number(changed.score), value);
  }
  async function correction(prefix) {
    let denied;
    try {
      await grade(40);
      denied = await sync(`${prefix}-deny`, false);
      assert.notEqual(headFingerprint(denied), headFingerprint(initial), 'Correction reused initial evidence');
      // A displayed deny is insufficient: exercise the real management boundary
      // while denied, then prove it neither reserved an offer nor signed a credential.
      report.pendingOperations.push('scoped-approval');
      assert.equal((await transactions()).length, 0, 'Unexpected issuance reservation before denied approval');
      const rejection = await marty.post(approvalPath, { review_notes: `Denied Canvas capture ${scenario}` }, [409]);
      assert.equal(rejection?.detail, 'Canvas application is not ready for approval');
      assert.equal((await transactions()).length, 0, 'Denied approval reserved an issuance transaction');
      const state = await unsigned();
      assert.equal(state.claim.available, false, 'Denied approval enabled the wallet claim');
      report.deniedApproval = { applicationId, jobId: denied.jobId, httpStatus: 409,
        transactionCount: 0, credentialCount: 0, claimAvailable: false };
      report.pendingOperations = report.pendingOperations.filter(operation => operation !== 'scoped-approval');
      await checkpoint(page, 'approval-denied-on-current-evidence', report.deniedApproval);
    } finally {
      // Always restore the exact synthetic grade, including when denial/readback fails.
      await grade(95);
    }
    const recovered = await sync(`${prefix}-recovery`, true);
    assert.notEqual(headFingerprint(recovered), headFingerprint(denied), 'Recovery reused denied evidence');
    return { denied, recovered };
  }
  report.preIssuanceCorrection = await correction('pre-issuance');
  await unsigned();
  report.pendingOperations.push('scoped-approval');
  const approval = await marty.post(approvalPath,
    { review_notes: `Canvas capture approval ${scenario}` }, [200]);
  same(approval?.application_id, applicationId, 'Approval returned another application');
  const transactionId = approval?.issuance_transaction_id;
  assert.ok(transactionId, 'Scoped approval did not reserve a transaction');
  report.transactionId = transactionId;
  report.approval = { applicationId, transactionId, transport: 'SCOPED_CANVAS_MANAGEMENT_API', signed: false };
  const reservation = await marty.get(`/v1/issuance/${enc(transactionId)}?organization_id=${enc(organizationId)}`);
  same(reservation.id, transactionId, 'Approval transaction');
  same(reservation.application_id, applicationId, 'Approval transaction application');
  same(reservation.organization_id, organizationId, 'Approval transaction organization');
  same(reservation.credential_template_id, templates.credential.id, 'Approval transaction template');
  assert.ok(!reservation.issued_at, 'Approval signed before the wallet claim');
  report.pendingOperations = report.pendingOperations.filter(operation => operation !== 'scoped-approval');
  await operations.reloadLearnerExperience(page);
  await page.getByTestId('canvas-ready-to-claim').waitFor({ state: 'visible' });
  await unsigned();
  await checkpoint(page, 'approved-still-unsigned', { applicationId, transactionId });

  // Hide bearer QR pixels before the dialog exists; real product controls still run.
  await page.addStyleTag({ content: '[data-testid="credential-offer-qr"] { visibility:hidden !important }' });
  const responsePromise = page.waitForResponse(response => new URL(response.url()).origin === martyOrigin
    && new URL(response.url()).pathname === '/v1/integrations/canvas/lti/experience-sessions/current/claim'
    && response.request().method() === 'POST');
  report.pendingOperations.push('wallet-claim');
  await page.getByTestId('canvas-claim-action').click();
  const response = await responsePromise;
  const claim = await operations.responseJson(response, 'canvas_claim_failed', 'Canvas claim', [200]);
  same(claim.id, applicationId, 'Claim application');
  same(claim.organization_id, organizationId, 'Claim organization');
  same(claim.transaction_id, transactionId, 'Claim approval transaction');
  await page.getByTestId('credential-claim-dialog').waitFor({ state: 'visible' });
  const receipt = await wallet.receiveCredential(walletPage,
    claim.credential_offer_uri || claim.offer_url, templates.credential.vct);
  assert.equal(receipt.ok, true, 'Rust wallet receipt failed');
  assert.ok(receipt.receipt?.id, 'Wallet omitted the stored receipt ID');
  same(receipt.receipt.vct, templates.credential.vct, 'Wallet stored the wrong credential type');
  report.walletReceipt = receipt;
  const issued = await operations.waitFor(async () => requireIssuedBinding(await inventory(), scope, transactionId));
  const credentialId = issued.credential_id || issued.id;
  report.credentialId = credentialId;
  report.issuerDid = issued.issuer_did;
  report.pendingOperations = report.pendingOperations.filter(operation => operation !== 'wallet-claim');
  await page.getByTestId('credential-claim-dialog').getByRole('button', { name: /close|done/i }).first().click();
  await operations.reloadLearnerExperience(page);
  await page.getByTestId('canvas-claim-complete').waitFor({ state: 'visible' });
  const verification = await wallet.verify(adminPage, walletPage, `Canvas ${applicationId}`, {
    organizationId, presentationPolicyId: templates.policy.id, issuerDid: issued.issuer_did,
  });
  requireVerificationDecision(verification, 'allow');
  report.verification = verification;
  await checkpoint(walletPage, 'wallet-receipt-and-verification', { applicationId, credentialId, transactionId });

  if (scenario === 'external-evidence-to-credential') {
    const reviewsPath = `/v1/integrations/canvas/evidence-policy-reviews?organization_id=${enc(organizationId)}&binding_id=${enc(binding.id)}&limit=100`;
    assert.equal((await marty.get(reviewsPath)).filter(r => r.application_id === applicationId && r.status === 'open').length, 0);
    let review, postDenied;
    try {
      await grade(40);
      postDenied = await sync('post-issuance-deny', false);
      assert.notEqual(headFingerprint(postDenied), headFingerprint(report.preIssuanceCorrection.recovered),
        'Post-issuance denial reused recovered evidence');
      review = await operations.waitFor(async () => {
        const matches = (await marty.get(reviewsPath)).filter(r => r.application_id === applicationId
          && r.credential_id === credentialId && r.status === 'open');
        assert.ok(matches.length <= 1, 'Duplicate correction reviews');
        return matches[0] || null;
      });
      const current = await marty.get(`/v1/issued-credentials/${enc(credentialId)}`);
      same(current.credential_id || current.id, credentialId, 'Wrong credential readback');
      assert.equal(String(current.status).toUpperCase(), 'ACTIVE');
      report.correctionReview = { id: review.id, applicationId, credentialId, status: 'open', credentialStatus: 'ACTIVE' };
      await checkpoint(page, 'correction-review-open', report.correctionReview);
    } finally { await grade(95); }
    const postRecovered = await sync('post-issuance-recovery', true);
    assert.notEqual(headFingerprint(postRecovered), headFingerprint(postDenied),
      'Post-issuance recovery reused denied evidence');
    report.postIssuanceCorrection = { denied: postDenied, recovered: postRecovered };
    const resolved = await operations.waitFor(async () => {
      const records = await marty.get(reviewsPath);
      const exact = records.find(r => r.id === review.id && r.application_id === applicationId && r.credential_id === credentialId);
      return exact?.status === 'resolved' ? exact : null;
    });
    report.correctionReview.resolved = resolved.status === 'resolved';
    assert.equal(resolved.resolution_action, 'evidence_recovered', 'Review resolved through another operation');
    const current = await marty.get(`/v1/issued-credentials/${enc(credentialId)}`);
    assert.equal(String(current.status).toUpperCase(), 'ACTIVE');
    await checkpoint(page, 'correction-review-resolved', report.correctionReview);
  }
  const authoritativeSnapshot = async () => ({
    evidence: headFingerprint({ headRevisions: operations.validateAuthoritativeEvidenceHeads(
      await marty.get(`/v1/organizations/${enc(organizationId)}/applicants/${enc(applicationId)}/evidence-facts`),
      pinnedBinding.evidence_requirements).map(f => ({ requirementId: f.requirement_id,
      sourceRevision: f.source_revision, payloadHash: f.payload_hash })) }),
    transactions: hash(await transactions()),
    credentials: hash((await inventory()).filter(record => String(record.application_id) === applicationId)),
  });
  const beforeLegacy = await authoritativeSnapshot();
  report.untrustedIngest = { applicationId, httpStatus: null, before: beforeLegacy,
    after: null, authoritativeStateUnchanged: false };
  report.pendingOperations.push('legacy-evidence-ingest');
  const legacy = await marty.post('/v1/integrations/canvas/evidence-events', {
    canvas_event_id: `untrusted-capture-${applicationId}`, organization_id: organizationId,
    credential_template_id: templates.credential.id, application_id: applicationId,
    canvas_account_id: 'untrusted-capture-account', canvas_course_id: String(fixtures.course.id),
    canvas_course_name: 'Untrusted capture claim', canvas_enrollment_id: 'untrusted-capture-enrollment',
    canvas_user_id: String(fixtures.learner.id), learner_email: 'untrusted-provenance@marty.demo',
    achievement_name: 'Untrusted capture claim', completion_at: new Date(now()).toISOString(),
    evidence_type: 'assignment', canvas_assignment_id: String(fixtures.assignment.id),
    completed: true, passed: true, score_percent: 100, eligible: true,
  }, [410]);
  report.untrustedIngest.httpStatus = 410;
  report.untrustedIngest.after = await authoritativeSnapshot();
  assert.deepEqual(report.untrustedIngest.after, beforeLegacy,
    'Rejected untrusted ingestion changed evidence, reservations or issued credentials');
  report.pendingOperations = report.pendingOperations.filter(operation => operation !== 'legacy-evidence-ingest');
  // The client accepts only the observed HTTP 410, never a report-shaped result.
  report.legacyIngestUnavailable = true;
  report.untrustedIngest.authoritativeStateUnchanged = true;
  void legacy;
  report.behaviorAssertions = scenario === 'canvas-learning-achievement'
    ? { capture_canvas_evidence: true, governed_review: true, issue_open_badge: true, invalid_evidence_provenance_denied: true }
    : { normalize_external_evidence: true, evaluate_policy: true, review_and_issue: true, insufficient_or_conflicting_evidence_review: true };
  return { page, applicationId, transactionId, credentialId };
}

module.exports = { requireJobBinding, requireIssuedBinding, requireCaptureMutationReconciliation, runCanvasCapture, readLearnerStatus };
