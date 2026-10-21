'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { approveThroughConsole, issueThroughConsole, matchesMutation, requireVerificationDecision } = require('./beta-demo-review-ui');
const { createActionRecording } = require('./demo-recording');

test('UI mutation evidence must match the exact origin, organization, application and method', () => {
  const endpoint = '/v1/organizations/org-1/applicants/app-1/approve';
  const response = (url, method = 'POST') => ({ url: () => url, request: () => ({ method: () => method }) });
  assert.equal(matchesMutation(response(`https://demo.example.test${endpoint}`), 'https://demo.example.test/console', endpoint), true);
  for (const candidate of [
    response(`https://other.example.test${endpoint}`),
    response('https://demo.example.test/v1/organizations/org-1/applicants/app-2/approve'),
    response(`https://demo.example.test${endpoint}`, 'GET'),
  ]) assert.equal(matchesMutation(candidate, 'https://demo.example.test/console', endpoint), false);
});

test('successful narration requires the wallet and completed verifier decision', () => {
  const passed = { session: { ok: true }, wallet: { ok: true }, result: {
    httpStatus: 200, decision: 'allow', status: 'COMPLETED', evaluation: 'passed',
  } };
  assert.equal(requireVerificationDecision(passed, 'allow'), passed.result);
  for (const evidence of [
    { ...passed, session: { ok: false } }, { ...passed, wallet: { ok: false } },
    { ...passed, result: { httpStatus: 202, decision: 'allow' } },
    { ...passed, result: { httpStatus: 200, decision: 'deny' } },
    { ...passed, result: { ...passed.result, status: 'PENDING' } },
    { ...passed, result: { ...passed.result, evaluation: 'failed' } },
  ]) assert.throws(() => requireVerificationDecision(evidence, 'allow'), /completed wallet presentation/);
});

test('expected denial requires typed submission rejection and corroborating terminal verifier result', () => {
  const denied = {
    session: { ok: true }, wallet: { ok: false, status: 400, submission: {
      submitted: true, verifier_http_status: 400, verifier_error: 'invalid_presentation',
    } }, result: { httpStatus: 200, status: 'FAILED', evaluation: 'failed', decision: 'deny' },
  };
  assert.equal(requireVerificationDecision(denied, 'deny'), denied.result);
  for (const evidence of [
    { ...denied, session: { ok: false } },
    { ...denied, wallet: { ...denied.wallet, submission: null } },
    { ...denied, wallet: { ...denied.wallet, submission: { ...denied.wallet.submission, verifier_http_status: 503 } } },
    { ...denied, wallet: { ...denied.wallet, submission: { ...denied.wallet.submission, verifier_error: 'invalid_request' } } },
    { ...denied, result: { ...denied.result, status: 'PENDING' } },
    { ...denied, result: { ...denied.result, decision: 'allow' } },
  ]) assert.throws(() => requireVerificationDecision(evidence, 'deny'), /completed wallet presentation/);
  assert.throws(() => requireVerificationDecision(denied, 'allow'), /completed wallet presentation/);
});

// Controlled local browser fixture: exercises recorder interaction and masking,
// not a live ElevenID service or production qualification.
test('browser recorder clicks approval and invitation, hiding the first QR frame', {
  skip: !process.env.MARTY_AUDIT_BROWSER,
}, async () => {
  const { chromium } = require('@playwright/test');
  const browser = await chromium.launch({ executablePath: process.env.MARTY_AUDIT_BROWSER, headless: true });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const owned = {
      organizationId: 'org-1', applicationId: 'app-1', applicantId: 'person-1',
      credentialTemplateId: 'template-1', applicationTemplateId: 'form-1', runId: 'run-1',
    };
    const application = {
      id: owned.applicationId, organization_id: owned.organizationId, applicant_id: owned.applicantId,
      credential_template_id: owned.credentialTemplateId, application_template_id: owned.applicationTemplateId,
      integration_context: { demo_run_id: owned.runId }, status: 'APPROVED',
    };
    const requests = [];
    await page.route('https://demo.example.test/**', async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.pathname.endsWith('/approve') || url.pathname.endsWith('/issue')) {
        requests.push({ path: url.pathname, body: request.postDataJSON() });
        await route.fulfill({ json: { ...application, credential_offer_uri: 'openid-credential-offer://fixture-only' } });
        return;
      }
      await route.fulfill({ contentType: 'text/html', body: `<!doctype html><html><body>
        <button id="approve">Approve</button><div id="status">Submitted</div><div id="dialogs"></div>
        <section data-testid="credential-issuance-section" hidden><button id="issue">Display OID4VCI Invite</button><div id="invite"></div></section>
        <script>
          document.querySelector('#approve').onclick = () => {
            document.querySelector('#dialogs').innerHTML = '<div role="dialog" aria-label="Approve Application"><label>Approval note (optional)<textarea></textarea></label><button id="confirm">Confirm Approval</button></div>';
            document.querySelector('#confirm').onclick = async () => {
              await fetch('/v1/organizations/org-1/applicants/app-1/approve', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({notes:document.querySelector('textarea').value}) });
              document.querySelector('#dialogs').innerHTML = ''; document.querySelector('#status').textContent = 'Approved';
              document.querySelector('section').hidden = false;
            };
          };
          document.querySelector('#issue').onclick = async () => {
            await fetch('/v1/organizations/org-1/applicants/app-1/issue', {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
            document.querySelector('#invite').innerHTML = '<h2>Scan to claim credential</h2><svg data-testid="credential-offer-qr" width="80" height="80"><rect width="80" height="80"/></svg>';
            window.firstQrVisibility = getComputedStyle(document.querySelector('svg')).visibility;
          };
        </script></body></html>` });
    });
    await page.goto('https://demo.example.test/console');
    const recording = createActionRecording({ enabled: false, scenario: 'fixture' });
    const approved = await approveThroughConsole(page, owned, recording, 'Synthetic employee approved.');
    assert.equal(approved.id, owned.applicationId);
    const issued = await issueThroughConsole(page, recording, '/v1/organizations/org-1/applicants/app-1/issue');
    assert.match(issued.credential_offer_uri, /^openid-credential-offer:/);
    assert.deepEqual(requests.map(({ path }) => path), [
      '/v1/organizations/org-1/applicants/app-1/approve', '/v1/organizations/org-1/applicants/app-1/issue',
    ]);
    assert.equal(requests[0].body.notes, 'Synthetic employee approved.');
    assert.equal(await page.evaluate(() => window.firstQrVisibility), 'hidden');
    assert.equal(await page.locator('svg').evaluate((qr) => getComputedStyle(qr).visibility), 'hidden');
    await context.close();
  } finally {
    await browser.close();
  }
});
