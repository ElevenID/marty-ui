'use strict';

const { requireOwnedApplication } = require('./beta-demo-resource-helpers');

function matchesMutation(response, pageUrl, endpoint) {
  const expected = new URL(endpoint, pageUrl);
  const actual = new URL(response.url());
  return actual.origin === expected.origin && actual.pathname === expected.pathname
    && response.request().method() === 'POST';
}

function requireVerificationDecision(verification, expectedDecision) {
  const terminalDecision = expectedDecision === 'allow'
    ? verification?.result?.status === 'COMPLETED' && verification.result.evaluation === 'passed'
    : expectedDecision === 'deny' && ['FAILED', 'COMPLETED'].includes(verification?.result?.status)
      && verification.result.evaluation === 'failed';
  const rejectedPresentation = expectedDecision === 'deny'
    && verification?.wallet?.ok === false && verification.wallet.status === 400
    && verification.wallet.submission?.submitted === true
    && verification.wallet.submission.verifier_http_status === 400
    && verification.wallet.submission.verifier_error === 'invalid_presentation'
    && verification?.result?.status === 'FAILED'
    && verification.result.evaluation === 'failed';
  if (!terminalDecision || verification?.session?.ok !== true || (verification?.wallet?.ok !== true && !rejectedPresentation)
      || verification?.result?.httpStatus !== 200 || verification?.result?.decision !== expectedDecision) {
    throw new Error(`Expected a completed wallet presentation with an explicit ${expectedDecision} decision`);
  }
  return verification.result;
}

async function responseForAction(page, predicate, action, timeout = 30000) {
  // Observe both failures immediately, and let the click settle before callers
  // start cleanup. A detached response timeout can otherwise terminate Node
  // while Playwright is still explaining why the real control cannot be used.
  const [response, dispatch] = await Promise.allSettled([
    page.waitForResponse(predicate, { timeout }),
    Promise.resolve().then(action),
  ]);
  if (dispatch.status === 'rejected') throw dispatch.reason;
  if (response.status === 'rejected') throw response.reason;
  return response.value;
}

async function clickForMutation(page, recording, locator, endpoint, action) {
  const response = await responseForAction(page,
    (candidate) => matchesMutation(candidate, page.url(), endpoint),
    () => recording.click(page, locator, { action, phase: 'confirmation', durationMs: 3200 }));
  const body = await response.json().catch(() => null);
  if (!response.ok() || !body) throw new Error(`${action} did not return a successful product response (HTTP ${response.status()})`);
  recording.mark(action, 'response-received', { httpStatus: response.status() });
  return body;
}

async function approveThroughConsole(page, owned, recording, reason) {
  const endpoint = `/v1/organizations/${encodeURIComponent(owned.organizationId)}/applicants/${encodeURIComponent(owned.applicationId)}/approve`;
  await recording.explain(page, 'approve', reason, { title: 'Review and approve the application' });
  await recording.click(page, page.getByRole('button', { name: /^approve$/i }), { action: 'approve', phase: 'open' });
  const dialog = page.getByRole('dialog', { name: /^approve application$/i });
  await recording.hold(page, dialog, 1800, { action: 'approve', phase: 'dialog' });
  await dialog.getByRole('textbox', { name: /approval note/i }).fill(reason);
  await recording.hold(page, dialog, 3200, { action: 'approve', phase: 'reason' });
  const approved = requireOwnedApplication(await clickForMutation(page, recording,
    dialog.getByRole('button', { name: /^confirm approval$/i }), endpoint, 'approve'), owned);
  if (approved.status !== 'APPROVED') throw new Error('Console approval did not reach APPROVED');
  await dialog.waitFor({ state: 'hidden', timeout: 30000 });
  await recording.hold(page, page.getByText(/^approved$/i).first(), 3200, { action: 'approve', phase: 'resulting-status' });
  return approved;
}

async function issueThroughConsole(page, recording, endpoint) {
  // This stable section marker also confirms the deployed UI includes the QR
  // masking hooks; an older UI must fail before the one-time offer is created.
  await page.getByTestId('credential-issuance-section').waitFor({ state: 'visible', timeout: 30000 });
  // Install before clicking, so the first rendered QR frame is already hidden.
  // The product still generates its real offer; the recorder keeps bearer data private.
  await page.addStyleTag({ content: '[data-testid="credential-offer-qr"] { visibility: hidden !important; }' });
  await recording.explain(page, 'issue', 'The approved applicant can now receive the credential in their wallet. The one-time QR code is hidden in this recording.', {
    title: 'Create the wallet invitation',
  });
  const issued = await clickForMutation(page, recording,
    page.getByRole('button', { name: /^display OID4VCI invite$/i }), endpoint, 'issue');
  if (!issued.credential_offer_uri && !Object.values(issued.credential_offer_uris || {}).some(Boolean)) {
    throw new Error('Console issuance returned no credential offer');
  }
  await recording.hold(page, page.getByText('Scan to claim credential', { exact: true }), 3200, {
    action: 'issue', phase: 'wallet-invite-ready',
  });
  return issued;
}

module.exports = { approveThroughConsole, clickForMutation, issueThroughConsole, matchesMutation, requireVerificationDecision, responseForAction };
