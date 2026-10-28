'use strict';

const {
  isExactLoginNonceStatusUrl, isExactLoginNonceFinalizeUrl,
  isTerminalLoginNonceStatus, loginFinalizeRedirectEvidence,
  loginNonceCompletionEvidence, readLoginNonceStatusSnapshot,
} = require('./beta-credential-contract');

// Bind the browser's own polling and one-use finalize before wallet presentation.
// The observer never requests either endpoint or logs a nonce, URL, cookie or body.
function observeCredentialLoginBrowser(page, origin, nonce, timeoutMs = 60_000) {
  const statusObservation = { requestCount: 0, responseCount: 0,
    pendingCount: 0, parseFailureCount: 0,
    lastHttpStatus: null, lastStatus: null, lastReasonCode: null };
  const isStatus = url => isExactLoginNonceStatusUrl(url, origin, nonce);
  let active = true;
  const onRequest = request => {
    if (active && request.method() === 'GET' && isStatus(request.url())) statusObservation.requestCount += 1;
  };
  page.on('request', onRequest);
  let terminalStatusSnapshot = null;
  const terminalStatusResponse = page.waitForResponse(async response => {
    if (!active || !isStatus(response.url()) || response.request().method() !== 'GET') return false;
    statusObservation.responseCount += 1;
    statusObservation.lastHttpStatus = response.status();
    if (response.status() !== 200) return false;
    const safe = await readLoginNonceStatusSnapshot(response);
    if (safe.status === 'pending') statusObservation.pendingCount += 1;
    if (safe.status === 'invalid-response') statusObservation.parseFailureCount += 1;
    statusObservation.lastStatus = safe.status;
    statusObservation.lastReasonCode = safe.reasonCode || null;
    if (isTerminalLoginNonceStatus(safe) && !terminalStatusSnapshot) terminalStatusSnapshot = safe;
    return isTerminalLoginNonceStatus(safe);
  }, {timeout: timeoutMs}).then(() => terminalStatusSnapshot).catch(() => null);
  const browserFinalizeResponse = page.waitForResponse(response =>
    active && response.request().method() === 'GET'
      && isExactLoginNonceFinalizeUrl(response.url(), origin, nonce),
  {timeout: timeoutMs}).then(async response => loginFinalizeRedirectEvidence({
    url: response.url(), status: response.status(), headers: await response.allHeaders(),
  }, origin, nonce)).catch(() => null);

  return {async completion() {
    const first = await Promise.race([
      terminalStatusResponse.then(snapshot => ({kind: 'status', snapshot})),
      browserFinalizeResponse.then(evidence => ({kind: 'finalize', evidence})),
    ]);
    let terminal = first.kind === 'status' ? first.snapshot : null;
    const browserFinalize = first.kind === 'finalize' ? first.evidence
      : terminal?.status === 'failed' || terminal?.status === 'expired'
        ? null : await browserFinalizeResponse;
    if (!terminal && !browserFinalize) terminal = await terminalStatusResponse;
    active = false;
    page.off('request', onRequest);
    const nonceEvidence = terminal?.status === 'failed' || terminal?.status === 'expired'
      ? terminal : browserFinalize?.verified
      ? {status: 'completed', observedNonceStatus: statusObservation.lastStatus === 'completed'
        ? 'completed' : 'not-observed'}
      : terminal || loginNonceCompletionEvidence({status: 'pending-timeout'});
    return {nonceEvidence, statusObservation: {...statusObservation},
      browserFinalize: browserFinalize || null, terminalObserved: terminal !== null};
  }};
}

module.exports = {observeCredentialLoginBrowser};
