'use strict';

const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const test = require('node:test');
const {observeCredentialLoginBrowser} = require('./credential-login-browser-observation');

const origin = 'https://beta.example.test';
const nonce = 'fresh_-nonce';

class Page extends EventEmitter {
  waitForResponse(predicate, {timeout}) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {this.off('response', accept); reject(Error('TIMED_OUT'));}, timeout);
      const accept = async response => {
        if (!await predicate(response)) return;
        clearTimeout(timer); this.off('response', accept); resolve(response);
      };
      this.on('response', accept);
    });
  }
  send(url, body, {status = 200, headers = {}} = {}) {
    const request = {method: () => 'GET', url: () => url};
    let reads = 0;
    const response = {url: () => url, request: () => request, status: () => status,
      allHeaders: async () => headers,
      json: async () => {reads++; if (reads > 1) throw Error('BODY_GONE_AFTER_NAVIGATION'); return body;}};
    this.emit('request', request); this.emit('response', response);
    return {reads: () => reads};
  }
}

test('one parsed terminal snapshot and exact browser finalize survive navigation body loss', async () => {
  const page = new Page();
  const observed = observeCredentialLoginBrowser(page, origin, nonce, 200);
  const status = page.send(`${origin}/v1/auth/credential-login/status?nonce=${nonce}`, {status: 'completed'});
  await new Promise(resolve => setImmediate(resolve));
  page.send(`${origin}/v1/auth/credential-login/finalize?nonce=${nonce}`, null, {status: 302,
    headers: {location: `${origin}/console/applicant/catalog?auth_method=credential`,
      'set-cookie': 'sessionId=fresh; Path=/; HttpOnly; Secure'}});
  const result = await observed.completion();
  assert.equal(status.reads(), 1, 'The response body must be read before navigation exactly once');
  assert.equal(result.nonceEvidence.status, 'completed');
  assert.equal(result.browserFinalize.verified, true);
  assert.equal(result.statusObservation.requestCount, 1);
  assert.equal(result.statusObservation.responseCount, 1);
  assert.equal(page.listenerCount('request'), 0);
});

test('first terminal denial remains failed without browser finalize proof', async () => {
  const page = new Page();
  const observed = observeCredentialLoginBrowser(page, origin, nonce, 20);
  page.send(`${origin}/v1/auth/credential-login/status?nonce=${nonce}`,
    {status: 'failed', reason_code: 'issuer_not_trusted'});
  const result = await observed.completion();
  assert.equal(result.nonceEvidence.status, 'failed');
  assert.equal(result.nonceEvidence.reasonCode, 'issuer_not_trusted');
  assert.equal(result.browserFinalize, null);
  assert.equal(page.listenerCount('request'), 0);
});

test('verified browser finalize remains complete when a later consumed-nonce status expires', async () => {
  const page = new Page();
  const observed = observeCredentialLoginBrowser(page, origin, nonce, 200);
  page.send(`${origin}/v1/auth/credential-login/finalize?nonce=${nonce}`, null, {status: 302,
    headers: {location: `${origin}/console/applicant/catalog?auth_method=credential`,
      'set-cookie': 'sessionId=fresh; Path=/; HttpOnly; Secure'}});
  await new Promise(resolve => setImmediate(resolve));
  page.send(`${origin}/v1/auth/credential-login/status?nonce=${nonce}`, {status: 'expired'});
  const result = await observed.completion();
  assert.equal(result.browserFinalize.verified, true);
  assert.equal(result.nonceEvidence.status, 'completed');
  assert.equal(result.nonceEvidence.observedNonceStatus, 'not-observed');
});
