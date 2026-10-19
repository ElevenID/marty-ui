'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  providerSwitchBehaviorAssertions,
} = require('./beta-issuer-provider-switch-contract');

function passingReport() {
  const issuerDid = 'did:web:beta.example:orgs:d02';
  return {
    identityCreation: { ok: true, identity: { issuer_did: issuerDid, status: 'active' } },
    providerA: {
      issuance: { ok: true },
      credential: { verified: true, issuerDid, kid: `${issuerDid}#provider-a` },
      reverifiedAfterSwitch: true,
    },
    providerBConfig: { defaultServiceId: 'provider-b', serviceId: 'provider-b' },
    rebind: { ok: true, changed: true },
    providerB: {
      issuance: { ok: true },
      credential: { verified: true, issuerDid, kid: `${issuerDid}#provider-b` },
    },
    didAfterSwitch: {
      assertionMethodIds: [`${issuerDid}#provider-a`, `${issuerDid}#provider-b`],
    },
    unpublishedReplacement: {
      rebindStatus: 503,
      rebindOk: false,
      issueAfterDenial: { ok: true },
      credentialAfterDenial: { verified: true, issuerDid, kid: `${issuerDid}#provider-b` },
    },
  };
}

test('requires every D-02 happy and failure behavior from observable evidence', () => {
  assert.deepEqual(providerSwitchBehaviorAssertions(passingReport()), {
    create_issuer_profile: true,
    issue_with_provider_a: true,
    switch_signing_provider: true,
    verify_same_did_identity: true,
    unpublished_signing_key_denied: true,
  });
});

test('does not accept a metadata-only switch or a failed-cutover key change', () => {
  const sameKey = passingReport();
  sameKey.providerB.credential.kid = sameKey.providerA.credential.kid;
  assert.equal(providerSwitchBehaviorAssertions(sameKey).switch_signing_provider, false);

  const failOpen = passingReport();
  failOpen.unpublishedReplacement.credentialAfterDenial.kid = 'did:web:beta.example:orgs:d02#missing';
  assert.equal(providerSwitchBehaviorAssertions(failOpen).unpublished_signing_key_denied, false);
});

test('visible verification evidence binds real credential keys, revalidation and denial response', () => {
  const {providerVerificationDisplay}=require('./audit-beta-issuer-provider-switch');
  const report=passingReport();
  const shown=providerVerificationDisplay(report,'denied-switch');
  assert(shown.rows.some(([,value])=>value===report.providerA.credential.kid));
  assert(shown.rows.some(([,value])=>value===report.providerB.credential.kid));
  assert(shown.rows.some(([,value])=>value==='HTTP 503; cutover accepted: false'));
  assert.match(shown.boundary,/not an admin portal screen/);
  assert.match(shown.custodyScope,/one beta OpenBao backend/);
  const invalid=passingReport();invalid.providerA.reverifiedAfterSwitch=false;
  assert.throws(()=>providerVerificationDisplay(invalid,'after-switch'),/actual passing verification/);
  const failOpen=passingReport();failOpen.unpublishedReplacement.rebindStatus=200;
  assert.throws(()=>providerVerificationDisplay(failOpen,'denied-switch'),/actual passing verification/);
});

test('actual provider panel wraps full issuer and key values inside the capture viewport', async () => {
  const {chromium} = require('@playwright/test');
  const {providerVerificationDisplay, renderProviderEvidence} = require('./audit-beta-issuer-provider-switch');
  const original = passingReport();
  const issuerDid = 'did:web:beta.elevenidllc.com:orgs:d02-provider-switch-20261018t232318';
  const report = JSON.parse(JSON.stringify(original).replaceAll('did:web:beta.example:orgs:d02', issuerDid)
    .replaceAll('#provider-a', '#managed-d4fc1acc38045cc1bc56').replaceAll('#provider-b', '#d02-external-20261018t232318'));
  const browser = await chromium.launch({headless: true});
  try {
    const page = await browser.newPage({viewport: {width: 1920, height: 1080}});
    for (const phase of ['after-switch', 'denied-switch']) {
      const payload = providerVerificationDisplay(report, phase);
      await page.evaluate(renderProviderEvidence, payload);
      const geometry = await page.locator('#d02-verification-evidence').evaluate(panel => ({
        bottom: panel.getBoundingClientRect().bottom,
        rows: [...panel.querySelectorAll('[data-evidence-value]')].map(node => ({
          text: node.textContent, width: node.clientWidth, height: node.clientHeight,
          overflow: node.scrollWidth > node.clientWidth,
          fontSize: Number.parseFloat(getComputedStyle(node).fontSize),
        })),
      }));
      assert(geometry.bottom <= 1068);
      assert.deepEqual(geometry.rows.map(row => row.text), payload.rows.map(([, value]) => value));
      assert(geometry.rows.every(row => !row.overflow && row.fontSize >= 30));
      assert(geometry.rows[0].height > 35, 'Full DID must wrap instead of clipping or shrinking');
    }
    await page.setViewportSize({width: 700, height: 400});
    await assert.rejects(page.evaluate(renderProviderEvidence, providerVerificationDisplay(report, 'denied-switch')), /without clipping/);
  } finally {
    await browser.close();
  }
});
