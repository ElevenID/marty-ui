#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('@playwright/test');
const source = __dirname;
const { login, selectOrg } = require(path.join(source, 'audit-beta-credential-lifecycle.js'));
const { browserJson, ensureActiveResource, requestedClaim } =
  require(path.join(source, 'beta-demo-resource-helpers.js'));
const org = process.env.BETA_AUDIT_ORG_ID;
const marker = process.env.BETA_EXPECTED_RELEASE_MARKER;
const expectedComponents = JSON.parse(process.env.BETA_EXPECTED_COMPONENT_REVISIONS_JSON || 'null');
const expectedImages = JSON.parse(process.env.BETA_EXPECTED_IMAGE_DIGESTS_JSON || 'null');
const origin = 'https://beta.elevenidllc.com';
const fixturePath = process.env.BETA_VC_API_TEMPLATE_FIXTURE;
const attemptsDir = process.env.DEMO_ARTIFACT_DIR;

function fixture() {
  assert.ok(fixturePath, 'A retained fixture locator is required; current state is read back from beta.');
  const result = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  assert.equal(result.state, 'ACTIVE_DATA_INTEGRITY_TEMPLATE_READY');
  assert.equal(result.organization_id, org);
  return result;
}

function policyPayload(item) {
  return {
    organization_id: org, name: `VC API Data Integrity Policy ${item.issuer_did.split(':').at(-1)}`,
    description: 'Scoped synthetic Data Integrity credential verification policy.',
    purpose: 'VC-API Data Integrity functional qualification',
    display_metadata: { title: 'Data Integrity badge', description: 'Verify synthetic badge.',
      purpose: 'other', purpose_description: 'Verify the signed badge.',
      verifier_name: 'ElevenID LLC', verifier_logo_url: null,
      privacy_policy_url: null, terms_of_service_url: null },
    required_claims: [{ claim_name: 'subject_id', credential_type: null,
      value_constraint: null, predicate_spec: null }],
    accepted_credential_types: ['VcApiDataIntegrityBadge'],
    trust_profile_id: item.trust_profile_id, holder_binding: { required: false },
    freshness: null, issuer_constraints: null,
    credential_ranking_strategy: 'FRESHEST_FIRST', credential_ranking_weights: null,
    credential_requirements: [{ credential_template_id: item.credential_template_id,
      display_name: 'VC API Data Integrity Badge', description: 'Synthetic badge',
      required: true, credential_payload_format: 'json_ld',
      requested_claims: [requestedClaim('subject_id', { displayName: 'Subject ID',
        selectiveDisclosure: false, acceptDerived: false })],
      trust_profile_id: item.trust_profile_id, max_age_seconds: null,
      require_fresh_issuance: false }],
    alternative_requirements: [], compliance_profile_id: '10000000-0000-0000-0000-000000000001',
    prefer_predicates: false, fallback_policy: null, supported_circuits: [],
  };
}

async function main() {
  assert.match(marker || '', /^beta-v259-[a-z0-9-]+$/);
  assert.ok(expectedComponents && Object.keys(expectedComponents).length > 0);
  assert.ok(expectedImages && Object.keys(expectedImages).length > 0);
  assert.ok(attemptsDir, 'An explicit attempt artifact directory is required.');
  assert.match(org || '', /^[0-9a-f-]{36}$/i);
  assert.match(process.env.TEST_ADMIN_EMAIL || '', /@example\.test$/);
  assert.ok(process.env.TEST_ADMIN_PASSWORD);
  const item = fixture();
  const attemptId = crypto.randomUUID();
  const report = { schema: 'marty.demo-audit.direct-vc-di-functional/v1',
    scope: 'UNRECORDED_VC_API_FUNCTIONAL_PROBE_ONLY', productionDemoReady: false,
    attempt_id: attemptId, observed_at_utc: new Date().toISOString(),
    release_marker: marker, organization_id: org,
    template_id: item.credential_template_id, issuer_did: item.issuer_did,
    state: 'ATTEMPT_STARTED', stage: 'login', media_created: false,
    fixture_created_on_release: item.release_marker,
    driver_sha256: crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex') };
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ baseURL: origin });
    const page = await context.newPage();
    await login(page, process.env.TEST_ADMIN_EMAIL, process.env.TEST_ADMIN_PASSWORD);
    await selectOrg(page);
    const release = await browserJson(page, '/.well-known/marty-release');
    assert.equal(release.body?.deployment_release_marker, marker);
    assert.deepEqual(release.body?.component_revisions, expectedComponents);
    assert.deepEqual(release.body?.image_digests, expectedImages);
    report.component_revisions = release.body.component_revisions;
    report.image_digests = release.body.image_digests;
    report.stage = 'current-template-readback';
    const template = await browserJson(page, `/v1/credential-templates/${encodeURIComponent(item.credential_template_id)}?organization_id=${encodeURIComponent(org)}`);
    assert.equal(template.status, 200);
    assert.equal(template.body?.id, item.credential_template_id);
    assert.equal(template.body?.organization_id, org);
    assert.equal(template.body?.credential_payload_format, 'JSON_LD');
    assert.equal(String(template.body?.status).toUpperCase(), 'ACTIVE');
    assert.equal(template.body?.issuer_did, item.issuer_did);
    report.current_template_readback = true;
    report.stage = 'policy';
    const policy = await ensureActiveResource(page, {
      organizationId: org, collectionPath: '/v1/presentation-policies',
      name: policyPayload(item).name, payload: policyPayload(item),
      idempotencyKey: `vc-api-di-policy-${item.issuer_did.split(':').at(-1)}`,
    });
    report.policy_id = policy.id;
    report.stage = 'issue';
    const subject = `did:example:vc-api-di-${attemptId}`;
    const credentialDocument = { '@context': ['https://www.w3.org/ns/credentials/v2',
      { VcApiDataIntegrityBadge: 'https://credentials.marty.dev/types/vc-api-data-integrity-badge',
        subject_id: 'https://credentials.marty.dev/claims/subject-id' }],
      type: ['VerifiableCredential', 'VcApiDataIntegrityBadge'], issuer: item.issuer_did,
      credentialSubject: { id: subject, subject_id: attemptId } };
    const route = `/v1/vc-api/credentials/issue?organization_id=${encodeURIComponent(org)}` +
      `&credential_template_id=${encodeURIComponent(item.credential_template_id)}` +
      `&issuer_did=${encodeURIComponent(item.issuer_did)}`;
    const issued = await browserJson(page, route,
      { method: 'POST', body: JSON.stringify({ credential: credentialDocument }) });
    report.issue_status = issued.status;
    report.issue_error = issued.ok ? null : (issued.body?.error || issued.body?.detail || null);
    report.issue_error_description = issued.ok ? null : (issued.body?.error_description || null);
    if (!issued.ok || !issued.body?.verifiableCredential) throw new Error('VC-API issue did not return a credential');
    const credential = issued.body.verifiableCredential;
    report.credential_sha256 = crypto.createHash('sha256').update(JSON.stringify(credential)).digest('hex');
    report.data_integrity_proof = credential.proof?.type === 'DataIntegrityProof' &&
      credential.proof?.cryptosuite === 'eddsa-rdfc-2022';
    report.issuer_matches = credential.issuer === item.issuer_did ||
      credential.issuer?.id === item.issuer_did;
    assert.ok(report.data_integrity_proof && report.issuer_matches);
    report.stage = 'verify-valid';
    const verifyRoute = `/v1/vc-api/credentials/verify?organization_id=${encodeURIComponent(org)}` +
      `&presentation_policy_id=${encodeURIComponent(policy.id)}`;
    const valid = await browserJson(page, verifyRoute,
      { method: 'POST', body: JSON.stringify({ verifiableCredential: credential }) });
    report.valid_verify_status = valid.status;
    report.valid_error = valid.ok ? null : (valid.body?.error || valid.body?.detail || null);
    report.valid_error_description = valid.ok ? null : (valid.body?.error_description || null);
    report.valid_verified = valid.body?.verified === true;
    report.valid_decision = valid.body?.results?.decision || null;
    report.stage = 'verify-tampered';
    const tampered = structuredClone(credential);
    const proof = tampered.proof?.proofValue;
    assert.ok(typeof proof === 'string' && proof.length > 12);
    const index = Math.floor(proof.length / 2);
    tampered.proof.proofValue = proof.slice(0, index) + (proof[index] === 'A' ? 'B' : 'A') + proof.slice(index + 1);
    const invalid = await browserJson(page, verifyRoute,
      { method: 'POST', body: JSON.stringify({ verifiableCredential: tampered }) });
    report.tampered_verify_status = invalid.status;
    report.tampered_verified = invalid.body?.verified === true;
    report.state = report.valid_verify_status === 200 && report.valid_verified &&
      report.valid_decision === 'allow' && report.tampered_verify_status >= 400 &&
      !report.tampered_verified ? 'ISSUE_VERIFY_AND_TAMPER_DENIAL_PASS' : 'FUNCTIONAL_ASSERTION_FAILED';
    const after = await browserJson(page, '/.well-known/marty-release');
    assert.equal(after.body?.deployment_release_marker, marker);
    assert.deepEqual(after.body?.component_revisions, expectedComponents);
    assert.deepEqual(after.body?.image_digests, expectedImages);
    report.release_unchanged = true;
    await context.close();
  } catch (error) {
    if (report.state !== 'FUNCTIONAL_ASSERTION_FAILED') report.state = 'ATTEMPT_FAILED';
    report.error_name = error.name;
    process.stderr.write(`${error.message}\n`);
  } finally {
    await browser.close();
    fs.mkdirSync(attemptsDir, { recursive: true });
    fs.writeFileSync(path.join(attemptsDir, `attempt-${attemptId}.json`),
      JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    process.stdout.write(JSON.stringify({ state: report.state, stage: report.stage,
      issueStatus: report.issue_status || null, validStatus: report.valid_verify_status || null,
      tamperedStatus: report.tampered_verify_status || null }) + '\n');
  }
  if (report.state !== 'ISSUE_VERIFY_AND_TAMPER_DENIAL_PASS') process.exitCode = 1;
}
main().catch(error => { process.stderr.write(`${error.name}\n`); process.exitCode = 1; });
