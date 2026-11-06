#!/usr/bin/env node
'use strict';

// Direct issuance and persistence acceptance for an existing installation.
// Authentication and OID4VCI verification remain owned by existing helpers.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');

const MAXIMUM_STATE_FILE_BYTES = 1024 * 1024;
const MAXIMUM_DIAGNOSTIC_BYTES = 64 * 1024;
const emit = (value) => process.stdout.write(JSON.stringify(value) + '\n');
let stage = 'arguments';
let state;
let diagnostic = 0;
const check = (condition, code) => {
  if (!condition) { const error = new Error(code); error.code = code; throw error; }
};
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const list = (value) => Array.isArray(value) ? value
  : value?.items || value?.application_templates || value?.templates || value?.credentials || [];

function options(argv) {
  const result = {
    phase: 'accept', repo: path.resolve(__dirname, '../..'),
    origin: '', 'password-file': '', 'state-dir': '', email: 'operator@localhost',
    'organization-id': '00000000-0000-0000-0000-000000000001',
    'credential-template-id': '50000000-0000-0000-0000-000000000040',
    'issuer-did': '',
  };
  for (let i = 0; i < argv.length; i += 2) {
    check(argv[i]?.startsWith('--') && Object.hasOwn(result, argv[i].slice(2))
      && typeof argv[i + 1] === 'string', 'invalid_arguments');
    result[argv[i].slice(2)] = argv[i + 1];
  }
  for (const name of ['origin', 'password-file', 'state-dir', 'issuer-did']) {
    check(result[name].trim(), 'missing_required_argument_' + name.replaceAll('-', '_'));
  }
  check(['accept', 'resume'].includes(result.phase), 'invalid_phase');
  const origin = new URL(result.origin);
  check(origin.protocol === 'https:' && origin.origin === result.origin,
    'canonical_https_origin_required');
  check(result['issuer-did'].startsWith('did:web:'), 'managed_did_web_issuer_required');
  check(process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0', 'normal_tls_validation_required');
  for (const name of ['repo', 'password-file', 'state-dir']) {
    check(path.isAbsolute(result[name]) && path.resolve(result[name]) === result[name],
      'absolute_paths_required');
  }
  return result;
}

function privateWrite(name, value) {
  const raw = typeof value === 'string' || Buffer.isBuffer(value)
    ? value : JSON.stringify(value, null, 2) + '\n';
  check(Buffer.byteLength(raw) <= MAXIMUM_STATE_FILE_BYTES, 'private_state_file_too_large');
  const fd = fs.openSync(path.join(state, name), fs.constants.O_WRONLY
    | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, raw); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function privateRead(file, maximum = 65536) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const info = fs.fstatSync(fd);
    check(info.isFile() && info.size > 0 && info.size <= maximum
      && (info.mode & 0o077) === 0, 'private_input_required');
    const raw = fs.readFileSync(fd);
    check(raw.length === info.size, 'private_input_changed');
    return raw;
  } finally { fs.closeSync(fd); }
}

async function main(argv) {
  if (argv.includes('--help')) {
    process.stdout.write('Usage: node tests/scripts/run-kubernetes-acceptance.cjs\n'
      + '  --origin HTTPS_ORIGIN --issuer-did DID_WEB\n'
      + '  --password-file ABSOLUTE_PATH --state-dir ABSOLUTE_PATH\n'
      + '  [--phase accept|resume] [--repo ABSOLUTE_CHECKOUT] [--email EMAIL]\n'
      + '  [--organization-id UUID] [--credential-template-id SOURCE_UUID]\n'
      + '\naccept creates private state and issues one synthetic credential.\n'
      + 'resume requires a successful accept receipt and only verifies retained state.\n');
    return;
  }
  const cfg = options(argv);
  state = cfg['state-dir'];
  if (cfg.phase === 'accept') fs.mkdirSync(state, { mode: 0o700 });
  const stateInfo = fs.lstatSync(state);
  check(stateInfo.isDirectory() && !stateInfo.isSymbolicLink()
    && (stateInfo.mode & 0o777) === 0o700, 'private_state_directory_required');
  const original = cfg.phase === 'resume'
    ? JSON.parse(privateRead(path.join(state, 'accept-receipt.json'))) : null;
  if (original) check(original.origin === cfg.origin
    && original.organizationId === cfg['organization-id']
    && original.issuerDid === cfg['issuer-did']
    && original.sourceCredentialTemplateId === cfg['credential-template-id'], 'readback_scope_changed');

  stage = 'load-existing-helpers';
  const fromTests = createRequire(path.join(cfg.repo, 'tests/package.json'));
  const { chromium } = fromTests('@playwright/test');
  const { AuthHelpers } = require(path.join(cfg.repo, 'tests/utils/test-helpers.js'));
  const helpers = require(path.join(cfg.repo, 'tests/scripts/run-canvas-oss-standard-contract.js'));
  const { requireSignedCredentialBinding } = require(
    path.join(cfg.repo, 'tests/scripts/canvas-credential-identity.js'));
  // AuthHelpers may print a page body on failure. Keep credential-bearing helper
  // diagnostics out of the operator transcript; only explicit public receipts
  // below are emitted.
  console.log = console.warn = console.error = () => {};
  process.env.KEYCLOAK_URL = cfg.origin + '/auth';
  process.env.API_BASE_URL = cfg.origin;
  process.env.API_URL = cfg.origin;
  check(new URL(helpers.didWebResolutionUrl(cfg['issuer-did'])).origin === cfg.origin,
    'requested_issuer_did_origin_mismatch');

  let browser;
  try {
    stage = 'browser-launch';
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ baseURL: cfg.origin, ignoreHTTPSErrors: false });
    context.setDefaultTimeout(60000);
    const page = await context.newPage();
    stage = 'operator-login';
    const password = privateRead(cfg['password-file'], 4096).toString('utf8').trimEnd();
    check(password.length >= 16, 'operator_password_invalid');
    await page.goto(cfg.origin, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await new AuthHelpers(page).login(cfg.email, password);

    async function api(method, route, data, headers = {}) {
      const response = await page.request.fetch(cfg.origin + route, {
        method, ...(data === undefined ? {} : { data }),
        headers, timeout: 90000, maxRedirects: 0,
      });
      if (!response.ok()) {
        privateWrite(`http-failure-${++diagnostic}.bin`,
          (await response.body()).subarray(0, MAXIMUM_DIAGNOSTIC_BYTES));
        check(false, `api_http_${response.status()}`);
      }
      return response.json();
    }

    stage = 'authenticated-identity';
    const me = await api('GET', '/v1/auth/me');
    const user = me.user || me;
    check(me.authenticated === true && (user.email === cfg.email || user.username === cfg.email
      || user.preferred_username === cfg.email), 'authenticated_operator_mismatch');
    const memberId = user.user_id || user.id;
    check(typeof memberId === 'string' && memberId, 'authenticated_user_id_missing');

    let receipt;
    if (cfg.phase === 'accept') {
      stage = 'template-prerequisites';
      const candidates = list(await api('GET', '/v1/credential-templates?organization_id='
        + encodeURIComponent(cfg['organization-id'])));
      check(Array.isArray(candidates) && candidates.some(item => item.id === cfg['credential-template-id']),
        'source_credential_template_not_in_inventory');
      let template = await api('GET', '/v1/credential-templates/'
        + encodeURIComponent(cfg['credential-template-id']));
      check(template.id === cfg['credential-template-id']
        && template.organization_id === cfg['organization-id']
        && String(template.status).toUpperCase() === 'ACTIVE', 'active_owned_credential_template_required');
      check(['OPEN_BADGE', 'OPEN_BADGE_V3', 'OPENBADGECREDENTIAL'].includes(
        String(template.credential_type).toUpperCase()), 'native_open_badge_template_required');
      check(['VC_JWT', 'JWT_VC', 'JWT_VC_JSON'].includes(
        String(template.credential_payload_format).toUpperCase()), 'native_vc_jwt_template_required');
      privateWrite('source-template.json', template);

      stage = 'issuer-identity-inventory';
      const scope = '?organization_id=' + encodeURIComponent(cfg['organization-id']);
      const issuerRoute = '/v1/signing-keys/issuer-identities' + scope;
      const matchesIssuer = item => item.issuer_did === cfg['issuer-did']
        && item.key_purpose === 'vc_jwt_issuer' && item.credential_format === 'VC_JWT'
        && item.algorithm === 'ES256' && item.status === 'active'
        && (item.organization_id == null || item.organization_id === cfg['organization-id']);
      let identities = (await api('GET', issuerRoute)).identities;
      check(Array.isArray(identities), 'issuer_identity_inventory_invalid');
      check(identities.filter(matchesIssuer).length <= 1, 'issuer_identity_ambiguous');
      if (!identities.some(matchesIssuer)) {
        stage = 'create-managed-issuer-identity';
        const requestId = crypto.randomUUID();
        const request = { organization_id: cfg['organization-id'], issuer_did: cfg['issuer-did'],
          key_purpose: 'vc_jwt_issuer', credential_format: 'VC_JWT', algorithm: 'ES256' };
        privateWrite('issuer-create-requested.json', { requestId, request });
        await api('POST', issuerRoute, request, { 'Idempotency-Key': requestId });
        identities = (await api('GET', issuerRoute)).identities;
      }
      check(Array.isArray(identities) && identities.filter(matchesIssuer).length === 1,
        'active_managed_issuer_identity_required');
      privateWrite('issuer-ready.json', identities.find(matchesIssuer));

      if (template.issuer_did !== cfg['issuer-did']) {
        stage = 'create-template-version';
        privateWrite('template-version-requested.json', { sourceId: template.id,
          desiredIssuerDid: cfg['issuer-did'], at: new Date().toISOString() });
        const draft = await api('POST', '/v1/credential-templates/'
          + encodeURIComponent(template.id) + '/new-version' + scope, {});
        check(typeof draft.id === 'string' && draft.id !== template.id
          && draft.organization_id === cfg['organization-id']
          && String(draft.status).toUpperCase() === 'DRAFT', 'new_template_draft_required');
        privateWrite('template-version-created.json', { templateId: draft.id });
        stage = 'configure-template-issuer';
        await api('PATCH', '/v1/credential-templates/' + encodeURIComponent(draft.id) + scope,
          { issuer_did: cfg['issuer-did'] });
        stage = 'activate-template-version';
        await api('POST', '/v1/credential-templates/' + encodeURIComponent(draft.id)
          + '/activate' + scope, {});
        template = await api('GET', '/v1/credential-templates/' + encodeURIComponent(draft.id));
      }
      check(template.organization_id === cfg['organization-id']
        && template.issuer_did === cfg['issuer-did']
        && String(template.status).toUpperCase() === 'ACTIVE', 'active_template_issuer_mismatch');
      const identity = { vct: template.vct, issuer_did: template.issuer_did,
        credential_payload_format: 'VC_JWT', credential_type: 'OpenBadgeCredential' };
      // These are the native Open Badge output identity names, not changes to
      // the actual offer's configuration ID or the stored template.
      check(typeof identity.vct === 'string' && identity.vct, 'template_vct_required');
      check(new URL(helpers.didWebResolutionUrl(identity.issuer_did)).origin === cfg.origin,
        'template_issuer_did_origin_mismatch');
      privateWrite('selected-template.json', template);

      stage = 'initiate-credential';
      const requestId = crypto.randomUUID();
      const request = { organization_id: cfg['organization-id'], credential_template_id: template.id,
        issuer_did: cfg['issuer-did'], claims: {
          member_id: memberId, email: cfg.email, given_name: 'Milestone', family_name: 'Operator',
          organization_id: cfg['organization-id'], organization_name: 'Marty', role: 'applicant',
          achievement_name: 'Kubernetes milestone acceptance',
          achievement_description: 'Synthetic operator credential for deployment acceptance',
          issued_at: new Date().toISOString(),
        } };
      privateWrite('issuance-requested.json', { requestId, request });
      const offer = await api('POST', '/v1/issuance', request, { 'Idempotency-Key': requestId });
      check(typeof offer.id === 'string' && offer.id
        && offer.organization_id === cfg['organization-id'] && offer.credential_template_id === template.id
        && typeof offer.credential_offer_uri === 'string' && offer.credential_offer_uri,
        'credential_offer_missing');
      privateWrite('offer-private.json', offer);
      stage = 'oid4vci-redeem-and-verify';
      const received = await helpers.receiveAndVerifyCredential(offer.credential_offer_uri, identity, cfg.origin);
      privateWrite('credential-private.json', received);
      const credentialId = received.payload?.jti;
      check(typeof credentialId === 'string' && credentialId, 'signed_credential_id_missing');
      if (received.payload.vc?.id) check(received.payload.vc.id === credentialId, 'signed_credential_ids_differ');
      receipt = { schema: 'marty.kubernetes-development-acceptance/v1', phase: 'accept',
        journey: 'direct-issuance', origin: cfg.origin, organizationId: cfg['organization-id'],
        sourceCredentialTemplateId: cfg['credential-template-id'], credentialTemplateId: template.id,
        transactionId: offer.id, applicationId: null, credentialId,
        credentialSha256: sha256(received.credential), issuerDid: received.payload.iss,
        vct: identity.vct, signatureVerified: true, holderBindingVerified: true,
        loginVerified: true, at: new Date().toISOString() };
    } else {
      stage = 'stored-credential-signature';
      const received = JSON.parse(privateRead(path.join(state, 'credential-private.json'), MAXIMUM_STATE_FILE_BYTES));
      check(sha256(received.credential) === original.credentialSha256, 'stored_credential_changed');
      const issuerUrl = helpers.didWebResolutionUrl(original.issuerDid);
      check(new URL(issuerUrl).origin === cfg.origin, 'stored_issuer_origin_changed');
      const response = await helpers.fetchWithTimeout(issuerUrl, {
        headers: { Accept: 'application/did+json, application/json' },
      });
      const did = await helpers.responseJson(response, 'did_readback_failed', 'Issuer DID readback failed');
      check(did.id === original.issuerDid, 'issuer_did_readback_changed');
      const method = helpers.verificationMethodFromDidDocument(did, received.header.kid);
      const verified = helpers.verifyCompactJws(received.credential.split('~')[0], method.publicKeyJwk);
      check(verified.payload.jti === original.credentialId, 'credential_id_readback_changed');
      requireSignedCredentialBinding(verified.payload, { vct: original.vct,
        issuer_did: original.issuerDid, credential_payload_format: 'VC_JWT', credential_type: 'OpenBadgeCredential' });
      receipt = { ...original, phase: 'resume', at: new Date().toISOString() };
    }

    stage = 'transaction-persistence-readback';
    const transaction = await api('GET', '/v1/issuance/' + encodeURIComponent(receipt.transactionId));
    check(transaction.id === receipt.transactionId && transaction.organization_id === receipt.organizationId
      && transaction.credential_template_id === receipt.credentialTemplateId
      && transaction.status === 'issued' && transaction.application_id == null,
      'issued_transaction_readback_failed');
    stage = 'credential-persistence-readback';
    const record = await api('GET', '/v1/issued-credentials/' + encodeURIComponent(receipt.credentialId));
    check(record.id === receipt.credentialId && record.credential_id === receipt.credentialId
      && record.organization_id === receipt.organizationId && record.application_id == null
      && record.credential_template_id === receipt.credentialTemplateId
      && record.credential_hash === receipt.credentialSha256 && record.status === 'ACTIVE'
      && record.flow_execution_id === receipt.transactionId,
      'issued_credential_readback_failed');
    receipt.transactionStatus = transaction.status;
    receipt.credentialStatus = record.status;
    receipt.persistenceVerified = true;
    receipt.result = 'passed';
    privateWrite(cfg.phase === 'accept' ? 'accept-receipt.json'
      : `resume-receipt-${Date.now()}.json`, receipt);
    emit(receipt);
  } finally {
    if (browser) await browser.close();
  }
}

main(process.argv.slice(2)).catch(error => {
  const code = /^[a-z0-9_]{1,90}$/.test(String(error?.code || '')) ? error.code : 'acceptance_step_failed';
  emit({ result: 'stopped', stage, code,
    preservePrivateState: true, initializationOrIssuanceReplayAttempted: false });
  process.exitCode = 1;
});
