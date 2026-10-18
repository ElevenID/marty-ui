#!/usr/bin/env node
/* eslint-disable no-console */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { chromium } = require('@playwright/test');

const {
  issueCredential,
  login,
  selectOrg,
} = require('./audit-beta-credential-lifecycle');
const {
  didWebResolutionUrl,
  receiveAndVerifyCredential,
  verificationMethodFromDidDocument,
  verifyCompactJws,
  verifyCompactJwsStructure,
} = require('./run-canvas-oss-standard-contract');
const {
  DEFAULT_BETA_ORGANIZATION_ID,
  DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID,
} = require('./beta-credential-contract');
const {
  providerSwitchBehaviorAssertions,
} = require('./beta-issuer-provider-switch-contract');
const { loadEnvFile, redact } = require('./verify-beta-waltid-acceptance');
const {
  VIDEO_SIZE,
  createArtifactDir,
  finalizeVideo,
  showStep,
} = require('./demo-recording');
const {
  ensureGovernedIssuer,
  safeErrorDetail,
} = require('./beta-demo-resource-helpers');

const ROOT = path.resolve(__dirname, '..', '..');
loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
loadEnvFile(path.join(ROOT, '.env'));

const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const ORG_ID = process.env.BETA_AUDIT_ORG_ID || DEFAULT_BETA_ORGANIZATION_ID;
const SOURCE_TEMPLATE_ID = process.env.BETA_AUDIT_TEMPLATE_ID
  || DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID;
const HEADLESS = process.env.HEADED !== '1';
const RECORD_VIDEO = process.env.RECORD_VIDEO === '1';
const LOCAL_BETA_PROXY = process.env.BETA_LOCAL_PROXY === '1';
const MANAGED_SERVICE_ID = 'managed-openbao-transit';

function providerVerificationDisplay(report, phase) {
  const assertions = providerSwitchBehaviorAssertions(report);
  const required = ['issue_with_provider_a', 'switch_signing_provider', 'verify_same_did_identity'];
  if (phase === 'denied-switch') required.push('unpublished_signing_key_denied');
  else if (phase !== 'after-switch') throw new Error('Unknown provider evidence phase');
  if (required.some(id => assertions[id] !== true)) throw new Error('Provider display requires actual passing verification evidence');
  const first = report.providerA.credential, second = report.providerB.credential;
  const rows = [
    ['Issuer DID (both credentials)', first.issuerDid],
    ['Original credential key ID', first.kid],
    ['New credential key ID', second.kid],
    ['Original credential reverified after switch', String(report.providerA.reverifiedAfterSwitch)],
    ['New credential signature verified', String(second.verified)],
  ];
  if (phase === 'denied-switch') {
    const denied = report.unpublishedReplacement;
    rows.push(['Unpublished replacement response', `HTTP ${denied.rebindStatus}; cutover accepted: ${denied.rebindOk}`],
      ['Post-denial issuance still uses published key B', String(denied.credentialAfterDenial.kid === second.kid)],
      ['Post-denial credential signature verified', String(denied.credentialAfterDenial.verified)]);
  }
  return {title:phase === 'denied-switch' ? 'Unpublished key denied; published key retained' : 'One issuer DID; both credentials verify', rows,
    boundary:'Cryptographic test evidence from actual issued credentials and resolved public DID keys. Added recording panel; not an admin portal screen.',
    custodyScope:'Distinct keys and provider configurations on one beta OpenBao backend.'};
}

async function showProviderVerification(page, report, phase) {
  const payload = providerVerificationDisplay(report, phase);
  if (!RECORD_VIDEO) return;
  await page.evaluate(payload => {
    document.getElementById('d02-verification-evidence')?.remove();
    const panel = document.createElement('section'); panel.id = 'd02-verification-evidence';
    Object.assign(panel.style,{position:'fixed',top:'96px',left:'276px',right:'28px',padding:'24px',
      zIndex:'2147483646',background:'#0f172a',color:'#f8fafc',fontFamily:'Arial, sans-serif',border:'3px solid #38bdf8'});
    const line = (text,size,color) => {const node=document.createElement('div');node.textContent=text;
      Object.assign(node.style,{fontSize:size+'px',color:color || '#f8fafc',marginBottom:'9px',overflowWrap:'anywhere'});panel.appendChild(node);};
    line('CRYPTOGRAPHIC TEST EVIDENCE',20,'#7dd3fc'); line(payload.title,32);
    for (const [label,value] of payload.rows) line(label+': '+value,22);
    line(payload.custodyScope,20,'#7dd3fc'); line(payload.boundary,18,'#cbd5e1');
    document.body.appendChild(panel);
  },payload);
  await page.locator('#d02-verification-evidence').waitFor({state:'visible'});
  await page.waitForTimeout(6000);
  await page.evaluate(() => document.getElementById('d02-verification-evidence')?.remove());
}

async function showProviderStep(page, title, detail) {
  return showStep(page, title, detail, {
    enabled: RECORD_VIDEO,
    eyebrow: 'Stable issuer identity with pluggable KMS custody',
  });
}

async function browserJson(page, pathName, options = {}) {
  return page.evaluate(async ({ requestPath, requestOptions }) => {
    const response = await fetch(requestPath, {
      credentials: 'include',
      ...requestOptions,
      headers: {
        ...(requestOptions.body ? { 'Content-Type': 'application/json' } : {}),
        ...(requestOptions.headers || {}),
      },
    });
    const body = await response.json().catch(() => null);
    return { ok: response.ok, status: response.status, body };
  }, { requestPath: pathName, requestOptions: options });
}

async function loadSigningConfig(page) {
  const response = await browserJson(
    page,
    `/v1/signing-keys/config?organization_id=${encodeURIComponent(ORG_ID)}`,
  );
  if (!response.ok || !response.body || !Array.isArray(response.body.services)) {
    throw new Error(`Signing configuration is unavailable (HTTP ${response.status})`);
  }
  return response.body;
}

function writableConfig(config, { extraServices = [], defaultServiceId, resetDefaults = false } = {}) {
  const replacements = new Set(extraServices.map((service) => service.id));
  const services = config.services
    .filter((service) => service.id !== MANAGED_SERVICE_ID && !service.managed)
    .filter((service) => !replacements.has(service.id))
    .concat(extraServices);
  return {
    services,
    default_service_id: defaultServiceId ?? config.default_service_id,
    format_defaults: resetDefaults ? {} : (config.format_defaults || {}),
    type_defaults: resetDefaults ? {} : (config.type_defaults || {}),
    key_reference_purposes: config.key_reference_purposes || {},
  };
}

function changedPaths(before, after, prefix = '') {
  if (stateHash(before ?? null) === stateHash(after ?? null)) return [];
  if (before && after && typeof before === 'object' && typeof after === 'object') return [...new Set([...Object.keys(before), ...Object.keys(after)])].flatMap(key => changedPaths(before[key], after[key], prefix ? `${prefix}.${key}` : key));
  return [prefix];
}

function stateHash(value) {
  const sorted = item => Array.isArray(item) ? item.map(sorted) : item && typeof item === 'object'
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, sorted(item[key])])) : item;
  return crypto.createHash('sha256').update(JSON.stringify(sorted(value))).digest('hex');
}

async function protectedFixtureState(page) {
  const routes = {
    loginTrust: '/v1/trust-profiles/60000000-0000-0000-0000-000000000001',
    loginIssuers: '/v1/trust-profiles/60000000-0000-0000-0000-000000000001/issuers',
    lifecycleSource: `/v1/credential-templates/${process.env.D02_PROTECTED_LIFECYCLE_TEMPLATE_ID}`,
    discovery: `/.well-known/openid-credential-issuer/org/${ORG_ID}`,
  };
  const result = {};
  for (const [name, route] of Object.entries(routes)) {
    const response = await browserJson(page, route);
    if (!response.ok) throw new Error(`Protected beta fixture ${name} unavailable (HTTP ${response.status})`);
    result[name] = stateHash(response.body);
  }
  return result;
}

function restoredConfigurationEvidence(original, restored, createdManagedKeys = []) {
  const before = writableConfig(original);
  const actual = writableConfig(restored);
  const normalized = structuredClone(actual);
  const retainedManagedKeyReferences = [];
  for (const key of createdManagedKeys) {
    if (before.key_reference_purposes?.[MANAGED_SERVICE_ID]?.[key] === undefined
        && stateHash(normalized.key_reference_purposes?.[MANAGED_SERVICE_ID]?.[key]) === stateHash(['vc_jwt_issuer'])) {
      delete normalized.key_reference_purposes[MANAGED_SERVICE_ID][key];
      retainedManagedKeyReferences.push(key);
    }
  }
  return {
    ok: stateHash(before) === stateHash(normalized),
    originalWritableConfigSha256: stateHash(before),
    actualWritableConfigSha256: stateHash(actual),
    restoredControlConfigSha256: stateHash(normalized),
    changedPaths: changedPaths(before, actual),
    retainedManagedKeyReferences,
    retentionReason: 'New non-exportable managed signing key records remain after retiring their synthetic issuer identity; existing keys and all controls must be unchanged.',
  };
}

async function saveSigningConfig(page, payload) {
  const response = await browserJson(
    page,
    `/v1/signing-keys/config?organization_id=${encodeURIComponent(ORG_ID)}`,
    { method: 'PATCH', body: JSON.stringify(payload) },
  );
  if (!response.ok) {
    throw new Error(`Signing configuration update failed (HTTP ${response.status})${safeErrorDetail(response.body)}`);
  }
  return response.body;
}

function identityRequest(issuerDid) {
  return {
    organization_id: ORG_ID,
    issuer_did: issuerDid,
    key_purpose: 'vc_jwt_issuer',
    credential_format: 'SD_JWT_VC',
    algorithm: 'ES256',
  };
}

async function createIdentity(page, issuerDid, idempotencyKey) {
  const response = await browserJson(
    page,
    `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(ORG_ID)}`,
    {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(identityRequest(issuerDid)),
    },
  );
  return {
    ok: response.ok,
    status: response.status,
    created: response.body?.created === true,
    identity: response.body?.identity || null,
  };
}

async function signingKeyForIdentity(page, issuerDid) {
  const response = await browserJson(
    page,
    `/v1/signing-keys?organization_id=${encodeURIComponent(ORG_ID)}`,
  );
  const key = response.body?.keys?.find((candidate) => (
    candidate.name === issuerDid
    && candidate.service_id === MANAGED_SERVICE_ID
    && candidate.algorithm === 'ES256'
  ));
  if (!response.ok || !key?.provider_key_name) {
    throw new Error('The managed seed identity did not expose its public signing-key inventory entry');
  }
  return key.provider_key_name;
}

function managedTransitEndpoint(config) {
  const services = config?.services?.filter((service) => service.id === MANAGED_SERVICE_ID) || [];
  if (services.length !== 1) throw new Error('Expected one managed transit service');
  const endpoint = services[0].endpoint;
  let parsed;
  try { parsed = new URL(endpoint); } catch { throw new Error('Managed transit endpoint is invalid'); }
  if (!['http:', 'https:'].includes(parsed.protocol)
    || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('Managed transit endpoint is invalid');
  }
  return endpoint;
}

function externalTransitPrerequisites(env = process.env) {
  if (env.BETA_ORIGIN !== 'https://beta.elevenidllc.com'
      || env.D02_SAME_BACKEND_FIXTURE !== '1'
      || env.D02_EXTERNAL_TRANSIT_ENDPOINT !== 'https://openbao:8200'
      || env.D02_EXTERNAL_TRANSIT_CA_FILE !== '/run/secrets/openbao_tls_ca_cert'
      || !/^d02-external-[a-z0-9-]+$/.test(env.D02_EXTERNAL_TRANSIT_KEY || '')
      || !env.D02_EXTERNAL_TRANSIT_TOKEN || /\s/.test(env.D02_EXTERNAL_TRANSIT_TOKEN)
      || env.D02_EXTERNAL_TRANSIT_TOKEN.length > 16384) {
    throw new Error('Scoped beta external-transit token, key, HTTPS CA and same-backend acknowledgement are required');
  }
  return {
    endpoint: env.D02_EXTERNAL_TRANSIT_ENDPOINT,
    token: env.D02_EXTERNAL_TRANSIT_TOKEN,
    caCertFile: env.D02_EXTERNAL_TRANSIT_CA_FILE,
    keyReference: env.D02_EXTERNAL_TRANSIT_KEY,
    unavailableKey: env.D02_EXTERNAL_TRANSIT_KEY + '-unpublished',
  };
}

function transitService(id, name, keyReference, endpoint, credentials) {
  managedTransitEndpoint({ services: [{ id: MANAGED_SERVICE_ID, endpoint }] });
  if (!endpoint.startsWith('https:') || !credentials?.token || !credentials?.caCertFile) {
    throw new Error('External transit requires explicit token authentication and HTTPS CA');
  }
  return {
    id, name,
    description: 'Synthetic provider configuration and key switch on the same beta OpenBao backend; not independent KMS products.',
    service_type: 'openbao-transit', provider: 'openbao', endpoint,
    mount: 'transit', namespace: '', region: '',
    auth_mode: 'token', auth_reference: credentials.token, ca_cert_file: credentials.caCertFile,
    key_reference: keyReference, key_aliases: [keyReference],
    algorithms: ['ES256'], key_purposes: ['vc_jwt_issuer'], credential_formats: ['dc+sd-jwt'], status: 'configured',
  };
}

async function createTemplateVersion(page, issuerDid, stamp) {
  const result = await page.evaluate(async ({ issuer, sourceTemplateId, versionStamp }) => {
    const sourceResponse = await fetch(
      `/v1/credential-templates/${encodeURIComponent(sourceTemplateId)}`,
      { credentials: 'include' },
    );
    const source = await sourceResponse.json().catch(() => null);
    if (!sourceResponse.ok || !source?.id) {
      return { ok: false, status: sourceResponse.status, error: 'Source template unavailable' };
    }
    const versionResponse = await fetch(
      `/v1/credential-templates/${encodeURIComponent(sourceTemplateId)}/new-version`,
      { method: 'POST', credentials: 'include' },
    );
    const version = await versionResponse.json().catch(() => null);
    if (!versionResponse.ok || !version?.id) {
      return { ok: false, status: versionResponse.status, error: 'Template version creation failed' };
    }
    const patchResponse = await fetch(`/v1/credential-templates/${encodeURIComponent(version.id)}`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: `D-02 Provider Switch ${versionStamp}`,
        issuer_did: issuer,
      }),
    });
    const patched = await patchResponse.json().catch(() => null);
    if (!patchResponse.ok) {
      return {
        ok: false,
        status: patchResponse.status,
        templateId: version.id,
        error: 'Template update failed',
        errorBody: patched,
      };
    }
    const activateResponse = await fetch(
      `/v1/credential-templates/${encodeURIComponent(version.id)}/activate`,
      { method: 'POST', credentials: 'include' },
    );
    const activated = await activateResponse.json().catch(() => null);
    return {
      ok: activateResponse.ok,
      status: activateResponse.status,
      templateId: version.id,
      template: activateResponse.ok ? activated : null,
      errorBody: activateResponse.ok ? null : activated,
    };
  }, {
    issuer: issuerDid,
    sourceTemplateId: SOURCE_TEMPLATE_ID,
    custodyScope: 'Two provider configurations and distinct keys on one beta OpenBao backend; not two independent KMS products.',
    externalAuthentication: { mode: 'token', explicitCa: true, scopedFixtureKey: true },
    versionStamp: stamp,
  });
  return {
    ...result,
    error: result.ok
      ? null
      : `${result.error || 'Template activation failed'}${safeErrorDetail(result.errorBody)}`,
    errorBody: undefined,
  };
}

function governedIssuerRequest(sourceTemplate, issuerDid, stamp) {
  if (!sourceTemplate?.trust_profile_id) {
    throw new Error('D-02 source Credential Template lacks a Trust Profile binding');
  }
  return {
    organizationId: ORG_ID,
    trustProfileId: sourceTemplate.trust_profile_id,
    issuerDid,
    displayName: `D-02 Provider Switch Issuer ${stamp}`,
    idempotencyKey: `d02-governed-issuer-${stamp}`,
  };
}

function credentialEvidence(issued) {
  return {
    verified: true,
    issuerDid: issued.payload.iss,
    kid: issued.header.kid,
    algorithm: issued.header.alg,
    vct: issued.payload.vct,
  };
}

async function issueAndVerify(page, template) {
  const issuance = await issueCredential(page, template.id);
  if (!issuance.ok || !issuance.offerUri) {
    throw new Error(`Credential issuance failed (HTTP ${issuance.status})`);
  }
  const issued = await receiveAndVerifyCredential(issuance.offerUri, template, BETA_ORIGIN);
  return {
    issuance: {
      ok: issuance.ok,
      status: issuance.status,
      templateName: issuance.templateName,
      expectedVct: issuance.expectedVct,
    },
    credential: credentialEvidence(issued),
    issued,
  };
}

async function didDocument(issuerDid) {
  const response = await fetch(didWebResolutionUrl(issuerDid), {
    headers: { Accept: 'application/did+json, application/json' },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`Issuer DID resolution failed (HTTP ${response.status})`);
  return response.json();
}

async function reverifyIssuedCredential(issued) {
  const compact = issued.credential.split('~')[0];
  const structure = verifyCompactJwsStructure(compact);
  const document = await didDocument(structure.payload.iss);
  const method = verificationMethodFromDidDocument(document, structure.header.kid);
  const verified = verifyCompactJws(compact, method.publicKeyJwk);
  return {
    verified: verified.payload.iss === structure.payload.iss,
    assertionMethodIds: (document.assertionMethod || []).map((entry) => (
      typeof entry === 'string' ? entry : entry?.id
    )).filter(Boolean),
  };
}

async function rebindThroughConsole(page, issuerDid) {
  await page.goto(`${BETA_ORIGIN}/console/org/deploy/issuer-identity`, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  const row = page.locator('tbody tr').filter({ hasText: issuerDid }).first();
  await row.waitFor({ state: 'visible', timeout: 30_000 });
  const responsePromise = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/v1/signing-keys/issuer-identities'
    && response.request().method() === 'PATCH'
  ), { timeout: 60_000 });
  await row.getByRole('button', { name: 'Move identity to default signing service' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Move identity' }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  return {
    ok: response.ok(),
    status: response.status(),
    changed: body?.changed === true,
    identity: body?.identity || null,
  };
}

async function directRebind(page, issuerDid) {
  const response = await browserJson(
    page,
    `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(ORG_ID)}`,
    { method: 'PATCH', body: JSON.stringify(identityRequest(issuerDid)) },
  );
  return { ok: response.ok, status: response.status };
}

async function cleanup(page, templateId, issuerDids, governance = null) {
  const results = {
    retiredTemplate: !templateId,
    templateRetirement: templateId ? null : 'not-created',
    revokedCredentials: 0,
    removedGovernanceRelationships: 0,
    removedGovernedIssuers: 0,
    retiredIdentities: 0,
  };
  if (templateId) {
    const list = await browserJson(
      page,
      `/v1/issued-credentials?organization_id=${encodeURIComponent(ORG_ID)}`,
    );
    const credentials = Array.isArray(list.body) ? list.body : [];
    for (const credential of credentials) {
      if (credential.credential_template_id !== templateId
        || String(credential.status).toUpperCase() !== 'ACTIVE') continue;
      const revoked = await browserJson(
        page,
        `/v1/issued-credentials/${encodeURIComponent(credential.id)}/revoke`,
        { method: 'POST', body: JSON.stringify({ reason: 'D-02 release qualification cleanup' }) },
      );
      if (revoked.ok) results.revokedCredentials += 1;
    }
    const current = await browserJson(
      page,
      `/v1/credential-templates/${encodeURIComponent(templateId)}`,
    );
    const status = String(current.body?.status || '').toUpperCase();
    const retirement = status === 'DRAFT'
      ? await browserJson(page, `/v1/credential-templates/${encodeURIComponent(templateId)}`, {
        method: 'DELETE',
      })
      : await browserJson(
        page,
        `/v1/credential-templates/${encodeURIComponent(templateId)}/deprecate`,
        { method: 'POST' },
      );
    results.retiredTemplate = retirement.ok;
    results.templateRetirement = status === 'DRAFT' ? 'deleted' : 'deprecated';
  }
  if (governance?.relationshipCreated && governance.relationship?.id) {
    const removed = await browserJson(
      page,
      `/v1/trust-profiles/${encodeURIComponent(governance.trustProfileId)}`
        + `/issuers/${encodeURIComponent(governance.relationship.id)}`,
      { method: 'DELETE' },
    );
    if (removed.ok) results.removedGovernanceRelationships += 1;
  }
  if (governance?.created && governance.issuer?.id) {
    const removed = await browserJson(
      page,
      `/v1/issuer-entities/${encodeURIComponent(governance.issuer.id)}`,
      { method: 'DELETE' },
    );
    if (removed.ok) results.removedGovernedIssuers += 1;
  }
  for (const issuerDid of issuerDids) {
    const response = await browserJson(
      page,
      `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(ORG_ID)}`,
      { method: 'DELETE', body: JSON.stringify(identityRequest(issuerDid)) },
    );
    if (response.ok) results.retiredIdentities += 1;
  }
  return results;
}

async function main() {
  const email = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const password = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  if (!email || !password) throw new Error('Missing beta operator credentials');

  const externalTransit = externalTransitPrerequisites();
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').toLowerCase();
  const artifactDir = createArtifactDir(ROOT, `beta-issuer-provider-switch-${stamp}`);
  const issuerDid = `did:web:${new URL(BETA_ORIGIN).host}:orgs:d02-provider-switch-${stamp}`;
  const providerBId = `d02-provider-b-${stamp}`;
  const providerCId = `d02-provider-unpublished-${stamp}`;
  const report = {
    createdAt: new Date().toISOString(),
    organizationId: ORG_ID,
    issuerDid,
    sourceTemplateId: SOURCE_TEMPLATE_ID,
    custodyScope: 'Two provider configurations and distinct keys on one beta OpenBao backend; not two independent KMS products.',
    externalAuthentication: { mode: 'token', explicitCa: true, scopedFixtureKey: true },
    pageErrors: [],
    unexpectedResponses: [],
  };
  const browser = await chromium.launch({
    headless: HEADLESS,
    args: LOCAL_BETA_PROXY
      ? ['--host-resolver-rules=MAP beta.elevenidllc.com 127.0.0.1', '--no-proxy-server']
      : [],
  });
  let context;
  let originalConfig;
  try {
    context = await browser.newContext({
      viewport: VIDEO_SIZE,
      ignoreHTTPSErrors: LOCAL_BETA_PROXY,
      ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
    });
    const page = await context.newPage();
    const video = page.video();
    page.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
    page.on('response', (response) => {
      if (!response.url().startsWith(BETA_ORIGIN) || response.status() < 400) return;
      const expectedDeniedRebind = response.status() === 503
        && response.request().method() === 'PATCH'
        && new URL(response.url()).pathname === '/v1/signing-keys/issuer-identities';
      if (!expectedDeniedRebind && !response.url().includes('/cdn-cgi/rum')) {
        report.unexpectedResponses.push({
          status: response.status(),
          method: response.request().method(),
          url: redact(response.url()),
        });
      }
    });

    report.loginTheme = await login(page, email, password);
    report.orgSelection = await selectOrg(page);
    if (!report.orgSelection.ok) throw new Error(`Cannot select organization ${ORG_ID}`);
    originalConfig = await loadSigningConfig(page);
    report.protectedStateBefore = await protectedFixtureState(page);
    report.originalWritableConfigSha256 = stateHash(writableConfig(originalConfig));
    const transitEndpoint = managedTransitEndpoint(originalConfig);
    if (transitEndpoint !== externalTransit.endpoint) throw new Error('Beta backend differs from the provisioned fixture');

    let templateId = null;
    let governance = null;
    let qualificationError = null;
    const createdIdentityDids = [];
    const createdManagedKeys = [];
    try {
      const managedConfig = await saveSigningConfig(page, writableConfig(originalConfig, {
        defaultServiceId: MANAGED_SERVICE_ID,
        resetDefaults: true,
      }));
      report.providerAConfig = {
        defaultServiceId: managedConfig.default_service_id,
        serviceId: MANAGED_SERVICE_ID,
      };

      report.identityCreation = await createIdentity(page, issuerDid, `d02-identity-${stamp}`);
      if (!report.identityCreation.ok) throw new Error(`Issuer identity creation failed (HTTP ${report.identityCreation.status})`);
      if (report.identityCreation.created) {
        createdIdentityDids.push(issuerDid);
        createdManagedKeys.push(await signingKeyForIdentity(page, issuerDid));
      }

      const sourceTemplate = await browserJson(
        page,
        `/v1/credential-templates/${encodeURIComponent(SOURCE_TEMPLATE_ID)}`,
      );
      if (!sourceTemplate.ok || !sourceTemplate.body?.id) {
        throw new Error(
          `D-02 source Credential Template unavailable (HTTP ${sourceTemplate.status})`
          + safeErrorDetail(sourceTemplate.body),
        );
      }
      const governanceRequest = governedIssuerRequest(sourceTemplate.body, issuerDid, stamp);
      governance = {
        ...(await ensureGovernedIssuer(page, governanceRequest)),
        trustProfileId: governanceRequest.trustProfileId,
      };
      report.governance = {
        issuerEntityId: governance.issuer.id,
        relationshipId: governance.relationship.id,
        trustProfileId: governance.trustProfileId,
        created: governance.created,
        relationshipCreated: governance.relationshipCreated,
      };

      report.template = await createTemplateVersion(page, issuerDid, stamp);
      templateId = report.template.templateId || null;
      if (!report.template.ok || !report.template.template?.id) {
        throw new Error(`D-02 template setup failed: ${report.template.error}`);
      }
      const template = report.template.template;
      report.template = { ok: true, id: template.id, name: template.name, vct: template.vct };

      await page.goto(`${BETA_ORIGIN}/console/org/deploy/issuer-identity`, {
        waitUntil: 'domcontentloaded',
        timeout: 60_000,
      });
      await page.getByText(issuerDid).first().waitFor({ state: 'visible', timeout: 30_000 });
      await showProviderStep(page, 'Stable issuer DID created', 'The public identity is active without exposing provider or key coordinates.');

      const providerA = await issueAndVerify(page, template);
      report.providerA = { issuance: providerA.issuance, credential: providerA.credential };
      await showProviderStep(page, 'Credential signed by provider A', 'The first credential verifies against the DID method published by managed custody.');

      const providerBKey = externalTransit.keyReference;
      const latestConfig = await loadSigningConfig(page);
      const providerB = transitService(providerBId, `D-02 Provider B ${stamp}`, providerBKey, transitEndpoint, externalTransit);
      const providerBConfig = await saveSigningConfig(page, writableConfig(latestConfig, {
        extraServices: [providerB],
        defaultServiceId: providerBId,
        resetDefaults: true,
      }));
      report.providerBConfig = {
        defaultServiceId: providerBConfig.default_service_id,
        serviceId: providerBId,
      };

      report.rebind = await rebindThroughConsole(page, issuerDid);
      if (!report.rebind.ok || !report.rebind.changed) {
        throw new Error(`Provider switch failed (HTTP ${report.rebind.status})`);
      }
      await showProviderStep(page, 'Signing moved to configuration B', 'This beta fixture uses a distinct key and scoped token on the same OpenBao backend. The replacement public key was published before the active configuration changed.');

      const providerBResult = await issueAndVerify(page, template);
      report.providerB = {
        issuance: providerBResult.issuance,
        credential: providerBResult.credential,
      };
      const oldReverification = await reverifyIssuedCredential(providerA.issued);
      report.providerA.reverifiedAfterSwitch = oldReverification.verified;
      report.didAfterSwitch = { assertionMethodIds: oldReverification.assertionMethodIds };
      await showProviderVerification(page, report, 'after-switch');
      await showProviderStep(page, 'One DID, both credentials valid', 'New issuance uses provider B while the provider-A credential remains verifiable through the retained DID method.');

      const beforeFailureConfig = await loadSigningConfig(page);
      const unavailable = transitService(
        providerCId,
        `D-02 Unpublished Provider ${stamp}`,
        externalTransit.unavailableKey,
        transitEndpoint,
        externalTransit,
      );
      await saveSigningConfig(page, writableConfig(beforeFailureConfig, {
        extraServices: [providerB, unavailable],
        defaultServiceId: providerCId,
        resetDefaults: true,
      }));
      const deniedRebind = await directRebind(page, issuerDid);
      const afterDenial = await issueAndVerify(page, template);
      report.unpublishedReplacement = {
        rebindOk: deniedRebind.ok,
        rebindStatus: deniedRebind.status,
        issueAfterDenial: afterDenial.issuance,
        credentialAfterDenial: afterDenial.credential,
      };
      await showProviderVerification(page, report, 'denied-switch');
      await showProviderStep(page, 'Unpublished replacement denied', 'An unavailable replacement key cannot cut over custody; issuance continues on the last published provider-B method.');

      report.behaviorAssertions = providerSwitchBehaviorAssertions(report);
    } catch (error) {
      qualificationError = error;
      report.error = redact(error.stack || error.message || String(error));
    } finally {
      try {
        report.cleanup = await cleanup(page, templateId, createdIdentityDids, governance);
      } catch (error) {
        report.cleanupError = redact(error.stack || error.message || String(error));
      }
      if (originalConfig) {
        try {
          const restored = await saveSigningConfig(page, writableConfig(originalConfig));
          report.configRestored = {
            ...restoredConfigurationEvidence(originalConfig, restored, createdManagedKeys),
            defaultServiceId: restored.default_service_id,
          };
        } catch (error) {
          report.configRestoreError = redact(error.stack || error.message || String(error));
        }
      }
    }

    report.protectedStateAfter = await protectedFixtureState(page);
    report.protectedStateUnchanged = stateHash(report.protectedStateBefore) === stateHash(report.protectedStateAfter);
    report.releaseReady = Boolean(
      report.protectedStateUnchanged
      && !qualificationError
      && Object.values(report.behaviorAssertions || {}).every((passed) => passed === true)
      && report.cleanup?.retiredTemplate
      && report.cleanup?.revokedCredentials >= 3
      && report.cleanup?.removedGovernanceRelationships === 1
      && report.cleanup?.removedGovernedIssuers === 1
      && report.cleanup?.retiredIdentities === 1
      && report.configRestored?.ok
      && report.loginTheme?.ok
      && report.pageErrors.length === 0
      && report.unexpectedResponses.length === 0
    );
    report.finishedAt = new Date().toISOString();
    await context.close();
    context = null;
    if (RECORD_VIDEO) {
      report.recording = path.relative(
        ROOT,
        await finalizeVideo(video, artifactDir, 'stable-issuer-identity-pluggable-kms.webm'),
      );
    }
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
    if (!report.releaseReady) process.exitCode = 1;
  } catch (error) {
    report.error = redact(error.stack || error.message || String(error));
    report.releaseReady = false;
    report.finishedAt = new Date().toISOString();
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    throw error;
  } finally {
    if (context) await context.close().catch(() => {});
    await browser.close();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
    process.exitCode = 1;
  });
}

module.exports = {
  providerVerificationDisplay,
  cleanup,
  credentialEvidence,
  governedIssuerRequest,
  identityRequest,
  managedTransitEndpoint,
  transitService,
  externalTransitPrerequisites,
  restoredConfigurationEvidence,
  writableConfig,
};
