#!/usr/bin/env node
/* eslint-disable no-console */
'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { chromium } = require('@playwright/test');

const {
  issueCredential,
  finalizeLiveRun,
  login,
  selectOrg,
} = require('./audit-beta-credential-lifecycle');
const { createDemoLiveEvidence, acknowledgeDemoInputs, applyLocalNativeReadiness } = require('./demo-live-evidence');
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
  createActionRecording,
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
const STRONG_CONFIG_REVISION = /^"r-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"$/i;

async function prepareProviderInputs(artifactDir, stamp, client) {
  return acknowledgeDemoInputs(artifactDir, 'provider-switch-fixture-input.json', {
    schemaVersion: 1,
    stamp,
    organizationId: ORG_ID,
    sourceTemplateId: SOURCE_TEMPLATE_ID,
    issuerDid: `did:web:${new URL(BETA_ORIGIN).host}:orgs:d02-provider-switch-${stamp}`,
    providerBId: `d02-provider-b-${stamp}`,
    providerCId: `d02-provider-unpublished-${stamp}`,
  }, client);
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
    return { ok: response.ok, status: response.status, body, etag: response.headers.get('etag') };
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
  return configSnapshot(response);
}

function configSnapshot(response) {
  const revision = response.etag;
  if (typeof revision !== 'string' || !STRONG_CONFIG_REVISION.test(revision)) {
    throw new Error('Signing configuration has no strong opaque revision');
  }
  return { config: response.body, revision };
}

function ownedIdentityRevision(result) {
  if (!result?.ok || typeof result.configRevision !== 'string'
      || !STRONG_CONFIG_REVISION.test(result.configRevision)) {
    throw new Error('Owned issuer identity mutation did not return a strong config revision');
  }
  return result.configRevision;
}

function unchangedOwnedRevision(snapshot, lastOwnedRevision) {
  if (snapshot.revision !== lastOwnedRevision) {
    throw new Error('Signing configuration changed outside this owned run');
  }
  return snapshot.config;
}

function createConfigMutationJournal(artifactDir, originalConfig, revision) {
  if (!STRONG_CONFIG_REVISION.test(revision || '')) {
    throw new Error('Cannot journal an unbound signing configuration');
  }
  const journalPath = path.join(artifactDir, 'signing-config-mutations.private.jsonl');
  const descriptor = fs.openSync(journalPath, 'wx', 0o600);
  let sequence = 0;
  let healthy = true;
  const append = (entry) => {
    if (!healthy) throw new Error('Signing config mutation journal is unavailable');
    try {
      const line = Buffer.from(`${JSON.stringify({ sequence: ++sequence, ...entry })}\n`);
      if (fs.writeSync(descriptor, line) !== line.length) {
        throw new Error('Signing config mutation journal write was incomplete');
      }
      fs.fsyncSync(descriptor);
    } catch (error) {
      healthy = false;
      throw error;
    }
  };
  try {
    const originalPublicConfig = structuredClone(writableConfig(originalConfig));
    for (const service of originalPublicConfig.services) {
      delete service.auth_reference;
      delete service.auth_reference_envelope;
    }
    append({ stage: 'ORIGINAL', organizationId: ORG_ID, originalPublicConfig,
      lastOwnedRevision: revision });
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
  return {
    path: journalPath,
    healthy: () => healthy,
    intent: (action, expectedRevision, body) => {
      if (!STRONG_CONFIG_REVISION.test(expectedRevision || '')) {
        throw new Error('Cannot dispatch an unbound signing mutation');
      }
      append({ stage: 'INPUT_OUTCOME_UNKNOWN', action, expectedRevision,
        requestSha256: stateHash(body) });
    },
    confirmed: (action, nextRevision) => {
      if (!STRONG_CONFIG_REVISION.test(nextRevision || '')) {
        throw new Error('Cannot confirm an unbound signing mutation');
      }
      append({ stage: 'CONFIRMED', action, lastOwnedRevision: nextRevision });
    },
    rejected: (action, status) => append({ stage: 'REJECTED_NO_BIND', action, httpStatus: status }),
    close: () => fs.closeSync(descriptor),
  };
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

async function saveSigningConfig(page, payload, revision) {
  if (typeof revision !== 'string' || !STRONG_CONFIG_REVISION.test(revision)) {
    throw new Error('Signing configuration update requires a strong opaque revision');
  }
  const response = await browserJson(
    page,
    `/v1/signing-keys/config?organization_id=${encodeURIComponent(ORG_ID)}`,
    { method: 'PATCH', body: JSON.stringify(payload), headers: { 'If-Match': revision } },
  );
  if (!response.ok) {
    throw new Error(`Signing configuration update failed (HTTP ${response.status})`);
  }
  return configSnapshot(response);
}

async function saveOwnedSigningConfig(page, payload, revision, journal, action) {
  journal.intent(action, revision, payload);
  const saved = await saveSigningConfig(page, payload, revision);
  journal.confirmed(action, saved.revision);
  return saved;
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

async function createIdentity(page, issuerDid, idempotencyKey, revision) {
  if (!STRONG_CONFIG_REVISION.test(revision || '')) {
    throw new Error('Issuer identity creation requires an owned config revision');
  }
  const response = await browserJson(
    page,
    `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(ORG_ID)}`,
    {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey, 'If-Match': revision },
      body: JSON.stringify(identityRequest(issuerDid)),
    },
  );
  return {
    ok: response.ok,
    status: response.status,
    created: response.body?.created === true,
    identity: response.body?.identity || null,
    configRevision: response.body?.config_revision || null,
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

function changedPaths(before, after, prefix = '') {
  if (stateHash(before ?? null) === stateHash(after ?? null)) return [];
  if (before && after && typeof before === 'object' && typeof after === 'object') return [...new Set([...Object.keys(before), ...Object.keys(after)])].flatMap(key => changedPaths(before[key], after[key], prefix ? `${prefix}.${key}` : key));
  return [prefix];
}

function stateHash(value) {
  const sorted = item => Array.isArray(item) ? item.map(sorted) : item && typeof item === 'object'
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, sorted(item[key])])) : item;
  return crypto.createHash('sha256').update(JSON.stringify(sorted(value ?? null))).digest('hex');
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

function existingProviderBInput(env = process.env) {
  const names = ['D02_EXISTING_PROVIDER_B_SERVICE_ID', 'D02_EXISTING_PROVIDER_B_SERVICE_TYPE',
    'D02_EXISTING_PROVIDER_B_PROVIDER', 'D02_EXISTING_PROVIDER_B_KEY_REFERENCE'];
  if (!names.some((name) => env[name])) return null;
  if (names.slice(0, 3).some((name) => !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(env[name] || ''))
      || !env[names[3]] || env[names[3]].length > 512 || /[\s\x00-\x1f\x7f]/.test(env[names[3]])) {
    throw new Error('Existing provider B requires exact nonsecret service, type, provider and key identity');
  }
  return {
    serviceId: env[names[0]], serviceType: env[names[1]],
    provider: env[names[2]], keyReference: env[names[3]],
  };
}

function boundExistingProviderB(config, expected, baselineEndpoint) {
  if (!expected) throw new Error('Existing provider B identity is required');
  const supportedProviders = {
    'hashicorp-vault-transit': 'hashicorp-vault',
    'aws-kms': 'aws', 'azure-key-vault': 'azure', 'gcp-cloud-kms': 'gcp',
  };
  if (supportedProviders[expected.serviceType] !== expected.provider) {
    throw new Error('Existing provider B requires a supported distinct KMS product');
  }
  const matches = config?.services?.filter((service) => service.id === expected.serviceId) || [];
  if (matches.length !== 1) throw new Error('Existing provider B service is missing or ambiguous');
  const service = matches[0];
  if (service.managed || service.status !== 'configured'
      || service.service_type !== expected.serviceType || service.provider !== expected.provider
      || service.key_reference !== expected.keyReference
      || service.service_type === 'openbao-transit' || service.provider === 'openbao'
      || (service.endpoint && new URL(service.endpoint).hostname === new URL(baselineEndpoint).hostname)
      || !Array.isArray(service.algorithms) || !service.algorithms.includes('ES256')
      || !Array.isArray(service.key_purposes) || !service.key_purposes.includes('vc_jwt_issuer')) {
    throw new Error('Existing provider B identity or signing capability does not match');
  }
  return service;
}

function managedBindingHash(organizationId, serviceId, keyReference) {
  const digest = crypto.createHash('sha256');
  for (const value of ['marty-managed-key-binding-v1', organizationId, serviceId, keyReference]) {
    digest.update(value).update(Buffer.from([0]));
  }
  return digest.digest('hex');
}

function matchesManagedBinding(resolved, issuerDid, serviceId, keyReference) {
  return resolved?.identity?.issuer_did === issuerDid
    && resolved.managed_key_binding_sha256 === managedBindingHash(ORG_ID, serviceId, keyReference)
    && Boolean(resolved.public_jwk);
}

async function verifySelectedIssuerBinding(page, issuerDid, service, issued) {
  const response = await browserJson(page,
    `/v1/signing-keys/issuer-identities/resolve?organization_id=${encodeURIComponent(ORG_ID)}`,
    { method: 'POST', body: JSON.stringify(identityRequest(issuerDid)) });
  if (!response.ok || !matchesManagedBinding(response.body, issuerDid, service.id, service.key_reference)) {
    throw new Error('Resolved issuer binding does not match selected signing service and key');
  }
  const compact = issued.credential.split('~')[0];
  const verified = verifyCompactJws(compact, response.body.public_jwk);
  if (verified.payload.iss !== issuerDid) {
    throw new Error('Issued credential does not verify under selected issuer binding');
  }
  return { selectedServiceBound: true, issuedSignatureMatchesBoundKey: true };
}

function observedRemoteSigner(existingInput, issuance, credential, selected, serviceId, binding) {
  return Boolean(existingInput && issuance?.ok && credential?.verified && selected === serviceId
    && binding?.selectedServiceBound && binding?.issuedSignatureMatchesBoundKey);
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

async function rebindThroughConsole(page, issuerDid, revision, recording = null) {
  if (!STRONG_CONFIG_REVISION.test(revision || '')) {
    throw new Error('UI issuer rebind requires an owned config revision');
  }
  await page.goto(`${BETA_ORIGIN}/console/org/deploy/issuer-identity`, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  const row = page.locator('tbody tr').filter({ hasText: issuerDid }).first();
  await row.waitFor({ state: 'visible', timeout: 30_000 });
  await recording?.explain(page, 'change-signing-provider', 'Synthetic scenario: move signing operations to the configured replacement provider while keeping the issuer identity.', {
    title: 'Keep the issuer identity while changing the signer',
  });
  const identityRoute = '**/v1/signing-keys/issuer-identities**';
  let forwarded = 0;
  const bindOwnedRevision = async (route) => {
    const request = route.request();
    let payload;
    try { payload = request.postDataJSON(); } catch { payload = null; }
    const url = new URL(request.url());
    if (forwarded !== 0 || url.origin !== new URL(BETA_ORIGIN).origin
        || url.pathname !== '/v1/signing-keys/issuer-identities'
        || url.searchParams.get('organization_id') !== ORG_ID
        || request.method() !== 'PATCH' || payload?.organization_id !== ORG_ID
        || payload?.issuer_did !== issuerDid) {
      await route.abort();
      return;
    }
    forwarded = 1;
    await route.continue({ headers: { ...request.headers(), 'If-Match': revision } });
  };
  await page.route(identityRoute, bindOwnedRevision);
  try {
    const responsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      if (url.origin !== new URL(BETA_ORIGIN).origin
          || url.pathname !== '/v1/signing-keys/issuer-identities'
          || response.request().method() !== 'PATCH') return false;
      try {
        const payload = response.request().postDataJSON();
        return payload?.organization_id === ORG_ID && payload?.issuer_did === issuerDid;
      } catch {
        return false;
      }
    }, { timeout: 60_000 });
    const move = row.getByRole('button', { name: 'Move identity to default signing service' });
    if (recording) await recording.click(page, move, { action: 'change-signing-provider', phase: 'open' });
    else await move.click();
    const confirm = page.getByRole('dialog').getByRole('button', { name: 'Move identity' });
    if (recording) await recording.click(page, confirm, { action: 'change-signing-provider', phase: 'confirmation', durationMs: 3200 });
    else await confirm.click();
    const response = await responsePromise;
    if (forwarded !== 1) throw new Error('UI rebind was not bound to the owned config revision');
    const body = await response.json().catch(() => null);
    recording?.mark('change-signing-provider', 'response-received', { httpStatus: response.status(), changed: body?.changed === true });
    return {
      ok: response.ok(),
      status: response.status(),
      changed: body?.changed === true,
      identity: body?.identity || null,
      configRevision: body?.config_revision || null,
    };
  } finally {
    await page.unroute(identityRoute, bindOwnedRevision);
  }
}

function requireProviderStage(report, ...names) {
  const assertions = providerSwitchBehaviorAssertions(report);
  for (const name of names) {
    if (assertions[name] !== true) throw new Error(`Provider scenario did not establish ${name}`);
  }
}

async function directRebind(page, issuerDid, revision) {
  if (!STRONG_CONFIG_REVISION.test(revision || '')) {
    throw new Error('Direct issuer rebind requires an owned config revision');
  }
  const response = await browserJson(
    page,
    `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(ORG_ID)}`,
    { method: 'PATCH', body: JSON.stringify(identityRequest(issuerDid)),
      headers: { 'If-Match': revision } },
  );
  return { ok: response.ok, status: response.status,
    configRevision: response.body?.config_revision || null };
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
  const existingProviderB = existingProviderBInput();
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').toLowerCase();
  const artifactDir = createArtifactDir(ROOT, `beta-issuer-provider-switch-${stamp}`);
  const evidence = await createDemoLiveEvidence();
  try {
    const input = await prepareProviderInputs(artifactDir, stamp, evidence);
    const { issuerDid, providerBId, providerCId } = input;
    const report = {
      createdAt: new Date().toISOString(),
      organizationId: ORG_ID,
      issuerDid,
      sourceTemplateId: SOURCE_TEMPLATE_ID,
      custodyScope: existingProviderB
        ? 'Preprovisioned non-OpenBao service B; actual signing is checked during issuance, product provenance remains unverified.'
        : 'Two provider configurations and distinct keys on one beta OpenBao backend; not two independent KMS products.',
      independentKmsProductsProved: false,
      differentProviderRemoteSignerObserved: false,
      openBaoACExternalAuthentication: { mode: 'token', explicitCa: true, scopedFixtureKey: true },
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
    let lastOwnedConfigRevision;
    let configJournal;
    let createIdentityAttempted = false;
    let createIdentityConfirmed = false;
    let uiRebindAttempted = false;
    let uiRebindConfirmed = false;
    let negativeRebindAttempted = false;
    let negativeRebindDenied = false;
    try {
      context = await browser.newContext({
        viewport: VIDEO_SIZE,
        serviceWorkers: 'block', // The owned If-Match route must see the real UI PATCH.
        ignoreHTTPSErrors: LOCAL_BETA_PROXY,
        ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
      });
      const page = await context.newPage();
      evidence.bindPage(page);
      const video = page.video();
      const recording = createActionRecording({
        enabled: RECORD_VIDEO, scenario: 'stable-issuer-identity-pluggable-kms', pageName: 'admin',
        onEvent: (events) => { report.recordingActions = events; },
      });
      report.demonstrationBoundary = {
        data: 'SYNTHETIC_ISSUER', providerConfiguration: 'AUTHENTICATED_PUBLIC_API',
        identityRebind: 'REAL_ADMIN_UI', signatureVerification: 'MACHINE_EVIDENCE',
        unpublishedReplacementDenial: 'AUTHENTICATED_PUBLIC_API_NEGATIVE_TEST',
      };
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
      const originalSnapshot = await loadSigningConfig(page);
      originalConfig = originalSnapshot.config;
      lastOwnedConfigRevision = originalSnapshot.revision;
      configJournal = createConfigMutationJournal(artifactDir, originalConfig, lastOwnedConfigRevision);
      report.configJournal = path.relative(ROOT, configJournal.path);
      if (existingProviderB) {
        boundExistingProviderB(originalConfig, existingProviderB,
          managedTransitEndpoint(originalConfig));
      }
      report.protectedStateBefore = await protectedFixtureState(page);
      report.originalWritableConfigSha256 = stateHash(writableConfig(originalConfig));
      const transitEndpoint = managedTransitEndpoint(originalConfig);
      if (transitEndpoint !== externalTransit.endpoint) throw new Error('Beta backend differs from the provisioned fixture');
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
      if (!sourceTemplate.body.trust_profile_id) throw new Error('D-02 source template requires a Trust Profile before mutation');

      let templateId = null;
      let governance = null;
      let qualificationError = null;
      const createdIdentityDids = [];
      const createdManagedKeys = [];
      try {
        const managedSnapshot = await saveOwnedSigningConfig(page, writableConfig(originalConfig, {
          defaultServiceId: MANAGED_SERVICE_ID,
          resetDefaults: true,
        }), lastOwnedConfigRevision, configJournal, 'select-managed-provider');
        lastOwnedConfigRevision = managedSnapshot.revision;
        const managedConfig = managedSnapshot.config;
        report.providerAConfig = {
          defaultServiceId: managedConfig.default_service_id,
          serviceId: MANAGED_SERVICE_ID,
        };

        configJournal.intent('create-issuer-identity', lastOwnedConfigRevision, identityRequest(issuerDid));
        createIdentityAttempted = true;
        report.identityCreation = await createIdentity(page, issuerDid, `d02-identity-${input.stamp}`,
          lastOwnedConfigRevision);
        if (!report.identityCreation.ok) throw new Error(`Issuer identity creation failed (HTTP ${report.identityCreation.status})`);
        lastOwnedConfigRevision = ownedIdentityRevision(report.identityCreation);
        configJournal.confirmed('create-issuer-identity', lastOwnedConfigRevision);
        createIdentityConfirmed = true;
        if (report.identityCreation.created) {
          createdIdentityDids.push(issuerDid);
          createdManagedKeys.push(await signingKeyForIdentity(page, issuerDid));
        }

        const governanceRequest = governedIssuerRequest(sourceTemplate.body, issuerDid, input.stamp);
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

        report.template = await createTemplateVersion(page, issuerDid, input.stamp);
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
        requireProviderStage(report, 'create_issuer_profile');
        await showProviderStep(page, 'Stable issuer DID created', 'The public identity is active without exposing provider or key coordinates.');

        const providerA = await issueAndVerify(page, template);
        report.providerA = { issuance: providerA.issuance, credential: providerA.credential };
        requireProviderStage(report, 'issue_with_provider_a');
        await showProviderStep(page, 'Credential signed by provider A', 'The first credential verifies against the DID method published by managed custody.');

        const latestConfig = unchangedOwnedRevision(await loadSigningConfig(page), lastOwnedConfigRevision);
        const providerB = existingProviderB
          ? boundExistingProviderB(latestConfig, existingProviderB, transitEndpoint)
          : transitService(providerBId, `D-02 Provider B ${stamp}`, externalTransit.keyReference, transitEndpoint, externalTransit);
        const providerBSnapshot = await saveOwnedSigningConfig(page, writableConfig(latestConfig, {
          extraServices: existingProviderB ? [] : [providerB],
          defaultServiceId: providerB.id,
          resetDefaults: true,
        }), lastOwnedConfigRevision, configJournal, 'select-provider-b');
        lastOwnedConfigRevision = providerBSnapshot.revision;
        const providerBConfig = providerBSnapshot.config;
        report.providerBConfig = {
          defaultServiceId: providerBConfig.default_service_id,
          serviceId: providerB.id,
        };

        configJournal.intent('rebind-issuer-identity-ui', lastOwnedConfigRevision, identityRequest(issuerDid));
        uiRebindAttempted = true;
        report.rebind = await rebindThroughConsole(page, issuerDid, lastOwnedConfigRevision, recording);
        if (!report.rebind.ok || !report.rebind.changed) {
          throw new Error(`Provider switch failed (HTTP ${report.rebind.status})`);
        }
        lastOwnedConfigRevision = ownedIdentityRevision(report.rebind);
        configJournal.confirmed('rebind-issuer-identity-ui', lastOwnedConfigRevision);
        uiRebindConfirmed = true;
        await showProviderStep(page, 'Issuer identity updated', 'The service confirmed the provider change. Next, verify the new credential and the earlier credential.');

        const providerBResult = await issueAndVerify(page, template);
        report.providerBBinding = await verifySelectedIssuerBinding(page, issuerDid,
          providerB, providerBResult.issued);
        report.providerB = {
          issuance: providerBResult.issuance,
          credential: providerBResult.credential,
        };
        const oldReverification = await reverifyIssuedCredential(providerA.issued);
        report.providerA.reverifiedAfterSwitch = oldReverification.verified;
        report.didAfterSwitch = { assertionMethodIds: oldReverification.assertionMethodIds };
        requireProviderStage(report, 'switch_signing_provider', 'verify_same_did_identity');
        report.differentProviderRemoteSignerObserved = observedRemoteSigner(
          existingProviderB, providerBResult.issuance, providerBResult.credential,
          providerBConfig.default_service_id, providerB.id, report.providerBBinding,
        );
        await showProviderStep(page, 'One DID, both credentials valid', 'New issuance uses provider B while the provider-A credential remains verifiable through the retained DID method.');

        const beforeFailureConfig = unchangedOwnedRevision(await loadSigningConfig(page), lastOwnedConfigRevision);
        const unavailable = transitService(
          providerCId,
          `D-02 Unpublished Provider ${stamp}`,
          externalTransit.unavailableKey,
          transitEndpoint,
          externalTransit,
        );
        const unavailableSnapshot = await saveOwnedSigningConfig(page, writableConfig(beforeFailureConfig, {
          extraServices: [providerB, unavailable],
          defaultServiceId: providerCId,
          resetDefaults: true,
        }), lastOwnedConfigRevision, configJournal, 'select-unpublished-provider');
        lastOwnedConfigRevision = unavailableSnapshot.revision;
        configJournal.intent('deny-unpublished-rebind', lastOwnedConfigRevision, identityRequest(issuerDid));
        negativeRebindAttempted = true;
        const deniedRebind = await directRebind(page, issuerDid, lastOwnedConfigRevision);
        if (deniedRebind.status === 503) {
          unchangedOwnedRevision(await loadSigningConfig(page), lastOwnedConfigRevision);
          configJournal.rejected('deny-unpublished-rebind', 503);
          negativeRebindDenied = true;
        }
        const afterDenial = await issueAndVerify(page, template);
        report.unpublishedReplacement = {
          rebindOk: deniedRebind.ok,
          rebindStatus: deniedRebind.status,
          issueAfterDenial: afterDenial.issuance,
          credentialAfterDenial: afterDenial.credential,
        };
        requireProviderStage(report, 'unpublished_signing_key_denied');
        await showProviderStep(page, 'Unpublished replacement denied', 'An unavailable replacement key cannot cut over custody; issuance continues on the last published provider-B method.');

        report.behaviorAssertions = providerSwitchBehaviorAssertions(report);
      } catch (error) {
        qualificationError = error;
        report.error = redact(error.stack || error.message || String(error));
      } finally {
        report.partialDidPublicationPossible = (createIdentityAttempted && !createIdentityConfirmed)
          || (uiRebindAttempted && !uiRebindConfirmed)
          || (negativeRebindAttempted && !negativeRebindDenied);
        try {
          report.cleanup = await cleanup(page, templateId, createdIdentityDids, governance);
        } catch (error) {
          report.cleanupError = redact(error.stack || error.message || String(error));
        }
        if (originalConfig && configJournal?.healthy()) {
          try {
            const restoredSnapshot = await saveOwnedSigningConfig(page, writableConfig(originalConfig),
              lastOwnedConfigRevision, configJournal, 'restore-original-config');
            lastOwnedConfigRevision = restoredSnapshot.revision;
            const restored = restoredSnapshot.config;
            report.configRestored = {
              ...restoredConfigurationEvidence(originalConfig, restored, createdManagedKeys),
              defaultServiceId: restored.default_service_id,
            };
          } catch (error) {
            report.configRestoreError = redact(error.stack || error.message || String(error));
          }
        } else if (originalConfig) {
          report.configRestoreError = 'Signing config journal failed; restoration requires separate reconciliation';
        }
      }

      report.protectedStateAfter = await protectedFixtureState(page);
      report.protectedStateUnchanged = stateHash(report.protectedStateBefore) === stateHash(report.protectedStateAfter);
      const ownedCleanupComplete = Boolean(report.protectedStateUnchanged
        && !report.partialDidPublicationPossible
        && report.cleanup?.retiredTemplate
        && report.cleanup?.revokedCredentials >= 3
        && report.cleanup?.removedGovernanceRelationships === 1
        && report.cleanup?.removedGovernedIssuers === 1
        && createdIdentityDids.length === 1
        && report.cleanup?.retiredIdentities === createdIdentityDids.length
        && report.configRestored?.ok);
      report.releaseReady = Boolean(
        ownedCleanupComplete
        && !qualificationError
        && Object.values(report.behaviorAssertions || {}).every((passed) => passed === true)
        && report.loginTheme?.ok
        && report.pageErrors.length === 0
        && report.unexpectedResponses.length === 0
      );
      report.finishedAt = new Date().toISOString();
      await finalizeLiveRun({
        cleanup: async () => {}, // Owned feature cleanup and restoration completed above.
        closeBrowser: async () => {
          await context.close();
          context = null;
          if (RECORD_VIDEO) {
            report.recording = path.relative(
              ROOT,
              await finalizeVideo(video, artifactDir, 'stable-issuer-identity-pluggable-kms.webm'),
            );
          }
        },
        writeReport: async () => {
          applyLocalNativeReadiness(report, evidence, {ready:report.releaseReady,
            cleanupComplete:ownedCleanupComplete});
          fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
          console.log(JSON.stringify(report, null, 2));
        },
        complete: () => evidence.complete(),
        closeEvidence: () => evidence.close(),
        successful: () => report.releaseReady === true || report.functionalReady === true,
      });
      if (!report.releaseReady && !report.functionalReady) process.exitCode = 1;
    } finally {
      if (configJournal) configJournal.close();
      if (context) await context.close().catch(() => {});
      await browser.close();
    }
  } finally {
    await evidence.close();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
    process.exitCode = 1;
  });
}

module.exports = {
  createIdentity,
  directRebind,
  rebindThroughConsole,
  ownedIdentityRevision,
  createConfigMutationJournal,
  loadSigningConfig,
  saveSigningConfig,
  unchangedOwnedRevision,
  prepareProviderInputs,
  cleanup,
  externalTransitPrerequisites,
  existingProviderBInput,
  boundExistingProviderB,
  managedBindingHash,
  matchesManagedBinding,
  verifySelectedIssuerBinding,
  observedRemoteSigner,
  managedTransitEndpoint,
  restoredConfigurationEvidence,
  credentialEvidence,
  governedIssuerRequest,
  identityRequest,
  transitService,
  writableConfig,
};
