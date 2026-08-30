import { chmod, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { createGatewayClient, normalizeGatewayOrigin } from '../src/gateway.mjs';

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function expectOk(label, promise) {
  const result = await promise;
  if (!result.ok) throw new Error(`${label} failed with HTTP ${result.status}: ${result.payload?.detail || 'unknown error'}`);
  return result.payload;
}

const gatewayOrigin = normalizeGatewayOrigin(required('MARTY_PUBLIC_GATEWAY_ORIGIN'));
const organizationId = required('NORTHSTAR_ORGANIZATION_ID');
const adminCookie = required('NORTHSTAR_ADMIN_SESSION_COOKIE');
const applicantCookie = required('NORTHSTAR_APPLICANT_SESSION_COOKIE');
const callbackUrl = required('NORTHSTAR_CALLBACK_URL');
const applicationInput = JSON.parse(await readFile(resolve(required('NORTHSTAR_APPLICATION_REQUEST_FILE')), 'utf8'));
const outputPath = resolve(required('NORTHSTAR_SECRET_OUTPUT_FILE'));
const origins = [];
const gateway = createGatewayClient({ origin: gatewayOrigin, observe: (entry) => origins.push(entry) });

const bootstrap = await expectOk('bootstrap API key creation', gateway(
  `/v1/api-keys?organization_id=${encodeURIComponent(organizationId)}`,
  {
    method: 'POST', sessionCookie: adminCookie, organizationId,
    body: { name: 'Northstar webhook bootstrap', scopes: ['webhooks:read', 'webhooks:write'] },
  },
));

let bootstrapRevoked = false;
try {
  const webhook = await expectOk('webhook creation', gateway('/v1/webhooks', {
    method: 'POST', apiKey: bootstrap.key, organizationId,
    body: {
      organization_id: organizationId,
      name: 'Northstar admissions callback',
      url: callbackUrl,
      event_types: ['application.approved'],
      enabled: true,
    },
  }));
  const subscription = await expectOk('subscription creation', gateway('/v1/subscriptions', {
    method: 'POST', apiKey: bootstrap.key, organizationId,
    body: {
      organization_id: organizationId,
      name: 'Northstar application approvals',
      description: 'Gateway-only D-11 subscription',
      event_types: ['application.approved'],
      delivery_channel: 'WEBHOOK',
      delivery_target_id: webhook.id,
      filter: { aggregate_types: ['application'], required_data_keys: ['application_id'] },
      retry_policy: { max_attempts: 3, initial_backoff_seconds: 1, max_backoff_seconds: 30 },
      enabled: true,
    },
  }));
  const application = await expectOk('application creation', gateway('/v1/me/applications', {
    method: 'POST', sessionCookie: applicantCookie, body: applicationInput,
  }));
  const submitted = await expectOk('application submission', gateway(
    `/v1/me/applications/${encodeURIComponent(application.id)}/submit`,
    { method: 'POST', sessionCookie: applicantCookie, body: {} },
  ));
  const runtime = await expectOk('runtime API key creation', gateway(
    `/v1/api-keys?organization_id=${encodeURIComponent(organizationId)}`,
    {
      method: 'POST', sessionCookie: adminCookie, organizationId,
      body: { name: 'Northstar admissions runtime', scopes: ['applications:read', 'applications:approve'] },
    },
  ));
  const readOnly = await expectOk('read-only API key creation', gateway(
    `/v1/api-keys?organization_id=${encodeURIComponent(organizationId)}`,
    {
      method: 'POST', sessionCookie: adminCookie, organizationId,
      body: { name: 'Northstar admissions read only', scopes: ['applications:read'] },
    },
  ));
  const evidence = await expectOk('delivery evidence API key creation', gateway(
    `/v1/api-keys?organization_id=${encodeURIComponent(organizationId)}`,
    {
      method: 'POST', sessionCookie: adminCookie, organizationId,
      body: { name: 'Northstar delivery evidence', scopes: ['webhooks:read'] },
    },
  ));
  await writeFile(outputPath, JSON.stringify({
    gateway_origin: gatewayOrigin,
    organization_id: organizationId,
    application_id: submitted.id || application.id,
    webhook_id: webhook.id,
    subscription_id: subscription.id,
    runtime_api_key: runtime.key,
    runtime_key_prefix: runtime.key_prefix,
    read_only_api_key: readOnly.key,
    evidence_api_key: evidence.key,
    webhook_signing_secret: webhook.signing_secret,
    callback_url: callbackUrl,
    outbound_origins: [...new Set(origins.map(({ origin }) => origin))],
    outbound_requests: origins,
  }, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  await chmod(outputPath, 0o600);
} finally {
  await expectOk('bootstrap API key revocation', gateway(
    `/v1/api-keys/${encodeURIComponent(bootstrap.id)}?organization_id=${encodeURIComponent(organizationId)}`,
    { method: 'DELETE', sessionCookie: adminCookie, organizationId },
  ));
  bootstrapRevoked = true;
}

if (!bootstrapRevoked) throw new Error('Bootstrap API key was not revoked');
process.stdout.write(`Northstar run prepared through ${gatewayOrigin}; secrets written to the protected output file.\n`);
