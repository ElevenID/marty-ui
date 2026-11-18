import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { getRuntimeStatus } from '../dashboardApi';

const nativeStatus = {
  can_issue: true,
  can_verify: true,
  issuer_keys_valid: true,
  issuer_active: true,
  deployment_active: true,
  policy_reachable: true,
  last_issuance_timestamp: null,
  last_verification_timestamp: null,
};

function respond(payload: Record<string, unknown>) {
  server.use(http.get('*/v1/organizations/org_live/runtime/status', () => HttpResponse.json(payload)));
}

describe('getRuntimeStatus payload validation', () => {
  it.each([true, false])('preserves native boolean readiness values (%s)', async (ready) => {
    respond({
      can_issue: ready,
      can_verify: ready,
      issuer_keys_valid: ready,
      issuer_active: ready,
      deployment_active: ready,
      policy_reachable: ready,
      last_issuance_timestamp: null,
      last_verification_timestamp: null,
    });

    await expect(getRuntimeStatus('org_live')).resolves.toEqual({
      canIssue: ready,
      canVerify: ready,
      issuerKeysValid: ready,
      issuerActive: ready,
      deploymentActive: ready,
      policyReachable: ready,
      lastIssuance: null,
      lastVerification: null,
    });
  });

  it.each([
    ['can_issue', 'false'],
    ['can_verify', null],
    ['issuer_keys_valid', 0],
    ['issuer_active', {}],
    ['deployment_active', []],
    ['policy_reachable', 1],
  ])('rejects malformed %s rather than coercing it into a readiness decision', async (field, value) => {
    respond({ ...nativeStatus, [field as string]: value });

    await expect(getRuntimeStatus('org_live')).rejects.toMatchObject({
      code: 'DASHBOARD_PAYLOAD_INVALID',
      status: 502,
      message: `Runtime status returned invalid boolean fields: ${field}.`,
    });
  });

  it.each([
    'can_issue', 'can_verify', 'issuer_keys_valid', 'issuer_active', 'deployment_active', 'policy_reachable',
  ])('rejects missing %s instead of manufacturing a false readiness flag', async (field) => {
    const incompleteStatus: Record<string, unknown> = { ...nativeStatus };
    delete incompleteStatus[field];
    respond(incompleteStatus);

    await expect(getRuntimeStatus('org_live')).rejects.toMatchObject({
      code: 'DASHBOARD_PAYLOAD_INCOMPLETE',
      status: 502,
      message: `Runtime status returned an incomplete response. Missing fields: ${field}.`,
    });
  });
});
