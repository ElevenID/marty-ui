import { afterEach, describe, expect, it, vi } from 'vitest';
import { resolveApiBaseUrl, resolveApiUrl } from '../authApiOrigin';
import { getPreferences, updatePreferences } from '../preferencesApi';
import { getSystemHealth } from '../healthApi';
import { listAgentIdentities } from '../agentTrustApi';
import { getDomainMatches } from '../domainMatchingApi';
import sseService from '../sseService';
import { fetchDigitalCredentialRequest, submitDigitalCredentialResponse } from '../digitalCredentialsApi';

const api = 'https://api.example';
const org = 'c87326bc-7be2-4bf4-a3b6-70a36dac6394';
function transport(body: unknown) {
  const fetch = vi.fn().mockImplementation(async () => Response.json(body));
  vi.stubGlobal('fetch', fetch);
  return fetch;
}
afterEach(() => { sseService.disconnect(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

describe('static console API origin transport', () => {
  it('keeps relative deployment and canonical origin selection, refusing alternate path authorities', () => {
    expect(resolveApiUrl('/v1/me/preferences', '')).toBe('/v1/me/preferences');
    expect(resolveApiBaseUrl(api + '/')).toBe(api);
    for (const path of ['//attacker.example/v1/me', 'https://attacker.example/v1/me', '/\\attacker.example', '/v1/me\n']) {
      expect(() => resolveApiUrl(path, api)).toThrow();
    }
    for (const origin of ['http://api.example', api + '/prefix', api + '?x=1', 'https://u:p@api.example']) {
      expect(() => resolveApiUrl('/v1/me', origin)).toThrow();
    }
  });
  it('loads and updates own preferences through the API with cookies and unchanged payload mapping', async () => {
    vi.stubEnv('VITE_API_URL', api);
    const fetch = transport({ last_view_mode: 'org_admin', last_active_org_id: org });
    expect((await getPreferences()).last_view_mode).toBe('org');
    expect(fetch).toHaveBeenLastCalledWith(api + '/v1/me/preferences', expect.objectContaining({ credentials: 'include', cache: 'no-store' }));
    await updatePreferences({ last_view_mode: 'org', last_active_org_id: org });
    expect(fetch).toHaveBeenLastCalledWith(api + '/v1/me/preferences', expect.objectContaining({ method: 'PUT', credentials: 'include', body: JSON.stringify({ last_view_mode: 'org_admin', last_active_org_id: org }) }));
  });
  it('reads real readiness from the API rather than the Pages host', async () => {
    vi.stubEnv('VITE_API_URL', api);
    const fetch = transport({ status: 'ready', services: { gateway: 'healthy' } });
    expect((await getSystemHealth()).gateway).toBe('healthy');
    expect(fetch).toHaveBeenCalledWith(api + '/health/ready', expect.objectContaining({ method: 'GET', cache: 'no-store' }));
  });
  it('keeps agent session authority at the configured API without adding retries', async () => {
    vi.stubEnv('VITE_API_URL', api);
    const fetch = transport({ items: [], total: 0 });
    await listAgentIdentities(org);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][0]).toBe(api + `/v1/organizations/${org}/agents?limit=50&offset=0`);
    expect(fetch.mock.calls[0][1]).toMatchObject({ method: 'GET', credentials: 'include', redirect: 'error', cache: 'no-store' });
  });
  it('keeps the legacy onboarding path while selecting the configured API', async () => {
    vi.stubEnv('VITE_API_URL', api);
    const fetch = transport({ matches: [] });
    await getDomainMatches();
    expect(fetch).toHaveBeenCalledWith(api + '/api/onboarding/domain-matches', expect.objectContaining({ credentials: 'include' }));
  });
  it('includes API cookies for digital-credential calls while preserving external request credential mode', async () => {
    vi.stubEnv('VITE_API_URL', api);
    const fetch = vi.fn().mockImplementation(async () => new Response('synthetic-request-jwt'));
    await fetchDigitalCredentialRequest('/v1/flows/instances/flow-1/request.jwt', { fetchImpl: fetch });
    expect(fetch).toHaveBeenLastCalledWith(api + '/v1/flows/instances/flow-1/request.jwt', expect.objectContaining({ credentials: 'include' }));
    await fetchDigitalCredentialRequest('https://provider.example/request.jwt', { fetchImpl: fetch });
    expect(fetch).toHaveBeenLastCalledWith('https://provider.example/request.jwt', expect.objectContaining({ credentials: 'same-origin' }));
    fetch.mockImplementation(async () => Response.json({ verified: true }));
    await submitDigitalCredentialResponse({ submitUrl: '/v1/flows/instances/flow-1/submit/dc-api', credential: { data: {} }, fetchImpl: fetch });
    expect(fetch).toHaveBeenLastCalledWith(api + '/v1/flows/instances/flow-1/submit/dc-api', expect.objectContaining({ method: 'POST', credentials: 'include' }));
  });
  it('opens the notification stream at the API with credentialed EventSource transport', () => {
    vi.stubEnv('VITE_API_URL', api);
    const EventSource = vi.fn(function () { return { addEventListener: vi.fn(), close: vi.fn() }; });
    vi.stubGlobal('EventSource', EventSource);
    sseService.connect({ organizationId: org });
    expect(EventSource).toHaveBeenCalledWith(api + `/v1/notifications/events/push?organization_id=${org}`, { withCredentials: true });
  });
});
