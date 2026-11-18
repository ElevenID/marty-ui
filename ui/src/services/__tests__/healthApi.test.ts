import { afterEach, describe, expect, it, vi } from 'vitest';
import { getSystemHealth } from '../healthApi';

const unknownServices = { issuer: 'unknown', verifier: 'unknown' };

function respond(body: unknown, status = 200) {
  const fetch = vi.fn().mockResolvedValue(Response.json(body, { status }));
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

afterEach(() => vi.unstubAllGlobals());

describe('getSystemHealth', () => {
  it('reads the native readiness contract and leaves unreported verification unknown', async () => {
    const fetch = respond({
      status: 'ready',
      service: 'api-gateway',
      services: {
        auth: { status: 'healthy', status_code: 200 },
        'issuance-native': { status: 'healthy', status_code: 200 },
      },
    });
    const signal = new AbortController().signal;

    await expect(getSystemHealth({ signal })).resolves.toEqual({ gateway: 'healthy', issuer: 'healthy', verifier: 'unknown' });
    expect(fetch).toHaveBeenCalledWith('/health/ready', expect.objectContaining({
      method: 'GET', cache: 'no-store', signal,
    }));
  });

  it('preserves individual service observations from a native 503 response', async () => {
    respond({
      status: 'not_ready',
      service: 'api-gateway',
      services: {
        issuance: { status: 'healthy', status_code: 200 },
        verification: { status: 'unreachable' },
      },
    }, 503);

    await expect(getSystemHealth()).resolves.toEqual({ gateway: 'error', issuer: 'healthy', verifier: 'error' });
  });

  it('does not infer downstream health from gateway liveness or unrelated metadata checks', async () => {
    respond({ status: 'healthy', service: 'api-gateway', services: { issuer_metadata: { status: 'healthy' } } });
    await expect(getSystemHealth()).resolves.toEqual({ gateway: 'healthy', ...unknownServices });
  });

  it('keeps missing or unconfigured services unknown even when the gateway is ready', async () => {
    respond({
      status: 'ready',
      services: {
        'issuance-native': { status: 'missing', url: null },
        verification: { status: 'not_configured' },
      },
    });
    await expect(getSystemHealth()).resolves.toEqual({ gateway: 'healthy', ...unknownServices });
  });

  it('uses explicit healthy or degraded observations when both services are reported', async () => {
    respond({ status: 'degraded', services: { issuance: 'warning', verification: { status: 'healthy' } } });
    await expect(getSystemHealth()).resolves.toEqual({ gateway: 'warning', issuer: 'warning', verifier: 'healthy' });
  });

  it.each([null, [], 'healthy', { unrelated: true }, { services: ['healthy'] }])(
    'does not manufacture health from malformed successful responses', async (payload) => {
      respond(payload);
      await expect(getSystemHealth()).resolves.toEqual({ gateway: 'unknown', ...unknownServices });
    },
  );

  it('reports a failed request without retaining or inventing downstream health', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network unavailable')));
    await expect(getSystemHealth()).resolves.toEqual({ gateway: 'error', ...unknownServices });
  });

  it('handles a non-JSON gateway error response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('upstream unavailable', { status: 502 })));
    await expect(getSystemHealth()).resolves.toEqual({ gateway: 'error', ...unknownServices });
  });
});
