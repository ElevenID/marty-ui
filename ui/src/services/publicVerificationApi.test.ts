import { afterEach, describe, expect, it, vi } from 'vitest';
import { createVerificationCapability, publicVerificationApi } from './publicVerificationApi';

const id = '54cfd66e-b7ed-8926-9f8b-18e63fa83797';
const revision = `sha256:${'a'.repeat(64)}`;
const key = 'A'.repeat(43);
const selection = { catalog_revision: revision, scenario_id: 'age', choice_id: 'over-18', consent: true };
const session = { session_id: id, scenario_id: 'age', choice_id: 'over-18', catalog_revision: revision,
  status: 'awaiting_wallet', expires_at: '2026-11-04T22:00:00Z', access_expires_at: '2026-11-04T22:10:00Z',
  wallet_uri: `openid4vp://authorize?client_id=demo&request_uri=${encodeURIComponent(`https://api.example/v1/flows/instances/${id}/request`)}` };

afterEach(() => vi.unstubAllGlobals());

function respond(body: unknown) {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }));
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

describe('public verification transport', () => {
  it('uses the real shared client without cookie authority and keeps the capability out of URLs and bodies', async () => {
    const fetch = respond(session);
    const result = await publicVerificationApi.launch({ ...selection, organization_id: 'injected' }, key, { credentials: 'include' });
    expect(result.status).toBe('awaiting_wallet');
    expect(fetch).toHaveBeenCalledOnce();
    const [url, options] = fetch.mock.calls[0];
    expect(String(url)).toContain('/v1/flows/public/verification/sessions');
    expect(String(url)).not.toContain(key);
    expect(options.credentials).toBe('omit');
    expect(options.cache).toBe('no-store');
    expect(options.referrerPolicy).toBe('no-referrer');
    expect(new Headers(options.headers).get('x-verification-session')).toBe(key);
    expect(JSON.parse(options.body)).toEqual(selection);
  });

  it('generates random 256-bit capabilities and uses only the own-session paths', async () => {
    expect(createVerificationCapability()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(createVerificationCapability()).not.toBe(createVerificationCapability());
    const fetch = respond(session);
    await publicVerificationApi.session(id, key);
    expect(String(fetch.mock.calls[0][0])).toContain(`/sessions/${id}`);
    await expect(publicVerificationApi.session('../definitions', key)).rejects.toThrow();
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('rejects missing verdicts, unsafe wallet links, and inconsistent lifetimes', async () => {
    for (const change of [
      { status: 'completed', wallet_uri: undefined },
      { wallet_uri: 'javascript:alert(1)' },
      { wallet_uri: 'openid4vp://authorize?request_uri=http://untrusted.example/request' },
      { access_expires_at: '2026-11-05T22:00:00Z' },
      { verified: true },
      { choice_id: undefined },
      { session_id: '54cfd66e-b7ed-8926-9f8b-18e63fa83798' },
    ]) {
      respond({ ...session, ...change });
      await expect(publicVerificationApi.session(id, key)).rejects.toMatchObject({ code: 'verification_response_invalid' });
    }
  });

  it('projects only public catalog/session fields and never passes through holder claims', async () => {
    respond({ ...session, status: 'completed', wallet_uri: undefined, verified: true, verified_claims: { name: 'private' }, context: { secret: 'private' } });
    const value = await publicVerificationApi.session(id, key);
    expect(value.verified).toBe(true);
    expect(JSON.stringify(value)).not.toContain('private');
    respond({ revision, notice: 'Review the request', organization_id: 'private-org', scenarios: [{ id: 'age', label: 'Age', choices: [{ id: 'over-18', label: '18 or older', presentation_policy_id: 'private-policy' }] }] });
    expect(JSON.stringify(await publicVerificationApi.catalog())).not.toContain('private');
  });

  it('does not accept a result for a different request or a pending cancellation', async () => {
    respond({ ...session, choice_id: 'over-21' });
    await expect(publicVerificationApi.launch(selection, key)).rejects.toMatchObject({ code: 'verification_response_invalid' });
    respond(session);
    await expect(publicVerificationApi.cancel(id, key)).rejects.toMatchObject({ code: 'verification_response_invalid' });
    respond({ ...session, wallet_uri: undefined, status: 'cancelled' });
    expect((await publicVerificationApi.cancel(id, key)).status).toBe('cancelled');
  });
  it('binds the specimen to launch and keeps signed fixture material out of catalog responses', async () => {
    respond({ ...session, wallet_uri: undefined, example_id: 'fictional-adult', example_status: 'running' });
    const value = await publicVerificationApi.launch({ ...selection, example_id: 'fictional-adult' }, key);
    expect(value.example_id).toBe('fictional-adult');
    const fetch = respond({ ...session, wallet_uri: undefined, example_id: 'fictional-adult', example_status: 'input_rejected' });
    expect((await publicVerificationApi.example(id, key)).example_status).toBe('input_rejected');
    expect(String(fetch.mock.calls[0][0])).toContain(`/sessions/${id}/example`);
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({});
    respond({ ...session, wallet_uri: undefined, example_id: 'different-specimen' });
    await expect(publicVerificationApi.launch({ ...selection, example_id: 'fictional-adult' }, key)).rejects.toThrow();
    respond({ revision, notice: 'Fictional examples only', scenarios: [{ id: 'age', label: 'Age', choices: [{ id: 'over-18', label: '18 or older' }] }], examples: [{ id: 'adult', scenario_id: 'age', label: 'Fictional adult', description: 'Fixed signed age claims', credential: 'private.signed.bytes', profile: { issuer_did: 'private-issuer' } }] });
    expect(JSON.stringify(await publicVerificationApi.catalog())).not.toContain('private');
  });

});
