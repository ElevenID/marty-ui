import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';
import userEvent from '@testing-library/user-event';
import PublicVerificationPage from './PublicVerificationPage';

const revision = `sha256:${'a'.repeat(64)}`;
const id = '54cfd66e-b7ed-8926-9f8b-18e63fa83797';
const catalog = { revision, retention_policy: { result_access_seconds: 600, receipt_days: 30 }, notice: 'I agree to present these fictional age claims.', scenarios: [{ id: 'age', label: 'Age requirement', choices: [{ id: 'over-18', label: '18 or older' }, { id: 'over-21', label: '21 or older' }] }], examples: [{ id: 'fictional-adult', scenario_id: 'age', label: 'Fictional adult, age 20', description: 'A fixed fictional age credential.' }] };
const session = () => { const now = Date.now(); return ({ session_id: id, scenario_id: 'age', choice_id: 'over-18', example_id: 'fictional-adult', catalog_revision: revision, status: 'awaiting_wallet', expires_at: new Date(now + 600_000).toISOString(), access_expires_at: new Date(now + 1_200_000).toISOString() }); };
function response(body: unknown) { return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }); }
function installFetch(fetch: ReturnType<typeof vi.fn>) {
  vi.stubGlobal('fetch', (url: string, options: RequestInit = {}) => {
    if (String(url).endsWith('/preview')) { const selected = JSON.parse(String(options.body)); return Promise.resolve(response({ ...selected, request_digest: 'sha256:' + 'a'.repeat(64), claims: [{ name: selected.choice_id === 'over-21' ? 'age_over_21' : 'age_over_18', display_name: 'Age threshold', required: true, purpose: 'Demonstrate an age requirement', intent_to_retain: null, constraints: [{ kind: 'equals', value: true }] }] })); }
    return fetch(url, options);
  });
}
beforeEach(() => sessionStorage.clear());
afterEach(() => { vi.unstubAllGlobals(); sessionStorage.clear(); });

describe('public verification experience', () => {
  it('shows the example first, starts only after consent, and uses the real public transport', async () => {
    const current = session();
    const fetch = vi.fn(async (url: string, options: RequestInit = {}) => {
      if (String(url).endsWith('/catalog')) return response(catalog);
      if (String(url).endsWith('/example')) return response({ ...current, wallet_uri: undefined, status: 'completed', verified: true });
      expect(JSON.parse(String(options.body))).toMatchObject({ example_id: 'fictional-adult', choice_id: 'over-18', consent: true });
      expect(options.credentials).toBe('omit');
      return response(current);
    });
    installFetch(fetch);
    const user = userEvent.setup(); render(<PublicVerificationPage />);
    const run = await screen.findByRole('button', { name: 'Verify example' });
    expect(run).toBeDisabled(); expect(fetch).toHaveBeenCalledOnce();
    expect(screen.queryByRole('link', { name: 'Open compatible wallet' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('checkbox'));
    await user.click(run);
    expect(await screen.findByText('Verified', { exact: true })).toBeInTheDocument();
    expect(screen.getByText(/establishes no fact about you/)).toBeInTheDocument();
    const posts = fetch.mock.calls.filter(([, opts]) => opts?.method === 'POST');
    expect(posts).toHaveLength(2);
    expect(new Headers(posts[0][1].headers).get('x-verification-session')).toBe(new Headers(posts[1][1].headers).get('x-verification-session'));
    await user.click(screen.getByRole('button', { name: 'Customize the request' }));
    await user.click(screen.getByRole('combobox', { name: 'Requirement' }));
    await user.click(screen.getByRole('option', { name: '21 or older' }));
    expect(screen.queryByText('Verified', { exact: true })).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox')).not.toBeChecked();
    expect(sessionStorage.getItem('marty.public-verification.v1')).toBeNull();
  });

  it('keeps the same capability through uncertain launch, reload, and cancellation retry', async () => {
    const current = session(); let attempts = 0; let cancelAttempts = 0;
    const fetch = vi.fn(async (url: string) => {
      if (String(url).endsWith('/catalog')) return response(catalog);
      if (String(url).endsWith('/sessions') && ++attempts === 1) throw new TypeError('connection lost');
      if (String(url).endsWith('/example')) return response({ ...current, example_status: 'input_rejected' });
      if (String(url).endsWith('/cancel')) {
        if (++cancelAttempts === 1) throw new TypeError('connection lost');
        return response({ ...current, status: 'cancelled' });
      }
      // Polling cannot independently clear the failed cancellation warning.
      if (String(url).endsWith(`/sessions/${id}`)) throw new TypeError('connection lost');
      return response(current);
    });
    installFetch(fetch); const user = userEvent.setup();
    const first = render(<PublicVerificationPage />);
    await screen.findByRole('button', { name: 'Verify example' });
    await user.click(screen.getByRole('checkbox')); await user.click(screen.getByRole('button', { name: 'Verify example' }));
    await screen.findByText(/could not confirm the result/);
    const saved = JSON.parse(sessionStorage.getItem('marty.public-verification.v1')!);
    expect(saved.id).toBeUndefined(); first.unmount();
    const count = fetch.mock.calls.length;
    render(<PublicVerificationPage />); await screen.findByRole('button', { name: 'Resume verification' });
    await waitFor(() => expect(fetch.mock.calls.length).toBe(count + 1));
    await user.click(screen.getByRole('button', { name: 'Resume verification' }));
    expect(await screen.findByText('Example input rejected')).toBeInTheDocument();
    expect(screen.queryByText('Not verified', { exact: true })).not.toBeInTheDocument();
    const launches = fetch.mock.calls.filter(([url]) => String(url).endsWith('/sessions'));
    expect(launches).toHaveLength(2);
    expect(new Headers((launches[0] as any)[1].headers).get('x-verification-session')).toBe(saved.key);
    expect(new Headers((launches[1] as any)[1].headers).get('x-verification-session')).toBe(saved.key);
    await user.click(screen.getByRole('button', { name: 'Cancel', exact: true }));
    expect(await screen.findByText(/could not confirm the result/)).toBeInTheDocument();
    expect(screen.queryByText('Verification cancelled', { exact: true })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Cancel', exact: true }));
    expect(await screen.findByText('Verification cancelled', { exact: true })).toBeInTheDocument();
    expect(screen.queryByText(/could not confirm the result/)).not.toBeInTheDocument();
    const cancellations = fetch.mock.calls.filter(([url]) => String(url).endsWith('/cancel'));
    expect(cancellations).toHaveLength(2);
    for (const request of cancellations) {
      expect(new Headers((request as any)[1].headers).get('x-verification-session')).toBe(saved.key);
    }
    expect(JSON.parse(sessionStorage.getItem('marty.public-verification.v1')!)).toMatchObject({ key: saved.key, id });
  });
  it('does not restore an old result after the visitor changes the recovered request', async () => {
    const current = session();
    sessionStorage.setItem('marty.public-verification.v1', JSON.stringify({ key: 'A'.repeat(43), id, savedAt: Date.now(), accessExpiresAt: Date.now() + 1_200_000, selection: { catalog_revision: revision, scenario_id: 'age', choice_id: 'over-18', example_id: 'fictional-adult', consent: true } }));
    let resolveRead!: (response: Response) => void;
    installFetch(vi.fn((url: string) => String(url).endsWith('/catalog') ? Promise.resolve(response(catalog)) : new Promise<Response>(resolve => { resolveRead = resolve; })));
    const user = userEvent.setup(); render(<PublicVerificationPage />);
    await screen.findByRole('button', { name: 'Resume verification' });
    await waitFor(() => expect(resolveRead).toBeTypeOf('function'));
    await user.click(screen.getByRole('button', { name: 'Customize the request' }));
    await user.click(screen.getByRole('combobox', { name: 'Requirement' }));
    await user.click(screen.getByRole('option', { name: '21 or older' }));
    resolveRead(response({ ...current, status: 'completed', verified: true }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Verify example' })).toBeDisabled());
    expect(screen.queryByText('Verified', { exact: true })).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox')).not.toBeChecked();
  });

  it('does not accept consent or launch when the canonical preview is unavailable', async () => {
    const fetch = vi.fn(async (url: string) => response(String(url).endsWith('/catalog') ? catalog : {}));
    vi.stubGlobal('fetch', fetch); render(<PublicVerificationPage />);
    await screen.findByText(/exact request could not be loaded/);
    expect(screen.getByRole('checkbox')).toBeDisabled();
    expect(screen.getByRole('button',{name:'Verify example'})).toBeDisabled();
    expect(fetch.mock.calls.some(([url])=>String(url).endsWith('/sessions'))).toBe(false);
  });

  it('removes an expired recovery capability before offering a fresh demonstration', async () => {
    sessionStorage.setItem('marty.public-verification.v1',JSON.stringify({key:'A'.repeat(43),id,savedAt:Date.now()-1_300_000,accessExpiresAt:Date.now()-1,selection:{catalog_revision:revision,scenario_id:'age',choice_id:'over-18',consent:true}}));
    const fetch=vi.fn(async()=>response(catalog));installFetch(fetch);
    render(<PublicVerificationPage />);await screen.findByRole('button',{name:'Verify example'});
    expect(sessionStorage.getItem('marty.public-verification.v1')).toBeNull();
    expect(screen.queryByRole('button',{name:'Resume verification'})).not.toBeInTheDocument();
  });

  it.each([
    {
      name: 'the exact unavailable catalog response',
      reply: () => new Response(JSON.stringify({ error: 'public_verification_unavailable', error_description: 'Private upstream diagnostic', message_id: id }), { status: 404, headers: { 'content-type': 'application/json' } }),
      severity: 'Info',
      message: 'This verification demonstration is not available on this site.',
      attempts: 1,
    },
    {
      name: 'a different not-found error',
      reply: () => new Response(JSON.stringify({ error: 'not_found', error_description: 'Private upstream diagnostic' }), { status: 404, headers: { 'content-type': 'application/json' } }),
      severity: 'Warning',
      message: 'We couldn’t load the verification demonstration. Try again.',
      attempts: 1,
    },
    {
      name: 'an HTML not-found response',
      reply: () => new Response('<html>Private upstream diagnostic</html>', { status: 404, headers: { 'content-type': 'text/html' } }),
      severity: 'Warning',
      message: 'We couldn’t load the verification demonstration. Try again.',
      attempts: 1,
    },
    {
      name: 'an unavailable code with a service-failure status',
      reply: () => new Response(JSON.stringify({ error: 'public_verification_unavailable', error_description: 'Private upstream diagnostic' }), { status: 503, headers: { 'content-type': 'application/json' } }),
      severity: 'Warning',
      message: 'We couldn’t load the verification demonstration. Try again.',
      attempts: 4,
    },
    {
      name: 'a failed network request',
      reply: () => { throw new TypeError('Private upstream diagnostic'); },
      severity: 'Warning',
      message: 'We couldn’t load the verification demonstration. Try again.',
      attempts: 4,
    },
  ])('distinguishes $name without starting a session or losing recovery', async ({ reply, severity, message, attempts }) => {
    const saved = JSON.stringify({
      key: 'A'.repeat(43), id, savedAt: Date.now(), accessExpiresAt: Date.now() + 1_200_000,
      selection: { catalog_revision: revision, scenario_id: 'age', choice_id: 'over-18', example_id: 'fictional-adult', consent: true },
    }, null, 2);
    sessionStorage.setItem('marty.public-verification.v1', saved);
    const fetch = vi.fn(async (url: string, options: RequestInit = {}) => {
      const request = new URL(String(url), window.location.origin);
      if (request.pathname !== '/v1/flows/public/verification/catalog' || request.search || options.method !== 'GET') {
        throw new Error('Unexpected public verification request');
      }
      return reply();
    });
    vi.stubGlobal('fetch', fetch);
    render(<PublicVerificationPage />);

    // Keep the real SDK's bounded GET retries; no request reaches a network transport.
    expect(await screen.findByRole('button', { name: 'Try again' }, { timeout: 15_000 })).toBeEnabled();
    expect(screen.getByRole('alert')).toHaveTextContent(message);
    expect(screen.getByRole('alert')).toHaveClass(`MuiAlert-color${severity}`);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(screen.queryByText(/Private upstream diagnostic/)).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Verify example|Create wallet request|Resume verification|Cancel/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Open compatible wallet' })).not.toBeInTheDocument();
    expect(screen.queryByTitle('Wallet verification request')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Verification result' })).not.toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(attempts);
    for (const [url, options = {}] of fetch.mock.calls) {
      expect(new URL(String(url), window.location.origin).pathname).toBe('/v1/flows/public/verification/catalog');
      expect(options.method).toBe('GET');
      expect(options.credentials).toBe('omit');
      expect(options.body).toBeUndefined();
      expect(new Headers(options.headers).has('x-verification-session')).toBe(false);
    }
    expect(sessionStorage.getItem('marty.public-verification.v1')).toBe(saved);
  });

});
