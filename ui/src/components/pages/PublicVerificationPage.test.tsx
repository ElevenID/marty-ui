import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';
import userEvent from '@testing-library/user-event';
import PublicVerificationPage from './PublicVerificationPage';

const revision = `sha256:${'a'.repeat(64)}`;
const id = '54cfd66e-b7ed-8926-9f8b-18e63fa83797';
const catalog = { revision, notice: 'I agree to present these fictional age claims.', scenarios: [{ id: 'age', label: 'Age requirement', choices: [{ id: 'over-18', label: '18 or older' }, { id: 'over-21', label: '21 or older' }] }], examples: [{ id: 'fictional-adult', scenario_id: 'age', label: 'Fictional adult, age 20', description: 'A fixed fictional age credential.' }] };
const session = () => { const now = Date.now(); return ({ session_id: id, scenario_id: 'age', choice_id: 'over-18', example_id: 'fictional-adult', catalog_revision: revision, status: 'awaiting_wallet', expires_at: new Date(now + 600_000).toISOString(), access_expires_at: new Date(now + 1_200_000).toISOString() }); };
function response(body: unknown) { return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }); }
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
    vi.stubGlobal('fetch', fetch);
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

  it('reconciles an uncertain launch with the same capability and does not create a session on reload', async () => {
    const current = session(); let attempts = 0;
    const fetch = vi.fn(async (url: string) => {
      if (String(url).endsWith('/catalog')) return response(catalog);
      if (String(url).endsWith('/sessions') && ++attempts === 1) throw new TypeError('connection lost');
      if (String(url).endsWith('/example')) return response({ ...current, example_status: 'input_rejected' });
      return response(current);
    });
    vi.stubGlobal('fetch', fetch); const user = userEvent.setup();
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
  });
  it('does not restore an old result after the visitor changes the recovered request', async () => {
    const current = session();
    sessionStorage.setItem('marty.public-verification.v1', JSON.stringify({ key: 'A'.repeat(43), id, savedAt: Date.now(), accessExpiresAt: Date.now() + 1_200_000, selection: { catalog_revision: revision, scenario_id: 'age', choice_id: 'over-18', example_id: 'fictional-adult', consent: true } }));
    let resolveRead!: (response: Response) => void;
    vi.stubGlobal('fetch', vi.fn((url: string) => String(url).endsWith('/catalog') ? Promise.resolve(response(catalog)) : new Promise<Response>(resolve => { resolveRead = resolve; })));
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

});
