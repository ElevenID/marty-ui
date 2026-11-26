import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import AgentDirectoryPage from './AgentDirectoryPage';
import DelegationApprovalPage from './DelegationApprovalPage';

const state = vi.hoisted(() => ({
  org: '062b3b4d-f6a4-47b2-8f14-997ce22dcd8d',
  user: 'e6a1e7f9-064f-4bd8-a0a7-947a22106b56',
  permissions: new Set<string>(), loading: false, error: null as unknown,
}));
const api = vi.hoisted(() => ({
  listAgentIdentities: vi.fn(), registerAgentIdentity: vi.fn(), updateAgentIdentity: vi.fn(),
  changeAgentIdentity: vi.fn(), listAgentHistory: vi.fn(), reviewDelegation: vi.fn(),
  confirmDelegation: vi.fn(), withdrawDelegation: vi.fn(), refresh: vi.fn(),
}));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: state.user } }) }));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: state.org }) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({
  can: (resource: string, action: string) => state.permissions.has(`${resource}:${action}`),
  isLoading: state.loading, error: state.error, refresh: api.refresh,
}) }));
vi.mock('../../../services/agentTrustApi', async original => ({
  ...await original<typeof import('../../../services/agentTrustApi')>(), ...api,
}));

const originalOrg = state.org;
const grantId = 'b3230587-aea7-41a3-bd77-00bf3b788f62';
const grant = { id: grantId, revision: 1, terms_digest: `sha256:${'a'.repeat(64)}` };
const review = () => ({
  review_id: '73290672-f6a4-49e3-9d71-ce664ee0d11b', grant,
  issuer: { type: 'ORGANIZATION', id: `urn:marty:organization:${state.org}` },
  expires_at: new Date(Date.now() + 120000).toISOString(), confirmation_max_age_seconds: 300,
  terms: {
    grantor: { type: 'USER', id: `urn:marty:user:${state.user}` },
    subject: { type: 'ORGANIZATION', id: `urn:marty:organization:${state.org}` },
    delegate: { type: 'EXTERNAL', id: 'urn:example:inventory-agent' },
    binding: { method: 'KEY', key_thumbprint: `sha256:${'b'.repeat(64)}` },
    actions: ['urn:example:inventory:read'], audiences: ['urn:example:warehouse'], resources: ['urn:example:inventory:item'],
    valid_from: new Date().toISOString(), valid_until: new Date(Date.now() + 300000).toISOString(), subdelegation_allowed: false,
    constraints: { mode: 'EXACT_OPERATION', request_profile: 'urn:example:inventory-read:v1', request_digest: `sha256:${'c'.repeat(64)}` },
  },
});
const identity = () => ({
  id: '6679117b-cd01-490d-8ca2-dd57b89b3ed2', organization_id: state.org, owner_user_id: state.user,
  kind: 'EXTERNAL', status: 'ACTIVE', revision: 1,
  metadata: { display_name: 'Warehouse reader', logical_application_ref: 'urn:example:inventory', description: '' },
  principal: { type: 'EXTERNAL', id: 'urn:example:inventory-agent' }, keys: [],
});
function App() { return <Routes>
  <Route path="/console/org/agents" element={<AgentDirectoryPage />} />
  <Route path="/console/org/delegation-grants/:grantId/approve" element={<DelegationApprovalPage />} />
</Routes>; }
const approvalPath = `/console/org/delegation-grants/${grantId}/approve?revision=1&terms_digest=${grant.terms_digest}`;

describe('optional agent administration and explicit approval', () => {
  beforeEach(() => {
    Object.values(api).forEach(mock => mock.mockReset());
    state.org = originalOrg; state.loading = false; state.error = null;
    state.permissions = new Set(['agent-identity:view', 'agent-identity:create', 'agent-identity:suspend', 'delegation-grant:view', 'delegation-grant:approve']);
    window.sessionStorage.clear();
    vi.stubEnv('VITE_AGENT_ADMIN_ENABLED', 'true'); vi.stubEnv('VITE_DELEGATION_APPROVAL_ENABLED', 'true');
    api.listAgentIdentities.mockResolvedValue({ items: [identity()], total: 1 });
    api.reviewDelegation.mockImplementation(async () => review());
    api.confirmDelegation.mockImplementation(async (_org, source, id) => ({
      confirmation_id: id, review_id: source.review_id, grant_id: grantId, terms_digest: grant.terms_digest,
      confirmed_at: new Date().toISOString(), valid_until: new Date(Date.now() + 300000).toISOString(), recovered: false,
    }));
  });
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

  it('does not load protected inventory when disabled or permission checks fail', () => {
    vi.stubEnv('VITE_AGENT_ADMIN_ENABLED', 'false');
    const { rerender } = renderWithRouter(<App />, { initialEntries: ['/console/org/agents'] });
    expect(screen.getByText(/not enabled in this application/)).toBeInTheDocument();
    expect(api.listAgentIdentities).not.toHaveBeenCalled();
    vi.stubEnv('VITE_AGENT_ADMIN_ENABLED', 'true'); state.error = new Error('Unavailable'); rerender(<App />);
    expect(screen.getByText('Agent identity permissions could not be checked.')).toBeInTheDocument();
    expect(api.listAgentIdentities).not.toHaveBeenCalled();
  });
  it('separates access eligibility from runtime activity', async () => {
    renderWithRouter(<App />, { initialEntries: ['/console/org/agents'] });
    await screen.findByText('Warehouse reader');
    expect(screen.getByText('Enabled')).toBeInTheDocument();
    expect(screen.getByText('Managed by your application')).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Owner at registration' })).toBeInTheDocument();
    expect(screen.getByText('Authority requires a separate check')).toBeInTheDocument();
    expect(screen.queryByText('Running')).not.toBeInTheDocument();
  });
  it('ignores a previous tenant response after an organization switch', async () => {
    let finish!: (value: any) => void;
    const old = identity(); api.listAgentIdentities.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    const { rerender } = renderWithRouter(<App />, { initialEntries: ['/console/org/agents'] });
    state.org = 'fbcf47e5-4bdb-4c6e-87a3-893bd37a320b';
    api.listAgentIdentities.mockResolvedValue({ items: [], total: 0 }); rerender(<App />);
    await screen.findByText('No agent identities are listed.');
    await act(async () => finish({ items: [old], total: 1 }));
    expect(screen.queryByText('Warehouse reader')).not.toBeInTheDocument();
  });
  it('blocks private key material in the browser before registration', async () => {
    const { user } = renderWithRouter(<App />, { initialEntries: ['/console/org/agents'] });
    await screen.findByText('Warehouse reader');
    await user.click(screen.getByRole('button', { name: 'Register identity' }));
    for (const [label, value] of [
      ['Display name', 'Inventory helper'], ['Logical application reference', 'urn:example:app'],
      ['Declared source issuer', 'https://issuer.example.invalid'], ['Source subject', 'worker-subject'],
      ['Runtime instance reference', 'urn:example:runtime'],
    ]) await user.type(screen.getByLabelText(new RegExp(label)), value);
    for (const extra of [{ d: 'private-test-material' }, { private_key: 'private-test-material' }, { extra: { seed: 'private-test-material' } }]) {
      const input = screen.getByLabelText(/Public JWK/);
      await user.clear(input);
      await user.click(input);
      await user.paste(JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: 'n8dTWA2bFf1mlIs9RN_mTZPq5ojx5mpbbtmPhPsSaCU', ...extra }));
      await user.click(screen.getAllByRole('button', { name: 'Register identity' }).at(-1)!);
      await screen.findByText(/Private or symmetric keys cannot be sent/);
    }
    expect(api.registerAgentIdentity).not.toHaveBeenCalled();
  });
  it('makes the absence of a resume action explicit before suspension', async () => {
    const { user } = renderWithRouter(<App />, { initialEntries: ['/console/org/agents'] });
    await screen.findByText('Warehouse reader');
    await user.click(screen.getByRole('button', { name: 'Suspend access' }));
    expect(screen.getByText(/There is no resume action for a suspended identity/)).toBeInTheDocument();
    expect(api.changeAgentIdentity).not.toHaveBeenCalled();
  });
  it.each(['commit_unknown', 'invalid_response'])('requires a successful current-state reload after an uncertain %s mutation, even after dialog dismissal', async code => {
    api.changeAgentIdentity.mockRejectedValueOnce({ code });
    const { user } = renderWithRouter(<App />, { initialEntries: ['/console/org/agents'] });
    await screen.findByText('Warehouse reader');
    await user.click(screen.getByRole('button', { name: 'Suspend access' }));
    await user.click(screen.getAllByRole('button', { name: 'Suspend access' }).at(-1)!);
    await waitFor(() => expect(api.changeAgentIdentity).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await screen.findByText(/The previous change may have been recorded/);
    expect(await screen.findByRole('button', { name: 'Register identity' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Suspend access' })).toBeDisabled();
    api.listAgentIdentities.mockRejectedValueOnce({ code: 'unavailable' });
    await user.click(screen.getByRole('button', { name: 'Reload current state' }));
    await screen.findByText(/The service is unavailable/);
    expect(screen.getByRole('button', { name: 'Register identity' })).toBeDisabled();
    api.listAgentIdentities.mockResolvedValueOnce({ items: [{ ...identity(), revision: 2, status: 'SUSPENDED' }], total: 1 });
    await user.click(screen.getByRole('button', { name: 'Reload current state' }));
    await screen.findByText('Suspended');
    expect(screen.getByRole('button', { name: 'Register identity' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Suspend access' })).not.toBeInTheDocument();
    expect(api.changeAgentIdentity).toHaveBeenCalledTimes(1);
  });
  it('distinguishes a failed directory read from a verified empty directory', async () => {
    api.listAgentIdentities.mockRejectedValueOnce({ code: 'unavailable' });
    const { user } = renderWithRouter(<App />, { initialEntries: ['/console/org/agents'] });
    await screen.findByText(/The service is unavailable/);
    expect(screen.getByRole('button', { name: 'Register identity' })).toBeDisabled();
    expect(api.registerAgentIdentity).not.toHaveBeenCalled();
    expect(screen.queryByRole('table', { name: 'Agent identity directory' })).not.toBeInTheDocument();
    expect(screen.queryByText('No agent identities are listed.')).not.toBeInTheDocument();
    expect(screen.queryByText('0 identities')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next' })).not.toBeInTheDocument();
    api.listAgentIdentities.mockResolvedValueOnce({ items: [], total: 0 });
    await user.click(screen.getByRole('button', { name: 'Reload current state' }));
    await screen.findByText('No agent identities are listed.');
    expect(screen.getByText('0 identities')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Register identity' })).toBeEnabled();
    expect(screen.queryByText(/The service is unavailable/)).not.toBeInTheDocument();
  });
  it('explains missing approval access without starting a review for a view-only user', () => {
    state.permissions.delete('delegation-grant:approve');
    renderWithRouter(<App />, { initialEntries: [approvalPath] });
    expect(screen.getByText(/Ask an organization owner or administrator to review your approval access/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Load exact terms' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm exact terms' })).not.toBeInTheDocument();
    expect(api.reviewDelegation).not.toHaveBeenCalled();
    expect(api.confirmDelegation).not.toHaveBeenCalled();
  });
  it('rejects another approver and clears an older review before a failed replacement', async () => {
    const { user } = renderWithRouter(<App />, { initialEntries: [approvalPath] });
    await user.click(screen.getByRole('button', { name: 'Load exact terms' }));
    await screen.findByText('Authority being approved');
    await user.click(screen.getByRole('checkbox'));
    const wrongActor = review();
    wrongActor.terms.grantor.id = 'urn:marty:user:bb583823-df24-4b0a-bc55-21e3b68c9494';
    api.reviewDelegation.mockResolvedValueOnce(wrongActor);
    await user.click(screen.getByRole('button', { name: 'Load exact terms' }));
    await screen.findByText(/The response could not be verified/);
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm exact terms' })).not.toBeInTheDocument();
    expect(api.confirmDelegation).not.toHaveBeenCalled();
  });
  it('requires explicit review and consent, and retains the same confirmation on a lost reply', async () => {
    api.confirmDelegation.mockRejectedValueOnce({ code: 'commit_unknown' });
    const { user } = renderWithRouter(<App />, { initialEntries: [approvalPath] });
    expect(api.reviewDelegation).not.toHaveBeenCalled(); expect(api.confirmDelegation).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Load exact terms' }));
    await screen.findByText('Authority being approved');
    expect(screen.getByRole('button', { name: 'Confirm exact terms' })).toBeDisabled();
    expect(screen.getByText('Actions: urn:example:inventory:read')).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: 'Confirm exact terms' }));
    await screen.findByText(/The reply was lost/);
    const first = api.confirmDelegation.mock.calls[0];
    expect(window.sessionStorage.length).toBe(1);
    await user.click(screen.getByRole('button', { name: 'Check original confirmation' }));
    await screen.findByText(/was recorded at/);
    expect(api.confirmDelegation.mock.calls[1][2]).toBe(first[2]);
    expect(api.confirmDelegation.mock.calls[1][1]).toEqual(first[1]);
    expect(api.reviewDelegation).toHaveBeenCalledTimes(1);
  });
  it('offers original recovery after reload without automatically confirming', async () => {
    const r = review(); const confirmationId = 'a8e6f123-0566-4af0-a664-3a0907ea0f8e';
    window.sessionStorage.setItem(`elevenid.delegation-approval.v1:${state.org}:${state.user}:${grant.id}:${grant.revision}:${grant.terms_digest}`,
      JSON.stringify({ review_id: r.review_id, grant, confirmation_id: confirmationId }));
    state.permissions.delete('delegation-grant:approve');
    const { user } = renderWithRouter(<App />, { initialEntries: [approvalPath] });
    await screen.findByText(/A confirmation was already requested/);
    expect(api.confirmDelegation).not.toHaveBeenCalled(); expect(api.reviewDelegation).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Check original confirmation' }));
    await waitFor(() => expect(api.confirmDelegation).toHaveBeenCalledTimes(1));
    expect(api.confirmDelegation.mock.calls[0][2]).toBe(confirmationId);
  });
  it('shows withdrawal as the current consent state while retaining the original confirmation record', async () => {
    api.withdrawDelegation.mockImplementation(async (_org, id, confirmationId) => ({
      grant_id: id, confirmation_id: confirmationId, withdrawn_at: new Date().toISOString(), recovered: false,
    }));
    const { user } = renderWithRouter(<App />, { initialEntries: [approvalPath] });
    await user.click(screen.getByRole('button', { name: 'Load exact terms' }));
    await screen.findByText('Authority being approved');
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: 'Confirm exact terms' }));
    await screen.findByText(/was recorded at/);
    const recoveryKey = `elevenid.delegation-approval.v1:${state.org}:${state.user}:${grant.id}:${grant.revision}:${grant.terms_digest}`;
    const originalIntent = window.sessionStorage.getItem(recoveryKey);
    const confirmationId = api.confirmDelegation.mock.calls[0][2];
    await user.click(screen.getByRole('button', { name: 'Withdraw this consent' }));
    await screen.findByText(/Consent was withdrawn at/);
    expect(screen.queryByText(/was recorded at/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Withdraw.*consent/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Check original confirmation' })).not.toBeInTheDocument();
    expect(api.withdrawDelegation).toHaveBeenCalledExactlyOnceWith(state.org, grant.id, confirmationId);
    expect(api.confirmDelegation).toHaveBeenCalledTimes(1);
    expect(originalIntent).not.toBeNull();
    expect(window.sessionStorage.getItem(recoveryKey)).toBe(originalIntent);
  });
  it('can deliberately withdraw the original journaled consent after old-session recovery is denied', async () => {
    const r = review(); const confirmationId = '0175b3bb-95bd-4b0d-a3cb-c4eb4d6a75c1';
    const recoveryKey = `elevenid.delegation-approval.v1:${state.org}:${state.user}:${grant.id}:${grant.revision}:${grant.terms_digest}`;
    const originalIntent = JSON.stringify({ review_id: r.review_id, grant, confirmation_id: confirmationId });
    window.sessionStorage.setItem(recoveryKey, originalIntent);
    state.permissions.delete('delegation-grant:approve');
    api.confirmDelegation.mockRejectedValueOnce({ code: 'conflict' });
    api.withdrawDelegation.mockResolvedValue({ grant_id: grantId, confirmation_id: confirmationId,
      withdrawn_at: new Date().toISOString(), recovered: false });
    const { user } = renderWithRouter(<App />, { initialEntries: [approvalPath] });
    await screen.findByText(/A confirmation was already requested/);
    expect(api.confirmDelegation).not.toHaveBeenCalled();
    expect(api.withdrawDelegation).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Check original confirmation' }));
    await screen.findByText(/The record changed or the review expired/);
    await user.click(screen.getByRole('button', { name: 'Withdraw recorded consent' }));
    await screen.findByText(/Consent was withdrawn at/);
    expect(api.withdrawDelegation).toHaveBeenCalledExactlyOnceWith(state.org, grant.id, confirmationId);
    expect(api.confirmDelegation).toHaveBeenCalledTimes(1);
    expect(api.reviewDelegation).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem(recoveryKey)).toBe(originalIntent);
    expect(screen.queryByRole('button', { name: 'Check original confirmation' })).not.toBeInTheDocument();
  });
  it('does not approve an expired review', async () => {
    api.reviewDelegation.mockResolvedValue({ ...review(), expires_at: new Date(Date.now() - 1000).toISOString() });
    const { user } = renderWithRouter(<App />, { initialEntries: [approvalPath] });
    await user.click(screen.getByRole('button', { name: 'Load exact terms' }));
    await screen.findByText(/This review expired/);
    expect(screen.getByRole('checkbox')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Confirm exact terms' })).toBeDisabled();
    expect(api.confirmDelegation).not.toHaveBeenCalled();
  });
});
