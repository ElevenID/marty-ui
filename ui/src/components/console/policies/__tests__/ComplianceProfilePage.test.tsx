import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { Route, Routes, useLocation } from 'react-router';
import { http, HttpResponse } from 'msw';
import { renderWithRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import ComplianceProfilePage from '../ComplianceProfilePage';
import examples from '../../../../../../contracts/compliance-profile-http-examples.json';

const { context, permission, can } = vi.hoisted(() => ({
  context: { activeOrgId: 'org-1' }, permission: { isLoading: false }, can: vi.fn(),
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => context }));
vi.mock('../../../../hooks/usePermissions', () => ({ usePermissions: () => ({ can, isLoading: permission.isLoading }) }));
const BASE = '/console/org/policies/compliance';
const ID = examples.response.id;
let profile: Record<string, any>;
let requests: Array<{ method: string; path: string; body: any }>;
function Location() { return <output data-testid="location">{useLocation().pathname}</output>; }
function Pages() {
  return <><Routes>
    <Route path={BASE + '/new'} element={<ComplianceProfilePage mode="create" />} />
    <Route path={BASE + '/:profileId/edit'} element={<ComplianceProfilePage mode="edit" />} />
    <Route path={BASE + '/:profileId'} element={<ComplianceProfilePage />} />
    <Route path={BASE} element={<div>Profile list</div>} />
  </Routes><Location /></>;
}
function renderPage(suffix = `/${ID}`) { return renderWithRouter(<Pages />, { initialEntries: [BASE + suffix] }); }
const field = (name: string) => screen.getByLabelText(new RegExp('^' + name));

describe('canonical compliance profile journeys', () => {
  beforeEach(() => {
    vi.clearAllMocks(); context.activeOrgId = 'org-1'; permission.isLoading = false; can.mockReturnValue(true);
    profile = structuredClone(examples.response); requests = [];
    server.use(
      http.get('*/v1/compliance-profiles/system/discoverable', ({ request }) => {
        expect(new URL(request.url).searchParams.get('organization_id')).toBe(context.activeOrgId);
        return HttpResponse.json([{ ...profile, id: 'preset', organization_id: null, is_system: true, status: 'ACTIVE', discoverable: true }]);
      }),
      http.get('*/v1/compliance-profiles/:id', () => HttpResponse.json(profile)),
      http.post('*/v1/compliance-profiles', async ({ request }) => {
        const body = await request.json() as Record<string, any>; requests.push({ method: 'POST', path: new URL(request.url).pathname, body });
        profile = { ...profile, ...body, status: 'DRAFT', is_system: false }; return HttpResponse.json(profile);
      }),
      http.patch('*/v1/compliance-profiles/:id', async ({ request }) => {
        const body = await request.json() as Record<string, any>; requests.push({ method: 'PATCH', path: new URL(request.url).pathname, body });
        profile = { ...profile, ...body }; return HttpResponse.json(profile);
      }),
      http.post('*/v1/compliance-profiles/:id/:action', async ({ request, params }) => {
        requests.push({ method: 'POST', path: new URL(request.url).pathname, body: await request.json() });
        profile = { ...profile, status: params.action === 'activate' ? 'ACTIVE' : 'SUSPENDED' }; return HttpResponse.json(profile);
      }),
      http.delete('*/v1/compliance-profiles/:id', ({ request }) => { requests.push({ method: 'DELETE', path: new URL(request.url).pathname, body: null }); return HttpResponse.json({ success: true }); }),
    );
  });
  it('loads public requirements, activates, uses, suspends and confirms deletion through real client methods', async () => {
    const { user } = renderPage();
    expect(await screen.findByRole('heading', { name: profile.name })).toBeInTheDocument();
    expect(screen.getByText(/Profile configuration/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Activate profile' }));
    expect(await screen.findByText('ACTIVE')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Use in a credential template' })).toHaveAttribute('href', '/console/org/templates/credentials/new');
    await user.click(screen.getByRole('button', { name: 'Suspend profile' }));
    expect(await screen.findByText('SUSPENDED')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Delete profile' }));
    expect(requests).toHaveLength(2);
    await user.click(screen.getByRole('button', { name: 'Confirm deletion' }));
    expect(await screen.findByText('Profile list')).toBeInTheDocument();
    expect(requests.map((r) => [r.method, r.path, r.body])).toEqual([
      ['POST', `/v1/compliance-profiles/${ID}/activate`, {}], ['POST', `/v1/compliance-profiles/${ID}/suspend`, {}], ['DELETE', `/v1/compliance-profiles/${ID}`, null],
    ]);
  });
  it('sends a name-only sparse edit and retains every unrelated public and hidden field', async () => {
    const initial = structuredClone(profile); const { user } = renderPage(`/${ID}/edit`);
    await screen.findByRole('button', { name: 'Save changes' });
    await user.clear(field('Name')); await user.type(field('Name'), 'Renamed');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByRole('heading', { name: 'Renamed' })).toBeInTheDocument();
    expect(requests[0].body).toEqual({ name: 'Renamed' });
    expect(profile).toEqual({ ...initial, name: 'Renamed' });
    expect(screen.queryByText('data_retention')).not.toBeInTheDocument();
  });
  it('preserves explicit empty descriptions and false discoverability', async () => {
    const { user } = renderPage(`/${ID}/edit`); await screen.findByRole('button', { name: 'Save changes' });
    await user.clear(field('Description')); await user.click(screen.getByRole('checkbox', { name: 'Discoverable' }));
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(requests[0]?.body).toEqual({ description: '', discoverable: false }));
  });
  it('copies only public preset requirements into a new organization-owned DRAFT', async () => {
    const { user } = renderPage('/new'); await screen.findByRole('button', { name: 'Create profile' });
    await user.click(field('Copy public preset requirements')); await user.click(await screen.findByRole('option', { name: /Enterprise SD-JWT VC/ }));
    await user.click(screen.getByRole('button', { name: 'Create profile' }));
    await waitFor(() => expect(requests).toHaveLength(1));
    expect(requests[0].body).toEqual({ ...Object.fromEntries(['description', 'compliance_code', 'credential_format', 'issuance_protocol', 'verification_policy_set_id', 'issuer_artifact_requirements', 'trust_profile_constraints', 'api_surface', 'discoverable'].map((key) => [key, examples.response[key as keyof typeof examples.response]])), name: 'Enterprise SD-JWT VC (organization)', organization_id: 'org-1' });
    for (const field of ['id', 'status', 'is_system', 'created_at', 'updated_at', 'frameworks', 'data_retention']) expect(requests[0].body).not.toHaveProperty(field);
  });
  it('rejects invalid nested JSON locally and preserves the draft for correction', async () => {
    const { user } = renderPage(`/${ID}/edit`); await screen.findByRole('button', { name: 'Save changes' });
    fireEvent.change(field('Issuer artifact requirements'), { target: { value: '{ broken' } });
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByText('Issuer artifact requirements must be valid JSON.')).toBeInTheDocument();
    expect(requests).toHaveLength(0); expect(field('Issuer artifact requirements')).toHaveValue('{ broken');
  });
  it('shows native validation errors without navigating or dropping the draft', async () => {
    server.use(http.patch('*/v1/compliance-profiles/:id', () => HttpResponse.json({ detail: 'Incompatible profile requirements' }, { status: 422 })));
    const { user } = renderPage(`/${ID}/edit`); await screen.findByRole('button', { name: 'Save changes' });
    await user.clear(field('Name')); await user.type(field('Name'), 'Retry this draft'); await user.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Incompatible profile requirements');
    expect(field('Name')).toHaveValue('Retry this draft'); expect(screen.getByTestId('location')).toHaveTextContent('/edit');
  });
  it('keeps system presets immutable even at direct edit URLs', async () => {
    profile = { ...profile, organization_id: null, is_system: true, status: 'ACTIVE' };
    renderPage(`/${ID}/edit`);
    expect(await screen.findByText(/System presets are immutable/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument(); expect(requests).toHaveLength(0);
  });
  it.each(['/new', `/${ID}/edit`, `/${ID}`])('denies direct unauthorized routes before requests at %s', async (path) => {
    can.mockReturnValue(false); renderPage(path);
    expect(screen.getByRole('alert')).toHaveTextContent('permission'); expect(requests).toHaveLength(0);
    expect(screen.queryByRole('button', { name: 'Create profile' })).not.toBeInTheDocument();
  });
  it('does not render a profile from another organization', async () => {
    profile.organization_id = 'org-foreign'; renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('not available in the selected organization');
    expect(screen.queryByRole('heading', { name: profile.name })).not.toBeInTheDocument();
  });
  it('discards a late organization response after selection changes', async () => {
    let release!: () => void; let started = false; const delayed = new Promise<void>((resolve) => { release = resolve; });
    server.use(http.get('*/v1/compliance-profiles/:id', async () => { if (context.activeOrgId === 'org-1') { started = true; await delayed; return HttpResponse.json(profile); } return HttpResponse.json({ detail: 'Not found' }, { status: 404 }); }));
    const { rerender } = renderPage(); await waitFor(() => expect(started).toBe(true));
    context.activeOrgId = 'org-2'; rerender(<Pages />);
    await screen.findByRole('alert'); await act(async () => { release(); });
    expect(screen.queryByRole('heading', { name: profile.name })).not.toBeInTheDocument();
  });
  it('does not apply a late creation result after an organization switch', async () => {
    let release!: () => void; let started = false; const delayed = new Promise<void>((resolve) => { release = resolve; });
    const created = structuredClone(profile);
    server.use(http.post('*/v1/compliance-profiles', async () => { started = true; await delayed; return HttpResponse.json(created); }));
    const { user, rerender } = renderPage('/new'); await screen.findByRole('button', { name: 'Create profile' });
    await user.type(field('Name'), 'New org-one profile'); await user.type(field('Credential format'), 'SD_JWT_VC');
    await user.click(screen.getByRole('button', { name: 'Create profile' })); await waitFor(() => expect(started).toBe(true));
    context.activeOrgId = 'org-2'; rerender(<Pages />); await screen.findByRole('button', { name: 'Create profile' });
    await act(async () => { release(); });
    expect(screen.getByTestId('location')).toHaveTextContent(BASE + '/new');
    expect(field('Name')).toHaveValue('');
  });

  it('renders read-only profile metadata without mutation controls', async () => {
    can.mockImplementation((_resource: string, action: string) => action === 'view'); renderPage();
    await screen.findByRole('heading', { name: profile.name });
    for (const name of ['Edit profile', 'Activate profile', 'Suspend profile', 'Delete profile']) expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    expect(requests).toHaveLength(0);
  });
});
