import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import example from '../../../../../contracts/issuer-identity-inspection-example.json';
import DidIdentityDetailPage from './DidIdentityDetailPage';

const { scope, permission, notify } = vi.hoisted(() => ({ scope: { activeOrgId: 'org-a' }, permission: { view: true }, notify: vi.fn() }));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => scope }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({ can: () => permission.view, isLoading: false }) }));
vi.mock('../../../hooks/useNotifications', () => ({ useNotifications: () => ({ showNotification: notify }) }));
const entry = '/console/org/deploy/issuer-identity/inspect?' + new URLSearchParams({ organization_id: 'org-a',
  ...Object.fromEntries(['issuer_did', 'key_purpose', 'credential_format', 'algorithm'].map((key) => [key, example.identity[key as keyof typeof example.identity]])) });
const renderPage = () => renderWithRouter(<DidIdentityDetailPage />, { initialEntries: [entry] });
beforeEach(() => {
  scope.activeOrgId = 'org-a'; permission.view = true; vi.clearAllMocks();
  server.use(http.get('*/v1/signing-keys/issuer-identities/inspection', ({ request }) => {
    const query = new URL(request.url).searchParams;
    expect(query.get('organization_id')).toBe('org-a');
    expect(query.get('issuer_did')).toBe(example.identity.issuer_did);
    expect(query.get('key_purpose')).toBe('vc_jwt_issuer');
    expect(query.has('issuer_profile_id')).toBe(false);
    return HttpResponse.json(example);
  }));
});
describe('public DID identity inspection', () => {
  it('shows API canonical publication, assertion methods, timestamps and copyable public material', async () => {
    const { user } = renderPage();
    expect(await screen.findByText(/Stored and public assertion keys match the current managed signer/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'View canonical public DID document' })).toHaveAttribute('href', example.canonical_document_url);
    expect(screen.getByRole('table', { name: 'Public verification methods' })).toHaveTextContent('Yes');
    expect(screen.getByText('Inspection completed: 2026-10-23T20:01:00Z')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Copy public did document' }));
    expect(JSON.parse(await navigator.clipboard.readText())).toEqual(example.public_resolution.document);
    expect(screen.queryByText(/signing_key_reference/)).not.toBeInTheDocument();
  });
  it('keeps stored documents visible when public publication is unavailable and offers refresh', async () => {
    const result = structuredClone(example) as Record<string, any>;
    result.assertion_ready = false;
    result.public_resolution = { status: 'unavailable', checked_at: example.inspected_at, retrieved_at: null, content_sha256: null, assertion_authorized: false, document: null, verification_methods: [] };
    server.use(http.get('*/v1/signing-keys/issuer-identities/inspection', () => HttpResponse.json(result)));
    const { user } = renderPage();
    expect(await screen.findByText('Public DID could not be resolved')).toBeInTheDocument();
    expect(screen.getByLabelText('Stored DID document')).toBeInTheDocument();
    expect(screen.queryByLabelText('Public DID document')).not.toBeInTheDocument();
    result.public_resolution = example.public_resolution; result.assertion_ready = true;
    await user.click(screen.getByRole('button', { name: 'Refresh inspection' }));
    expect(await screen.findByText(/Stored and public assertion keys match the current managed signer/)).toBeInTheDocument();
  });
  it('reports stale public keys without showing assertion readiness', async () => {
    const result = structuredClone(example); result.assertion_ready = false; result.public_resolution.status = 'stale';
    server.use(http.get('*/v1/signing-keys/issuer-identities/inspection', () => HttpResponse.json(result)));
    renderPage();
    expect(await screen.findByText('Public DID key is stale or different')).toBeInTheDocument();
    expect(screen.queryByText('Stored and public assertion keys match the current managed signer.')).not.toBeInTheDocument();
  });
  it('rejects another tenant response and never renders private nested material', async () => {
    const result = structuredClone(example) as Record<string, any>;
    result.registry.document.verificationMethod[0].publicKeyJwk.d = 'private-sentinel';
    result.organization_id = 'other';
    server.use(http.get('*/v1/signing-keys/issuer-identities/inspection', () => HttpResponse.json(result)));
    renderPage();
    expect(await screen.findByText(/Identity inspection is unavailable/)).toBeInTheDocument();
    expect(screen.queryByText(/private-sentinel/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Stored DID document')).not.toBeInTheDocument();
  });
  it('does not request inspection without view permission', async () => {
    permission.view = false; const requests = vi.fn();
    server.use(http.get('*/v1/signing-keys/issuer-identities/inspection', () => { requests(); return HttpResponse.json(example); }));
    renderPage();
    expect(screen.getByText(/do not have permission/)).toBeInTheDocument();
    expect(requests).not.toHaveBeenCalled();
  });
  it('discards a late result and clears public material when the organization changes', async () => {
    let release!: () => void; const pending = new Promise<void>((resolve) => { release = resolve; });
    let requested = false;
    server.use(http.get('*/v1/signing-keys/issuer-identities/inspection', async () => { requested = true; await pending; return HttpResponse.json(example); }));
    const view = renderPage();
    await waitFor(() => expect(requested).toBe(true));
    scope.activeOrgId = 'org-b'; view.rerender(<DidIdentityDetailPage />);
    expect(await screen.findByText(/different organization selection/)).toBeInTheDocument();
    await act(async () => { release(); await pending; });
    expect(screen.queryByLabelText('Stored DID document')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Refresh inspection' })).toBeDisabled();
  });
});
