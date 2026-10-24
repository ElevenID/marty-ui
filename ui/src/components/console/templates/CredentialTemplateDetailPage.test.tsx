import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, renderWithRouter } from '@test/utils';
import { Route, Routes } from 'react-router';
import { act, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import walletExample from '../../../../../contracts/wallet-compatibility-example.json';

import CredentialTemplateDetailPage from './CredentialTemplateDetailPage';

const {
  mockGetCredentialTemplate,
  mockListDeliveryDestinations,
  mockCreateDeliveryDestination,
  mockUpdateDeliveryDestination,
  mockListCanvasProgramBindings,
  mockGetCanvasMirrorHealth,
  context, permission, can,
} = vi.hoisted(() => ({
  mockGetCredentialTemplate: vi.fn(),
  mockListDeliveryDestinations: vi.fn(),
  mockCreateDeliveryDestination: vi.fn(),
  mockUpdateDeliveryDestination: vi.fn(),
  mockListCanvasProgramBindings: vi.fn(),
  mockGetCanvasMirrorHealth: vi.fn(),
  context: { activeOrgId: 'org-1' }, permission: { isLoading: false }, can: vi.fn(),
}));

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}));

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => context,
}));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({ ...permission, can }) }));

vi.mock('../../../services/presentationPolicyApi', () => ({
  getCredentialTemplate: mockGetCredentialTemplate,
}));

vi.mock('../../../services/deliveryDestinationsApi', () => ({
  listDeliveryDestinations: mockListDeliveryDestinations,
  createDeliveryDestination: mockCreateDeliveryDestination,
  updateDeliveryDestination: mockUpdateDeliveryDestination,
}));

vi.mock('../../../services/canvasIntegrationsApi', () => ({
  listCanvasProgramBindings: mockListCanvasProgramBindings,
  getCanvasMirrorHealth: mockGetCanvasMirrorHealth,
}));

describe('CredentialTemplateDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    context.activeOrgId = 'org-1'; permission.isLoading = false; can.mockReturnValue(true);
    mockGetCredentialTemplate.mockResolvedValue({
      id: 'template-1',
      organization_id: 'org-1',
      name: 'Interoperable Credentials Foundations Badge',
      credential_type: 'OpenBadgeCredential',
      credential_payload_format: 'SD_JWT_VC',
      status: 'active',
      claims: [{ name: 'achievement' }],
    });
    server.use(http.get('http://localhost:8000/v1/credential-templates/template-1/wallet-compatibility', () => HttpResponse.json(walletExample)));
    mockListDeliveryDestinations.mockResolvedValue([
      {
        id: 'dd-canvas-credentials-institutional',
        is_system: true,
        name: 'Canvas Credentials',
        description: 'Publish a public Open Badge view to Canvas Credentials after ElevenID issuance.',
        provider: 'canvas_credentials',
        setup_actor: 'organization_admin',
        credential_format: 'VC_JWT',
        claim_projection_policy: { mode: 'public_badge_provenance' },
      },
      {
        id: 'dd-elevenid-wallet',
        is_system: true,
        name: 'ElevenID Wallet',
        provider: 'elevenid_wallet',
        mode: 'holder_wallet',
        credential_format: 'VC_JWT',
      },
    ]);
    mockCreateDeliveryDestination.mockResolvedValue({
      id: 'dd-org-canvas-credentials',
      name: 'Canvas Credentials',
      provider: 'canvas_credentials',
      mode: 'organization_mirror',
      is_system: false,
      is_enabled: true,
    });
    mockUpdateDeliveryDestination.mockResolvedValue({
      id: 'dd-org-canvas-credentials',
      provider: 'canvas_credentials',
      mode: 'organization_mirror',
      is_system: false,
      is_enabled: false,
    });
    mockListCanvasProgramBindings.mockResolvedValue([
      {
        id: 'binding-1',
        organization_id: 'org-1',
        display_name: 'Interoperable Credentials Foundations Quiz',
        credential_template_id: 'template-1',
        canvas_scope: {
          course_id: 'course-1',
          quiz_id: 'quiz-1',
        },
        canvas_credentials: {
          provider: 'badgr_api',
          assertion_scope: 'badgeclasses',
          badgeclass_id: 'badgeclass-1',
          issuer_id: 'issuer-1',
          api_base_url: 'https://api.badgr.test',
          api_token_secret_id: 'secret-1',
        },
      },
    ]);
    mockGetCanvasMirrorHealth.mockResolvedValue({
      organization_id: 'org-1',
      pending_publish_count: 2,
      failed_publish_count: 1,
      delivered_count: 5,
      lifecycle_sync_failed_count: 1,
      lifecycle_sync_ok_count: 4,
      alert_count: 1,
      critical_alert_count: 0,
      warning_alert_count: 1,
      last_successful_publish_at: '2026-05-21T16:03:54.200968+00:00',
      last_lifecycle_sync_success_at: '2026-05-21T16:04:54.200968+00:00',
    });
  });

  const page = () => <Routes><Route path="/console/org/templates/credentials/:templateId" element={<CredentialTemplateDetailPage />} /></Routes>;
  const renderPage = () => renderWithRouter(page(), { initialEntries: ['/console/org/templates/credentials/template-1'] });

  it('loads real wallet profile HTTP data on demand and separates derived configuration from evidence', async () => {
    let calls = 0;
    server.use(http.get('http://localhost:8000/v1/credential-templates/template-1/wallet-compatibility', () => {
      calls++;
      return HttpResponse.json({ ...walletExample, organization_id: 'org-1', id: 'override-1', is_override: true, override_precedence: 85,
        merge_strategy: 'REPLACE', applied_override_ids: ['override-1'], wallet_apps: ['Campus Wallet'],
        template_wallet_configs: [{ wallet_id: 'campus', deep_link_scheme: 'campus://', format_variant: 'dc+sd-jwt' }] });
    }));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'Interoperable Credentials Foundations Badge' });
    expect(calls).toBe(0);
    expect(mockListDeliveryDestinations).not.toHaveBeenCalled();
    expect(mockListCanvasProgramBindings).not.toHaveBeenCalled();
    await user.click(screen.getByRole('tab', { name: 'Wallet profile' }));
    expect(await screen.findByText('Campus Wallet')).toBeInTheDocument();
    expect(screen.getByText('Derived configuration')).toBeInTheDocument();
    expect(screen.getByText(/not verified wallet interoperability or delivery evidence/)).toBeInTheDocument();
    expect(screen.getByText(/Other declared credential formats require separate qualification/)).toBeInTheDocument();
    expect(screen.getByText(/REPLACE; primary precedence 85/)).toBeInTheDocument();
    expect(screen.getByText('override-1')).toBeInTheDocument();
    expect(screen.getByText(/campus \/ campus:\/\/ \/ dc\+sd-jwt/)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /openid-credential-offer/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Refresh wallet profile' }));
    await waitFor(() => expect(calls).toBe(2));
  });

  it('preserves an unavailable wallet dependency and retries without fabricating compatibility', async () => {
    server.use(http.get('http://localhost:8000/v1/credential-templates/template-1/wallet-compatibility', () => HttpResponse.json({ detail: 'Wallet registry unavailable' }, { status: 422 })));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'Interoperable Credentials Foundations Badge' });
    await user.click(screen.getByRole('tab', { name: 'Wallet profile' }));
    expect(await screen.findByText(/Wallet registry unavailable/)).toBeInTheDocument();
    expect(screen.queryByText('EUDI Wallet')).not.toBeInTheDocument();
    server.use(http.get('http://localhost:8000/v1/credential-templates/template-1/wallet-compatibility', () => HttpResponse.json(walletExample)));
    await user.click(screen.getByRole('button', { name: 'Retry wallet profile' }));
    expect(await screen.findByText('EUDI Wallet')).toBeInTheDocument();
  });

  it.each([
    { organization_id: 'foreign', name: 'Foreign wallet' },
    { wallet_apps: [42], name: 'Malformed wallet' },
    { derived_from: { credential_format: 'MDOC', issuance_protocol: 'OTHER' }, name: 'Mismatched wallet' },
  ])('rejects malformed or foreign wallet responses: %j', async (invalid) => {
    server.use(http.get('http://localhost:8000/v1/credential-templates/template-1/wallet-compatibility', () => HttpResponse.json({ ...walletExample, ...invalid })));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'Interoperable Credentials Foundations Badge' });
    await user.click(screen.getByRole('tab', { name: 'Wallet profile' }));
    expect(await screen.findByText(/Wallet profile response is invalid/)).toBeInTheDocument();
    expect(screen.queryByText(invalid.name)).not.toBeInTheDocument();
  });

  it('does not request a wallet profile for physical documents', async () => {
    mockGetCredentialTemplate.mockResolvedValue({ id: 'template-1', organization_id: 'org-1', name: 'Passport', credential_payload_format: 'ICAO_EMRTD', issuance_protocol: 'PHYSICAL_DOCUMENT' });
    let calls = 0;
    server.use(http.get('http://localhost:8000/v1/credential-templates/template-1/wallet-compatibility', () => { calls++; return HttpResponse.json(walletExample); }));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'Passport' });
    await user.click(screen.getByRole('tab', { name: 'Wallet profile' }));
    expect(await screen.findByText('Wallet profiles do not apply to physical documents.')).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it.each(['loading', 'denied', 'no organization'])('blocks direct template loaders while %s', async (condition) => {
    if (condition === 'loading') permission.isLoading = true;
    if (condition === 'denied') can.mockReturnValue(false);
    if (condition === 'no organization') context.activeOrgId = '';
    renderPage();
    expect(mockGetCredentialTemplate).not.toHaveBeenCalled();
    expect(mockListDeliveryDestinations).not.toHaveBeenCalled();
    expect(mockGetCanvasMirrorHealth).not.toHaveBeenCalled();
  });

  it('does not mount wallet or destination data for a foreign owning template', async () => {
    mockGetCredentialTemplate.mockResolvedValue({ id: 'template-1', organization_id: 'foreign', name: 'Foreign template' });
    const { user } = renderPage();
    expect(await screen.findByText('Credential template is outside the selected organization.')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Wallet profile' }));
    expect(screen.queryByText('EUDI Wallet')).not.toBeInTheDocument();
    expect(screen.queryByText('Foreign template')).not.toBeInTheDocument();
    expect(mockListDeliveryDestinations).not.toHaveBeenCalled();
  });

  it('uses existing integration grants for destination reads and mutations', async () => {
    can.mockImplementation((resource, action) => resource === 'credential-template' || (['integration-connector', 'wallet'].includes(resource) && action === 'view'));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'Interoperable Credentials Foundations Badge' });
    await user.click(screen.getByRole('tab', { name: 'Destinations' }));
    expect(await screen.findByRole('heading', { name: 'Canvas Credentials' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /add org destination/i })).not.toBeInTheDocument();
    expect(mockCreateDeliveryDestination).not.toHaveBeenCalled();
    expect(screen.queryByText('Ready')).not.toBeInTheDocument();
  });

  it('discards a late wallet response after changing organizations', async () => {
    let release: () => void = () => {};
    let calls = 0;
    server.use(http.get('http://localhost:8000/v1/credential-templates/template-1/wallet-compatibility', async () => {
      calls++;
      if (calls === 1) {
        await new Promise<void>((resolve) => { release = resolve; });
        return HttpResponse.json({ ...walletExample, organization_id: 'org-1', name: 'Late old wallet' });
      }
      return HttpResponse.json({ ...walletExample, organization_id: 'org-2', name: 'Current wallet' });
    }));
    const { user, rerender } = renderPage();
    await screen.findByRole('heading', { name: 'Interoperable Credentials Foundations Badge' });
    await user.click(screen.getByRole('tab', { name: 'Wallet profile' }));
    await waitFor(() => expect(calls).toBe(1));
    context.activeOrgId = 'org-2';
    mockGetCredentialTemplate.mockResolvedValue({ id: 'template-1', organization_id: 'org-2', name: 'Other organization template', credential_payload_format: 'SD_JWT_VC' });
    rerender(page());
    await screen.findByRole('heading', { name: 'Other organization template' });
    await user.click(screen.getByRole('tab', { name: 'Wallet profile' }));
    expect(await screen.findByText('Current wallet')).toBeInTheDocument();
    await act(async () => { release(); });
    expect(screen.queryByText('Late old wallet')).not.toBeInTheDocument();
    expect(screen.getByText('Current wallet')).toBeInTheDocument();
  });

  it('shows destination readiness and Canvas bindings for a credential template', async () => {
    const { user } = renderWithRouter(
      <Routes>
        <Route path="/console/org/templates/credentials/:templateId" element={<CredentialTemplateDetailPage />} />
      </Routes>,
      {
        initialEntries: ['/console/org/templates/credentials/template-1'],
      },
    );

    expect(
      await screen.findByRole('heading', { name: 'Interoperable Credentials Foundations Badge' }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: /destinations/i }));

    expect(await screen.findByTestId('credential-template-destinations')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Canvas Credentials' })).toBeInTheDocument();
    expect(screen.getByText(/Canvas Credentials is an organization-managed destination/i)).toBeInTheDocument();
    expect(screen.getByText(/Active bindings for this template:/i)).toBeInTheDocument();
    expect(screen.getByText('Interoperable Credentials Foundations Quiz')).toBeInTheDocument();
    expect(screen.getByText(/Badge class:/i)).toBeInTheDocument();
    expect(screen.getByText('badgeclass-1')).toBeInTheDocument();
    expect(screen.getByText(/Token:/i)).toBeInTheDocument();
    expect(screen.getByText('Pending: 2')).toBeInTheDocument();
    expect(screen.getByText('Failed: 1')).toBeInTheDocument();
    expect(screen.getByText('Sync failures: 1')).toBeInTheDocument();
    expect(screen.getByText(/Canvas mirror drift needs attention/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /manage canvas platforms/i })).toHaveAttribute(
      'href',
      '/console/org/deploy/canvas',
    );
  });

  it('creates an organization Canvas Credentials destination from the template destinations tab', async () => {
    const { user } = renderWithRouter(
      <Routes>
        <Route path="/console/org/templates/credentials/:templateId" element={<CredentialTemplateDetailPage />} />
      </Routes>,
      {
        initialEntries: ['/console/org/templates/credentials/template-1'],
      },
    );

    await screen.findByRole('heading', { name: 'Interoperable Credentials Foundations Badge' });
    await user.click(screen.getByRole('tab', { name: /destinations/i }));
    await user.click(await screen.findByRole('button', { name: /add org destination/i }));

    expect(mockCreateDeliveryDestination).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: 'org-1',
      provider: 'canvas_credentials',
      mode: 'organization_mirror',
      setup_actor: 'org_admin',
      delivery_target: 'canvas_credentials',
      requires_consent: true,
      claim_projection_policy: expect.objectContaining({ mode: 'public_badge' }),
    }));
  });

  it('surfaces destination dependency failures instead of showing an empty destination state', async () => {
    mockListDeliveryDestinations.mockRejectedValue(new Error('Delivery service unavailable'));
    mockListCanvasProgramBindings.mockRejectedValue(new Error('Canvas bindings unavailable'));

    const { user } = renderWithRouter(
      <Routes>
        <Route path="/console/org/templates/credentials/:templateId" element={<CredentialTemplateDetailPage />} />
      </Routes>,
      {
        initialEntries: ['/console/org/templates/credentials/template-1'],
      },
    );

    await screen.findByRole('heading', { name: 'Interoperable Credentials Foundations Badge' });
    await user.click(screen.getByRole('tab', { name: /destinations/i }));

    expect(await screen.findByText('Delivery service unavailable')).toBeInTheDocument();
    expect(screen.getByText('Canvas bindings unavailable')).toBeInTheDocument();
    expect(screen.queryByText(/No delivery destinations are available/i)).not.toBeInTheDocument();
  });
});
