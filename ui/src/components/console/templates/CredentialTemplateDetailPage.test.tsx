import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, renderWithRouter } from '@test/utils';
import { Route, Routes } from 'react-router-dom';

import CredentialTemplateDetailPage from './CredentialTemplateDetailPage';

const {
  mockGetCredentialTemplate,
  mockListDeliveryDestinations,
  mockCreateDeliveryDestination,
  mockUpdateDeliveryDestination,
  mockListCanvasProgramBindings,
  mockGetCanvasMirrorHealth,
} = vi.hoisted(() => ({
  mockGetCredentialTemplate: vi.fn(),
  mockListDeliveryDestinations: vi.fn(),
  mockCreateDeliveryDestination: vi.fn(),
  mockUpdateDeliveryDestination: vi.fn(),
  mockListCanvasProgramBindings: vi.fn(),
  mockGetCanvasMirrorHealth: vi.fn(),
}));

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}));

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}));

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
    mockGetCredentialTemplate.mockResolvedValue({
      id: 'template-1',
      name: 'Interoperable Credentials Foundations Badge',
      credential_type: 'OpenBadgeCredential',
      credential_payload_format: 'VC_JWT',
      status: 'active',
      claims: [{ name: 'achievement' }],
    });
    mockListDeliveryDestinations.mockResolvedValue([
      {
        id: 'dd-canvas-credentials-institutional',
        name: 'Canvas Credentials',
        description: 'Publish a public Open Badge view to Canvas Credentials after ElevenID issuance.',
        provider: 'canvas_credentials',
        setup_actor: 'organization_admin',
        credential_format: 'VC_JWT',
        claim_projection_policy: { mode: 'public_badge_provenance' },
      },
      {
        id: 'dd-elevenid-wallet',
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
