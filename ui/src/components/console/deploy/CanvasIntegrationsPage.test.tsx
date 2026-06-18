import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import CanvasIntegrationsPage from './CanvasIntegrationsPage';

const {
  mockListCanvasPlatforms,
  mockListCanvasProgramBindings,
  mockListCanvasIntegrationSecrets,
  mockCreateCanvasIntegrationSecret,
  mockUpdateCanvasIntegrationSecret,
  mockDiscoverCanvasScope,
  mockGetCanvasMirrorHealth,
  mockProcessPendingCanvasMirrorDeliveries,
  mockProcessCanvasMirrorStatusSyncFailures,
  mockRunCanvasMirrorAutomationCycle,
  mockValidateCanvasCredentialsProvider,
  mockListApplicationTemplates,
  mockListCredentialTemplates,
  mockListDeploymentProfiles,
  mockListDeliveryDestinations,
  mockCreateDeliveryDestination,
  mockUpdateDeliveryDestination,
} = vi.hoisted(() => ({
  mockListCanvasPlatforms: vi.fn(),
  mockListCanvasProgramBindings: vi.fn(),
  mockListCanvasIntegrationSecrets: vi.fn(),
  mockCreateCanvasIntegrationSecret: vi.fn(),
  mockUpdateCanvasIntegrationSecret: vi.fn(),
  mockDiscoverCanvasScope: vi.fn(),
  mockGetCanvasMirrorHealth: vi.fn(),
  mockProcessPendingCanvasMirrorDeliveries: vi.fn(),
  mockProcessCanvasMirrorStatusSyncFailures: vi.fn(),
  mockRunCanvasMirrorAutomationCycle: vi.fn(),
  mockValidateCanvasCredentialsProvider: vi.fn(),
  mockListApplicationTemplates: vi.fn(),
  mockListCredentialTemplates: vi.fn(),
  mockListDeploymentProfiles: vi.fn(),
  mockListDeliveryDestinations: vi.fn(),
  mockCreateDeliveryDestination: vi.fn(),
  mockUpdateDeliveryDestination: vi.fn(),
}));

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}));

vi.mock('../../../services/applicationTemplatesApi', () => ({
  listApplicationTemplates: (...args: unknown[]) => mockListApplicationTemplates(...args),
}));

vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: (...args: unknown[]) => mockListCredentialTemplates(...args),
}));

vi.mock('../../../services/deploymentProfilesApi', () => ({
  listDeploymentProfiles: (...args: unknown[]) => mockListDeploymentProfiles(...args),
}));

vi.mock('../../../services/canvasIntegrationsApi', () => ({
  listCanvasPlatforms: (...args: unknown[]) => mockListCanvasPlatforms(...args),
  listCanvasProgramBindings: (...args: unknown[]) => mockListCanvasProgramBindings(...args),
  listCanvasIntegrationSecrets: (...args: unknown[]) => mockListCanvasIntegrationSecrets(...args),
  createCanvasIntegrationSecret: (...args: unknown[]) => mockCreateCanvasIntegrationSecret(...args),
  updateCanvasIntegrationSecret: (...args: unknown[]) => mockUpdateCanvasIntegrationSecret(...args),
  discoverCanvasScope: (...args: unknown[]) => mockDiscoverCanvasScope(...args),
  getCanvasMirrorHealth: (...args: unknown[]) => mockGetCanvasMirrorHealth(...args),
  processPendingCanvasMirrorDeliveries: (...args: unknown[]) => mockProcessPendingCanvasMirrorDeliveries(...args),
  processCanvasMirrorStatusSyncFailures: (...args: unknown[]) => mockProcessCanvasMirrorStatusSyncFailures(...args),
  runCanvasMirrorAutomationCycle: (...args: unknown[]) => mockRunCanvasMirrorAutomationCycle(...args),
  validateCanvasCredentialsProvider: (...args: unknown[]) => mockValidateCanvasCredentialsProvider(...args),
  createCanvasPlatform: vi.fn(),
  createCanvasProgramBinding: vi.fn(),
  deleteCanvasPlatform: vi.fn(),
  deleteCanvasProgramBinding: vi.fn(),
  updateCanvasPlatform: vi.fn(),
  updateCanvasProgramBinding: vi.fn(),
}));

vi.mock('../../../services/deliveryDestinationsApi', () => ({
  listDeliveryDestinations: (...args: unknown[]) => mockListDeliveryDestinations(...args),
  createDeliveryDestination: (...args: unknown[]) => mockCreateDeliveryDestination(...args),
  updateDeliveryDestination: (...args: unknown[]) => mockUpdateDeliveryDestination(...args),
}));

const platform = {
  id: 'platform-1',
  organization_id: 'org-1',
  display_name: 'Canvas Main',
  canvas_account_id: 'canvas-account-1',
  canvas_base_url: 'https://canvas.example.edu',
  lti_client_id: 'client-1',
  lti_jwks_url: 'https://canvas.example.edu/jwks',
  enabled: true,
};

const binding = {
  id: 'binding-1',
  platform_id: 'platform-1',
  application_template_id: 'app-template-1',
  credential_template_id: 'credential-template-1',
  display_name: 'Safety Course',
  canvas_scope: { course_id: 'course-101' },
  evidence_requirements: [{ fact_type: 'canvas.course_completion' }],
  delivery_mode: 'wallet_plus_canvas_mirror',
  deployment_profile_id: 'deployment-profile-1',
  feature_flags: {
    enable_canvas_evidence: true,
    enable_canvas_lti: true,
    enable_canvas_mirror_publish: true,
    enable_canvas_mirror_ops: true,
    enable_canvas_deep_linking: false,
    enable_canvas_ags: true,
    enable_canvas_nrps: false,
  },
  auto_approve_on_evidence: true,
  enabled: true,
};

describe('CanvasIntegrationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListCanvasPlatforms.mockResolvedValue([platform]);
    mockListCanvasProgramBindings.mockResolvedValue([binding]);
    mockListCanvasIntegrationSecrets.mockResolvedValue([
      {
        id: 'secret-1',
        organization_id: 'org-1',
        name: 'Canvas Credentials API token',
        provider: 'canvas_credentials',
        purpose: 'api_token',
        secret_ref: 'org_secret://org-1/secret-1',
        secret_hint: '...1234',
        enabled: true,
      },
    ]);
    mockCreateCanvasIntegrationSecret.mockResolvedValue({
      id: 'secret-new',
      organization_id: 'org-1',
      name: 'Safety Course',
      provider: 'canvas_credentials',
      purpose: 'api_token',
      secret_ref: 'org_secret://org-1/secret-new',
      secret_hint: '...7890',
      enabled: true,
    });
    mockUpdateCanvasIntegrationSecret.mockResolvedValue({
      id: 'secret-1',
      organization_id: 'org-1',
      name: 'Canvas Credentials API token',
      provider: 'canvas_credentials',
      purpose: 'api_token',
      secret_ref: 'org_secret://org-1/secret-1',
      secret_hint: '...7890',
      enabled: true,
    });
    mockDiscoverCanvasScope.mockResolvedValue({
      platform_id: 'platform-1',
      organization_id: 'org-1',
      canvas_base_url: 'https://canvas.example.edu',
      courses: [{ id: 'course-101', name: 'Safety Course', type: 'course' }],
      assignments: [{ id: 'assignment-1', name: 'Safety Assignment', type: 'assignment', points_possible: 100 }],
      quizzes: [{ id: 'quiz-1', name: 'Safety Quiz', type: 'quiz', points_possible: 100 }],
      modules: [{ id: 'module-1', name: 'Safety Module', type: 'module' }],
      warnings: [],
    });
    mockListApplicationTemplates.mockResolvedValue([
      { id: 'app-template-1', name: 'Safety Application', credential_template_id: 'credential-template-1' },
    ]);
    mockListCredentialTemplates.mockResolvedValue([
      { id: 'credential-template-1', name: 'Safety Credential' },
    ]);
    mockListDeploymentProfiles.mockResolvedValue([
      {
        id: 'deployment-profile-1',
        name: 'Canvas Production Profile',
        canvas_feature_flags: binding.feature_flags,
      },
    ]);
    mockListDeliveryDestinations.mockResolvedValue([
      {
        id: 'dd-canvas-credentials-institutional',
        name: 'Canvas Credentials',
        provider: 'canvas_credentials',
        mode: 'organization_mirror',
        delivery_target: 'canvas_credentials',
        setup_actor: 'org_admin',
        is_system: true,
        is_enabled: true,
        claim_projection_policy: {
          mode: 'public_badge',
          allowed_claims: ['achievement', 'result', 'learning_context', 'issuer', 'credentialSubject', 'credentialStatus', 'provenance'],
        },
      },
    ]);
    mockCreateDeliveryDestination.mockResolvedValue({
      id: 'dd-org-canvas-credentials',
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
    mockGetCanvasMirrorHealth.mockResolvedValue({
      organization_id: 'org-1',
      pending_publish_count: 2,
      failed_publish_count: 1,
      delivered_count: 5,
      lifecycle_sync_failed_count: 1,
      lifecycle_sync_ok_count: 4,
      repeated_publish_failure_count: 1,
      repeated_lifecycle_sync_failure_count: 1,
      warning_alert_count: 1,
      critical_alert_count: 1,
      alert_count: 2,
      alerts: [
        {
          alert_type: 'lifecycle_sync_failure',
          severity: 'critical',
          delivery_record_id: 'delivery-sync-failed',
          credential_id: 'cred-sync-failed',
          transaction_id: 'tx-sync-failed',
          attempt_count: 5,
          last_error: 'Canvas status endpoint unavailable',
          message: 'Canvas mirror lifecycle status sync has failed 5 times for delivery record delivery-sync-failed.',
          recommended_action: 'Check Canvas Credentials lifecycle status sync configuration and rerun failed status syncs.',
        },
        {
          alert_type: 'publish_failure',
          severity: 'warning',
          delivery_record_id: 'delivery-publish-failed',
          credential_id: 'cred-publish-failed',
          transaction_id: 'tx-publish-failed',
          attempt_count: 3,
          last_error: 'Canvas publish endpoint unavailable',
          message: 'Canvas mirror publish has failed 3 times for delivery record delivery-publish-failed.',
          recommended_action: 'Check Canvas Credentials publish configuration and rerun the Canvas mirror automation cycle.',
        },
      ],
    });
    mockProcessPendingCanvasMirrorDeliveries.mockResolvedValue({
      processed_count: 1,
      delivered_count: 1,
      failed_count: 0,
    });
    mockProcessCanvasMirrorStatusSyncFailures.mockResolvedValue({
      processed_count: 1,
      synced_count: 1,
      failed_count: 0,
    });
    mockRunCanvasMirrorAutomationCycle.mockResolvedValue({
      processed_count: 2,
      failed_count: 0,
      blocked_count: 1,
      publish: { delivered_count: 1 },
      status_sync: { synced_count: 1 },
    });
    mockValidateCanvasCredentialsProvider.mockResolvedValue({
      ok: true,
      provider: 'badgr_api',
      api_base_url: 'https://api.badgr.test',
      assertion_scope: 'badgeclasses',
      badgeclass_id: 'badgeclass-1',
      token_configured: true,
      validation_url: 'https://api.badgr.test/v2/badgeclasses/badgeclass-1',
    });
  });

  it('shows Canvas mirror health and runs a combined automation cycle', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    expect(await screen.findByTestId('canvas-mirror-ops')).toBeInTheDocument();
    expect(await screen.findByTestId('canvas-credentials-destination')).toBeInTheDocument();
    expect(await screen.findByText('Pending publish: 2')).toBeInTheDocument();
    expect(screen.getByText('Projection: public_badge')).toBeInTheDocument();
    expect(screen.getByText(/Students can consent to Canvas display/)).toBeInTheDocument();
    expect(screen.getByText('Failed publish: 1')).toBeInTheDocument();
    expect(screen.getByText('Sync failures: 1')).toBeInTheDocument();
    expect(screen.getByText('Alerts: 2')).toBeInTheDocument();
    expect(screen.getByText(/lifecycle status sync has failed 5 times/i)).toBeInTheDocument();
    expect(screen.getByText(/Canvas status endpoint unavailable/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /run cycle/i }));

    await waitFor(() => {
      expect(mockRunCanvasMirrorAutomationCycle).toHaveBeenCalledWith({
        organizationId: 'org-1',
        limit: 25,
        retryFailed: true,
      });
    });
    expect(await screen.findByText('2 processed, 1 delivered, 1 synced, 1 blocked by profile')).toBeInTheDocument();
    expect(mockGetCanvasMirrorHealth).toHaveBeenCalledWith('org-1');
  });

  it('runs individual publish and status retry actions', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findByText('Canvas Main');

    await user.click(screen.getByRole('button', { name: /retry publish/i }));
    await waitFor(() => {
      expect(mockProcessPendingCanvasMirrorDeliveries).toHaveBeenCalledWith({
        organizationId: 'org-1',
        limit: 25,
        retryFailed: true,
      });
    });

    await user.click(screen.getByRole('button', { name: /retry status/i }));
    await waitFor(() => {
      expect(mockProcessCanvasMirrorStatusSyncFailures).toHaveBeenCalledWith({
        organizationId: 'org-1',
        limit: 25,
      });
    });
  });

  it('points Canvas Credentials destination management to credential templates', async () => {
    renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findByTestId('canvas-credentials-destination');
    expect(screen.getByRole('link', { name: /manage per badge template/i })).toHaveAttribute(
      'href',
      '/console/org/templates/credentials',
    );
    expect(screen.queryByRole('button', { name: /add org destination/i })).not.toBeInTheDocument();
    expect(mockCreateDeliveryDestination).not.toHaveBeenCalled();
  });

  it('validates Canvas Credentials provider settings from the binding dialog', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findByText('Safety Course');
    await user.click(screen.getByLabelText(/edit safety course/i));
    expect(await screen.findByText('Program')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /next/i }));
    expect((await screen.findAllByText('Canvas activity')).length).toBeGreaterThan(0);
    await user.click(screen.getByRole('button', { name: /next/i }));
    expect(await screen.findByText('Canvas Credentials provider')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /validate provider/i }));

    await waitFor(() => {
      expect(mockValidateCanvasCredentialsProvider).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: 'badgr_api',
          assertion_scope: 'badgeclasses',
        }),
        { organizationId: 'org-1' },
      );
    });
    expect(await screen.findByText('Provider validated: badgeclass-1.')).toBeInTheDocument();
  });

  it('stores a Canvas Credentials API token as a managed org secret', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findByText('Safety Course');
    await user.click(screen.getByLabelText(/edit safety course/i));
    await user.click(await screen.findByRole('button', { name: /next/i }));
    await user.click(screen.getByRole('button', { name: /next/i }));

    expect(await screen.findByText('Managed API token secret')).toBeInTheDocument();
    await user.type(screen.getByLabelText(/new token value/i), 'canvas-token-7890');
    await user.click(screen.getByRole('button', { name: /save secret/i }));

    await waitFor(() => {
      expect(mockCreateCanvasIntegrationSecret).toHaveBeenCalledWith(expect.objectContaining({
        organization_id: 'org-1',
        provider: 'canvas_credentials',
        purpose: 'api_token',
        secret_value: 'canvas-token-7890',
      }));
    });
  });

  it('discovers Canvas admin activity IDs from the binding wizard', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findByText('Safety Course');
    await user.click(screen.getByLabelText(/edit safety course/i));
    await user.click(await screen.findByRole('button', { name: /next/i }));
    expect(await screen.findByText('Import Canvas activity')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /discover/i }));

    await waitFor(() => {
      expect(mockDiscoverCanvasScope).toHaveBeenCalledWith('platform-1', expect.objectContaining({
        courseId: 'course-101',
      }));
    });
    expect((await screen.findAllByText('Imported assignment')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Imported quiz')).length).toBeGreaterThan(0);
  });
});
