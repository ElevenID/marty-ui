import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import CanvasIntegrationsPage, {
  buildCanvasBindingScope,
  buildCanvasScope,
  requirementFormFields,
} from './CanvasIntegrationsPage';

const {
  mockListCanvasPlatforms,
  mockListCanvasProgramBindings,
  mockListCanvasIntegrationSecrets,
  mockCreateCanvasIntegrationSecret,
  mockUpdateCanvasIntegrationSecret,
  mockDiscoverCanvasScope,
  mockGetCanvasLtiRegistrationConfig,
  mockGetCanvasPlatformReadiness,
  mockStartCanvasOAuthConnection,
  mockDisconnectCanvasOAuthConnection,
  mockFinalizeCanvasLtiInstallation,
  mockListCanvasSyncJobs,
  mockListCanvasAwardCandidates,
  mockListCanvasEvidencePolicyReviews,
  mockRetryCanvasSyncJob,
  mockResolveCanvasSyncJob,
  mockResolveCanvasEvidencePolicyReview,
  mockValidateCanvasProgramBinding,
  mockActivateCanvasProgramBinding,
  mockDeactivateCanvasProgramBinding,
  mockUpdateCanvasProgramBinding,
  mockUpdateCanvasPlatform,
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
  mockCanCanvas,
  mockPermissionsState,
} = vi.hoisted(() => ({
  mockListCanvasPlatforms: vi.fn(),
  mockListCanvasProgramBindings: vi.fn(),
  mockListCanvasIntegrationSecrets: vi.fn(),
  mockCreateCanvasIntegrationSecret: vi.fn(),
  mockUpdateCanvasIntegrationSecret: vi.fn(),
  mockDiscoverCanvasScope: vi.fn(),
  mockGetCanvasLtiRegistrationConfig: vi.fn(),
  mockGetCanvasPlatformReadiness: vi.fn(),
  mockStartCanvasOAuthConnection: vi.fn(),
  mockDisconnectCanvasOAuthConnection: vi.fn(),
  mockFinalizeCanvasLtiInstallation: vi.fn(),
  mockListCanvasSyncJobs: vi.fn(),
  mockListCanvasAwardCandidates: vi.fn(),
  mockListCanvasEvidencePolicyReviews: vi.fn(),
  mockRetryCanvasSyncJob: vi.fn(),
  mockResolveCanvasSyncJob: vi.fn(),
  mockResolveCanvasEvidencePolicyReview: vi.fn(),
  mockValidateCanvasProgramBinding: vi.fn(),
  mockActivateCanvasProgramBinding: vi.fn(),
  mockDeactivateCanvasProgramBinding: vi.fn(),
  mockUpdateCanvasProgramBinding: vi.fn(),
  mockUpdateCanvasPlatform: vi.fn(),
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
  mockCanCanvas: vi.fn(),
  mockPermissionsState: { isLoading: false },
}));

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}));

vi.mock('../../../hooks/usePermissions', () => ({
  usePermissions: () => ({
    can: mockCanCanvas,
    isLoading: mockPermissionsState.isLoading,
  }),
}));

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
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
  getCanvasLtiRegistrationConfig: (...args: unknown[]) => mockGetCanvasLtiRegistrationConfig(...args),
  getCanvasPlatformReadiness: (...args: unknown[]) => mockGetCanvasPlatformReadiness(...args),
  startCanvasOAuthConnection: (...args: unknown[]) => mockStartCanvasOAuthConnection(...args),
  disconnectCanvasOAuthConnection: (...args: unknown[]) => mockDisconnectCanvasOAuthConnection(...args),
  finalizeCanvasLtiInstallation: (...args: unknown[]) => mockFinalizeCanvasLtiInstallation(...args),
  listCanvasSyncJobs: (...args: unknown[]) => mockListCanvasSyncJobs(...args),
  listCanvasAwardCandidates: (...args: unknown[]) => mockListCanvasAwardCandidates(...args),
  listCanvasEvidencePolicyReviews: (...args: unknown[]) => mockListCanvasEvidencePolicyReviews(...args),
  retryCanvasSyncJob: (...args: unknown[]) => mockRetryCanvasSyncJob(...args),
  resolveCanvasSyncJob: (...args: unknown[]) => mockResolveCanvasSyncJob(...args),
  resolveCanvasEvidencePolicyReview: (...args: unknown[]) => mockResolveCanvasEvidencePolicyReview(...args),
  validateCanvasProgramBinding: (...args: unknown[]) => mockValidateCanvasProgramBinding(...args),
  activateCanvasProgramBinding: (...args: unknown[]) => mockActivateCanvasProgramBinding(...args),
  deactivateCanvasProgramBinding: (...args: unknown[]) => mockDeactivateCanvasProgramBinding(...args),
  getCanvasMirrorHealth: (...args: unknown[]) => mockGetCanvasMirrorHealth(...args),
  processPendingCanvasMirrorDeliveries: (...args: unknown[]) => mockProcessPendingCanvasMirrorDeliveries(...args),
  processCanvasMirrorStatusSyncFailures: (...args: unknown[]) => mockProcessCanvasMirrorStatusSyncFailures(...args),
  runCanvasMirrorAutomationCycle: (...args: unknown[]) => mockRunCanvasMirrorAutomationCycle(...args),
  validateCanvasCredentialsProvider: (...args: unknown[]) => mockValidateCanvasCredentialsProvider(...args),
  createCanvasPlatform: vi.fn(),
  createCanvasProgramBinding: vi.fn(),
  deleteCanvasPlatform: vi.fn(),
  deleteCanvasProgramBinding: vi.fn(),
  updateCanvasPlatform: (...args: unknown[]) => mockUpdateCanvasPlatform(...args),
  updateCanvasProgramBinding: (...args: unknown[]) => mockUpdateCanvasProgramBinding(...args),
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
  lti_deployment_id: 'deployment-1',
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
  evidence_requirements: [{
    requirement_id: 'course-completion',
    source: 'canvas_rest',
    fact_type: 'canvas.course_completion',
    scope: { course_id: 'course-101' },
    pass_rule: { completed: true },
    required: true,
  }],
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
  it('emits only the canonical activity identifier for the current typed rule', () => {
    const common = {
      course_id: 'course-101',
      assignment_id: 'assignment-current',
      quiz_id: 'quiz-assignment-current',
      module_id: 'module-stale',
      evidence_source: 'canvas_rest',
    };

    expect(buildCanvasScope({ ...common, evidence_type: 'canvas.assignment_score' })).toEqual({
      course_id: 'course-101',
      activity_id: 'assignment-current',
    });
    expect(buildCanvasScope({ ...common, evidence_type: 'canvas.quiz_score' })).toEqual({
      course_id: 'course-101',
      activity_id: 'quiz-assignment-current',
    });
    expect(buildCanvasScope({ ...common, evidence_type: 'canvas.module_completion' })).toEqual({
      course_id: 'course-101',
      module_id: 'module-stale',
    });
    expect(buildCanvasScope({
      ...common,
      evidence_type: 'canvas.assignment_score',
      evidence_source: 'ags_result',
    })).toEqual({ course_id: 'course-101' });

    expect(buildCanvasBindingScope({ ...common, evidence_type: 'canvas.assignment_score' })).toEqual({
      course_id: 'course-101',
      assignment_id: 'assignment-current',
    });
    expect(buildCanvasBindingScope({ ...common, evidence_type: 'canvas.quiz_score' })).toEqual({
      course_id: 'course-101',
      quiz_id: 'quiz-assignment-current',
    });

    expect(requirementFormFields({
      fact_type: 'canvas.quiz_score',
      source: 'canvas_rest',
      scope: { course_id: 'course-101', activity_id: 'quiz-assignment-current' },
      pass_rule: { min_score_percent: 80 },
    })).toEqual(expect.objectContaining({
      assignment_id: '',
      quiz_id: 'quiz-assignment-current',
      min_score_percent: 80,
    }));
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mockPermissionsState.isLoading = false;
    mockCanCanvas.mockImplementation((resource, action) => (
      resource === 'integration-connector'
      && ['view', 'create', 'edit', 'delete'].includes(action)
    ));
    mockListCanvasPlatforms.mockResolvedValue([platform]);
    mockGetCanvasLtiRegistrationConfig.mockResolvedValue({
      platform_id: 'platform-1',
      developer_key_configuration: { title: 'Marty Portable Credentials' },
    });
    mockStartCanvasOAuthConnection.mockResolvedValue({ authorization_url: 'https://canvas.example.edu/login/oauth2/auth' });
    mockDisconnectCanvasOAuthConnection.mockResolvedValue({ status: 'disconnected' });
    mockFinalizeCanvasLtiInstallation.mockResolvedValue({ platform_id: 'platform-1' });
    mockGetCanvasPlatformReadiness.mockResolvedValue({
      platform_id: 'platform-1',
      ready: false,
      checks: [
        {
          code: 'canvas_oauth',
          component: 'Canvas OAuth',
          status: 'fail',
          blocking: true,
          remediation: 'Authorize the required Canvas capabilities.',
        },
      ],
    });
    mockListCanvasSyncJobs.mockResolvedValue([{
      id: 'job-1',
      target_id: 'target-1',
      target_type: 'application_evidence',
      application_id: 'application-1',
      status: 'dead_letter',
      attempt_count: 8,
      max_attempts: 8,
      last_error_code: 'canvas_rate_limited',
      last_error_summary: 'Canvas synchronization exhausted its retry budget.',
    }]);
    mockListCanvasAwardCandidates.mockResolvedValue([
      { id: 'candidate-1', binding_id: 'binding-1', status: 'pending_claim' },
      { id: 'candidate-2', binding_id: 'binding-1', status: 'identity_link_required' },
    ]);
    mockListCanvasEvidencePolicyReviews.mockResolvedValue([{
      id: 'review-1',
      credential_id: 'credential-1',
      application_id: 'application-1',
      status: 'open',
    }]);
    mockRetryCanvasSyncJob.mockResolvedValue({ id: 'job-1', status: 'queued' });
    mockResolveCanvasSyncJob.mockResolvedValue({ id: 'job-1', status: 'cancelled' });
    mockResolveCanvasEvidencePolicyReview.mockResolvedValue({ id: 'review-1', status: 'resolved' });
    mockValidateCanvasProgramBinding.mockResolvedValue({ ready: true, checks: [] });
    mockActivateCanvasProgramBinding.mockResolvedValue({ enabled: true });
    mockDeactivateCanvasProgramBinding.mockResolvedValue({ enabled: false });
    mockUpdateCanvasProgramBinding.mockResolvedValue(binding);
    mockUpdateCanvasPlatform.mockResolvedValue(platform);
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

  it('fails closed without loading Canvas data while connector permissions are loading', async () => {
    mockPermissionsState.isLoading = true;

    renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    expect(screen.getByText(/Checking your Canvas integration permissions/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Platform$/i })).not.toBeInTheDocument();
    await waitFor(() => expect(mockListCanvasPlatforms).not.toHaveBeenCalled());
    expect(mockListCanvasProgramBindings).not.toHaveBeenCalled();
  });

  it('keeps a view-only Canvas console read-only', async () => {
    mockCanCanvas.mockImplementation((resource, action) => (
      resource === 'integration-connector' && action === 'view'
    ));

    renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    expect((await screen.findAllByText('Canvas Main')).length).toBeGreaterThan(0);
    expect(screen.queryByRole('button', { name: /^Platform$/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Edit Safety Course/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Archive Safety Course/i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Retry dead letter/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Resolve dead letter/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Run cycle/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /^Dismiss$/i })).toBeDisabled();
  });

  it('allows a new binding to advance after its application template is selected', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findAllByText('Canvas Main');
    const addBinding = screen.getByRole('button', { name: /^Binding$/i });
    await waitFor(() => expect(addBinding).toBeEnabled());
    await user.click(addBinding);
    expect(await screen.findByRole('dialog', { name: /Add Canvas binding/i })).toBeInTheDocument();

    await user.click(screen.getAllByRole('combobox')[2]);
    await user.click(await screen.findByRole('option', { name: 'Safety Application' }));

    const next = screen.getByRole('button', { name: /^Next$/i });
    expect(next).toBeEnabled();
    await user.click(next);
    expect(await screen.findByText('Import Canvas activity')).toBeInTheDocument();
  });

  it('accepts not-applicable readiness but locks a binding when any rule is legacy', async () => {
    mockGetCanvasPlatformReadiness.mockResolvedValue({
      platform_id: 'platform-1',
      ready: true,
      checks: [{
        code: 'canvas_credentials_projection',
        component: 'Canvas Credentials projection',
        status: 'not_applicable',
        blocking: true,
        remediation: 'No projection is configured.',
      }],
    });
    mockListCanvasProgramBindings.mockResolvedValue([{
      ...binding,
      evidence_requirements: [
        binding.evidence_requirements[0],
        { fact_type: 'canvas.assignment_score', source: 'custom_webhook' },
      ],
    }]);

    renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    expect(await screen.findByText('Not applicable')).toBeInTheDocument();
    expect(screen.queryByText(/Activation is blocked by/i)).not.toBeInTheDocument();
    expect(await screen.findByText(/Legacy binding: migration review required/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Validate Safety Course/i)).toBeDisabled();
    expect(screen.getByLabelText(/Deactivate Safety Course/i)).toBeDisabled();
    expect(screen.getByLabelText(/Edit Safety Course/i)).toBeDisabled();
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

  it('shows blocking readiness and the portable award pipeline', async () => {
    renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    expect(await screen.findByTestId('canvas-readiness')).toBeInTheDocument();
    expect(await screen.findByText('Canvas OAuth')).toBeInTheDocument();
    expect(screen.getByText(/Activation is blocked by 1 readiness check/)).toBeInTheDocument();
    expect(await screen.findByTestId('canvas-portable-operations')).toBeInTheDocument();
    expect(screen.getByText('Sync jobs: 1')).toBeInTheDocument();
    expect(screen.getByText('Pending awards: 1')).toBeInTheDocument();
    expect(screen.getByText('Identity links required: 1')).toBeInTheDocument();
    expect(screen.getByText('Correction reviews: 1')).toBeInTheDocument();
  });

  it('retries or resolves dead-letter sync jobs and resolves correction reviews', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await user.click(await screen.findByRole('button', { name: /retry dead letter/i }));
    await waitFor(() => expect(mockRetryCanvasSyncJob).toHaveBeenCalledWith('job-1'));

    await user.click(await screen.findByRole('button', { name: /resolve dead letter/i }));
    await waitFor(() => expect(mockResolveCanvasSyncJob).toHaveBeenCalledWith('job-1'));
    expect(confirm).toHaveBeenCalledWith(expect.stringMatching(/leave its synchronization target stopped/i));

    await user.click(await screen.findByRole('button', { name: /^dismiss$/i }));
    await waitFor(() => {
      expect(mockResolveCanvasEvidencePolicyReview).toHaveBeenCalledWith('review-1', 'dismiss');
    });
    confirm.mockRestore();
  });

  it('validates and deactivates an active program binding through explicit actions', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findByText('Safety Course');
    await user.click(screen.getByLabelText(/validate safety course/i));
    await waitFor(() => expect(mockValidateCanvasProgramBinding).toHaveBeenCalledWith('binding-1'));
    expect((await screen.findAllByText('Ready')).length).toBeGreaterThan(0);

    await user.click(screen.getByLabelText(/deactivate safety course/i));
    await waitFor(() => expect(mockDeactivateCanvasProgramBinding).toHaveBeenCalledWith('binding-1'));
  });

  it('finalizes entered client and deployment IDs through the LTI installation endpoint', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findAllByText('Canvas Main');
    await user.click(screen.getAllByRole('button', { name: /^edit$/i })[0]);
    expect(await screen.findByRole('dialog', { name: /edit canvas platform/i })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^save$/i }));

    await waitFor(() => {
      expect(mockUpdateCanvasPlatform).toHaveBeenCalledWith('platform-1', {
        display_name: 'Canvas Main',
        canvas_base_url: 'https://canvas.example.edu',
        lti_client_id: 'client-1',
        lti_deployment_id: 'deployment-1',
        enabled: true,
      });
      expect(mockFinalizeCanvasLtiInstallation).toHaveBeenCalledWith('platform-1', {
        lti_client_id: 'client-1',
        lti_deployment_id: 'deployment-1',
      });
    });
  });

  it('runs individual publish and status retry actions', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findAllByText('Canvas Main');

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
    expect((await screen.findAllByText('Imported quiz assignment')).length).toBeGreaterThan(0);
  });

  it('creates and saves multiple independently typed evidence requirements', async () => {
    const { user } = renderWithRouter(<CanvasIntegrationsPage />, {
      initialEntries: ['/console/org/deploy/canvas'],
    });

    await screen.findByText('Safety Course');
    await user.click(screen.getByLabelText(/edit safety course/i));
    await user.click(await screen.findByRole('button', { name: /next/i }));
    await user.click(await screen.findByRole('button', { name: /add requirement/i }));

    expect(screen.getByRole('button', { name: /rule 1: course completion/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /rule 2: course completion/i })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /next/i }));
    await user.click(await screen.findByRole('button', { name: /^save$/i }));

    await waitFor(() => {
      expect(mockUpdateCanvasProgramBinding).toHaveBeenCalledWith(
        'binding-1',
        expect.objectContaining({
          evidence_requirements: [
            expect.objectContaining({
              requirement_id: 'course-completion',
              source: 'canvas_rest',
              fact_type: 'canvas.course_completion',
            }),
            expect.objectContaining({
              source: 'canvas_rest',
              fact_type: 'canvas.course_completion',
            }),
          ],
        }),
      );
    });
    const savedPayload = mockUpdateCanvasProgramBinding.mock.calls[0][1];
    expect(savedPayload).not.toHaveProperty('organization_id');
    expect(savedPayload).not.toHaveProperty('flow_mode');
    expect(savedPayload).not.toHaveProperty('direct_issue_enabled');
    expect(savedPayload).not.toHaveProperty('enabled');
    expect(savedPayload.evidence_requirements[0]).not.toHaveProperty('provider');
  });
});
