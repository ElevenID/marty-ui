import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';
import userEvent from '@testing-library/user-event';

import VerificationSessionManager from './VerificationSessionManager';

const {
  mockListFlowExecutions,
  mockStartVerificationFlow,
  mockListIssuerProfiles,
  mockListPresentationPolicies,
  mockListFlows,
} = vi.hoisted(() => ({
  mockListFlowExecutions: vi.fn(),
  mockStartVerificationFlow: vi.fn(),
  mockListIssuerProfiles: vi.fn(),
  mockListPresentationPolicies: vi.fn(),
  mockListFlows: vi.fn(),
}));

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showSuccess: vi.fn(),
  }),
}));

vi.mock('../../../services/flowsApi', () => ({
  listFlowExecutions: (...args: unknown[]) => mockListFlowExecutions(...args),
  listFlows: (...args: unknown[]) => mockListFlows(...args),
}));

vi.mock('../../../services/zkVerificationApi', () => ({
  startVerificationFlow: (...args: unknown[]) => mockStartVerificationFlow(...args),
}));

vi.mock('../../../services/signingKeysApi', () => ({
  listIssuerProfiles: (...args: unknown[]) => mockListIssuerProfiles(...args),
}));

vi.mock('../../../services/presentationPolicyApi', () => ({
  listPresentationPolicies: (...args: unknown[]) => mockListPresentationPolicies(...args),
}));

describe('VerificationSessionManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListFlowExecutions.mockResolvedValue([]);
    mockListIssuerProfiles.mockResolvedValue({
      profiles: [{
        id: 'internal-profile-1',
        issuer_did: 'did:web:verifier.example:oid4vp',
        key_purpose: 'oid4vp_request_signing',
        status: 'active',
      }],
    });
    mockListPresentationPolicies.mockResolvedValue([]);
    mockListFlows.mockResolvedValue([]);
  });

  it('lists OID4VP sessions from MIP flow instances', async () => {
    mockListFlowExecutions.mockResolvedValue([
      {
        id: 'flow-session-1',
        flow_type: 'oid4vp_presentation',
        status: 'AWAITING_WALLET',
        context_data: {
          qr_code_data: 'openid4vp://authorize?request_uri=https://example.test/request',
          request_uri: 'https://example.test/request',
        },
        created_at: '2026-05-26T20:00:00Z',
        updated_at: '2026-05-26T20:00:00Z',
      },
      {
        id: 'issuance-session-1',
        flow_type: 'oid4vci_pre_authorized',
        status: 'IN_PROGRESS',
        created_at: '2026-05-26T20:00:00Z',
        updated_at: '2026-05-26T20:00:00Z',
      },
    ]);

    render(<VerificationSessionManager organizationId="org-1" />);

    expect(await screen.findByRole('tab', { name: /active \(1\)/i })).toBeInTheDocument();
    expect(screen.getByText('Credential verification')).toBeInTheDocument();
    expect(mockListFlowExecutions).toHaveBeenCalledWith(null, { organization_id: 'org-1' });
  });

  it('surfaces current flow API errors instead of falling back to legacy verification sessions', async () => {
    mockListFlowExecutions.mockRejectedValue(new Error('Flow service unavailable'));

    render(<VerificationSessionManager organizationId="org-1" />);

    await waitFor(() => {
      expect(mockListFlowExecutions).toHaveBeenCalledWith(null, { organization_id: 'org-1' });
    });

    expect(await screen.findByRole('tab', { name: /active \(0\)/i })).toBeInTheDocument();
    expect(screen.getByText('Flow service unavailable')).toBeInTheDocument();
  });

  it('keeps cancelled verification instances out of the active queue', async () => {
    mockListFlowExecutions.mockResolvedValue([
      {
        id: 'cancelled-session-1',
        flow_type: 'oid4vp_presentation',
        status: 'CANCELLED',
        created_at: '2026-07-12T12:00:00Z',
        updated_at: '2026-07-12T12:05:00Z',
      },
    ]);

    render(<VerificationSessionManager organizationId="org-1" />);

    expect(await screen.findByRole('tab', { name: /active \(0\)/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /history \(1\)/i })).toBeInTheDocument();
  });

  it('generates the details QR code when the flow exposes only request_uri', async () => {
    const user = userEvent.setup();
    const requestUri = 'openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test%2Frequest';
    mockListFlowExecutions.mockResolvedValue([
      {
        id: 'flow-session-request-only',
        flow_type: 'oid4vp_presentation',
        status: 'AWAITING_WALLET',
        context_data: { request_uri: requestUri },
        created_at: '2026-07-13T12:00:00Z',
        updated_at: '2026-07-13T12:00:00Z',
      },
    ]);

    render(<VerificationSessionManager organizationId="org-1" />);

    await user.click(await screen.findByRole('button', { name: 'Show QR code' }));

    expect(await screen.findByRole('img', { name: 'OID4VP QR Code' })).toHaveAttribute(
      'data-qr-value',
      requestUri,
    );
  });

  it('starts verification with the organization issuer DID and no public profile ID', async () => {
    const user = userEvent.setup();
    mockListPresentationPolicies.mockResolvedValue([
      { id: 'policy-1', name: 'Employment proof' },
    ]);
    mockStartVerificationFlow.mockResolvedValue({
      instance_id: 'flow-1',
      request_uri: 'openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test%2Frequest',
      status: 'AWAITING_WALLET',
    });

    render(<VerificationSessionManager organizationId="org-1" />);

    const newVerification = await screen.findByRole('button', { name: 'New Verification' });
    await waitFor(() => expect(newVerification).toBeEnabled());
    await user.click(newVerification);
    await user.click(await screen.findByLabelText('Presentation Policy'));
    await user.click(await screen.findByRole('option', { name: 'Employment proof' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Start Session' }));

    await waitFor(() => {
      expect(mockStartVerificationFlow).toHaveBeenCalledWith({
        organization_id: 'org-1',
        issuer_did: 'did:web:verifier.example:oid4vp',
        presentation_policy_id: 'policy-1',
        trust_profile_id: undefined,
        deployment_profile_id: undefined,
        external_reference: undefined,
      });
    });
    expect(mockStartVerificationFlow.mock.calls[0][0]).not.toHaveProperty('issuer_profile_id');
  });
});
