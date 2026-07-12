import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import VerificationSessionManager from './VerificationSessionManager';

const {
  mockListFlowExecutions,
  mockStartVerificationFlow,
} = vi.hoisted(() => ({
  mockListFlowExecutions: vi.fn(),
  mockStartVerificationFlow: vi.fn(),
}));

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showSuccess: vi.fn(),
  }),
}));

vi.mock('../../../services/flowsApi', () => ({
  listFlowExecutions: (...args: unknown[]) => mockListFlowExecutions(...args),
}));

vi.mock('../../../services/zkVerificationApi', () => ({
  startVerificationFlow: (...args: unknown[]) => mockStartVerificationFlow(...args),
}));

describe('VerificationSessionManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListFlowExecutions.mockResolvedValue([]);
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
});
