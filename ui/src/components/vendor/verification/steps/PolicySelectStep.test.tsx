import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@test/utils';

import PolicySelectStep from './PolicySelectStep';

const {
  mockListPresentationPolicies,
  mockListFlows,
  mockOnChange,
} = vi.hoisted(() => ({
  mockListPresentationPolicies: vi.fn(),
  mockListFlows: vi.fn(),
  mockOnChange: vi.fn(),
}));

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      organization_id: 'org-1',
    },
  }),
}));

vi.mock('../../../../services/presentationPolicyApi', () => ({
  listPresentationPolicies: (...args: unknown[]) => mockListPresentationPolicies(...args),
}));

vi.mock('../../../../services/flowsApi', () => ({
  listFlows: (...args: unknown[]) => mockListFlows(...args),
}));

describe('PolicySelectStep', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListPresentationPolicies.mockResolvedValue({
      policies: [
        { id: 'policy-1', name: 'Open Badge Employer Review' },
      ],
    });
    mockListFlows.mockResolvedValue([
      {
        id: 'flow-1',
        name: 'Employer Badge Verification',
        flow_type: 'oid4vp_presentation',
        presentation_policy_id: 'policy-1',
        trust_profile_id: 'trust-1',
        deployment_profile_id: 'deploy-1',
      },
      {
        id: 'flow-issuance',
        name: 'Issuer Flow',
        flow_type: 'issuance',
        presentation_policy_id: 'policy-1',
      },
    ]);
  });

  it('lets a verifier start from a saved verification flow', async () => {
    const { user } = render(<PolicySelectStep value={{}} onChange={mockOnChange} />);

    expect(await screen.findByText('Select Presentation Policy')).toBeInTheDocument();
    await waitFor(() => {
      expect(mockListFlows).toHaveBeenCalledWith({ organization_id: 'org-1' });
    });

    await user.click(screen.getByRole('combobox', { name: /verification flow/i }));
    const listbox = await screen.findByRole('listbox');
    expect(within(listbox).queryByText('Issuer Flow')).not.toBeInTheDocument();
    await user.click(within(listbox).getByText('Employer Badge Verification'));

    expect(mockOnChange).toHaveBeenCalledWith(expect.objectContaining({
      flow_id: 'flow-1',
      flow_name: 'Employer Badge Verification',
      policy_id: 'policy-1',
      trust_profile_id: 'trust-1',
      deployment_profile_id: 'deploy-1',
    }));
  });

  it('surfaces verification flow load failures', async () => {
    mockListFlows.mockRejectedValue(new Error('flow service unavailable'));

    render(<PolicySelectStep value={{}} onChange={mockOnChange} />);

    expect(await screen.findByText(/flow service unavailable/i)).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: /verification flow/i })).not.toBeInTheDocument();
  });
});
