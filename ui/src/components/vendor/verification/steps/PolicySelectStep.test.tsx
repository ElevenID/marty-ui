import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor, within } from '@test/utils';

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

vi.mock('../../../../services/presentationPolicyApi', () => ({
  listPresentationPolicies: (...args: unknown[]) => mockListPresentationPolicies(...args),
}));

vi.mock('../../../../services/flowsApi', () => ({
  listFlows: (...args: unknown[]) => mockListFlows(...args),
}));

describe('PolicySelectStep', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListPresentationPolicies.mockResolvedValue([
      { id: 'policy-1', name: 'Open Badge Employer Review', status: 'active' },
    ]);
    mockListFlows.mockResolvedValue([
      {
        id: 'flow-1',
        name: 'Employer Badge Verification',
        status: 'ACTIVE',
        flow_type: 'oid4vp_presentation',
        presentation_policy_id: 'policy-1',
        trust_profile_id: 'trust-1',
        deployment_profile_id: 'deploy-1',
      },
      {
        id: 'flow-issuance',
        name: 'Issuer Flow',
        status: 'ACTIVE',
        flow_type: 'issuance',
        presentation_policy_id: 'policy-1',
      },
      {
        id: 'flow-draft',
        name: 'Draft Verification',
        status: 'DRAFT',
        flow_type: 'oid4vp',
        presentation_policy_id: 'policy-1',
      },
      {
        id: 'flow-missing-policy',
        name: 'Unavailable Policy Flow',
        status: 'ACTIVE',
        flow_type: 'oid4vp',
        presentation_policy_id: 'missing-policy',
      },
    ]);
  });

  it('lets a verifier start from a saved verification flow', async () => {
    const { user } = render(<PolicySelectStep value={{}} onChange={mockOnChange} organizationId="org-1" />);

    expect(await screen.findByText('Select Presentation Policy')).toBeInTheDocument();
    await waitFor(() => {
      expect(mockListFlows).toHaveBeenCalledWith({ organization_id: 'org-1', limit: 100, offset: 0 });
    });

    await user.click(screen.getByRole('combobox', { name: /verification flow/i }));
    const listbox = await screen.findByRole('listbox');
    expect(within(listbox).queryByText('Issuer Flow')).not.toBeInTheDocument();
    expect(within(listbox).queryByText('Draft Verification')).not.toBeInTheDocument();
    expect(within(listbox).queryByText('Unavailable Policy Flow')).not.toBeInTheDocument();
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

    render(<PolicySelectStep value={{}} onChange={mockOnChange} organizationId="org-1" />);

    expect(await screen.findByText(/flow service unavailable/i)).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: /verification flow/i })).not.toBeInTheDocument();
    expect(screen.queryByText('No active presentation policies')).not.toBeInTheDocument();
  });

  it('retries after a malformed policy response', async () => {
    mockListPresentationPolicies
      .mockRejectedValueOnce(new Error('Presentation Policy service returned a malformed list response.'))
      .mockResolvedValueOnce([{ id: 'policy-1', name: 'Recovered Policy', status: 'active' }]);

    const { user } = render(<PolicySelectStep value={{}} onChange={mockOnChange} organizationId="org-1" />);

    expect(await screen.findByText(/malformed list response/i)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /retry/i }));

    expect(await screen.findByRole('combobox', { name: /presentation policy/i })).toBeInTheDocument();
    expect(mockListPresentationPolicies).toHaveBeenCalledTimes(2);
  });

  it.each([
    { policies: [] },
    { policies: [{ id: 'draft', name: 'Draft Policy', status: 'DRAFT' }, { id: 'unknown', name: 'Unknown Status' }] },
  ])('explains missing active prerequisites without an unsupported ad-hoc escape', async ({ policies }) => {
    mockListPresentationPolicies.mockResolvedValue(policies);
    mockListFlows.mockResolvedValue([]);
    const onValidityChange = vi.fn();
    render(<PolicySelectStep value={{}} onChange={mockOnChange} organizationId="org-1" onValidityChange={onValidityChange} />);

    expect(await screen.findByRole('alert')).toHaveTextContent('No active presentation policies');
    expect(screen.getByRole('link', { name: 'Manage Presentation Policies' })).toHaveAttribute('href', '/console/org/policies/presentation');
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
    expect(screen.queryByText(/ad-hoc|editing the session request/i)).not.toBeInTheDocument();
    expect(onValidityChange).toHaveBeenLastCalledWith(false);
  });

  it('keeps selection unavailable during loading and validates only a loaded active policy', async () => {
    let resolvePolicies!: (policies: unknown[]) => void;
    mockListPresentationPolicies.mockReturnValue(new Promise((resolve) => { resolvePolicies = resolve; }));
    const onValidityChange = vi.fn();
    render(<PolicySelectStep value={{ policy_id: 'policy-1' }} onChange={mockOnChange} organizationId="org-1" onValidityChange={onValidityChange} />);

    expect(screen.getByRole('progressbar', { name: 'Loading verification policies and flows' })).toBeInTheDocument();
    expect(screen.queryByText('No active presentation policies')).not.toBeInTheDocument();
    expect(onValidityChange).toHaveBeenLastCalledWith(false);
    await act(async () => { resolvePolicies([{ id: 'policy-1', name: 'Loaded Policy', status: 'active' }]); });
    expect(await screen.findByRole('combobox', { name: 'Presentation Policy' })).toBeInTheDocument();
    expect(onValidityChange).toHaveBeenLastCalledWith(true);
  });

  it('finds active policies after a full page of drafts before declaring prerequisites absent', async () => {
    mockListPresentationPolicies
      .mockResolvedValueOnce(Array.from({ length: 100 }, (_, index) => ({ id: `draft-${index}`, status: 'DRAFT' })))
      .mockResolvedValueOnce([{ id: 'policy-1', name: 'Later Active Policy', status: 'ACTIVE' }]);
    const { user } = render(<PolicySelectStep value={{}} onChange={mockOnChange} organizationId="org-1" />);

    await user.click(await screen.findByRole('combobox', { name: 'Presentation Policy' }));
    expect(await screen.findByRole('option', { name: 'Later Active Policy' })).toBeInTheDocument();
    expect(mockListPresentationPolicies).toHaveBeenLastCalledWith({ organization_id: 'org-1', limit: 100, offset: 100 });
    expect(screen.queryByText('No active presentation policies')).not.toBeInTheDocument();
  });

  it('allows a saved policy when a previously selected flow is no longer available and clears its overrides', async () => {
    mockListFlows.mockResolvedValue([]);
    const onValidityChange = vi.fn();
    const { user } = render(<PolicySelectStep
      value={{ flow_id: 'old-flow', policy_id: 'policy-1', trust_profile_id: 'old-trust', deployment_profile_id: 'old-deployment' }}
      onChange={mockOnChange}
      organizationId="org-1"
      onValidityChange={onValidityChange}
    />);

    expect(await screen.findByRole('alert')).toHaveTextContent('No active verification flows are available');
    expect(onValidityChange).toHaveBeenLastCalledWith(false);
    await user.click(screen.getByRole('combobox', { name: 'Presentation Policy' }));
    await user.click(await screen.findByRole('option', { name: 'Open Badge Employer Review' }));
    expect(mockOnChange).toHaveBeenCalledWith(expect.objectContaining({
      flow_id: null, flow_name: null, policy_id: 'policy-1', trust_profile_id: null, deployment_profile_id: null,
    }));
  });
});
