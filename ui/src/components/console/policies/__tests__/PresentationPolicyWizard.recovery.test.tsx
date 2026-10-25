import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { render } from '@test/utils';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import Wizard from '../PresentationPolicyWizard';
import { createPresentationPolicy, activatePresentationPolicy, getPresentationPolicy } from '../../../../services/presentationPolicyApi';
const scope = vi.hoisted(() => ({ organization: 'org-a', principal: 'user-a', navigate: vi.fn() }));
vi.mock('react-router', async () => ({ ...await vi.importActual('react-router'), useNavigate: () => scope.navigate }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.organization }) }));
vi.mock('../../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: scope.principal } }) }));
vi.mock('../../../../services/presentationPolicyApi', () => ({
  buildPresentationPolicyPayload: ({ activate_immediately, ...data }) => data,
  createPresentationPolicy: vi.fn(), getPresentationPolicy: vi.fn(), activatePresentationPolicy: vi.fn(),
  getTrustProfile: vi.fn(async () => ({ id: 'trust', organization_id: scope.organization, status: 'active' })),
  getCredentialTemplate: vi.fn(),
}));
vi.mock('../steps', () => ({
  TrustProfileStep: ({ onSelectTrustProfile }) => <button onClick={() => onSelectTrustProfile({ id: 'trust' })}>Select trust</button>,
  TemplateSelectionStep: ({ onSelectTemplate }) => <button onClick={() => onSelectTemplate({ id: 'custom' })}>Select custom</button>,
  ClaimsConfigurationStep: ({ onConfigChange }) => <button onClick={() => onConfigChange({ name: 'Policy', purpose: 'Test', required_claims: [{ claim_name: 'name' }] })}>Set claims</button>,
  FreshnessBindingStep: () => <div>Binding</div>, ReviewStep: () => <div>Review settings</div>,
}));
const draft = { id: 'policy-a', organization_id: 'org-a', status: 'draft' };
async function ready() {
  fireEvent.click(screen.getByText('Select trust'));
  fireEvent.click(screen.getByTestId('wizard.policy.next'));
  fireEvent.click(screen.getByText('Select custom'));
  fireEvent.click(screen.getByTestId('wizard.policy.next'));
  fireEvent.click(screen.getByText('Set claims'));
  fireEvent.click(screen.getByTestId('wizard.policy.next'));
  fireEvent.click(screen.getByTestId('wizard.policy.next'));
}
beforeEach(() => {
  vi.clearAllMocks(); sessionStorage.clear(); vi.stubGlobal('crypto', webcrypto);
  scope.organization = 'org-a'; scope.principal = 'user-a';
  vi.mocked(createPresentationPolicy).mockResolvedValue(draft);
  vi.mocked(getPresentationPolicy).mockResolvedValue(draft);
  vi.mocked(activatePresentationPolicy).mockResolvedValue({ ...draft, status: 'active' });
});
afterEach(() => { vi.useRealTimers(); });
describe('mounted policy recovery and scope lifecycle', () => {
  it('retries activation of the same acknowledged draft', async () => {
    vi.mocked(activatePresentationPolicy).mockRejectedValueOnce(Object.assign(new Error('Activation unavailable'), { status: 503 }));
    render(<Wizard />); await ready();
    fireEvent.click(screen.getByTestId('wizard.policy.submit'));
    await screen.findByText('Policy policy-a was created. Retry to recover its activation.');
    fireEvent.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(activatePresentationPolicy).toHaveBeenCalledTimes(2));
    expect(createPresentationPolicy).toHaveBeenCalledTimes(1);
    expect(activatePresentationPolicy).toHaveBeenLastCalledWith('policy-a');
  });
  it.each(['organization', 'principal'] as const)('invalidates late create and resets selections on %s switch', async (field) => {
    let resolve!: (value: typeof draft) => void;
    vi.mocked(createPresentationPolicy).mockImplementationOnce(() => new Promise((r) => { resolve = r; }));
    const view = render(<Wizard />); await ready();
    fireEvent.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(createPresentationPolicy).toHaveBeenCalledTimes(1));
    scope[field] = 'new-scope'; view.rerender(<Wizard />);
    expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
    await act(async () => { resolve(draft); });
    expect(activatePresentationPolicy).not.toHaveBeenCalled();
    expect(scope.navigate).not.toHaveBeenCalled();
    expect(screen.queryByText(/Policy policy-a was created/)).not.toBeInTheDocument();
    expect(JSON.parse(sessionStorage.getItem('marty:policy-create:v1:org-a')!).resourceId).toBe('policy-a');
  });
  it('cancels success navigation on scope change', async () => {
    const view = render(<Wizard />); await ready();
    fireEvent.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(activatePresentationPolicy).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(sessionStorage.getItem('marty:policy-create:v1:org-a')).toBeNull());
    vi.useFakeTimers(); scope.organization = 'org-b'; view.rerender(<Wizard />);
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(scope.navigate).not.toHaveBeenCalled();
    expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
  });
});
