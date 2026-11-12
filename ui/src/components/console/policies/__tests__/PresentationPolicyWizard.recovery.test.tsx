import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { render } from '@test/utils';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import i18n from 'i18next';
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
  ClaimsConfigurationStep: ({ policyConfig, onConfigChange }) => <button onClick={() => onConfigChange({ ...policyConfig, name: 'Policy', purpose: 'Test', accepted_credential_types: ['urn:example:member'], required_claims: [{ claim_name: 'name', credential_type: 'urn:example:member' }] })}>Set claims</button>,
  FreshnessBindingStep: () => <div>Binding</div>,
  ReviewStep: ({ data, onToggleActivation }) => <>
    <div>Review settings</div>
    <label><input type="checkbox" checked={data.activateImmediately}
      onChange={(event) => onToggleActivation(event.target.checked)} />Activate immediately</label>
  </>,
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
async function finishCreation(activateImmediately: boolean, status: string) {
  const created = { ...draft, id: 'policy/created?source=wizard' };
  const result = { ...created, status };
  let resolve!: (value: typeof result) => void;
  vi.mocked(createPresentationPolicy).mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
  vi.mocked(getPresentationPolicy).mockResolvedValue(created);
  vi.mocked(activatePresentationPolicy).mockResolvedValue(result);
  const view = render(<Wizard />);
  await ready();
  if (!activateImmediately) fireEvent.click(screen.getByRole('checkbox', { name: 'Activate immediately' }));
  fireEvent.click(screen.getByTestId('wizard.policy.submit'));
  await waitFor(() => expect(createPresentationPolicy).toHaveBeenCalledTimes(1));
  // Install the clock before the response schedules delayed success navigation.
  vi.useFakeTimers();
  await act(async () => { resolve(activateImmediately ? created : result); });
  return view;
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
  it('uses readable draft redirect copy when the loaded locale predates the new key', async () => {
    const copy = i18n.getResourceBundle('en', 'console').wizards.presentationPolicy.success;
    const redirectingDraft = copy.redirectingDraft;
    delete copy.redirectingDraft;
    try {
      await finishCreation(false, 'draft');
      expect(screen.getByText('Opening the saved policy draft...')).toBeInTheDocument();
      expect(screen.queryByText('wizards.presentationPolicy.success.redirectingDraft')).not.toBeInTheDocument();
      await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
      expect(scope.navigate).toHaveBeenCalledWith('/console/org/policies/presentation/policy%2Fcreated%3Fsource%3Dwizard');
    } finally {
      copy.redirectingDraft = redirectingDraft;
    }
  });

  it.each([
    { activateImmediately: false, status: 'DRAFT', active: false },
    { activateImmediately: true, status: 'ACTIVE', active: true },
    { activateImmediately: true, status: 'DRAFT', active: false },
  ])('uses returned $status for delayed completion (activation requested: $activateImmediately)', async ({ activateImmediately, status, active }) => {
    await finishCreation(activateImmediately, status);
    expect(screen.getByText(active ? '"Policy" is active and ready to use.' : '"Policy" is saved as draft.')).toBeInTheDocument();
    expect(screen.getByText(active ? 'Redirecting to Deployment Profiles...' : 'Opening the saved policy draft...')).toBeInTheDocument();
    expect(activatePresentationPolicy).toHaveBeenCalledTimes(activateImmediately ? 1 : 0);
    expect(scope.navigate).not.toHaveBeenCalled();
    await act(async () => { await vi.advanceTimersByTimeAsync(1499); });
    expect(scope.navigate).not.toHaveBeenCalled();
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(scope.navigate).toHaveBeenCalledTimes(1);
    expect(scope.navigate).toHaveBeenCalledWith(active
      ? '/console/org/deploy/profiles'
      : '/console/org/policies/presentation/policy%2Fcreated%3Fsource%3Dwizard');
  });

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
  it.each([
    { status: 'draft', change: 'organization' },
    { status: 'draft', change: 'principal' },
    { status: 'draft', change: 'unmount' },
    { status: 'active', change: 'organization' },
    { status: 'active', change: 'principal' },
    { status: 'active', change: 'unmount' },
  ] as const)('cancels $status success navigation on $change', async ({ status, change }) => {
    const view = await finishCreation(status === 'active', status);
    expect(sessionStorage.getItem('marty:policy-create:v1:org-a')).toBeNull();
    if (change === 'unmount') view.unmount();
    else {
      scope[change] = 'new-scope';
      view.rerender(<Wizard />);
      expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
    }
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(scope.navigate).not.toHaveBeenCalled();
  });
});
