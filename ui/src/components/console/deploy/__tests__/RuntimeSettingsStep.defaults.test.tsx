import { useCallback, useState } from 'react';
import { act, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from '@test/utils';
import Step from '../steps/RuntimeSettingsStep';
import { getOrganizationDefaults } from '../../../../services/organizationsApi';
import { listCredentialTemplates, listPresentationPolicies } from '../../../../services/presentationPolicyApi';

const scope = vi.hoisted(() => ({ organizationId: 'org-a' }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.organizationId }) }));
vi.mock('../../../../services/organizationsApi', () => ({ getOrganizationDefaults: vi.fn() }));
vi.mock('../../../../services/presentationPolicyApi', () => ({ listCredentialTemplates: vi.fn(), listPresentationPolicies: vi.fn() }));
vi.mock('../../../../services/flowsApi', () => ({ listFlows: async () => [] }));

const resource = (id: string, overrides = {}) => ({
  id, name: id, organization_id: 'org-a', status: 'ACTIVE', trust_profile_id: 'trust-a', ...overrides,
});
function deferred() {
  let resolve!: (value: Record<string, unknown>) => void;
  const promise = new Promise<Record<string, unknown>>((complete) => { resolve = complete; });
  return { promise, resolve };
}
function Stateful({ initial = {} }: { initial?: Record<string, unknown> }) {
  const [data, setData] = useState<Record<string, any>>({ default_policy_id: null, trust_profile_id: null,
    credential_template_ids: [], enabled_flows: [], runtime_catalog_ready: false, ...initial });
  const [show, setShow] = useState(true);
  const onChange = useCallback((patch: Record<string, unknown>) => setData((previous) => ({ ...previous, ...patch })), []);
  return <>
    <button onClick={() => setShow((value) => !value)}>Toggle step</button>
    {show && <Step data={data} onChange={onChange} />}
    <output data-testid="selections">{JSON.stringify(data)}</output>
  </>;
}
const selections = () => JSON.parse(screen.getByTestId('selections').textContent!);

beforeEach(() => {
  scope.organizationId = 'org-a'; vi.resetAllMocks();
  vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_policy_id: 'policy-default', default_template_id: 'template-default' });
  vi.mocked(listCredentialTemplates).mockResolvedValue([resource('template-first'), resource('template-default')]);
  vi.mocked(listPresentationPolicies).mockResolvedValue([resource('policy-first'), resource('policy-default')]);
});

describe('deployment organization defaults', () => {
  it('preselects the configured policy and compatible template from multiple options', async () => {
    render(<Stateful />);
    await waitFor(() => expect(selections()).toMatchObject({
      default_policy_id: 'policy-default', trust_profile_id: 'trust-a', credential_template_ids: ['template-default'],
    }));
    expect(screen.getByRole('checkbox', { name: 'template-default' })).toBeChecked();
  });

  it('keeps an explicit policy and skips a default template with a different trust profile', async () => {
    vi.mocked(listPresentationPolicies).mockResolvedValue([resource('policy-first', { trust_profile_id: 'trust-other' }), resource('policy-default')]);
    render(<Stateful initial={{ default_policy_id: 'policy-first', trust_profile_id: 'trust-other' }} />);
    await waitFor(() => expect(selections().runtime_catalog_ready).toBe(true));
    expect(selections().default_policy_id).toBe('policy-first');
    expect(screen.getByRole('checkbox', { name: 'template-default' })).not.toBeChecked();
  });

  it('does not select a default policy that conflicts with an explicit template', async () => {
    vi.mocked(listCredentialTemplates).mockResolvedValue([resource('template-first', { trust_profile_id: 'trust-other' }), resource('template-default')]);
    render(<Stateful initial={{ credential_template_ids: ['template-first'] }} />);
    await waitFor(() => expect(selections().runtime_catalog_ready).toBe(true));
    expect(selections().default_policy_id).toBeNull();
    expect(selections().credential_template_ids).toEqual(['template-first']);
  });

  it('preserves manual choices, including an unchecked template, when defaults arrive late', async () => {
    const pending = deferred();
    vi.mocked(getOrganizationDefaults).mockReturnValue(pending.promise);
    const { user } = render(<Stateful />);
    await user.click(await screen.findByRole('combobox', { name: /default presentation policy/i }));
    await user.click(screen.getByRole('option', { name: 'policy-first' }));
    await user.click(screen.getByRole('checkbox', { name: 'template-default' }));
    await user.click(screen.getByRole('checkbox', { name: 'template-default' }));
    await act(async () => { pending.resolve({ default_policy_id: 'policy-default', default_template_id: 'template-default' }); await pending.promise; });
    expect(selections().default_policy_id).toBe('policy-first');
    expect(selections().credential_template_ids).toEqual([]);
  });

  it('does not restore a deselected default when returning to the runtime step', async () => {
    const { user } = render(<Stateful />);
    await waitFor(() => expect(screen.getByRole('checkbox', { name: 'template-default' })).toBeChecked());
    await user.click(screen.getByRole('checkbox', { name: 'template-default' }));
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    expect(await screen.findByRole('checkbox', { name: 'template-default' })).not.toBeChecked();
    expect(selections().credential_template_ids).toEqual([]);
  });

  it.each([false, true])('clears a conflicting automatic template after a policy change across remount, preserving explicit templates (%s)', async (explicitTemplate) => {
    vi.mocked(listPresentationPolicies).mockResolvedValue([resource('policy-first', { trust_profile_id: 'trust-other' }), resource('policy-default')]);
    const { user } = render(<Stateful initial={explicitTemplate ? { credential_template_ids: ['template-default'] } : {}} />);
    await waitFor(() => expect(selections().default_policy_id).toBe('policy-default'));
    expect(selections().credential_template_ids).toEqual(['template-default']);
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    await user.click(await screen.findByRole('combobox', { name: /default presentation policy/i }));
    await user.click(screen.getByRole('option', { name: 'policy-first' }));
    await waitFor(() => expect(selections().credential_template_ids).toEqual(explicitTemplate ? ['template-default'] : []));
    expect(selections().default_policy_id).toBe('policy-first');
  });

  it('clears an automatic policy and template after a conflicting manual template selection', async () => {
    vi.mocked(listCredentialTemplates).mockResolvedValue([resource('template-first', { trust_profile_id: 'trust-other' }), resource('template-default')]);
    const { user } = render(<Stateful />);
    await waitFor(() => expect(selections()).toMatchObject({ default_policy_id: 'policy-default', credential_template_ids: ['template-default'] }));
    await user.click(screen.getByRole('checkbox', { name: 'template-first' }));
    await waitFor(() => expect(selections()).toMatchObject({ default_policy_id: null, trust_profile_id: null, credential_template_ids: ['template-first'] }));
  });

  it('ignores an inactive default without preventing manual selection of an active policy', async () => {
    vi.mocked(listPresentationPolicies).mockResolvedValue([resource('policy-first'), resource('policy-default', { status: 'DRAFT' })]);
    const { user } = render(<Stateful />);
    const select = await screen.findByRole('combobox', { name: /default presentation policy/i });
    expect(selections().default_policy_id).toBeNull();
    await user.click(select);
    await user.click(screen.getByRole('option', { name: 'policy-first' }));
    expect(selections().default_policy_id).toBe('policy-first');
  });

  it('ignores a defaults response from the previous organization', async () => {
    const old = deferred();
    vi.mocked(getOrganizationDefaults).mockImplementation((id) => id === 'org-a' ? old.promise : Promise.resolve({ default_policy_id: 'policy-b', default_template_id: 'template-b' }));
    vi.mocked(listPresentationPolicies).mockImplementation(({ organization_id }) => Promise.resolve([
      resource(`policy-${organization_id === 'org-a' ? 'a' : 'b'}`, { organization_id }), resource(`policy-other-${organization_id}`, { organization_id }),
    ]));
    vi.mocked(listCredentialTemplates).mockImplementation(({ organization_id }) => Promise.resolve([
      resource(`template-${organization_id === 'org-a' ? 'a' : 'b'}`, { organization_id }),
    ]));
    const view = render(<Stateful />);
    await screen.findByRole('combobox', { name: /default presentation policy/i });
    scope.organizationId = 'org-b'; view.rerender(<Stateful />);
    await waitFor(() => expect(selections().default_policy_id).toBe('policy-b'));
    await act(async () => { old.resolve({ default_policy_id: 'policy-a', default_template_id: 'template-a' }); await old.promise; });
    expect(selections()).toMatchObject({ default_policy_id: 'policy-b', credential_template_ids: ['template-b'] });
  });
});
