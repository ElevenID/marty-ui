import { useCallback, useState } from 'react';
import { act, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from '@test/utils';
import Step from '../steps/DeploymentBindingStep';
import { getOrganizationDefaults } from '../../../../services/organizationsApi';
import { listCredentialTemplates, listPresentationPolicies } from '../../../../services/presentationPolicyApi';
import { listDeploymentProfiles } from '../../../../services/deploymentProfilesApi';

const scope = vi.hoisted(() => ({ organizationId: 'org-a' }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.organizationId }) }));
vi.mock('../../../../services/organizationsApi', () => ({ getOrganizationDefaults: vi.fn() }));
vi.mock('../../../../services/presentationPolicyApi', () => ({ listCredentialTemplates: vi.fn(), listPresentationPolicies: vi.fn() }));
vi.mock('../../../../services/deploymentProfilesApi', () => ({ listDeploymentProfiles: vi.fn() }));
vi.mock('../../../../services/applicationTemplatesApi', () => ({ listApplicationTemplates: async () => [] }));
vi.mock('../../../../services/deliveryDestinationsApi', () => ({ listDeliveryDestinations: async () => [] }));

const template = (id: string, overrides = {}) => ({
  id, name: id, organization_id: 'org-a', status: 'ACTIVE', trust_profile_id: 'trust-a',
  issuance_protocol: 'OID4VCI_PRE_AUTH', credential_payload_format: 'SD_JWT_VC', ...overrides,
});
const policy = (id: string, overrides = {}) => ({ id, name: id, organization_id: 'org-a', status: 'ACTIVE', trust_profile_id: 'trust-a', ...overrides });
function deferred() {
  let resolve!: (value: Record<string, unknown>) => void;
  const promise = new Promise<Record<string, unknown>>((complete) => { resolve = complete; });
  return { promise, resolve };
}
function Stateful({ initial = {} }: { initial?: Record<string, unknown> }) {
  const [data, setData] = useState<Record<string, any>>({
    flowType: 'oid4vci_pre_authorized', credentialTemplateId: null, defaultPolicyId: null,
    selectedDeployment: null, trustProfileId: null, ...initial,
  });
  const [show, setShow] = useState(true);
  const onUpdate = useCallback((patch: Record<string, unknown>) => setData((previous) => ({ ...previous, ...patch })), []);
  return <><button onClick={() => setShow((value) => !value)}>Toggle step</button>
    {show && <Step {...data} onUpdate={onUpdate} />}<output data-testid="selections">{JSON.stringify(data)}</output></>;
}
const selections = () => JSON.parse(screen.getByTestId('selections').textContent!);

beforeEach(() => {
  scope.organizationId = 'org-a'; vi.resetAllMocks();
  vi.mocked(getOrganizationDefaults).mockResolvedValue({});
  vi.mocked(listCredentialTemplates).mockResolvedValue([template('template-first'), template('template-default')]);
  vi.mocked(listPresentationPolicies).mockResolvedValue([policy('policy-first'), policy('policy-default')]);
  vi.mocked(listDeploymentProfiles).mockResolvedValue([]);
});

describe('flow organization defaults', () => {
  it('selects the configured eligible template and policy, with their matching trust binding', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default', default_policy_id: 'policy-default' });
    render(<Stateful initial={{ flowType: 'combined' }} />);
    await waitFor(() => expect(selections()).toMatchObject({
      credentialTemplateId: 'template-default', defaultPolicyId: 'policy-default', trustProfileId: 'trust-a',
    }));
    expect(getOrganizationDefaults).toHaveBeenCalledWith('org-a');
    expect(screen.getByRole('combobox', { name: /credential template/i })).toHaveTextContent('template-default');
  });

  it('preserves an explicitly linked template instead of the organization default', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default' });
    render(<Stateful initial={{ credentialTemplateId: 'template-first', trustProfileId: 'trust-a' }} />);
    await screen.findByRole('combobox', { name: /credential template/i });
    expect(selections().credentialTemplateId).toBe('template-first');
  });

  it('does not overwrite a user choice when defaults arrive late', async () => {
    const pending = deferred();
    vi.mocked(getOrganizationDefaults).mockReturnValue(pending.promise);
    const { user } = render(<Stateful />);
    await user.click(await screen.findByRole('combobox', { name: /credential template/i }));
    await user.click(screen.getByRole('option', { name: 'template-first' }));
    await act(async () => { pending.resolve({ default_template_id: 'template-default' }); await pending.promise; });
    expect(selections().credentialTemplateId).toBe('template-first');
  });

  it.each([
    ['inactive', { status: 'DRAFT' }],
    ['foreign', { organization_id: 'org-other' }],
    ['wrong issuance protocol', { issuance_protocol: 'OID4VCI_AUTH_CODE' }],
    ['unknown credential format', { credential_payload_format: undefined }],
    ['physical document', { issuance_protocol: 'PHYSICAL_DOCUMENT', credential_payload_format: 'ICAO_EMRTD' }],
    ['wrong trust profile', { trust_profile_id: 'trust-other' }],
  ])('ignores a %s template default and leaves a manual choice available', async (_label, overrides) => {
    const pending = deferred();
    vi.mocked(getOrganizationDefaults).mockReturnValue(pending.promise);
    vi.mocked(listCredentialTemplates).mockResolvedValue([template('template-first'), template('template-default', overrides)]);
    const { user } = render(<Stateful initial={{ trustProfileId: 'trust-a' }} />);
    const input = await screen.findByRole('combobox', { name: /credential template/i });
    await act(async () => { pending.resolve({ default_template_id: 'template-default' }); await pending.promise; });
    expect(selections().credentialTemplateId).toBeNull();
    await user.click(input);
    await user.click(screen.getByRole('option', { name: 'template-first' }));
    expect(selections().credentialTemplateId).toBe('template-first');
  });

  it('does not combine defaults that use different trust profiles', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default', default_policy_id: 'policy-default' });
    vi.mocked(listPresentationPolicies).mockResolvedValue([policy('policy-first'), policy('policy-default', { trust_profile_id: 'trust-other' })]);
    render(<Stateful initial={{ flowType: 'combined' }} />);
    await waitFor(() => expect(selections().credentialTemplateId).toBe('template-default'));
    expect(selections().defaultPolicyId).toBeNull();
  });

  it.each([false, true])('clears a conflicting automatic template after a later policy choice across remount, preserving explicit templates (%s)', async (explicitTemplate) => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default', default_policy_id: 'policy-default' });
    vi.mocked(listPresentationPolicies).mockResolvedValue([policy('policy-first', { trust_profile_id: 'trust-other' }), policy('policy-default')]);
    const { user } = render(<Stateful initial={{ flowType: 'combined',
      ...(explicitTemplate ? { credentialTemplateId: 'template-default', trustProfileId: 'trust-a' } : {}),
    }} />);
    await waitFor(() => expect(selections().defaultPolicyId).toBe('policy-default'));
    expect(selections().credentialTemplateId).toBe('template-default');
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    await user.click(await screen.findByRole('combobox', { name: /presentation policy/i }));
    await user.click(screen.getByRole('option', { name: 'policy-first' }));
    await waitFor(() => expect(selections().credentialTemplateId).toBe(explicitTemplate ? 'template-default' : null));
    expect(selections().defaultPolicyId).toBe('policy-first');
  });

  it('clears a conflicting automatic policy after a later template choice', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default', default_policy_id: 'policy-default' });
    vi.mocked(listCredentialTemplates).mockResolvedValue([template('template-first', { trust_profile_id: 'trust-other' }), template('template-default')]);
    const { user } = render(<Stateful initial={{ flowType: 'combined' }} />);
    await waitFor(() => expect(selections().defaultPolicyId).toBe('policy-default'));
    await user.click(screen.getByRole('combobox', { name: /credential template/i }));
    await user.click(screen.getByRole('option', { name: 'template-first' }));
    await waitFor(() => expect(selections().defaultPolicyId).toBeNull());
    expect(selections()).toMatchObject({ credentialTemplateId: 'template-first', trustProfileId: 'trust-other' });
  });

  it('clears conflicting automatic resources when the user binds a different deployment trust', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default', default_policy_id: 'policy-default' });
    vi.mocked(listDeploymentProfiles).mockResolvedValue([
      { id: 'deployment-a', name: 'Deployment A', status: 'ACTIVE', organization_id: 'org-a', trust_profile_id: 'trust-a' },
      { id: 'deployment-b', name: 'Deployment B', status: 'ACTIVE', organization_id: 'org-a', trust_profile_id: 'trust-other' },
    ]);
    const { user } = render(<Stateful initial={{ flowType: 'combined' }} />);
    await waitFor(() => expect(selections().defaultPolicyId).toBe('policy-default'));
    await user.click(screen.getByRole('combobox', { name: /deployment profile/i }));
    await user.click(screen.getByRole('option', { name: 'Deployment B' }));
    await waitFor(() => expect(selections()).toMatchObject({
      credentialTemplateId: null, defaultPolicyId: null, trustProfileId: 'trust-other', selectedDeployment: { id: 'deployment-b' },
    }));
  });

  it('clears a sole automatic deployment when the user chooses a different policy trust', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default', default_policy_id: 'policy-default' });
    vi.mocked(listDeploymentProfiles).mockResolvedValue([
      { id: 'deployment-a', name: 'Deployment A', status: 'ACTIVE', organization_id: 'org-a', trust_profile_id: 'trust-a' },
    ]);
    vi.mocked(listPresentationPolicies).mockResolvedValue([policy('policy-first', { trust_profile_id: 'trust-other' }), policy('policy-default')]);
    const { user } = render(<Stateful initial={{ flowType: 'combined' }} />);
    await waitFor(() => expect(selections().selectedDeployment?.id).toBe('deployment-a'));
    await user.click(screen.getByRole('combobox', { name: /presentation policy/i }));
    await user.click(screen.getByRole('option', { name: 'policy-first' }));
    await waitFor(() => expect(selections()).toMatchObject({
      defaultPolicyId: 'policy-first', credentialTemplateId: null, selectedDeployment: null, trustProfileId: 'trust-other',
    }));
  });

  it('preserves an explicit no-deployment choice across remount', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default' });
    vi.mocked(listDeploymentProfiles).mockResolvedValue([
      { id: 'deployment-a', name: 'Deployment A', status: 'ACTIVE', organization_id: 'org-a', trust_profile_id: 'trust-a' },
    ]);
    const { user } = render(<Stateful />);
    await waitFor(() => expect(selections().selectedDeployment?.id).toBe('deployment-a'));
    await user.click(screen.getByRole('combobox', { name: /deployment profile/i }));
    await user.click(screen.getByRole('option', { name: 'None' }));
    expect(selections().selectedDeployment).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    await screen.findByRole('combobox', { name: /deployment profile/i });
    expect(selections().selectedDeployment).toBeNull();
  });

  it('does not apply a default that conflicts with the selected deployment trust', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default' });
    const deployment = { id: 'deployment', name: 'Deployment', organization_id: 'org-a', status: 'ACTIVE', trust_profile_id: 'trust-other' };
    vi.mocked(listDeploymentProfiles).mockResolvedValue([deployment]);
    render(<Stateful initial={{ selectedDeployment: deployment }} />);
    await screen.findByRole('combobox', { name: /credential template/i });
    expect(selections().credentialTemplateId).toBeNull();
  });

  it('leaves an incompatible sole deployment unselected instead of overriding the default trust binding', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default' });
    vi.mocked(listDeploymentProfiles).mockResolvedValue([
      { id: 'deployment', name: 'Deployment', organization_id: 'org-a', status: 'ACTIVE', trust_profile_id: 'trust-other' },
    ]);
    render(<Stateful />);
    await waitFor(() => expect(selections().credentialTemplateId).toBe('template-default'));
    expect(selections()).toMatchObject({ selectedDeployment: null, trustProfileId: 'trust-a' });
  });

  it('does not add an incompatible sole template alongside a default policy', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_policy_id: 'policy-default' });
    vi.mocked(listCredentialTemplates).mockResolvedValue([template('different-trust', { trust_profile_id: 'trust-other' })]);
    render(<Stateful initial={{ flowType: 'combined' }} />);
    await waitFor(() => expect(selections().defaultPolicyId).toBe('policy-default'));
    expect(selections()).toMatchObject({ credentialTemplateId: null, trustProfileId: 'trust-a' });
  });

  it.each([
    ['SD_JWT_VC', null], ['MDOC', 'policy-default'],
  ])('selects a default for an mDL presentation only when its requirements use mdoc (%s)', async (format, expected) => {
    const pending = deferred(); vi.mocked(getOrganizationDefaults).mockReturnValue(pending.promise);
    vi.mocked(listPresentationPolicies).mockResolvedValue([policy('policy-first'), policy('policy-default', {
      credential_requirements: [{ credential_payload_format: format, credential_template_id: 'template-default' }],
    })]);
    render(<Stateful initial={{ flowType: 'mdl_presentation' }} />);
    await screen.findByRole('combobox', { name: /presentation policy/i });
    await act(async () => { pending.resolve({ default_policy_id: 'policy-default' }); await pending.promise; });
    expect(selections().defaultPolicyId).toBe(expected);
  });

  it.each([true, false])('uses the public proof-only policy shape for SIOPv2 defaults (holder required: %s)', async (required) => {
    const pending = deferred(); vi.mocked(getOrganizationDefaults).mockReturnValue(pending.promise);
    vi.mocked(listPresentationPolicies).mockResolvedValue([policy('policy-first'), policy('policy-default', {
      holder_binding: { required, binding_methods: ['SESSION_BINDING'] },
      credential_requirements: [], alternative_requirements: [], required_claims: [], accepted_credential_types: [],
    })]);
    render(<Stateful initial={{ flowType: 'siopv2' }} />);
    await screen.findByRole('combobox', { name: /presentation policy/i });
    await act(async () => { pending.resolve({ default_policy_id: 'policy-default' }); await pending.promise; });
    expect(selections().defaultPolicyId).toBe(required ? 'policy-default' : null);
  });

  it('discards old-organization defaults after the active organization switches', async () => {
    const old = deferred();
    vi.mocked(getOrganizationDefaults).mockImplementation((id) => id === 'org-a' ? old.promise : Promise.resolve({ default_template_id: 'template-b' }));
    vi.mocked(listCredentialTemplates).mockImplementation(({ organization_id }) => Promise.resolve([
      template(`template-${organization_id === 'org-a' ? 'a' : 'b'}`, { organization_id }),
      template(`other-${organization_id}`, { organization_id }),
    ]));
    const view = render(<Stateful />);
    await screen.findByRole('combobox', { name: /credential template/i });
    scope.organizationId = 'org-b'; view.rerender(<Stateful />);
    await waitFor(() => expect(selections().credentialTemplateId).toBe('template-b'));
    await act(async () => { old.resolve({ default_template_id: 'template-a' }); await old.promise; });
    expect(selections().credentialTemplateId).toBe('template-b');
  });

  it('keeps manual resource selection usable if defaults cannot load', async () => {
    vi.mocked(getOrganizationDefaults).mockRejectedValue(new Error('defaults unavailable'));
    const { user } = render(<Stateful />);
    await user.click(await screen.findByRole('combobox', { name: /credential template/i }));
    await user.click(screen.getByRole('option', { name: 'template-first' }));
    expect(selections().credentialTemplateId).toBe('template-first');
  });
});
