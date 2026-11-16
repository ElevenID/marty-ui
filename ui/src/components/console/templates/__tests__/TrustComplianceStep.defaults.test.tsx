import { useCallback, useState } from 'react';
import { act, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from '@test/utils';
import Step from '../steps/TrustComplianceStep';
import { getOrganizationDefaults } from '../../../../services/organizationsApi';
import { listTrustProfiles } from '../../../../services/presentationPolicyApi';
import { listComplianceProfiles } from '../../../../services/complianceProfilesApi';

const scope = vi.hoisted(() => ({ organizationId: 'org-a' }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.organizationId }) }));
vi.mock('../../../../services/organizationsApi', () => ({ getOrganizationDefaults: vi.fn() }));
vi.mock('../../../../services/presentationPolicyApi', () => ({ listTrustProfiles: vi.fn() }));
vi.mock('../../../../services/complianceProfilesApi', () => ({ listComplianceProfiles: vi.fn() }));
vi.mock('../../../../services/issuerIdentitiesApi', () => ({ default: {
  getTemplateIssuerOptions: async (request: Record<string, unknown>) => {
    const format = request.compliance_profile_id === 'compliance-mdoc' ? 'MDOC' : 'SD_JWT_VC';
    return { ...request, credential_payload_format: format, supported_formats: [format], issuance_protocol: 'OID4VCI_PRE_AUTH',
      requirements: { vct: format !== 'MDOC', doctype: format === 'MDOC', revocation_profile: true }, identities: [], rejected_issuers: [] };
  },
} }));

const trust = (id: string, overrides = {}) => ({ id, name: id, organization_id: 'org-a', status: 'ACTIVE', supported_formats: ['SD_JWT_VC'], ...overrides });
function deferred() {
  let resolve!: (value: Record<string, unknown>) => void;
  const promise = new Promise<Record<string, unknown>>((complete) => { resolve = complete; });
  return { promise, resolve };
}
function Stateful({ initial = {} }: { initial?: Record<string, unknown> }) {
  const [data, setData] = useState<Record<string, any>>({ trust_profile_id: null, compliance_profile_id: 'compliance-sd',
    vct: 'urn:example:employee', ...initial });
  const [show, setShow] = useState(true);
  const onChange = useCallback((patch: Record<string, unknown>) => setData((previous) => ({ ...previous, ...patch })), []);
  return <><button onClick={() => setShow((value) => !value)}>Toggle step</button>
    {show && <Step data={data} onChange={onChange} />}<output data-testid="selections">{JSON.stringify(data)}</output></>;
}
const selections = () => JSON.parse(screen.getByTestId('selections').textContent!);

beforeEach(() => {
  scope.organizationId = 'org-a'; vi.resetAllMocks();
  vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_trust_profile_id: 'trust-default' });
  vi.mocked(listTrustProfiles).mockResolvedValue([trust('trust-first'), trust('trust-default')]);
  vi.mocked(listComplianceProfiles).mockImplementation(({ organization_id }) => Promise.resolve([
    { id: 'compliance-sd', name: 'Compliance', organization_id, status: 'ACTIVE', credential_format: 'SD_JWT_VC' },
  ]));
});

describe('credential template trust defaults', () => {
  it('selects the active default trust profile that supports the template format', async () => {
    render(<Stateful />);
    await waitFor(() => expect(selections().trust_profile_id).toBe('trust-default'));
    expect(screen.getByRole('combobox', { name: /Trust Profile/ })).toHaveTextContent('trust-default');
  });

  it('keeps an explicit trust profile instead of replacing it with a default', async () => {
    render(<Stateful initial={{ trust_profile_id: 'trust-first' }} />);
    await waitFor(() => expect(screen.getByRole('combobox', { name: /Trust Profile/ })).toHaveTextContent('trust-first'));
    expect(selections().trust_profile_id).toBe('trust-first');
  });

  it('checks the auto-selected compliance format before applying a trust default', async () => {
    vi.mocked(listTrustProfiles).mockResolvedValue([trust('trust-first'), trust('trust-default', { supported_formats: ['MDOC'] })]);
    render(<Stateful initial={{ compliance_profile_id: null }} />);
    await waitFor(() => expect(selections().credential_payload_format).toBe('SD_JWT_VC'));
    expect(selections().compliance_profile_id).toBe('compliance-sd');
    expect(selections().trust_profile_id).toBeNull();
  });

  it('does not overwrite a manual selection when defaults finish loading', async () => {
    const pending = deferred(); vi.mocked(getOrganizationDefaults).mockReturnValue(pending.promise);
    const { user } = render(<Stateful />);
    const input = screen.getByRole('combobox', { name: /Trust Profile/ });
    await waitFor(() => expect(input).not.toHaveAttribute('aria-disabled', 'true'));
    await user.click(input); await user.click(screen.getByRole('option', { name: 'trust-first' }));
    await act(async () => { pending.resolve({ default_trust_profile_id: 'trust-default' }); await pending.promise; });
    expect(selections().trust_profile_id).toBe('trust-first');
  });

  it.each([false, true])('clears an incompatible automatic trust choice after a format change across remount, preserving explicit choices (%s)', async (makeExplicit) => {
    vi.mocked(listComplianceProfiles).mockResolvedValue([
      { id: 'compliance-sd', name: 'SD compliance', organization_id: 'org-a', status: 'ACTIVE', credential_format: 'SD_JWT_VC' },
      { id: 'compliance-mdoc', name: 'MDOC compliance', organization_id: 'org-a', status: 'ACTIVE', credential_format: 'MDOC' },
    ]);
    const { user } = render(<Stateful />);
    await waitFor(() => expect(selections().trust_profile_id).toBe('trust-default'));
    expect(selections()._organization_default_trust).toEqual({ organizationId: 'org-a', id: 'trust-default' });
    if (makeExplicit) {
      await user.click(screen.getByRole('combobox', { name: /Trust Profile/ }));
      await user.click(screen.getByRole('option', { name: 'trust-first' }));
      await user.click(screen.getByRole('combobox', { name: /Trust Profile/ }));
      await user.click(screen.getByRole('option', { name: 'trust-default' }));
      expect(selections()._organization_default_trust).toBeNull();
    }
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    await user.click(screen.getByRole('button', { name: 'Toggle step' }));
    const compliance = await screen.findByRole('combobox', { name: 'Compliance Profile' });
    await waitFor(() => expect(compliance).not.toHaveAttribute('aria-disabled', 'true'));
    await user.click(compliance); await user.click(screen.getByRole('option', { name: 'MDOC compliance' }));
    await waitFor(() => expect(selections().credential_payload_format).toBe('MDOC'));
    expect(selections().trust_profile_id).toBe(makeExplicit ? 'trust-default' : null);
    expect(selections()._organization_default_trust).toBeNull();
  });

  it.each([
    ['inactive', { status: 'SUSPENDED' }],
    ['foreign', { organization_id: 'org-other' }],
    ['incompatible format', { supported_formats: ['MDOC'] }],
  ])('ignores a default with %s eligibility and permits manual selection', async (_label, overrides) => {
    vi.mocked(listTrustProfiles).mockResolvedValue([trust('trust-first'), trust('trust-default', overrides)]);
    const { user } = render(<Stateful />);
    const input = screen.getByRole('combobox', { name: /Trust Profile/ });
    await waitFor(() => expect(input).not.toHaveAttribute('aria-disabled', 'true'));
    expect(selections().trust_profile_id).toBeNull();
    await user.click(input); await user.click(screen.getByRole('option', { name: 'trust-first' }));
    expect(selections().trust_profile_id).toBe('trust-first');
  });

  it('ignores late defaults after the active organization changes', async () => {
    const old = deferred();
    vi.mocked(getOrganizationDefaults).mockImplementation((id) => id === 'org-a' ? old.promise : Promise.resolve({ default_trust_profile_id: 'trust-b' }));
    vi.mocked(listTrustProfiles).mockImplementation(({ organization_id }) => Promise.resolve([
      trust(`trust-${organization_id === 'org-a' ? 'a' : 'b'}`, { organization_id }), trust(`other-${organization_id}`, { organization_id }),
    ]));
    const view = render(<Stateful />);
    await waitFor(() => expect(screen.getByRole('combobox', { name: /Trust Profile/ })).not.toHaveAttribute('aria-disabled', 'true'));
    scope.organizationId = 'org-b'; view.rerender(<Stateful />);
    await waitFor(() => expect(selections().trust_profile_id).toBe('trust-b'));
    await act(async () => { old.resolve({ default_trust_profile_id: 'trust-a' }); await old.promise; });
    expect(selections().trust_profile_id).toBe('trust-b');
  });
});
