import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';
import CustomFlowBuilder from '../CustomFlowBuilder';

const mocks = vi.hoisted(() => ({ org: 'org-1', search: '', navigate: vi.fn(), capabilities: vi.fn(), list: vi.fn(), create: vi.fn() }));
vi.mock('react-router', async () => ({ ...await vi.importActual('react-router'), useNavigate: () => mocks.navigate, useSearchParams: () => [new URLSearchParams(mocks.search)] }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: mocks.org }) }));
vi.mock('../../../../services/flowsApi', () => ({ getFlowCapabilities: mocks.capabilities, createFlow: mocks.create }));
vi.mock('../../../../services/presentationPolicyApi', () => ({ listCredentialTemplates: mocks.list }));

const capabilities = { flow_types: ['custom', 'oid4vci_pre_authorized'], standard_flow_types: ['oid4vci_pre_authorized'], triggers: ['API_CALL', 'WEBHOOK'] };
const template = { id: 'credential-1', organization_id: 'org-1', name: 'Tenant membership', status: 'ACTIVE',
  issuance_protocol: 'OID4VCI_PRE_AUTH', trust_profile_id: 'trust-1' };

async function approved(user: any) {
  await waitFor(() => expect(mocks.capabilities).toHaveBeenCalled());
  await user.click(screen.getByRole('combobox', { name: 'Flow setup' }));
  const option = screen.getByRole('option', { name: 'Approved application issuance' });
  await waitFor(() => expect(option).not.toHaveAttribute('aria-disabled', 'true'));
  await user.click(option);
}

describe('CustomFlowBuilder', () => {
  it.each([true, false])('validates a linked template before preselection (eligible=%s)', async (eligible) => {
    mocks.search = 'templateId=credential-1';
    mocks.list.mockResolvedValue([{ ...template, organization_id: eligible ? 'org-1' : 'foreign-org' }]);
    try {
      render(<CustomFlowBuilder />);
      const select = await screen.findByRole('combobox', { name: /Credential template/ });
      await waitFor(() => expect(select).toBeEnabled());
      if (eligible) await waitFor(() => expect(select).toHaveTextContent('Tenant membership'));
      else expect(await screen.findByText(/linked template is unavailable or incompatible/)).toBeInTheDocument();
      expect(mocks.create).not.toHaveBeenCalled();
    } finally { mocks.search = ''; }
  });
  beforeEach(() => {
    vi.clearAllMocks(); mocks.org = 'org-1';
    mocks.capabilities.mockResolvedValue(capabilities);
    mocks.list.mockResolvedValue([template]);
    mocks.create.mockResolvedValue({ id: 'created', organization_id: 'org-1', status: 'DRAFT' });
  });

  it('preserves generic custom API flow creation', async () => {
    const { user } = render(<CustomFlowBuilder />);
    await user.type(screen.getByRole('textbox', { name: 'Flow name' }), 'Generic extension');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create draft' })).toBeEnabled());
    await user.click(screen.getByRole('button', { name: 'Create draft' }));
    await waitFor(() => expect(mocks.create).toHaveBeenCalledOnce());
    expect(mocks.create.mock.calls[0][0]).toMatchObject({ organization_id: 'org-1', flow_type: 'custom',
      trigger: { trigger_type: 'API_CALL', config: {} }, extension: { entry_step_id: 'collect_input' } });
    expect(mocks.create.mock.calls[0][0]).not.toHaveProperty('credential_template_id');
    expect(mocks.list).not.toHaveBeenCalled();
  });

  it('loads every page, excludes incompatible or foreign templates and creates the native approved-application contract', async () => {
    const first = Array.from({ length: 100 }, (_, i) => ({ ...template, id: `draft-${i}`, name: `Draft ${i}`, status: 'DRAFT' }));
    mocks.list.mockImplementation(({ offset }: any) => Promise.resolve(offset === 0 ? first : [template,
      { ...template, id: 'foreign', name: 'Foreign', organization_id: 'org-2' },
      { ...template, id: 'auth-code', name: 'Auth code', issuance_protocol: 'OID4VCI_AUTH_CODE' },
      { ...template, id: 'no-trust', name: 'No trust', trust_profile_id: null }]));
    const { user } = render(<CustomFlowBuilder />);
    await approved(user);
    await user.type(screen.getByRole('textbox', { name: 'Flow name' }), 'Approved membership');
    await waitFor(() => expect(screen.getByRole('combobox', { name: /Credential template/ })).toBeEnabled());
    await user.click(screen.getByRole('combobox', { name: /Credential template/ }));
    expect(screen.queryByRole('option', { name: 'Foreign' })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'Auth code' })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'No trust' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('option', { name: 'Tenant membership' }));
    expect(screen.queryByRole('button', { name: 'Add step' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create draft' }));
    await waitFor(() => expect(mocks.create).toHaveBeenCalledOnce());
    expect(mocks.list).toHaveBeenCalledWith({ organization_id: 'org-1', limit: 100, offset: 100 });
    expect(mocks.create.mock.calls[0][0]).toMatchObject({ organization_id: 'org-1', credential_template_id: 'credential-1',
      trust_profile_id: 'trust-1', flow_type: 'custom', trigger: { trigger_type: 'WEBHOOK', config: { event_type: 'APPLICATION_APPROVED' } },
      extension: { extends_flow_type: 'oid4vci_pre_authorized', entry_step_id: 'issue',
        steps: [{ step_id: 'issue', action: 'issuance.issue', config: {} }], transitions: [] } });
    expect(mocks.create.mock.calls[0][0]).not.toHaveProperty('application_template_id');
    expect(mocks.navigate).toHaveBeenCalledWith('/console/org/flows/definitions/created');
  });

  it('fails closed on dependency failure and permits an explicit successful retry', async () => {
    mocks.list.mockRejectedValueOnce(new Error('Catalog unavailable')).mockResolvedValue([template]);
    const { user } = render(<CustomFlowBuilder />);
    await approved(user);
    await user.type(screen.getByRole('textbox', { name: 'Flow name' }), 'Approved membership');
    expect(await screen.findByText('Catalog unavailable')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Retry templates' }));
    await waitFor(() => expect(screen.getByRole('combobox', { name: /Credential template/ })).toBeEnabled());
    await user.click(screen.getByRole('combobox', { name: /Credential template/ }));
    await user.click(screen.getByRole('option', { name: 'Tenant membership' }));
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeEnabled();
  });

  it('rejects repeated pagination instead of silently selecting an incomplete catalog', async () => {
    mocks.list.mockResolvedValue(Array.from({ length: 100 }, (_, i) => ({ ...template, id: `template-${i}` })));
    const { user } = render(<CustomFlowBuilder />);
    await approved(user);
    expect(await screen.findByText('Credential template pagination did not advance.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled();
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it('does not submit without API capabilities and supports explicit recovery', async () => {
    mocks.capabilities.mockRejectedValueOnce(new Error('Capabilities unavailable')).mockResolvedValue(capabilities);
    const { user } = render(<CustomFlowBuilder />);
    await user.type(screen.getByRole('textbox', { name: 'Flow name' }), 'Generic extension');
    expect(await screen.findByText('Capabilities unavailable')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Retry capabilities' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create draft' })).toBeEnabled());
  });

  it('resets the form on organization switch and ignores a late former-tenant dependency response', async () => {
    let resolveOld!: (value: any) => void;
    mocks.list.mockImplementation(({ organization_id }: any) => organization_id === 'org-1'
      ? new Promise((resolve) => { resolveOld = resolve; })
      : Promise.resolve([{ ...template, id: 'credential-2', organization_id: 'org-2', name: 'Second tenant' }]));
    const { user, rerender } = render(<CustomFlowBuilder />);
    await approved(user);
    await user.type(screen.getByRole('textbox', { name: 'Flow name' }), 'Former tenant');
    await waitFor(() => expect(mocks.list).toHaveBeenCalled());
    mocks.org = 'org-2'; rerender(<CustomFlowBuilder />);
    expect(screen.getByRole('textbox', { name: 'Flow name' })).toHaveValue('');
    await approved(user);
    await waitFor(() => expect(screen.getByRole('combobox', { name: /Credential template/ })).toBeEnabled());
    resolveOld([template]);
    await user.click(screen.getByRole('combobox', { name: /Credential template/ }));
    expect(screen.queryByRole('option', { name: 'Tenant membership' })).not.toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Second tenant' })).toBeInTheDocument();
    expect(mocks.create).not.toHaveBeenCalled();
  });
});
