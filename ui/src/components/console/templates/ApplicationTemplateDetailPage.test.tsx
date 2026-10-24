import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import ApplicationTemplateDetailPage from './ApplicationTemplateDetailPage';

const {
  mockActivate,
  mockDelete,
  mockDeprecate,
  mockGet,
  mockValidate,
  scope,
  permissions,
} = vi.hoisted(() => ({
  mockActivate: vi.fn(),
  mockDelete: vi.fn(),
  mockDeprecate: vi.fn(),
  mockGet: vi.fn(),
  mockValidate: vi.fn(),
  scope: { activeOrgId: 'org-1' },
  permissions: { can: vi.fn((_resource: string, _action: string) => true), isLoading: false },
}));

vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => scope }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => permissions }));

vi.mock('../../../services/applicationTemplatesApi', () => ({
  activateApplicationTemplate: mockActivate,
  deleteApplicationTemplate: mockDelete,
  deprecateApplicationTemplate: mockDeprecate,
  getApplicationTemplate: mockGet,
  validateApplicationTemplate: mockValidate,
}));

const draft = {
  id: 'application-template-1',
  organization_id: 'org-1',
  name: 'Membership application',
  status: 'DRAFT',
  credential_template_id: 'credential-template-1',
  approval_strategy: 'MANUAL',
  application_validity_days: 30,
  form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true }],
  evidence_requirements: [],
  required_checks: [],
};

function renderPage() {
  return renderWithRouter(
    <Routes>
      <Route path="/console/org/templates/applications/:templateId" element={<ApplicationTemplateDetailPage />} />
    </Routes>,
    { initialEntries: ['/console/org/templates/applications/application-template-1'] },
  );
}

describe('ApplicationTemplateDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    scope.activeOrgId = 'org-1';
    permissions.can.mockReturnValue(true);
    mockGet.mockResolvedValue(draft);
    mockValidate.mockResolvedValue({ valid: true, errors: [] });
    mockActivate.mockResolvedValue({ ...draft, status: 'ACTIVE' });
    mockDeprecate.mockResolvedValue({ ...draft, status: 'DEPRECATED' });
  });

  it('rejects an existing foreign template before validation or actions', async () => {
    mockGet.mockResolvedValue({ ...draft, organization_id: 'org-2' });
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i);
    expect(screen.queryByText(draft.name)).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /preview/i })).not.toBeInTheDocument();
    expect(mockValidate).not.toHaveBeenCalled();
  });

  it('lets a viewer inspect without making lifecycle requests', async () => {
    permissions.can.mockImplementation((_resource, action) => action === 'view');
    renderPage();
    expect(await screen.findByRole('heading', { name: draft.name })).toBeInTheDocument();
    expect(mockValidate).not.toHaveBeenCalled();
    expect(screen.queryByRole('link', { name: /edit/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /validate|activate|delete/i })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /preview/i })).toHaveAttribute('href', expect.stringContaining('organization_id=org-1'));
  });

  it('validates drafts before exposing activation', async () => {
    const { user } = renderPage();

    expect(await screen.findByText(/valid and can be activated/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /edit/i })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /activate/i }));

    await waitFor(() => expect(mockActivate).toHaveBeenCalledWith('application-template-1'));
    expect(screen.getByText('ACTIVE')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /deprecate/i })).toBeInTheDocument();
  });

  it('shows section validation errors and withholds activation', async () => {
    mockValidate.mockResolvedValue({
      valid: false,
      errors: [{ section: 'claim_mappings', field: 'form_fields.0.claim_mapping', code: 'UNKNOWN_CLAIM', message: 'Claim mapping is not defined by the Credential Template.' }],
    });

    renderPage();

    expect(await screen.findByText(/claim mapping is not defined/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /activate/i })).not.toBeInTheDocument();
  });

  it('deprecates active templates instead of deleting them', async () => {
    mockGet.mockResolvedValue({ ...draft, status: 'ACTIVE' });
    const { user } = renderPage();

    await screen.findByText('ACTIVE');
    expect(screen.queryByRole('link', { name: /edit/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /deprecate/i }));
    await user.click(screen.getAllByRole('button', { name: /deprecate/i }).at(-1)!);

    await waitFor(() => expect(mockDeprecate).toHaveBeenCalledWith('application-template-1'));
    expect(screen.getByText('DEPRECATED')).toBeInTheDocument();
  });
});
