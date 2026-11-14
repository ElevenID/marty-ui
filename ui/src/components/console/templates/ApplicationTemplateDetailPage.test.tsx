import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Link, Route, Routes, useNavigate } from 'react-router';
import { act, fireEvent, renderWithRouter, screen, waitFor, within } from '@test/utils';

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

let navigateTo: ReturnType<typeof useNavigate>;
function NavigationProbe() {
  navigateTo = useNavigate();
  return null;
}

function page() {
  return <>
    <NavigationProbe />
    <Link to="/console/org/templates/applications/application-template-1?review=again">Reopen template</Link>
    <Routes>
      <Route path="/console/org/templates/applications/:templateId" element={<ApplicationTemplateDetailPage />} />
      <Route path="/console/org/templates/applications" element={<h1>Application Template inventory</h1>} />
    </Routes>
  </>;
}

function renderPage() {
  return renderWithRouter(
    page(),
    { initialEntries: ['/console/org/templates/applications/application-template-1'] },
  );
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

describe('ApplicationTemplateDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    scope.activeOrgId = 'org-1';
    permissions.isLoading = false;
    permissions.can.mockReturnValue(true);
    mockGet.mockReset();
    mockValidate.mockReset();
    mockActivate.mockReset();
    mockDelete.mockReset();
    mockDeprecate.mockReset();
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

  it('lets a viewer review the saved structured claim source without lifecycle requests', async () => {
    permissions.can.mockImplementation((_resource, action) => action === 'view');
    const configuration = {
      system_field: 'constant',
      value: { id: 'https://issuer.example.test/criteria/workplace-safety', narrative: 'Complete the workplace safety assessment.' },
    };
    mockGet.mockResolvedValue({ ...draft, claim_collection_rules: [
      { claim_name: 'achievement_criteria', source: 'SYSTEM', source_config: configuration },
    ] });
    renderPage();
    const rule = await screen.findByRole('group', { name: 'Claim rule 1: achievement_criteria' });
    expect(within(rule).getByRole('heading', { name: 'achievement_criteria' })).toBeInTheDocument();
    expect(within(rule).getByText('Source: System')).toBeInTheDocument();
    expect(within(rule).getByLabelText('Source configuration for achievement_criteria').textContent).toBe(JSON.stringify(configuration, null, 2));
    expect(mockGet).toHaveBeenCalledExactlyOnceWith('application-template-1', 'org-1');
    for (const operation of [mockValidate, mockActivate, mockDelete, mockDeprecate]) expect(operation).not.toHaveBeenCalled();
  });

  it.each([false, 0, null, '', ['Safety', { passed: false, score: 0 }]])('preserves the stored constant %j in its read-only JSON projection', async (value) => {
    permissions.can.mockImplementation((_resource, action) => action === 'view');
    const configuration = { system_field: 'constant', value };
    mockGet.mockResolvedValue({ ...draft, claim_collection_rules: [
      { claim_name: 'saved_value', source: 'SYSTEM', source_config: configuration },
    ] });
    renderPage();
    const display = await screen.findByLabelText('Source configuration for saved_value');
    expect(display.textContent).toBe(JSON.stringify(configuration, null, 2));
    expect(display).not.toHaveTextContent('Not configured');
    expect(mockValidate).not.toHaveBeenCalled();
  });

  it('renders form, evidence and unknown sources as saved text without interpreting HTML', async () => {
    permissions.can.mockImplementation((_resource, action) => action === 'view');
    const unsafeLookingText = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const configurations = [{ form_field_id: 'email' }, { evidence_type: 'training', field_path: 'completion.score' }, { value: unsafeLookingText }, { value: 0 }];
    mockGet.mockResolvedValue({ ...draft, claim_collection_rules: [
      { claim_name: 'contact_email', source: 'FORM_FIELD', source_config: configurations[0] },
      { claim_name: 'assessment_score', source: 'EVIDENCE_EXTRACTION', source_config: configurations[1] },
      { claim_name: unsafeLookingText, source: 'CUSTOM_SOURCE', source_config: configurations[2] },
      { claim_name: 'unknown_source', source: '__proto__', source_config: configurations[3] },
    ] });
    renderPage();
    const section = await screen.findByRole('region', { name: 'Claim collection rules' });
    expect(within(section).getByText('Source: Form field')).toBeInTheDocument();
    expect(within(section).getByText('Source: Evidence extraction')).toBeInTheDocument();
    expect(within(section).getByText('Source: CUSTOM_SOURCE')).toBeInTheDocument();
    expect(within(section).getByText('Source: __proto__')).toBeInTheDocument();
    const displays = within(section).getAllByLabelText(/^Source configuration for/);
    expect(displays.map((element) => element.textContent)).toEqual(configurations.map((value) => JSON.stringify(value, null, 2)));
    expect(section.querySelector('img,script')).toBeNull();
  });

  it.each([undefined, []])('shows no collection rules when the saved template has none: %j', async (rules) => {
    permissions.can.mockImplementation((_resource, action) => action === 'view');
    mockGet.mockResolvedValue({ ...draft, claim_collection_rules: rules });
    renderPage();
    const section = await screen.findByRole('region', { name: 'Claim collection rules' });
    expect(within(section).getByText('None')).toBeInTheDocument();
  });

  it('distinguishes an unreadable rules response from an empty configuration', async () => {
    permissions.can.mockImplementation((_resource, action) => action === 'view');
    mockGet.mockResolvedValue({ ...draft, claim_collection_rules: { unexpected: true } });
    renderPage();
    const section = await screen.findByRole('region', { name: 'Claim collection rules' });
    expect(within(section).getByText('Saved claim collection rules could not be read.')).toBeInTheDocument();
    expect(within(section).queryByText('None')).not.toBeInTheDocument();
    expect(mockValidate).not.toHaveBeenCalled();
  });

  it('never exposes collection rules from a foreign organization response', async () => {
    mockGet.mockResolvedValue({ ...draft, organization_id: 'org-2', claim_collection_rules: [
      { claim_name: 'foreign_claim', source: 'SYSTEM', source_config: { value: 'foreign configuration' } },
    ] });
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i);
    expect(screen.queryByRole('region', { name: 'Claim collection rules' })).not.toBeInTheDocument();
    expect(screen.queryByText(/foreign configuration/)).not.toBeInTheDocument();
    expect(mockValidate).not.toHaveBeenCalled();
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

  it('keeps a loaded draft available when automatic validation fails and permits retry', async () => {
    mockValidate.mockRejectedValueOnce(new Error('Validation service unavailable'));
    const { user } = renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('Validation service unavailable');
    expect(screen.getByRole('heading', { name: draft.name })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /preview/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^validate$/i }));
    expect(await screen.findByText(/valid and can be activated/i)).toBeInTheDocument();
    expect(screen.queryByText('Validation service unavailable')).not.toBeInTheDocument();
  });

  it('retries a failed template load without navigating away', async () => {
    mockGet.mockRejectedValueOnce(new Error('Template service unavailable'));
    const { user } = renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('Template service unavailable');
    expect(mockValidate).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByRole('heading', { name: draft.name })).toBeInTheDocument();
    expect(await screen.findByText(/valid and can be activated/i)).toBeInTheDocument();
    expect(screen.queryByText('Template service unavailable')).not.toBeInTheDocument();
  });

  it('clears an earlier successful validation when a fresh validation fails', async () => {
    const { user } = renderPage();
    await screen.findByText(/valid and can be activated/i);
    mockValidate.mockRejectedValueOnce(new Error('Fresh validation failed'));
    await user.click(screen.getByRole('button', { name: /^validate$/i }));
    expect(await screen.findByText('Fresh validation failed')).toBeInTheDocument();
    expect(screen.queryByText(/valid and can be activated/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: draft.name })).toBeInTheDocument();
  });

  it.each([
    { valid: 'false', errors: [] },
    { valid: true, errors: [{ section: 'template', field: 'name', code: 'INVALID', message: 'Invalid template' }] },
    { valid: true, errors: null },
    { valid: false, errors: [{ section: 42, field: 'name', code: 'INVALID', message: 'Invalid template' }] },
    null,
  ])('rejects a malformed native validation without hiding the template: %j', async (response) => {
    mockValidate.mockResolvedValue(response);
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/validation response/i);
    expect(screen.getByRole('heading', { name: draft.name })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
    expect(mockActivate).not.toHaveBeenCalled();
  });

  it('keeps lifecycle mutations disabled until automatic validation finishes', async () => {
    const validation = deferred<{ valid: boolean; errors: [] }>();
    mockValidate.mockReturnValueOnce(validation.promise);
    renderPage();
    await screen.findByRole('heading', { name: draft.name });
    expect(screen.getByRole('button', { name: /^validate$/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /^delete$/i })).toBeDisabled();
    await act(async () => { validation.resolve({ valid: true, errors: [] }); });
    expect(screen.getByRole('button', { name: /^validate$/i })).toBeEnabled();
  });

  it('allows only one activation validation and mutation for synchronous repeated clicks', async () => {
    const validation = deferred<{ valid: boolean; errors: [] }>();
    renderPage();
    const activate = await screen.findByRole('button', { name: /^activate$/i });
    mockValidate.mockReturnValueOnce(validation.promise);
    act(() => { fireEvent.click(activate); fireEvent.click(activate); });
    expect(mockValidate).toHaveBeenCalledTimes(2);
    expect(mockActivate).not.toHaveBeenCalled();
    await act(async () => { validation.resolve({ valid: true, errors: [] }); });
    expect(mockActivate).toHaveBeenCalledTimes(1);
  });

  it.each([
    { id: 'another-template', status: 'ACTIVE' },
    { organization_id: 'another-org', status: 'ACTIVE' },
    { status: 'DRAFT' },
  ])('rejects an activation response with the wrong native identity or lifecycle: %j', async (replacement) => {
    mockActivate.mockResolvedValue({ ...draft, ...replacement });
    const { user } = renderPage();
    await user.click(await screen.findByRole('button', { name: /^activate$/i }));
    expect(await screen.findByText(/activation response/i)).toBeInTheDocument();
    expect(screen.getByText('DRAFT')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^deprecate$/i })).not.toBeInTheDocument();
  });

  it('rejects a deprecation response that did not enter the deprecated lifecycle', async () => {
    mockGet.mockResolvedValue({ ...draft, status: 'ACTIVE' });
    mockDeprecate.mockResolvedValue({ ...draft, status: 'ACTIVE' });
    const { user } = renderPage();
    await user.click(await screen.findByRole('button', { name: /^deprecate$/i }));
    await user.click(screen.getAllByRole('button', { name: /^deprecate$/i }).at(-1)!);
    expect(await screen.findByRole('alert')).toHaveTextContent(/deprecation response/i);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText('ACTIVE')).toBeInTheDocument();
  });

  it('does not activate after the create grant changes during validation', async () => {
    const validation = deferred<{ valid: boolean; errors: [] }>();
    const { user, rerender } = renderPage();
    const activate = await screen.findByRole('button', { name: /^activate$/i });
    mockValidate.mockReturnValueOnce(validation.promise);
    await user.click(activate);
    permissions.can.mockImplementation((_resource, action) => action === 'view');
    rerender(page());
    await act(async () => { validation.resolve({ valid: true, errors: [] }); });
    expect(mockActivate).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
  });

  it('discards activation validation when the same template opens in a new route entry', async () => {
    const validation = deferred<{ valid: boolean; errors: [] }>();
    const { user } = renderPage();
    const activate = await screen.findByRole('button', { name: /^activate$/i });
    mockValidate.mockReturnValueOnce(validation.promise);
    await user.click(activate);
    mockGet.mockResolvedValue({ ...draft, name: 'Reopened draft' });
    await user.click(screen.getByRole('link', { name: 'Reopen template' }));
    await act(async () => { validation.resolve({ valid: true, errors: [] }); });
    expect(mockActivate).not.toHaveBeenCalled();
    expect(await screen.findByRole('heading', { name: 'Reopened draft' })).toBeInTheDocument();
  });

  it('does not navigate away from a new route entry when an earlier delete finishes', async () => {
    const deletion = deferred<void>();
    mockDelete.mockReturnValueOnce(deletion.promise);
    const { user } = renderPage();
    await screen.findByText(/valid and can be activated/i);
    await user.click(screen.getByRole('button', { name: /^delete$/i }));
    await user.click(screen.getAllByRole('button', { name: /^delete$/i }).at(-1)!);
    mockGet.mockResolvedValue({ ...draft, name: 'Reopened draft' });
    await act(async () => { navigateTo('/console/org/templates/applications/application-template-1?review=again'); });
    await act(async () => { deletion.resolve(); });
    expect(screen.queryByRole('heading', { name: 'Application Template inventory' })).not.toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'Reopened draft' })).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('discards late deprecation results when lifecycle grants change', async () => {
    const deprecation = deferred<typeof draft>();
    mockGet.mockResolvedValue({ ...draft, status: 'ACTIVE' });
    mockDeprecate.mockReturnValueOnce(deprecation.promise);
    const { user, rerender } = renderPage();
    await user.click(await screen.findByRole('button', { name: /^deprecate$/i }));
    await user.click(screen.getAllByRole('button', { name: /^deprecate$/i }).at(-1)!);
    permissions.can.mockImplementation((_resource, action) => action === 'view');
    rerender(page());
    await act(async () => { deprecation.resolve({ ...draft, status: 'DEPRECATED' }); });
    expect(screen.getByText('ACTIVE')).toBeInTheDocument();
    expect(screen.queryByText('DEPRECATED')).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('does not close a pending destructive action dialog as if the action were cancelled', async () => {
    const deletion = deferred<void>();
    mockDelete.mockReturnValueOnce(deletion.promise);
    const { user } = renderPage();
    await screen.findByText(/valid and can be activated/i);
    await user.click(screen.getByRole('button', { name: /^delete$/i }));
    await user.click(screen.getAllByRole('button', { name: /^delete$/i }).at(-1)!);
    expect(screen.getByRole('button', { name: /^cancel$/i })).toBeDisabled();
    await user.keyboard('{Escape}');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await act(async () => { deletion.reject(new Error('Delete service unavailable')); });
    expect(screen.getByRole('alert')).toHaveTextContent('Delete service unavailable');
    expect(screen.getByRole('button', { name: /^cancel$/i })).toBeEnabled();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    mockDelete.mockResolvedValueOnce(undefined);
    await user.click(screen.getByRole('button', { name: /^delete$/i }));
    expect(await screen.findByRole('heading', { name: 'Application Template inventory' })).toBeInTheDocument();
    expect(mockDelete).toHaveBeenCalledTimes(2);
  });

  it('isolates the new preview tab from its opener', async () => {
    renderPage();
    const preview = await screen.findByRole('link', { name: /preview/i });
    expect(preview).toHaveAttribute('target', '_blank');
    expect(preview).toHaveAttribute('rel', 'noopener noreferrer');
  });
});
