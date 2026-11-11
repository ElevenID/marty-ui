import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Link, Route, Routes, useLocation } from 'react-router';
import { act, fireEvent, render, screen, waitFor } from '@test/utils';
import CredentialTemplateEditorPage from './CredentialTemplateEditorPage';

const { scope, load, save, post } = vi.hoisted(() => ({
  scope: { activeOrgId: 'org-1', principal: 'user-1', authenticated: true, loading: false, view: true, edit: true, version: true },
  load: vi.fn(), save: vi.fn(), post: vi.fn(),
}));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => scope }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: scope.principal }, isAuthenticated: scope.authenticated }) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({
  isLoading: scope.loading, can: (_resource: string, action: 'view' | 'edit' | 'version') => scope[action],
}) }));
vi.mock('../../../services/api', () => ({ post: (...args: unknown[]) => post(...args) }));
vi.mock('../../../services/presentationPolicyApi', async (original) => ({
  ...await original<typeof import('../../../services/presentationPolicyApi')>(),
  getCredentialTemplate: (...args: unknown[]) => load(...args),
  updateCredentialTemplate: (...args: unknown[]) => save(...args),
}));

function template(id = 'template-1', organizationId = 'org-1', status = 'draft') {
  return { id, organization_id: organizationId, status, name: 'Review credential', description: 'Keep this description',
    credential_type: 'VerifiableCredential', credential_payload_format: 'VC_JWT', issuer_did: 'did:web:issuer.example',
    claims: [{ name: 'subject', required: false, validation: { pattern: '[A-Z]+' } }],
    validity_rules: { default_validity_days: 365, max_validity_days: 730, not_before_offset_seconds: 0,
      renewable: false, renewal_window_days: 0, require_revalidation: true, revalidation_interval_days: 7 },
  };
}
function deferred() {
  let resolve!: (value: unknown) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function CurrentPath() { return <div data-testid="path">{useLocation().pathname}</div>; }
function EditorRoutes() {
  return <><Link to="/elsewhere">Leave editor</Link><Routes>
    <Route path="/console/org/templates/credentials/:templateId/edit" element={<CredentialTemplateEditorPage />} />
    <Route path="/console/org/templates/credentials/:templateId" element={<div>Template detail</div>} />
    <Route path="*" element={<div>Elsewhere</div>} />
  </Routes><CurrentPath /></>;
}
function openEditor() { return render(<EditorRoutes />); }

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
  Object.assign(scope, { activeOrgId: 'org-1', principal: 'user-1', authenticated: true, loading: false, view: true, edit: true, version: true });
  window.history.replaceState({}, '', '/console/org/templates/credentials/template-1/edit');
  load.mockResolvedValue(template());
  save.mockImplementation(async (id, patch) => ({ ...template(id, patch.organization_id), ...patch,
    validity_rules: { ...template().validity_rules, ...patch.validity_rules } }));
});

describe('CredentialTemplateEditorPage', () => {
  it('loads the selected draft, preserves rejected edits, and saves only the changed setting', async () => {
    const { user } = openEditor();
    const name = await screen.findByRole('textbox', { name: 'Template name' });
    expect(name).toHaveValue('Review credential');
    expect(post).not.toHaveBeenCalled();
    save.mockRejectedValueOnce(new Error('Issuer is unavailable'));
    await user.clear(name); await user.type(name, 'Renamed draft');
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(await screen.findByText('Issuer is unavailable')).toBeInTheDocument();
    expect(name).toHaveValue('Renamed draft');
    expect(screen.getByRole('textbox', { name: 'Description' })).toHaveValue('Keep this description');
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(await screen.findByText('Draft settings saved.')).toBeInTheDocument();
    expect(save).toHaveBeenLastCalledWith('template-1', { organization_id: 'org-1', name: 'Renamed draft' });
    expect(screen.getByRole('button', { name: 'Save draft' })).toBeDisabled();
  });

  it('rejects an empty numeric draft and sends a sparse signed offset without renewal defaults', async () => {
    const { user } = openEditor();
    const offset = await screen.findByRole('spinbutton', { name: 'Not-before offset (seconds)' });
    await user.clear(offset);
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('must be a whole number');
    expect(save).not.toHaveBeenCalled();
    await user.type(offset, '-90');
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(await screen.findByText('Draft settings saved.')).toBeInTheDocument();
    expect(save).toHaveBeenCalledWith('template-1', { organization_id: 'org-1', validity_rules: { not_before_offset_seconds: -90 } });
  });

  it('validates native UTF-8 name length before dispatch', async () => {
    const { user } = openEditor();
    const name = await screen.findByRole('textbox', { name: 'Template name' });
    fireEvent.change(name, { target: { value: '界'.repeat(86) } });
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(await screen.findByText('The template name is too long. Use a shorter name.')).toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
  });

  it.each([
    ['template-other', 'org-1'], ['template-1', 'org-other'],
  ])('does not hydrate a response for %s in %s', async (id, org) => {
    load.mockResolvedValue(template(id, org));
    openEditor();
    expect(await screen.findByRole('alert')).toHaveTextContent('not available in the selected organization');
    expect(screen.queryByRole('textbox', { name: 'Template name' })).not.toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
  });

  it('keeps entered values when a save returns the wrong resource', async () => {
    const { user } = openEditor();
    const name = await screen.findByRole('textbox', { name: 'Template name' });
    fireEvent.change(name, { target: { value: 'Keep entered draft' } });
    save.mockResolvedValue(template('foreign', 'org-1'));
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('saved draft could not be confirmed');
    expect(name).toHaveValue('Keep entered draft');
    expect(screen.queryByText('Draft settings saved.')).not.toBeInTheDocument();
  });

  it.each(['active', 'deprecated', 'archived'])('keeps an %s template read-only until an explicit version request returns its new ID', async (status) => {
    load.mockImplementation(async (id) => template(id, 'org-1', id === 'template-1' ? status : 'draft'));
    post.mockResolvedValue(template('new-draft'));
    const { user } = openEditor();
    const create = await screen.findByRole('button', { name: 'Create new draft version' });
    expect(screen.queryByRole('button', { name: 'Save draft' })).not.toBeInTheDocument();
    expect(post).not.toHaveBeenCalled();
    await user.click(create);
    expect(await screen.findByRole('textbox', { name: 'Template name' })).toBeInTheDocument();
    expect(screen.getByTestId('path')).toHaveTextContent('/console/org/templates/credentials/new-draft/edit');
    expect(post).toHaveBeenCalledTimes(1);
    expect(post).toHaveBeenCalledWith('/v1/credential-templates/template-1/new-version', {}, expect.objectContaining({
      params: { organization_id: 'org-1' }, headers: { 'Idempotency-Key': expect.stringMatching(/^credential-template-version:/) },
    }));
    expect(save).not.toHaveBeenCalled();
  });

  it('does not turn version permission into edit permission', async () => {
    scope.edit = false;
    load.mockResolvedValue(template('template-1', 'org-1', 'active'));
    post.mockResolvedValue(template('new-draft'));
    const { user } = openEditor();
    await user.click(await screen.findByRole('button', { name: 'Create new draft version' }));
    expect(await screen.findByText('Template detail')).toBeInTheDocument();
    expect(screen.getByTestId('path')).toHaveTextContent('/console/org/templates/credentials/new-draft');
    expect(save).not.toHaveBeenCalled();
  });

  it('retains an uncertain version request across remount and requires explicit duplicate-risk confirmation', async () => {
    load.mockResolvedValue(template('template-1', 'org-1', 'active'));
    post.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    const first = openEditor();
    await first.user.click(await screen.findByRole('button', { name: 'Create new draft version' }));
    expect(await screen.findByText(/A draft-version request was sent without a confirmed result/)).toBeInTheDocument();
    expect(post).toHaveBeenCalledTimes(1);
    first.unmount();
    const second = openEditor();
    await screen.findByText(/A draft-version request was sent without a confirmed result/);
    expect(screen.queryByRole('button', { name: 'Create new draft version' })).not.toBeInTheDocument();
    await second.user.click(screen.getByRole('button', { name: 'Start a separate draft version' }));
    expect(await screen.findByRole('dialog')).toHaveTextContent('A previous request may already have created a draft');
    expect(post).toHaveBeenCalledTimes(1);
    post.mockResolvedValue(template('confirmed-draft'));
    await second.user.click(screen.getByRole('button', { name: 'Create separate draft' }));
    await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
    expect(post.mock.calls[0][2].headers['Idempotency-Key']).not.toBe(post.mock.calls[1][2].headers['Idempotency-Key']);
  });

  it.each(['organization', 'principal', 'grant'] as const)('discards a pending save after the %s owner changes', async (change) => {
    const pending = deferred(); save.mockReturnValueOnce(pending.promise);
    load.mockImplementation(async (id) => template(id, scope.activeOrgId));
    const view = openEditor();
    fireEvent.change(await screen.findByRole('textbox', { name: 'Template name' }), { target: { value: 'Old actor edit' } });
    await view.user.click(screen.getByRole('button', { name: 'Save draft' }));
    if (change === 'organization') scope.activeOrgId = 'org-2';
    if (change === 'principal') scope.principal = 'user-2';
    if (change === 'grant') scope.edit = false;
    view.rerender(<EditorRoutes />);
    await screen.findByRole('textbox', { name: 'Template name' });
    await act(async () => pending.resolve({ ...template(), name: 'Old actor edit' }));
    expect(screen.queryByText('Draft settings saved.')).not.toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Template name' })).toHaveValue('Review credential');
    expect(save).toHaveBeenCalledTimes(1);
  });

  it('does not navigate or send another version request after leaving the pending action', async () => {
    const pending = deferred(); post.mockReturnValue(pending.promise);
    load.mockResolvedValue(template('template-1', 'org-1', 'active'));
    const { user } = openEditor();
    await user.click(await screen.findByRole('button', { name: 'Create new draft version' }));
    await user.click(screen.getByRole('link', { name: 'Leave editor' }));
    await act(async () => pending.resolve(template('late-draft')));
    expect(screen.getByTestId('path')).toHaveTextContent('/elsewhere');
    expect(post).toHaveBeenCalledTimes(1);
  });

  it('gates reads while permissions are loading or view access is denied', () => {
    scope.loading = true;
    const view = openEditor();
    expect(load).not.toHaveBeenCalled();
    scope.loading = false; scope.view = false;
    view.rerender(<EditorRoutes />);
    expect(screen.getByRole('alert')).toHaveTextContent('do not have permission to view');
    expect(load).not.toHaveBeenCalled();
    expect(post).not.toHaveBeenCalled();
  });
});
