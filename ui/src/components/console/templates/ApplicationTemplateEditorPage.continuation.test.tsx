import { Suspense, useLayoutEffect, useState } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithoutRouter, screen } from '@test/utils';
import ApplicationTemplateEditorPage from './ApplicationTemplateEditorPage';

const trace = vi.hoisted(() => ({
  organization: 'org-1',
  saves: [] as Promise<unknown>[],
  owners: [] as Array<(() => boolean) | undefined>,
  get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn(),
}));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: trace.organization }) }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: 'principal-1' }, isAuthenticated: true }) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({ can: () => true, isLoading: false }) }));
vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: vi.fn(async ({ organization_id }) => [{
    id: 'credential-1', organization_id, name: 'Membership Badge', status: 'ACTIVE', revocation_profile_id: 'revocation-1',
    claims: [{ name: 'email', display_name: 'Email', type: 'EMAIL', required: true }],
  }]),
}));
vi.mock('../../../services/policySetsApi', () => ({ listPolicySets: vi.fn(async () => []) }));
vi.mock('../../../services/api', () => ({ get: trace.get, post: trace.post, patch: trace.patch, del: trace.del }));
// Observe the actual service/helper boundary; creation and its network retry remain real.
vi.mock('../../../services/applicationTemplatesApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../services/applicationTemplatesApi')>();
  return {
    ...actual,
    createApplicationTemplate: (...args: Parameters<typeof actual.createApplicationTemplate>) => {
      const result = actual.createApplicationTemplate(...args);
      trace.saves.push(result);
      trace.owners.push(args[1]?.isCurrent);
      return result;
    },
    updateApplicationTemplate: (...args: Parameters<typeof actual.updateApplicationTemplate>) => {
      const result = actual.updateApplicationTemplate(...args);
      trace.saves.push(result);
      return result;
    },
  };
});

const NEW_PATH = '/console/org/templates/applications/new';
const EDIT_PATH = '/console/org/templates/applications/template-1/edit';
const NEXT_PATH = '/console/org/policies';
let navigateTo: ReturnType<typeof useNavigate>;
let refreshCommittedEditor: () => void;

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function CurrentRoute() {
  const location = useLocation();
  const navigate = useNavigate();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  return <output data-testid="committed-route" data-entry-key={location.key}>{location.pathname}</output>;
}

function heldEditor({ create = false, samePath = false } = {}) {
  const path = create ? NEW_PATH : EDIT_PATH;
  window.history.replaceState({}, '', path);
  const initialKey = window.history.state?.key || 'default';
  const transition = deferred<void>();
  let ready = false;
  function EditorEntry() {
    const location = useLocation();
    const [, setRevision] = useState(0);
    useLayoutEffect(() => { refreshCommittedEditor = () => setRevision(value => value + 1); }, []);
    if (samePath && location.key !== initialKey && !ready) throw transition.promise;
    return <ApplicationTemplateEditorPage />;
  }
  function Destination() {
    if (!ready) throw transition.promise;
    return <h1>Other work</h1>;
  }
  const view = renderWithoutRouter(<BrowserRouter><Suspense fallback={<h1>Loading destination</h1>}>
    <CurrentRoute /><Routes>
      <Route path={create ? NEW_PATH : '/console/org/templates/applications/:templateId/edit'} element={<EditorEntry />} />
      <Route path={NEXT_PATH} element={<Destination />} />
      <Route path="/console/org/templates/applications/:templateId" element={<h1>Saved template</h1>} />
      <Route path="/console/org/templates/applications" element={<h1>Template list</h1>} />
    </Routes>
  </Suspense></BrowserRouter>);
  return { ...view, path, async release() {
    ready = true;
    await act(async () => { transition.resolve(); });
  } };
}

async function fillCreation(user: ReturnType<typeof renderWithoutRouter>['user']) {
  await user.type(await screen.findByRole('textbox', { name: /^name/i }), 'Member form');
  await user.click(screen.getByRole('combobox', { name: /credential template/i }));
  await user.click(await screen.findByRole('option', { name: 'Membership Badge' }));
  return screen.getByRole('button', { name: /save draft/i });
}

async function settleSaves() {
  await act(async () => { await Promise.allSettled(trace.saves); });
}

beforeEach(() => {
  trace.organization = 'org-1'; trace.saves.length = 0; trace.owners.length = 0;
  trace.get.mockReset().mockImplementation(async (path: string) => ({
    id: 'template-1', organization_id: new URL(path, 'https://fixture.example').searchParams.get('organization_id'),
    name: 'Editable member form', status: 'DRAFT', credential_template_id: 'credential-1',
    form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL' }],
  }));
  trace.post.mockReset().mockResolvedValue({ id: 'saved-draft' });
  trace.patch.mockReset().mockResolvedValue({ id: 'template-1' });
  trace.del.mockReset();
});

describe('Application editor committed browser-entry ownership', () => {
  it.each(['success', 'failure'] as const)('preserves a suspended external destination when an old edit settles with %s', async (outcome) => {
    const reply = deferred<unknown>();
    trace.patch.mockReturnValueOnce(reply.promise);
    const view = heldEditor();
    try {
      await screen.findByDisplayValue('Editable member form');
      await view.user.click(screen.getByRole('button', { name: /save draft/i }));
      expect(trace.patch).toHaveBeenCalledTimes(1);
      const oldKey = screen.getByTestId('committed-route').getAttribute('data-entry-key');
      await act(async () => { navigateTo(NEXT_PATH); });
      expect(window.location.pathname).toBe(NEXT_PATH);
      expect(window.history.state?.key).not.toBe(oldKey);
      expect(screen.getByTestId('committed-route')).toHaveAttribute('data-entry-key', oldKey);
      expect(screen.getByDisplayValue('Editable member form')).toBeInTheDocument();

      if (outcome === 'success') reply.resolve({ id: 'template-1' });
      else reply.reject(new Error('Obsolete edit failure'));
      await settleSaves();
      expect(window.location.pathname).toBe(NEXT_PATH);
      expect(screen.queryByText('Obsolete edit failure')).not.toBeInTheDocument();
      expect(screen.queryByRole('heading', { name: 'Saved template' })).not.toBeInTheDocument();
    } finally { reply.resolve({ id: 'template-1' }); await settleSaves(); await view.release(); }
    expect(screen.getByRole('heading', { name: 'Other work' })).toBeInTheDocument();
  });

  it('rejects save, edit, and cancellation events from an old visible entry while navigation is suspended', async () => {
    const view = heldEditor();
    try {
      const name = await screen.findByDisplayValue('Editable member form');
      const save = screen.getByRole('button', { name: /save draft/i });
      await act(async () => { navigateTo(NEXT_PATH); });
      expect(screen.getByTestId('committed-route')).toHaveTextContent(EDIT_PATH);
      act(() => {
        fireEvent.change(name, { target: { value: 'Obsolete edit' } });
        fireEvent.click(screen.getByRole('button', { name: 'Add field' }));
        fireEvent.click(save);
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
      });
      expect(name).toHaveValue('Editable member form');
      expect(screen.getAllByRole('textbox', { name: 'Field ID' })).toHaveLength(1);
      expect(trace.patch).not.toHaveBeenCalled();
      expect(window.location.pathname).toBe(NEXT_PATH);
    } finally { await view.release(); }
  });

  it('treats a new history entry at the identical URL as a new editor', async () => {
    const reply = deferred<unknown>();
    trace.patch.mockReturnValueOnce(reply.promise);
    const view = heldEditor({ samePath: true });
    try {
      await screen.findByDisplayValue('Editable member form');
      await view.user.click(screen.getByRole('button', { name: /save draft/i }));
      const oldKey = screen.getByTestId('committed-route').getAttribute('data-entry-key');
      await act(async () => { navigateTo(EDIT_PATH); });
      expect(window.location.pathname).toBe(EDIT_PATH);
      expect(window.history.state?.key).not.toBe(oldKey);
      expect(screen.getByTestId('committed-route')).toHaveAttribute('data-entry-key', oldKey);
      reply.resolve({ id: 'template-1' }); await settleSaves();
      expect(window.location.pathname).toBe(EDIT_PATH);
      expect(screen.queryByRole('heading', { name: 'Saved template' })).not.toBeInTheDocument();
    } finally { reply.resolve({ id: 'template-1' }); await settleSaves(); await view.release(); }
    await screen.findByDisplayValue('Editable member form');
    expect(screen.getByRole('button', { name: /save draft/i })).toBeEnabled();
  });

  it('stops the actual creation helper retry after browser departure before React commits', async () => {
    const reply = deferred<unknown>();
    trace.post.mockReturnValueOnce(reply.promise);
    const view = heldEditor({ create: true });
    try {
      await view.user.click(await fillCreation(view.user));
      expect(trace.post).toHaveBeenCalledTimes(1);
      expect(trace.owners[0]?.()).toBe(true);
      await act(async () => { navigateTo(NEXT_PATH); });
      expect(screen.getByTestId('committed-route')).toHaveTextContent(NEW_PATH);
      expect(trace.owners[0]?.()).toBe(false);
      reply.reject(new TypeError('Failed to fetch'));
      await settleSaves();
      expect(trace.post).toHaveBeenCalledTimes(1);
      expect(window.location.pathname).toBe(NEXT_PATH);
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    } finally { reply.resolve({ id: 'saved-draft' }); await settleSaves(); await view.release(); }
  });

  it('invalidates the old save synchronously on Back and presents a usable fresh editor', async () => {
    const reply = deferred<unknown>();
    trace.post.mockReturnValueOnce(reply.promise);
    const view = heldEditor({ create: true });
    const observed: Array<{ path: string; oldSaveCurrent: boolean | undefined }> = [];
    let oldOwner: (() => boolean) | undefined;
    const observeBack = () => {
      observed.push({ path: window.location.pathname, oldSaveCurrent: oldOwner?.() });
      reply.resolve({ id: 'saved-draft' });
    };
    try {
      await view.user.click(await fillCreation(view.user));
      oldOwner = trace.owners[0];
      expect(oldOwner?.()).toBe(true);
      await act(async () => { navigateTo(NEXT_PATH); });
      window.addEventListener('popstate', observeBack, true);
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(observed).toEqual([{ path: NEW_PATH, oldSaveCurrent: false }]));
      await settleSaves(); await view.release();
      expect(window.location.pathname).toBe(NEW_PATH);
      expect(screen.getByRole('textbox', { name: /^name/i })).toHaveValue('');
      await view.user.click(await fillCreation(view.user));
      await settleSaves();
      expect(trace.post).toHaveBeenCalledTimes(2);
      expect(await screen.findByRole('heading', { name: 'Saved template' })).toBeInTheDocument();
    } finally {
      window.removeEventListener('popstate', observeBack, true);
      reply.resolve({ id: 'saved-draft' }); await settleSaves(); await view.release();
    }
  });

  it('keeps a replacement organization editor bound to the original committed browser entry', async () => {
    const view = heldEditor();
    try {
      await screen.findByDisplayValue('Editable member form');
      await act(async () => { navigateTo(NEXT_PATH); });
      await act(async () => { trace.organization = 'org-2'; refreshCommittedEditor(); });
      await screen.findByDisplayValue('Editable member form');
      expect(window.location.pathname).toBe(NEXT_PATH);
      expect(screen.getByTestId('committed-route')).toHaveTextContent(EDIT_PATH);
      const save = screen.getByRole('button', { name: /save draft/i });
      expect(save).toBeDisabled();
      fireEvent.click(save);
      expect(trace.patch).not.toHaveBeenCalled();
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(window.location.pathname).toBe(EDIT_PATH));
      await view.release();
      await waitFor(() => expect(screen.getByRole('button', { name: /save draft/i })).toBeEnabled());
    } finally { await view.release(); }
  });
});
