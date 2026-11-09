import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInstance } from 'i18next';
import { BrowserRouter, Link, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, fireEvent, renderWithRouter, renderWithoutRouter, screen, waitFor } from '@test/utils';
import TrustProfileEditPage from '../TrustProfileEditPage';

const { getProfile, updateProfile, scope, permissions } = vi.hoisted(() => ({
  getProfile: vi.fn(), updateProfile: vi.fn(), scope: { activeOrgId: 'org-1' },
  permissions: { isLoading: false, can: vi.fn((_resource: string, _action: string) => true) },
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => scope }));
vi.mock('../../../../hooks/usePermissions', () => ({ usePermissions: () => permissions }));
vi.mock('../../../../services/presentationPolicyApi', () => ({
  getTrustProfile: getProfile, updateTrustProfile: updateProfile,
}));

const profile = (id = 'profile-1', organizationId = 'org-1') => ({
  id, organization_id: organizationId, name: id === 'profile-1' ? 'First profile' : 'Second profile',
  description: 'Original description', framework: 'custom', supported_formats: ['sd_jwt_vc'], status: 'active',
});
let navigateTo: ReturnType<typeof useNavigate>;
function NavigationProbe() {
  navigateTo = useNavigate();
  const location = useLocation();
  return <output data-testid="current-route">{location.pathname}{location.search}{location.hash}</output>;
}
function page() {
  return <>
    <NavigationProbe />
    <Link to="/console/org/trust/profiles/profile-2/edit">Edit second profile</Link>
    <Link to="/console/org/trust/profiles/profile-1/edit?review=again">Reopen first profile</Link>
    <Routes>
      <Route path="/console/org/trust/profiles/:id/edit" element={<TrustProfileEditPage />} />
      <Route path="/console/org/trust/profiles/:id" element={<h1>Profile details</h1>} />
      <Route path="/elsewhere" element={<h1>Another page</h1>} />
    </Routes>
  </>;
}
function renderPage() {
  return renderWithRouter(page(), { initialEntries: ['/console/org/trust/profiles/profile-1/edit'] });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function editAndSave() {
  fireEvent.change(await screen.findByTestId('edit.trustProfile.name'), { target: { value: 'Edited profile' } });
  fireEvent.click(screen.getByTestId('edit.trustProfile.save'));
}

describe('Trust Profile edit scope and save lifetimes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState({}, '', '/');
    scope.activeOrgId = 'org-1'; permissions.isLoading = false; permissions.can.mockReturnValue(true);
    getProfile.mockReset(); updateProfile.mockReset();
    getProfile.mockImplementation(async (id) => profile(id, scope.activeOrgId));
    updateProfile.mockImplementation(async (id, changes) => ({ ...profile(id, scope.activeOrgId), ...changes }));
  });

  it.each(['loading permissions', 'no organization', 'view denied', 'edit denied'])('does not load or expose an editor with %s', async (condition) => {
    if (condition === 'loading permissions') permissions.isLoading = true;
    if (condition === 'no organization') scope.activeOrgId = '';
    if (condition.endsWith('denied')) permissions.can.mockImplementation((_resource, action) => action !== condition.split(' ')[0]);
    renderPage();
    await act(async () => {});
    expect(getProfile).not.toHaveBeenCalled();
    expect(screen.queryByTestId('edit.trustProfile.name')).not.toBeInTheDocument();
  });

  it.each([{ id: 'wrong-profile' }, { organization_id: 'org-2' }])('rejects a loaded profile with mismatched identity %j', async (invalid) => {
    getProfile.mockResolvedValue({ ...profile(), ...invalid });
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization|requested profile/i);
    expect(screen.queryByTestId('edit.trustProfile.name')).not.toBeInTheDocument();
    expect(updateProfile).not.toHaveBeenCalled();
  });

  it('shows a retryable not-found state instead of a permanent skeleton for a null result', async () => {
    getProfile.mockResolvedValueOnce(null);
    const { user } = renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/not found/i);
    await user.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByDisplayValue('First profile')).toBeInTheDocument();
  });

  it('replaces unsaved form fields when navigating directly to another profile', async () => {
    const { user } = renderPage();
    fireEvent.change(await screen.findByDisplayValue('First profile'), { target: { value: 'Unsaved first profile' } });
    await user.click(screen.getByRole('link', { name: 'Edit second profile' }));
    expect(await screen.findByDisplayValue('Second profile')).toBeInTheDocument();
    expect(screen.queryByDisplayValue('Unsaved first profile')).not.toBeInTheDocument();
    fireEvent.change(screen.getByTestId('edit.trustProfile.description'), { target: { value: 'Second description' } });
    fireEvent.click(screen.getByTestId('edit.trustProfile.save'));
    await waitFor(() => expect(updateProfile).toHaveBeenCalledWith('profile-2', { description: 'Second description' }));
  });

  it('starts a fresh form for another entry and query of the same profile', async () => {
    const { user } = renderPage();
    fireEvent.change(await screen.findByDisplayValue('First profile'), { target: { value: 'Stale edits' } });
    await user.click(screen.getByRole('link', { name: 'Reopen first profile' }));
    expect(await screen.findByDisplayValue('First profile')).toBeInTheDocument();
    expect(screen.queryByDisplayValue('Stale edits')).not.toBeInTheDocument();
    expect(getProfile).toHaveBeenCalledTimes(2);
  });

  it('discards unsaved fields when the same URL is opened as a new history entry', async () => {
    renderPage();
    fireEvent.change(await screen.findByDisplayValue('First profile'), { target: { value: 'Stale entry fields' } });
    await act(async () => { navigateTo('/console/org/trust/profiles/profile-1/edit'); });
    expect(await screen.findByDisplayValue('First profile')).toBeInTheDocument();
    expect(screen.queryByDisplayValue('Stale entry fields')).not.toBeInTheDocument();
    expect(getProfile).toHaveBeenCalledTimes(2);
  });

  it('discards the old organization loader before mounting the replacement editor', async () => {
    const old = deferred<ReturnType<typeof profile>>();
    getProfile.mockReturnValueOnce(old.promise);
    const { rerender } = renderPage();
    scope.activeOrgId = 'org-2';
    getProfile.mockResolvedValue({ ...profile('profile-1', 'org-2'), name: 'Organization two profile' });
    rerender(page());
    expect(await screen.findByDisplayValue('Organization two profile')).toBeInTheDocument();
    await act(async () => { old.resolve(profile()); });
    expect(screen.queryByDisplayValue('First profile')).not.toBeInTheDocument();
    expect(screen.getByDisplayValue('Organization two profile')).toBeInTheDocument();
  });

  it('does not navigate away from a new route after an obsolete save succeeds', async () => {
    const save = deferred<ReturnType<typeof profile>>(); updateProfile.mockReturnValue(save.promise);
    renderPage(); await editAndSave();
    await act(async () => { navigateTo('/elsewhere'); });
    await act(async () => { save.resolve({ ...profile(), name: 'Edited profile' }); });
    expect(screen.getByRole('heading', { name: 'Another page' })).toBeInTheDocument();
  });

  it('does not restore an old error or form after another profile becomes current', async () => {
    const save = deferred<ReturnType<typeof profile>>(); updateProfile.mockReturnValue(save.promise);
    const { user } = renderPage(); await editAndSave();
    await user.click(screen.getByRole('link', { name: 'Edit second profile' }));
    await act(async () => { save.reject(new Error('Old save failed')); });
    expect(await screen.findByDisplayValue('Second profile')).toBeInTheDocument();
    expect(screen.queryByText('Old save failed')).not.toBeInTheDocument();
    expect(screen.getByTestId('edit.trustProfile.save')).toBeEnabled();
  });

  it('does not complete an old save in a replacement query entry', async () => {
    const save = deferred<ReturnType<typeof profile>>(); updateProfile.mockReturnValue(save.promise);
    const { user } = renderPage(); await editAndSave();
    await user.click(screen.getByRole('link', { name: 'Reopen first profile' }));
    await act(async () => { save.resolve({ ...profile(), name: 'Edited profile' }); });
    expect(screen.getByTestId('current-route')).toHaveTextContent('/profile-1/edit?review=again');
    expect(await screen.findByDisplayValue('First profile')).toBeInTheDocument();
  });

  it('invalidates the pending save when edit permission is lost', async () => {
    const save = deferred<ReturnType<typeof profile>>(); updateProfile.mockReturnValue(save.promise);
    const { rerender } = renderPage(); await editAndSave();
    permissions.can.mockImplementation((_resource, action) => action !== 'edit'); rerender(page());
    await act(async () => { save.resolve({ ...profile(), name: 'Edited profile' }); });
    expect(screen.queryByTestId('edit.trustProfile.name')).not.toBeInTheDocument();
    expect(screen.getByTestId('current-route')).toHaveTextContent('/profile-1/edit');
    expect(updateProfile).toHaveBeenCalledTimes(1);
  });

  it('keeps the replacement organization editor current after an older organization save settles', async () => {
    const save = deferred<ReturnType<typeof profile>>(); updateProfile.mockReturnValue(save.promise);
    const { rerender } = renderPage(); await editAndSave();
    scope.activeOrgId = 'org-2';
    getProfile.mockResolvedValue({ ...profile('profile-1', 'org-2'), name: 'Organization two editor' });
    rerender(page());
    expect(await screen.findByDisplayValue('Organization two editor')).toBeInTheDocument();
    await act(async () => { save.resolve({ ...profile(), name: 'Edited profile' }); });
    expect(screen.getByDisplayValue('Organization two editor')).toBeInTheDocument();
    expect(screen.getByTestId('current-route')).toHaveTextContent('/profile-1/edit');
    expect(updateProfile).toHaveBeenCalledTimes(1);
  });

  it.each([
    '/console/org/trust/profiles/profile-2/edit',
    '/console/org/trust/profiles/profile-1/edit?review=again',
    '/console/org/trust/profiles/profile-1/edit',
  ])('keeps a newer browser entry when a save resolves before its React transition commits: %s', async (nextPath) => {
    const save = deferred<ReturnType<typeof profile>>(); updateProfile.mockReturnValue(save.promise);
    window.history.replaceState({}, '', '/console/org/trust/profiles/profile-1/edit');
    renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>); await editAndSave();
    await act(async () => {
      save.resolve({ ...profile(), name: 'Edited profile' });
      queueMicrotask(() => navigateTo(nextPath));
    });
    expect(screen.getByTestId('current-route')).toHaveTextContent(nextPath);
    expect(await screen.findByDisplayValue(nextPath.includes('profile-2') ? 'Second profile' : 'First profile')).toBeInTheDocument();
  });

  it('does not dispatch a new save from the old browser entry while navigation is pending', async () => {
    window.history.replaceState({}, '', '/console/org/trust/profiles/profile-1/edit');
    renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>);
    fireEvent.change(await screen.findByDisplayValue('First profile'), { target: { value: 'Stale submitted edit' } });
    const saveButton = screen.getByTestId('edit.trustProfile.save');
    await act(async () => {
      navigateTo('/console/org/trust/profiles/profile-2/edit');
      fireEvent.click(saveButton);
    });
    expect(updateProfile).not.toHaveBeenCalled();
    expect(await screen.findByDisplayValue('Second profile')).toBeInTheDocument();
  });

  it.each([{ id: 'wrong-profile' }, { organization_id: 'org-2' }])('keeps the editor open when the save response has wrong identity %j', async (invalid) => {
    updateProfile.mockResolvedValue({ ...profile(), name: 'Edited profile', ...invalid });
    renderPage(); await editAndSave();
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization|requested profile/i);
    expect(screen.getByDisplayValue('Edited profile')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Profile details' })).not.toBeInTheDocument();
  });

  it('locks duplicate saves synchronously and freezes edited fields until completion', async () => {
    const save = deferred<ReturnType<typeof profile>>(); updateProfile.mockReturnValue(save.promise);
    renderPage();
    fireEvent.change(await screen.findByDisplayValue('First profile'), { target: { value: 'Edited profile' } });
    const button = screen.getByTestId('edit.trustProfile.save');
    act(() => { fireEvent.click(button); fireEvent.click(button); });
    expect(updateProfile).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('edit.trustProfile.name')).toBeDisabled();
    expect(screen.getByTestId('edit.trustProfile.description')).toBeDisabled();
    await act(async () => { save.resolve({ ...profile(), name: 'Edited profile' }); });
    expect(await screen.findByRole('heading', { name: 'Profile details' })).toBeInTheDocument();
  });

  it('preserves current errors, enables retry and sends only a deliberately cleared description', async () => {
    updateProfile.mockRejectedValueOnce(new Error('Current save failed'));
    const { user } = renderPage();
    fireEvent.change(await screen.findByTestId('edit.trustProfile.description'), { target: { value: '' } });
    await user.click(screen.getByTestId('edit.trustProfile.save'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Current save failed');
    expect(updateProfile).toHaveBeenLastCalledWith('profile-1', { description: '' });
    await user.click(screen.getByTestId('edit.trustProfile.save'));
    expect(await screen.findByRole('heading', { name: 'Profile details' })).toBeInTheDocument();
  });

  it('renders suspended status without presenting it as active', async () => {
    getProfile.mockResolvedValue({ ...profile(), status: 'suspended' });
    renderPage();
    await screen.findByDisplayValue('First profile');
    expect(screen.getByText('Suspended')).toBeInTheDocument();
    expect(screen.queryByText('Active')).not.toBeInTheDocument();
  });

  it('keeps an absent lifecycle status unknown', async () => {
    getProfile.mockResolvedValue({ ...profile(), status: undefined });
    renderPage();
    await screen.findByDisplayValue('First profile');
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.queryByText('Active')).not.toBeInTheDocument();
  });

  it.each(['en', 'de', 'es', 'fr', 'ja', 'nl'])('provides editor scope errors and native status labels in %s without fallback', async (locale) => {
    const messages = JSON.parse(readFileSync(resolve('public', 'locales', locale, 'console.json'), 'utf8'));
    const translations = createInstance();
    await translations.init({ lng: locale, fallbackLng: false, resources: { [locale]: { console: messages } } });
    for (const suffix of ['selectOrganization', 'permissionDenied', 'scopeMismatch', 'invalidResponse', 'suspendedStatus', 'unknownStatus', 'notFound']) {
      const key = `trust.trustProfileEdit.${suffix}`;
      expect(translations.exists(key, { ns: 'console' })).toBe(true);
      expect(translations.t(key, { ns: 'console' })).not.toBe(key);
    }
  });
});
