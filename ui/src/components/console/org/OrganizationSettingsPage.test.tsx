import { act, fireEvent } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';
import OrganizationSettingsPage from './OrganizationSettingsPage';
import i18n from '@test/i18nTestSetup';

const { load, save, useConsole, can } = vi.hoisted(() => ({
  load: vi.fn(), save: vi.fn(), useConsole: vi.fn(), can: vi.fn(),
}));
vi.mock('../../../application/orgSettings', () => ({ loadOrgSettings: load, saveOrgSettings: save }));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({ organizationId: 'auth-org', organizationName: 'Old auth organization' }) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({ can }) }));
vi.mock('./OrgDefaultsSection', () => ({ default: () => <section>Defaults section</section> }));
vi.mock('../../common', () => ({
  ResourcePage: ({ children, actions }: { children: React.ReactNode; actions: React.ReactNode }) => <main>{actions}{children}</main>,
}));

const profile = {
  name: 'Selected', displayName: 'Selected Organization', description: 'Current details',
  website: 'https://selected.example', contactEmail: 'admin@selected.example', contactPhone: '',
  visibility: 'PRIVATE', joinMechanism: 'invite', requiresApproval: true,
};
const loaded = (org = profile) => ({ org, error: null });
const selectOrganization = (id: string | null) => useConsole.mockReturnValue({
  activeOrgId: id, memberships: [{ id: 'selected-org', display_name: 'Selected membership' }, { id: 'second-org', display_name: 'Second membership' }],
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

beforeEach(() => {
  vi.clearAllMocks();
  selectOrganization('selected-org');
  can.mockReturnValue(true);
  load.mockResolvedValue(loaded());
  save.mockResolvedValue(loaded());
});

afterEach(async () => { await i18n.changeLanguage('en'); });

describe('OrganizationSettingsPage', () => {
  it('uses the active organization for its header, loading, and saved edits', async () => {
    const { user } = renderWithRouter(<OrganizationSettingsPage />);
    const name = await screen.findByRole('textbox', { name: 'Organization Name' });
    expect(load).toHaveBeenCalledWith({ organizationId: 'selected-org' });
    expect(screen.getByText('Organization ID: selected-org')).toBeInTheDocument();
    expect(screen.queryByText(/auth-org|Old auth organization/)).not.toBeInTheDocument();
    expect(name).toHaveValue('Selected');
    expect(name).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Edit' }));
    const displayName = screen.getByRole('textbox', { name: 'Display Name' });
    await user.clear(displayName);
    await user.type(displayName, 'Updated name');
    save.mockResolvedValue(loaded({ ...profile, displayName: 'Updated name' }));
    await user.click(screen.getByRole('button', { name: 'Save Changes' }));
    await screen.findByText('Organization settings saved successfully.');
    expect(save).toHaveBeenCalledWith({ organizationId: 'selected-org', org: { ...profile, displayName: 'Updated name' }, originalOrg: profile });
    expect(displayName).toHaveValue('Updated name');
    expect(displayName).toBeDisabled();
    expect(can).toHaveBeenCalledWith('organization', 'edit');
  });

  it('shows a retry state with no editable blank form after loading fails', async () => {
    load.mockResolvedValueOnce({ org: null, error: 'Route not found' });
    const { user } = renderWithRouter(<OrganizationSettingsPage />);
    await screen.findByText(/Failed to load organization details: Route not found/);
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save Changes' })).not.toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    await screen.findByRole('textbox', { name: 'Organization Name' });
    expect(screen.queryByText(/Route not found/)).not.toBeInTheDocument();
  });

  it('discards a late response from the previously selected organization', async () => {
    const first = deferred<ReturnType<typeof loaded>>();
    load.mockReturnValueOnce(first.promise).mockResolvedValueOnce(loaded({ ...profile, name: 'Second', displayName: 'Second Organization' }));
    const { rerender } = renderWithRouter(<OrganizationSettingsPage />);
    selectOrganization('second-org');
    rerender(<OrganizationSettingsPage />);
    expect(await screen.findByRole('textbox', { name: 'Organization Name' })).toHaveValue('Second');
    await act(async () => { first.resolve(loaded()); });
    expect(screen.getByRole('textbox', { name: 'Organization Name' })).toHaveValue('Second');
    expect(screen.getByText('Organization ID: second-org')).toBeInTheDocument();
  });

  it('does not expose an old draft when the next organization fails to load', async () => {
    const { rerender, user } = renderWithRouter(<OrganizationSettingsPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Display Name' }), { target: { value: 'Unsaved first org' } });
    load.mockResolvedValueOnce({ org: null, error: 'Access denied' });
    selectOrganization('second-org');
    rerender(<OrganizationSettingsPage />);
    await screen.findByText(/Failed to load organization details: Access denied/);
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save Changes' })).not.toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
  });

  it('ignores an old save completion while the new organization is being edited', async () => {
    const pendingSave = deferred<ReturnType<typeof loaded>>();
    save.mockReturnValueOnce(pendingSave.promise);
    const { user, rerender } = renderWithRouter(<OrganizationSettingsPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    await user.click(screen.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    selectOrganization('second-org');
    load.mockResolvedValueOnce(loaded({ ...profile, displayName: 'Second Organization' }));
    rerender(<OrganizationSettingsPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    await act(async () => { pendingSave.resolve(loaded()); });
    expect(screen.getByRole('textbox', { name: 'Display Name' })).toHaveValue('Second Organization');
    expect(screen.getByRole('textbox', { name: 'Display Name' })).toBeEnabled();
    expect(screen.queryByText('Organization settings saved successfully.')).not.toBeInTheDocument();
  });

  it('restores the saved profile when an edit is cancelled', async () => {
    const { user } = renderWithRouter(<OrganizationSettingsPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Display Name' }), { target: { value: 'Discard this draft' } });
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByRole('textbox', { name: 'Display Name' })).toHaveValue('Selected Organization');
    expect(save).not.toHaveBeenCalled();
  });

  it('allows members without edit permission to read without submitting changes', async () => {
    can.mockReturnValue(false);
    renderWithRouter(<OrganizationSettingsPage />);
    expect(await screen.findByRole('textbox', { name: 'Organization Name' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    fireEvent.submit(document.getElementById('organization-settings-profile')!);
    expect(save).not.toHaveBeenCalled();
  });

  it('does not load or save when no organization is selected', async () => {
    selectOrganization(null);
    renderWithRouter(<OrganizationSettingsPage />);
    await screen.findByText('Select an organization to view its settings.');
    expect(load).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  });

  it('preserves unsaved edits and pending saves when the language changes', async () => {
    const pendingSave = deferred<ReturnType<typeof loaded>>();
    save.mockReturnValueOnce(pendingSave.promise);
    const { user } = renderWithRouter(<OrganizationSettingsPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Display Name' }), { target: { value: 'Keep my draft' } });
    await act(async () => { await i18n.changeLanguage('es'); });
    expect(load).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('textbox', { name: 'Display Name' })).toHaveValue('Keep my draft');
    await user.click(screen.getByRole('button', { name: 'Save Changes' }));
    await act(async () => { await i18n.changeLanguage('fr'); });
    await act(async () => { pendingSave.resolve(loaded({ ...profile, displayName: 'Keep my draft' })); });
    expect(await screen.findByText('Organization settings saved successfully.')).toBeInTheDocument();
    expect(load).toHaveBeenCalledTimes(1);
  });

  it('blocks newly invalid names while preserving a loaded legacy name', async () => {
    load.mockResolvedValueOnce(loaded({ ...profile, name: 'Marty' }));
    const { user } = renderWithRouter(<OrganizationSettingsPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeEnabled();
    fireEvent.change(screen.getByRole('textbox', { name: 'Organization Name' }), { target: { value: 'New Invalid Name' } });
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeDisabled();
    fireEvent.submit(document.getElementById('organization-settings-profile')!);
    expect(save).not.toHaveBeenCalled();
  });

  it('keeps a failed save editable and prevents duplicate requests while saving', async () => {
    const pendingSave = deferred<{ org: null; error: string }>();
    save.mockReturnValueOnce(pendingSave.promise);
    const { user } = renderWithRouter(<OrganizationSettingsPage />);
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.submit(document.getElementById('organization-settings-profile')!);
    fireEvent.submit(document.getElementById('organization-settings-profile')!);
    expect(save).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('textbox', { name: 'Display Name' })).toBeDisabled();
    await act(async () => { pendingSave.resolve({ org: null, error: 'Permission denied' }); });
    expect(await screen.findByText('Permission denied')).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Display Name' })).toBeEnabled();
    expect(screen.queryByText('Organization settings saved successfully.')).not.toBeInTheDocument();
  });
});
