import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@test/utils';

import OrgDefaultsSection from './OrgDefaultsSection';

const {
  scope,
  permissionState,
  mockCan,
  mockGetDefaults,
  mockUpdateDefaults,
  mockListTrustProfiles,
  mockListPolicies,
  mockListTemplates,
} = vi.hoisted(() => ({
  scope: { activeOrgId: 'org-a' as string | null },
  permissionState: { isLoading: false },
  mockCan: vi.fn(),
  mockGetDefaults: vi.fn(),
  mockUpdateDefaults: vi.fn(),
  mockListTrustProfiles: vi.fn(),
  mockListPolicies: vi.fn(),
  mockListTemplates: vi.fn(),
}));

vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => scope }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({ can: mockCan, ...permissionState }) }));
vi.mock('../../../services/organizationsApi', () => ({
  getOrganizationDefaults: mockGetDefaults,
  updateOrganizationDefaults: mockUpdateDefaults,
}));
vi.mock('../../../services/presentationPolicyApi', () => ({
  listTrustProfiles: mockListTrustProfiles,
  listPresentationPolicies: mockListPolicies,
  listCredentialTemplates: mockListTemplates,
}));

type Defaults = {
  default_trust_profile_id: string | null;
  default_policy_id: string | null;
  default_template_id: string | null;
};

function defaultsFor(organizationId: string): Defaults {
  return {
    default_trust_profile_id: `${organizationId}-trust`,
    default_policy_id: `${organizationId}-policy`,
    default_template_id: `${organizationId}-template`,
  };
}

function catalogFor(organizationId: string, resource: string, status = 'active') {
  return [
    { id: `${organizationId}-${resource}`, name: `${organizationId} ${resource}`, status },
    { id: `${organizationId}-${resource}-other`, name: `${organizationId} other ${resource}`, status },
    { id: `${organizationId}-${resource}-draft`, name: `${organizationId} draft ${resource}`, status: 'draft' },
  ];
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

const trustLabel = /^Default Trust Profile/;
const policyLabel = /^Default Presentation Policy/;
const templateLabel = /^Default Credential Template/;
const loadError = 'Failed to load organization defaults';
const saveError = 'Failed to save organization defaults';
const saveSuccess = 'Organization defaults saved successfully';
const noneLabel = 'None (manual selection required)';

describe('OrgDefaultsSection', () => {
  beforeEach(() => {
    [mockCan, mockGetDefaults, mockUpdateDefaults, mockListTrustProfiles, mockListPolicies, mockListTemplates]
      .forEach(mock => mock.mockReset());
    scope.activeOrgId = 'org-a';
    permissionState.isLoading = false;
    mockCan.mockReturnValue(true);
    mockGetDefaults.mockImplementation(async organizationId => defaultsFor(organizationId));
    mockUpdateDefaults.mockImplementation(async (organizationId, patch) => ({ ...defaultsFor(organizationId), ...patch }));
    mockListTrustProfiles.mockImplementation(async ({ organization_id }) => catalogFor(organization_id, 'trust'));
    mockListPolicies.mockImplementation(async ({ organization_id }) => catalogFor(organization_id, 'policy'));
    // The native credential-template API uses uppercase lifecycle status.
    mockListTemplates.mockImplementation(async ({ organization_id }) => catalogFor(organization_id, 'template', 'ACTIVE'));
  });

  it('loads labeled controls for the active organization and saves IDs or explicit nulls', async () => {
    const { user } = render(<OrgDefaultsSection />);

    const trustSelect = await screen.findByRole('combobox', { name: trustLabel });
    expect(trustSelect).toHaveTextContent('org-a trust');
    expect(screen.getByRole('combobox', { name: policyLabel })).toHaveTextContent('org-a policy');
    expect(screen.getByRole('combobox', { name: templateLabel })).toHaveTextContent('org-a template');
    expect(mockGetDefaults).toHaveBeenCalledWith('org-a');
    for (const listResources of [mockListTrustProfiles, mockListPolicies, mockListTemplates]) {
      expect(listResources).toHaveBeenCalledWith({ organization_id: 'org-a', limit: 100, offset: 0 });
    }

    for (const label of [trustLabel, policyLabel]) {
      await user.click(screen.getByRole('combobox', { name: label }));
      await user.click(screen.getByRole('option', { name: noneLabel }));
    }
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));

    expect(mockUpdateDefaults).toHaveBeenCalledWith('org-a', {
      default_trust_profile_id: null,
      default_policy_id: null,
    });
    expect(await screen.findByText(saveSuccess)).toBeInTheDocument();
  });

  it('does not load or offer editing without an active organization', () => {
    scope.activeOrgId = null;
    render(<OrgDefaultsSection />);

    expect(screen.getByRole('alert')).toHaveTextContent('Select an organization before configuring defaults.');
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    for (const request of [mockGetDefaults, mockUpdateDefaults, mockListTrustProfiles, mockListPolicies, mockListTemplates]) {
      expect(request).not.toHaveBeenCalled();
    }
  });

  it('preserves concurrent changes to untouched defaults and reconciles the saved response', async () => {
    const empty = { default_trust_profile_id: null, default_policy_id: null, default_template_id: null };
    mockGetDefaults.mockResolvedValueOnce(empty);
    let stored = { ...empty, default_trust_profile_id: 'org-a-trust-other' };
    mockUpdateDefaults.mockImplementation(async (_organizationId, patch) => {
      stored = { ...stored, ...patch };
      return stored;
    });
    const { user } = render(<OrgDefaultsSection />);
    await screen.findByRole('combobox', { name: policyLabel });
    expect(screen.getByRole('button', { name: 'Save Defaults' })).toBeDisabled();
    await user.click(screen.getByRole('combobox', { name: policyLabel }));
    await user.click(screen.getByRole('option', { name: 'org-a other policy' }));
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));
    expect(await screen.findByText(saveSuccess)).toBeInTheDocument();
    expect(mockUpdateDefaults).toHaveBeenCalledWith('org-a', { default_policy_id: 'org-a-policy-other' });
    expect(screen.getByRole('combobox', { name: trustLabel })).toHaveTextContent('org-a other trust');
    expect(screen.getByRole('button', { name: 'Save Defaults' })).toBeDisabled();
    await user.click(screen.getByRole('combobox', { name: templateLabel }));
    await user.click(screen.getByRole('option', { name: 'org-a other template' }));
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));
    await screen.findByText(saveSuccess);
    expect(mockUpdateDefaults).toHaveBeenLastCalledWith('org-a', { default_template_id: 'org-a-template-other' });
    expect(stored).toEqual({ default_trust_profile_id: 'org-a-trust-other', default_policy_id: 'org-a-policy-other', default_template_id: 'org-a-template-other' });
  });

  it('does not report success for an incomplete saved response', async () => {
    mockUpdateDefaults.mockResolvedValueOnce({ default_trust_profile_id: null });
    const { user } = render(<OrgDefaultsSection />);
    await user.click(await screen.findByRole('combobox', { name: trustLabel }));
    await user.click(screen.getByRole('option', { name: noneLabel }));
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));
    expect(await screen.findByText(saveError)).toBeInTheDocument();
    expect(screen.queryByText(saveSuccess)).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: trustLabel })).toHaveTextContent(noneLabel);
  });

  it.each(['defaults', 'catalog'])('requires a successful %s load before editing and supports retry', async failedRequest => {
    const request = failedRequest === 'defaults' ? mockGetDefaults : mockListPolicies;
    request.mockRejectedValueOnce(new Error('Service unavailable'));
    const { user } = render(<OrgDefaultsSection />);

    expect(await screen.findByText(loadError)).toBeInTheDocument();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save Defaults' })).not.toBeInTheDocument();
    expect(mockUpdateDefaults).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('combobox', { name: trustLabel })).toHaveTextContent('org-a trust');
    expect(screen.queryByText(loadError)).not.toBeInTheDocument();
    await user.click(screen.getByRole('combobox', { name: policyLabel }));
    await user.click(screen.getByRole('option', { name: 'org-a other policy' }));
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));
    expect(mockUpdateDefaults).toHaveBeenCalledWith('org-a', { default_policy_id: 'org-a-policy-other' });
  });

  it('rejects incomplete defaults instead of treating missing fields as empty selections', async () => {
    mockGetDefaults.mockResolvedValueOnce({ default_trust_profile_id: null });
    render(<OrgDefaultsSection />);

    expect(await screen.findByText(loadError)).toBeInTheDocument();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save Defaults' })).not.toBeInTheDocument();
    expect(mockUpdateDefaults).not.toHaveBeenCalled();
  });

  it('shows loaded defaults read-only when the member cannot edit organizations', async () => {
    mockCan.mockImplementation((_resource, action) => action === 'view');
    render(<OrgDefaultsSection />);

    expect(await screen.findByRole('combobox', { name: trustLabel })).toHaveTextContent('org-a trust');
    for (const select of screen.getAllByRole('combobox')) {
      expect(select).toHaveAttribute('aria-disabled', 'true');
    }
    expect(mockCan).toHaveBeenCalledWith('organization', 'edit');
    expect(screen.queryByRole('button', { name: 'Save Defaults' })).not.toBeInTheDocument();
    expect(mockUpdateDefaults).not.toHaveBeenCalled();
  });

  it('waits for current permissions and does not request defaults without organization view', async () => {
    permissionState.isLoading = true;
    mockCan.mockReturnValue(false);
    const view = render(<OrgDefaultsSection />);

    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    for (const request of [mockGetDefaults, mockListTrustProfiles, mockListPolicies, mockListTemplates]) {
      expect(request).not.toHaveBeenCalled();
    }

    permissionState.isLoading = false;
    view.rerender(<OrgDefaultsSection />);
    expect(screen.getByRole('alert')).toHaveTextContent('You do not have permission to view organization defaults.');
    expect(mockGetDefaults).not.toHaveBeenCalled();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
  });

  it('lets an access administrator read defaults and clear one without catalog view grants', async () => {
    mockCan.mockImplementation((resource) => resource === 'organization');
    for (const catalog of [mockListTrustProfiles, mockListPolicies, mockListTemplates]) {
      catalog.mockRejectedValue(new Error('Forbidden'));
    }
    const { user } = render(<OrgDefaultsSection />);

    await user.click(await screen.findByRole('combobox', { name: trustLabel }));
    await user.click(screen.getByRole('option', { name: noneLabel }));
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));

    expect(await screen.findByText(saveSuccess)).toBeInTheDocument();
    expect(mockUpdateDefaults).toHaveBeenCalledWith('org-a', { default_trust_profile_id: null });
    expect(screen.queryByText(loadError)).not.toBeInTheDocument();
    for (const catalog of [mockListTrustProfiles, mockListPolicies, mockListTemplates]) {
      expect(catalog).not.toHaveBeenCalled();
    }
  });

  it('saves an allowed resource without replacing inaccessible or inactive untouched defaults', async () => {
    mockCan.mockImplementation((resource) => resource !== 'credential-template');
    mockGetDefaults.mockResolvedValue({ ...defaultsFor('org-a'), default_trust_profile_id: 'retired-trust' });
    mockListTemplates.mockRejectedValue(new Error('Forbidden'));
    mockUpdateDefaults.mockImplementation(async (_organizationId, patch) => ({
      ...defaultsFor('org-a'), default_trust_profile_id: 'retired-trust', ...patch,
    }));
    const { user } = render(<OrgDefaultsSection />);

    await user.click(await screen.findByRole('combobox', { name: policyLabel }));
    await user.click(screen.getByRole('option', { name: 'org-a other policy' }));
    expect(screen.getByRole('button', { name: 'Save Defaults' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));

    expect(await screen.findByText(saveSuccess)).toBeInTheDocument();
    expect(mockUpdateDefaults).toHaveBeenCalledWith('org-a', { default_policy_id: 'org-a-policy-other' });
    expect(mockListTemplates).not.toHaveBeenCalled();
  });

  it('discards a pending save and draft when organization edit permission is withdrawn', async () => {
    const pendingSave = deferred<Defaults>();
    mockUpdateDefaults.mockReturnValue(pendingSave.promise);
    const view = render(<OrgDefaultsSection />);
    await view.user.click(await screen.findByRole('combobox', { name: trustLabel }));
    await view.user.click(screen.getByRole('option', { name: 'org-a other trust' }));
    await view.user.click(screen.getByRole('button', { name: 'Save Defaults' }));

    mockCan.mockImplementation((_resource, action) => action === 'view');
    view.rerender(<OrgDefaultsSection />);
    expect(await screen.findByRole('combobox', { name: trustLabel })).toHaveTextContent('org-a trust');
    await act(async () => pendingSave.resolve({ ...defaultsFor('org-a'), default_trust_profile_id: 'org-a-trust-other' }));

    expect(screen.getByRole('combobox', { name: trustLabel })).toHaveTextContent('org-a trust');
    expect(screen.getByRole('combobox', { name: trustLabel })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.queryByText(saveSuccess)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save Defaults' })).not.toBeInTheDocument();
  });

  it.each(['before', 'after'])('discards the previous organization load when it completes %s the current load', async order => {
    const previousLoad = deferred<Defaults>();
    const currentLoad = deferred<Defaults>();
    mockGetDefaults.mockImplementation(organizationId => (
      organizationId === 'org-a' ? previousLoad.promise : currentLoad.promise
    ));
    const view = render(<OrgDefaultsSection />);
    scope.activeOrgId = 'org-b';
    view.rerender(<OrgDefaultsSection />);

    if (order === 'before') {
      await act(async () => previousLoad.resolve(defaultsFor('org-a')));
      expect(screen.getByRole('progressbar', { name: 'Loading...' })).toBeInTheDocument();
      expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    }

    await act(async () => currentLoad.resolve(defaultsFor('org-b')));
    expect(await screen.findByRole('combobox', { name: trustLabel })).toHaveTextContent('org-b trust');

    if (order === 'after') {
      await act(async () => previousLoad.resolve(defaultsFor('org-a')));
    }

    expect(screen.getByRole('combobox', { name: trustLabel })).toHaveTextContent('org-b trust');
    await view.user.click(screen.getByRole('combobox', { name: trustLabel }));
    await view.user.click(screen.getByRole('option', { name: 'org-b other trust' }));
    await view.user.click(screen.getByRole('button', { name: 'Save Defaults' }));
    expect(mockUpdateDefaults).toHaveBeenCalledWith('org-b', { default_trust_profile_id: 'org-b-trust-other' });
  });

  it('discards unsaved defaults when switching to an organization whose load fails', async () => {
    const view = render(<OrgDefaultsSection />);
    await view.user.click(await screen.findByRole('combobox', { name: trustLabel }));
    await view.user.click(screen.getByRole('option', { name: 'org-a other trust' }));

    mockGetDefaults.mockRejectedValueOnce(new Error('Organization unavailable'));
    scope.activeOrgId = 'org-b';
    view.rerender(<OrgDefaultsSection />);
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(await screen.findByText(loadError)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save Defaults' })).not.toBeInTheDocument();
    expect(screen.queryByText('org-a other trust')).not.toBeInTheDocument();
    expect(mockUpdateDefaults).not.toHaveBeenCalled();
  });

  it.each(['success', 'failure'])('ignores an obsolete save %s without disturbing the current save', async outcome => {
    const previousSave = deferred<Defaults>();
    const currentSave = deferred<Defaults>();
    mockUpdateDefaults.mockImplementation(organizationId => (
      organizationId === 'org-a' ? previousSave.promise : currentSave.promise
    ));
    const view = render(<OrgDefaultsSection />);
    await view.user.click(await screen.findByRole('combobox', { name: trustLabel }));
    await view.user.click(screen.getByRole('option', { name: 'org-a other trust' }));
    await view.user.click(screen.getByRole('button', { name: 'Save Defaults' }));
    expect(mockUpdateDefaults).toHaveBeenCalledWith('org-a', { default_trust_profile_id: 'org-a-trust-other' });

    scope.activeOrgId = 'org-b';
    view.rerender(<OrgDefaultsSection />);
    await view.user.click(await screen.findByRole('combobox', { name: trustLabel }));
    await view.user.click(screen.getByRole('option', { name: 'org-b other trust' }));
    await view.user.click(screen.getByRole('button', { name: 'Save Defaults' }));
    expect(mockUpdateDefaults).toHaveBeenLastCalledWith('org-b', { default_trust_profile_id: 'org-b-trust-other' });

    await act(async () => {
      if (outcome === 'success') previousSave.resolve(defaultsFor('org-a'));
      else previousSave.reject(new Error('Previous save failed'));
    });
    expect(screen.getByRole('button', { name: 'Saving...' })).toBeDisabled();
    expect(screen.queryByText(saveSuccess)).not.toBeInTheDocument();
    expect(screen.queryByText(saveError)).not.toBeInTheDocument();

    await act(async () => currentSave.resolve(defaultsFor('org-b')));
    expect(await screen.findByText(saveSuccess)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save Defaults' })).toBeDisabled();
  });

  it('retains selected values when a save fails and retries the same scoped data', async () => {
    mockUpdateDefaults.mockRejectedValueOnce(new Error('Save unavailable'));
    const { user } = render(<OrgDefaultsSection />);
    await user.click(await screen.findByRole('combobox', { name: trustLabel }));
    await user.click(screen.getByRole('option', { name: 'org-a other trust' }));
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));

    expect(await screen.findByText(saveError)).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: trustLabel })).toHaveTextContent('org-a other trust');
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));

    expect(await screen.findByText(saveSuccess)).toBeInTheDocument();
    expect(screen.queryByText(saveError)).not.toBeInTheDocument();
    expect(mockUpdateDefaults).toHaveBeenCalledTimes(2);
    expect(mockUpdateDefaults).toHaveBeenLastCalledWith('org-a', {
      default_trust_profile_id: 'org-a-trust-other',
    });
    expect(mockGetDefaults).toHaveBeenCalledTimes(1);
  });

  it('offers only active resources and preserves an unavailable saved default until explicitly cleared', async () => {
    mockGetDefaults.mockResolvedValueOnce({ ...defaultsFor('org-a'), default_trust_profile_id: 'retired-trust' });
    mockListTrustProfiles.mockResolvedValueOnce([
      ...catalogFor('org-a', 'trust'),
      { id: 'retired-trust', name: 'Retired trust', status: 'inactive' },
    ]);
    const { user } = render(<OrgDefaultsSection />);

    expect(await screen.findByRole('combobox', { name: trustLabel })).toHaveTextContent('Unavailable resource');
    expect(screen.getByRole('button', { name: 'Save Defaults' })).toBeDisabled();
    expect(mockUpdateDefaults).not.toHaveBeenCalled();

    for (const [label, resource] of [[policyLabel, 'policy'], [templateLabel, 'template']] as const) {
      await user.click(screen.getByRole('combobox', { name: label }));
      expect(screen.queryByRole('option', { name: `org-a draft ${resource}` })).not.toBeInTheDocument();
      await user.click(screen.getByRole('option', { name: `org-a ${resource}` }));
    }

    await user.click(screen.getByRole('combobox', { name: trustLabel }));
    expect(screen.getByRole('option', { name: 'Unavailable resource' })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.queryByRole('option', { name: 'Retired trust' })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'org-a draft trust' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('option', { name: noneLabel }));

    expect(screen.getByRole('button', { name: 'Save Defaults' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Save Defaults' }));
    await waitFor(() => expect(mockUpdateDefaults).toHaveBeenCalledWith('org-a', {
      default_trust_profile_id: null,
    }));
  });
});
