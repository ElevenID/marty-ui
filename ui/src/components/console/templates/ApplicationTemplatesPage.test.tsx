import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, within } from '@testing-library/react';
import { renderWithRouter, screen, waitFor } from '@test/utils';
import ApplicationTemplatesPage from './ApplicationTemplatesPage';

const { mockListApplicationTemplates, mockListCredentialTemplates, consoleState, authState } = vi.hoisted(() => ({
  mockListApplicationTemplates: vi.fn(),
  mockListCredentialTemplates: vi.fn(),
  consoleState: { activeOrgId: 'org-1' as string | null },
  authState: { isAuthenticated: true, user: { user_id: 'user-1' } },
}));

vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => consoleState }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => authState }));
vi.mock('../../../services/applicationTemplatesApi', () => ({
  listApplicationTemplates: (...args: unknown[]) => mockListApplicationTemplates(...args),
  updateTemplateRequiredChecks: vi.fn(),
}));
vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: (...args: unknown[]) => mockListCredentialTemplates(...args),
}));

function applicationTemplate(overrides = {}) {
  return {
    id: 'application-template-1',
    organization_id: 'org-1',
    name: 'Membership application',
    credential_template_id: 'credential-template-1',
    status: 'DRAFT',
    form_fields: [],
    required_checks: [],
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const route = { initialEntries: ['/console/org/templates/applications'] };

describe('ApplicationTemplatesPage', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    consoleState.activeOrgId = 'org-1';
    authState.isAuthenticated = true;
    authState.user = { user_id: 'user-1' };
    mockListApplicationTemplates.mockResolvedValue([]);
    mockListCredentialTemplates.mockResolvedValue([]);
  });

  it('keeps a failed first load out of the table and retries in place', async () => {
    const initialLoad = deferred<unknown>();
    mockListApplicationTemplates
      .mockReturnValueOnce(initialLoad.promise)
      .mockResolvedValueOnce([applicationTemplate()]);
    const { user } = renderWithRouter(<ApplicationTemplatesPage />, route);

    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    expect(screen.queryByText('No application templates yet')).not.toBeInTheDocument();
    await act(async () => { initialLoad.reject(new Error('Templates are temporarily unavailable')); });

    expect(await screen.findByRole('alert')).toHaveTextContent('Templates are temporarily unavailable');
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.queryByText('No application templates yet')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry', exact: true }));

    expect(await screen.findByText('Membership application')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(mockListApplicationTemplates).toHaveBeenCalledTimes(2);
    expect(mockListApplicationTemplates).toHaveBeenLastCalledWith('org-1');
  });

  it('provides a readable fallback for an error without a message', async () => {
    mockListApplicationTemplates.mockRejectedValue(new Error('   '));
    renderWithRouter(<ApplicationTemplatesPage />, route);

    expect(await screen.findByRole('alert')).toHaveTextContent('Application templates could not be loaded.');
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it.each([
    ['null', null],
    ['an unexpected envelope', { templates: [] }],
    ['a null row', [null]],
    ['another organization', [applicationTemplate({ organization_id: 'org-2' })]],
  ])('treats %s as an inventory failure instead of an empty success', async (_description, response) => {
    mockListApplicationTemplates.mockResolvedValue(response);
    renderWithRouter(<ApplicationTemplatesPage />, route);

    expect(await screen.findByRole('alert')).toHaveTextContent('Application templates could not be loaded for the selected organization.');
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.queryByText('No application templates yet')).not.toBeInTheDocument();
  });

  it('shows the empty state only after a successful empty inventory', async () => {
    renderWithRouter(<ApplicationTemplatesPage />, route);
    expect(await screen.findByText('No application templates yet')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('keeps explicit fields visible while failed credential details can be retried separately', async () => {
    mockListApplicationTemplates.mockResolvedValue([
      applicationTemplate(),
      applicationTemplate({ id: 'application-template-2', name: 'Custom application', form_fields: [{ name: 'full_name' }] }),
    ]);
    mockListCredentialTemplates
      .mockRejectedValueOnce(new Error('Credential catalog unavailable'))
      .mockResolvedValueOnce([{
        id: 'credential-template-1', organization_id: 'org-1', name: 'Member Badge', claims: [{ name: 'name' }, { name: 'member_id' }],
      }]);
    const { user } = renderWithRouter(<ApplicationTemplatesPage />, route);

    expect(await screen.findByRole('alert')).toHaveTextContent('Credential template details could not be loaded.');
    const derivedRow = await screen.findByRole('row', { name: /Membership application/ });
    const explicitRow = screen.getByRole('row', { name: /Custom application/ });
    expect(within(derivedRow).getAllByRole('cell')[2]).toHaveTextContent('—');
    expect(within(explicitRow).getAllByRole('cell')[2]).toHaveTextContent('1');

    await user.click(screen.getByRole('button', { name: 'Retry credential details' }));
    await waitFor(() => expect(within(screen.getByRole('row', { name: /Membership application/ })).getAllByRole('cell')[2]).toHaveTextContent('2'));
    expect(screen.getAllByText('Member Badge')).toHaveLength(2);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(mockListApplicationTemplates).toHaveBeenCalledTimes(1);
  });

  it('closes an old check dialog and discards delayed credential details when changing organization', async () => {
    const oldDetails = deferred<unknown[]>();
    mockListApplicationTemplates
      .mockResolvedValueOnce([applicationTemplate()])
      .mockResolvedValueOnce([applicationTemplate({ id: 'application-template-2', organization_id: 'org-2', name: 'Second organization application' })]);
    mockListCredentialTemplates
      .mockReturnValueOnce(oldDetails.promise)
      .mockResolvedValueOnce([{ id: 'credential-template-1', organization_id: 'org-2', name: 'Second organization badge', claims: [] }]);
    const { user, rerender } = renderWithRouter(<ApplicationTemplatesPage />, route);
    await screen.findByText('Membership application');
    await user.click(screen.getByRole('button', { name: 'Configure required checks' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('Membership application');

    consoleState.activeOrgId = 'org-2';
    rerender(<ApplicationTemplatesPage />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByText('Membership application')).not.toBeInTheDocument();
    expect(await screen.findByText('Second organization application')).toBeInTheDocument();
    expect(await screen.findByText('Second organization badge')).toBeInTheDocument();
    await act(async () => { oldDetails.resolve([{ id: 'credential-template-1', organization_id: 'org-1', name: 'Old organization badge', claims: [{ name: 'old_claim' }] }]); });

    expect(screen.queryByText('Old organization badge')).not.toBeInTheDocument();
    expect(screen.getByText('Second organization badge')).toBeInTheDocument();
    expect(mockListApplicationTemplates).toHaveBeenLastCalledWith('org-2');
  });

  it('does not let an earlier account result replace the current account loading state', async () => {
    const oldInventory = deferred<unknown[]>();
    const newInventory = deferred<unknown[]>();
    mockListApplicationTemplates.mockReturnValueOnce(oldInventory.promise).mockReturnValueOnce(newInventory.promise);
    const { rerender } = renderWithRouter(<ApplicationTemplatesPage />, route);
    authState.user = { user_id: 'user-2' };
    rerender(<ApplicationTemplatesPage />);
    expect(mockListApplicationTemplates).toHaveBeenCalledTimes(2);

    await act(async () => { oldInventory.resolve([applicationTemplate()]); });
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    expect(screen.queryByText('Membership application')).not.toBeInTheDocument();
    await act(async () => { newInventory.resolve([applicationTemplate({ name: 'Current account application' })]); });
    expect(await screen.findByText('Current account application')).toBeInTheDocument();
  });

  it('does not fetch inventories without a selected organization', () => {
    consoleState.activeOrgId = null;
    renderWithRouter(<ApplicationTemplatesPage />, route);
    expect(screen.getByRole('alert')).toHaveTextContent('Select an organization before loading application templates.');
    expect(mockListApplicationTemplates).not.toHaveBeenCalled();
    expect(mockListCredentialTemplates).not.toHaveBeenCalled();
  });
});
