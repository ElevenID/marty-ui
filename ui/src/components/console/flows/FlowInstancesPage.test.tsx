import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import userEvent from '@testing-library/user-event'
import FlowInstancesPage from './FlowInstancesPage'

const { mockGetFlowInstance, mockListFlows, mockListFlowInstances, mockAdvance, mockCancel, scope } = vi.hoisted(() => ({
  mockGetFlowInstance: vi.fn(),
  mockListFlows: vi.fn(),
  mockListFlowInstances: vi.fn(),
  mockAdvance: vi.fn(), mockCancel: vi.fn(), scope: { org: 'org-1', advance: true, cancel: true },
}))

vi.mock('react-i18next', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-i18next')>()
  return {
    ...actual,
    useTranslation: () => ({
      t: (key: string) => key,
    }),
  }
})

vi.mock('../../../services/flowsApi', () => ({
  listFlows: (...args: unknown[]) => mockListFlows(...args),
  listFlowInstances: (...args: unknown[]) => mockListFlowInstances(...args),
  getFlowInstance: (...args: unknown[]) => mockGetFlowInstance(...args),
  advanceFlowInstance: (...args: unknown[]) => mockAdvance(...args),
  cancelFlowExecution: (...args: unknown[]) => mockCancel(...args),
}))

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: scope.org }),
}))

vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({
  isLoading: false, can: (_resource: string, action: string) => action === 'advance' ? scope.advance : scope.cancel,
}) }))

describe('FlowInstancesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    scope.org = 'org-1'; scope.advance = true; scope.cancel = true;
    mockListFlows.mockResolvedValue([
      { id: 'flow_1', name: 'Issuance Flow', organization_id: 'org-1' },
    ])
    mockListFlowInstances.mockResolvedValue([
      {
        id: 'exec_1',
        organization_id: 'org-1',
        status: 'pending',
        flow_id: 'flow_1',
        current_step: 'issue_credential',
        current_step_index: 1,
        started_at: '2026-04-14T10:00:00Z',
        completed_at: null,
      },
    ])
  })

  it('renders instances and supports refresh without runtime errors', async () => {
    const user = userEvent.setup()
    renderWithRouter(<FlowInstancesPage />, {
      initialEntries: ['/console/org/operate/flow-instances'],
    })

    await waitFor(() => {
      expect(screen.getByText('Issuance Flow')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Refresh' }))

    await waitFor(() => {
      expect(mockListFlows).toHaveBeenCalledTimes(2)
    })
  })

  it('renders a runtime timeline and related-record links on the detail route', async () => {
    mockGetFlowInstance.mockResolvedValue({
      id: 'exec_1',
      organization_id: 'org-1',
      flow_id: 'flow_1',
      flow_type: 'physical_document_issuance',
      status: 'pending',
      current_step: 'track_production',
      context_data: {
        application_id: 'application-1',
        physical_document_job: { id: 'job-1', status: 'IN_PRODUCTION' },
      },
      state_history: [{ to_status: 'pending', timestamp: '2026-04-14T10:00:00Z' }],
      started_at: '2026-04-14T10:00:00Z',
    })

    renderWithRouter(<FlowInstancesPage />, {
      initialEntries: ['/console/org/operate/flow-instances/exec_1'],
    })

    await waitFor(() => {
      expect(screen.getByText('Runtime timeline')).toBeInTheDocument()
    })
    expect(screen.getByRole('link', { name: 'application-1' })).toHaveAttribute('href', '/console/org/operate/applications/application-1')
    expect(screen.getByText(/job-1/)).toBeInTheDocument()
  })

  it('handles malformed API payloads gracefully', async () => {
    mockListFlows.mockResolvedValue({ items: [] })
    mockListFlowInstances.mockResolvedValue({ items: [] })

    renderWithRouter(<FlowInstancesPage />, {
      initialEntries: ['/console/org/operate/flow-instances'],
    })

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/malformed/)
    })
  })

  it('rejects an existing foreign detail instead of rendering its related application', async () => {
    mockGetFlowInstance.mockResolvedValue({ id: 'foreign', organization_id: 'org-2', flow_id: 'flow_2',
      status: 'IN_PROGRESS', context_data: { application_id: 'private-application' } });
    renderWithRouter(<FlowInstancesPage />, { initialEntries: ['/console/org/operate/flow-instances/foreign'] });
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/);
    expect(screen.queryByRole('link', { name: 'private-application' })).not.toBeInTheDocument();
    expect(mockAdvance).not.toHaveBeenCalled(); expect(mockCancel).not.toHaveBeenCalled();
  });

  it('does not retain or publish former-tenant instance data after an organization switch', async () => {
    let resolveOld!: (value: any) => void;
    mockListFlows.mockImplementation(({ organization_id }: any) => Promise.resolve([{ id: 'flow_1', organization_id, name: 'Flow' }]));
    mockGetFlowInstance.mockImplementation(() => scope.org === 'org-1'
      ? new Promise((resolve) => { resolveOld = resolve; })
      : Promise.resolve({ id: 'exec_1', organization_id: 'org-1', status: 'IN_PROGRESS', context_data: { application_id: 'private-application' } }));
    const { rerender } = renderWithRouter(<FlowInstancesPage />, { initialEntries: ['/console/org/operate/flow-instances/exec_1'] });
    await waitFor(() => expect(mockGetFlowInstance).toHaveBeenCalled());
    scope.org = 'org-2'; rerender(<FlowInstancesPage />);
    resolveOld({ id: 'exec_1', organization_id: 'org-1', status: 'IN_PROGRESS', context_data: { application_id: 'private-application' } });
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/);
    expect(screen.queryByRole('link', { name: 'private-application' })).not.toBeInTheDocument();
  });

  const active = { id: 'exec_1', organization_id: 'org-1', flow_id: 'flow_1', status: 'IN_PROGRESS',
    current_step: 'issue_credential', updated_at: '2026-10-24T15:00:00Z', context_data: {} };

  it.each(['success', 'failure'])('requires confirmation and records a canonical %s step outcome', async (outcome) => {
    mockGetFlowInstance.mockResolvedValueOnce(active).mockResolvedValueOnce(active)
      .mockResolvedValue({ ...active, status: outcome === 'success' ? 'COMPLETED' : 'FAILED' });
    mockAdvance.mockResolvedValue({ ...active, status: outcome === 'success' ? 'COMPLETED' : 'FAILED' });
    const user = userEvent.setup();
    renderWithRouter(<FlowInstancesPage />, { initialEntries: ['/console/org/operate/flow-instances/exec_1'] });
    await user.click(await screen.findByRole('button', { name: outcome === 'success' ? 'Record successful step' : 'Record failed step' }));
    expect(mockAdvance).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toHaveTextContent('issue_credential');
    await user.click(screen.getByRole('button', { name: 'Confirm outcome' }));
    await waitFor(() => expect(mockAdvance).toHaveBeenCalledWith('exec_1', outcome));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Record successful step' })).not.toBeInTheDocument());
    expect(mockGetFlowInstance).toHaveBeenCalledWith('exec_1', { organizationId: 'org-1' });
  });

  it('requires cancellation confirmation and uses the existing native cancellation operation', async () => {
    mockGetFlowInstance.mockResolvedValueOnce(active).mockResolvedValueOnce(active).mockResolvedValue({ ...active, status: 'CANCELLED' });
    mockCancel.mockResolvedValue({ ...active, status: 'CANCELLED' });
    const user = userEvent.setup();
    renderWithRouter(<FlowInstancesPage />, { initialEntries: ['/console/org/operate/flow-instances/exec_1'] });
    await user.click(await screen.findByRole('button', { name: 'Cancel execution' }));
    expect(mockCancel).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Confirm cancellation' }));
    await waitFor(() => expect(mockCancel).toHaveBeenCalledWith('flow_1', 'exec_1'));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Cancel execution' })).not.toBeInTheDocument());
  });

  it('cancels an unchanged graphless execution whose optional current step is absent', async () => {
    const { current_step: _step, ...graphless } = active;
    mockGetFlowInstance.mockResolvedValueOnce(graphless).mockResolvedValueOnce(graphless).mockResolvedValue({ ...graphless, status: 'CANCELLED' });
    mockCancel.mockResolvedValue({ ...graphless, status: 'CANCELLED' });
    const user = userEvent.setup();
    renderWithRouter(<FlowInstancesPage />, { initialEntries: ['/console/org/operate/flow-instances/exec_1'] });
    await user.click(await screen.findByRole('button', { name: 'Cancel execution' }));
    await user.click(screen.getByRole('button', { name: 'Confirm cancellation' }));
    await waitFor(() => expect(mockCancel).toHaveBeenCalledWith('flow_1', 'exec_1'));
    expect(screen.queryByText(/Execution changed/)).not.toBeInTheDocument();
  });

  it('lets a viewer inspect an execution without mutation controls', async () => {
    scope.advance = false; scope.cancel = false; mockGetFlowInstance.mockResolvedValue(active);
    renderWithRouter(<FlowInstancesPage />, { initialEntries: ['/console/org/operate/flow-instances/exec_1'] });
    expect(await screen.findByText('Runtime timeline')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Record successful step' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel execution' })).not.toBeInTheDocument();
    expect(mockAdvance).not.toHaveBeenCalled(); expect(mockCancel).not.toHaveBeenCalled();
  });

  it('checks the independent cancellation grant without offering unauthorized advancement', async () => {
    scope.advance = false; mockGetFlowInstance.mockResolvedValue(active);
    renderWithRouter(<FlowInstancesPage />, { initialEntries: ['/console/org/operate/flow-instances/exec_1'] });
    expect(await screen.findByRole('button', { name: 'Cancel execution' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Record successful step' })).not.toBeInTheDocument();
  });

  it('refuses to mutate when the fresh preflight response belongs to another organization', async () => {
    mockGetFlowInstance.mockResolvedValueOnce(active).mockResolvedValue({ ...active, organization_id: 'org-2' });
    const user = userEvent.setup();
    renderWithRouter(<FlowInstancesPage />, { initialEntries: ['/console/org/operate/flow-instances/exec_1'] });
    await user.click(await screen.findByRole('button', { name: 'Record successful step' }));
    await user.click(screen.getByRole('button', { name: 'Confirm outcome' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/);
    expect(mockAdvance).not.toHaveBeenCalled(); expect(mockCancel).not.toHaveBeenCalled();
  });

  it('rejects a changed execution before writing and requires refresh to review the new step', async () => {
    const changed = { ...active, current_step: 'next_step', updated_at: '2026-10-24T15:01:00Z' };
    mockGetFlowInstance.mockResolvedValueOnce(active).mockResolvedValue(changed);
    const user = userEvent.setup();
    renderWithRouter(<FlowInstancesPage />, { initialEntries: ['/console/org/operate/flow-instances/exec_1'] });
    await user.click(await screen.findByRole('button', { name: 'Record successful step' }));
    await user.click(screen.getByRole('button', { name: 'Confirm outcome' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Execution changed');
    expect(mockAdvance).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Record successful step' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Record successful step' })).toBeEnabled());
    expect(screen.getByRole('heading', { name: 'next step' })).toBeInTheDocument();
  });
})
