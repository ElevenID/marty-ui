import { describe, expect, it, vi } from 'vitest';

import {
  approveFlowManagerExecution,
  batchRevokeFlowManagerCredentials,
  loadFlowManagerCredentials,
  loadFlowManagerExecutions,
  loadFlowManagerFlows,
  loadFlowManagerRevocationBatches,
} from './flowManagerUseCases';

describe('flowManager use cases', () => {
  it('loads flows and surfaces backend failures without sample data fallback', async () => {
    const listFlows = vi.fn().mockResolvedValue([{ id: 'flow-1' }]);

    await expect(loadFlowManagerFlows({ listFlows, organizationId: 'org-1' })).resolves.toEqual({
      flows: [{ id: 'flow-1' }],
      error: null,
      notification: null,
      unsupported: false,
    });
    expect(listFlows).toHaveBeenCalledWith({ organization_id: 'org-1', limit: 100 });

    const failingListFlows = vi.fn().mockRejectedValue(new Error('offline'));
    const failure = await loadFlowManagerFlows({ listFlows: failingListFlows, organizationId: 'org-1' });

    expect(failure.flows).toEqual([]);
    expect(failure.error).toBe('offline');
    expect(failure.notification).toEqual({
      type: 'error',
      message: 'Unable to load flow definitions',
      options: { autoHideDuration: 8000 },
    });
    expect(failure.unsupported).toBe(false);
  });

  it('does not call flow APIs without an organization id', async () => {
    const listFlows = vi.fn();

    await expect(loadFlowManagerFlows({ listFlows, organizationId: '' })).resolves.toEqual({
      flows: [],
      error: 'An active organization is required before loading flows.',
      notification: null,
      unsupported: false,
    });
    expect(listFlows).not.toHaveBeenCalled();
  });

  it('loads executions for one or many flows', async () => {
    const listFlowExecutions = vi.fn(async (flowId?: string) => {
      if (flowId === 'flow-1') {
        return [{ id: 'exec-1' }];
      }

      if (flowId === 'flow-2') {
        return [{ id: 'exec-2' }];
      }

      return [];
    });

    await expect(loadFlowManagerExecutions({
      listFlowExecutions,
      organizationId: 'org-1',
      flowId: 'flow-1',
    })).resolves.toEqual({
      executions: [{ id: 'exec-1' }],
      notification: null,
      unsupported: false,
    });

    await expect(loadFlowManagerExecutions({
      listFlowExecutions,
      organizationId: 'org-1',
      flows: [{ id: 'flow-1' }, { id: 'flow-2' }],
    })).resolves.toEqual({
      executions: [{ id: 'exec-1' }, { id: 'exec-2' }],
      notification: null,
      unsupported: false,
    });
  });

  it('loads credentials and revocation batches with safe fallbacks', async () => {
    await expect(loadFlowManagerCredentials({
      listCredentials: vi.fn().mockResolvedValue([{ id: 'cred-1' }]),
      organizationId: 'org-1',
    })).resolves.toEqual({
      credentials: [{ id: 'cred-1' }],
      notification: null,
      unsupported: false,
    });

    await expect(loadFlowManagerRevocationBatches({
      listRevocationBatches: vi.fn().mockResolvedValue([{ batch_id: 'batch-1' }]),
      organizationId: 'org-1',
    })).resolves.toEqual({
      revocationBatches: [{ batch_id: 'batch-1' }],
      notification: null,
      unsupported: false,
    });
  });

  it('approves executions and batches revocations', async () => {
    const approveFlowExecution = vi.fn().mockResolvedValue(undefined);

    await expect(approveFlowManagerExecution({
      approveFlowExecution,
      execution: { id: 'exec-1', flow_id: 'flow-1' },
      user: { id: 'user-1' },
    })).resolves.toEqual({
      notification: { type: 'success', message: 'Execution approved' },
      shouldReloadExecutions: true,
    });

    expect(approveFlowExecution).toHaveBeenCalledWith('flow-1', 'exec-1', {
      approver_id: 'user-1',
      notes: 'Approved via UI',
    });

    const batchRevokeCredentials = vi.fn().mockResolvedValue(undefined);

    await expect(batchRevokeFlowManagerCredentials({
      batchRevokeCredentials,
      selectedCredentials: ['cred-1', 'cred-2'],
      strategy: 'scheduled',
    })).resolves.toEqual({
      notification: { type: 'success', message: '2 credentials queued for batch revocation' },
      shouldReloadCredentials: true,
      shouldReloadRevocationBatches: true,
      selectedCredentials: [],
      revocationDialog: false,
    });
  });

  it('warns when batch revoke is requested with no selection', async () => {
    await expect(batchRevokeFlowManagerCredentials({
      batchRevokeCredentials: vi.fn(),
      selectedCredentials: [],
      strategy: 'immediate',
    })).resolves.toEqual({
      notification: { type: 'warning', message: 'No credentials selected' },
      shouldReloadCredentials: false,
      shouldReloadRevocationBatches: false,
      selectedCredentials: [],
      revocationDialog: true,
    });
  });
});
