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
  it('loads flows and falls back to sample data on failure', async () => {
    const listFlows = vi.fn().mockResolvedValue([{ id: 'flow-1' }]);

    await expect(loadFlowManagerFlows({ listFlows })).resolves.toEqual({
      flows: [{ id: 'flow-1' }],
      error: null,
      notification: null,
      unsupported: false,
    });

    const failingListFlows = vi.fn().mockRejectedValue(new Error('offline'));
    const fallback = await loadFlowManagerFlows({ listFlows: failingListFlows });

    expect(fallback.notification).toBeTruthy();
    expect(Array.isArray(fallback.flows)).toBe(true);
    expect(typeof fallback.unsupported).toBe('boolean');
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
      flowId: 'flow-1',
    })).resolves.toEqual({
      executions: [{ id: 'exec-1' }],
      notification: null,
      unsupported: false,
    });

    await expect(loadFlowManagerExecutions({
      listFlowExecutions,
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
    })).resolves.toEqual({
      credentials: [{ id: 'cred-1' }],
      notification: null,
      unsupported: false,
    });

    await expect(loadFlowManagerRevocationBatches({
      listRevocationBatches: vi.fn().mockResolvedValue([{ batch_id: 'batch-1' }]),
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