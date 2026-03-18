import {
  getBatchRevocationFeedback,
  getFlowManagerMockFlows,
} from './flowManager';

export async function loadFlowManagerFlows({ listFlows }) {
  try {
    const flows = await listFlows({ limit: 100 });
    return {
      flows,
      error: null,
      notification: null,
    };
  } catch (error) {
    return {
      flows: getFlowManagerMockFlows(),
      error: null,
      notification: {
        type: 'warning',
        message: 'Backend service unavailable - showing sample data for testing',
        options: { autoHideDuration: 8000 },
      },
    };
  }
}

export async function loadFlowManagerExecutions({ listFlowExecutions, flows = [], flowId = null }) {
  if (flowId) {
    return {
      executions: await listFlowExecutions(flowId, { limit: 50 }),
      notification: null,
    };
  }

  if (flows.length === 0) {
    return {
      executions: [],
      notification: null,
    };
  }

  try {
    const executionSets = await Promise.all(
      flows.map((flow) => listFlowExecutions(flow.id, { limit: 10 }))
    );

    return {
      executions: executionSets.flat(),
      notification: null,
    };
  } catch (error) {
    return {
      executions: [],
      notification: {
        type: 'error',
        message: 'Unable to load flow executions',
        options: {
          details: 'The backend service may be unavailable. Check console for details.',
        },
      },
    };
  }
}

export async function loadFlowManagerCredentials({ listCredentials }) {
  try {
    return {
      credentials: await listCredentials({ limit: 100 }),
      notification: null,
    };
  } catch (error) {
    return {
      credentials: [],
      notification: {
        type: 'error',
        message: 'Unable to load credentials',
        options: {
          details: 'The backend service may be unavailable. Check console for details.',
        },
      },
    };
  }
}

export async function loadFlowManagerRevocationBatches({ listRevocationBatches }) {
  try {
    return {
      revocationBatches: await listRevocationBatches(),
      notification: null,
    };
  } catch (error) {
    return {
      revocationBatches: [],
      notification: {
        type: 'error',
        message: 'Unable to load revocation batches',
        options: {
          details: 'The backend service may be unavailable. Check console for details.',
        },
      },
    };
  }
}

export async function approveFlowManagerExecution({ approveFlowExecution, execution, user }) {
  await approveFlowExecution(
    execution.flow_id,
    execution.id,
    { approver_id: user.id, notes: 'Approved via UI' }
  );

  return {
    notification: {
      type: 'success',
      message: 'Execution approved',
    },
    shouldReloadExecutions: true,
  };
}

export async function batchRevokeFlowManagerCredentials({
  batchRevokeCredentials,
  selectedCredentials = [],
  strategy,
}) {
  if (selectedCredentials.length === 0) {
    return {
      notification: {
        type: 'warning',
        message: 'No credentials selected',
      },
      shouldReloadCredentials: false,
      shouldReloadRevocationBatches: false,
      selectedCredentials,
      revocationDialog: true,
    };
  }

  await batchRevokeCredentials(selectedCredentials, {
    revocation_strategy: strategy,
    revocation_reason: 'Batch revocation via UI',
  });

  const feedback = getBatchRevocationFeedback(strategy, selectedCredentials.length);

  return {
    notification: {
      type: feedback.severity,
      message: feedback.message,
    },
    shouldReloadCredentials: true,
    shouldReloadRevocationBatches: true,
    selectedCredentials: [],
    revocationDialog: false,
  };
}