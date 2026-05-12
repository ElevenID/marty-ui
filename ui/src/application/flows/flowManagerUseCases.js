import {
  getBatchRevocationFeedback,
  getFlowManagerMockFlows,
} from './flowManager';

function isUnsupportedEndpointError(error) {
  return error?.status === 404 || error?.status === 422;
}

function shouldUseMockFlowData() {
  return Boolean(import.meta?.env?.DEV);
}

export async function loadFlowManagerFlows({ listFlows, organizationId }) {
  try {
    const flows = await listFlows({ organization_id: organizationId, limit: 100 });
    return {
      flows,
      error: null,
      notification: null,
      unsupported: false,
    };
  } catch (error) {
    if (!shouldUseMockFlowData()) {
      return {
        flows: [],
        error: null,
        notification: {
          type: 'warning',
          message: 'Flow services are unavailable for this environment',
          options: { autoHideDuration: 8000 },
        },
        unsupported: isUnsupportedEndpointError(error),
      };
    }

    return {
      flows: getFlowManagerMockFlows(),
      error: null,
      notification: {
        type: 'warning',
        message: 'Backend service unavailable - showing sample data for testing',
        options: { autoHideDuration: 8000 },
      },
      unsupported: false,
    };
  }
}

export async function loadFlowManagerExecutions({
  listFlowExecutions,
  organizationId,
  flows = [],
  flowId = null,
}) {
  if (flowId) {
    try {
      return {
        executions: await listFlowExecutions(flowId, { organization_id: organizationId, limit: 50 }),
        notification: null,
        unsupported: false,
      };
    } catch (error) {
      if (isUnsupportedEndpointError(error)) {
        return {
          executions: [],
          notification: null,
          unsupported: true,
        };
      }

      return {
        executions: [],
        notification: {
          type: 'error',
          message: 'Unable to load flow executions',
          options: {
            details: 'The backend service may be unavailable. Check console for details.',
          },
        },
        unsupported: false,
      };
    }
  }

  if (flows.length === 0) {
    return {
      executions: [],
      notification: null,
      unsupported: false,
    };
  }

  try {
    const executionSets = await Promise.all(
      flows.map((flow) => listFlowExecutions(flow.id, { organization_id: organizationId, limit: 10 }))
    );

    return {
      executions: executionSets.flat(),
      notification: null,
      unsupported: false,
    };
  } catch (error) {
    if (isUnsupportedEndpointError(error)) {
      return {
        executions: [],
        notification: null,
        unsupported: true,
      };
    }

    return {
      executions: [],
      notification: {
        type: 'error',
        message: 'Unable to load flow executions',
        options: {
          details: 'The backend service may be unavailable. Check console for details.',
        },
      },
      unsupported: false,
    };
  }
}

export async function loadFlowManagerCredentials({ listCredentials, organizationId }) {
  try {
    return {
      credentials: await listCredentials({ organization_id: organizationId, limit: 100 }),
      notification: null,
      unsupported: false,
    };
  } catch (error) {
    if (isUnsupportedEndpointError(error)) {
      return {
        credentials: [],
        notification: null,
        unsupported: true,
      };
    }

    return {
      credentials: [],
      notification: {
        type: 'error',
        message: 'Unable to load credentials',
        options: {
          details: 'The backend service may be unavailable. Check console for details.',
        },
      },
      unsupported: false,
    };
  }
}

export async function loadFlowManagerRevocationBatches({ listRevocationBatches, organizationId }) {
  try {
    return {
      revocationBatches: await listRevocationBatches({ organization_id: organizationId }),
      notification: null,
      unsupported: false,
    };
  } catch (error) {
    if (isUnsupportedEndpointError(error)) {
      return {
        revocationBatches: [],
        notification: null,
        unsupported: true,
      };
    }

    return {
      revocationBatches: [],
      notification: {
        type: 'error',
        message: 'Unable to load revocation batches',
        options: {
          details: 'The backend service may be unavailable. Check console for details.',
        },
      },
      unsupported: false,
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