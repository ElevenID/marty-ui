import {
  getBatchRevocationFeedback,
} from './flowManager';

function isUnsupportedEndpointError(error) {
  return error?.status === 404 || error?.status === 422;
}

function isMissingOrganizationId(organizationId) {
  return (
    organizationId == null
    || String(organizationId).trim() === ''
    || String(organizationId).trim().toLowerCase() === 'null'
    || String(organizationId).trim().toLowerCase() === 'undefined'
  );
}

function getErrorMessage(error, fallback) {
  const message = error?.message || fallback;
  const messageId = error?.message_id || error?.messageId;
  return messageId ? `${message} (message id: ${messageId})` : message;
}

export async function loadFlowManagerFlows({ listFlows, organizationId }) {
  if (isMissingOrganizationId(organizationId)) {
    return {
      flows: [],
      error: 'An active organization is required before loading flows.',
      notification: null,
      unsupported: false,
    };
  }

  try {
    const flows = await listFlows({ organization_id: organizationId, limit: 100 });
    return {
      flows,
      error: null,
      notification: null,
      unsupported: false,
    };
  } catch (error) {
    return {
      flows: [],
      error: getErrorMessage(error, 'Unable to load flow definitions.'),
      notification: {
        type: 'error',
        message: isUnsupportedEndpointError(error)
          ? 'Flow services are unavailable for this environment'
          : 'Unable to load flow definitions',
        options: { autoHideDuration: 8000 },
      },
      unsupported: isUnsupportedEndpointError(error),
    };
  }
}

export async function loadFlowManagerExecutions({
  listFlowExecutions,
  organizationId,
  flows = [],
  flowId = null,
}) {
  if (isMissingOrganizationId(organizationId)) {
    return {
      executions: [],
      notification: null,
      unsupported: false,
    };
  }

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
  if (isMissingOrganizationId(organizationId)) {
    return {
      credentials: [],
      notification: null,
      unsupported: false,
    };
  }

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
  if (isMissingOrganizationId(organizationId)) {
    return {
      revocationBatches: [],
      notification: null,
      unsupported: false,
    };
  }

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
