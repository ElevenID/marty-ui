export function getFlowPublishInitialState() {
  return {
    changeDescription: '',
    publishing: false,
    error: null,
    published: false,
    publicUrl: null,
  };
}

export function getFlowDisableInitialState() {
  return {
    reason: '',
    disabling: false,
    error: null,
  };
}

export function resetFlowPublishState() {
  return getFlowPublishInitialState();
}

export function resetFlowDisableState() {
  return getFlowDisableInitialState();
}

export async function publishFlowDefinition({
  publishFlow,
  flow,
  changeDescription,
  fallbackOrigin,
}) {
  const result = await publishFlow(flow.id, {
    change_description: changeDescription,
  });

  return {
    result,
    state: {
      publishing: false,
      error: null,
      published: true,
      publicUrl: result.public_url || `${fallbackOrigin}/apply/${flow.id}`,
    },
  };
}

export function getFlowPublishFailureState({ error, fallbackMessage }) {
  return {
    publishing: false,
    error: error?.message || fallbackMessage,
  };
}

export function validateFlowDisableReason({ reason, reasonErrorMessage }) {
  if (!reason.trim()) {
    return {
      valid: false,
      error: reasonErrorMessage,
    };
  }

  return {
    valid: true,
    error: null,
  };
}

export async function disableFlowDefinition({ disableFlow, flow, reason }) {
  const result = await disableFlow(flow.id, { reason });

  return {
    result,
    state: {
      disabling: false,
      error: null,
    },
  };
}

export function getFlowDisableFailureState({ error, fallbackMessage }) {
  return {
    disabling: false,
    error: error?.message || fallbackMessage,
  };
}
