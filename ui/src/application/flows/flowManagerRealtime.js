export function getFlowManagerRealtimeSubscriptions(eventTypes) {
  return [
    eventTypes.FLOW_EXECUTION_STARTED,
    eventTypes.FLOW_EXECUTION_COMPLETED,
    eventTypes.APPLICATION_APPROVED,
    eventTypes.CREDENTIAL_ISSUED,
    eventTypes.CREDENTIAL_REVOKED,
    eventTypes.REVOCATION_BATCH_COMPLETED,
  ];
}

export function startFlowManagerRealtimeUpdates({
  sseService,
  eventTypes,
  organizationId,
  loadExecutions,
  loadCredentials,
  loadRevocationBatches,
  showSuccess,
  logger,
}) {
  if (!organizationId) {
    return () => {};
  }

  const subscriptions = getFlowManagerRealtimeSubscriptions(eventTypes);
  const activeLogger = logger;

  sseService.connect({
    organizationId,
    subscriptions,
  });

  const eventHandlers = [
    [eventTypes.FLOW_EXECUTION_STARTED, (data) => {
      activeLogger?.log?.('Flow execution started:', data);
      loadExecutions();
      showSuccess(`Flow execution started: ${data.flow_id}`);
    }],
    [eventTypes.FLOW_EXECUTION_COMPLETED, (data) => {
      activeLogger?.log?.('Flow execution completed:', data);
      loadExecutions();
      showSuccess(`Flow execution completed: ${data.execution_id}`);
    }],
    [eventTypes.APPLICATION_APPROVED, (data) => {
      activeLogger?.log?.('Application approved:', data);
      loadExecutions();
    }],
    [eventTypes.CREDENTIAL_ISSUED, (data) => {
      activeLogger?.log?.('Credential issued:', data);
      loadCredentials();
      showSuccess(`Credential issued: ${data.credential_id}`);
    }],
    [eventTypes.CREDENTIAL_REVOKED, (data) => {
      activeLogger?.log?.('Credential revoked:', data);
      loadCredentials();
      loadRevocationBatches();
    }],
    [eventTypes.REVOCATION_BATCH_COMPLETED, (data) => {
      activeLogger?.log?.('Revocation batch completed:', data);
      loadRevocationBatches();
      loadCredentials();
      showSuccess(`Revocation batch completed: ${data.credential_count} credentials`);
    }],
  ];

  const unsubscribers = eventHandlers.map(([eventType, handler]) => sseService.on(eventType, handler));

  return () => {
    unsubscribers.forEach((unsubscribe) => unsubscribe());
    sseService.disconnect();
  };
}
