import { describe, expect, it, vi } from 'vitest';

import {
  getFlowManagerRealtimeSubscriptions,
  startFlowManagerRealtimeUpdates,
} from './flowManagerRealtime';

describe('flowManager realtime helpers', () => {
  const EVENT_TYPES = {
    FLOW_EXECUTION_STARTED: 'flow.execution.started',
    FLOW_EXECUTION_COMPLETED: 'flow.execution.completed',
    APPLICATION_APPROVED: 'application.approved',
    CREDENTIAL_ISSUED: 'credential.issued',
    CREDENTIAL_REVOKED: 'credential.revoked',
    REVOCATION_BATCH_COMPLETED: 'revocation_batch.completed',
  };

  it('returns the expected realtime subscriptions', () => {
    expect(getFlowManagerRealtimeSubscriptions(EVENT_TYPES)).toEqual([
      EVENT_TYPES.FLOW_EXECUTION_STARTED,
      EVENT_TYPES.FLOW_EXECUTION_COMPLETED,
      EVENT_TYPES.APPLICATION_APPROVED,
      EVENT_TYPES.CREDENTIAL_ISSUED,
      EVENT_TYPES.CREDENTIAL_REVOKED,
      EVENT_TYPES.REVOCATION_BATCH_COMPLETED,
    ]);
  });

  it('returns a noop cleanup when organization id is missing', () => {
    const sseService = {
      connect: vi.fn(),
      on: vi.fn(),
      disconnect: vi.fn(),
    };

    const cleanup = startFlowManagerRealtimeUpdates({
      sseService,
      eventTypes: EVENT_TYPES,
      organizationId: null,
      loadExecutions: vi.fn(),
      loadCredentials: vi.fn(),
      loadRevocationBatches: vi.fn(),
      showSuccess: vi.fn(),
      logger: { log: vi.fn() },
    });

    cleanup();

    expect(sseService.connect).not.toHaveBeenCalled();
    expect(sseService.on).not.toHaveBeenCalled();
    expect(sseService.disconnect).not.toHaveBeenCalled();
  });

  it('connects, wires listeners, reacts to events, and cleans up', () => {
    const loadExecutions = vi.fn();
    const loadCredentials = vi.fn();
    const loadRevocationBatches = vi.fn();
    const showSuccess = vi.fn();
    const logger = { log: vi.fn() };
    const handlers = new Map();
    const unsubscribers = [vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn()];
    let onCall = 0;

    const sseService = {
      connect: vi.fn(),
      on: vi.fn((eventType, handler) => {
        handlers.set(eventType, handler);
        const unsubscribe = unsubscribers[onCall];
        onCall += 1;
        return unsubscribe;
      }),
      disconnect: vi.fn(),
    };

    const cleanup = startFlowManagerRealtimeUpdates({
      sseService,
      eventTypes: EVENT_TYPES,
      organizationId: 'org-1',
      loadExecutions,
      loadCredentials,
      loadRevocationBatches,
      showSuccess,
      logger,
    });

    expect(sseService.connect).toHaveBeenCalledWith({
      organizationId: 'org-1',
      subscriptions: getFlowManagerRealtimeSubscriptions(EVENT_TYPES),
    });
    expect(sseService.on).toHaveBeenCalledTimes(6);

    handlers.get(EVENT_TYPES.FLOW_EXECUTION_STARTED)({ flow_id: 'flow-1' });
    handlers.get(EVENT_TYPES.FLOW_EXECUTION_COMPLETED)({ execution_id: 'exec-1' });
    handlers.get(EVENT_TYPES.APPLICATION_APPROVED)({ application_id: 'app-1' });
    handlers.get(EVENT_TYPES.CREDENTIAL_ISSUED)({ credential_id: 'cred-1' });
    handlers.get(EVENT_TYPES.CREDENTIAL_REVOKED)({ credential_id: 'cred-1' });
    handlers.get(EVENT_TYPES.REVOCATION_BATCH_COMPLETED)({ credential_count: 3 });

    expect(loadExecutions).toHaveBeenCalledTimes(3);
    expect(loadCredentials).toHaveBeenCalledTimes(3);
    expect(loadRevocationBatches).toHaveBeenCalledTimes(2);
    expect(showSuccess).toHaveBeenCalledWith('Flow execution started: flow-1');
    expect(showSuccess).toHaveBeenCalledWith('Flow execution completed: exec-1');
    expect(showSuccess).toHaveBeenCalledWith('Credential issued: cred-1');
    expect(showSuccess).toHaveBeenCalledWith('Revocation batch completed: 3 credentials');

    cleanup();

    unsubscribers.forEach((unsubscribe) => {
      expect(unsubscribe).toHaveBeenCalled();
    });
    expect(sseService.disconnect).toHaveBeenCalledTimes(1);
  });
});
