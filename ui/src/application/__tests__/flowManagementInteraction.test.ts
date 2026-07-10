/**
 * Interaction tests: Flow Management Journey
 *
 * Exercises the vendor flow management console through the headless layer:
 *
 *   1. Load flows → view dashboard
 *   2. Publish a flow → get public URL
 *   3. Load executions → approve a manual execution
 *   4. Batch revoke credentials
 *   5. Disable a flow with reason
 */

import { describe, expect, it, vi } from 'vitest';

import {
  loadFlowManagerFlows,
  loadFlowManagerExecutions,
  loadFlowManagerCredentials,
  approveFlowManagerExecution,
  batchRevokeFlowManagerCredentials,
} from '../flows/flowManagerUseCases';
import {
  getFlowPublishInitialState,
  publishFlowDefinition,
  getFlowPublishFailureState,
  validateFlowDisableReason,
  disableFlowDefinition,
} from '../flows/flowDialogUseCases';
import {
  getFlowStatusPresentation,
  getApprovalStrategyPresentation,
} from '../flows/flowManager';

describe('Flow Management — vendor console interaction', () => {
  const DRAFT_FLOW = {
    id: 'flow-1',
    name: 'Employee Badge Issuance',
    flow_type: 'issuance',
    status: 'DRAFT',
    approval_strategy: 'manual',
  };

  const PUBLISHED_FLOW = {
    ...DRAFT_FLOW,
    status: 'PUBLISHED',
  };

  it('loads flows, examines status, then publishes a draft flow', async () => {
    // ── Step 1: Load flows ──────────────────────────────────
    const { flows } = await loadFlowManagerFlows({
      listFlows: vi.fn().mockResolvedValue([DRAFT_FLOW]),
      organizationId: 'org-1',
    });
    expect(flows).toHaveLength(1);

    // ── Step 2: Check flow status presentation ─────────────
    const statusInfo = getFlowStatusPresentation(flows[0].status);
    expect(statusInfo.isDraft).toBe(true);
    expect(statusInfo.isPublished).toBe(false);
    expect(statusInfo.hasApplicantEntry).toBe(false);

    const approvalInfo = getApprovalStrategyPresentation(flows[0].approval_strategy);
    expect(approvalInfo).toBeDefined();

    // ── Step 3: Publish the flow ────────────────────────────
    const publishState = getFlowPublishInitialState();
    expect(publishState.published).toBe(false);

    const { result, state: publishedState } = await publishFlowDefinition({
      publishFlow: vi.fn().mockResolvedValue({
        public_url: 'https://marty.dev/apply/flow-1',
      }),
      flow: DRAFT_FLOW,
      changeDescription: 'Initial publication',
      fallbackOrigin: 'https://marty.dev',
    });

    expect(publishedState.published).toBe(true);
    expect(publishedState.error).toBeNull();
    expect(publishedState.publicUrl).toBe('https://marty.dev/apply/flow-1');

    // ── Step 4: Published flow status ───────────────────────
    const publishedStatusInfo = getFlowStatusPresentation('PUBLISHED');
    expect(publishedStatusInfo.isPublished).toBe(true);
    expect(publishedStatusInfo.hasApplicantEntry).toBe(true);
  });

  it('surfaces backend failures without returning mock flows', async () => {
    const { flows, error, notification } = await loadFlowManagerFlows({
      listFlows: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')),
      organizationId: 'org-1',
    });

    expect(flows).toEqual([]);
    expect(error).toBe('ECONNREFUSED');
    expect(notification).toMatchObject({
      type: 'error',
      message: 'Unable to load flow definitions',
    });
  });

  it('loads executions, approves one, then reloads', async () => {
    // ── Load executions ─────────────────────────────────────
    const execution = {
      id: 'exec-1',
      flow_id: 'flow-1',
      status: 'PENDING_APPROVAL',
      subject_id: 'user-99',
    };

    const { executions } = await loadFlowManagerExecutions({
      listFlowExecutions: vi.fn().mockResolvedValue([execution]),
      organizationId: 'org-1',
      flowId: 'flow-1',
    });
    expect(executions).toHaveLength(1);

    // ── Approve execution ───────────────────────────────────
    const approveResult = await approveFlowManagerExecution({
      approveFlowExecution: vi.fn().mockResolvedValue(undefined),
      execution: executions[0],
      user: { id: 'admin-1' },
    });

    expect(approveResult.notification.type).toBe('success');
    expect(approveResult.shouldReloadExecutions).toBe(true);
  });

  it('aggregates executions from all flows when no specific flow selected', async () => {
    const listFlowExecutions = vi
      .fn()
      .mockResolvedValueOnce([{ id: 'exec-1', flow_id: 'flow-1' }])
      .mockResolvedValueOnce([{ id: 'exec-2', flow_id: 'flow-2' }]);

    const { executions } = await loadFlowManagerExecutions({
      listFlowExecutions,
      organizationId: 'org-1',
      flows: [{ id: 'flow-1' }, { id: 'flow-2' }],
    });

    expect(executions).toHaveLength(2);
    expect(listFlowExecutions).toHaveBeenCalledTimes(2);
  });

  it('batch revokes selected credentials and clears selection', async () => {
    const { notification, selectedCredentials, revocationDialog, shouldReloadCredentials } =
      await batchRevokeFlowManagerCredentials({
        batchRevokeCredentials: vi.fn().mockResolvedValue(undefined),
        selectedCredentials: ['cred-1', 'cred-2'],
        strategy: 'immediate',
      });

    // 'immediate' strategy yields a warning-severity feedback (expected design)
    expect(notification.type).toBe('warning');
    expect(notification.message).toContain('2 credentials revoked immediately');
    expect(selectedCredentials).toEqual([]);
    expect(revocationDialog).toBe(false);
    expect(shouldReloadCredentials).toBe(true);
  });

  it('warns when attempting batch revoke with empty selection', async () => {
    const { notification, revocationDialog } = await batchRevokeFlowManagerCredentials({
      batchRevokeCredentials: vi.fn(),
      selectedCredentials: [],
      strategy: 'immediate',
    });

    expect(notification.type).toBe('warning');
    expect(revocationDialog).toBe(true);
  });

  it('disables a flow with validated reason', async () => {
    // ── Validate reason ─────────────────────────────────────
    const invalid = validateFlowDisableReason({ reason: '', reasonErrorMessage: 'Required' });
    expect(invalid.valid).toBe(false);
    expect(invalid.error).toBe('Required');

    const valid = validateFlowDisableReason({ reason: 'Policy change', reasonErrorMessage: 'Required' });
    expect(valid.valid).toBe(true);

    // ── Disable ─────────────────────────────────────────────
    const { state } = await disableFlowDefinition({
      disableFlow: vi.fn().mockResolvedValue(undefined),
      flow: PUBLISHED_FLOW,
      reason: 'Policy change',
    });

    expect(state.disabling).toBe(false);
    expect(state.error).toBeNull();
  });

  it('publish failure produces readable error state', () => {
    const failState = getFlowPublishFailureState({
      error: new Error('Validation failed: missing trust profile'),
      fallbackMessage: 'Could not publish',
    });

    expect(failState.publishing).toBe(false);
    expect(failState.error).toBe('Validation failed: missing trust profile');
  });
});
