import { describe, expect, it, vi } from 'vitest';

import {
  disableFlowDefinition,
  getFlowDisableFailureState,
  getFlowDisableInitialState,
  getFlowPublishFailureState,
  getFlowPublishInitialState,
  publishFlowDefinition,
  resetFlowDisableState,
  resetFlowPublishState,
  validateFlowDisableReason,
} from './flowDialogUseCases';

describe('flow dialog use cases', () => {
  it('provides and resets initial dialog state', () => {
    expect(getFlowPublishInitialState()).toEqual({
      changeDescription: '',
      publishing: false,
      error: null,
      published: false,
      publicUrl: null,
    });

    expect(resetFlowPublishState()).toEqual(getFlowPublishInitialState());

    expect(getFlowDisableInitialState()).toEqual({
      reason: '',
      disabling: false,
      error: null,
    });

    expect(resetFlowDisableState()).toEqual(getFlowDisableInitialState());
  });

  it('publishes a flow and derives a fallback public url', async () => {
    const publishFlow = vi.fn().mockResolvedValue({ id: 'flow-1', name: 'Employee Flow' });

    await expect(publishFlowDefinition({
      publishFlow,
      flow: { id: 'flow-1' },
      changeDescription: 'Ready for launch',
      fallbackOrigin: 'https://example.test',
    })).resolves.toEqual({
      result: { id: 'flow-1', name: 'Employee Flow' },
      state: {
        publishing: false,
        error: null,
        published: true,
        publicUrl: 'https://example.test/apply/flow-1',
      },
    });

    expect(publishFlow).toHaveBeenCalledWith('flow-1', {
      change_description: 'Ready for launch',
    });
  });

  it('accepts explicit public urls from the publish response', async () => {
    const publishFlow = vi.fn().mockResolvedValue({ public_url: 'https://custom.example/apply/flow-1' });

    const result = await publishFlowDefinition({
      publishFlow,
      flow: { id: 'flow-1' },
      changeDescription: '',
      fallbackOrigin: 'https://example.test',
    });

    expect(result.state.publicUrl).toBe('https://custom.example/apply/flow-1');
  });

  it('builds publish and disable failure state from thrown errors', () => {
    expect(getFlowPublishFailureState({
      error: new Error('Publish failed'),
      fallbackMessage: 'fallback publish',
    })).toEqual({
      publishing: false,
      error: 'Publish failed',
    });

    expect(getFlowDisableFailureState({
      error: undefined,
      fallbackMessage: 'fallback disable',
    })).toEqual({
      disabling: false,
      error: 'fallback disable',
    });
  });

  it('validates and disables flows', async () => {
    expect(validateFlowDisableReason({
      reason: '   ',
      reasonErrorMessage: 'Reason required',
    })).toEqual({
      valid: false,
      error: 'Reason required',
    });

    expect(validateFlowDisableReason({
      reason: 'Security incident',
      reasonErrorMessage: 'Reason required',
    })).toEqual({
      valid: true,
      error: null,
    });

    const disableFlow = vi.fn().mockResolvedValue({ id: 'flow-1', status: 'disabled' });

    await expect(disableFlowDefinition({
      disableFlow,
      flow: { id: 'flow-1' },
      reason: 'Security incident',
    })).resolves.toEqual({
      result: { id: 'flow-1', status: 'disabled' },
      state: {
        disabling: false,
        error: null,
      },
    });

    expect(disableFlow).toHaveBeenCalledWith('flow-1', {
      reason: 'Security incident',
    });
  });
});
