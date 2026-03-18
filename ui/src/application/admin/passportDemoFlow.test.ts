import { describe, expect, it } from 'vitest';

import {
  createPassportInspectError,
  createPassportIssueError,
  resolvePassportInspectResult,
  resolvePassportIssueResult,
} from './passportDemoFlow';

describe('passportDemoFlow helpers', () => {
  it('builds success result wrappers', () => {
    expect(resolvePassportIssueResult({ passport_number: 'P123' })).toEqual({
      error: null,
      result: { passport_number: 'P123' },
    });

    expect(resolvePassportInspectResult({ details: { passport_number: 'P123' } })).toEqual({
      error: null,
      inspectResult: { details: { passport_number: 'P123' } },
    });
  });

  it('builds error result wrappers', () => {
    expect(createPassportIssueError()).toEqual({
      error: 'Failed to issue passport',
      result: null,
    });

    expect(createPassportInspectError('No passport found')).toEqual({
      error: 'No passport found',
      inspectResult: null,
    });
  });
});
