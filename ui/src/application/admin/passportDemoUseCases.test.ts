import { describe, expect, it, vi } from 'vitest';

import { inspectPassport, issuePassport } from './passportDemoUseCases';

describe('passportDemoUseCases', () => {
  it('issues passports through the injected transport', async () => {
    await expect(issuePassport({
      passportNumber: 'P123',
      processPassport: vi.fn().mockResolvedValue({ passport_number: 'P123', status: 'issued' }),
    })).resolves.toEqual({
      error: null,
      result: { passport_number: 'P123', status: 'issued' },
    });
  });

  it('inspects passports and returns friendly errors on failure', async () => {
    await expect(inspectPassport({
      passportNumber: 'P123',
      inspectPassportRequest: vi.fn().mockResolvedValue({
        details: { passport_number: 'P123', holder: 'Avery Example', nationality: 'USA' },
      }),
    })).resolves.toEqual({
      error: null,
      inspectResult: {
        details: { passport_number: 'P123', holder: 'Avery Example', nationality: 'USA' },
      },
    });

    await expect(inspectPassport({
      passportNumber: 'P404',
      inspectPassportRequest: vi.fn().mockRejectedValue(new Error('Failed to inspect passport')),
    })).resolves.toEqual({
      error: 'Failed to inspect passport',
      inspectResult: null,
    });
  });
});
