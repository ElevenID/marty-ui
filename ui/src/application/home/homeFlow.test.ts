import { describe, expect, it } from 'vitest';

import {
  HOME_DEFAULT_STATS,
  HOME_DEFAULT_SYSTEM_STATUS,
  resolveHomeStats,
  resolveHomeSystemStatus,
} from './homeFlow';

describe('homeFlow helpers', () => {
  it('returns default home system status when data is missing', () => {
    expect(resolveHomeSystemStatus(null)).toEqual(HOME_DEFAULT_SYSTEM_STATUS);
  });

  it('maps health payloads into the home status shape', () => {
    expect(resolveHomeSystemStatus({
      status: 'healthy',
      services: { issuer: 'online', verifier: 'online', wallet: 'degraded' },
    })).toEqual({
      healthy: true,
      services: { issuer: 'online', verifier: 'online', wallet: 'degraded' },
    });
  });

  it('merges stats with defaults', () => {
    expect(resolveHomeStats({ credentials: 12, verifications: 7 })).toEqual({
      ...HOME_DEFAULT_STATS,
      credentials: 12,
      verifications: 7,
    });
  });
});