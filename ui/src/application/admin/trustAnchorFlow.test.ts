import { describe, expect, it } from 'vitest';

import {
  TRUST_ANCHOR_DEFAULT_CONFIG,
  TRUST_ANCHOR_FALLBACK_STATUS,
  createTrustAnchorVerificationError,
  createTrustAnchorVerificationResult,
  readTrustAnchorStoredConfig,
  resolveTrustAnchorConfig,
  resolveTrustAnchorStatus,
  serializeTrustAnchorConfig,
} from './trustAnchorFlow';

describe('trustAnchorFlow helpers', () => {
  it('normalizes and serializes trust anchor config', () => {
    expect(resolveTrustAnchorConfig({
      anchor_name: 'Demo Anchor',
      domain: 'trust.example',
      policy: 'lenient',
      log_level: 'warn',
    })).toEqual({
      anchorName: 'Demo Anchor',
      domain: 'trust.example',
      policy: 'lenient',
      logLevel: 'warn',
    });

    expect(serializeTrustAnchorConfig(TRUST_ANCHOR_DEFAULT_CONFIG)).toEqual({
      anchor_name: 'Marty Trust Anchor',
      domain: 'trust.marty.local',
      policy: 'strict',
      log_level: 'info',
    });
  });

  it('merges trust status and reads stored config safely', () => {
    expect(resolveTrustAnchorStatus({
      healthy: false,
      rootCA: { expires: '2040' },
    })).toEqual({
      ...TRUST_ANCHOR_FALLBACK_STATUS,
      healthy: false,
      rootCA: {
        ...TRUST_ANCHOR_FALLBACK_STATUS.rootCA,
        expires: '2040',
      },
    });

    const storage = {
      getItem: () => JSON.stringify({ anchorName: 'Stored Anchor', domain: 'stored.example' }),
    };

    expect(readTrustAnchorStoredConfig(storage)).toEqual({
      ...TRUST_ANCHOR_DEFAULT_CONFIG,
      anchorName: 'Stored Anchor',
      domain: 'stored.example',
    });
  });

  it('builds verification success and error models', () => {
    expect(createTrustAnchorVerificationResult({ is_trusted: true })).toEqual({
      success: true,
      isTrusted: true,
      message: 'Entity is trusted.',
    });

    expect(createTrustAnchorVerificationError(new Error('Nope'))).toEqual({
      success: false,
      message: 'Nope',
    });
  });
});
