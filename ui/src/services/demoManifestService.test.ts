import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  DemoManifestError,
  compareStackVersions,
  loadDemoIndex,
  loadDemoManifest,
  validateDemoManifest,
} from './demoManifestService';

const scenario = {
  slug: 'membership-badge-login',
  mip_version: '0.3.1',
  state: 'DRAFT',
  protocols: ['openid4vci-1.0', 'openid4vp-1.0', 'dcql-1.0', 'sd-jwt-vc', 'open-badges-3.0'],
  poster: { src: '/images/demos/2026.07.0/membership-badge-login.png' },
  youtube_id: null,
};

const manifest = {
  schema_version: 1,
  stack_version: '2026.07.0',
  release_name: 'Credential Lifecycle Foundation',
  mip_version: '0.3.1',
  scenarios: [scenario],
};

afterEach(() => vi.restoreAllMocks());

describe('demoManifestService', () => {
  it('orders immutable ElevenID LLC versions independently from MIP versions', () => {
    expect(compareStackVersions('2026.07.1', '2026.07.0')).toBeGreaterThan(0);
    expect(compareStackVersions('2026.08.0', '2026.07.9')).toBeGreaterThan(0);
  });

  it('loads and sorts the public release index', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      schema_version: 1,
      latest_approved_stack_version: '2026.07.1',
      releases: [
        { stack_version: '2026.07.0', release_name: 'Credential Lifecycle Foundation', mip_version: '0.3.1' },
        { stack_version: '2026.07.1', release_name: 'Credential Lifecycle Refinement', mip_version: '0.3.1' },
      ],
    }), { status: 200 }));

    const index = await loadDemoIndex();

    expect(index.releases.map((release) => release.stack_version)).toEqual(['2026.07.1', '2026.07.0']);
    expect(index.releases.map((release) => release.mip_version)).toEqual(['0.3.1', '0.3.1']);
  });

  it('rejects draft and deprecated protocol identifiers', () => {
    expect(() => validateDemoManifest({
      ...manifest,
      scenarios: [{ ...scenario, protocols: ['openid4vp-draft-24'] }],
    })).toThrow(DemoManifestError);
  });

  it('rejects a manifest bound to another ElevenID LLC release', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      ...manifest,
      stack_version: '2026.08.0',
      scenarios: [{
        ...scenario,
        poster: { src: '/images/demos/2026.08.0/membership-badge-login.png' },
      }],
    }), { status: 200 }));

    await expect(loadDemoManifest('2026.07.0')).rejects.toThrow('does not match');
  });

  it('turns malformed JSON and HTTP failures into recoverable manifest errors', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response('{bad', { status: 200 }))
      .mockResolvedValueOnce(new Response('', { status: 503 }));

    await expect(loadDemoIndex()).rejects.toThrow('malformed JSON');
    await expect(loadDemoIndex()).rejects.toThrow('(503)');
  });
});
