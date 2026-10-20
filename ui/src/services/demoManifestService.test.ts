import { afterEach, describe, expect, it, vi } from 'vitest';
import { copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import compiledWalletSchema from '../generated/demoWalletSchema.generated.json';

import {
  DemoManifestError,
  compareStackVersions,
  loadDemoIndex,
  loadDemoManifest,
  validateDemoIndex,
  validateDemoManifest,
} from './demoManifestService';

const scenario = {
  slug: 'membership-badge-login',
  mip_version: '0.3.1',
  state: 'DRAFT',
  scenario_revision: 1,
  recording_classification: 'FIRST_PARTY_CONTROL',
  revision_history: [],
  protocols: ['openid4vci-1.0', 'openid4vp-1.0', 'dcql-1.0', 'sd-jwt-vc', 'open-badges-3.0'],
  poster: { src: '/images/demos/2026.07.0/membership-badge-login.png' },
  youtube_id: null,
  media_evidence: null,
  published_at: null,
  publication_attestation: null,
  assertions: [],
  wallets: [],
};

const manifest = {
  schema_version: 2,
  stack_version: '2026.07.0',
  release_name: 'Credential Lifecycle Foundation',
  mip_version: '0.3.1',
  publication_state: 'DRAFT',
  coverage_state: 'PARTIAL',
  release_ready: false,
  public_demo_ready: false,
  published_at: null,
  publication_attestation: null,
  video_distribution: {
    provider: 'YOUTUBE',
    status: 'PENDING_CHANNEL_SETUP',
    channel_name: 'ElevenID LLC',
    channel_id: null,
    channel_handle: null,
    channel_url: null,
    playlist_id: null,
    playlist_url: null,
    privacy_enhanced_embeds: true,
    verified_at: null,
  },
  scenarios: [scenario],
};

const publicSchema = JSON.parse(readFileSync('../deploy-config/schemas/stack-demo-manifest.schema.json', 'utf8'));
const validateWalletSchema = new Ajv2020({ validateFormats: false }).compile({
  ...publicSchema.$defs.scenario.properties.wallets,
  $defs: { stringList: publicSchema.$defs.stringList },
});
const historicalWallet = JSON.parse(readFileSync('public/demos/manifests/2026.07.0.json', 'utf8'))
  .scenarios.find((item) => item.slug === 'membership-badge-login').wallets[0];
const androidWallet = {
  ...historicalWallet,
  implementation: 'SpruceID Showcase Wallet',
  vendor: 'SpruceID',
  deployment_mode: 'ANDROID_EMULATOR',
  classification: 'INDEPENDENT',
  lane_id: 'spruceid-same-device-happy',
  evidence_sha256: 'a'.repeat(64),
};

afterEach(() => {
  vi.restoreAllMocks();
  Reflect.deleteProperty(window, '__ELEVENID_PRERENDER__');
});

describe('demoManifestService', () => {
  it('keeps the bundled wallet schema identical to the publication contract', () => {
    expect(compiledWalletSchema).toEqual({
      ...publicSchema.$defs.scenario.properties.wallets.items,
      $defs: { stringList: publicSchema.$defs.stringList },
    });
  });

  it('generates manifests in a UI-only image context and detects a stale wallet projection in a source checkout', () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), 'demo-wallet-schema-'));
    const uiRoot = path.join(directory, 'ui');
    const projection = path.join(uiRoot, 'src/generated/demoWalletSchema.generated.json');
    try {
      mkdirSync(path.join(uiRoot, 'scripts'), { recursive: true });
      mkdirSync(path.dirname(projection), { recursive: true });
      for (const filename of ['generate-demo-manifest-module.mjs', 'generated-text.mjs']) {
        copyFileSync(`scripts/${filename}`, path.join(uiRoot, 'scripts', filename));
      }
      cpSync('public/demos/manifests', path.join(uiRoot, 'public/demos/manifests'), { recursive: true });
      copyFileSync('src/generated/demoWalletSchema.generated.json', projection);
      const generate = (...args: string[]) => spawnSync(process.execPath, ['scripts/generate-demo-manifest-module.mjs', ...args], {
        cwd: uiRoot, encoding: 'utf8',
      });
      const isolated = generate();
      expect(isolated.status, isolated.stderr).toBe(0);
      expect(JSON.parse(readFileSync(projection, 'utf8'))).toEqual(compiledWalletSchema);

      // A full source checkout must reject drift from the canonical schema.
      const schemaDirectory = path.join(directory, 'deploy-config/schemas');
      mkdirSync(schemaDirectory, { recursive: true });
      copyFileSync('../deploy-config/schemas/stack-demo-manifest.schema.json', path.join(schemaDirectory, 'stack-demo-manifest.schema.json'));
      writeFileSync(projection, '{}\n');
      const stale = generate('--check');
      expect(stale.status).not.toBe(0);
      expect(stale.stderr).toContain('Generated demo wallet schema is stale');
      const regenerated = generate();
      expect(regenerated.status, regenerated.stderr).toBe(0);
      expect(JSON.parse(readFileSync(projection, 'utf8'))).toEqual(compiledWalletSchema);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each([
    ['historical wallet without Android metadata', [historicalWallet], true],
    ['separate Android happy and cancellation lanes', [androidWallet, { ...androidWallet, lane_id: 'spruceid-same-device-cancel', result: 'FAIL', evidence_sha256: 'b'.repeat(64) }], true],
    ['private protocol telemetry', [{ ...androidWallet, protocol_assertions: [] }], false],
    ['unprojected path metadata', [{ ...androidWallet, path: 'HOLDER_CANCEL' }], false],
    ['malformed lane identity', [{ ...androidWallet, lane_id: 'SpruceID same device' }], false],
    ['uppercase evidence digest', [{ ...androidWallet, evidence_sha256: 'A'.repeat(64) }], false],
    ['null evidence digest', [{ ...androidWallet, evidence_sha256: null }], false],
    ['malformed rendered classification', [{ ...androidWallet, classification: null }], false],
    ['missing wallet array', undefined, false],
    ['null wallet row', [null], false],
  ])('matches the actual strict public wallet schema for %s', (_label, wallets, accepted) => {
    expect(validateWalletSchema(wallets)).toBe(accepted);
    const validate = () => validateDemoManifest({ ...manifest, scenarios: [{ ...scenario, wallets }] });
    if (accepted) expect(validate).not.toThrow();
    else expect(validate).toThrow(DemoManifestError);
  });

  it('orders immutable ElevenID LLC versions independently from MIP versions', () => {
    expect(compareStackVersions('2026.07.1', '2026.07.0')).toBeGreaterThan(0);
    expect(compareStackVersions('2026.08.0', '2026.07.9')).toBeGreaterThan(0);
  });

  it('loads and sorts the public release index', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      schema_version: 2,
      latest_approved_stack_version: '2026.07.1',
      releases: [
        { stack_version: '2026.07.0', release_name: 'Credential Lifecycle Foundation', mip_version: '0.3.1', publication_state: 'DRAFT', coverage_state: 'PARTIAL' },
        { stack_version: '2026.07.1', release_name: 'Credential Lifecycle Refinement', mip_version: '0.3.1', publication_state: 'PUBLIC', coverage_state: 'PARTIAL' },
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

  it('accepts the public HTTPS webhook protocol used by external integrations', () => {
    expect(() => validateDemoManifest({
      ...manifest,
      scenarios: [{ ...scenario, protocols: ['https-webhooks'] }],
    })).not.toThrow();
  });

  it('rejects a published video before the ElevenID LLC channel and release playlist are verified', () => {
    expect(() => validateDemoManifest({
      ...manifest,
      scenarios: [{ ...scenario, state: 'YOUTUBE_UNLISTED', youtube_id: 'abcdefghijk' }],
    })).toThrow('verified ElevenID LLC YouTube channel');
  });

  it('rejects public media without release-bound hashes and automated evidence', () => {
    const configured = {
      ...manifest,
      video_distribution: {
        ...manifest.video_distribution,
        status: 'CONFIGURED',
        channel_id: `UC${'a'.repeat(22)}`,
        channel_handle: '@elevenidllc',
        channel_url: 'https://www.youtube.com/@elevenidllc',
        playlist_id: `PL${'b'.repeat(24)}`,
        playlist_url: `https://www.youtube.com/playlist?list=PL${'b'.repeat(24)}`,
        verified_at: '2026-07-13T12:00:00Z',
      },
      scenarios: [{ ...scenario, state: 'YOUTUBE_UNLISTED', youtube_id: 'abcdefghijk' }],
    };
    expect(() => validateDemoManifest(configured)).toThrow('release-bound media evidence');
  });

  it('accepts only an explicit transient smoke candidate without a final smoke hash', () => {
    const candidate = JSON.parse(readFileSync('public/demos/manifests/2026.07.0.json', 'utf8'));
    const publishedAt = '2026-07-15T00:00:00Z';
    const membership = candidate.scenarios.find((item) => item.slug === 'membership-badge-login');
    membership.state = 'PUBLIC';
    membership.youtube_id = 'abcdefghijk';
    membership.published_at = publishedAt;
    membership.media_evidence = {
      video_sha256: '1'.repeat(64),
      captions_sha256: '2'.repeat(64),
      thumbnail_sha256: '3'.repeat(64),
      privacy_scan_sha256: '4'.repeat(64),
      publication_config_sha256: '5'.repeat(64),
      youtube_uploaded_at: publishedAt,
    };
    membership.limitations = ['First-party control evidence.'];
    membership.publication_attestation = {
      kind: 'AUTOMATED',
      smoke_pending: true,
      pipeline_revision: 'a'.repeat(40),
      published_at: publishedAt,
      checks: ['accessibility', 'captions', 'evidence', 'links', 'playback', 'privacy', 'thumbnail', 'transcript'],
      verification_report_sha256: '6'.repeat(64),
      result_sha256: '7'.repeat(64),
      youtube_privacy_status: 'public',
    };

    expect(() => validateDemoManifest(candidate)).not.toThrow();
    membership.publication_attestation.smoke_pending = false;
    expect(() => validateDemoManifest(candidate)).toThrow('invalid public smoke report hash');
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

  it('loads deployed evidence in ordinary headless browsers and reports HTTP failures', async () => {
    vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0 HeadlessChrome/155.0.0.0');
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('', { status: 503 }));

    await expect(loadDemoIndex()).rejects.toThrow('(503)');
    await expect(loadDemoManifest('2026.08.0')).rejects.toThrow('(503)');
    expect(fetchSpy.mock.calls.map(([url]) => url)).toEqual([
      '/demos/manifests/index.json',
      '/demos/manifests/2026.08.0.json',
    ]);
  });

  it('uses compiled evidence only when the build renderer explicitly requests it', async () => {
    vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue('Mozilla/5.0 Chrome/155.0.0.0');
    Object.defineProperty(window, '__ELEVENID_PRERENDER__', {
      configurable: true,
      value: { demoManifests: true },
    });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('No manifest server in this build renderer'));
    const expectedIndex = JSON.parse(readFileSync('public/demos/manifests/index.json', 'utf8'));

    const loadedIndex = await loadDemoIndex();
    const loadedManifest = await loadDemoManifest(loadedIndex.latest_available_stack_version);

    expect(loadedIndex).toEqual(validateDemoIndex(expectedIndex));
    expect(loadedManifest.stack_version).toBe(expectedIndex.latest_available_stack_version);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('rejects a latest-available pointer that is absent from the release index', () => {
    const candidate = JSON.parse(readFileSync('public/demos/manifests/index.json', 'utf8'));
    candidate.latest_available_stack_version = '2026.99.0';

    expect(() => validateDemoIndex(candidate)).toThrow(DemoManifestError);
  });

  it('rejects an index with no available or approved catalog entry', () => {
    const candidate = JSON.parse(readFileSync('public/demos/manifests/index.json', 'utf8'));
    delete candidate.latest_available_stack_version;

    expect(() => validateDemoIndex(candidate)).toThrow(DemoManifestError);
  });

  it.each([undefined, null, {}, [null], [{ result: 42 }]])(
    'rejects malformed draft assertions before they can crash the catalog: %j',
    (assertions) => {
      const candidate = JSON.parse(readFileSync('public/demos/manifests/2026.08.0.json', 'utf8'));
      candidate.scenarios[0].assertions = assertions;

      expect(() => validateDemoManifest(candidate)).toThrow(DemoManifestError);
    },
  );
});
