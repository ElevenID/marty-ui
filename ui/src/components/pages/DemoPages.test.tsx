import { describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import {
  DemoCatalogPage,
  DemoLatestScenarioRedirect,
  DemoScenarioPage,
} from './DemoPages';

const { mockLoadIndex, mockLoadManifest } = vi.hoisted(() => ({
  mockLoadIndex: vi.fn(),
  mockLoadManifest: vi.fn(),
}));

vi.mock('../../services/demoManifestService', async () => {
  const actual = await vi.importActual<typeof import('../../services/demoManifestService')>('../../services/demoManifestService');
  return {
    ...actual,
    loadDemoIndex: (...args: unknown[]) => mockLoadIndex(...args),
    loadDemoManifest: (...args: unknown[]) => mockLoadManifest(...args),
  };
});

const scenarios = [
  {
    slug: 'membership-badge-login',
    title: 'Membership Badge and Login',
    summary: 'Receive a badge and return to the same account.',
    scenario_revision: 1,
    mip_version: '0.3.1',
    state: 'VALIDATED',
    audiences: ['Holder', 'Issuer'],
    capabilities: ['Credential login'],
    protocols: ['openid4vci-1.0', 'openid4vp-1.0', 'dcql-1.0', 'sd-jwt-vc', 'open-badges-3.0'],
    poster: { src: '/images/demos/2026.07.0/membership-badge-login.png', alt: 'Badge result' },
    youtube_id: null,
    media_evidence: null,
    transcript: { language: 'en', segments: [{ start_seconds: 0, speaker: 'Narrator', text: 'Receive the badge.' }] },
    chapters: [{ start_seconds: 0, title: 'Receive badge', role: 'Holder', mip_primitives: ['Issuance Flow'], standards: ['Open Badges 3.0'], documentation_links: [] }],
    wallets: [],
    assertions: [{ id: 'badge', label: 'Badge received', result: 'PASS', evidence_sha256: 'a'.repeat(64) }],
    limitations: ['YouTube publication pending.'],
    published_at: null,
    publication_approval: null,
  },
  {
    slug: 'organization-primitives',
    title: 'Organization and MIP Primitives',
    summary: 'Configure issuer and verifier primitives.',
    scenario_revision: 1,
    mip_version: '0.3.1',
    state: 'PUBLIC',
    audiences: ['Administrator', 'Developer'],
    capabilities: ['Organization setup'],
    protocols: ['openid4vci-1.0'],
    poster: { src: '/images/demos/2026.07.0/organization-primitives.png', alt: 'Organization setup' },
    youtube_id: 'abcdefghijk',
    media_evidence: {
      video_sha256: 'e'.repeat(64),
      captions_sha256: 'f'.repeat(64),
      thumbnail_sha256: '1'.repeat(64),
      privacy_scan_sha256: '2'.repeat(64),
      publication_config_sha256: '3'.repeat(64),
      youtube_uploaded_at: '2026-07-13T11:30:00Z',
    },
    transcript: { language: 'en', segments: [{ start_seconds: 0, speaker: 'Narrator', text: 'Create the organization.' }] },
    chapters: [{ start_seconds: 0, title: 'Create organization', role: 'Administrator', mip_primitives: ['Organization'], standards: ['OpenID4VCI 1.0'], documentation_links: [] }],
    wallets: [],
    assertions: [{ id: 'organization', label: 'Organization configured', result: 'PASS', evidence_sha256: 'b'.repeat(64) }],
    limitations: [],
    published_at: '2026-07-13T12:00:00Z',
    publication_approval: {
      approval_sha256: 'd'.repeat(64),
      reviewed_at: '2026-07-13T12:00:00Z',
      checks: ['accessibility', 'captions', 'evidence', 'links', 'playback', 'privacy', 'thumbnail', 'transcript'],
    },
  },
];

const manifest = {
  schema_version: 1,
  stack_version: '2026.07.0',
  release_name: 'Credential Lifecycle Foundation',
  mip_version: '0.3.1',
  publication_state: 'DRAFT',
  coverage_state: 'PARTIAL',
  release_ready: false,
  public_demo_ready: false,
  published_at: null,
  publication_approval: null,
  video_distribution: {
    provider: 'YOUTUBE',
    status: 'CONFIGURED',
    channel_name: 'ElevenID LLC',
    channel_id: `UC${'a'.repeat(22)}`,
    channel_handle: '@elevenidllc',
    channel_url: 'https://www.youtube.com/@elevenidllc',
    playlist_id: `PL${'b'.repeat(24)}`,
    playlist_url: `https://www.youtube.com/playlist?list=PL${'b'.repeat(24)}`,
    privacy_enhanced_embeds: true,
    verified_at: '2026-07-13T12:00:00Z',
  },
  deployment_release_marker: 'release-1',
  release_evidence: {
    recorded_at: '2026-07-13T12:00:00Z',
    displayed_offers_invalidated_at: '2026-07-13T12:00:00Z',
    artifacts: [{ label: 'Report', visibility: 'PROTECTED', sha256: 'c'.repeat(64) }],
  },
  component_revisions: [{ component: 'marty-ui' }],
  image_digests: [{ component: 'ui' }],
  release_differences: {
    previous_stack_version: '2026.05.0',
    ux: ['New demo pages'],
    services: [],
    wallets: [],
    integrations: [],
    operations: [],
  },
  scenarios,
};

const index = {
  schema_version: 1,
  latest_approved_stack_version: null,
  latest_available_stack_version: '2026.07.0',
  releases: [{ stack_version: '2026.07.0', release_name: 'Credential Lifecycle Foundation', mip_version: '0.3.1' }],
};

describe('DemoPages', () => {
  it('leads with the release name and identifies the ElevenID LLC platform version separately from MIP', async () => {
    mockLoadIndex.mockResolvedValue(index);
    mockLoadManifest.mockResolvedValue(manifest);

    const { user } = renderWithRouter(<DemoCatalogPage />);

    expect(await screen.findByRole('heading', { level: 1, name: 'Credential Lifecycle Foundation' })).toBeInTheDocument();
    expect(screen.getByText('ElevenID LLC Credential Platform')).toBeInTheDocument();
    expect(screen.getByText('Version v2026.07.0')).toBeInTheDocument();
    expect(screen.getByText('Implements MIP 0.3.1')).toBeInTheDocument();
    expect(screen.getByText('2 of 2')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Watch release playlist' })).toHaveAttribute(
      'href',
      `https://www.youtube.com/playlist?list=PL${'b'.repeat(24)}`,
    );

    await user.click(screen.getByRole('button', { name: 'Administrator' }));
    expect(screen.queryByText('Membership Badge and Login')).not.toBeInTheDocument();
    expect(screen.getByText('Organization and MIP Primitives')).toBeInTheDocument();
  });

  it('shows evidence and a publication fallback when YouTube is not ready', async () => {
    mockLoadManifest.mockResolvedValue(manifest);

    renderWithRouter(
      <Routes>
        <Route path="/demos/:stackVersion/:scenario" element={<DemoScenarioPage />} />
      </Routes>,
      { initialEntries: ['/demos/2026.07.0/membership-badge-login'] },
    );

    expect(await screen.findByRole('heading', { level: 1, name: 'Membership Badge and Login' })).toBeInTheDocument();
    expect(screen.getByText('Recording publication pending')).toBeInTheDocument();
    expect(screen.queryByTitle('Membership Badge and Login video')).not.toBeInTheDocument();
    expect(screen.getByText('Receive the badge.')).toBeInTheDocument();
  });

  it('does not contact YouTube until the viewer activates playback', async () => {
    mockLoadManifest.mockResolvedValue(manifest);
    const { user } = renderWithRouter(
      <Routes>
        <Route path="/demos/:stackVersion/:scenario" element={<DemoScenarioPage />} />
      </Routes>,
      { initialEntries: ['/demos/2026.07.0/organization-primitives'] },
    );

    expect(await screen.findByRole('button', { name: 'Load Organization and MIP Primitives from YouTube' })).toBeInTheDocument();
    expect(screen.queryByTitle('Organization and MIP Primitives video')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Load Organization and MIP Primitives from YouTube' }));
    expect(screen.getByTitle('Organization and MIP Primitives video')).toHaveAttribute('src', expect.stringContaining('youtube-nocookie.com'));
    expect(screen.getByText(/Approval sha256:/)).toHaveTextContent(`Approval sha256:${'d'.repeat(64)}`);
    expect(screen.getByText(/Video sha256:/)).toHaveTextContent(`Video sha256:${'e'.repeat(64)}`);
  });

  it('redirects latest scenario links only to an approved ElevenID LLC release', async () => {
    mockLoadIndex.mockResolvedValue({ ...index, latest_approved_stack_version: '2026.07.0' });

    renderWithRouter(
      <Routes>
        <Route path="/demos/latest/:scenario" element={<DemoLatestScenarioRedirect />} />
        <Route path="/demos/:stackVersion/:scenario" element={<div>Approved target</div>} />
      </Routes>,
      { initialEntries: ['/demos/latest/membership-badge-login'] },
    );

    await waitFor(() => expect(screen.getByText('Approved target')).toBeInTheDocument());
  });
});
