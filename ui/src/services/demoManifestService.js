import { DEMO_INDEX, DEMO_MANIFESTS } from '../generated/demoManifests.generated';

const MANIFEST_ROOT = '/demos/manifests';
const STACK_VERSION_PATTERN = /^\d{4}\.\d{2}\.\d+$/;
const MIP_VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
const YOUTUBE_CHANNEL_ID_PATTERN = /^UC[A-Za-z0-9_-]{22}$/;
const YOUTUBE_HANDLE_PATTERN = /^@[A-Za-z0-9._-]{3,30}$/;
const YOUTUBE_PLAYLIST_ID_PATTERN = /^[A-Za-z0-9_-]{10,64}$/;
const FINAL_PROTOCOLS = new Set([
  'openid4vci-1.0',
  'openid4vp-1.0',
  'dcql-1.0',
  'sd-jwt-vc',
  'open-badges-3.0',
  'lti-1.3',
]);

export class DemoManifestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DemoManifestError';
  }
}

function assert(condition, message) {
  if (!condition) throw new DemoManifestError(message);
}

async function fetchJson(url, signal) {
  const response = await fetch(url, {
    headers: { Accept: 'application/json' },
    signal,
  });
  if (!response.ok) {
    throw new DemoManifestError(`Demo evidence could not be loaded (${response.status}).`);
  }
  try {
    return await response.json();
  } catch {
    throw new DemoManifestError('Demo evidence returned malformed JSON.');
  }
}

function isHeadlessPrerender() {
  return typeof navigator !== 'undefined' && /HeadlessChrome/i.test(navigator.userAgent || '');
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function compareStackVersions(left, right) {
  const leftParts = left.split('.').map(Number);
  const rightParts = right.split('.').map(Number);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const difference = (leftParts[index] || 0) - (rightParts[index] || 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

export function validateDemoIndex(index) {
  assert(index && index.schema_version === 1, 'Unsupported demo index contract.');
  assert(Array.isArray(index.releases) && index.releases.length > 0, 'No ElevenID LLC releases are available.');
  const versions = new Set();
  index.releases.forEach((release) => {
    assert(STACK_VERSION_PATTERN.test(release.stack_version || ''), 'An ElevenID LLC release has an invalid version.');
    assert(typeof release.release_name === 'string' && release.release_name.trim().length >= 3, `${release.stack_version} needs a release name.`);
    assert(MIP_VERSION_PATTERN.test(release.mip_version || ''), `${release.stack_version} has an invalid MIP version.`);
    assert(!versions.has(release.stack_version), `${release.stack_version} is duplicated.`);
    versions.add(release.stack_version);
  });
  if (index.latest_approved_stack_version) {
    assert(versions.has(index.latest_approved_stack_version), 'The latest approved ElevenID LLC release is missing.');
  }
  return {
    ...index,
    releases: [...index.releases].sort((a, b) => compareStackVersions(b.stack_version, a.stack_version)),
  };
}

export function validateDemoManifest(manifest) {
  assert(manifest && manifest.schema_version === 1, 'Unsupported demo manifest contract.');
  assert(STACK_VERSION_PATTERN.test(manifest.stack_version || ''), 'Invalid ElevenID LLC version.');
  assert(typeof manifest.release_name === 'string' && manifest.release_name.trim().length >= 3, 'This ElevenID LLC release needs a descriptive name.');
  assert(MIP_VERSION_PATTERN.test(manifest.mip_version || ''), 'Invalid MIP version metadata.');
  const distribution = manifest.video_distribution;
  assert(distribution?.provider === 'YOUTUBE', 'This release needs a YouTube distribution binding.');
  assert(distribution.channel_name === 'ElevenID LLC', 'YouTube distribution must use the ElevenID LLC channel.');
  assert(distribution.privacy_enhanced_embeds === true, 'Privacy-enhanced YouTube embeds are required.');
  assert(['PENDING_CHANNEL_SETUP', 'CONFIGURED'].includes(distribution.status), 'Invalid YouTube distribution status.');
  if (distribution.status === 'CONFIGURED') {
    assert(YOUTUBE_CHANNEL_ID_PATTERN.test(distribution.channel_id || ''), 'Invalid ElevenID LLC YouTube channel ID.');
    assert(!distribution.channel_handle || YOUTUBE_HANDLE_PATTERN.test(distribution.channel_handle), 'Invalid ElevenID LLC YouTube handle.');
    const channelUrls = new Set([`https://www.youtube.com/channel/${distribution.channel_id}`]);
    if (distribution.channel_handle) channelUrls.add(`https://www.youtube.com/${distribution.channel_handle}`);
    assert(channelUrls.has(distribution.channel_url), 'The YouTube channel URL does not match its identity.');
    assert(YOUTUBE_PLAYLIST_ID_PATTERN.test(distribution.playlist_id || ''), 'Invalid release playlist ID.');
    assert(distribution.playlist_url === `https://www.youtube.com/playlist?list=${distribution.playlist_id}`, 'The release playlist URL does not match its identity.');
    assert(Boolean(distribution.verified_at), 'The YouTube distribution binding has not been verified.');
  } else {
    ['channel_id', 'channel_handle', 'channel_url', 'playlist_id', 'playlist_url', 'verified_at'].forEach((field) => {
      assert(distribution[field] === null, `Pending YouTube distribution cannot publish ${field}.`);
    });
  }
  assert(Array.isArray(manifest.scenarios) && manifest.scenarios.length > 0, 'This release has no demo scenarios.');
  const slugs = new Set();
  manifest.scenarios.forEach((scenario) => {
    assert(scenario.mip_version === manifest.mip_version, `${scenario.slug}: MIP metadata does not match its ElevenID LLC release.`);
    assert(!slugs.has(scenario.slug), `${scenario.slug}: duplicate scenario.`);
    slugs.add(scenario.slug);
    assert(Array.isArray(scenario.protocols) && scenario.protocols.length > 0, `${scenario.slug}: protocols are missing.`);
    scenario.protocols.forEach((protocol) => {
      assert(FINAL_PROTOCOLS.has(protocol), `${scenario.slug}: unsupported protocol ${protocol}.`);
    });
    assert(
      scenario.poster?.src?.startsWith(`/images/demos/${manifest.stack_version}/`),
      `${scenario.slug}: poster is not bound to this ElevenID LLC release.`,
    );
    if (['YOUTUBE_UNLISTED', 'PUBLIC'].includes(scenario.state)) {
      assert(/^[A-Za-z0-9_-]{11}$/.test(scenario.youtube_id || ''), `${scenario.slug}: published video is missing.`);
      assert(distribution.status === 'CONFIGURED', `${scenario.slug}: a verified ElevenID LLC YouTube channel and release playlist are required.`);
    }
  });
  return manifest;
}

export async function loadDemoIndex({ signal } = {}) {
  if (isHeadlessPrerender()) return validateDemoIndex(clone(DEMO_INDEX));
  return validateDemoIndex(await fetchJson(`${MANIFEST_ROOT}/index.json`, signal));
}

export async function loadDemoManifest(stackVersion, { signal } = {}) {
  assert(STACK_VERSION_PATTERN.test(stackVersion || ''), 'Invalid ElevenID LLC version.');
  const source = isHeadlessPrerender()
    ? clone(DEMO_MANIFESTS[stackVersion])
    : await fetchJson(`${MANIFEST_ROOT}/${stackVersion}.json`, signal);
  assert(source, `ElevenID LLC v${stackVersion} does not have a published manifest.`);
  const manifest = validateDemoManifest(source);
  assert(manifest.stack_version === stackVersion, 'The requested ElevenID LLC release does not match the manifest.');
  return manifest;
}

export function findDemoScenario(manifest, slug) {
  return manifest.scenarios.find((scenario) => scenario.slug === slug) || null;
}
