import { DEMO_INDEX, DEMO_MANIFESTS } from '../generated/demoManifests.generated';

const MANIFEST_ROOT = '/demos/manifests';
const STACK_VERSION_PATTERN = /^\d{4}\.\d{2}\.\d+$/;
const MIP_VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
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
  assert(Array.isArray(index.releases) && index.releases.length > 0, 'No Stack releases are available.');
  const versions = new Set();
  index.releases.forEach((release) => {
    assert(STACK_VERSION_PATTERN.test(release.stack_version || ''), 'A Stack release has an invalid version.');
    assert(MIP_VERSION_PATTERN.test(release.mip_version || ''), `${release.stack_version} has an invalid MIP version.`);
    assert(!versions.has(release.stack_version), `${release.stack_version} is duplicated.`);
    versions.add(release.stack_version);
  });
  if (index.latest_approved_stack_version) {
    assert(versions.has(index.latest_approved_stack_version), 'The latest approved Stack release is missing.');
  }
  return {
    ...index,
    releases: [...index.releases].sort((a, b) => compareStackVersions(b.stack_version, a.stack_version)),
  };
}

export function validateDemoManifest(manifest) {
  assert(manifest && manifest.schema_version === 1, 'Unsupported demo manifest contract.');
  assert(STACK_VERSION_PATTERN.test(manifest.stack_version || ''), 'Invalid ElevenID Stack version.');
  assert(MIP_VERSION_PATTERN.test(manifest.mip_version || ''), 'Invalid MIP version metadata.');
  assert(Array.isArray(manifest.scenarios) && manifest.scenarios.length > 0, 'This release has no demo scenarios.');
  const slugs = new Set();
  manifest.scenarios.forEach((scenario) => {
    assert(scenario.mip_version === manifest.mip_version, `${scenario.slug}: MIP metadata does not match its Stack release.`);
    assert(!slugs.has(scenario.slug), `${scenario.slug}: duplicate scenario.`);
    slugs.add(scenario.slug);
    assert(Array.isArray(scenario.protocols) && scenario.protocols.length > 0, `${scenario.slug}: protocols are missing.`);
    scenario.protocols.forEach((protocol) => {
      assert(FINAL_PROTOCOLS.has(protocol), `${scenario.slug}: unsupported protocol ${protocol}.`);
    });
    assert(
      scenario.poster?.src?.startsWith(`/images/demos/${manifest.stack_version}/`),
      `${scenario.slug}: poster is not bound to this Stack release.`,
    );
    if (['YOUTUBE_UNLISTED', 'PUBLIC'].includes(scenario.state)) {
      assert(/^[A-Za-z0-9_-]{11}$/.test(scenario.youtube_id || ''), `${scenario.slug}: published video is missing.`);
    }
  });
  return manifest;
}

export async function loadDemoIndex({ signal } = {}) {
  if (isHeadlessPrerender()) return validateDemoIndex(clone(DEMO_INDEX));
  return validateDemoIndex(await fetchJson(`${MANIFEST_ROOT}/index.json`, signal));
}

export async function loadDemoManifest(stackVersion, { signal } = {}) {
  assert(STACK_VERSION_PATTERN.test(stackVersion || ''), 'Invalid ElevenID Stack version.');
  const source = isHeadlessPrerender()
    ? clone(DEMO_MANIFESTS[stackVersion])
    : await fetchJson(`${MANIFEST_ROOT}/${stackVersion}.json`, signal);
  assert(source, `Stack ${stackVersion} does not have a published manifest.`);
  const manifest = validateDemoManifest(source);
  assert(manifest.stack_version === stackVersion, 'The requested Stack release does not match the manifest.');
  return manifest;
}

export function findDemoScenario(manifest, slug) {
  return manifest.scenarios.find((scenario) => scenario.slug === slug) || null;
}
