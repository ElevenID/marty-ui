import { DEMO_INDEX, DEMO_MANIFESTS } from '../generated/demoManifests.generated';

const MANIFEST_ROOT = '/demos/manifests';
const STACK_VERSION_PATTERN = /^\d{4}\.\d{2}\.\d+$/;
const MIP_VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
const YOUTUBE_CHANNEL_ID_PATTERN = /^UC[A-Za-z0-9_-]{22}$/;
const YOUTUBE_HANDLE_PATTERN = /^@[A-Za-z0-9._-]{3,30}$/;
const YOUTUBE_PLAYLIST_ID_PATTERN = /^[A-Za-z0-9_-]{10,64}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const ISO_DATE_TIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;
const PENDING_PUBLICATION_LANGUAGE = /\b(awaiting|must pass before|not completed|not run|pending)\b/i;
const SCENARIO_PUBLICATION_CHECKS = new Set([
  'accessibility', 'captions', 'evidence', 'links', 'playback', 'privacy', 'thumbnail', 'transcript',
]);
const RELEASE_PUBLICATION_CHECKS = new Set([
  'accessibility', 'canonical-urls', 'metadata', 'navigation', 'playback', 'privacy',
  'responsive-layouts', 'version-selection',
]);
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

function validatePublicationAttestation(attestation, expectedChecks, publishedAt, label) {
  assert(attestation && typeof attestation === 'object', `${label} requires automated publication evidence.`);
  assert(attestation.kind === 'AUTOMATED', `${label} publication must be automated.`);
  assert(/^[a-f0-9]{40}$/.test(attestation.pipeline_revision || ''), `${label} has an invalid pipeline revision.`);
  assert(SHA256_PATTERN.test(attestation.result_sha256 || ''), `${label} has an invalid publication result hash.`);
  assert(SHA256_PATTERN.test(attestation.verification_report_sha256 || ''), `${label} has an invalid verification report hash.`);
  assert(SHA256_PATTERN.test(attestation.smoke_report_sha256 || ''), `${label} has an invalid public smoke report hash.`);
  assert(attestation.youtube_privacy_status === 'public', `${label} YouTube video is not public.`);
  assert(ISO_DATE_TIME_PATTERN.test(attestation.published_at || ''), `${label} has an invalid publication time.`);
  assert(attestation.published_at === publishedAt, `${label} attestation time does not match publication.`);
  assert(Array.isArray(attestation.checks), `${label} publication checks are missing.`);
  const checks = new Set(attestation.checks);
  assert(
    checks.size === attestation.checks.length
      && checks.size === expectedChecks.size
      && [...expectedChecks].every((check) => checks.has(check)),
    `${label} automated checks are incomplete.`,
  );
}

function validateMediaEvidence(evidence, label) {
  assert(evidence && typeof evidence === 'object', `${label} requires release-bound media evidence.`);
  [
    'video_sha256',
    'captions_sha256',
    'thumbnail_sha256',
    'privacy_scan_sha256',
    'publication_config_sha256',
  ].forEach((field) => assert(SHA256_PATTERN.test(evidence[field] || ''), `${label} has invalid ${field}.`));
  assert(ISO_DATE_TIME_PATTERN.test(evidence.youtube_uploaded_at || ''), `${label} has an invalid YouTube upload time.`);
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
  assert(index && index.schema_version === 2, 'Unsupported demo index contract.');
  assert(Array.isArray(index.releases) && index.releases.length > 0, 'No ElevenID LLC releases are available.');
  const versions = new Set();
  index.releases.forEach((release) => {
    assert(STACK_VERSION_PATTERN.test(release.stack_version || ''), 'An ElevenID LLC release has an invalid version.');
    assert(typeof release.release_name === 'string' && release.release_name.trim().length >= 3, `${release.stack_version} needs a release name.`);
    assert(MIP_VERSION_PATTERN.test(release.mip_version || ''), `${release.stack_version} has an invalid MIP version.`);
    assert(['DRAFT', 'PUBLIC', 'SUPERSEDED'].includes(release.publication_state), `${release.stack_version} has an invalid publication state.`);
    assert(['PARTIAL', 'COMPLETE', 'SUPERSEDED'].includes(release.coverage_state), `${release.stack_version} has an invalid coverage state.`);
    assert(!versions.has(release.stack_version), `${release.stack_version} is duplicated.`);
    versions.add(release.stack_version);
  });
  if (index.latest_approved_stack_version) {
    assert(versions.has(index.latest_approved_stack_version), 'The latest approved ElevenID LLC release is missing.');
    const latest = index.releases.find((release) => release.stack_version === index.latest_approved_stack_version);
    assert(latest.publication_state === 'PUBLIC', 'The latest approved ElevenID LLC release is not public.');
  }
  return {
    ...index,
    releases: [...index.releases].sort((a, b) => compareStackVersions(b.stack_version, a.stack_version)),
  };
}

export function validateDemoManifest(manifest) {
  assert(manifest && manifest.schema_version === 2, 'Unsupported demo manifest contract.');
  assert(STACK_VERSION_PATTERN.test(manifest.stack_version || ''), 'Invalid ElevenID LLC version.');
  assert(typeof manifest.release_name === 'string' && manifest.release_name.trim().length >= 3, 'This ElevenID LLC release needs a descriptive name.');
  assert(MIP_VERSION_PATTERN.test(manifest.mip_version || ''), 'Invalid MIP version metadata.');
  assert(['DRAFT', 'PUBLIC', 'SUPERSEDED'].includes(manifest.publication_state), 'Invalid release publication state.');
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
    assert(['DRAFT', 'VALIDATED', 'YOUTUBE_UNLISTED', 'PUBLIC', 'SUPERSEDED'].includes(scenario.state), `${scenario.slug}: invalid publication state.`);
    assert(
      ['FIRST_PARTY_CONTROL', 'INDEPENDENT_WALLET'].includes(scenario.recording_classification),
      `${scenario.slug}: invalid recording classification.`,
    );
    assert(Array.isArray(scenario.revision_history), `${scenario.slug}: revision history is missing.`);
    const priorRevisions = new Set();
    scenario.revision_history.forEach((revision) => {
      assert(Number.isInteger(revision.scenario_revision) && revision.scenario_revision > 0, `${scenario.slug}: invalid prior revision.`);
      assert(revision.scenario_revision < scenario.scenario_revision, `${scenario.slug}: prior revision must precede the current revision.`);
      assert(!priorRevisions.has(revision.scenario_revision), `${scenario.slug}: duplicate prior revision.`);
      assert(['FIRST_PARTY_CONTROL', 'INDEPENDENT_WALLET'].includes(revision.recording_classification), `${scenario.slug}: prior revision classification is invalid.`);
      priorRevisions.add(revision.scenario_revision);
    });
    assert(
      scenario.poster?.src?.startsWith(`/images/demos/${manifest.stack_version}/`),
      `${scenario.slug}: poster is not bound to this ElevenID LLC release.`,
    );
    if (['YOUTUBE_UNLISTED', 'PUBLIC'].includes(scenario.state)) {
      assert(/^[A-Za-z0-9_-]{11}$/.test(scenario.youtube_id || ''), `${scenario.slug}: published video is missing.`);
      assert(distribution.status === 'CONFIGURED', `${scenario.slug}: a verified ElevenID LLC YouTube channel and release playlist are required.`);
      validateMediaEvidence(scenario.media_evidence, scenario.slug);
    } else if (scenario.state !== 'SUPERSEDED') {
      assert(scenario.media_evidence === null, `${scenario.slug}: unpublished scenario cannot retain media evidence.`);
    }
    if (scenario.state === 'PUBLIC') {
      assert(ISO_DATE_TIME_PATTERN.test(scenario.published_at || ''), `${scenario.slug}: public timestamp is invalid.`);
      validatePublicationAttestation(scenario.publication_attestation, SCENARIO_PUBLICATION_CHECKS, scenario.published_at, scenario.slug);
      assert(Array.isArray(scenario.assertions) && scenario.assertions.length > 0, `${scenario.slug}: public assertions are missing.`);
      scenario.assertions.forEach((item) => {
        assert(item.result === 'PASS' && SHA256_PATTERN.test(item.evidence_sha256 || ''), `${scenario.slug}: every public assertion must pass with evidence.`);
      });
      assert(
        !(scenario.limitations || []).some((item) => PENDING_PUBLICATION_LANGUAGE.test(item)),
        `${scenario.slug}: unresolved publication language is not public evidence.`,
      );
    } else if (scenario.state !== 'SUPERSEDED') {
      assert(scenario.published_at === null, `${scenario.slug}: non-public scenario cannot retain published_at.`);
      assert(scenario.publication_attestation === null, `${scenario.slug}: non-public scenario cannot retain publication attestation.`);
    }
  });
  if (manifest.publication_state === 'PUBLIC') {
    assert(manifest.release_ready === true && manifest.public_demo_ready === true, 'Public release evidence has not passed its release gates.');
    assert(ISO_DATE_TIME_PATTERN.test(manifest.published_at || ''), 'Public release timestamp is invalid.');
    validatePublicationAttestation(manifest.publication_attestation, RELEASE_PUBLICATION_CHECKS, manifest.published_at, 'Public release');
    assert(manifest.scenarios.some((scenario) => scenario.state === 'PUBLIC'), 'Public release has no public scenarios.');
  } else if (manifest.publication_state !== 'SUPERSEDED') {
    assert(manifest.published_at === null, 'Non-public release cannot retain published_at.');
    assert(manifest.publication_attestation === null, 'Non-public release cannot retain publication attestation.');
  }
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
