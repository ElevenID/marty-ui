const CROCKFORD_BASE32_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

const OFFICIAL_REFERENCE_PREFIXES = {
  account: 'ACT',
  applicant: 'APR',
  application: 'APP',
  credential: 'CRD',
  deployment: 'DPL',
  event: 'AUD',
  flow: 'FLW',
  organization: 'ORG',
  payment: 'PMT',
  policy: 'PLC',
  profile: 'PRF',
  record: 'REF',
  template: 'TPL',
  trust: 'TRU',
};

const OFFICIAL_REFERENCE_PREFIX_PATTERN = Object.values(OFFICIAL_REFERENCE_PREFIXES).join('|');
const OFFICIAL_REFERENCE_PATTERN = new RegExp(
  `^(?:${OFFICIAL_REFERENCE_PREFIX_PATTERN})(?:-[A-Z0-9]{4,}){2,4}$`
);
const IDENTIFIER_KEY_PATTERN = /(^id$|(^|_)(id|identifier|reference|ref)$|Id$|_id$|_identifier$|_reference$|reference_number$)/;

function normalizeReferenceKind(kind = 'record') {
  return OFFICIAL_REFERENCE_PREFIXES[kind] ? kind : 'record';
}

function fnv1a64(input) {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;

  for (const char of String(input)) {
    hash ^= BigInt(char.codePointAt(0) || 0);
    hash = BigInt.asUintN(64, hash * prime);
  }

  return hash;
}

function encodeBase32(value, minLength = 12) {
  let current = value;
  let encoded = '';

  if (current === 0n) {
    encoded = CROCKFORD_BASE32_ALPHABET[0];
  }

  while (current > 0n) {
    encoded = CROCKFORD_BASE32_ALPHABET[Number(current % 32n)] + encoded;
    current /= 32n;
  }

  return encoded.padStart(minLength, CROCKFORD_BASE32_ALPHABET[0]);
}

export function looksLikeOfficialReference(value) {
  return typeof value === 'string' && OFFICIAL_REFERENCE_PATTERN.test(value.trim().toUpperCase());
}

export function inferOfficialReferenceKind(key = '') {
  const normalizedKey = String(key || '').toLowerCase();

  if (normalizedKey.includes('organization')) return 'organization';
  if (normalizedKey.includes('application')) return 'application';
  if (normalizedKey.includes('applicant')) return 'applicant';
  if (normalizedKey.includes('credential')) return 'credential';
  if (normalizedKey.includes('template')) return 'template';
  if (normalizedKey.includes('payment')) return 'payment';
  if (normalizedKey.includes('policy')) return 'policy';
  if (normalizedKey.includes('deployment')) return 'deployment';
  if (normalizedKey.includes('flow')) return 'flow';
  if (normalizedKey.includes('trust')) return 'trust';
  if (normalizedKey.includes('profile')) return 'profile';
  if (normalizedKey.includes('event') || normalizedKey.includes('audit')) return 'event';
  if (normalizedKey.includes('user') || normalizedKey.includes('account') || normalizedKey.includes('member')) return 'account';

  return 'record';
}

export function formatOfficialReference(value, kind = 'record') {
  if (value === null || value === undefined) {
    return '—';
  }

  const rawValue = String(value).trim();
  if (!rawValue) {
    return '—';
  }

  if (looksLikeOfficialReference(rawValue)) {
    return rawValue.toUpperCase();
  }

  const normalizedKind = normalizeReferenceKind(kind);
  const prefix = OFFICIAL_REFERENCE_PREFIXES[normalizedKind];
  const encoded = encodeBase32(fnv1a64(`${prefix}:${rawValue}`), 12).slice(-12);

  return `${prefix}-${encoded.slice(0, 4)}-${encoded.slice(4, 8)}-${encoded.slice(8, 12)}`;
}

export function pickOfficialReference({ reference, rawId, kind = 'record', fallback = '—' } = {}) {
  if (reference) {
    return formatOfficialReference(reference, kind);
  }

  if (rawId) {
    return formatOfficialReference(rawId, kind);
  }

  return fallback;
}

export function formatStructuredIdentifiers(value, parentKey = '') {
  if (Array.isArray(value)) {
    return value.map((item) => formatStructuredIdentifiers(item, parentKey));
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, nestedValue]) => [
        key,
        formatStructuredIdentifiers(nestedValue, key),
      ])
    );
  }

  if (typeof value === 'string' && IDENTIFIER_KEY_PATTERN.test(parentKey)) {
    return formatOfficialReference(value, inferOfficialReferenceKind(parentKey));
  }

  return value;
}
