export const TRUST_PROFILE_SUPPORTED_FORMATS = [
  {
    value: 'jwt_vc',
    labelKey: 'wizards.trustProfile.basicsStep.formatOptions.jwt_vc',
    recommended: true,
  },
  {
    value: 'sd_jwt_vc',
    labelKey: 'wizards.trustProfile.basicsStep.formatOptions.sd_jwt_vc',
    recommended: true,
  },
  {
    value: 'mdoc',
    labelKey: 'wizards.trustProfile.basicsStep.formatOptions.mdoc',
    recommended: true,
  },
  {
    value: 'ldp_vc',
    labelKey: 'wizards.trustProfile.basicsStep.formatOptions.ldp_vc',
    recommended: false,
  },
];

export const TRUST_PROFILE_ALLOWED_ALGORITHMS = [
  { value: 'ES256', label: 'ES256 (ECDSA P-256)' },
  { value: 'ES384', label: 'ES384 (ECDSA P-384)' },
  { value: 'ES512', label: 'ES512 (ECDSA P-521)' },
  { value: 'EdDSA', label: 'EdDSA (Ed25519)' },
  { value: 'RS256', label: 'RS256 (RSA 2048+)' },
  { value: 'RS384', label: 'RS384 (RSA 2048+)' },
  { value: 'RS512', label: 'RS512 (RSA 2048+)' },
  { value: 'PS256', label: 'PS256 (RSA-PSS)' },
  { value: 'PS384', label: 'PS384 (RSA-PSS)' },
  { value: 'PS512', label: 'PS512 (RSA-PSS)' },
];

export const DEFAULT_CUSTOM_SUPPORTED_FORMATS = ['jwt_vc', 'sd_jwt_vc', 'mdoc'];
export const DEFAULT_CUSTOM_ALLOWED_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'EdDSA'];

export const TRUST_PROFILE_FRAMEWORK_FORMAT_PRESETS = {
  icao: ['mdoc'],
  aamva: ['mdoc'],
  eudi: ['sd_jwt_vc', 'mdoc'],
};

// Mirror the trust-profile service defaults for system-managed frameworks.
export const TRUST_PROFILE_FRAMEWORK_ALGORITHM_PRESETS = {
  icao: ['ES256', 'ES384', 'EdDSA'],
  aamva: ['ES256', 'ES384'],
  eudi: ['ES256', 'ES384', 'EdDSA'],
};

export function normalizeTrustProfileSupportedFormats(formats) {
  const safeFormats = Array.isArray(formats) ? formats : [];
  return TRUST_PROFILE_SUPPORTED_FORMATS
    .map((format) => format.value)
    .filter((value) => safeFormats.includes(value));
}

export function normalizeTrustProfileAllowedAlgorithms(algorithms) {
  const safeAlgorithms = Array.isArray(algorithms) ? algorithms : [];
  return TRUST_PROFILE_ALLOWED_ALGORITHMS
    .map((algorithm) => algorithm.value)
    .filter((value) => safeAlgorithms.includes(value));
}

export function isFrameworkFormatSelectionLocked(frameworkType) {
  return Boolean(frameworkType) && frameworkType !== 'custom';
}

export function isFrameworkAlgorithmSelectionLocked(frameworkType) {
  return isFrameworkFormatSelectionLocked(frameworkType);
}

export function getSupportedFormatsForFramework(frameworkType, currentFormats) {
  if (isFrameworkFormatSelectionLocked(frameworkType)) {
    return TRUST_PROFILE_FRAMEWORK_FORMAT_PRESETS[frameworkType] || DEFAULT_CUSTOM_SUPPORTED_FORMATS;
  }

  const normalizedCurrentFormats = normalizeTrustProfileSupportedFormats(currentFormats);
  return normalizedCurrentFormats.length > 0 ? normalizedCurrentFormats : DEFAULT_CUSTOM_SUPPORTED_FORMATS;
}

export function getAllowedAlgorithmsForFramework(frameworkType, currentAlgorithms) {
  if (isFrameworkAlgorithmSelectionLocked(frameworkType)) {
    return TRUST_PROFILE_FRAMEWORK_ALGORITHM_PRESETS[frameworkType] || DEFAULT_CUSTOM_ALLOWED_ALGORITHMS;
  }

  const normalizedCurrentAlgorithms = normalizeTrustProfileAllowedAlgorithms(currentAlgorithms);
  return normalizedCurrentAlgorithms.length > 0 ? normalizedCurrentAlgorithms : DEFAULT_CUSTOM_ALLOWED_ALGORITHMS;
}