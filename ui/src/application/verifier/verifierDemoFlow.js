/**
 * Pure helpers for the verifier demo experience.
 */

export function createVerifierDemoMockPresentation({
  issuanceDate = new Date().toISOString(),
} = {}) {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    verifiableCredential: [
      {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'mDL'],
        issuer: 'did:example:issuer',
        issuanceDate,
        credentialSubject: {
          given_name: 'Jane',
          family_name: 'Doe',
          birth_date: '1990-01-01',
          document_number: 'DL123456789',
          age_over_18: true,
          age_over_21: true,
        },
      },
    ],
  };
}

export function serializeVerifierDemoPresentation(data) {
  return JSON.stringify(data, null, 2);
}

export function resolveVerifierDemoRequest({
  presentationData = '',
  expectedAudience = 'demo_verifier',
} = {}) {
  const trimmedPresentationData = presentationData.trim();

  if (!trimmedPresentationData) {
    throw new Error('Please scan a QR code or enter presentation data first');
  }

  if (!trimmedPresentationData.startsWith('{')) {
    return {
      requestType: 'presentation',
      payload: {
        presentation_jwt: trimmedPresentationData,
        expected_audience: expectedAudience,
        expected_nonce: null,
      },
    };
  }

  const parsed = JSON.parse(trimmedPresentationData);

  if (parsed.presentation_jwt) {
    return {
      requestType: 'presentation',
      payload: {
        presentation_jwt: parsed.presentation_jwt,
        expected_audience: expectedAudience,
        expected_nonce: null,
      },
    };
  }

  if (parsed.verifiableCredential && parsed.verifiableCredential.length > 0) {
    return {
      requestType: 'credential',
      payload: {
        credential_jwt: typeof parsed.verifiableCredential[0] === 'string'
          ? parsed.verifiableCredential[0]
          : JSON.stringify(parsed.verifiableCredential[0]),
        expected_issuer: null,
      },
    };
  }

  throw new Error('Invalid presentation format');
}

export function createVerifierDemoVerificationResult(result = {}) {
  const claimCount = Object.keys(result.claims || {}).length;
  const isValid = Boolean(result.valid);

  return {
    success: isValid,
    verified: isValid,
    error: result.error,
    claims: result.claims,
    issuer: result.issuer || result.holder,
    presentation_summary: result.presentation_summary,
    checks: [
      {
        check_name: 'JWT Structure',
        passed: isValid,
        details: isValid ? 'Valid JWT format' : result.error,
      },
      {
        check_name: 'Signature',
        passed: isValid,
        details: isValid ? 'Signature verified' : 'Signature verification failed',
      },
      {
        check_name: 'Claims',
        passed: isValid && claimCount > 0,
        details: isValid ? `Found ${claimCount} claims` : 'No claims extracted',
      },
    ],
  };
}

export function createVerifierDemoVerificationError(message) {
  return {
    success: false,
    verified: false,
    error: `Verification failed: ${message}`,
    checks: [
      {
        check_name: 'Format Check',
        passed: false,
        details: message,
      },
    ],
  };
}