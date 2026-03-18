/**
 * Pure helpers for verifier presentation request workflows.
 */

export const PRESENTATION_REQUEST_CREDENTIAL_TYPES = [
  {
    value: 'mDL',
    label: 'Mobile Driving License (mDL)',
    attributes: ['given_name', 'family_name', 'birth_date', 'age_over_21', 'document_number'],
  },
  {
    value: 'VerifiableId',
    label: 'Verifiable ID',
    attributes: ['given_name', 'family_name', 'birth_date', 'nationality'],
  },
  {
    value: 'VerifiableDiploma',
    label: 'Verifiable Diploma',
    attributes: ['degree', 'institution', 'graduation_date'],
  },
  {
    value: 'ProofOfAge',
    label: 'Proof of Age',
    attributes: ['age_over_18', 'age_over_21'],
  },
];

export function getPresentationRequestAttributes(selectedCredentialType = 'mDL') {
  return PRESENTATION_REQUEST_CREDENTIAL_TYPES.find((type) => type.value === selectedCredentialType)?.attributes || [];
}

export function createVerifierPresentationRequestPayload({
  selectedCredentialType = 'mDL',
  verifierName = 'Demo Verifier',
} = {}) {
  return {
    requested_credentials: [selectedCredentialType],
    verifier_id: verifierName,
  };
}

export function createVerifierPresentationRequestError(message = 'Failed to create request') {
  return {
    error: message,
    requestId: null,
    requestUri: '',
    requestAudience: '',
    requestStatus: 'error',
  };
}

export function resolveVerifierPresentationRequest(data = {}) {
  return {
    error: null,
    requestId: data.request_id ?? null,
    requestUri: data.request_uri || '',
    requestAudience: data.audience || '',
    requestStatus: 'pending',
  };
}

export function createVerifierPresentationVerificationPayload({
  presentationData,
  customNonce = '',
  requestAudience = '',
  verifierName = 'Demo Verifier',
} = {}) {
  return {
    presentation_jwt: presentationData?.vp_jwt || presentationData,
    expected_nonce: customNonce || null,
    expected_audience: requestAudience || verifierName,
  };
}

export function createVerifierPresentationVerificationError(message = 'Verification failed') {
  return {
    error: message,
    requestStatus: 'error',
  };
}

export function resolveVerifierPresentationVerification(data = {}) {
  if (data.valid) {
    return {
      error: null,
      requestStatus: 'verified',
    };
  }

  return {
    error: data.error || 'Verification failed',
    requestStatus: 'error',
  };
}