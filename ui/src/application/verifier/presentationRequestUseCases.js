import { getErrorMessage, post } from '../../services/api';
import {
  createVerifierPresentationRequestError,
  createVerifierPresentationRequestPayload,
  createVerifierPresentationVerificationError,
  createVerifierPresentationVerificationPayload,
  resolveVerifierPresentationRequest,
  resolveVerifierPresentationVerification,
} from './presentationRequestFlow';

async function defaultCreatePresentationRequest(payload) {
  return post('/api/verifier/request', payload);
}

async function defaultVerifyPresentationRequest(payload) {
  return post('/api/verifier/verify-presentation', payload);
}

export async function createPresentationRequest({
  selectedCredentialType,
  verifierName,
  createRequest = defaultCreatePresentationRequest,
} = {}) {
  try {
    const result = await createRequest(createVerifierPresentationRequestPayload({
      selectedCredentialType,
      verifierName,
    }));

    return resolveVerifierPresentationRequest(result);
  } catch (error) {
    return createVerifierPresentationRequestError(getErrorMessage(error) || 'Failed to create request');
  }
}

export async function verifyPresentationRequest({
  presentationData,
  customNonce,
  requestAudience,
  verifierName,
  verifyRequest = defaultVerifyPresentationRequest,
} = {}) {
  try {
    const result = await verifyRequest(createVerifierPresentationVerificationPayload({
      presentationData,
      customNonce,
      requestAudience,
      verifierName,
    }));

    return resolveVerifierPresentationVerification(result);
  } catch (error) {
    return createVerifierPresentationVerificationError(getErrorMessage(error) || 'Verification failed');
  }
}