import { getErrorMessage, post } from '../../services/api';
import {
  createVerifierDemoVerificationError,
  createVerifierDemoVerificationResult,
  resolveVerifierDemoRequest,
} from './verifierDemoFlow';

async function defaultVerifyPresentation(payload) {
  return post('/api/verifier/verify-presentation', payload);
}

async function defaultVerifyCredential(payload) {
  return post('/api/verifier/verify', payload);
}

export async function verifyVerifierDemoPresentation({
  presentationData,
  expectedAudience = 'demo_verifier',
  verifyPresentation = defaultVerifyPresentation,
  verifyCredential = defaultVerifyCredential,
} = {}) {
  try {
    const request = resolveVerifierDemoRequest({
      presentationData,
      expectedAudience,
    });

    if (!request || !request.payload) {
      throw new Error('Invalid presentation format');
    }

    const result = request.requestType === 'credential'
      ? await verifyCredential(request.payload)
      : await verifyPresentation(request.payload);

    return createVerifierDemoVerificationResult(result);
  } catch (error) {
    return createVerifierDemoVerificationError(
      getErrorMessage(error) || error.message || 'Verification failed',
    );
  }
}