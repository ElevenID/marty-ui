/**
 * Pure helpers for the Enhanced Verifier Demo.
 *
 * Four feature domains:
 *  1. Age verification (selective disclosure)
 *  2. Offline QR code verification
 *  3. Certificate lifecycle monitoring
 *  4. Policy-based selective disclosure
 */

// ── Age Verification ────────────────────────────────────────────────

export const AGE_VERIFICATION_USE_CASES = {
  alcohol_purchase: 'Alcohol Purchase (21+)',
  voting_registration: 'Voting Registration (18+)',
  senior_discount: 'Senior Discount (65+)',
  employment_eligibility: 'Employment Eligibility (18-65)',
};

export function buildAgeVerificationFlowBody({
  useCase,
  verifierId = 'demo_enhanced_verifier',
  useCaseLabels = AGE_VERIFICATION_USE_CASES,
}) {
  return {
    flow_type: 'age_verification',
    use_case: useCase,
    verifier_id: verifierId,
    purpose: `Enhanced demo for ${useCaseLabels[useCase]}`,
  };
}

export function createAgeVerificationMockPresentation({ useCase, now = Date.now }) {
  return {
    verifiableCredential: [{
      credentialSubject: {
        age_over_18: true,
        age_over_21: useCase === 'alcohol_purchase',
        age_over_65: useCase === 'senior_discount',
        given_name: 'Jane',
        age_in_range: useCase === 'employment_eligibility',
      },
      issuer: 'did:example:demo:issuer',
      expirationDate: new Date(now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    }],
  };
}

export function parseFlowInstanceResponse(data) {
  if (data.instance_id) {
    return {
      request: {
        request_id: data.instance_id,
        request_uri: data.request_uri,
        qr_code_data: data.qr_code_data,
        ...data,
      },
      error: null,
    };
  }
  return { request: null, error: data.error || 'Request failed' };
}

// ── Offline QR ──────────────────────────────────────────────────────

export function createDefaultMockMDLData() {
  return {
    given_name: 'Jane',
    family_name: 'Doe',
    birth_date: '1990-01-01',
    age_over_18: true,
    age_over_21: true,
    document_number: 'DL123456789',
    expiry_date: '2030-01-01',
    issuing_country: 'XX',
    issuing_authority: 'Demo DMV',
  };
}

export function buildOfflineQRFlowBody({
  mdlData,
  requirements = {
    required_fields: ['given_name', 'family_name', 'age_over_18'],
    purpose: 'offline_demo',
    context: 'demo',
  },
  expiresInMinutes = 60,
}) {
  return {
    flow_type: 'offline_qr',
    mdl_data: mdlData,
    verification_requirements: requirements,
    expires_in_minutes: expiresInMinutes,
  };
}

export function parseOfflineQRResponse(data) {
  if (data.instance_id) {
    return {
      qrCode: {
        qr_code_data: data.qr_code_data,
        instance_id: data.instance_id,
        ...data,
      },
      error: null,
    };
  }
  return { qrCode: null, error: data.error || 'QR creation failed' };
}

// ── Policy ──────────────────────────────────────────────────────────

export function createDefaultMockPolicyEvaluation() {
  return {
    presentation_request: {
      purpose: 'age_verification',
      requested_attributes: ['age_over_21', 'given_name'],
    },
    available_attributes: {
      age_over_21: true,
      given_name: 'Jane',
      family_name: 'Doe',
      birth_date: '1990-01-01',
      address: '123 Demo St',
    },
    context: {
      context_type: 'commercial',
      verifier_trust_level: 'verified_commercial',
      location: 'private_establishment',
      urgency: 'routine',
    },
  };
}
