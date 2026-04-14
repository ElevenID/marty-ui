import {
  createVerifierDemoMockPresentation,
  serializeVerifierDemoPresentation,
} from '../../application/verifier';

export const PROOF_LAB_RUNTIME = {
  'retail-age': {
    policyId: 'policy_age_over_21',
    trustProfileId: 'trust_retail_age_v1',
    issuer: 'did:web:retail.issuer.elevenid.demo',
    credentialType: 'RetailAgeCredential',
    issuedAt: '2026-03-01T10:15:00.000Z',
    claims: {
      age_over_21: true,
      issuer_trust: 'approved_retail_issuer',
    },
    expectedResult: {
      valid: true,
      issuer: 'did:web:retail.issuer.elevenid.demo',
      claims: {
        age_over_21: true,
        issuer_trust: 'approved_retail_issuer',
      },
      presentation_summary: 'Retail lane receives a pass result without collecting a birth date.',
    },
  },
  'enterprise-access': {
    policyId: 'policy_hq_north_access',
    trustProfileId: 'trust_workforce_v1',
    issuer: 'did:web:corp.issuer.elevenid.demo',
    credentialType: 'WorkforceAccessBadge',
    issuedAt: '2026-03-04T08:30:00.000Z',
    claims: {
      employment_active: true,
      access_zone_hq_north: true,
      department: 'operations',
    },
    expectedResult: {
      valid: true,
      issuer: 'did:web:corp.issuer.elevenid.demo',
      claims: {
        employment_active: true,
        access_zone_hq_north: true,
        department: 'operations',
      },
      presentation_summary: 'Door and portal both accept the same workforce credential under separate policies.',
    },
  },
  'airline-boarding': {
    policyId: 'policy_flight_boarding_gate',
    trustProfileId: 'trust_travel_runtime_v1',
    issuer: 'did:web:travel.issuer.elevenid.demo',
    credentialType: 'TravelClearanceCredential',
    issuedAt: '2026-03-07T14:45:00.000Z',
    claims: {
      document_authentic: true,
      journey_entitlement: 'LH430-seat-21A',
      clearance_status: 'board_now',
    },
    expectedResult: {
      valid: true,
      issuer: 'did:web:travel.issuer.elevenid.demo',
      claims: {
        document_authentic: true,
        journey_entitlement: 'LH430-seat-21A',
        clearance_status: 'board_now',
      },
      presentation_summary: 'Gate decision is returned from the travel policy without a new enrollment step.',
    },
  },
};

export function createProofLabPresentation(scenarioId) {
  const runtime = PROOF_LAB_RUNTIME[scenarioId] || PROOF_LAB_RUNTIME['retail-age'];
  const basePresentation = createVerifierDemoMockPresentation({ issuanceDate: runtime.issuedAt });
  const baseCredential = basePresentation.verifiableCredential?.[0] || {};

  return {
    ...basePresentation,
    verifiableCredential: [
      {
        ...baseCredential,
        type: ['VerifiableCredential', runtime.credentialType],
        issuer: runtime.issuer,
        issuanceDate: runtime.issuedAt,
        credentialSubject: runtime.claims,
      },
    ],
  };
}

export function createProofLabPresentationData(scenarioId) {
  return serializeVerifierDemoPresentation(createProofLabPresentation(scenarioId));
}

export function createProofLabRequestPreview(scenario, runtime) {
  const endpoint = scenario.requestPath.replace(/^POST\s+/, '');

  return {
    endpoint,
    presentation_policy_id: runtime.policyId,
    trust_profile_id: runtime.trustProfileId,
    requested_claims: scenario.disclosed,
    channel: scenario.channel,
  };
}