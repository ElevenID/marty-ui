/**
 * Pre-built Presentation Policy Templates
 * 
 * Each template is aligned with industry standards and provides a quick-start
 * configuration for common verification scenarios.
 */

export const POLICY_TEMPLATES = [
  {
    id: 'mdl-age-verification',
    name: 'Age Verification (mDL)',
    description: 'Verify age using mobile driver\'s license with predicate proofs for privacy',
    trustFramework: 'aamva',
    standardReference: 'ISO 18013-5:2021',
    icon: '🔞',
    category: 'Age Verification',
    config: {
      accepted_credential_types: ['org.iso.18013.5.1.mDL'],
      required_claims: [
        {
          claim_name: 'age_over_21',
          credential_type: 'org.iso.18013.5.1.mDL',
          accept_predicate: true,
          required_value: null,
        },
        {
          claim_name: 'age_over_18',
          credential_type: 'org.iso.18013.5.1.mDL',
          accept_predicate: true,
          required_value: null,
        },
      ],
      holder_binding: 'device_key',
      freshness_requirements: {
        max_credential_age_seconds: 31536000, // 1 year
        max_proof_age_seconds: 300, // 5 minutes
        require_revocation_check: true,
      },
      prefer_predicates: true,
      single_presentation: false,
    },
  },
  {
    id: 'mdl-identity-verification',
    name: 'Identity Verification (mDL)',
    description: 'Full identity verification using mobile driver\'s license',
    trustFramework: 'aamva',
    standardReference: 'ISO 18013-5:2021',
    icon: '🪪',
    category: 'Identity Verification',
    config: {
      accepted_credential_types: ['org.iso.18013.5.1.mDL'],
      required_claims: [
        {
          claim_name: 'family_name',
          credential_type: 'org.iso.18013.5.1.mDL',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'given_name',
          credential_type: 'org.iso.18013.5.1.mDL',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'birth_date',
          credential_type: 'org.iso.18013.5.1.mDL',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'portrait',
          credential_type: 'org.iso.18013.5.1.mDL',
          accept_predicate: false,
          required_value: null,
        },
      ],
      holder_binding: 'device_key',
      freshness_requirements: {
        max_credential_age_seconds: 31536000, // 1 year
        max_proof_age_seconds: 300, // 5 minutes
        require_revocation_check: true,
      },
      prefer_predicates: false,
      single_presentation: true,
    },
  },
  {
    id: 'mdl-driving-privileges',
    name: 'Driving Privileges Verification (mDL)',
    description: 'Verify driving privileges for vehicle rental or access',
    trustFramework: 'aamva',
    standardReference: 'ISO 18013-5:2021',
    icon: '🚗',
    category: 'Access Control',
    config: {
      accepted_credential_types: ['org.iso.18013.5.1.mDL'],
      required_claims: [
        {
          claim_name: 'driving_privileges',
          credential_type: 'org.iso.18013.5.1.mDL',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'expiry_date',
          credential_type: 'org.iso.18013.5.1.mDL',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'document_number',
          credential_type: 'org.iso.18013.5.1.mDL',
          accept_predicate: false,
          required_value: null,
        },
      ],
      holder_binding: 'device_key',
      freshness_requirements: {
        max_credential_age_seconds: 86400, // 24 hours
        max_proof_age_seconds: 300, // 5 minutes
        require_revocation_check: true,
      },
      prefer_predicates: false,
      single_presentation: true,
    },
  },
  {
    id: 'eudi-pid-verification',
    name: 'EUDI PID Verification',
    description: 'Verify Person Identification Data (PID) for EU Digital Identity Wallet',
    trustFramework: 'eudi',
    standardReference: 'ARF 1.4.0',
    icon: '🇪🇺',
    category: 'Identity Verification',
    config: {
      accepted_credential_types: ['eu.europa.ec.eudiw.pid.1'],
      required_claims: [
        {
          claim_name: 'family_name',
          credential_type: 'eu.europa.ec.eudiw.pid.1',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'given_name',
          credential_type: 'eu.europa.ec.eudiw.pid.1',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'birth_date',
          credential_type: 'eu.europa.ec.eudiw.pid.1',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'nationality',
          credential_type: 'eu.europa.ec.eudiw.pid.1',
          accept_predicate: false,
          required_value: null,
        },
      ],
      holder_binding: 'device_key',
      freshness_requirements: {
        max_credential_age_seconds: 31536000, // 1 year
        max_proof_age_seconds: 300, // 5 minutes
        require_revocation_check: true,
      },
      prefer_predicates: false,
      single_presentation: true,
    },
  },
  {
    id: 'travel-document-verification',
    name: 'Travel Document Verification',
    description: 'Verify eMRTD/ePassport for border control',
    trustFramework: 'icao',
    standardReference: 'ICAO 9303 Ed. 8',
    icon: '✈️',
    category: 'Identity Verification',
    config: {
      accepted_credential_types: ['icao.mrtd'],
      required_claims: [
        {
          claim_name: 'family_name',
          credential_type: 'icao.mrtd',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'given_name',
          credential_type: 'icao.mrtd',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'nationality',
          credential_type: 'icao.mrtd',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'document_number',
          credential_type: 'icao.mrtd',
          accept_predicate: false,
          required_value: null,
        },
      ],
      holder_binding: 'session_nonce',
      freshness_requirements: {
        max_credential_age_seconds: 315360000, // 10 years
        max_proof_age_seconds: 300, // 5 minutes
        require_revocation_check: true,
      },
      prefer_predicates: false,
      single_presentation: true,
    },
  },
  {
    id: 'employee-access',
    name: 'Employee Access Verification',
    description: 'Verify employee credentials for physical or logical access control',
    trustFramework: 'custom',
    standardReference: null,
    icon: '🏢',
    category: 'Access Control',
    config: {
      accepted_credential_types: ['custom.employee.badge'],
      required_claims: [
        {
          claim_name: 'employee_id',
          credential_type: 'custom.employee.badge',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'department',
          credential_type: 'custom.employee.badge',
          accept_predicate: false,
          required_value: null,
        },
        {
          claim_name: 'clearance_level',
          credential_type: 'custom.employee.badge',
          accept_predicate: false,
          required_value: null,
        },
      ],
      holder_binding: 'biometric',
      freshness_requirements: {
        max_credential_age_seconds: 2592000, // 30 days
        max_proof_age_seconds: 300, // 5 minutes
        require_revocation_check: true,
      },
      prefer_predicates: false,
      single_presentation: true,
    },
  },
];

/**
 * Get templates filtered by trust framework type
 */
export function getTemplatesByFramework(frameworkType) {
  if (!frameworkType) return POLICY_TEMPLATES;
  return POLICY_TEMPLATES.filter(t => t.trustFramework === frameworkType.toLowerCase());
}

/**
 * Get template by ID
 */
export function getTemplateById(id) {
  return POLICY_TEMPLATES.find(t => t.id === id);
}

/**
 * Get all unique categories
 */
export function getCategories() {
  return [...new Set(POLICY_TEMPLATES.map(t => t.category))];
}
