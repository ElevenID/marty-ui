/**
 * Pure helpers for wallet demo flows.
 */

// Explicit sample data only; never used to populate a real wallet inventory.
export const WALLET_DEMO_FALLBACK_CREDENTIALS = [
  {
    id: 'demo_mdl_001',
    type: 'DriverLicenseCredential',
    issuer: 'Demo DMV',
    issued_date: '2024-01-15',
    expiry_date: '2030-01-15',
    status: 'active',
    subject_data: {
      given_name: 'Jane',
      family_name: 'Doe',
      birth_date: '1990-01-01',
      document_number: 'DL123456789',
    },
  },
];

export function mapWalletCredential(credential = {}) {
  const expiry = Date.parse(credential.expiration_date);
  const reportedStatus = typeof credential.status === 'string' ? credential.status : 'unknown';
  const status = ['revoked', 'suspended'].includes(reportedStatus)
    ? reportedStatus
    : Number.isFinite(expiry) && expiry <= Date.now() ? 'expired' : reportedStatus;
  return {
    id: credential.id,
    type: credential.types ? credential.types.join(', ') : 'VerifiableCredential',
    issuer: credential.issuer,
    issued_date: credential.issuance_date ? credential.issuance_date.split('T')[0] : 'Unknown',
    expiry_date: credential.expiration_date ? credential.expiration_date.split('T')[0] : 'No expiry',
    status,
    subject_data: credential.claims || {},
  };
}

export function resolveWalletCredentials(data = {}) {
  if (!Array.isArray(data?.credentials)) {
    throw new Error('Wallet inventory response must contain a credentials array');
  }
  return data.credentials.map(mapWalletCredential);
}

export function resolveWalletDelete(credentials = [], credentialId) {
  return credentials.filter((credential) => credential.id !== credentialId);
}

export function resolveWalletPresentationRequest(requestText = '') {
  let parsed;
  try {
    parsed = JSON.parse(requestText);
  } catch {
    throw new Error('Presentation request must be valid JSON');
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('Presentation request must be an object');
  }
  const audience = parsed.audience ?? parsed.verifier;
  if (typeof audience !== 'string' || !audience.trim()) {
    throw new Error('Presentation request requires a verifier audience');
  }
  const nonce = parsed.nonce ?? null;
  if (nonce !== null && (typeof nonce !== 'string' || !nonce.trim())) {
    throw new Error('Presentation request nonce must be a nonempty string');
  }
  return { audience, nonce };
}

export function buildWalletPresentationPayload({ selectedCredential, presentationRequest } = {}) {
  if (!selectedCredential?.id) {
    throw new Error('Please select a credential');
  }

  const { audience, nonce } = resolveWalletPresentationRequest(presentationRequest);

  return {
    credential_ids: [selectedCredential.id],
    audience,
    nonce,
  };
}

export function resolveWalletPresentationResult(result = {}) {
  if (result.success) {
    return {
      success: true,
      error: null,
      message: 'Presentation created successfully!',
    };
  }

  return {
    success: false,
    error: result.error || 'Failed to create presentation',
    message: null,
  };
}

export function createSampleWalletCredential({ now = Date.now(), random = Math.random } = {}) {
  return {
    id: `mdl_${now}`,
    type: 'mDL',
    issuer: 'Demo Issuer',
    issued_date: new Date(now).toISOString().split('T')[0],
    expiry_date: '2030-12-31',
    status: 'active',
    subject_data: {
      given_name: 'New',
      family_name: 'User',
      birth_date: '1995-05-05',
      document_number: `DL${random().toString().slice(2, 11)}`,
      age_over_18: true,
      age_over_21: true,
    },
  };
}

export function getWalletCredentialStatusColor(status) {
  switch (status) {
    case 'active':
      return 'success';
    case 'expired':
    case 'revoked':
      return 'error';
    default:
      return 'default';
  }
}