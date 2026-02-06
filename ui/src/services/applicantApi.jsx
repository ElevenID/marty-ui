/**
 * Applicant API Service
 *
 * API functions for applicant registration, biometric enrollment,
 * application workflow, and vetting operations.
 */

const API_BASE = '/v1/applicants';

// Applicant API
export async function createApplicant(data) {
  const response = await fetch(API_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to create applicant');
  }
  return response.json();
}

export async function getApplicant(applicantId) {
  const response = await fetch(`${API_BASE}/${applicantId}`);
  if (!response.ok) throw new Error('Failed to fetch applicant');
  return response.json();
}

export async function getApplicantByUser(userId) {
  const response = await fetch(`${API_BASE}/by-user/${userId}`);
  if (!response.ok && response.status !== 404) throw new Error('Failed to fetch applicant');
  if (response.status === 404) return null;
  return response.json();
}

export async function enrollBiometric(applicantId, data) {
  const response = await fetch(`${API_BASE}/${applicantId}/biometrics`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to enroll biometric');
  }
  return response.json();
}

export async function getApplicantBiometrics(applicantId) {
  const response = await fetch(`${API_BASE}/${applicantId}/biometrics`);
  if (!response.ok) throw new Error('Failed to fetch biometrics');
  return response.json();
}

// Application API
export async function createApplication(data) {
  const response = await fetch(`${API_BASE}/applications`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to create application');
  }
  return response.json();
}

export async function submitApplication(applicationId) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/submit`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to submit application');
  }
  return response.json();
}

export async function getApplication(applicationId) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}`);
  if (!response.ok) throw new Error('Failed to fetch application');
  return response.json();
}

export async function listApplications(params = {}) {
  const queryParams = new URLSearchParams();
  if (params.status) queryParams.append('status', params.status);
  if (params.document_type) queryParams.append('document_type', params.document_type);
  if (params.limit) queryParams.append('limit', params.limit);
  if (params.offset) queryParams.append('offset', params.offset);

  const response = await fetch(`${API_BASE}/applications?${queryParams}`);
  if (!response.ok) throw new Error('Failed to fetch applications');
  return response.json();
}

export async function getApprovedApplications(limit = 50) {
  const response = await fetch(`${API_BASE}/applications/approved?limit=${limit}`);
  if (!response.ok) throw new Error('Failed to fetch approved applications');
  return response.json();
}

// Vetting Checks API
export async function getVettingChecks(applicationId) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/checks`);
  if (!response.ok) throw new Error('Failed to fetch vetting checks');
  return response.json();
}

export async function startCheck(checkId) {
  const response = await fetch(`${API_BASE}/checks/${checkId}/start`, {
    method: 'POST',
  });
  if (!response.ok) throw new Error('Failed to start check');
  return response.json();
}

export async function completeCheck(checkId, data) {
  const response = await fetch(`${API_BASE}/checks/${checkId}/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error('Failed to complete check');
  return response.json();
}

export async function getPendingChecks(checkType = null) {
  const url = checkType
    ? `${API_BASE}/checks/pending?check_type=${checkType}`
    : `${API_BASE}/checks/pending`;
  const response = await fetch(url);
  if (!response.ok) throw new Error('Failed to fetch pending checks');
  return response.json();
}

// Approval API
export async function approveApplication(applicationId, data) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to approve application');
  }
  return response.json();
}

export async function rejectApplication(applicationId, data) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to reject application');
  }
  return response.json();
}

// KYC API
export async function submitKYC(applicationId, data) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/kyc`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to submit KYC');
  }
  return response.json();
}

export async function getDocumentTypes() {
  const response = await fetch(`${API_BASE}/document-types`);
  if (!response.ok) throw new Error('Failed to fetch document types');
  return response.json();
}