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
  const response = await fetch(`${API_BASE}/profiles/${applicantId}`);
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
  const response = await fetch(`${API_BASE}/profiles/${applicantId}/biometrics`, {
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
  const response = await fetch(`${API_BASE}/profiles/${applicantId}/biometrics`);
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

export async function listOrganizationApplications(organizationId, params = {}) {
  const searchParams = new URLSearchParams({ organization_id: organizationId });
  if (params.status && params.status !== 'all') {
    searchParams.set('status', params.status);
  }

  const response = await fetch(`${API_BASE}/org-applications?${searchParams.toString()}`, {
    credentials: 'include',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || 'Failed to fetch organization applications');
  }

  const applications = await response.json();
  const normalized = Array.isArray(applications) ? applications : (applications?.applications || []);
  return {
    applications: normalized,
    total: normalized.length,
    limit: params.limit || normalized.length,
    offset: params.offset || 0,
  };
}

export async function reviewOrganizationApplication(applicationId, decision, payload = {}) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/review`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ decision, ...payload }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `Failed to ${decision} application`);
  }

  return response.json();
}

export async function issueOrganizationApplication(applicationId) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/issue`, {
    method: 'POST',
    credentials: 'include',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || 'Failed to issue application');
  }

  return response.json();
}

export async function getApplication(applicationId) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}`);
  if (!response.ok) throw new Error('Failed to fetch application');
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

// Request Info API
export async function requestApplicationInfo(applicationId, data) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/request-info`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || 'Failed to request info');
  }
  return response.json();
}

// Reviewer Lock API
export async function acquireReviewerLock(applicationId, reviewerId, reviewerName) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/lock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ reviewer_id: reviewerId, reviewer_name: reviewerName }),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || 'Failed to acquire lock');
  }
  return response.json();
}

export async function releaseReviewerLock(applicationId, reviewerId) {
  const response = await fetch(
    `${API_BASE}/applications/${applicationId}/lock?reviewer_id=${encodeURIComponent(reviewerId)}`,
    { method: 'DELETE', credentials: 'include' },
  );
  if (!response.ok) return { released: false };
  return response.json();
}

export async function getLockStatus(applicationId) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/lock`);
  if (!response.ok) return { locked: false };
  return response.json();
}

export async function listApplications(params = {}) {
  try {
    console.log('[listApplications] Fetching user info from /v1/auth/me');
    const meResponse = await fetch('/v1/auth/me', { credentials: 'include' });
    if (!meResponse.ok) {
      console.warn('[listApplications] Failed to fetch user info:', meResponse.status);
      return {
        applications: [],
        total: 0,
        limit: params.limit || 50,
        offset: params.offset || 0,
      };
    }

    const me = await meResponse.json();
    const userId = me?.user?.user_id || me?.user_id || me?.sub;
    const applicantIdFromAuth = me?.user?.applicant_id || me?.applicant_id || null;
    console.log('[listApplications] User ID:', userId);
    if (!userId) {
      console.warn('[listApplications] No user ID found in response');
      return {
        applications: [],
        total: 0,
        limit: params.limit || 50,
        offset: params.offset || 0,
      };
    }

    console.log('[listApplications] Fetching applicant by user ID:', userId);
    const applicantResponse = await fetch(`${API_BASE}/by-user/${userId}`, {
      credentials: 'include',
    });

    let applicantId = null;
    if (applicantResponse.ok) {
      const applicant = await applicantResponse.json();
      applicantId = applicant?.id || null;
      console.log('[listApplications] Applicant ID (by-user):', applicantId);
    } else {
      console.warn('[listApplications] Failed to fetch applicant by user:', applicantResponse.status);
    }

    if (!applicantId && applicantIdFromAuth) {
      applicantId = applicantIdFromAuth;
      console.log('[listApplications] Falling back to applicant_id from auth/me:', applicantId);
    }

    if (!applicantId) {
      console.warn('[listApplications] No applicant ID available after fallbacks');
      return {
        applications: [],
        total: 0,
        limit: params.limit || 50,
        offset: params.offset || 0,
      };
    }

    console.log('[listApplications] Fetching applications for applicant:', applicantId);

    // Primary endpoint used by current applicant service
    let response = await fetch(`${API_BASE}/${applicantId}/applications`, {
      credentials: 'include',
    });

    // Backward-compatible fallback for older gateway routes
    if (!response.ok && response.status === 404) {
      console.warn('[listApplications] Primary applications endpoint not found, falling back to /profiles route');
      response = await fetch(`${API_BASE}/profiles/${applicantId}/applications`, {
        credentials: 'include',
      });
    }

    if (!response.ok) {
      console.warn('[listApplications] Failed to fetch applications:', response.status);
      return {
        applications: [],
        total: 0,
        limit: params.limit || 50,
        offset: params.offset || 0,
      };
    }

    const applications = await response.json();
    const normalized = Array.isArray(applications) ? applications : (applications?.applications || []);
    console.log('[listApplications] Found', normalized.length, 'applications');

    return {
      applications: normalized,
      total: normalized.length,
      limit: params.limit || normalized.length,
      offset: params.offset || 0,
    };
  } catch (error) {
    console.error('Error in listApplications:', error);
    return {
      applications: [],
      total: 0,
      limit: params.limit || 50,
      offset: params.offset || 0,
    };
  }
}

export async function getApprovedApplications(limit = 50) {
  const response = await fetch(`${API_BASE}/applications/approved?limit=${limit}`);
  if (!response.ok) throw new Error('Failed to fetch approved applications');
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

// ============================================================
// Applicant Dashboard & Profile APIs
// ============================================================

/**
 * Get applicant dashboard statistics for the current user
 * @returns {Promise<Object>} Dashboard stats with active credentials, pending applications, etc.
 */
export async function getApplicantStats() {
  // This calls the applications list endpoint and credentials API to compute stats
  // Since there's no dedicated stats endpoint yet, we aggregate from existing endpoints
  try {
    const [applications, credentials] = await Promise.all([
      listApplications({ limit: 100 }),
      getMyCredentials().catch(() => ({ credentials: [] }))
    ]);

    const pendingStatuses = ['SUBMITTED', 'UNDER_REVIEW', 'VETTING_IN_PROGRESS'];
    const pendingApplications = applications.applications?.filter(
      app => pendingStatuses.includes(app.status)
    ).length || 0;

    const activeCredentials = credentials.credentials?.filter(
      cred => cred.status === 'ACTIVE'
    ).length || 0;

    // Check for credentials expiring in next 90 days
    const now = new Date();
    const ninetyDaysFromNow = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
    const expiringSoon = credentials.credentials?.filter(cred => {
      if (!cred.expiry_date) return false;
      const expiryDate = new Date(cred.expiry_date);
      return expiryDate > now && expiryDate <= ninetyDaysFromNow;
    }).length || 0;

    return {
      activeCredentials,
      pendingApplications,
      expiringSoon,
      totalApplications: applications.total || 0,
      totalCredentials: credentials.credentials?.length || 0,
    };
  } catch (error) {
    console.error('Error fetching applicant stats:', error);
    return {
      activeCredentials: 0,
      pendingApplications: 0,
      expiringSoon: 0,
      totalApplications: 0,
      totalCredentials: 0,
    };
  }
}

/**
 * Get applications for the current user
 * @param {Object} params - Query parameters
 * @returns {Promise<Object>} Applications list with pagination
 */
export async function getMyApplications(params = {}) {
  // Uses the same listApplications but filtered by user context
  // The backend will automatically filter by the authenticated user
  return listApplications(params);
}

/**
 * Get credentials issued to the current user
 * @returns {Promise<Object>} List of credentials
 */
export async function getMyCredentials() {
  // This endpoint would typically be in a credentials service
  // For now, we'll call the document service API
  const response = await fetch('/v1/documents', {
    credentials: 'include',
  });
  if (!response.ok && response.status !== 404) {
    throw new Error('Failed to fetch credentials');
  }
  if (response.status === 404) {
    return { credentials: [] };
  }
  return response.json();
}

/**
 * Update applicant profile settings
 * @param {string} applicantId - Applicant ID
 * @param {Object} updates - Profile fields to update
 * @returns {Promise<Object>} Updated applicant record
 */
export async function updateApplicantProfile(applicantId, updates) {
  const response = await fetch(`${API_BASE}/profiles/${applicantId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(updates),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to update profile');
  }
  return response.json();
}