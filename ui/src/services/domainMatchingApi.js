/**
 * Email Domain Matching API
 * 
 * Handles API calls for email domain-based organization matching
 */

const ONBOARDING_BASE_URL = '/api/onboarding';

/**
 * Get organizations matching the user's email domain
 * @returns {Promise<Array<{id: string, name: string, domain_join_policy: string, default_role: string}>>}
 */
export async function getDomainMatches() {
  try {
    const response = await fetch(`${ONBOARDING_BASE_URL}/domain-matches`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return data.matches || [];
  } catch (error) {
    console.error('Error fetching domain matches:', error);
    return [];
  }
}

/**
 * Join or request to join an organization based on email domain
 * @param {string} organizationId - Organization ID to join
 * @returns {Promise<{success: boolean, action: string, organization_id: string, organization_name: string, message: string}>}
 */
export async function joinDomainOrganization(organizationId) {
  try {
    const response = await fetch(`${ONBOARDING_BASE_URL}/join-domain-org`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ organization_id: organizationId }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to join organization');
    }

    return await response.json();
  } catch (error) {
    console.error('Error joining domain organization:', error);
    throw error;
  }
}

/**
 * Set user's role intent preference
 * @param {string} intent - "apply_for_credentials" or "manage_credentials"
 * @returns {Promise<{success: boolean, intent: string, message: string}>}
 */
export async function setRoleIntent(intent) {
  try {
    const response = await fetch(`${ONBOARDING_BASE_URL}/set-intent`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ intent }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to set role intent');
    }

    return await response.json();
  } catch (error) {
    console.error('Error setting role intent:', error);
    throw error;
  }
}

export default {
  getDomainMatches,
  joinDomainOrganization,
  setRoleIntent,
};
