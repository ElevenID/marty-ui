/**
 * AuthenticatedApiClient - DRY wrapper for common page.request patterns
 * 
 * Encapsulates 20+ instances of inline API setup code across test files.
 * Provides convenience methods for credential config, trust config, and common operations.
 * 
 * Usage:
 *   const api = new AuthenticatedApiClient(page);
 *   await api.ensureCredentialConfig(orgId, 'employee_badge');
 *   await api.ensureTrustConfig(orgId);
 */
class AuthenticatedApiClient {
  constructor(page, apiUrl = null) {
    this.page = page;
    this.apiUrl = apiUrl || process.env.API_URL || 'http://localhost:8000';
  }

  /**
   * GET request with automatic cookie handling
   */
  async get(path, options = {}) {
    const url = path.startsWith('http') ? path : `${this.apiUrl}${path}`;
    return this.page.request.get(url, options);
  }

  /**
   * POST request with automatic cookie handling
   */
  async post(path, data, options = {}) {
    const url = path.startsWith('http') ? path : `${this.apiUrl}${path}`;
    return this.page.request.post(url, { ...options, data });
  }

  /**
   * PUT request with automatic cookie handling
   */
  async put(path, data, options = {}) {
    const url = path.startsWith('http') ? path : `${this.apiUrl}${path}`;
    return this.page.request.put(url, { ...options, data });
  }

  /**
   * DELETE request with automatic cookie handling
   */
  async delete(path, options = {}) {
    const url = path.startsWith('http') ? path : `${this.apiUrl}${path}`;
    return this.page.request.delete(url, options);
  }

  /**
   * Ensure credential configuration exists, create if needed.
   * Consolidates pattern repeated 10+ times across test files.
   */
  async ensureCredentialConfig(organizationId, credentialType = 'employee_badge') {
    const listResponse = await this.get(
      `/api/organizations/${organizationId}/credential-types`
    );

    if (listResponse.ok()) {
      const listData = await listResponse.json();
      const configs = listData.credential_types || [];
      const existing = configs.find((c) => c.credential_type === credentialType);

      if (existing) {
        return existing.id;
      }

      // Create new credential config
      const createResponse = await this.post(
        `/api/organizations/${organizationId}/credential-types`,
        {
          credential_type: credentialType,
          name: `${credentialType} Credential`,
          description: `Auto-generated ${credentialType} credential for testing`,
          schema: { type: 'object', properties: {} },
        }
      );

      if (createResponse.ok()) {
        const created = await createResponse.json();
        return created.id || created.credential_type_id;
      }
    }

    return null;
  }

  /**
   * Ensure trust configuration with signing key exists.
   * Consolidates pattern repeated 8+ times across test files.
   */
  async ensureTrustConfig(organizationId, options = {}) {
    const {
      trustFramework = 'marty_hosted',
      keySource = 'marty_generated',
      algorithm = 'ES256',
    } = options;

    // Create or update trust config
    const configResponse = await this.put(
      `/api/organizations/${organizationId}/trust-config`,
      {
        trust_framework: trustFramework,
        key_source: keySource,
      }
    );

    // Generate signing key
    const keyResponse = await this.post(
      `/api/organizations/${organizationId}/trust-config/keys`,
      {
        algorithm,
        key_purpose: 'signing',
      }
    );

    // Key might already exist (409), which is OK
    return {
      configSuccess: configResponse.ok(),
      keySuccess: keyResponse.ok() || keyResponse.status() === 409,
    };
  }

  /**
   * Create application for testing
   */
  async createApplication(organizationId, applicantData = {}) {
    const response = await this.post('/api/applicants/applications', {
      organization_id: organizationId,
      credential_type: applicantData.credential_type || 'employee_badge',
      applicant: {
        given_name: applicantData.given_name || 'Test',
        family_name: applicantData.family_name || 'User',
        email: applicantData.email || `test-${Date.now()}@example.com`,
        ...applicantData,
      },
    });

    return response.ok() ? response.json() : null;
  }

  /**
   * Approve application
   */
  async approveApplication(applicationId, approvedBy = 'test-admin') {
    const response = await this.post(`/api/applicants/applications/${applicationId}/approve`, {
      approved_by: approvedBy,
      notes: 'Auto-approved for E2E testing',
    });

    return response.ok() ? response.json() : null;
  }

  /**
   * Create credential offer
   */
  async createCredentialOffer(options) {
    const {
      organizationId,
      credentialConfigId = 'employee_badge',
      applicantId = `test-applicant-${Date.now()}`,
      deviceId = null,
      credentialData = {},
      credentialFormat = 'vc+sd-jwt',
    } = options;

    const response = await this.post('/api/issuance/offers', {
      organization_id: organizationId,
      credential_config_id: credentialConfigId,
      applicant_id: applicantId,
      device_id: deviceId,
      credential_data: credentialData,
      credential_format: credentialFormat,
    });

    return response.ok() ? response.json() : null;
  }
}

module.exports = { AuthenticatedApiClient };
