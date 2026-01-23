/**
 * Keycloak Admin Helpers
 * 
 * Utilities for managing users and organizations via Keycloak Admin API.
 * Used for edge case testing where seeded users aren't sufficient.
 */

const KEYCLOAK_ADMIN_URL = process.env.KEYCLOAK_ADMIN_URL || 'http://localhost:8180';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'marty';
const KEYCLOAK_ADMIN_USER = process.env.KEYCLOAK_ADMIN_USER || 'admin';
const KEYCLOAK_ADMIN_PASSWORD = process.env.KEYCLOAK_ADMIN_PASSWORD || 'admin';

class KeycloakAdminClient {
  constructor(options = {}) {
    this.baseUrl = options.adminUrl || KEYCLOAK_ADMIN_URL;
    this.realm = options.realm || KEYCLOAK_REALM;
    this.adminUser = options.adminUser || KEYCLOAK_ADMIN_USER;
    this.adminPassword = options.adminPassword || KEYCLOAK_ADMIN_PASSWORD;
    this._accessToken = null;
    this._tokenExpiry = null;
  }

  /**
   * Get admin access token
   */
  async getAccessToken() {
    // Return cached token if still valid
    if (this._accessToken && this._tokenExpiry && Date.now() < this._tokenExpiry) {
      return this._accessToken;
    }

    const tokenUrl = `${this.baseUrl}/realms/master/protocol/openid-connect/token`;
    
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: 'admin-cli',
        username: this.adminUser,
        password: this.adminPassword,
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to get admin token: ${response.status}`);
    }

    const data = await response.json();
    this._accessToken = data.access_token;
    // Set expiry 10 seconds before actual expiry
    this._tokenExpiry = Date.now() + (data.expires_in - 10) * 1000;
    
    return this._accessToken;
  }

  /**
   * Make authenticated request to Keycloak Admin API
   */
  async request(method, path, body = null) {
    const token = await this.getAccessToken();
    const url = `${this.baseUrl}/admin/realms/${this.realm}${path}`;
    
    const options = {
      method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    
    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Keycloak API error: ${response.status} - ${error}`);
    }

    // Return null for 204 No Content
    if (response.status === 204) {
      return null;
    }

    return response.json();
  }

  // =========================================================================
  // User Management
  // =========================================================================

  /**
   * Create a new user
   * @param {object} user - User data
   * @returns {string} User ID
   */
  async createUser(user) {
    const userData = {
      username: user.email,
      email: user.email,
      emailVerified: true,
      enabled: true,
      firstName: user.firstName,
      lastName: user.lastName,
      credentials: user.password ? [{
        type: 'password',
        value: user.password,
        temporary: false,
      }] : undefined,
      attributes: user.attributes || {},
    };

    await this.request('POST', '/users', userData);
    
    // Get the created user ID
    const users = await this.request('GET', `/users?email=${encodeURIComponent(user.email)}`);
    return users[0]?.id;
  }

  /**
   * Get user by email
   * @param {string} email - User email
   * @returns {object|null} User or null if not found
   */
  async getUserByEmail(email) {
    const users = await this.request('GET', `/users?email=${encodeURIComponent(email)}`);
    return users[0] || null;
  }

  /**
   * Get user by ID
   * @param {string} userId - User ID
   * @returns {object} User
   */
  async getUser(userId) {
    return this.request('GET', `/users/${userId}`);
  }

  /**
   * Update user
   * @param {string} userId - User ID
   * @param {object} updates - User updates
   */
  async updateUser(userId, updates) {
    await this.request('PUT', `/users/${userId}`, updates);
  }

  /**
   * Delete user
   * @param {string} userId - User ID
   */
  async deleteUser(userId) {
    await this.request('DELETE', `/users/${userId}`);
  }

  /**
   * Set user password
   * @param {string} userId - User ID
   * @param {string} password - New password
   * @param {boolean} temporary - Require password change
   */
  async setPassword(userId, password, temporary = false) {
    await this.request('PUT', `/users/${userId}/reset-password`, {
      type: 'password',
      value: password,
      temporary,
    });
  }

  /**
   * Assign realm role to user
   * @param {string} userId - User ID
   * @param {string} roleName - Role name
   */
  async assignRealmRole(userId, roleName) {
    // Get role
    const roles = await this.request('GET', '/roles');
    const role = roles.find(r => r.name === roleName);
    
    if (!role) {
      throw new Error(`Role not found: ${roleName}`);
    }

    await this.request('POST', `/users/${userId}/role-mappings/realm`, [role]);
  }

  /**
   * Remove realm role from user
   * @param {string} userId - User ID
   * @param {string} roleName - Role name
   */
  async removeRealmRole(userId, roleName) {
    const roles = await this.request('GET', '/roles');
    const role = roles.find(r => r.name === roleName);
    
    if (!role) {
      throw new Error(`Role not found: ${roleName}`);
    }

    await this.request('DELETE', `/users/${userId}/role-mappings/realm`, [role]);
  }

  // =========================================================================
  // Organization Management (Keycloak 25+ with organizations feature)
  // =========================================================================

  /**
   * Create an organization
   * @param {object} org - Organization data
   * @returns {string} Organization ID
   */
  async createOrganization(org) {
    const orgData = {
      name: org.name,
      alias: org.alias || org.name.toLowerCase().replace(/\s+/g, '-'),
      enabled: true,
      attributes: org.attributes || {},
    };

    await this.request('POST', '/organizations', orgData);
    
    // Get created org
    const orgs = await this.request('GET', `/organizations?search=${encodeURIComponent(org.name)}`);
    return orgs[0]?.id;
  }

  /**
   * Add user to organization
   * @param {string} orgId - Organization ID
   * @param {string} userId - User ID
   */
  async addUserToOrganization(orgId, userId) {
    await this.request('PUT', `/organizations/${orgId}/members/${userId}`);
  }

  /**
   * Remove user from organization
   * @param {string} orgId - Organization ID
   * @param {string} userId - User ID
   */
  async removeUserFromOrganization(orgId, userId) {
    await this.request('DELETE', `/organizations/${orgId}/members/${userId}`);
  }

  /**
   * Get organization members
   * @param {string} orgId - Organization ID
   * @returns {object[]} Members
   */
  async getOrganizationMembers(orgId) {
    return this.request('GET', `/organizations/${orgId}/members`);
  }

  /**
   * Delete organization
   * @param {string} orgId - Organization ID
   */
  async deleteOrganization(orgId) {
    await this.request('DELETE', `/organizations/${orgId}`);
  }

  // =========================================================================
  // Invitation Helpers
  // =========================================================================

  /**
   * Create a user invite action token
   * This simulates sending an invite link that can be used once
   * @param {string} email - Email to invite
   * @param {number} lifespan - Token lifespan in seconds
   * @returns {string} Action token URL
   */
  async createInviteLink(email, lifespan = 86400) {
    // First create disabled user
    const userId = await this.createUser({
      email,
      firstName: 'Invited',
      lastName: 'User',
    });

    // Generate action token for setting password
    const response = await this.request(
      'PUT',
      `/users/${userId}/execute-actions-email?lifespan=${lifespan}`,
      ['UPDATE_PASSWORD']
    );

    // Get the user to return the action URL (would come from email)
    // For testing, we'll construct it manually
    const token = await this.request('GET', `/users/${userId}`);
    
    return {
      userId,
      email,
      // In real scenario, user clicks link from email
      // For testing, we may need to extract from MailHog
    };
  }
}

/**
 * Create Keycloak admin client with default configuration
 * @param {object} options - Override options
 * @returns {KeycloakAdminClient}
 */
function createAdminClient(options = {}) {
  return new KeycloakAdminClient(options);
}

module.exports = {
  KeycloakAdminClient,
  createAdminClient,
};
