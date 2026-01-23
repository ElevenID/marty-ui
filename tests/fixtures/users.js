/**
 * Seeded Test Users
 * 
 * References to users pre-created in Keycloak realm.
 * These match the users defined in marty-realm.json and docker-compose.test.yml.
 */

const SEEDED_USERS = {
  // Super admin - cross-org access
  admin: {
    email: process.env.TEST_ADMIN_EMAIL || 'admin@marty.demo',
    password: process.env.TEST_ADMIN_PASSWORD || 'Admin123!',
    firstName: process.env.TEST_ADMIN_FIRST_NAME || 'Admin',
    lastName: process.env.TEST_ADMIN_LAST_NAME || 'User',
    role: 'administrator',
    fullName: function() { return `${this.firstName} ${this.lastName}`; },
  },

  // Vendor organization admin
  vendor: {
    email: process.env.TEST_VENDOR_EMAIL || 'vendor@marty.demo',
    password: process.env.TEST_VENDOR_PASSWORD || 'Vendor123!',
    firstName: process.env.TEST_VENDOR_FIRST_NAME || 'Vendor',
    lastName: process.env.TEST_VENDOR_LAST_NAME || 'Admin',
    role: 'vendor',
    organization: process.env.TEST_VENDOR_ORG || 'Demo Vendor Org',
    fullName: function() { return `${this.firstName} ${this.lastName}`; },
  },

  // Applicant 1 - USA nationality
  applicant1: {
    email: process.env.TEST_APPLICANT1_EMAIL || 'john.doe@marty.demo',
    password: process.env.TEST_APPLICANT1_PASSWORD || 'Applicant123!',
    firstName: process.env.TEST_APPLICANT1_FIRST_NAME || 'John',
    lastName: process.env.TEST_APPLICANT1_LAST_NAME || 'Doe',
    nationality: process.env.TEST_APPLICANT1_NATIONALITY || 'USA',
    dateOfBirth: process.env.TEST_APPLICANT1_DOB || '1985-03-15',
    role: 'applicant',
    fullName: function() { return `${this.firstName} ${this.lastName}`; },
  },

  // Applicant 2 - UK nationality
  applicant2: {
    email: process.env.TEST_APPLICANT2_EMAIL || 'jane.smith@marty.demo',
    password: process.env.TEST_APPLICANT2_PASSWORD || 'Applicant123!',
    firstName: process.env.TEST_APPLICANT2_FIRST_NAME || 'Jane',
    lastName: process.env.TEST_APPLICANT2_LAST_NAME || 'Smith',
    nationality: process.env.TEST_APPLICANT2_NATIONALITY || 'GBR',
    dateOfBirth: process.env.TEST_APPLICANT2_DOB || '1990-07-22',
    role: 'applicant',
    fullName: function() { return `${this.firstName} ${this.lastName}`; },
  },

  // Applicant 3 - Spain nationality
  applicant3: {
    email: process.env.TEST_APPLICANT3_EMAIL || 'carlos.garcia@marty.demo',
    password: process.env.TEST_APPLICANT3_PASSWORD || 'Applicant123!',
    firstName: process.env.TEST_APPLICANT3_FIRST_NAME || 'Carlos',
    lastName: process.env.TEST_APPLICANT3_LAST_NAME || 'Garcia',
    nationality: process.env.TEST_APPLICANT3_NATIONALITY || 'ESP',
    dateOfBirth: process.env.TEST_APPLICANT3_DOB || '1978-11-08',
    role: 'applicant',
    fullName: function() { return `${this.firstName} ${this.lastName}`; },
  },

  // Verifier user - can verify credentials
  verifier: {
    email: process.env.TEST_VERIFIER_EMAIL || 'verifier@marty.demo',
    password: process.env.TEST_VERIFIER_PASSWORD || 'Verifier123!',
    firstName: process.env.TEST_VERIFIER_FIRST_NAME || 'Verifier',
    lastName: process.env.TEST_VERIFIER_LAST_NAME || 'User',
    role: 'verifier',
    fullName: function() { return `${this.firstName} ${this.lastName}`; },
  },
};

/**
 * Get a seeded user by role for dynamic test scenarios
 * @param {string} role - 'admin', 'vendor', or 'applicant'
 * @returns {object} User object
 */
function getUserByRole(role) {
  switch (role) {
    case 'administrator':
    case 'admin':
      return SEEDED_USERS.admin;
    case 'vendor':
      return SEEDED_USERS.vendor;
    case 'applicant':
      return SEEDED_USERS.applicant1; // Default applicant
    default:
      throw new Error(`Unknown role: ${role}`);
  }
}

/**
 * Seeded Passwords - convenience object for tests that need passwords by role
 */
const SEEDED_PASSWORDS = {
  admin: SEEDED_USERS.admin.password,
  vendor: SEEDED_USERS.vendor.password,
  applicant: SEEDED_USERS.applicant1.password,
  verifier: process.env.TEST_VERIFIER_PASSWORD || 'Verifier123!',
};

/**
 * Seeded Organizations - organizations created during test setup
 */
const SEEDED_ORGS = {
  travelCorp: {
    id: process.env.TEST_TRAVEL_CORP_ID || 'travel-corp-test-id',
    name: process.env.TEST_TRAVEL_CORP_NAME || 'Travel Corp',
  },
  demoVendor: {
    id: process.env.TEST_DEMO_VENDOR_ID || 'demo-vendor-test-id',
    name: SEEDED_USERS.vendor.organization,
  },
};

/**
 * Get all applicant users
 * @returns {object[]} Array of applicant user objects
 */
function getAllApplicants() {
  return [
    SEEDED_USERS.applicant1,
    SEEDED_USERS.applicant2,
    SEEDED_USERS.applicant3,
  ];
}

/**
 * Generate a unique test user email for dynamic user creation
 * @param {string} prefix - Prefix for the email
 * @returns {string} Unique email address
 */
function generateTestEmail(prefix = 'test') {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 8);
  return `${prefix}-${timestamp}-${random}@marty.demo`;
}

/**
 * Generate test user data for registration
 * @param {object} overrides - Override default values
 * @returns {object} User registration data
 */
function generateTestUser(overrides = {}) {
  const timestamp = Date.now();
  return {
    email: generateTestEmail('testuser'),
    password: 'TestUser123!',
    firstName: `Test`,
    lastName: `User${timestamp % 10000}`,
    ...overrides,
  };
}

module.exports = {
  SEEDED_USERS,
  SEEDED_PASSWORDS,
  SEEDED_ORGS,
  getUserByRole,
  getAllApplicants,
  generateTestEmail,
  generateTestUser,
};
