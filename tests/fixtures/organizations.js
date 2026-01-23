/**
 * Seeded Test Organizations
 *
 * References to organizations pre-created in Keycloak realm.
 * These match the organizations defined in marty-realm.json.
 */

const SEEDED_ORGS = {
  // Default vendor organization
  demoVendor: {
    id: process.env.TEST_DEMO_VENDOR_ID || 'demo-vendor-org',
    name: 'Demo Vendor Org',
    alias: 'demo-vendor-org',
    membershipMode: 'open',
    discoverable: true,
  },

  // Travel corporation - approval-based membership
  travelCorp: {
    id: process.env.TEST_TRAVEL_CORP_ID || 'travel-corp',
    name: 'Travel Corp',
    alias: 'travel-corp',
    membershipMode: 'approval',
    discoverable: true,
  },

  // Test organization Alpha - approval-based, discoverable
  testOrgAlpha: {
    id: process.env.TEST_ORG_ALPHA_ID || 'test-org-alpha',
    name: 'Test Org Alpha',
    alias: 'test-org-alpha',
    membershipMode: 'approval',
    discoverable: true,
  },

  // Test organization Beta - invite-only, not discoverable
  testOrgBeta: {
    id: process.env.TEST_ORG_BETA_ID || 'test-org-beta',
    name: 'Test Org Beta',
    alias: 'test-org-beta',
    membershipMode: 'invite_only',
    discoverable: false,
  },
};

/**
 * Get an organization by alias
 * @param {string} alias - Organization alias
 * @returns {object|undefined} Organization object or undefined
 */
function getOrgByAlias(alias) {
  return Object.values(SEEDED_ORGS).find((org) => org.alias === alias);
}

/**
 * Get all discoverable organizations
 * @returns {object[]} Array of discoverable organizations
 */
function getDiscoverableOrgs() {
  return Object.values(SEEDED_ORGS).filter((org) => org.discoverable);
}

/**
 * Get organizations by membership mode
 * @param {string} mode - 'open', 'approval', or 'invite_only'
 * @returns {object[]} Array of organizations with matching mode
 */
function getOrgsByMembershipMode(mode) {
  return Object.values(SEEDED_ORGS).filter((org) => org.membershipMode === mode);
}

/**
 * Generate a unique organization name for dynamic org creation
 * @param {string} prefix - Prefix for the organization name
 * @returns {string} Unique organization name
 */
function generateTestOrgName(prefix = 'Test Org') {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 6);
  return `${prefix} ${timestamp}-${random}`;
}

/**
 * Generate test organization data for creation
 * @param {object} overrides - Override default values
 * @returns {object} Organization creation data
 */
function generateTestOrg(overrides = {}) {
  const name = overrides.name || generateTestOrgName();
  const alias = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
  return {
    name,
    alias,
    membershipMode: 'approval',
    discoverable: true,
    ...overrides,
  };
}

module.exports = {
  SEEDED_ORGS,
  getOrgByAlias,
  getDiscoverableOrgs,
  getOrgsByMembershipMode,
  generateTestOrgName,
  generateTestOrg,
};
