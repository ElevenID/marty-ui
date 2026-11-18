/**
 * Test Data Builders - Generate consistent mock data for E2E tests
 * 
 * Centralizes scattered mock definitions and improves test readability.
 * Follows the Builder pattern for flexible test data generation.
 * 
 * Usage:
 *   const mdl = CredentialDataBuilder.mdl()
 *     .withName('John', 'Doe')
 *     .withBirthDate('1990-01-15')
 *     .build();
 */

class CredentialDataBuilder {
  constructor() {
    this.data = {};
  }

  /**
   * Start building an mDL (mobile Driver's License) credential
   */
  static mdl() {
    const builder = new CredentialDataBuilder();
    builder.data = {
      credential_type: 'org.iso.18013.5.1.mDL',
      document_type: 'driving_license',
      issuing_country: 'US',
      issuing_authority: 'Test DMV',
      document_number: `DL${Date.now().toString().slice(-8)}`,
      issue_date: new Date().toISOString().split('T')[0],
      expiry_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000 * 5).toISOString().split('T')[0],
    };
    return builder;
  }

  /**
   * Start building an employee badge credential
   */
  static employeeBadge() {
    const builder = new CredentialDataBuilder();
    builder.data = {
      credential_type: 'employee_badge',
      employee_id: `EMP-${Date.now()}`,
      department: 'Engineering',
      job_title: 'Software Engineer',
      hire_date: new Date().toISOString().split('T')[0],
    };
    return builder;
  }

  /**
   * Start building a National ID credential
   */
  static nationalId() {
    const builder = new CredentialDataBuilder();
    builder.data = {
      credential_type: 'national_id',
      document_type: 'national_id_card',
      issuing_country: 'US',
      id_number: `ID${Date.now()}`,
      issue_date: new Date().toISOString().split('T')[0],
      expiry_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000 * 10).toISOString().split('T')[0],
    };
    return builder;
  }

  /**
   * Set given name and family name
   */
  withName(givenName, familyName) {
    this.data.given_name = givenName;
    this.data.family_name = familyName;
    return this;
  }

  /**
   * Set birth date (YYYY-MM-DD)
   */
  withBirthDate(birthDate) {
    this.data.birth_date = birthDate;
    this.data.date_of_birth = birthDate; // Some schemas use different keys
    return this;
  }

  /**
   * Set address
   */
  withAddress(street, city, state, postalCode, country = 'US') {
    this.data.address = {
      street_address: street,
      locality: city,
      region: state,
      postal_code: postalCode,
      country: country,
    };
    return this;
  }

  /**
   * Add custom field
   */
  withField(key, value) {
    this.data[key] = value;
    return this;
  }

  /**
   * Build the final credential data object
   */
  build() {
    return { ...this.data };
  }
}

class UserDataBuilder {
  constructor() {
    this.data = {};
  }

  /**
   * Start building an applicant user
   */
  static applicant() {
    const builder = new UserDataBuilder();
    const timestamp = Date.now();
    builder.data = {
      role: 'applicant',
      given_name: 'Test',
      family_name: 'User',
      email: `test-applicant-${timestamp}@example.com`,
      username: `applicant${timestamp}`,
    };
    return builder;
  }

  /**
   * Start building a vendor user
   */
  static vendor() {
    const builder = new UserDataBuilder();
    const timestamp = Date.now();
    builder.data = {
      role: 'vendor',
      given_name: 'Vendor',
      family_name: 'User',
      email: `vendor-${timestamp}@example.com`,
      username: `vendor${timestamp}`,
      organization_name: `Test Org ${timestamp}`,
    };
    return builder;
  }

  /**
   * Set name
   */
  withName(givenName, familyName) {
    this.data.given_name = givenName;
    this.data.family_name = familyName;
    return this;
  }

  /**
   * Set email
   */
  withEmail(email) {
    this.data.email = email;
    return this;
  }

  /**
   * Set organization name (for vendors)
   */
  withOrganization(organizationName) {
    this.data.organization_name = organizationName;
    return this;
  }

  /**
   * Add custom field
   */
  withField(key, value) {
    this.data[key] = value;
    return this;
  }

  /**
   * Build the final user data object
   */
  build() {
    return { ...this.data };
  }
}

/**
 * Mock API responses for common scenarios
 */
const MockResponses = {
  credentialOffer: (transactionId = `tx-${Date.now()}`) => ({
    credential_offer_uri: `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify({
        credential_issuer: 'http://localhost:8000',
        credentials: ['employee_badge'],
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': transactionId,
          },
        },
      })
    )}`,
    transaction_id: transactionId,
    status: 'pending',
  }),

  deviceRegistration: (deviceId = `test-device-${Date.now()}`) => ({
    device_id: deviceId,
    registration_id: `reg-${Date.now()}`,
    registered_at: new Date().toISOString(),
    public_key_kid: `kid-${Date.now()}`,
  }),

  application: (applicationNumber = `APP-${Date.now()}`) => ({
    id: `${Date.now()}`,
    application_number: applicationNumber,
    status: 'pending',
    applicant: {
      given_name: 'Test',
      family_name: 'User',
      email: `test-${Date.now()}@example.com`,
    },
    created_at: new Date().toISOString(),
  }),
};

module.exports = {
  CredentialDataBuilder,
  UserDataBuilder,
  MockResponses,
};
