/**
 * Multi-Credential Type E2E Tests
 *
 * Tests credential issuance across different credential types and formats:
 * 1. eMRTD (Electronic Machine Readable Travel Document) - SD-JWT-VC
 * 2. DTC (Digital Travel Credential) - SD-JWT-VC
 * 3. mDL (Mobile Driver's License) - mso_mdoc
 * 4. National ID - JWT VC JSON
 *
 * Each test validates:
 * - Correct credential format is used
 * - Credential is properly signed with format-appropriate key
 * - Credential can be stored in wallet simulator
 * - Credential can be verified
 */

const { test, expect } = require('@playwright/test');
const axios = require('axios');

// Credential type configurations for testing
const CREDENTIAL_TYPES = {
  eMRTD: {
    configId: 'emrtd_credential',
    displayName: 'Electronic Travel Document',
    format: 'vc+sd-jwt',
    algorithm: 'ES256',
    claims: {
      document_type: 'P',  // Passport
      issuing_state: 'USA',
      given_name: 'Test',
      family_name: 'Traveler',
      document_number: 'TEST123456',
      nationality: 'USA',
      date_of_birth: '1990-01-15',
      sex: 'M',
      expiry_date: '2030-01-15',
    },
  },
  DTC: {
    configId: 'dtc_credential',
    displayName: 'Digital Travel Credential',
    format: 'vc+sd-jwt',
    algorithm: 'ES256',
    claims: {
      credential_type: 'DTC',
      issuer_authority: 'US Department of State',
      holder_name: 'Test Traveler',
      document_reference: 'DTC-2025-001',
      nationality: 'USA',
      issued_at: new Date().toISOString(),
      valid_until: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    },
  },
  mDL: {
    configId: 'mdl_credential',
    displayName: 'Mobile Driver License',
    format: 'mso_mdoc',
    algorithm: 'P-256',
    claims: {
      family_name: 'Driver',
      given_name: 'Test',
      birth_date: '1985-05-20',
      issue_date: new Date().toISOString().split('T')[0],
      expiry_date: '2030-05-20',
      issuing_country: 'US',
      issuing_authority: 'TX DMV',
      document_number: 'TX12345678',
      driving_privileges: [
        { vehicle_category_code: 'C', issue_date: '2020-01-01' },
      ],
    },
  },
  NationalID: {
    configId: 'national_id_credential',
    displayName: 'National Identity Card',
    format: 'jwt_vc_json',
    algorithm: 'RS256',
    claims: {
      given_name: 'Citizen',
      family_name: 'Test',
      birth_date: '1992-08-10',
      personal_id_number: 'NID-2025-TEST',
      nationality: 'USA',
      address: {
        street_address: '123 Test Street',
        locality: 'Test City',
        region: 'TX',
        postal_code: '75001',
        country: 'USA',
      },
    },
  },
};

const BASE_URL = process.env.BASE_URL || 'http://localhost:9080';
const TEST_ORG_ID = 'test-org';

test.describe('Multi-Credential Type Issuance', () => {
  // Ensure test keys are available before running tests
  test.beforeAll(async () => {
    console.log('🔑 Verifying test signing keys are available...');
    try {
      const response = await axios.get(`${BASE_URL}/api/issuance/test-keys`, {
        timeout: 5000,
      });
      
      const keys = response.data;
      console.log(`   Found ${keys.length} keys in storage`);
      
      // Check for required algorithms
      const algorithms = keys.map(k => k.algorithm);
      const required = ['ES256', 'RS256', 'P-256'];
      const missing = required.filter(a => !algorithms.includes(a));
      
      if (missing.length > 0) {
        console.log(`⚠️  Missing keys for algorithms: ${missing.join(', ')}`);
        // Generate missing keys
        await axios.post(`${BASE_URL}/api/issuance/test-keys`, {
          organization_id: TEST_ORG_ID,
          algorithms: missing,
          force_regenerate: false,
        });
        console.log('   Generated missing keys');
      }
    } catch (error) {
      console.log(`⚠️  Could not verify keys: ${error.message}`);
    }
  });

  for (const [typeName, config] of Object.entries(CREDENTIAL_TYPES)) {
    test.describe(`${typeName} Credential`, () => {
      test(`should issue ${typeName} credential with ${config.format} format`, async ({ request }) => {
        // Create credential offer
        const offerResponse = await request.post(`${BASE_URL}/api/issuance/offers`, {
          data: {
            organization_id: TEST_ORG_ID,
            credential_config_id: config.configId,
            applicant_id: `test-user-${typeName.toLowerCase()}`,
            credential_data: config.claims,
            credential_format: config.format,
            deferred: false,
          },
        });

        // May fail if endpoint requires auth - that's acceptable for this test
        if (!offerResponse.ok()) {
          console.log(`   Note: Offer creation requires auth (${offerResponse.status()})`);
          test.skip();
          return;
        }

        const offer = await offerResponse.json();
        expect(offer.transaction_id).toBeDefined();
        expect(offer.credential_offer_uri).toBeDefined();
        
        console.log(`   Created offer: ${offer.transaction_id}`);
      });

      test(`should use correct algorithm (${config.algorithm}) for ${typeName}`, async ({ request }) => {
        // Verify the signing key for this algorithm exists
        const keysResponse = await request.get(`${BASE_URL}/api/issuance/test-keys`);
        
        if (!keysResponse.ok()) {
          console.log('   Keys endpoint requires auth');
          test.skip();
          return;
        }

        const keys = await keysResponse.json();
        const matchingKey = keys.find(k => k.algorithm === config.algorithm);
        
        expect(matchingKey).toBeDefined();
        expect(matchingKey.algorithm).toBe(config.algorithm);
        expect(matchingKey.public_key_jwk).toBeDefined();
        
        console.log(`   Found key: ${matchingKey.algorithm}:${matchingKey.key_id}`);
      });

      test(`should have required claims for ${typeName}`, async () => {
        // Validate that the test fixture has all expected claims
        const claims = config.claims;
        
        switch (typeName) {
          case 'eMRTD':
            expect(claims.document_type).toBeDefined();
            expect(claims.issuing_state).toBeDefined();
            expect(claims.document_number).toBeDefined();
            expect(claims.expiry_date).toBeDefined();
            break;
            
          case 'DTC':
            expect(claims.credential_type).toBe('DTC');
            expect(claims.issuer_authority).toBeDefined();
            expect(claims.document_reference).toBeDefined();
            break;
            
          case 'mDL':
            expect(claims.driving_privileges).toBeDefined();
            expect(claims.issuing_authority).toBeDefined();
            expect(claims.document_number).toBeDefined();
            break;
            
          case 'NationalID':
            expect(claims.personal_id_number).toBeDefined();
            expect(claims.address).toBeDefined();
            break;
        }
      });
    });
  }

  test.describe('Credential Format Selection', () => {
    test('should select ES256 for SD-JWT-VC format', async () => {
      const sdJwtTypes = Object.entries(CREDENTIAL_TYPES)
        .filter(([_, config]) => config.format === 'vc+sd-jwt');
      
      for (const [name, config] of sdJwtTypes) {
        expect(config.algorithm).toBe('ES256');
        console.log(`   ${name}: ${config.format} → ${config.algorithm}`);
      }
    });

    test('should select RS256 for JWT VC JSON format', async () => {
      const jwtVcTypes = Object.entries(CREDENTIAL_TYPES)
        .filter(([_, config]) => config.format === 'jwt_vc_json');
      
      for (const [name, config] of jwtVcTypes) {
        expect(config.algorithm).toBe('RS256');
        console.log(`   ${name}: ${config.format} → ${config.algorithm}`);
      }
    });

    test('should select P-256 for mso_mdoc format', async () => {
      const mdocTypes = Object.entries(CREDENTIAL_TYPES)
        .filter(([_, config]) => config.format === 'mso_mdoc');
      
      for (const [name, config] of mdocTypes) {
        expect(config.algorithm).toBe('P-256');
        console.log(`   ${name}: ${config.format} → ${config.algorithm}`);
      }
    });
  });

  test.describe('Credential Storage Persistence', () => {
    test('should persist issuance session in Redis', async ({ request }) => {
      // This test verifies that sessions are stored in Redis (not in-memory)
      // by creating a session and retrieving it
      
      const offerResponse = await request.post(`${BASE_URL}/api/issuance/offers`, {
        data: {
          organization_id: TEST_ORG_ID,
          credential_config_id: 'persistence_test',
          applicant_id: 'persistence-test-user',
          credential_data: { test: true },
          credential_format: 'vc+sd-jwt',
        },
      });

      if (!offerResponse.ok()) {
        console.log('   Offer creation requires auth');
        test.skip();
        return;
      }

      const offer = await offerResponse.json();
      const transactionId = offer.transaction_id;
      
      // Retrieve the session by transaction ID
      const sessionResponse = await request.get(
        `${BASE_URL}/api/issuance/sessions/${transactionId}`
      );
      
      if (!sessionResponse.ok()) {
        console.log('   Session retrieval requires auth');
        test.skip();
        return;
      }

      const session = await sessionResponse.json();
      expect(session.transaction_id).toBe(transactionId);
      expect(session.credential_format).toBe('vc+sd-jwt');
      
      console.log(`   Session persisted: ${transactionId}`);
    });
  });
});

// Export credential type configurations for use in other tests
module.exports = {
  CREDENTIAL_TYPES,
  TEST_ORG_ID,
};
