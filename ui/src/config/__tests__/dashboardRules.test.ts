/**
 * Unit Tests for Dashboard Rules
 * 
 * Tests readiness computation, blocker detection, and quick action visibility.
 * These are pure functions with no external dependencies - perfect for unit testing.
 */

import { describe, it, expect } from 'vitest'
import {
  computeSetupReadiness,
  computeBlockers,
  computeQuickActionVisibility,
  ReadinessState,
} from '../dashboardRules'

const activeIssuerProfile = {
  id: 'issuer-profile-1',
  status: 'active',
  issuer_did: 'did:web:issuer.example.com',
  signing_service_id: 'managed-openbao-transit',
}
const templateIssuerFields = {
  issuer_profile_id: activeIssuerProfile.id,
  key_access_mode: 'REMOTE_SIGNING',
}

const readyTrustDependencies = {
  signingKeys: [{ id: 'key_1', name: 'Issuer Key' }],
  issuerProfiles: [activeIssuerProfile],
  keyManagementConfig: {
    default_service_id: 'managed-openbao-transit',
    services: [{ id: 'managed-openbao-transit', name: 'Managed OpenBao', status: 'configured' }],
  },
}

describe('dashboardRules', () => {
  describe('computeSetupReadiness', () => {
    it('should surface missing active compliance profiles when lifecycle reports none', () => {
      const data = {
        ...readyTrustDependencies,
        lifecycle: { complianceProfiles: [] },
        trustProfiles: [],
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)
      const blockers = computeBlockers(result)

      expect(result.compliance.state).toBe(ReadinessState.BLOCKED)
      expect(result.compliance.message).toBe('No active Compliance Profiles')
      expect(result.compliance.path).toBe('/console/org/policies/compliance')
      expect(blockers).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: 'compliance' }),
      ]))
    })

    it('should mark compliance ready when lifecycle reports an active profile', () => {
      const data = {
        ...readyTrustDependencies,
        lifecycle: { complianceProfiles: ['ENTERPRISE_VC'] },
        trustProfiles: [],
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.compliance.state).toBe(ReadinessState.READY)
      expect(result.compliance.message).toContain('1 active Compliance Profile')
    })

    it('should return all MISSING when org is empty', () => {
      const data = {
        ...readyTrustDependencies,
        trustProfiles: [],
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.trust.state).toBe(ReadinessState.MISSING)
      expect(result.trust.message).toBe('No Trust Profiles configured')
      expect(result.trust.action).toBe('Create')
      expect(result.trust.path).toBe('/console/org/trust/profiles/new')

      expect(result.template.state).toBe(ReadinessState.MISSING)
      expect(result.template.dependencyBlocked).toBe(true)

      expect(result.policy.state).toBe(ReadinessState.MISSING)
      expect(result.policy.dependencyBlocked).toBe(true)

      expect(result.deployment.state).toBe(ReadinessState.MISSING)
      expect(result.deployment.dependencyBlocked).toBe(true)

      expect(result.flow.state).toBe(ReadinessState.MISSING)
      expect(result.flow.dependencyBlocked).toBe(true)
    })

    it('should let verifier setup progress without issuer identity or credential templates', () => {
      const data = {
        setupIntent: 'verify',
        trustProfiles: [{ id: 1, status: 'active' }],
        signingKeys: [],
        issuerProfiles: [],
        keyManagementConfig: {
          default_service_id: null,
          services: [],
        },
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)
      const actions = computeQuickActionVisibility(result)

      expect(result.activeIntent).toBe('verify')
      expect(result.intents.verify.steps.trust.state).toBe(ReadinessState.READY)
      expect(result.intents.verify.steps.policy.state).toBe(ReadinessState.MISSING)
      expect(result.intents.verify.steps.policy.dependencyBlocked).toBeUndefined()
      expect(result.intents.verify.steps.template).toBeUndefined()
      expect(actions['create-policy'].visible).toBe(true)
      expect(actions['create-template'].visible).toBe(false)
      expect(actions['register-signing-service'].visible).toBe(false)
    })

    it('should keep issuer identity and KMS as blockers for issue setup', () => {
      const data = {
        setupIntent: 'issue',
        trustProfiles: [],
        signingKeys: [],
        issuerProfiles: [],
        keyManagementConfig: {
          default_service_id: null,
          services: [],
        },
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)
      const actions = computeQuickActionVisibility(result)

      expect(result.activeIntent).toBe('issue')
      expect(result.intents.issue.steps.issuer.state).toBe(ReadinessState.BLOCKED)
      expect(result.intents.issue.steps.issuer.path).toBe('/console/org/deploy/key-management')
      expect(actions['register-signing-service'].visible).toBe(true)
      expect(actions['create-trust-profile'].visible).toBe(false)
    })

    it('should not require a Deployment Profile for a protocol-valid verification flow', () => {
      const data = {
        setupIntent: 'verify',
        trustProfiles: [{ id: 'trust-1', status: 'active' }],
        signingKeys: [],
        issuerProfiles: [],
        keyManagementConfig: { default_service_id: null, services: [] },
        templates: [],
        policies: [{ id: 'policy-1', required_claims: ['given_name'] }],
        deployments: [],
        flows: [{ id: 'flow-1', status: 'ACTIVE', flow_type: 'oid4vp_presentation', presentation_policy_id: 'policy-1' }],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.intents.verify.steps.deployment).toBeUndefined()
      expect(result.intents.verify.steps.flow.state).toBe(ReadinessState.READY)
    })

    it('should require an active approval Policy Set for application setup without requiring deployment', () => {
      const data = {
        setupIntent: 'application',
        ...readyTrustDependencies,
        trustProfiles: [],
        templates: [],
        applicationTemplates: [{ id: 'application-1', status: 'active' }],
        policySets: [{ id: 'set-1', status: 'ACTIVE', policy_type: 'APPROVAL_RULES' }],
        policies: [],
        deployments: [],
        flows: [{ id: 'flow-1', status: 'ACTIVE', flow_type: 'application_approval_issuance', application_template_id: 'application-1' }],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.intents.application.steps.policySet.state).toBe(ReadinessState.READY)
      expect(result.intents.application.steps.deployment).toBeUndefined()
      expect(result.intents.application.steps.flow.state).toBe(ReadinessState.READY)
    })

    it('should expose every physical issuance dependency and fail closed on capability blockers', () => {
      const data = {
        setupIntent: 'physical',
        ...readyTrustDependencies,
        trustProfiles: [{ id: 'trust-1', status: 'active' }],
        templates: [{
          id: 'template-1',
          status: 'active',
          artifacts_status: 'valid',
          trust_profile_id: 'trust-1',
          ...templateIssuerFields,
        }],
        applicationTemplates: [{ id: 'application-1', status: 'active' }],
        deliveryDestinations: [],
        physicalDocumentCapabilities: { supported: false, blockers: ['Configure personalization bureau.'] },
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)
      const physical = result.intents.physical.steps

      expect(physical.physicalCapability.state).toBe(ReadinessState.BLOCKED)
      expect(physical.physicalCapability.message).toContain('personalization bureau')
      expect(physical.deliveryDestination.dependencyBlocked).toBe(true)
      expect(physical.flow.dependencyBlocked).toBe(true)
    })

    it('should mark a fully referenced physical issuance recipe ready', () => {
      const data = {
        setupIntent: 'physical',
        ...readyTrustDependencies,
        trustProfiles: [{ id: 'trust-1', status: 'active' }],
        templates: [{
          id: 'template-1',
          status: 'active',
          artifacts_status: 'valid',
          trust_profile_id: 'trust-1',
          ...templateIssuerFields,
        }],
        applicationTemplates: [{ id: 'application-1', status: 'active' }],
        deliveryDestinations: [{ id: 'bureau-1', is_enabled: true, provider: 'physical_document_bureau' }],
        physicalDocumentCapabilities: { supported: true, blockers: [] },
        policies: [],
        deployments: [],
        flows: [{
          id: 'flow-1',
          status: 'ACTIVE',
          flow_type: 'physical_document_issuance',
          credential_template_id: 'template-1',
          application_template_id: 'application-1',
          delivery_destination_profile_id: 'bureau-1',
        }],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)
      const physical = result.intents.physical.steps

      expect(Object.values(physical).every((step) => step.state === ReadinessState.READY)).toBe(true)
    })

    it('should mark setup data unavailable instead of treating failed artifact loads as empty setup', () => {
      const data = {
        ...readyTrustDependencies,
        trustProfiles: [],
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
        resourceErrors: {
          trustProfiles: {
            message: 'service unavailable',
            message_id: 'msg-trust-503',
          },
        },
      }

      const result = computeSetupReadiness(data)
      const blockers = computeBlockers(result)

      expect(result.trust.state).toBe(ReadinessState.BLOCKED)
      expect(result.trust.serviceError).toBe(true)
      expect(result.trust.message).toContain('msg-trust-503')
      expect(result.trust.message).not.toContain('No Trust Profiles configured')
      expect(result.template.dependencyBlocked).toBe(true)
      expect(blockers[0]).toMatchObject({
        id: 'trust',
        reason: expect.stringContaining('setup readiness cannot be trusted'),
      })
    })

    it('should block trust when key management is missing and no trust profile exists', () => {
      const data = {
        trustProfiles: [],
        signingKeys: [],
        issuerProfiles: [],
        keyManagementConfig: {
          default_service_id: null,
          services: [],
        },
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.trust.state).toBe(ReadinessState.BLOCKED)
      expect(result.trust.action).toBe('Configure KMS')
      expect(result.trust.path).toBe('/console/org/deploy/key-management')
      expect(result.template.dependencyBlocked).toBe(true)
    })

    it('should block trust when issuer input is missing and no trust profile exists', () => {
      const data = {
        trustProfiles: [],
        signingKeys: [],
        issuerProfiles: [],
        keyManagementConfig: {
          default_service_id: 'managed-openbao-transit',
          services: [{ id: 'managed-openbao-transit', name: 'Managed OpenBao', status: 'configured' }],
        },
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.trust.state).toBe(ReadinessState.BLOCKED)
      expect(result.trust.action).toBe('Set Up Issuer Identity')
      expect(result.trust.path).toBe('/console/org/deploy/issuer-identity')
      expect(result.template.dependencyBlocked).toBe(true)
    })

    it('should mark trust as BLOCKED when profile exists but inactive', () => {
      const data = {
        trustProfiles: [
          {
            id: 1,
            status: 'inactive',
            name: 'Inactive Trust',
          },
        ],
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.trust.state).toBe(ReadinessState.BLOCKED)
      expect(result.trust.message).toContain('none active')
      expect(result.trust.blockReason).toBeTruthy()
    })

    it('should mark trust as READY when active profile exists', () => {
      const data = {
        trustProfiles: [
          {
            id: 1,
            status: 'active',
            name: 'Active Trust',
          },
        ],
        templates: [],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.trust.state).toBe(ReadinessState.READY)
      expect(result.trust.message).toContain('1 active Trust Profile')
      expect(result.trust.blockReason).toBeNull()
    })

    it('should mark template as BLOCKED when artifacts are missing', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [activeIssuerProfile],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'missing',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.template.state).toBe(ReadinessState.BLOCKED)
      expect(result.template.message).toContain('missing signing artifacts')
      expect(result.template.blockReason).toContain('missing signing artifacts')
    })

    it('should mark template as READY when active with valid artifacts', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [activeIssuerProfile],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.template.state).toBe(ReadinessState.READY)
      expect(result.template.message).toContain('1 active template')
    })

    it('should mark template as BLOCKED when no active KMS-backed issuer profile is bound', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [activeIssuerProfile],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
          },
        ],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.template.state).toBe(ReadinessState.BLOCKED)
      expect(result.template.message).toContain('missing active KMS-backed issuer profile')
      expect(result.template.blockReason).toContain('missing active KMS-backed issuer profile')
      expect(result.policy.dependencyBlocked).toBe(true)
    })

    it('should mark template as BLOCKED when the referenced issuer profile is inactive', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [{ ...activeIssuerProfile, status: 'inactive' }],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.template.state).toBe(ReadinessState.BLOCKED)
      expect(result.template.message).toContain('missing active KMS-backed issuer profile')
      expect(result.policy.dependencyBlocked).toBe(true)
    })

    it('should mark template as BLOCKED when the referenced issuer profile has no KMS signing service', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [{
          id: activeIssuerProfile.id,
          status: 'active',
          issuer_did: 'did:web:issuer.example.com',
        }],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.template.state).toBe(ReadinessState.BLOCKED)
      expect(result.template.message).toContain('missing active KMS-backed issuer profile')
      expect(result.policy.dependencyBlocked).toBe(true)
    })

    it('should mark policy as BLOCKED when missing required claims', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [activeIssuerProfile],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [
          {
            id: 1,
            required_claims: [],
          },
        ],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.policy.state).toBe(ReadinessState.BLOCKED)
      expect(result.policy.message).toContain('missing required claims')
      expect(result.policy.blockReason).toBeTruthy()
    })

    it('should mark policy as READY when configured with required claims', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [activeIssuerProfile],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [
          {
            id: 1,
            required_claims: [{ claim_name: 'age', credential_type: 'IdentityCredential' }],
          },
        ],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.policy.state).toBe(ReadinessState.READY)
      expect(result.policy.message).toContain('1 policy')
    })

    it('should mark deployment as BLOCKED when no API keys exist', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [activeIssuerProfile],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [
          {
            id: 1,
            required_claims: [{ claim_name: 'age' }],
          },
        ],
        deployments: [{ id: 1, status: 'active' }],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.deployment.state).toBe(ReadinessState.BLOCKED)
      expect(result.deployment.message).toContain('no API keys')
      expect(result.deployment.blockReason).toContain('no API key')
    })

    it('should mark deployment as READY when active with API keys', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [activeIssuerProfile],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [
          {
            id: 1,
            required_claims: [{ claim_name: 'age' }],
          },
        ],
        deployments: [{ id: 1, status: 'active' }],
        flows: [],
        apiKeys: [{ id: 1, key: 'test-key' }],
      }

      const result = computeSetupReadiness(data)

      expect(result.deployment.state).toBe(ReadinessState.READY)
      expect(result.deployment.message).toContain('1 active Deployment')
      expect(result.deployment.message).toContain('1 API key')
    })

    it('should mark flow as BLOCKED when missing references', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [activeIssuerProfile],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [
          {
            id: 1,
            required_claims: [{ claim_name: 'age' }],
          },
        ],
        deployments: [{ id: 1, status: 'active' }],
        flows: [
          {
            id: 1,
            status: 'active',
            trust_profile_id: null, // Missing
            presentation_policy_id: null,
            credential_template_id: null,
          },
        ],
        apiKeys: [{ id: 1 }],
      }

      const result = computeSetupReadiness(data)

      expect(result.flow.state).toBe(ReadinessState.BLOCKED)
      expect(result.flow.message).toContain('missing references')
      expect(result.flow.blockReason).toBeTruthy()
    })

    it('should mark all as READY in fully configured org', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        issuerProfiles: [activeIssuerProfile],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
            ...templateIssuerFields,
          },
        ],
        policies: [
          {
            id: 1,
            required_claims: [{ claim_name: 'age' }],
          },
        ],
        deployments: [{ id: 1, status: 'active' }],
        flows: [
          {
            id: 1,
            status: 'active',
            trust_profile_id: 1,
            presentation_policy_id: 1,
          },
        ],
        apiKeys: [{ id: 1 }],
      }

      const result = computeSetupReadiness(data)

      expect(result.trust.state).toBe(ReadinessState.READY)
      expect(result.template.state).toBe(ReadinessState.READY)
      expect(result.policy.state).toBe(ReadinessState.READY)
      expect(result.deployment.state).toBe(ReadinessState.READY)
      expect(result.flow.state).toBe(ReadinessState.READY)
    })
  })

  describe('computeBlockers', () => {
    it('should return empty array when no blockers', () => {
      const readiness = {
        trust: { state: ReadinessState.READY },
        template: { state: ReadinessState.READY },
        policy: { state: ReadinessState.READY },
        deployment: { state: ReadinessState.READY },
        flow: { state: ReadinessState.READY },
      }

      const blockers = computeBlockers(readiness)

      expect(blockers).toEqual([])
    })

    it('should extract blockers with fix actions', () => {
      const readiness = {
        trust: { state: ReadinessState.READY },
        template: {
          state: ReadinessState.BLOCKED,
          blockReason: 'Missing signing artifacts',
          action: 'Fix',
          path: '/console/templates',
        },
        policy: { state: ReadinessState.MISSING },
        deployment: {
          state: ReadinessState.BLOCKED,
          blockReason: 'No API key',
          action: 'Generate',
          path: '/console/api-keys',
        },
        flow: { state: ReadinessState.MISSING },
      }

      const blockers = computeBlockers(readiness)

      expect(blockers).toHaveLength(2)
      expect(blockers[0]).toEqual({
        id: 'template',
        reason: 'Missing signing artifacts',
        action: 'Fix',
        path: '/console/templates',
      })
      expect(blockers[1]).toEqual({
        id: 'deployment',
        reason: 'No API key',
        action: 'Generate',
        path: '/console/api-keys',
      })
    })

    it('should not include MISSING items without blockReason', () => {
      const readiness = {
        trust: {
          state: ReadinessState.MISSING,
          message: 'No Trust Profiles',
          blockReason: null,
        },
        template: { state: ReadinessState.MISSING },
      }

      const blockers = computeBlockers(readiness)

      expect(blockers).toEqual([])
    })
  })

  describe('computeQuickActionVisibility', () => {
    it('should show register-signing-service when trust is blocked on key management', () => {
      const readiness = {
        trust: { state: ReadinessState.BLOCKED, path: '/console/org/deploy/key-management' },
        template: { state: ReadinessState.MISSING, dependencyBlocked: true },
        policy: { state: ReadinessState.MISSING, dependencyBlocked: true },
        deployment: { state: ReadinessState.MISSING, dependencyBlocked: true },
        flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
      }

      const actions = computeQuickActionVisibility(readiness)

      expect(actions['register-signing-service'].visible).toBe(true)
      expect(actions['create-trust-profile'].visible).toBe(false)
      expect(actions['create-template'].visible).toBe(false)
    })

    it('should show create-issuer-identity when trust is blocked on issuer input', () => {
      const readiness = {
        trust: { state: ReadinessState.BLOCKED, path: '/console/org/deploy/issuer-identity' },
        template: { state: ReadinessState.MISSING, dependencyBlocked: true },
        policy: { state: ReadinessState.MISSING, dependencyBlocked: true },
        deployment: { state: ReadinessState.MISSING, dependencyBlocked: true },
        flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
      }

      const actions = computeQuickActionVisibility(readiness)

      expect(actions['register-signing-service'].visible).toBe(false)
      expect(actions['create-issuer-identity'].visible).toBe(true)
      expect(actions['create-trust-profile'].visible).toBe(false)
    })

    it('should show create-trust-profile when trust is missing', () => {
      const readiness = {
        trust: { state: ReadinessState.MISSING },
        template: { state: ReadinessState.MISSING, dependencyBlocked: true },
        policy: { state: ReadinessState.MISSING, dependencyBlocked: true },
        deployment: { state: ReadinessState.MISSING, dependencyBlocked: true },
        flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
      }

      const actions = computeQuickActionVisibility(readiness)

      expect(actions['create-trust-profile'].visible).toBe(true)
      expect(actions['register-signing-service'].visible).toBe(false)
      expect(actions['create-issuer-identity'].visible).toBe(false)
      expect(actions['create-template'].visible).toBe(false)
      expect(actions['create-policy'].visible).toBe(false)
      expect(actions['generate-api-key'].visible).toBe(false)
      expect(actions['create-flow'].visible).toBe(false)
    })

    it('should show create-template when trust ready but template not', () => {
      const readiness = {
        trust: { state: ReadinessState.READY },
        template: { state: ReadinessState.MISSING },
        policy: { state: ReadinessState.MISSING, dependencyBlocked: true },
        deployment: { state: ReadinessState.MISSING, dependencyBlocked: true },
        flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
      }

      const actions = computeQuickActionVisibility(readiness)

      expect(actions['create-trust-profile'].visible).toBe(false)
      expect(actions['create-template'].visible).toBe(true)
      expect(actions['create-policy'].visible).toBe(false)
    })

    it('should show create-policy when trust and template ready', () => {
      const readiness = {
        trust: { state: ReadinessState.READY },
        template: { state: ReadinessState.READY },
        policy: { state: ReadinessState.MISSING },
        deployment: { state: ReadinessState.MISSING, dependencyBlocked: true },
        flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
      }

      const actions = computeQuickActionVisibility(readiness)

      expect(actions['create-trust-profile'].visible).toBe(false)
      expect(actions['create-template'].visible).toBe(false)
      expect(actions['create-policy'].visible).toBe(true)
      expect(actions['generate-api-key'].visible).toBe(false)
    })

    it('should show generate-api-key when policy ready', () => {
      const readiness = {
        trust: { state: ReadinessState.READY },
        template: { state: ReadinessState.READY },
        policy: { state: ReadinessState.READY },
        deployment: { state: ReadinessState.MISSING },
        flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
      }

      const actions = computeQuickActionVisibility(readiness)

      expect(actions['create-policy'].visible).toBe(false)
      expect(actions['generate-api-key'].visible).toBe(true)
      expect(actions['create-flow'].visible).toBe(false)
    })

    it('should show create-flow when deployment ready', () => {
      const readiness = {
        trust: { state: ReadinessState.READY },
        template: { state: ReadinessState.READY },
        policy: { state: ReadinessState.READY },
        deployment: { state: ReadinessState.READY },
        flow: { state: ReadinessState.MISSING },
      }

      const actions = computeQuickActionVisibility(readiness)

      expect(actions['generate-api-key'].visible).toBe(false)
      expect(actions['create-flow'].visible).toBe(true)
    })

    it('should hide all actions when fully ready', () => {
      const readiness = {
        trust: { state: ReadinessState.READY },
        template: { state: ReadinessState.READY },
        policy: { state: ReadinessState.READY },
        deployment: { state: ReadinessState.READY },
        flow: { state: ReadinessState.READY },
      }

      const actions = computeQuickActionVisibility(readiness)

      expect(actions['create-trust-profile'].visible).toBe(false)
      expect(actions['create-template'].visible).toBe(false)
      expect(actions['create-policy'].visible).toBe(false)
      expect(actions['generate-api-key'].visible).toBe(false)
      expect(actions['create-flow'].visible).toBe(false)
    })

    it.each([
      [
        'trust profile load fails',
        {
          trust: { state: ReadinessState.BLOCKED, serviceError: true },
          template: { state: ReadinessState.MISSING, dependencyBlocked: true },
          policy: { state: ReadinessState.MISSING, dependencyBlocked: true },
          deployment: { state: ReadinessState.MISSING, dependencyBlocked: true },
          flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
        },
      ],
      [
        'template load fails',
        {
          trust: { state: ReadinessState.READY },
          template: { state: ReadinessState.BLOCKED, serviceError: true },
          policy: { state: ReadinessState.MISSING, dependencyBlocked: true },
          deployment: { state: ReadinessState.MISSING, dependencyBlocked: true },
          flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
        },
      ],
      [
        'policy load fails',
        {
          trust: { state: ReadinessState.READY },
          template: { state: ReadinessState.READY },
          policy: { state: ReadinessState.BLOCKED, serviceError: true },
          deployment: { state: ReadinessState.MISSING, dependencyBlocked: true },
          flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
        },
      ],
      [
        'deployment or API key load fails',
        {
          trust: { state: ReadinessState.READY },
          template: { state: ReadinessState.READY },
          policy: { state: ReadinessState.READY },
          deployment: { state: ReadinessState.BLOCKED, serviceError: true },
          flow: { state: ReadinessState.MISSING, dependencyBlocked: true },
        },
      ],
      [
        'flow load fails',
        {
          trust: { state: ReadinessState.READY },
          template: { state: ReadinessState.READY },
          policy: { state: ReadinessState.READY },
          deployment: { state: ReadinessState.READY },
          flow: { state: ReadinessState.BLOCKED, serviceError: true },
        },
      ],
    ])('should hide quick actions when %s', (_name, readiness) => {
      const actions = computeQuickActionVisibility(readiness)

      expect(Object.values(actions).every((action) => action.visible === false)).toBe(true)
    })
  })
})
