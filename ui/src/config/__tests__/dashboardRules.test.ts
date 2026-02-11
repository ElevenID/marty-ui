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

describe('dashboardRules', () => {
  describe('computeSetupReadiness', () => {
    it('should return all MISSING when org is empty', () => {
      const data = {
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
      expect(result.trust.path).toBe('/console/trust/profiles/new')

      expect(result.template.state).toBe(ReadinessState.MISSING)
      expect(result.template.dependencyBlocked).toBe(true)

      expect(result.policy.state).toBe(ReadinessState.MISSING)
      expect(result.policy.dependencyBlocked).toBe(true)

      expect(result.deployment.state).toBe(ReadinessState.MISSING)
      expect(result.deployment.dependencyBlocked).toBe(true)

      expect(result.flow.state).toBe(ReadinessState.MISSING)
      expect(result.flow.dependencyBlocked).toBe(true)
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
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'missing',
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
      expect(result.template.message).toContain('missing signing artifacts')
      expect(result.template.blockReason).toContain('missing signing artifacts')
    })

    it('should mark template as READY when active with valid artifacts', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
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

      expect(result.template.state).toBe(ReadinessState.READY)
      expect(result.template.message).toContain('1 active template')
    })

    it('should mark policy as BLOCKED when missing credential requirements', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
          },
        ],
        policies: [
          {
            id: 1,
            status: 'active',
            credential_requirements: [],
          },
        ],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.policy.state).toBe(ReadinessState.BLOCKED)
      expect(result.policy.message).toContain('missing requirements')
      expect(result.policy.blockReason).toBeTruthy()
    })

    it('should mark policy as READY when active with requirements', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
          },
        ],
        policies: [
          {
            id: 1,
            status: 'active',
            credential_requirements: [{ field: 'age', condition: 'gt', value: 21 }],
          },
        ],
        deployments: [],
        flows: [],
        apiKeys: [],
      }

      const result = computeSetupReadiness(data)

      expect(result.policy.state).toBe(ReadinessState.READY)
      expect(result.policy.message).toContain('1 active policy')
    })

    it('should mark deployment as BLOCKED when no API keys exist', () => {
      const data = {
        trustProfiles: [{ id: 1, status: 'active' }],
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
          },
        ],
        policies: [
          {
            id: 1,
            status: 'active',
            credential_requirements: [{ field: 'age' }],
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
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
          },
        ],
        policies: [
          {
            id: 1,
            status: 'active',
            credential_requirements: [{ field: 'age' }],
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
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
          },
        ],
        policies: [
          {
            id: 1,
            status: 'active',
            credential_requirements: [{ field: 'age' }],
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
        templates: [
          {
            id: 1,
            status: 'active',
            artifacts_status: 'valid',
            trust_profile_id: 1,
          },
        ],
        policies: [
          {
            id: 1,
            status: 'active',
            credential_requirements: [{ field: 'age' }],
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
      expect(actions['create-template'].visible).toBe(false)
      expect(actions['create-policy'].visible).toBe(false)
      expect(actions['generate-api-key'].visible).toBe(false)
      expect(actions['start-verification'].visible).toBe(false)
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
      expect(actions['start-verification'].visible).toBe(false)
    })

    it('should show start-verification when deployment ready', () => {
      const readiness = {
        trust: { state: ReadinessState.READY },
        template: { state: ReadinessState.READY },
        policy: { state: ReadinessState.READY },
        deployment: { state: ReadinessState.READY },
        flow: { state: ReadinessState.MISSING },
      }

      const actions = computeQuickActionVisibility(readiness)

      expect(actions['generate-api-key'].visible).toBe(false)
      expect(actions['start-verification'].visible).toBe(true)
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
      expect(actions['start-verification'].visible).toBe(false)
    })
  })
})
