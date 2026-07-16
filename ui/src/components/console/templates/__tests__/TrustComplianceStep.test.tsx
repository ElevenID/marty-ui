import { describe, expect, it, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { screen, waitFor } from '@testing-library/react'
import { renderWithoutRouter } from '@test/utils'

import TrustComplianceStep from '../steps/TrustComplianceStep'

const { mockUseAsyncData } = vi.hoisted(() => ({
  mockUseAsyncData: vi.fn(),
}))

vi.mock('../../../../hooks/useAsyncData', () => ({
  useAsyncData: (...args: unknown[]) => mockUseAsyncData(...args),
}))

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-123' }),
}))

describe('TrustComplianceStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('treats null async data as empty lists instead of crashing', () => {
    mockUseAsyncData
      .mockReturnValueOnce({
        data: null,
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: null,
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: null,
        loading: false,
        error: null,
        reload: vi.fn(),
      })

    renderWithoutRouter(
      <MemoryRouter>
        <TrustComplianceStep
          data={{ trust_profile_id: null, signing_algorithm: 'ES256' }}
          onChange={vi.fn()}
        />
      </MemoryRouter>
    )

    expect(screen.getByText(/trust profile required/i)).toBeInTheDocument()
  })

  it('loads and auto-selects the sole required active compliance profile', async () => {
    const onChange = vi.fn()
    mockUseAsyncData
      .mockReturnValueOnce({
        data: [{ id: 'trust-1', name: 'Production Trust', status: 'active' }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [{
          id: 'issuer-1',
          name: 'Production Issuer',
          issuer_did: 'did:web:issuer.example.com',
          signing_service_id: 'managed-openbao-transit',
          signing_key_reference: 'issuer-key',
          status: 'active',
        }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [
          { id: 'compliance-1', name: 'OID4VC Core', compliance_code: 'OID4VC', status: 'ACTIVE', is_system: true, discoverable: true },
        ],
        loading: false,
        error: null,
        reload: vi.fn(),
      })

    renderWithoutRouter(
      <MemoryRouter>
        <TrustComplianceStep
          data={{ trust_profile_id: 'trust-1', issuer_profile_id: 'issuer-1', signing_algorithm: 'ES256' }}
          onChange={onChange}
        />
      </MemoryRouter>
    )

    expect(screen.getByText(/1 active compliance profile available/i)).toBeInTheDocument()
    expect(screen.getByTestId('template-compliance-profile-select').parentElement?.querySelector('input')).toBeRequired()
    await waitFor(() => {
      expect(onChange).toHaveBeenCalledWith({ compliance_profile_id: 'compliance-1' })
    })
    expect(screen.queryByText(/coming soon/i)).not.toBeInTheDocument()
  })

  it('does not offer active issuer profiles that are missing a KMS signing service', () => {
    mockUseAsyncData
      .mockReturnValueOnce({
        data: [{ id: 'trust-1', name: 'Production Trust', status: 'active' }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [{
          id: 'issuer-1',
          name: 'Unbound Issuer',
          issuer_did: 'did:web:issuer.example.com',
          status: 'active',
        }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [],
        loading: false,
        error: null,
        reload: vi.fn(),
      })

    renderWithoutRouter(
      <MemoryRouter>
        <TrustComplianceStep
          data={{ trust_profile_id: 'trust-1', issuer_profile_id: null, signing_algorithm: 'ES256' }}
          onChange={vi.fn()}
        />
      </MemoryRouter>
    )

    expect(screen.getByText(/active issuer profile required/i)).toBeInTheDocument()
    expect(screen.getByText(/registered KMS signing service/i)).toBeInTheDocument()
    expect(screen.queryByText(/optional compliance profile/i)).not.toBeInTheDocument()
  })

  it('auto-selects a single KMS-backed issuer profile as remote signing input', async () => {
    const onChange = vi.fn()
    mockUseAsyncData
      .mockReturnValueOnce({
        data: [{ id: 'trust-1', name: 'Production Trust', status: 'active' }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [{
          id: 'issuer-1',
          name: 'Production Issuer',
          issuer_did: 'did:web:issuer.example.com',
          signing_service_id: 'managed-openbao-transit',
          signing_key_reference: 'issuer-key',
          status: 'active',
        }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [],
        loading: false,
        error: null,
        reload: vi.fn(),
      })

    renderWithoutRouter(
      <MemoryRouter>
        <TrustComplianceStep
          data={{ trust_profile_id: 'trust-1', issuer_profile_id: null, signing_algorithm: 'ES256' }}
          onChange={onChange}
        />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
        issuer_profile_id: 'issuer-1',
        issuer_did: 'did:web:issuer.example.com',
        issuer_key_id: 'issuer-key',
        key_access_mode: 'REMOTE_SIGNING',
        remote_signing_config: expect.objectContaining({
          signing_service_id: 'managed-openbao-transit',
          signing_key_reference: 'issuer-key',
        }),
      }))
    })
  })
})
