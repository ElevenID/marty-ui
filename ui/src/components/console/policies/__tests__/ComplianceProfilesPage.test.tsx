import { describe, expect, it, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithRouter } from '@test/utils'

import ComplianceProfilesPage from '../ComplianceProfilesPage'

const listComplianceProfiles = vi.fn()

const translations: Record<string, string> = {
  'policies.presentationPolicies': 'Presentation Policies',
  'policies.complianceProfiles': 'Compliance Profiles',
  'complianceProfilesPage.title': 'Compliance Profiles',
  'complianceProfilesPage.description': 'Manage compliance profiles.',
  'complianceProfilesPage.resourceName': 'Compliance Profile',
  'complianceProfilesPage.breadcrumbs.console': 'Console',
  'complianceProfilesPage.breadcrumbs.policies': 'Policies',
  'complianceProfilesPage.breadcrumbs.complianceProfiles': 'Compliance Profiles',
  'complianceProfilesPage.tableHeaders.name': 'Name',
  'complianceProfilesPage.tableHeaders.actions': 'Actions',
  'complianceProfilesPage.emptyState': 'No compliance profiles',
}

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options: Record<string, unknown> = {}) => String(options.defaultValue || translations[key] || key),
  }),
}))

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-123' }),
}))

vi.mock('../../../../services/complianceProfilesApi', () => ({
  listComplianceProfiles: (...args: unknown[]) => listComplianceProfiles(...args),
}))

vi.mock('../../../common', () => ({
  ResourcePage: ({ children, title, tabs }: { children: React.ReactNode; title: string; tabs?: Array<{ label: string }> }) => (
    <div>
      <h1>{title}</h1>
      {tabs?.length ? <div data-testid="resource-tabs">{tabs.map((tab) => tab.label).join(',')}</div> : null}
      {children}
    </div>
  ),
}))

describe('ComplianceProfilesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('loads organization-scoped compliance profiles and renders canonical protocol fields', async () => {
    listComplianceProfiles.mockResolvedValue([
      {
        id: 'compliance-1',
        organization_id: 'org-123',
        name: 'Enterprise VC Baseline',
        compliance_code: 'ENTERPRISE_VC',
        credential_format: 'SD_JWT_VC',
        issuance_protocol: 'OID4VCI_PRE_AUTH',
        is_system: false,
        created_at: '2026-07-09T00:00:00Z',
      },
    ])

    renderWithRouter(<ComplianceProfilesPage />)

    await waitFor(() => {
      expect(listComplianceProfiles).toHaveBeenCalledWith({ organization_id: 'org-123' })
    })

    expect(await screen.findByText('Enterprise VC Baseline')).toBeInTheDocument()
    expect(screen.getByText('ENTERPRISE_VC')).toBeInTheDocument()
    expect(screen.getByText('SD_JWT_VC')).toBeInTheDocument()
    expect(screen.getByText('OID4VCI_PRE_AUTH')).toBeInTheDocument()
    expect(screen.getByText('Organization')).toBeInTheDocument()
  })
})
