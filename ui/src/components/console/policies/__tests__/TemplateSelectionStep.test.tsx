import { describe, expect, it, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { render } from '@test/utils'

import TemplateSelectionStep from '../steps/TemplateSelectionStep'

const mockListCredentialTemplates = vi.fn()

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-123' }),
}))

vi.mock('../../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: (...args: unknown[]) => mockListCredentialTemplates(...args),
}))

describe('TemplateSelectionStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListCredentialTemplates.mockResolvedValue([
      {
        id: 'template-employee',
        name: 'Audit Employee Credential',
        description: 'Employee credential template',
        status: 'ACTIVE',
        credential_type: 'VerifiableCredential',
        vct: 'https://credentials.example.com/vct/employee',
        credential_payload_format: 'SD_JWT_VC',
        claims: [
          { name: 'employee_id' },
          { name: 'department' },
        ],
      },
    ])
  })

  it('offers active org credential templates and builds policy config from template claims', async () => {
    const onSelectTemplate = vi.fn()
    const { user } = render(
      <TemplateSelectionStep
        trustProfile={{ id: 'trust-1', trust_framework_type: 'custom' }}
        selectedTemplate={null}
        onSelectTemplate={onSelectTemplate}
      />,
    )

    await waitFor(() => {
      expect(mockListCredentialTemplates).toHaveBeenCalledWith({ organization_id: 'org-123' })
      expect(screen.getByText('Audit Employee Credential')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: /select audit employee credential presentation policy template/i }))

    expect(onSelectTemplate).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 'credential-template:template-employee',
        config: expect.objectContaining({
          accepted_credential_types: ['https://credentials.example.com/vct/employee'],
          required_claims: [
            expect.objectContaining({
              claim_name: 'employee_id',
              credential_type: 'https://credentials.example.com/vct/employee',
            }),
            expect.objectContaining({
              claim_name: 'department',
              credential_type: 'https://credentials.example.com/vct/employee',
            }),
          ],
          credential_requirements: [
            expect.objectContaining({
              credential_template_id: 'template-employee',
              requested_claims: [
                expect.objectContaining({ claim_name: 'employee_id' }),
                expect.objectContaining({ claim_name: 'department' }),
              ],
            }),
          ],
          metadata: expect.objectContaining({
            credential_template_id: 'template-employee',
            credential_template_vct: 'https://credentials.example.com/vct/employee',
          }),
        }),
      }),
    )
  })
})
