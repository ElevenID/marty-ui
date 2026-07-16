import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { render } from '@test/utils'

import ClaimsConfigurationStep from '../steps/ClaimsConfigurationStep'

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-123' }),
}))

vi.mock('../../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: vi.fn().mockResolvedValue([]),
}))

describe('ClaimsConfigurationStep', () => {
  it('renders while credential-template data is still loading', async () => {
    render(
      <ClaimsConfigurationStep
        policyConfig={{
          name: '',
          description: '',
          purpose: '',
          accepted_credential_types: [],
          required_claims: [],
          prefer_predicates: true,
          single_presentation: false,
        }}
        onConfigChange={vi.fn()}
      />,
    )

    expect(screen.getByText('Basic Information')).toBeInTheDocument()
    await screen.findByText('Basic Information')
  })
})
