import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@test/utils'

import ApplicationTemplateEditorPage from './ApplicationTemplateEditorPage'

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}))

vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: vi.fn().mockResolvedValue([
    {
      id: 'credential-1',
      name: 'Membership Badge',
      status: 'ACTIVE',
      revocation_profile_id: 'revocation-1',
      claims: [
        {
          name: 'member_id',
          display_name: 'Member ID',
          type: 'STRING',
          required: true,
        },
      ],
    },
  ]),
}))

vi.mock('../../../services/policySetsApi', () => ({
  listPolicySets: vi.fn().mockResolvedValue([]),
}))

vi.mock('../../../services/applicationTemplatesApi', () => ({
  createApplicationTemplate: vi.fn(),
  getApplicationTemplate: vi.fn(),
  updateApplicationTemplate: vi.fn(),
}))

describe('ApplicationTemplateEditorPage', () => {
  it('names select controls and derives form fields from the active credential template', async () => {
    const { user } = render(<ApplicationTemplateEditorPage />)

    const credentialTemplate = await screen.findByRole('combobox', {
      name: /credential template/i,
    })
    expect(screen.getByRole('combobox', { name: /approval/i })).toBeInTheDocument()

    await user.click(credentialTemplate)
    await user.click(await screen.findByRole('option', { name: 'Membership Badge' }))

    await waitFor(() => {
      expect(screen.getByRole('textbox', { name: /field id/i })).toHaveValue('member_id')
      expect(screen.getByRole('textbox', { name: /^label/i })).toHaveValue('Member ID')
      expect(screen.getByRole('combobox', { name: /^type/i })).toHaveTextContent('TEXT')
    })
  })
})
