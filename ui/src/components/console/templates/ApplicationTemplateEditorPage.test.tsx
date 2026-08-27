import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Route, Routes } from 'react-router'
import { render, renderWithRouter, screen, waitFor } from '@test/utils'

import ApplicationTemplateEditorPage from './ApplicationTemplateEditorPage'
import { formatFieldOptions, parseFieldOptions } from './applicationFieldOptions'
import {
  getApplicationTemplate,
  updateApplicationTemplate,
} from '../../../services/applicationTemplatesApi'

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
  beforeEach(() => vi.clearAllMocks())

  it('round trips structured and legacy select options without losing stable values', () => {
    const options = [
      'PENDING',
      { label: 'Cleared', value: 'CLEARED' },
      { label: 'Manual review', value: 'MANUAL_REVIEW' },
    ]

    const editable = formatFieldOptions(options)

    expect(editable).toBe('PENDING, Cleared=CLEARED, Manual review=MANUAL_REVIEW')
    expect(parseFieldOptions(editable)).toEqual(options)
    expect(parseFieldOptions('legacy=value=with-equals')).toEqual([
      { label: 'legacy', value: 'value=with-equals' },
    ])
  })

  it('edits and saves structured select options without collapsing typed separators', async () => {
    vi.mocked(getApplicationTemplate).mockResolvedValueOnce({
      id: 'application-template-1',
      name: 'Pre-boarding clearance',
      description: '',
      status: 'DRAFT',
      credential_template_id: 'credential-1',
      form_fields: [{
        field_id: 'clearance_status',
        label: 'Clearance status',
        field_type: 'SELECT',
        required: true,
        options: [{ label: 'Cleared', value: 'CLEARED' }],
      }],
      evidence_requirements: [],
      required_checks: [],
      claim_collection_rules: [],
      approval_strategy: 'MANUAL',
      notification_config: {},
      ui_config: {},
    })
    vi.mocked(updateApplicationTemplate).mockResolvedValueOnce({ id: 'application-template-1' })
    const { user } = renderWithRouter(
      <Routes>
        <Route
          path="/console/org/templates/applications/:templateId/edit"
          element={<ApplicationTemplateEditorPage />}
        />
      </Routes>,
      { initialEntries: ['/console/org/templates/applications/application-template-1/edit'] },
    )

    const options = await screen.findByRole('textbox', { name: /options/i })
    expect(options).toHaveValue('Cleared=CLEARED')

    await user.clear(options)
    await user.type(options, 'Pending=PENDING, Cleared=CLEARED')
    expect(options).toHaveValue('Pending=PENDING, Cleared=CLEARED')
    await user.click(screen.getByRole('button', { name: /save draft/i }))

    await waitFor(() => {
      expect(updateApplicationTemplate).toHaveBeenCalledWith(
        'application-template-1',
        expect.objectContaining({
          form_fields: [expect.objectContaining({
            options: [
              { label: 'Pending', value: 'PENDING' },
              { label: 'Cleared', value: 'CLEARED' },
            ],
          })],
        }),
      )
    })
  })

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
