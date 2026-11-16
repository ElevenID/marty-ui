import { describe, expect, it, vi } from 'vitest'
import { renderWithoutRouter, screen } from '@test/utils'
import ReviewStep from '../steps/ReviewStep'

const data = {
  name: 'Workplace Safety', credential_type: 'OpenBadgeCredential', vct: '',
  claims: [{ name: 'achievement', type: 'object', required: true }],
  trust_profile_id: 'trust-a', compliance_profile_id: 'compliance-a', revocation_profile_id: 'revocation-a',
  validity_rules: { default_validity_days: 1, max_validity_days: 1, not_before_offset_seconds: 0 },
}
const profileDisplay = {
  trust: { organizationId: 'org-a', id: 'trust-a', name: 'MartyCredentialLoginTrust' },
  compliance: { organizationId: 'org-a', id: 'compliance-a', name: 'OpenBadges3.0' },
  revocation: { organizationId: 'org-a', id: 'revocation-a', name: 'MartyDefaultRevocation' },
}

describe('credential template review', () => {
  it('shows selected profile names, explicit empty VCT and singular validity, with distinct edit actions', async () => {
    const onEdit = vi.fn()
    const { user } = renderWithoutRouter(<ReviewStep data={data} onChange={vi.fn()} onEdit={onEdit}
      organizationId="org-a" profileDisplay={profileDisplay} />)
    for (const profile of Object.values(profileDisplay)) expect(screen.getByText(profile.name)).toBeInTheDocument()
    expect(screen.getByText('Not configured')).toBeInTheDocument()
    expect(screen.getAllByText('1 day')).toHaveLength(2)
    expect(screen.queryByText('1 days')).not.toBeInTheDocument()
    const sections = ['Basic Information', 'Claims', 'Trust & Compliance', 'Cryptography & Validity']
    for (const [index, section] of sections.entries()) {
      await user.click(screen.getByRole('button', { name: `Edit ${section}` }))
      expect(onEdit).toHaveBeenLastCalledWith(index)
    }
  })

  it('keeps current identifiers when cached display names belong to another scope or selection', () => {
    renderWithoutRouter(<ReviewStep data={{ ...data, compliance_profile_id: 'compliance-b' }}
      onChange={vi.fn()} onEdit={vi.fn()} organizationId="org-b" profileDisplay={profileDisplay} />)
    for (const profile of Object.values(profileDisplay)) expect(screen.queryByText(profile.name)).not.toBeInTheDocument()
    for (const id of ['trust-a', 'compliance-b', 'revocation-a']) expect(screen.getByText(id)).toBeInTheDocument()
  })

  it('does not reuse a previous selection name within the same organization and retains plural days', () => {
    renderWithoutRouter(<ReviewStep data={{ ...data, trust_profile_id: 'trust-b', vct: 'urn:badge:workplace',
      validity_rules: { default_validity_days: 2, max_validity_days: 3, not_before_offset_seconds: 0 } }}
      onChange={vi.fn()} onEdit={vi.fn()} organizationId="org-a" profileDisplay={profileDisplay} />)
    expect(screen.queryByText('MartyCredentialLoginTrust')).not.toBeInTheDocument()
    expect(screen.getByText('trust-b')).toBeInTheDocument()
    expect(screen.getByText('OpenBadges3.0')).toBeInTheDocument()
    expect(screen.getByText('urn:badge:workplace')).toBeInTheDocument()
    expect(screen.getByText('2 days')).toBeInTheDocument()
    expect(screen.getByText('3 days')).toBeInTheDocument()
  })
})
