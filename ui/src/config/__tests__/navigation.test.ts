import { describe, expect, it } from 'vitest'

import { ADMIN_VENDOR_NAV, findActiveNavItem } from '../navigation'

describe('findActiveNavItem', () => {
  it('keeps Design > Trust Profiles active for trust profile wizard routes', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/trust/profiles/new')).toMatchObject({
      parent: expect.objectContaining({ id: 'design' }),
      child: expect.objectContaining({ id: 'trust-profiles' }),
    })
  })

  it('prefers the most specific descendant route over the generic org section', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/trust/profiles/profile-123')).toMatchObject({
      parent: expect.objectContaining({ id: 'design' }),
      child: expect.objectContaining({ id: 'trust-profiles' }),
    })
  })

  it('maps deeper template descendants back to the visible credential templates nav item', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/templates/applications')).toMatchObject({
      parent: expect.objectContaining({ id: 'design' }),
      child: expect.objectContaining({ id: 'credential-templates' }),
    })
  })
})