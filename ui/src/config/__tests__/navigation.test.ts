import { describe, expect, it } from 'vitest'

import { ADMIN_VENDOR_NAV, findActiveNavItem } from '../navigation'

describe('findActiveNavItem', () => {
  it('keeps Govern > Trust Profiles active for trust profile wizard routes', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/trust/profiles/new')).toMatchObject({
      parent: expect.objectContaining({ id: 'govern' }),
      child: expect.objectContaining({ id: 'trust-profiles' }),
    })
  })

  it('prefers the most specific descendant route over the generic org section', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/trust/profiles/profile-123')).toMatchObject({
      parent: expect.objectContaining({ id: 'govern' }),
      child: expect.objectContaining({ id: 'trust-profiles' }),
    })
  })

  it('maps application template routes to the visible Design item', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/templates/applications')).toMatchObject({
      parent: expect.objectContaining({ id: 'design' }),
      child: expect.objectContaining({ id: 'application-templates' }),
    })
  })

  it('keeps Govern > Presentation Policies active for presentation policy routes', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/policies/presentation/new')).toMatchObject({
      parent: expect.objectContaining({ id: 'govern' }),
      child: expect.objectContaining({ id: 'presentation-policies' }),
    })
  })

  it('keeps Design > Flows active for flow definition routes', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/flows/definitions/new')).toMatchObject({
      parent: expect.objectContaining({ id: 'design' }),
      child: expect.objectContaining({ id: 'flows' }),
    })
  })

  it('keeps Connect > Delivery Destinations active', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/connect/delivery-destinations')).toMatchObject({
      parent: expect.objectContaining({ id: 'connect' }),
      child: expect.objectContaining({ id: 'delivery-destinations' }),
    })
  })

  it('keeps Operate > Flow Instances active for instance details', () => {
    expect(findActiveNavItem(ADMIN_VENDOR_NAV, '/console/org/operate/flow-instances/instance-1')).toMatchObject({
      parent: expect.objectContaining({ id: 'operate' }),
      child: expect.objectContaining({ id: 'flow-instances' }),
    })
  })
})
