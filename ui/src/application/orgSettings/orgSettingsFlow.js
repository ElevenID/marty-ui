/**
 * Pure helpers for organization settings.
 */

export function parseOrgSettingsResponse(data, { organizationName = '' } = {}) {
  return {
    name: data.organization_name || organizationName || '',
    displayName: data.display_name || data.organization_name || organizationName || '',
    description: data.description || '',
    website: data.website || '',
    contactEmail: data.contact_email || '',
    address: data.address || '',
    country: data.country || '',
    isDiscoverable: data.is_discoverable || false,
    membershipMode: data.membership_mode || 'invite_only',
    allowedEmailDomains: data.allowed_email_domains || [],
    domainJoinPolicy: data.domain_join_policy || 'approval',
    defaultRole: data.default_role || 'member',
    requireDeviceRegistration: data.require_device_registration || false,
    allowPushNotifications: data.allow_push_notifications !== false,
    deviceRegistrationPrompt: data.device_registration_prompt || 'first_action',
  };
}

export function buildOrgSettingsSaveBody(org) {
  return {
    is_discoverable: org.isDiscoverable,
    membership_mode: org.membershipMode,
    allowed_email_domains: org.allowedEmailDomains,
    domain_join_policy: org.domainJoinPolicy,
    default_role: org.defaultRole,
    require_device_registration: org.requireDeviceRegistration,
    allow_push_notifications: org.allowPushNotifications,
    device_registration_prompt: org.deviceRegistrationPrompt,
  };
}
