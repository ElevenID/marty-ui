/** Map the public organization contract to the editable profile. */
export function parseOrgSettingsResponse(data, { organizationId } = {}) {
  if (!data || typeof data !== 'object' || !data.id || data.id !== organizationId
    || typeof data.name !== 'string' || !data.name.trim()
    || typeof data.display_name !== 'string' || !data.display_name.trim()
    || !['PUBLIC', 'PRIVATE'].includes(data.visibility)
    || !['open', 'code', 'invite', 'domain'].includes(data.join_mechanism)
    || typeof data.requires_approval !== 'boolean'
    || ['description', 'website', 'contact_email', 'contact_phone']
      .some((field) => data[field] != null && typeof data[field] !== 'string')) {
    throw new Error('Organization details are unavailable for the selected organization.');
  }

  return {
    name: data.name,
    displayName: data.display_name,
    description: data.description ?? '',
    website: data.website ?? '',
    contactEmail: data.contact_email ?? '',
    contactPhone: data.contact_phone ?? '',
    visibility: data.visibility,
    joinMechanism: data.join_mechanism,
    requiresApproval: data.requires_approval,
  };
}

export function isValidOrganizationName(name) {
  return typeof name === 'string' && /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/.test(name);
}

/** Build a partial update so untouched settings and legacy names are preserved. */
export function buildOrgSettingsSaveBody(org, { originalOrg } = {}) {
  if (!org?.name?.trim() || !org?.displayName?.trim()) {
    throw new Error('Organization name and display name are required.');
  }
  if (org.joinMechanism === 'open' && org.visibility !== 'PUBLIC') {
    throw new Error('Open enrollment requires public organization visibility.');
  }

  const nullableText = (value) => value?.trim() || null;
  const fields = (value) => ({
    name: value.name.trim(),
    displayName: value.displayName.trim(),
    description: nullableText(value.description),
    websiteUrl: nullableText(value.website),
    contactEmail: nullableText(value.contactEmail),
    contactPhone: nullableText(value.contactPhone),
    visibility: value.visibility,
    joinMechanism: value.joinMechanism,
    requiresApproval: value.requiresApproval,
  });
  const previous = originalOrg ? fields(originalOrg) : {};
  const body = Object.fromEntries(Object.entries(fields(org)).filter(([field, value]) => previous[field] !== value));
  if (body.name !== undefined && !isValidOrganizationName(body.name)) {
    throw new Error('Organization name must contain 2–64 lowercase letters, numbers, or hyphens, starting and ending with a letter or number.');
  }
  // The gateway validates open admission against the visibility in this PATCH.
  if (body.joinMechanism === 'open') body.visibility = 'PUBLIC';
  return body;
}
