/** Defaults may initialize only an active resource from the current organization's catalog. */
export function findOrganizationDefault(resources, id, organizationId, compatible = () => true) {
  if (!id || !organizationId) return null;
  return resources.find((resource) => resource.id === id
    && resource.organization_id === organizationId
    && (String(resource.status || '').trim().toUpperCase() === 'ACTIVE'
      || (!resource.status && resource.is_active === true))
    && compatible(resource)) || null;
}

export function matchesTrust(resource, trustProfileId) {
  return Boolean(resource?.trust_profile_id)
    && (!trustProfileId || resource.trust_profile_id === trustProfileId);
}

function credentialFormat(value) {
  const format = String(value || '').trim().toUpperCase();
  if (['MDOC', 'MSO_MDOC'].includes(format)) return 'MDOC';
  if (['SD_JWT_VC', 'IETF_SD_JWT', 'W3C_VCDM_V2_SD_JWT', 'DC+SD-JWT', 'VC+SD-JWT'].includes(format)) return 'SD_JWT_VC';
  if (['VC_JWT', 'JWT_VC', 'JWT_VC_JSON', 'W3C_VCDM_V2_JWT_VC'].includes(format)) return 'VC_JWT';
  if (['JSON_LD', 'JSON-LD', 'LDP_VC'].includes(format)) return 'JSON_LD';
  return format;
}

export function trustSupportsFormat(profile, format) {
  return !format || (Array.isArray(profile.supported_formats)
    && profile.supported_formats.some((supported) => credentialFormat(supported) === credentialFormat(format)));
}

export function templateMatchesFlow(template, flowType, trustProfileId) {
  if (!matchesTrust(template, trustProfileId)) return false;
  const protocol = String(template.issuance_protocol || '').toUpperCase();
  const format = credentialFormat(template.credential_payload_format || template.format);
  if (!format) return false;
  if (flowType === 'physical_document_issuance') {
    return protocol === 'PHYSICAL_DOCUMENT' && format === 'ICAO_EMRTD';
  }
  if (format === 'ICAO_EMRTD') return false;
  if (flowType === 'oid4vci_authorization_code') return protocol === 'OID4VCI_AUTH_CODE';
  if (flowType === 'oid4vci_pre_authorized') return protocol === 'OID4VCI_PRE_AUTH';
  if (!['OID4VCI_AUTH_CODE', 'OID4VCI_PRE_AUTH'].includes(protocol)) return false;
  if (flowType === 'mdl_issuance') return format === 'MDOC';
  return ['credential_renewal', 'credential_revocation', 'combined'].includes(flowType);
}

export function policyMatchesFlow(policy, flowType, trustProfileId) {
  if (!matchesTrust(policy, trustProfileId)) return false;
  if ((policy.credential_requirements != null && !Array.isArray(policy.credential_requirements))
    || (policy.alternative_requirements != null && !Array.isArray(policy.alternative_requirements))) return false;
  const alternatives = policy.alternative_requirements || [];
  if (alternatives.some((alternative) => !Array.isArray(alternative?.credential_requirements))) return false;
  const requirements = [
    ...(policy.credential_requirements || []),
    ...alternatives.flatMap((alternative) => alternative.credential_requirements),
  ];
  if (requirements.some((requirement) => !requirement?.credential_payload_format)) return false;
  if (flowType === 'mdl_presentation') {
    return requirements.length > 0
      && requirements.every((requirement) => credentialFormat(requirement.credential_payload_format) === 'MDOC');
  }
  if (flowType === 'siopv2') {
    return policy.holder_binding?.required === true && requirements.length === 0
      && alternatives.length === 0 && !(policy.required_claims || []).length;
  }
  return ['oid4vp_presentation', 'combined'].includes(flowType)
    && requirements.every((requirement) => credentialFormat(requirement.credential_payload_format) !== 'ICAO_EMRTD');
}
