export function templateIssuerRequest(data, organizationId) {
  return {
    organization_id: organizationId,
    compliance_profile_id: data.compliance_profile_id,
    ...(data.credential_payload_format ? { credential_payload_format: data.credential_payload_format } : {}),
    ...(Array.isArray(data.supported_formats) ? { supported_formats: data.supported_formats } : {}),
  };
}

export function templateIssuerRequirementsSatisfied(data, requirements) {
  return (!requirements?.vct || Boolean(data.vct?.trim()))
    && (!requirements?.doctype || Boolean(data.doctype?.trim()));
}

export function validTemplateIssuerSelection(data, organizationId) {
  const selection = data._issuer_selection;
  return Boolean(selection && organizationId && data.trust_profile_id && data.issuer_did
    && selection.organization_id === organizationId
    && selection.compliance_profile_id === data.compliance_profile_id
    && selection.trust_profile_id === data.trust_profile_id
    && selection.issuer_did === data.issuer_did
    && selection.credential_payload_format === data.credential_payload_format
    && selection.issuance_protocol === data.issuance_protocol
    && JSON.stringify(selection.supported_formats) === JSON.stringify(data.supported_formats)
    && templateIssuerRequirementsSatisfied(data, selection.requirements));
}
