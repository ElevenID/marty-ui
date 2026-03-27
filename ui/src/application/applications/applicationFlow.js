/**
 * Pure helpers for applicant application flows.
 */

const PERSONAL_FIELDS = ['first_name', 'last_name', 'family_name', 'given_name', 'date_of_birth', 'birth_date', 'email', 'phone', 'nationality', 'sex', 'gender'];
const ADDRESS_FIELDS = ['street', 'city', 'state', 'zip', 'postal_code', 'country', 'address'];
const DOCUMENT_FIELDS = ['document_number', 'license_class', 'driving_privileges', 'restrictions', 'issue_date', 'expiry_date'];
const PHOTO_FIELDS = ['portrait', 'signature', 'photo'];
const MDL_CREDENTIAL_TYPE = 'org.iso.18013.5.1.mDL';
const MEMBER_CREDENTIAL_TYPE = 'MemberCredential';
const MDOC_MEMBER_CREDENTIAL_TYPE = 'com.elevenid.member_credential';
const OPEN_BADGE_CREDENTIAL_TYPE = 'open_badge';
const ACCESS_BADGE_CREDENTIAL_TYPE = 'access_badge';

export function normalizeCredentialConfigInput(config) {
  if (!config) {
    return null;
  }

  const requiredFields = Array.isArray(config.required_fields)
    ? config.required_fields
    : (Array.isArray(config.requiredFields) ? config.requiredFields : []);
  const optionalFields = Array.isArray(config.optional_fields)
    ? config.optional_fields
    : (Array.isArray(config.optionalFields) ? config.optionalFields : []);
  const customFields = Array.isArray(config.custom_fields)
    ? config.custom_fields
    : (Array.isArray(config.customFields) ? config.customFields : []);

  return {
    ...config,
    id: config.id,
    credential_type: config.credential_type || config.credentialType,
    display_name: config.display_name || config.name,
    required_fields: requiredFields,
    optional_fields: optionalFields,
    custom_fields: customFields,
    field_validation_rules: config.field_validation_rules || {},
  };
}

export function normalizeTemplateToFormConfig(template) {
  const claims = Array.isArray(template?.claims) ? template.claims : [];
  const requiredClaims = claims.filter((claim) => claim?.required).map((claim) => claim?.name).filter(Boolean);
  const optionalClaims = claims.filter((claim) => !claim?.required).map((claim) => claim?.name).filter(Boolean);

  return {
    id: template?.id,
    credentialType: template?.credential_type,
    credential_type: template?.credential_type,
    name: template?.name,
    display_name: template?.name,
    description: template?.description,
    required_fields: requiredClaims,
    optional_fields: optionalClaims,
    custom_fields: [],
    field_validation_rules: {},
    submission_instructions: null,
    validity_rules: template?.validity_rules || null,
    issuer_requirements: template?.issuer_requirements || {},
    claims,
  };
}

function normalizeField(field, required) {
  if (typeof field === 'string') {
    return { name: field, required };
  }

  return {
    name: field?.name,
    required,
    ...field,
  };
}

export function groupFieldsIntoSteps(requiredFields = [], optionalFields = [], customFields = [], t) {
  const steps = [];

  const allFields = [
    ...requiredFields.map((field) => normalizeField(field, true)),
    ...optionalFields.map((field) => normalizeField(field, false)),
    ...customFields.map((field) => normalizeField(field, false)),
  ];

  const personal = allFields.filter((field) => PERSONAL_FIELDS.some((name) => field.name?.toLowerCase().includes(name)));
  const address = allFields.filter((field) => ADDRESS_FIELDS.some((name) => field.name?.toLowerCase().includes(name)));
  const document = allFields.filter((field) => DOCUMENT_FIELDS.some((name) => field.name?.toLowerCase().includes(name)));
  const photo = allFields.filter((field) => PHOTO_FIELDS.some((name) => field.name?.toLowerCase().includes(name)));
  const other = allFields.filter((field) => !personal.includes(field) && !address.includes(field) && !document.includes(field) && !photo.includes(field));

  if (personal.length > 0) steps.push({ label: t('applicationForm.steps.personalInfo'), fields: personal });
  if (address.length > 0) steps.push({ label: t('applicationForm.steps.address'), fields: address });
  if (document.length > 0) steps.push({ label: t('applicationForm.steps.documentDetails'), fields: document });
  if (other.length > 0) steps.push({ label: t('applicationForm.steps.additionalInfo'), fields: other });
  if (photo.length > 0) steps.push({ label: t('applicationForm.steps.photos'), fields: photo });
  steps.push({ label: t('applicationForm.steps.review'), fields: [] });

  return steps;
}

export function getCredentialKindFlags(credentialConfig) {
  const credentialType = credentialConfig?.credential_type;
  const isMemberCredential = credentialType === MEMBER_CREDENTIAL_TYPE;
  const isMdlCredential = credentialType === MDL_CREDENTIAL_TYPE;
  const isMdocMemberCredential = credentialType === MDOC_MEMBER_CREDENTIAL_TYPE;
  const isOpenBadgeCredential = credentialType === OPEN_BADGE_CREDENTIAL_TYPE;
  const isAccessBadgeCredential = credentialType === ACCESS_BADGE_CREDENTIAL_TYPE;

  return {
    isMemberCredential,
    isMdlCredential,
    isMdocMemberCredential,
    isOpenBadgeCredential,
    isAccessBadgeCredential,
    isOneClickCredential: isMemberCredential || isMdlCredential || isMdocMemberCredential || isOpenBadgeCredential || isAccessBadgeCredential,
  };
}

export function buildApplicantProfileData({ organizationId, user, formData }) {
  const applicantData = {
    organization_id: organizationId,
    user_id: user.user_id,
    given_name: formData.given_name || formData.first_name || '',
    family_name: formData.family_name || formData.last_name || '',
    email: formData.email || user.email,
    date_of_birth: formData.date_of_birth || formData.birth_date,
    nationality: formData.nationality || 'USA',
  };

  const address = {};
  if (formData.street) address.street_line1 = formData.street;
  if (formData.city) address.city = formData.city;
  if (formData.state) address.state_province = formData.state;
  if (formData.zip || formData.postal_code) address.postal_code = formData.zip || formData.postal_code;
  if (formData.country) address.country = formData.country;
  else address.country = 'USA';

  if (Object.keys(address).length > 0) {
    applicantData.address = address;
  }

  return applicantData;
}

export function buildStandardApplicationPayload({ applicantId, credentialConfig, credentialConfigId, formData }) {
  return {
    applicant_id: applicantId,
    credential_configuration_id: credentialConfig?.id || credentialConfigId,
    issuing_authority: 'ElevenID LLC',
    requested_validity_years: 10,
    metadata: {
      document_number: formData.documentNumber,
      credential_type: credentialConfig?.credentialType || credentialConfig?.credential_type,
      credential_display_name: credentialConfig?.name || credentialConfig?.display_name,
      license_class: formData.licenseClass,
      restrictions: formData.restrictions,
    },
  };
}

export function buildAutoApplyContext({ credentialConfig, user, organizationId, nowIso = new Date().toISOString() }) {
  const { isMdlCredential, isMdocMemberCredential, isOpenBadgeCredential, isAccessBadgeCredential } = getCredentialKindFlags(credentialConfig);
  const role = (user.roles || []).find((value) => ['applicant', 'vendor', 'administrator'].includes(value)) || 'applicant';

  if (isOpenBadgeCredential) {
    return {
      requested_validity_years: 1,
      metadata: {
        credential_type: OPEN_BADGE_CREDENTIAL_TYPE,
        credential_display_name: credentialConfig?.name || 'Professional Certificate',
        given_name: user.given_name || '',
        family_name: user.family_name || '',
        email: user.email,
        achievement_name: 'Platform Onboarding',
        course_name: 'ElevenID Getting Started',
        completion_date: nowIso.slice(0, 10),
        institution_name: 'ElevenID LLC',
        certificate_id: `OB-${user.user_id?.slice(0, 8)?.toUpperCase() || '00000000'}`,
        auto_approve: true,
      },
    };
  }

  if (isAccessBadgeCredential) {
    return {
      requested_validity_years: 1,
      metadata: {
        credential_type: ACCESS_BADGE_CREDENTIAL_TYPE,
        credential_display_name: credentialConfig?.name || 'Employee Access Badge',
        given_name: user.given_name || '',
        family_name: user.family_name || '',
        email: user.email,
        employee_id: `EMP-${user.user_id?.slice(0, 8)?.toUpperCase() || '00000000'}`,
        department: 'Engineering',
        job_title: 'Platform Member',
        clearance_level: 'general',
        building_access: 'HQ-A, HQ-B',
        issue_date: nowIso.slice(0, 10),
        expiry_date: new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10),
        auto_approve: true,
      },
    };
  }

  if (isMdocMemberCredential) {
    return {
      requested_validity_years: 1,
      metadata: {
        credential_type: MDOC_MEMBER_CREDENTIAL_TYPE,
        credential_display_name: credentialConfig?.name || 'Membership ID (mDoc)',
        member_id: user.user_id,
        user_id: user.user_id,
        email: user.email,
        given_name: user.given_name || '',
        family_name: user.family_name || '',
        organization_id: organizationId,
        organization_name: user.organization_name || '',
        role,
        issued_at: nowIso,
        auto_approve: true,
      },
    };
  }

  if (isMdlCredential) {
    return {
      requested_validity_years: 5,
      metadata: {
        credential_type: MDL_CREDENTIAL_TYPE,
        credential_display_name: credentialConfig?.name || 'Mobile Driving Licence',
        family_name: user.family_name || '',
        given_name: user.given_name || '',
        birth_date: user.birth_date || '1990-01-01',
        issue_date: nowIso.slice(0, 10),
        expiry_date: new Date(Date.now() + 1825 * 86400000).toISOString().slice(0, 10),
        issuing_country: 'US',
        issuing_authority: 'ElevenID LLC',
        document_number: `MDL-${user.user_id?.slice(0, 8)?.toUpperCase() || '00000000'}`,
        driving_privileges: 'C',
        un_distinguishing_sign: 'USA',
        auto_approve: true,
      },
    };
  }

  return {
    requested_validity_years: 1,
    metadata: {
      credential_type: MEMBER_CREDENTIAL_TYPE,
      credential_display_name: credentialConfig?.name || 'ElevenID Login Credential',
      member_id: user.user_id,
      user_id: user.user_id,
      email: user.email,
      given_name: user.given_name || '',
      family_name: user.family_name || '',
      organization_id: organizationId,
      organization_name: user.organization_name || '',
      role,
      issued_at: nowIso,
      auto_approve: true,
    },
  };
}

export function getOneClickSummaryFields({ credentialConfig, user, organizationId }) {
  const { isMdlCredential, isMdocMemberCredential, isOpenBadgeCredential, isAccessBadgeCredential } = getCredentialKindFlags(credentialConfig);
  const displayRole = (user?.roles || []).find((value) => ['applicant', 'vendor', 'administrator'].includes(value)) || 'applicant';

  if (isOpenBadgeCredential) {
    return [
      { label: 'Name', value: [user?.given_name, user?.family_name].filter(Boolean).join(' ') || '—' },
      { label: 'Achievement', value: 'Platform Onboarding' },
      { label: 'Course', value: 'ElevenID Getting Started' },
      { label: 'Institution', value: 'ElevenID LLC' },
    ];
  }

  if (isAccessBadgeCredential) {
    return [
      { label: 'Name', value: [user?.given_name, user?.family_name].filter(Boolean).join(' ') || '—' },
      { label: 'Employee ID', value: `EMP-${user?.user_id?.slice(0, 8)?.toUpperCase() || '00000000'}` },
      { label: 'Department', value: 'Engineering' },
      { label: 'Clearance', value: 'General' },
    ];
  }

  if (isMdocMemberCredential) {
    const ROLE_DISPLAY = { applicant: 'Member', vendor: 'Vendor', administrator: 'Administrator' };
    const roleLabel = ROLE_DISPLAY[displayRole] || displayRole.charAt(0).toUpperCase() + displayRole.slice(1);
    return [
      { label: 'Name', value: [user?.given_name, user?.family_name].filter(Boolean).join(' ') || '—' },
      { label: 'Email', value: user?.email || '—' },
      { label: 'Role', value: roleLabel },
      { label: 'Format', value: 'mDoc (ISO 18013-5)' },
    ];
  }

  if (isMdlCredential) {
    return [
      { label: 'Name', value: [user?.given_name, user?.family_name].filter(Boolean).join(' ') || '—' },
      { label: 'Document Number', value: `MDL-${user?.user_id?.slice(0, 8)?.toUpperCase() || '00000000'}` },
      { label: 'Driving Privileges', value: 'C' },
      { label: 'Issuing Authority', value: 'ElevenID LLC' },
    ];
  }

  const ROLE_DISPLAY = { applicant: 'Member', vendor: 'Vendor', administrator: 'Administrator' };
  const roleLabel = ROLE_DISPLAY[displayRole] || displayRole.charAt(0).toUpperCase() + displayRole.slice(1);

  return [
    { label: 'Name', value: [user?.given_name, user?.family_name].filter(Boolean).join(' ') || '—' },
    { label: 'Email', value: user?.email || '—' },
    { label: 'Role', value: roleLabel },
    { label: 'Organization', value: 'ElevenID LLC' },
  ];
}

export function validateApplicationStep({ stepIndex, steps, formData, validationRules = {} }) {
  const errors = {};

  if (stepIndex === steps.length - 1) {
    if (!formData.acceptTerms) {
      errors.acceptTerms = 'You must accept the terms';
    }

    return {
      valid: Object.keys(errors).length === 0,
      errors,
    };
  }

  const currentStepFields = steps[stepIndex]?.fields || [];

  currentStepFields.forEach((field) => {
    const fieldName = field.name;
    const value = formData[fieldName];
    const rules = validationRules[fieldName];

    if (field.required && !value) {
      errors[fieldName] = `${field.label || fieldName.replace(/_/g, ' ')} is required`;
      return;
    }

    if (!value && !field.required) {
      return;
    }

    if (rules) {
      if (rules.min_length && value.length < rules.min_length) {
        errors[fieldName] = `Minimum length is ${rules.min_length}`;
      }
      if (rules.max_length && value.length > rules.max_length) {
        errors[fieldName] = `Maximum length is ${rules.max_length}`;
      }
      if (rules.pattern && !new RegExp(rules.pattern).test(value)) {
        errors[fieldName] = rules.pattern_description || 'Invalid format';
      }
      if (rules.min_value !== undefined && value < rules.min_value) {
        errors[fieldName] = `Minimum value is ${rules.min_value}`;
      }
      if (rules.max_value !== undefined && value > rules.max_value) {
        errors[fieldName] = `Maximum value is ${rules.max_value}`;
      }
    }
  });

  return {
    valid: Object.keys(errors).length === 0,
    errors,
  };
}
