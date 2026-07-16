/**
 * Pure helpers for applicant application flows.
 */

const PERSONAL_FIELDS = ['first_name', 'last_name', 'family_name', 'surname', 'given_name', 'date_of_birth', 'birth_date', 'email', 'phone', 'nationality', 'sex', 'gender'];
const ADDRESS_FIELDS = ['street', 'city', 'state', 'zip', 'postal_code', 'country', 'address'];
const DOCUMENT_FIELDS = ['document_number', 'license_class', 'driving_privileges', 'restrictions', 'issue_date', 'date_of_issue', 'expiry_date', 'date_of_expiry', 'issuing_state', 'issuing_authority'];
const PHOTO_FIELDS = ['portrait', 'signature', 'photo'];
const MDL_CREDENTIAL_TYPE = 'org.iso.18013.5.1.mDL';
const MEMBER_CREDENTIAL_TYPE = 'MemberCredential';
const MDOC_MEMBER_CREDENTIAL_TYPE = 'com.elevenid.member_credential';
const OPEN_BADGE_CREDENTIAL_TYPE = 'open_badge';
const ACCESS_BADGE_CREDENTIAL_TYPE = 'access_badge';
const ROLE_DISPLAY = { applicant: 'Member', vendor: 'Vendor', administrator: 'Administrator' };

function formatRoleLabel(role) {
  return ROLE_DISPLAY[role] || role.charAt(0).toUpperCase() + role.slice(1);
}

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
  const requiredClaims = claims.filter((claim) => claim?.required && claim?.name);
  const optionalClaims = claims.filter((claim) => !claim?.required && claim?.name);

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
    application_template_id: template?.application_template_id || null,
    claims,
  };
}

function parseListField(value) {
  if (Array.isArray(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  return [];
}

function humanizeFieldName(fieldName) {
  return String(fieldName || '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function normalizeApplicationInputType(type) {
  const normalized = String(type || 'text').toLowerCase();
  if (['string', 'str'].includes(normalized)) return 'text';
  if (['integer', 'int'].includes(normalized)) return 'integer';
  if (['float', 'decimal'].includes(normalized)) return 'number';
  if (['enum'].includes(normalized)) return 'select';
  if (['bool'].includes(normalized)) return 'boolean';
  if (['datetime-local', 'datetime'].includes(normalized)) return 'datetime';
  if (['email', 'phone', 'url', 'date', 'select', 'file', 'address', 'boolean', 'integer', 'number', 'text'].includes(normalized)) {
    return normalized;
  }
  return 'text';
}

function normalizeApplicationFormField(field, defaultRequired = false) {
  if (typeof field === 'string') {
    return {
      name: field,
      label: humanizeFieldName(field),
      type: 'text',
      required: defaultRequired,
    };
  }

  if (!field || typeof field !== 'object') {
    return null;
  }

  const name = field.name || field.field_name || field.claim_name || field.id;
  if (!name) {
    return null;
  }

  return {
    ...field,
    name,
    label: field.label || field.display_name || field.title || humanizeFieldName(name),
    type: normalizeApplicationInputType(field.type || field.input_type || field.field_type || field.claim_type),
    required: field.required !== undefined ? Boolean(field.required) : defaultRequired,
  };
}

function normalizeFieldList(fields = [], defaultRequired = false) {
  return parseListField(fields)
    .map((field) => normalizeApplicationFormField(field, defaultRequired))
    .filter(Boolean);
}

function normalizeCanonicalApplicationField(field) {
  if (!field || typeof field !== 'object' || !field.field_id || !field.field_type) {
    return null;
  }
  return {
    name: field.field_id,
    label: field.label || humanizeFieldName(field.field_id),
    type: normalizeApplicationInputType(field.field_type),
    required: Boolean(field.required),
    claim_mapping: field.claim_mapping,
    pattern: field.validation_pattern,
    options: field.options,
    minimum: field.minimum,
    maximum: field.maximum,
    placeholder: field.placeholder,
    hint: field.hint,
  };
}

function mergeFieldsByName(...fieldGroups) {
  const fieldsByName = new Map();

  fieldGroups.flat().filter(Boolean).forEach((field) => {
    const normalized = normalizeApplicationFormField(field, Boolean(field?.required));
    if (!normalized?.name) {
      return;
    }

    const existing = fieldsByName.get(normalized.name);
    fieldsByName.set(normalized.name, {
      ...(existing || {}),
      ...normalized,
      required: Boolean(existing?.required || normalized.required),
    });
  });

  return Array.from(fieldsByName.values());
}

export function normalizeApplicationTemplateToFormConfig(applicationTemplate, credentialConfig = null) {
  const baseConfig = normalizeCredentialConfigInput(credentialConfig) || {};
  const templateFormFields = parseListField(applicationTemplate?.form_fields)
    .map(normalizeCanonicalApplicationField)
    .filter(Boolean);
  const requiredTemplateFields = templateFormFields.filter((field) => field.required);
  const optionalTemplateFields = templateFormFields.filter((field) => !field.required);
  const baseRequiredFields = normalizeFieldList(baseConfig.required_fields, true);
  const baseOptionalFields = normalizeFieldList(baseConfig.optional_fields, false);
  const baseCustomFields = normalizeFieldList(baseConfig.custom_fields, false);
  const requiredFields = mergeFieldsByName(baseRequiredFields, requiredTemplateFields);
  const requiredFieldNames = new Set(requiredFields.map((field) => field.name));
  const optionalFields = mergeFieldsByName(baseOptionalFields, optionalTemplateFields)
    .filter((field) => !requiredFieldNames.has(field.name));
  const evidenceRequirements = parseListField(applicationTemplate?.evidence_requirements);
  const uiConfig = applicationTemplate?.ui_config && typeof applicationTemplate.ui_config === 'object'
    ? applicationTemplate.ui_config
    : {};

  return {
    ...baseConfig,
    id: baseConfig.id || applicationTemplate?.credential_template_id,
    credentialType: baseConfig.credentialType || baseConfig.credential_type,
    credential_type: baseConfig.credential_type || baseConfig.credentialType,
    name: applicationTemplate?.name || baseConfig.name,
    display_name: uiConfig.display_name || applicationTemplate?.name || baseConfig.display_name || baseConfig.name,
    description: applicationTemplate?.description || baseConfig.description,
    required_fields: requiredFields,
    optional_fields: optionalFields,
    custom_fields: baseCustomFields,
    field_validation_rules: {
      ...(baseConfig.field_validation_rules || {}),
      ...(uiConfig.field_validation_rules || {}),
    },
    submission_instructions: uiConfig.submission_instructions || applicationTemplate?.description || baseConfig.submission_instructions,
    application_template_id: applicationTemplate?.id || baseConfig.application_template_id,
    application_template: applicationTemplate ? {
      ...applicationTemplate,
      form_fields: templateFormFields,
      evidence_requirements: evidenceRequirements,
    } : baseConfig.application_template,
    evidence_requirements: evidenceRequirements,
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

  const matches = (field, names) => {
    const normalized = String(field.name || '').toLowerCase();
    const leaf = normalized.split(/[.:/]/).pop();
    return names.includes(normalized) || names.includes(leaf);
  };
  const personal = allFields.filter((field) => matches(field, PERSONAL_FIELDS));
  const document = allFields.filter((field) => matches(field, DOCUMENT_FIELDS));
  const address = allFields.filter((field) => !document.includes(field) && matches(field, ADDRESS_FIELDS));
  const photo = allFields.filter((field) => matches(field, PHOTO_FIELDS));
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

export function buildApplicantProfileData({ user, formData }) {
  return {
    given_name: formData.given_name || formData.first_name || '',
    family_name: formData.family_name || formData.last_name || '',
    email: formData.email || user.email,
    ...(formData.phone ? { phone: formData.phone } : {}),
  };
}

export function buildStandardApplicationPayload({ organizationId, credentialConfig, formData, canvasLtiContext = null }) {
  return {
    organization_id: organizationId,
    application_template_id: credentialConfig?.application_template_id,
    form_data: { ...formData },
    integration_context: canvasLtiContext ? { canvas_lti: canvasLtiContext } : {},
  };
}

function applicantProfileValue(fieldId, user = {}) {
  if (fieldId === 'birth_date') return user.birth_date || user.date_of_birth;
  if (fieldId === 'date_of_birth') return user.date_of_birth || user.birth_date;
  return ['email', 'given_name', 'family_name'].includes(fieldId) ? user[fieldId] : undefined;
}

export function buildAutoApplyFormData({ applicationTemplate, user }) {
  const fields = Array.isArray(applicationTemplate?.form_fields) ? applicationTemplate.form_fields : [];
  if (!applicationTemplate?.id || fields.length === 0) {
    throw new Error('An active Application Template with form fields is required.');
  }

  const formData = {};
  for (const field of fields) {
    const fieldId = field?.field_id;
    if (!fieldId) continue;
    const value = applicantProfileValue(fieldId, user);
    if (field.required && (value === undefined || value === null || value === '')) {
      throw new Error(`Complete the required ${field.label || fieldId} field before applying.`);
    }
    if (value !== undefined && value !== null && value !== '') formData[fieldId] = value;
  }
  return formData;
}

export function canAutoApplyApplicationTemplate({ applicationTemplate, user }) {
  try {
    buildAutoApplyFormData({ applicationTemplate, user });
    return true;
  } catch {
    return false;
  }
}

export function getOneClickSummaryFields({ credentialConfig, user, organizationId }) {
  const { isMdlCredential, isMdocMemberCredential, isOpenBadgeCredential, isAccessBadgeCredential } = getCredentialKindFlags(credentialConfig);
  const displayRole = (user?.roles || []).find((value) => ['applicant', 'vendor', 'administrator'].includes(value)) || 'applicant';

  if (isOpenBadgeCredential) {
    return [
      { label: 'Name', value: [user?.given_name, user?.family_name].filter(Boolean).join(' ') || '—' },
      { label: 'Email', value: user?.email || '—' },
      { label: 'Role', value: formatRoleLabel(displayRole) },
      { label: 'Badge', value: credentialConfig?.name || 'Verified Member Badge' },
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
    const roleLabel = formatRoleLabel(displayRole);
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

  const roleLabel = formatRoleLabel(displayRole);

  return [
    { label: 'Name', value: [user?.given_name, user?.family_name].filter(Boolean).join(' ') || '—' },
    { label: 'Email', value: user?.email || '—' },
    { label: 'Role', value: roleLabel },
    { label: 'Organization', value: user?.organization_name || user?.default_organization_name || organizationId || 'ElevenID LLC' },
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
    const rules = { ...field, ...(validationRules[fieldName] || {}) };
    const missing = value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0);

    if (field.required && missing) {
      errors[fieldName] = `${field.label || fieldName.replace(/_/g, ' ')} is required`;
      return;
    }

    if (missing && !field.required) {
      return;
    }

    if (rules) {
      const fieldType = String(rules.type || 'text').toLowerCase();
      if (fieldType === 'date') {
        const validDate = /^\d{4}-\d{2}-\d{2}$/.test(String(value))
          && !Number.isNaN(new Date(`${value}T00:00:00Z`).getTime());
        if (!validDate) errors[fieldName] = 'Use a date in YYYY-MM-DD format';
      } else if (['datetime', 'datetime-local'].includes(fieldType) && Number.isNaN(new Date(value).getTime())) {
        errors[fieldName] = 'Use a valid date and time';
      } else if (fieldType === 'boolean' && typeof value !== 'boolean') {
        errors[fieldName] = 'Choose true or false';
      } else if (fieldType === 'number' && (typeof value !== 'number' || Number.isNaN(value))) {
        errors[fieldName] = 'Enter a number';
      } else if (fieldType === 'integer' && !Number.isInteger(value)) {
        errors[fieldName] = 'Enter a whole number';
      }
      if (rules.min_length && value.length < rules.min_length) {
        errors[fieldName] = `Minimum length is ${rules.min_length}`;
      }
      if (rules.max_length && value.length > rules.max_length) {
        errors[fieldName] = `Maximum length is ${rules.max_length}`;
      }
      if (rules.pattern) {
        try {
          if (!new RegExp(`^(?:${rules.pattern})$`).test(value)) errors[fieldName] = rules.pattern_description || 'Invalid format';
        } catch {
          // Invalid template patterns are rejected server-side during template validation.
        }
      }
      const allowedValues = rules.enum || rules.allowed_values || rules.options;
      if (Array.isArray(allowedValues) && allowedValues.length > 0) {
        const normalized = allowedValues.map((item) => typeof item === 'object' ? item.value : item);
        if (!normalized.includes(value)) errors[fieldName] = 'Choose one of the allowed values';
      }
      const minimum = rules.minimum ?? rules.min ?? rules.min_value;
      const maximum = rules.maximum ?? rules.max ?? rules.max_value;
      if (minimum !== undefined && value < minimum) {
        errors[fieldName] = `Minimum value is ${minimum}`;
      }
      if (maximum !== undefined && value > maximum) {
        errors[fieldName] = `Maximum value is ${maximum}`;
      }
    }
  });

  return {
    valid: Object.keys(errors).length === 0,
    errors,
  };
}
